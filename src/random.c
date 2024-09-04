/*
 * MSSB (More Secure Secure Boot -- "Mosby") OpenSSL UEFI RNG provider
 * Copyright 2024 Pete Batard <pete@akeo.ie>
 * Copyright 2021-2023 The OpenSSL Project Authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Note: I hate providing a custom random generator as much as they next
 * next guy, but OpenSSL isn't designed for bare metal so short of using
 * an x86 CPU with the RDRAND instruction, the default OpenSSL EVP random
 * provider will *NOT* work.
 *
 * Which means that we have little choice but to add a new provider that
 * can use the platform's UEFI Rng protocol, in case the default from
 * OpenSSL does not work.
 */
 
#include "mosby.h"
#include "console.h"
#include "file.h"
#include "pki.h"
#include "random.h"

#include <Protocol/Rng.h>

#include <openssl/core_names.h>
#include <openssl/md5.h>

// UEFI RNG protocol
STATIC EFI_RNG_PROTOCOL *mRngProtocol;

// Macro to access context of the opaque EVP_RAND_CTX structure
#define GET_CTX(x) (((void**)x)[1])

/*
 * For platforms that don't have any RNG source at all, we use
 * Mersenne Twister as a last resource, using the code from:
 * https://en.wikipedia.org/wiki/Mersenne_Twister#C_code
 *
 * Which means that our RNG sources are:
 * 1. OpenSSL's internal RNG
 * 2. The UEFI platform's RNG
 * 3. The Mersenne Twister PRNG
 *
 * Obviously, the use of this PRNG will come with a BIG WARNING.
 */

#define n 624
#define m 397
#define w 32
#define r 31
#define UMASK (0xffffffffUL << r)
#define LMASK (0xffffffffUL >> (w-r))
#define a 0x9908b0dfUL
#define u 11
#define s 7
#define t 15
#define l 18
#define b 0x9d2c5680UL
#define c 0xefc60000UL
#define f 1812433253UL

struct {
	UINT32 StateArray[n];
	INTN StateIndex;
	BOOLEAN Initialized;
} mState = { 0 };

STATIC VOID MtInitializeState(
	IN UINT32 Seed
)
{
	INTN i;
	UINT32* StateArray = &(mState.StateArray[0]);

	StateArray[0] = Seed;

	for (i = 1; i < n; i++) {
		Seed = f * (Seed ^ (Seed >> (w - 2))) + i;
		StateArray[i] = Seed;
	}

	mState.StateIndex = 0;
	mState.Initialized = TRUE;
}

STATIC UINT32 MtGetRandom32(VOID)
{
	UINT32* StateArray = &(mState.StateArray[0]);
	UINT32 x, xA, y, z;
	INTN k = mState.StateIndex;
	INTN j = k - (n - 1);

	if (j < 0)
		j += n;

	x = (StateArray[k] & UMASK) | (StateArray[j] & LMASK);

	xA = x >> 1;
	if (x & 0x00000001UL)
		xA ^= a;

	j = k - (n - m);
	if (j < 0)
		j += n;

	x = StateArray[j] ^ xA;
	StateArray[k++] = x;

	if (k >= n)
		k = 0;
	mState.StateIndex = k;

	y = x ^ (x >> u);
	y = y ^ ((y << s) & b);
	y = y ^ ((y << t) & c);
	z = y ^ (y >> l);

	return z;
}

#undef n
#undef m
#undef w
#undef r
#undef a
#undef u
#undef s
#undef t
#undef l
#undef b
#undef c
#undef f

// Return a 32 bit integer derived from the MD5 hash of a buffer
STATIC UINT32 Hash32(
	IN CONST UINT8 *Buf,
	IN CONST UINTN Len
)
{
	UINT32 Digest[4];
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, Buf, Len);
	MD5_Final((unsigned char*)Digest, &ctx);
	return Digest[0] ^ Digest[1] ^ Digest[2] ^ Digest[3];
}

/* UEFI RNG provider implementation */
typedef struct {
	uefi_random_generate_cb *cb;
	int state;
	const char *name;
	EVP_RAND_CTX *ctx;
} UEFI_RAND;

static OSSL_FUNC_rand_newctx_fn uefi_rand_newctx;
static OSSL_FUNC_rand_freectx_fn uefi_rand_freectx;
static OSSL_FUNC_rand_instantiate_fn uefi_rand_instantiate;
static OSSL_FUNC_rand_uninstantiate_fn uefi_rand_uninstantiate;
static OSSL_FUNC_rand_generate_fn uefi_rand_generate;
static OSSL_FUNC_rand_gettable_ctx_params_fn uefi_rand_gettable_ctx_params;
static OSSL_FUNC_rand_get_ctx_params_fn uefi_rand_get_ctx_params;
static OSSL_FUNC_rand_enable_locking_fn uefi_rand_enable_locking;
static OSSL_FUNC_rand_reseed_fn uefi_rand_reseed;

static void *uefi_rand_newctx(
	void *provctx,
	void *parent,
	const OSSL_DISPATCH *parent_dispatch
)
{
	UEFI_RAND *r = OPENSSL_zalloc(sizeof(*r));

	if (r != NULL)
		r->state = EVP_RAND_STATE_UNINITIALISED;
	return r;
}

static void uefi_rand_freectx(
	void *vrng
)
{
	OPENSSL_free(vrng);
}

static int uefi_rand_instantiate(
	void *vrng,
	ossl_unused unsigned int strength,
	ossl_unused int prediction_resistance,
	ossl_unused const unsigned char *pstr,
	size_t pstr_len,
	ossl_unused const OSSL_PARAM params[]
)
{
	UEFI_RAND *frng = (UEFI_RAND *)vrng;

	frng->state = EVP_RAND_STATE_READY;
	return 1;
}

static int uefi_rand_uninstantiate(
	void *vrng
)
{
	UEFI_RAND *frng = (UEFI_RAND *)vrng;

	frng->state = EVP_RAND_STATE_UNINITIALISED;
	return 1;
}

static int uefi_rand_reseed(
	void *vrng,
	int prediction_resistance,
	const unsigned char *ent,
	size_t ent_len,
	const unsigned char *adin,
	size_t adin_len
)
{
	UINT32 i, Seed, Data;

	if (adin == NULL || adin_len == 0)
		return 0;

	Seed = Hash32(adin, adin_len);

	if (mRngProtocol != NULL) {
		// We don't have a way to re-seed the UEFI RNG protocol
		// but we can issue a set of RNG calls based on the seed.
		for (i = 0; i < (Seed & 0xFF) + 7; i++)
			mRngProtocol->GetRNG(mRngProtocol, NULL, sizeof(Data), (UINT8*)&Data);
	} else {
		MtInitializeState(Seed);
	}

	return 1;
}

static int uefi_rand_generate(
	void *vrng,
	unsigned char *out,
	size_t outlen,
	unsigned int strength,
	int prediction_resistance,
	const unsigned char *adin,
	size_t adinlen
)
{
	size_t l;
	UINT32 r;
	EFI_STATUS Status;
	UEFI_RAND *frng = (UEFI_RAND *)vrng;

	if (frng->cb != NULL)
		return (*frng->cb)(out, outlen, frng->name, frng->ctx);

	// Use the platform RNG if available
	if (mRngProtocol != NULL) {
		Status = mRngProtocol->GetRNG(mRngProtocol, NULL, outlen, out);
		return (EFI_ERROR(Status) ? 0 : 1);
	}

	// Fall back to the Mersenne PRNG if not
	if (!mState.Initialized)
		return 0;
	while (outlen > 0) {
		r = MtGetRandom32();
		l = outlen < sizeof(r) ? outlen : sizeof(r);

		CopyMem(out, &r, l);
		out += l;
		outlen -= l;
	}
	return 1;
}

static int uefi_rand_enable_locking(
	void *vrng
)
{
	return 1;
}

static int uefi_rand_get_ctx_params(
	ossl_unused void *vrng,
	OSSL_PARAM params[]
)
{
	UEFI_RAND *frng = (UEFI_RAND *)vrng;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
	if (p != NULL && !OSSL_PARAM_set_int(p, frng->state))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
	if (p != NULL && !OSSL_PARAM_set_uint(p, 256))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
	if (p != NULL && !OSSL_PARAM_set_uint(p, 4096))
		return 0;

	return 1;
}

static const OSSL_PARAM *uefi_rand_gettable_ctx_params(
	ossl_unused void *vrng,
	ossl_unused void *provctx
)
{
	static const OSSL_PARAM known_gettable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
		OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
		OSSL_PARAM_uint(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
		OSSL_PARAM_END
	};
	return known_gettable_ctx_params;
}

static const OSSL_DISPATCH uefi_rand_functions[] = {
	{ OSSL_FUNC_RAND_NEWCTX, (void (*)(void))uefi_rand_newctx },
	{ OSSL_FUNC_RAND_FREECTX, (void (*)(void))uefi_rand_freectx },
	{ OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))uefi_rand_instantiate },
	{ OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))uefi_rand_uninstantiate },
	{ OSSL_FUNC_RAND_RESEED, (void (*)(void))uefi_rand_reseed },
	{ OSSL_FUNC_RAND_GENERATE, (void (*)(void))uefi_rand_generate },
	{ OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))uefi_rand_enable_locking },
	{ OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))uefi_rand_gettable_ctx_params },
	{ OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))uefi_rand_get_ctx_params },
	{ 0, NULL }
};

static const OSSL_ALGORITHM uefi_rand_rand[] = {
	{ "UEFI", "provider=uefi", uefi_rand_functions },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *uefi_rand_query(
	void *provctx,
	int operation_id,
	int *no_cache
)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_RAND:
        return uefi_rand_rand;
    }
    return NULL;
}

static const OSSL_DISPATCH uefi_rand_method[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))uefi_rand_query },
	{ 0, NULL }
};

static int uefi_rand_provider_init(
	const OSSL_CORE_HANDLE *handle,
	const OSSL_DISPATCH *in,
	const OSSL_DISPATCH **out,
	void **provctx
)
{
	*provctx = OSSL_LIB_CTX_new();
	if (*provctx == NULL)
		return 0;
	*out = uefi_rand_method;
	return 1;
}

static int check_rng(
	EVP_RAND_CTX *rng,
	const char *name
)
{
	UEFI_RAND *f;

	if (rng == NULL)
		return 0;
	f = GET_CTX(rng);
	f->name = name;
	f->ctx = rng;
	return 1;
}

OSSL_PROVIDER *uefi_rand_init(
	OSSL_LIB_CTX *libctx,
	int allow_unsafe_rng
)
{
	CHAR8* DefaultSeedString = __DATE__ __TIME__;
	UINT32 Seed;
	EFI_TIME Time;
	EFI_STATUS Status;
	OSSL_PROVIDER *p;

	if (mRngProtocol == NULL) {
		// Try to use the UEFI RNG if we can
		Status = gBS->LocateProtocol(&gEfiRngProtocolGuid, NULL, (VOID **)&mRngProtocol);
		if (EFI_ERROR(Status)) {
			if (!allow_unsafe_rng)
				return NULL;
			RecallPrint(L"WARNING: Using UNSAFE random generator!\n");
			mRngProtocol = NULL;
			// Initialize our *UNSAFE* RNG with a time derived seed
			Status = gRT->GetTime(&Time, NULL);
			if (EFI_ERROR(Status))
				Seed = Hash32((UINT8*)DefaultSeedString, AsciiStrLen(DefaultSeedString));
			else
				Seed = Hash32((UINT8*)&Time, sizeof(Time));
			MtInitializeState(Seed);
		} else {
			RecallPrint(L"Notice: Using UEFI random generator\n");
		}
	}

	if (!OSSL_PROVIDER_add_builtin(libctx, "uefi-rand", uefi_rand_provider_init) ||
		!RAND_set_DRBG_type(libctx, "uefi", NULL, NULL, NULL) ||
		((p = OSSL_PROVIDER_try_load(libctx, "uefi-rand", 1)) == NULL))
		return NULL;

	// Ensure that our RNG is properly initialized.
	if (!check_rng(RAND_get0_primary(libctx), "primary") ||
		!check_rng(RAND_get0_private(libctx), "private") ||
		!check_rng(RAND_get0_public(libctx), "public")) {
		OSSL_PROVIDER_unload(p);
		return NULL;
	}

	return p;
}

void uefi_rand_finish(
	OSSL_PROVIDER *p
)
{
	OSSL_PROVIDER_unload(p);
}

void uefi_rand_set_callback(
	EVP_RAND_CTX *rng,
	uefi_random_generate_cb *cb
)
{
	if (rng != NULL)
		((UEFI_RAND *)GET_CTX(rng))->cb = cb;
}

void uefi_rand_set_public_private_callbacks(
	OSSL_LIB_CTX *libctx,
	uefi_random_generate_cb *cb
)
{
	uefi_rand_set_callback(RAND_get0_private(libctx), cb);
	uefi_rand_set_callback(RAND_get0_public(libctx), cb);
}
