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

#pragma once

#include <openssl/rand.h>
#include <openssl/provider.h>

typedef int uefi_random_generate_cb(
	unsigned char *out,
	size_t outlen,
	const char *name,
	EVP_RAND_CTX *ctx
);

OSSL_PROVIDER *uefi_rand_init(
	OSSL_LIB_CTX *libctx,
	int allow_unsafe_rng
);

void uefi_rand_finish(
	OSSL_PROVIDER *p
);

void uefi_rand_set_callback(
	EVP_RAND_CTX *ctx,
	uefi_random_generate_cb *cb
);

void uefi_rand_set_public_private_callbacks(
	OSSL_LIB_CTX *libctx,
	uefi_random_generate_cb *cb
);

