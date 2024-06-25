/*
 * TurnKey
 * Copyright © 2024 Pete Batard <pete@akeo.ie>
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

#include <Base.h>
#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Uefi/UefiBaseType.h>

#undef _WIN32
#undef _WIN64
#define OPENSSL_NO_DEPRECATED 0
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

// For OpenSSL error reporting
STATIC int Error_CB(CONST CHAR8 *str, UINTN len, VOID *u)
{
	Print(L"ERROR: %s %a\n", (CHAR16*)u, str);
	return 0;
}
#define OSSL_REPORT_ERROR(msg) ERR_print_errors_cb(Error_CB, msg)

STATIC INTN X509_add_ext_helper(X509 *cert, int nid, char *value)
{
	X509V3_CTX ctx;

	X509V3_set_ctx_nodb(&ctx);

	X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (ex == NULL) {
		Print(L"ERROR: X509V3_EXT_conf_nid(%d, %s) failed", nid, value);
		return 0;
	}

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);

	return 1;
}

STATIC VOID DumpBufferHex(VOID* Buf, UINTN Size)
{
	UINT8* Buffer = (UINT8*)Buf;
	UINTN i, j, k;
	CHAR8 Line[80] = "";

	for (i = 0; i < Size; i += 16) {
		if (i != 0)
			Print(L"%a\n", Line);
		Line[0] = 0;
//		AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), "  %08x  ", i);
		for (j = 0, k = 0; k < 16; j++, k++) {
			if (i + j < Size)
				AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), "%02x", Buffer[i + j]);
			else
				AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), "  ");
			AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), " ");
		}
#if 0
		AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), " ");
		for (j = 0, k = 0; k < 16; j++, k++) {
			if (i + j < Size) {
				if ((Buffer[i + j] < 32) || (Buffer[ i + j] > 126))
					AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), ".");
				else
					AsciiSPrint (&Line[AsciiStrLen (Line)], 80 - AsciiStrLen (Line), "%c", Buffer[i + j]);
			}
		}
#endif
	}
	Print(L"%a\n", Line);
}

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	CONST CHAR16 DestPath[] = L"FS0:\\PK.pfx";
	CONST CHAR8 DefaultSeed[] = "Turnkey crypto default seed";
	EFI_STATUS Status;
	UINT8 *Buffer = NULL;
	OSSL_ENCODER_CTX* ectx = NULL;
	EVP_PKEY* pk_key = NULL;
	X509* pk_cert = NULL;
	PKCS12* p12 = NULL;

	// TODO: Test CPU flags for RDRAND
	Print(L"X509 Test\n");

	// Initialize the random generator
	// TODO: Derive a seed from user input
	RAND_seed(DefaultSeed, sizeof(DefaultSeed));
	Print(L"RAND_status = %d\n", RAND_status());

	pk_key = EVP_RSA_gen(2048);
	if (pk_key == NULL) {
		OSSL_REPORT_ERROR(L"EVP_RSA_gen()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	Print(L"PK RSA keypair was generated, type %d\n", EVP_PKEY_get_id(pk_key));

	/* Allocate memory for the X509 structure. */
	pk_cert = X509_new();
	if (pk_cert == NULL) {
		OSSL_REPORT_ERROR(L"X509_new()");
		Status = EFI_NOT_FOUND;
		goto out;
	}

	// Set the certificate serial number.
	ASN1_INTEGER* sn = ASN1_INTEGER_new();
	// TODO: Derive a serial number from current date
	ASN1_INTEGER_set(sn, 12345678);
	if (!X509_set_serialNumber(pk_cert, sn))
		OSSL_REPORT_ERROR(L"X509_set_serialNumber()");
	ASN1_INTEGER_free(sn);

	// Set version
	X509_set_version(pk_cert, 2);

	// Set usage for code signing as a Certification Authority
	X509_add_ext_helper(pk_cert, NID_basic_constraints, (char*)"critical,CA:TRUE");
	X509_add_ext_helper(pk_cert, NID_key_usage, (char*)"critical,digitalSignature,keyEncipherment");

	// Set certificate validity to 20 years
	ASN1_TIME* asn1time = ASN1_TIME_new();
	ASN1_TIME_set(asn1time, time(NULL));
	X509_set1_notBefore(pk_cert, asn1time);
	ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * 365 * 20 + 5));
	X509_set1_notAfter(pk_cert, asn1time);
	ASN1_TIME_free(asn1time);

	X509_NAME* name = X509_get_subject_name(pk_cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (UINT8 *)"Turnkey PK", -1, -1, 0);
	X509_set_issuer_name(pk_cert, name);

	// Certify and sign with the private key we created
	if (!X509_set_pubkey(pk_cert, pk_key)) {
		OSSL_REPORT_ERROR(L"X509_set_pubkey()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	if (X509_sign(pk_cert, pk_key, EVP_sha256()) == 0) {
		OSSL_REPORT_ERROR(L"X509_sign()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	// Might as well verify the signature while we're at it
	if (!X509_verify(pk_cert, pk_key))
		OSSL_REPORT_ERROR(L"X509_verify()");

	// Save as PKCS#12/PFX
	UINT8 keyid[EVP_MAX_MD_SIZE];
	unsigned int keyidlen = 0;
	if (!X509_digest(pk_cert, EVP_sha256(), keyid, &keyidlen)) {
		OSSL_REPORT_ERROR(L"X509_digest()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	X509_keyid_set1(pk_cert, keyid, keyidlen);
	p12 = PKCS12_create("password", NULL, pk_key, pk_cert, NULL, NID_undef, NID_undef, 0, 0, 0);
	if (p12 == NULL) {
		OSSL_REPORT_ERROR(L"PKCS12_create()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	Print(L"PKCS12 GENERATION OKAY!\n");

	//NB: i2d_X509(pk_cert, &Buffer) can be used to dump .der of cert
	INTN _Size = (INTN)i2d_PKCS12(p12, &Buffer);
	if (_Size < 0) {
		OSSL_REPORT_ERROR(L"i2d_PKCS12()");
		Status = EFI_NOT_FOUND;
		goto out;
	}
	UINTN Size = (UINTN)_Size;
	SHELL_FILE_HANDLE  FileHandle = { 0 };
	ShellDeleteFileByName(DestPath);
	Status = ShellOpenFileByName(DestPath, &FileHandle,
		EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (Status == EFI_SUCCESS)
		Status = ShellWriteFile(FileHandle, &Size, Buffer);
	if (EFI_ERROR(Status))
		Print(L"Could not write %s %r\n", DestPath, Status);
	ShellCloseFile(&FileHandle);
//	DumpBufferHex(Buffer, Size);

out:
	OPENSSL_free(Buffer);
	PKCS12_free(p12);
	OSSL_ENCODER_CTX_free(ectx);
	X509_free(pk_cert);
	EVP_PKEY_free(pk_key);

	return Status;
}
