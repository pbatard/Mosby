/*
 * Secure Boot Kick - Secure Boot Key Installation/Creation
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
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "console.h"
#include "file.h"

enum {
	DB = 0,
	KEK,
	PK,
	MAX_CERT,
};

// For OpenSSL error reporting
STATIC int Error_CB(CONST CHAR8 *str, UINTN len, VOID *u)
{
	Print(L"ERROR: %s %a\n", (CHAR16*)u, str);
	return 0;
}
#define OSSL_REPORT_ERROR(msg) ERR_print_errors_cb(Error_CB, msg)

#define ReportOpenSSLError(msg) do { ERR_print_errors_cb(Error_CB, msg); } while(0)
#define ReportOpenSSLErrorAndExit(msg, err) do { ERR_print_errors_cb(Error_CB, msg), Status = err; goto exit; } while(0)

// Helper function to add X509 extensions
EFI_STATUS AddExtension(X509 *Cert, INTN ExtNid, CONST CHAR8* ExtStr)
{
	EFI_STATUS Status = EFI_SUCCESS;
	X509_EXTENSION *ex = NULL;

	ex = X509V3_EXT_nconf_nid(NULL, NULL, ExtNid, (char *)ExtStr);
	if (ex == NULL)
		ReportOpenSSLErrorAndExit(L"X509V3_EXT_conf_nid", EFI_UNSUPPORTED);

	if (!X509_add_ext(Cert, ex, -1))
		ReportOpenSSLErrorAndExit(L"X509_add_ext", EFI_ACCESS_DENIED);

exit:
	X509_EXTENSION_free(ex);
	return Status;
}

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	CONST CHAR8 DefaultSeed[] = "SB Kick crypto default seed";
	CONST CHAR8 Password[] = "password";
	CHAR16 *FileName, *Title[3];
	EFI_STATUS Status;
	EFI_FILE_HANDLE File = NULL;
	EFI_HANDLE Handle = NULL;
	UINT8 *Buffer = NULL;
	EVP_PKEY* Key[MAX_CERT] = { 0 };
	X509* Cert[MAX_CERT] = { 0 };
	PKCS12* p12 = NULL;
	BIO* bio = NULL;
	INTN Size, Index = 0;

	// Initialize the random generator and validate the platform
	// TODO: Derive a seed from user input
	RAND_seed(DefaultSeed, sizeof(DefaultSeed));
	if (RAND_status() != 1) {
		Print(L"ERROR: This platform does not meet the minimum security requirements.\n");
		Status = EFI_UNSUPPORTED;
		goto exit;
	}

	Title[0] = L"Select cert file";
	Title[1] = NULL;
	Status = SimpleFileSelector(&Handle, Title, L"\\", L".crt", &FileName);
	if (EFI_ERROR(Status))
		goto exit;
	Status = SimpleFileOpen(Handle, FileName, &File, EFI_FILE_MODE_READ);
	if (EFI_ERROR(Status))
		goto exit;
	Status = SimpleFileReadAll(File, (UINTN*)&Size, (VOID**)&Buffer);
	if (EFI_ERROR(Status))
		goto exit;
	bio = BIO_new_mem_buf(Buffer, Size);
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(L"BIO_new()", EFI_OUT_OF_RESOURCES);
	Cert[1] = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (Cert[1] == NULL)
		ReportOpenSSLErrorAndExit(L"X509_new()", EFI_PROTOCOL_ERROR);
	else
		Print(L"Read Cert OKAY\n");
	BIO_free(bio);
	bio = NULL;
	FreePool(Buffer);
	Buffer = NULL;

	// Create a new RSA-2048 keypair
	Key[Index] = EVP_RSA_gen(2048);
	if (Key[Index] == NULL)
		ReportOpenSSLErrorAndExit(L"EVP_RSA_gen()", EFI_PROTOCOL_ERROR);
	Print(L"Generated RSA keypair...\n");

	// Create a new X509 certificate
	Cert[Index] = X509_new();
	if (Cert[Index] == NULL)
		ReportOpenSSLErrorAndExit(L"X509_new()", EFI_PROTOCOL_ERROR);

	// Set the certificate serial number.
	ASN1_INTEGER* sn = ASN1_INTEGER_new();
	// TODO: Derive a serial number from current date
	ASN1_INTEGER_set(sn, 0x12345678);
	if (!X509_set_serialNumber(Cert[Index], sn))
		OSSL_REPORT_ERROR(L"X509_set_serialNumber()");
	ASN1_INTEGER_free(sn);

	// Set version
	X509_set_version(Cert[Index], 2);

	// Set usage for code signing as a Certification Authority
	AddExtension(Cert[Index], NID_basic_constraints, "critical,CA:TRUE");
	AddExtension(Cert[Index], NID_key_usage, "critical,digitalSignature,keyEncipherment");

	// Set certificate validity to 20 years
	ASN1_TIME* asn1time = ASN1_TIME_new();
	ASN1_TIME_set(asn1time, time(NULL));
	X509_set1_notBefore(Cert[Index], asn1time);
	ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * (365 * 20 + 5)));
	X509_set1_notAfter(Cert[Index], asn1time);
	ASN1_TIME_free(asn1time);

	X509_NAME* name = X509_get_subject_name(Cert[Index]);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (UINT8 *)"Kick PK", -1, -1, 0);
	X509_set_issuer_name(Cert[Index], name);

	// Certify and sign with the private key we created
	if (!X509_set_pubkey(Cert[Index], Key[Index]))
		ReportOpenSSLErrorAndExit(L"X509_set_pubkey()", EFI_PROTOCOL_ERROR);
	if (!X509_sign(Cert[Index], Key[Index], EVP_sha256()))
		ReportOpenSSLErrorAndExit(L"X509_sign()", EFI_PROTOCOL_ERROR);
	// Might as well verify the signature while we're at it
	if (!X509_verify(Cert[Index], Key[Index]))
		ReportOpenSSLError(L"X509_verify()");
	Print(L"Generated X509 certificate...\n");

	// Save as PKCS#12/PFX
	UINT8 keyid[EVP_MAX_MD_SIZE];
	unsigned int keyidlen = 0;
	if (!X509_digest(Cert[Index], EVP_sha256(), keyid, &keyidlen))
		ReportOpenSSLErrorAndExit(L"X509_digest()", EFI_PROTOCOL_ERROR);
	X509_keyid_set1(Cert[Index], keyid, keyidlen);
	p12 = PKCS12_create(Password, NULL, Key[Index], Cert[Index], NULL, NID_undef, NID_undef, 0, 0, 0);
	if (p12 == NULL)
		ReportOpenSSLErrorAndExit(L"PKCS12_create()", EFI_PROTOCOL_ERROR);
	Print(L"Generated PKCS#12 data...\n");

	// Create .pfx
	Size = (INTN)i2d_PKCS12(p12, &Buffer);
	PKCS12_free(p12);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(L"i2d_PKCS12()", EFI_PROTOCOL_ERROR);
	Status = ShellWriteAll(L"FS0:\\PK.pfx", Buffer, (UINTN)Size);
	OPENSSL_free(Buffer);

	// Create .cer
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(L"BIO_new()", EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_X509(bio, Cert[Index]))
		ReportOpenSSLErrorAndExit(L"PEM_write_bio_X509()", EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(L"BIO_get_mem_data()", EFI_PROTOCOL_ERROR);
	Status = ShellWriteAll(L"FS0:\\PK.crt", Buffer, (UINTN)Size);
	BIO_free(bio);

	// Create .crt
	Size = (INTN)i2d_X509(Cert[Index], &Buffer);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(L"i2d_X509()", EFI_PROTOCOL_ERROR);
	Status = ShellWriteAll(L"FS0:\\PK.cer", Buffer, (UINTN)Size);
	OPENSSL_free(Buffer);

	// Create .pem
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(L"BIO_new()", EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_PKCS8PrivateKey(bio, Key[Index], EVP_aes_256_cbc(), Password, AsciiStrLen(Password), NULL, NULL))
		ReportOpenSSLErrorAndExit(L"PEM_write_bio_PKCS8PrivateKey()", EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(L"BIO_get_mem_data()", EFI_PROTOCOL_ERROR);
	Status = ShellWriteAll(L"FS0:\\PK.pem", Buffer, (UINTN)Size);
	Print(L"Generated all certificate and key files...\n");

exit:
	if (bio != NULL)
		BIO_free(bio);
	for (Index = 0; Index < MAX_CERT; Index++) {
		X509_free(Cert[Index]);
		EVP_PKEY_free(Key[Index]);
	}

	return Status;
}
