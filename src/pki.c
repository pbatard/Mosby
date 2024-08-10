/*
 * MSSB (More Secure Secure Boot -- "Mosby") PKI/OpenSSL functions
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

#include "mosby.h"
#include "console.h"
#include "file.h"
#include "pki.h"

/* OpenSSL */
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

/* For OpenSSL error reporting */
STATIC int OpenSSLErrorCallback(
	CONST CHAR8 *AsciiString,
	UINTN Len,
	VOID *UserData
)
{
	Print(L"ERROR: %s %a\n", (CHAR16*)UserData, AsciiString);
	return 0;
}

EFI_STATUS InitializePki(VOID)
{
	// TODO: Derive from clock or something?
	CONST CHAR8 DefaultSeed[] = "Mosby crypto default seed";

	RAND_seed(DefaultSeed, sizeof(DefaultSeed));
	return (RAND_status() != 1) ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

/* Helper function to add X509 extensions */
STATIC EFI_STATUS AddExtension(
	IN X509 *Cert,
	IN INTN ExtNid,
	IN CONST CHAR8* ExtStr
)
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

VOID* ReadCertificate(
	IN CONST CHAR16 *Path
)
{
	EFI_STATUS Status;
	UINTN Size;
	UINT8 *Buffer = NULL;
	X509 *Cert = NULL;
	BIO *bio = NULL;

	Status = SimpleFileReadAllByPath(Path, &Size, (VOID**)&Buffer);
	if (EFI_ERROR(Status))
		goto exit;

	/* Try d2i first in case it's a binary cert */
	Cert = d2i_X509(NULL, (CONST UINT8**)&Buffer, Size);
	if (Cert != NULL)
		goto exit;

	/* d2i didn't succeed, try to read as PEM */
	bio = BIO_new_mem_buf(Buffer, Size);
	if (bio == NULL)
		ReportErrorAndExit(L"Internal error");
	Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (Cert == NULL)
		ReportErrorAndExit(L"'%s' is not a valid certificate", Path);

exit:
	BIO_free(bio);
	FreePool(Buffer);
	return Cert;
}

UINT32 GetCertificateLength(
	IN CONST VOID *Cert
)
{
	int len;

	len = i2d_X509((X509*)Cert, NULL);

	return len > 0 ? (UINT32)len : 0;
}

UINT32 GetDbxLength(
	IN CONST VOID *Dbx
)
{
	EFI_SIGNATURE_LIST* Esl = (EFI_SIGNATURE_LIST*)Dbx;

	return Esl->SignatureListSize;
}


VOID* ReadDbx(
	IN CONST CHAR16 *Path
)
{
	EFI_STATUS Status;
	EFI_FILE_HANDLE File = NULL;
	UINTN Size, HeaderSize;
	EFI_SIGNATURE_LIST* Esl = NULL;
	UINT8 *Buffer = NULL;

	Status = SimpleFileReadAllByPath(Path, &Size, (VOID**)&Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not read '%s'", Path);

	if (Size < sizeof(EFI_SIGNATURE_LIST))
		ReportErrorAndExit(L"Invalid DBX '%s'", Path);

	/* Check for unsigned ESL */
	Esl = (EFI_SIGNATURE_LIST*)Buffer;
	if (Esl->SignatureListSize == Size) {
		/* Don't free the ESL */
		Buffer = NULL;
		goto exit;
	}

	/* Check for signed ESL */
	Esl = NULL;
	if (Buffer[0x28] != 0x30 || Buffer[0x29] != 0x82)
		ReportErrorAndExit(L"Invalid DBX '%s'", Path);
	HeaderSize = (Buffer[0x2A] << 8) | Buffer[0x2B];
	if (HeaderSize + 0x30 + sizeof(EFI_SIGNATURE_LIST) > Size)
		ReportErrorAndExit(L"Invalid DBX '%s'", Path);
	Esl = AllocateZeroPool(Size - HeaderSize - 0x2C);
	if (Esl == NULL)
		ReportErrorAndExit(L"Could not allocate ESL");
	CopyMem(Esl, &Buffer[HeaderSize + 0x2C], Size - HeaderSize - 0x2C);
	SafeFree(Buffer);
	if (Esl->SignatureListSize != Size - HeaderSize - 0x2C) {
		SafeFree(Esl);
		ReportErrorAndExit(L"Invalid DBX '%s'", Path);
	}

exit:
	SimpleFileClose(File);
	FreePool(Buffer);

	return Esl;
}

VOID* GenerateCredentials(
	IN CONST CHAR8 *CertName,
	OUT VOID **GeneratedKey
)
{
	EFI_STATUS Status;
	EFI_TIME EfiTime = { 0 };
	INTN NumLeapDays = 0, i;
	EVP_PKEY *Key = NULL;
	X509 *Cert = NULL;
	
	/* Create a new RSA-2048 keypair */
	Key = EVP_RSA_gen(2048);
	if (Key == NULL)
		ReportOpenSSLErrorAndExit(L"EVP_RSA_gen()", EFI_PROTOCOL_ERROR);
	Print(L"Generated RSA keypair...\n");

	/* Create a new X509 certificate */
	Cert = X509_new();
	if (Cert == NULL)
		ReportOpenSSLErrorAndExit(L"X509_new()", EFI_PROTOCOL_ERROR);

	/* Set the certificate serial number */
	ASN1_INTEGER* sn = ASN1_INTEGER_new();
	// TODO: Derive a serial number from current date
	ASN1_INTEGER_set(sn, 0x12345678);
	if (!X509_set_serialNumber(Cert, sn))
		OSSL_REPORT_ERROR(L"X509_set_serialNumber()");
	ASN1_INTEGER_free(sn);

	/* Set version */
	X509_set_version(Cert, 2);

	/* Set usage for code signing as a Certification Authority */
	AddExtension(Cert, NID_basic_constraints, "critical,CA:TRUE");
	AddExtension(Cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	/* Set certificate validity to MOSBY_VALID_YEARS */
	ASN1_TIME* asn1time = ASN1_TIME_new();
	ASN1_TIME_set(asn1time, time(NULL));
	X509_set1_notBefore(Cert, asn1time);

	/* Because we want the certificate expiration to end on the same month & day as */
	/* the start date, we need to compute how many leap days there are in-between   */
	struct tm tm = { 0 };
	ASN1_TIME_to_tm(asn1time, &tm);
	for (i = 0; i < MOSBY_VALID_YEARS; i++) {
		EfiTime.Year = (UINT16)(1900 + tm.tm_year + i);
		if (IsLeapYear(&EfiTime)) {
			if (i != 0 && i != MOSBY_VALID_YEARS - 1)
				/* For year that are neither start or end year */
				NumLeapDays++;
			else if (i == 0 && tm.tm_mon < 2)
				/* Start year is leap year and start date is before March 1st */
				NumLeapDays++;
			else if (i == MOSBY_VALID_YEARS - 1 && tm.tm_mon > 1)
				/* End year is leap year and end date is after February 29th */
				NumLeapDays++;
		}
	}
	ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * (365 * MOSBY_VALID_YEARS + NumLeapDays) - 1));
	X509_set1_notAfter(Cert, asn1time);
	ASN1_TIME_free(asn1time);

	X509_NAME* name = X509_get_subject_name(Cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (UINT8*)CertName, -1, -1, 0);
	X509_set_issuer_name(Cert, name);

	/* Certify and sign with the private key we created */
	if (!X509_set_pubkey(Cert, Key))
		ReportOpenSSLErrorAndExit(L"X509_set_pubkey()", EFI_PROTOCOL_ERROR);
	if (!X509_sign(Cert, Key, EVP_sha256()))
		ReportOpenSSLErrorAndExit(L"X509_sign()", EFI_PROTOCOL_ERROR);
	/* Might as well verify the signature while we're at it */
	if (!X509_verify(Cert, Key))
		ReportOpenSSLError(L"X509_verify()");
	Print(L"Generated X509 certificate...\n");
	Status = EFI_SUCCESS;

exit:
	if (EFI_ERROR(Status)) {
		EVP_PKEY_free(Key);
		X509_free(Cert);
		return NULL;
	}

	/* If the caller doesn't need the generated key, discard it */
	if (GeneratedKey == NULL)
		EVP_PKEY_free(Key);
	else
		*GeneratedKey = Key;
	return Cert;
}

EFI_STATUS SaveCredentials(
	IN CONST VOID *Cert,
	IN CONST VOID *Key,
	IN CONST CHAR16 *BaseName
)
{
	EFI_STATUS Status;
	UINT8 *Buffer = NULL, *Ptr;
	CHAR16 Path[MAX_PATH];
	PKCS12* p12 = NULL;
	BIO *bio = NULL;
	UINT8 keyid[EVP_MAX_MD_SIZE];
	INTN Size;
	unsigned int keyidlen = 0;


	/* Generate PKCS#12 data */
	if (!X509_digest((X509*)Cert, EVP_sha256(), keyid, &keyidlen))
		ReportOpenSSLErrorAndExit(L"X509_digest()", EFI_PROTOCOL_ERROR);
	X509_keyid_set1((X509*)Cert, keyid, keyidlen);
	p12 = PKCS12_create(NULL, NULL, (EVP_PKEY*)Key, (X509*)Cert, NULL, NID_undef, NID_undef, 0, 0, 0);
	if (p12 == NULL)
		ReportOpenSSLErrorAndExit(L"PKCS12_create()", EFI_PROTOCOL_ERROR);
	Print(L"Generated PKCS#12 data...\n");

	/* Save .pfx */
	Ptr = Buffer;	/* i2d_###() modifies the pointer */
	Size = (INTN)i2d_PKCS12(p12, &Ptr);
	PKCS12_free(p12);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(L"i2d_PKCS12()", EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.pfx", BaseName);
	Status = SimpleFileWriteAllByPath(Path, (UINTN)Size, Buffer);
	OPENSSL_free(Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not write '%s'", Path);

	/* Save .cer */
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(L"BIO_new()", EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_X509(bio, (X509*)Cert))
		ReportOpenSSLErrorAndExit(L"PEM_write_bio_X509()", EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(L"BIO_get_mem_data()", EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.cer", BaseName);
	Status = SimpleFileWriteAllByPath(Path, (UINTN)Size, Buffer);
	BIO_free(bio);
	bio = NULL;

	/* Save .crt */
	Ptr = Buffer;	/* i2d_###() modifies the pointer */
	Size = (INTN)i2d_X509((X509*)Cert, &Ptr);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(L"i2d_X509()", EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.crt", BaseName);
	Status = SimpleFileWriteAllByPath(Path, (UINTN)Size, Buffer);
	OPENSSL_free(Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not write '%s'", Path);

	/* Save .pem */
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(L"BIO_new()", EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_PKCS8PrivateKey(bio, (EVP_PKEY*)Key, EVP_aes_256_cbc(), "", 0, NULL, NULL))
		ReportOpenSSLErrorAndExit(L"PEM_write_bio_PKCS8PrivateKey()", EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(L"BIO_get_mem_data()", EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.pem", BaseName);
	Status = SimpleFileWriteAllByPath(Path, (UINTN)Size, Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not write '%s'", Path);
	Print(L"Generated all certificate and key files...\n");
	Status = EFI_SUCCESS;

exit:
	BIO_free(bio);
	return Status;
}
