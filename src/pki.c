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
#include "random.h"

#include <Guid/ImageAuthentication.h>
#include <Guid/WinCertificate.h>

#include <Protocol/LoadedImage.h>

/* OpenSSL */
#undef _WIN32
#undef _WIN64
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define ReportOpenSSLErrorAndExit(Error) do { CHAR16 _ErrMsg[128];  \
	UnicodeSPrint(_ErrMsg, ARRAY_SIZE(_ErrMsg), L"%a:%d ",          \
		__FILE__, __LINE__); Status = Error;                        \
	ERR_print_errors_cb(OpenSSLErrorCallback, _ErrMsg); goto exit;  \
	} while(0)

STATIC EFI_TIME mTime = { 0 };

/* For OpenSSL error reporting */
STATIC int OpenSSLErrorCallback(
	CONST CHAR8 *AsciiString,
	UINTN Len,
	VOID *UserData
)
{
	RecallPrint(L"%s %a\n", (CHAR16*)UserData, AsciiString);
	return 0;
}

EFI_STATUS InitializePki(
	IN CONST BOOLEAN TestMode
)
{
	CONST CHAR8 DefaultSeed[] = __DATE__ __TIME__;
	EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
	CHAR16 *Seed = NULL;
	EFI_STATUS Status;
	OSSL_PROVIDER *prov;

	Status = gRT->GetTime(&mTime, NULL);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Failed to get current time: %r\n", Status);

	// SetVariable() *will* fail with "Security Violation" unless you
	// explicitly zero these before calling CreateTimeBasedPayload()
	mTime.Nanosecond = 0;
	mTime.TimeZone = 0;
	mTime.Daylight = 0;

	// See if the default RNG works. If not try to use the UEFI platform's RNG.
	if (!RAND_status()) {
		prov = uefi_rand_init(NULL, TestMode);
		if (prov == NULL || !RAND_status()) {
			Status = EFI_UNSUPPORTED;
			ReportErrorAndExit(L"Failed to access a random number generator\n");
		}
	}

	// Try to use the loaded image's DevicePath (of the DeviceHandle) as our seed since
	// it is both unique enough and *not* time-based (therefore harder to guess).
	// We convert it to text form first, as a DevicePath binary on its own is typically
	// just a short set of references to existing system DevicePath elements.
	if (gBS->HandleProtocol(gBaseImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage) == EFI_SUCCESS)
		Seed = ConvertDevicePathToText(DevicePathFromHandle(LoadedImage->DeviceHandle), FALSE, FALSE);

	if (Seed != NULL && Seed[0] != L'\0') {
		RAND_seed(Seed, StrLen(Seed));
	} else {
		RecallPrint(L"Notice: Using hardcoded default random seed\n");
		RAND_seed(DefaultSeed, sizeof(DefaultSeed));
	}
	FreePool(Seed);
	Status = RAND_status() ? EFI_SUCCESS : EFI_UNSUPPORTED;

exit:
	return Status;
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
		ReportOpenSSLErrorAndExit(EFI_UNSUPPORTED);

	if (!X509_add_ext(Cert, ex, -1))
		ReportOpenSSLErrorAndExit(EFI_ACCESS_DENIED);

exit:
	X509_EXTENSION_free(ex);
	return Status;
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
	UINT8 Hash[SHA_DIGEST_LENGTH] = { 0 };
	time_t Epoch;
	unsigned int Len;

	// Create a new RSA-2048 keypair
	Key = EVP_RSA_gen(2048);
	if (Key == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);

	// Create a new X509 certificate
	Cert = X509_new();
	if (Cert == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);

	// Set the certificate serial number
	ASN1_INTEGER* sn = ASN1_INTEGER_new();
	Epoch = time(NULL);
	ASN1_INTEGER_set(sn, Epoch);
	if (!X509_set_serialNumber(Cert, sn))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	ASN1_INTEGER_free(sn);

	// Set version
	X509_set_version(Cert, 2);

	// Set usage for code signing as a Certification Authority
	AddExtension(Cert, NID_basic_constraints, "critical,CA:TRUE");
	AddExtension(Cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");

	// Set subject key identifier
	ASN1_OCTET_STRING *Skid = ASN1_OCTET_STRING_new();
	if (Skid == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	X509_pubkey_digest(Cert, EVP_sha1(), Hash, &Len);
	ASN1_OCTET_STRING_set(Skid, Hash, SHA_DIGEST_LENGTH);
	X509_add1_ext_i2d(Cert, NID_subject_key_identifier, Skid, 0, X509V3_ADD_DEFAULT);
	ASN1_OCTET_STRING_free(Skid);

	// Set certificate validity to MOSBY_VALID_YEARS
	ASN1_TIME* asn1time = ASN1_TIME_new();
	ASN1_TIME_set(asn1time, Epoch);
	X509_set1_notBefore(Cert, asn1time);

	// Because we want the certificate expiration to end on the same month & day as
	// the start date, we need to compute how many leap days there are in-between
	struct tm tm = { 0 };
	ASN1_TIME_to_tm(asn1time, &tm);
	for (i = 0; i < MOSBY_VALID_YEARS; i++) {
		EfiTime.Year = (UINT16)(1900 + tm.tm_year + i);
		if (IsLeapYear(&EfiTime)) {
			if (i != 0 && i != MOSBY_VALID_YEARS - 1)
				// For years that are neither start or end year
				NumLeapDays++;
			else if (i == 0 && tm.tm_mon < 2)
				// Start year is leap year and start date is before March 1st
				NumLeapDays++;
			else if (i == MOSBY_VALID_YEARS - 1 && tm.tm_mon > 1)
				// End year is leap year and end date is after February 29th
				NumLeapDays++;
		}
	}
	ASN1_TIME_set(asn1time, time(NULL) + (60 * 60 * 24 * (365 * MOSBY_VALID_YEARS + NumLeapDays) - 1));
	X509_set1_notAfter(Cert, asn1time);
	ASN1_TIME_free(asn1time);

	X509_NAME* name = X509_get_subject_name(Cert);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (UINT8*)CertName, -1, -1, 0);
	X509_set_issuer_name(Cert, name);

	// Certify and sign with the private key we created
	if (!X509_set_pubkey(Cert, Key))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	if (!X509_sign(Cert, Key, EVP_sha256()))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	// Might as well verify the signature while we're at it
	if (!X509_verify(Cert, Key))
		RecallPrint(L"WARNING: Failed to verify autogenerated X509 credentials\n");
	Status = EFI_SUCCESS;

exit:
	if (EFI_ERROR(Status)) {
		EVP_PKEY_free(Key);
		X509_free(Cert);
		return NULL;
	}

	// If the caller doesn't need the generated key, discard it
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
	UINT8 KeyId[EVP_MAX_MD_SIZE];
	INTN Size;
	unsigned int KeyIdLen = 0;

	// Generate PKCS#12 data
	if (!X509_digest((X509*)Cert, EVP_sha256(), KeyId, &KeyIdLen))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	X509_keyid_set1((X509*)Cert, KeyId, KeyIdLen);
	p12 = PKCS12_create(NULL, NULL, (EVP_PKEY*)Key, (X509*)Cert, NULL, NID_undef, NID_undef, 0, 0, 0);
	if (p12 == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);

	// Save certificate and key as .pfx
	Size = (INTN)i2d_PKCS12(p12, NULL);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	Buffer = AllocateZeroPool(Size);
	if (Buffer == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		ReportErrorAndExit(L"Failed to allocate PFX buffer\n");
	}
	Ptr = Buffer;	// i2d_###() modifies the pointer...
	Size = (INTN)i2d_PKCS12(p12, &Ptr);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.pfx", BaseName);
	Status = SimpleFileWriteAllByPath(gBaseImageHandle, Path, (UINTN)Size, Buffer);
	SafeFree(Buffer);
	if (EFI_ERROR(Status))
		goto exit;

	// Save certificate as base64 encoded .crt
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_X509(bio, (X509*)Cert))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.crt", BaseName);
	Status = SimpleFileWriteAllByPath(gBaseImageHandle, Path, (UINTN)Size, Buffer);
	BIO_free(bio);
	bio = NULL;

#if 0
	// Save certificate as DER encoded .cer
	Size = (INTN)i2d_X509(Cert, NULL);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	Buffer = AllocateZeroPool(Size);
	if (Buffer == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		ReportErrorAndExit(L"Failed to allocate DER buffer\n");
	}
	Ptr = Buffer;	// i2d_###() modifies the pointer
	Size = (INTN)i2d_X509(Cert, &Ptr);
	if (Size < 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.cer", BaseName);
	Status = SimpleFileWriteAllByPath(gBaseImageHandle, Path, (UINTN)Size, Buffer);
	SafeFree(Buffer);
	if (EFI_ERROR(Status))
		goto exit;
#endif

	// Save key as as base64 encoded .pem
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(EFI_OUT_OF_RESOURCES);
	if (!PEM_write_bio_PKCS8PrivateKey(bio, (EVP_PKEY*)Key, EVP_aes_256_cbc(), "", 0, NULL, NULL))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	Size = (INTN)BIO_get_mem_data(bio, &Buffer);
	if (Size <= 0)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	UnicodeSPrint(Path, ARRAY_SIZE(Path), L"%s.pem", BaseName);
	Status = SimpleFileWriteAllByPath(gBaseImageHandle, Path, (UINTN)Size, Buffer);
	if (EFI_ERROR(Status))
		goto exit;
	Status = EFI_SUCCESS;

exit:
	PKCS12_free(p12);
	BIO_free(bio);
	return Status;
}

VOID FreeCredentials(
	IN CONST VOID *Cert,
	IN CONST VOID *Key
)
{
	X509_free((X509*)Cert);
	EVP_PKEY_free((EVP_PKEY*)Key);
}

EFI_STATUS CertToAuthVar(
	CONST IN VOID *Cert,
	OUT AUTHENTICATED_VARIABLE *Variable
)
{
	EFI_STATUS Status = EFI_INVALID_PARAMETER;
	EFI_SIGNATURE_LIST *Esl = NULL;
	EFI_SIGNATURE_DATA *Data = NULL;
	INTN Size;
	UINT8 *Ptr;
	EFI_GUID OwnerGuid;
	UINT8 Sha1[SHA_DIGEST_LENGTH] = { 0 };

	if (Cert == NULL || Variable == NULL)
		return EFI_INVALID_PARAMETER;

	Size = (INTN)i2d_X509((X509*)Cert, NULL);
	if (Size <= 0)
		goto exit;
	Esl = AllocateZeroPool(sizeof(EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size);
	if (Esl == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		ReportErrorAndExit(L"Failed to allocate ESL\n");
	}

	CopyGuid(&Esl->SignatureType, &gEfiCertX509Guid);
	Esl->SignatureListSize = sizeof(EFI_SIGNATURE_LIST) + sizeof (EFI_SIGNATURE_DATA) - 1 + Size;
	Esl->SignatureSize = sizeof(EFI_SIGNATURE_DATA) - 1 + Size;

	Data = (EFI_SIGNATURE_DATA*)&Esl[1];
	Ptr = &Data->SignatureData[0];
	i2d_X509((X509*)Cert, &Ptr);

	// Derive the SignatureOwner GUID from the SHA-1 Thumbprint
	SHA1(&Data->SignatureData[0], Size, Sha1);

	// Reorder, to have the GUID read in the same order as the byte data
	OwnerGuid.Data1 = SwapBytes32(((UINT32*)Sha1)[0]);
	OwnerGuid.Data2 = SwapBytes16(((UINT16*)Sha1)[2]);
	OwnerGuid.Data3 = SwapBytes16(((UINT16*)Sha1)[3]);
	CopyMem(&OwnerGuid.Data4, &Sha1[8], 8);
	CopyGuid(&Data->SignatureOwner, &OwnerGuid);

	Variable->Size = Esl->SignatureListSize;
	Variable->Data = (EFI_VARIABLE_AUTHENTICATION_2*)Esl;
	// NB: CreateTimeBasedPayload() frees the input buffer before replacing it
	Status = CreateTimeBasedPayload(&Variable->Size, (UINT8**)&Variable->Data, &mTime);
	if (EFI_ERROR(Status)) {
		FreePool(Esl);
		ReportErrorAndExit(L"Failed to create time-based data payload: %r\n", Status);
	}

exit:
	if (EFI_ERROR(Status)) {
		Variable->Size = 0;
		Variable->Data = NULL;
	}
	return Status;
}

EFI_STATUS LoadToAuthVar(
	IN CONST CHAR16 *Path,
	OUT AUTHENTICATED_VARIABLE* Variable
)
{
	EFI_STATUS Status;
	UINTN Size, HeaderSize;
	UINT8 *Buffer = NULL;
	CONST UINT8 *Ptr;
	EFI_SIGNATURE_LIST *Esl = NULL;
	EFI_VARIABLE_AUTHENTICATION_2 *SignedEsl = NULL;
	BIO *bio = NULL;

	if (Path == NULL || Variable == NULL)
		return EFI_INVALID_PARAMETER;

	if (!SimpleFileExistsByPath(gBaseImageHandle, Path))
		ReportErrorAndExit(L"File '%s' does not exist\n", Path);

	Status = SimpleFileReadAllByPath(gBaseImageHandle, Path, &Size, (VOID**)&Buffer);
	if (EFI_ERROR(Status))
		goto exit;

	Status = EFI_INVALID_PARAMETER;
	if (Size < sizeof(EFI_SIGNATURE_LIST))
		ReportErrorAndExit(L"'%s' is too small to be a valid certificate or signature list\n", Path);

	// Check for signed ESL (PKCS#7 only)
	SignedEsl = (EFI_VARIABLE_AUTHENTICATION_2*)Buffer;
	if (Size > sizeof(EFI_VARIABLE_AUTHENTICATION_2) &&
		SignedEsl->AuthInfo.Hdr.dwLength < Size &&
		SignedEsl->AuthInfo.Hdr.wRevision == 0x0200 &&
		SignedEsl->AuthInfo.Hdr.wCertificateType == WIN_CERT_TYPE_EFI_GUID &&
		CompareGuid(&SignedEsl->AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
		if (SignedEsl->AuthInfo.CertData[0] != 0x30 || SignedEsl->AuthInfo.CertData[1] != 0x82)
			ReportErrorAndExit(L"Invalid signed ESL '%s'\n", Path);
		HeaderSize = (SignedEsl->AuthInfo.CertData[2] << 8) | SignedEsl->AuthInfo.CertData[3];
		HeaderSize += OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo);
		HeaderSize += OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
		HeaderSize += 4;	// For the 4 extra bytes above
		if (HeaderSize + sizeof(EFI_SIGNATURE_LIST) > Size)
			ReportErrorAndExit(L"Invalid signed ESL '%s'\n", Path);
		Esl = (EFI_SIGNATURE_LIST*)&Buffer[HeaderSize];
		if (Esl->SignatureListSize != Size - HeaderSize)
			ReportErrorAndExit(L"Invalid signed ESL '%s'\n", Path);
		Buffer = NULL;	// Don't free our data
		Variable->Size = Size;
		Variable->Data = SignedEsl;
		Status = EFI_SUCCESS;
		goto exit;
	}

	// Check for a DER encoded X509 certificate
	Ptr = Buffer;	// d2i_###() modifies the pointer
	Status = CertToAuthVar(d2i_X509(NULL, &Ptr, Size), Variable);
	if (Status == EFI_SUCCESS)
		goto exit;

	// Check for a PEM encoded X509 certificate
	bio = BIO_new_mem_buf(Buffer, Size);
	if (bio == NULL)
		ReportErrorAndExit(L"Failed to allocate X509 buffer\n");
	Status = CertToAuthVar(PEM_read_bio_X509(bio, NULL, NULL, NULL), Variable);
	if (Status == EFI_SUCCESS)
		goto exit;

	// Check for an unsigned ESL
	Esl = (EFI_SIGNATURE_LIST*)Buffer;
	if (Esl->SignatureListSize == Size) {
		Variable->Size = Esl->SignatureListSize;
		Variable->Data = (EFI_VARIABLE_AUTHENTICATION_2*)Esl;
		// NB: CreateTimeBasedPayload() frees the input buffer before replacing it
		Status = CreateTimeBasedPayload(&Variable->Size, (UINT8**)&Variable->Data, &mTime);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to create time-based data payload: %r\n", Status);
		Buffer = NULL;	// CreateTimeBasedPayload freed Esl = Buffer already
	}

	ReportErrorAndExit(L"Failed to process '%s'\n", Path);

exit:
	BIO_free(bio);
	FreePool(Buffer);
	if (EFI_ERROR(Status)) {
		Variable->Size = 0;
		Variable->Data = NULL;
	}
	return Status;
}

EFI_STATUS SignToAuthVar(
	IN CONST CHAR16 *VariableName,
	IN CONST EFI_GUID *VendorGuid,
	IN CONST UINT32 Attributes,
	IN OUT AUTHENTICATED_VARIABLE *Variable,
	IN CONST VOID *Cert,
	IN CONST VOID *Key
)
{
	CONST INTN PAYLOAD = 4;
	CONST int flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOATTR;
	CONST struct {
		UINT8 *Ptr;
		UINTN Size;
	} SignableElement[5] = {
		{ (UINT8*)VariableName, StrLen(VariableName) * sizeof(CHAR16) },
		{ (UINT8*)VendorGuid, sizeof(EFI_GUID) },
		{ (UINT8*)&Attributes, sizeof(Attributes) },
		{ (UINT8*)&Variable->Data->TimeStamp, sizeof(EFI_TIME) },
		{ &(((UINT8*)Variable->Data)[OFFSET_OF_AUTHINFO2_CERT_DATA]), Variable->Size - OFFSET_OF_AUTHINFO2_CERT_DATA }
	};
	EFI_STATUS Status = EFI_INVALID_PARAMETER;
	UINT8 *SignData = NULL;
	EFI_VARIABLE_AUTHENTICATION_2 *SignedVariable = NULL;
	UINT8 *Payload, *Ptr;
	UINTN i, SignDataSize, SignatureSize, Offset;
	BIO *bio;
	PKCS7 *p7;

	if (Variable->Size < OFFSET_OF_AUTHINFO2_CERT_DATA)
		ReportErrorAndExit(L"Variable to sign (%d) is too small (%d)\n", Variable->Size, OFFSET_OF_AUTHINFO2_CERT_DATA);

	// We can only sign for PKCS#7
	if (!CompareGuid(&Variable->Data->AuthInfo.CertType, &gEfiCertPkcs7Guid))
		ReportErrorAndExit(L"Variable to sign is not PKCS#7\n");

	// Make sure we are dealing with a variable that does NOT already contain a signature
	if (Variable->Data->AuthInfo.Hdr.dwLength != OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData))
		ReportErrorAndExit(L"Variable is already signed\n");

	// Construct the data buffer to sign
	SignDataSize = 0;
	for (i = 0; i < ARRAY_SIZE(SignableElement); i++)
		SignDataSize += SignableElement[i].Size;
	SignData = AllocateZeroPool(SignDataSize);
	if (SignData == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		ReportErrorAndExit(L"Failed to allocate buffer to sign\n");
	}
	Offset = 0;
	for (i = 0; i < ARRAY_SIZE(SignableElement); i++) {
		CopyMem(&SignData[Offset], SignableElement[i].Ptr, SignableElement[i].Size);
		Offset += SignableElement[i].Size;
	}

	// Sign the constructed data buffer
	bio = BIO_new_mem_buf(SignData, SignDataSize);
	if (bio == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);

	p7 = PKCS7_sign(NULL, NULL, NULL, bio, flags | PKCS7_PARTIAL);
	if (p7 == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	if (PKCS7_sign_add_signer(p7, (X509*)Cert, (EVP_PKEY*)Key, EVP_get_digestbyname("SHA256"), flags) == NULL)
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	if (!PKCS7_final(p7, bio, flags))
		ReportOpenSSLErrorAndExit(EFI_PROTOCOL_ERROR);
	SignatureSize = i2d_PKCS7(p7, NULL);

	// Create the signed variable
	SignedVariable = AllocateZeroPool(Variable->Size + SignatureSize);
	if (SignedVariable == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		ReportErrorAndExit(L"Failed to allocate buffer for signed variable\n");
	}
	CopyMem(SignedVariable, Variable->Data, OFFSET_OF_AUTHINFO2_CERT_DATA);
	SignedVariable->AuthInfo.Hdr.dwLength = OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) + SignatureSize;
	Ptr = SignedVariable->AuthInfo.CertData;
	SignatureSize = i2d_PKCS7(p7, &Ptr);
	Payload = (UINT8*)SignedVariable;
	Payload = &Payload[OFFSET_OF_AUTHINFO2_CERT_DATA + SignatureSize];
	CopyMem(Payload, SignableElement[PAYLOAD].Ptr, SignableElement[PAYLOAD].Size);

	// Update the variable passed as parameter with the signed one
	FreePool(Variable->Data);
	Variable->Data = SignedVariable;
	Variable->Size = Variable->Size + SignatureSize;

	Status = EFI_SUCCESS;

exit:
	FreePool(SignData);
	return Status;
}
