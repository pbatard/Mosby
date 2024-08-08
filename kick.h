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

#include <Uefi/UefiBaseType.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/TimeBaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

extern EFI_HANDLE gBaseImageHandle;
extern BOOLEAN gOptionSilent;

#define LISTFILE_NAME L"KickList.txt"

#define NUM_YEARS_VALID 30

/* Types of blobs this application is able to install */
#define FOREACH_BLOB(BLOB) \
	BLOB(PK)  \
	BLOB(KEK) \
	BLOB(DB) \
	BLOB(DBX) \
	BLOB(DBT) \
	BLOB(MOK) \
	BLOB(MAX_TYPES)

/* Ensure enum and corresponding strings are in sync */
#define GENERATE_ENUM(ENUM)     ENUM,
#define GENERATE_STRING(STRING) #STRING,

enum BLOB_TYPE {
	FOREACH_BLOB(GENERATE_ENUM)
};

STATIC inline CONST CHAR8 *BlobName(enum BLOB_TYPE Blob)
{
	STATIC CONST CHAR8 *Name[] = { FOREACH_BLOB(GENERATE_STRING) };

	return Name[Blob];
}

/* Maximum number of entries we can install for each blob type */
#define MAX_NUM_ENTRIES 16

/* */
typedef struct {
	UINTN NumEntries;
	CHAR8 *Path[MAX_NUM_ENTRIES];
	VOID *Blob[MAX_NUM_ENTRIES];
} INSTALLABLE_LIST;

typedef struct {
	CHAR8 *ListData;
	UINTN ListDataSize;
	INSTALLABLE_LIST List[MAX_TYPES];
} INSTALLABLE_COLLECTION;

/* FreePool() replacement, that NULLs the freed pointer. */
#define SafeFree(p)  do { FreePool(p); p = NULL; } while(0)

/* Check for a valid whitespace character */
STATIC __inline BOOLEAN IsWhiteSpace(CHAR8 c)
{
	return (c == ' ' || c == '\t');
}

#define ReportErrorAndExit(...) do { CHAR16 _ErrMsg[128];           \
	UnicodeSPrint(_ErrMsg, ARRAY_SIZE(_ErrMsg), __VA_ARGS__);       \
	ConsoleErrorBox(_ErrMsg); goto exit; } while(0)

#define OSSL_REPORT_ERROR(msg) ERR_print_errors_cb(OpenSSLErrorCallback, msg)

#define ReportOpenSSLError(msg) do {                                \
	ERR_print_errors_cb(OpenSSLErrorCallback, msg); } while(0)

#define ReportOpenSSLErrorAndExit(msg, err) do {                    \
	ERR_print_errors_cb(OpenSSLErrorCallback, msg), Status = err;   \
	goto exit; } while(0)

/**
  Convert a UTF-8 encoded string to a UCS-2 encoded string.

  @param[in]  Utf8String      A pointer to the input UTF-8 encoded string.
  @param[out] Ucs2String      A pointer to the output UCS-2 encoded string.
  @param[in]  Ucs2StringSize  The size of the Ucs2String buffer (in CHAR16).

  @retval EFI_SUCCESS            The conversion was successful.
  @retval EFI_INVALID_PARAMETER  One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL   The output buffer is too small to hold the result.
**/
EFI_STATUS Utf8ToUcs2(
	IN CONST CHAR8* Utf8String,
	OUT CHAR16* Ucs2String,
	IN CONST UINTN Ucs2StringSize
);
