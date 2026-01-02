/*
 * MSSB (More Secure Secure Boot -- "Mosby")
 * Copyright © 2024-2026 Pete Batard <pete@akeo.ie>
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

#include <Base.h>
#include <Uefi.h>

#include <Guid/ImageAuthentication.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Uefi/UefiBaseType.h>
#include <UefiSecureBoot.h>
#include <Library/AuthVariableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PlatformPKProtectionLib.h>
#include <Library/PrintLib.h>
#include <Library/SecureBootVariableLib.h>
#include <Library/TimeBaseLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

/* Maximum number of binaries we can install */
#define MOSBY_MAX_LIST_SIZE         64

/* Number of years certs created by this application are valid for */
#define MOSBY_VALID_YEARS           30

/* Base name for the Secure Boot signing credentials we create */
#define MOSBY_CRED_NAME             "MosbyKey"

/* Short name of the current architecture the application runs on */
#if defined(_M_X64) || defined(__x86_64__)
	#define ARCH_EXT                L"x64"
#elif defined(_M_IX86) || defined(__i386__)
	#define ARCH_EXT                L"ia32"
#elif defined (_M_ARM64) || defined(__aarch64__)
	#define ARCH_EXT                L"aa64"
#elif defined (_M_ARM) || defined(__arm__)
	#define ARCH_EXT                L"arm"
#elif defined(_M_RISCV64) || (defined(__riscv) && (__riscv_xlen == 64))
	#define ARCH_EXT                L"riscv64"
#elif defined (_M_LOONGARCH64) || defined(__loongarch64)
	#define ARCH_EXT                L"loongarch64"
#else
#	error Unsupported architecture
#endif

/* WCHAR expansion macros */
#define _WIDEN(s)                   L ## s
#define WIDEN(s)                    _WIDEN(s)

/* FreePool() replacement, that NULLs the freed pointer. */
#define SafeFree(p)                 do { FreePool(p); p = NULL; } while(0)

/* Variable attributes */
#define UEFI_VAR_NV_BS              (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define UEFI_VAR_NV_BS_AP           (UEFI_VAR_NV_BS | EFI_VARIABLE_APPEND_WRITE)
#define UEFI_VAR_NV_BS_RT           (UEFI_VAR_NV_BS | EFI_VARIABLE_RUNTIME_ACCESS)
#define UEFI_VAR_NV_BS_RT_AT        (UEFI_VAR_NV_BS_RT | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
#define UEFI_VAR_NV_BS_RT_AT_AP     (UEFI_VAR_NV_BS_RT_AT | EFI_VARIABLE_APPEND_WRITE)

/* Flags */
#define USE_BUFFER                  0x01
#define NO_INSTALL                  0x02
#define ALLOW_UPDATE                0x04
#define USE_MICROSOFT_GUID          0x08

/* Exclusive sets */
#define MOSBY_SET1                  0x01
#define MOSBY_SET2                  0x02

/* Global Image Handle for the current executable */
extern EFI_HANDLE gBaseImageHandle;

/* Microsoft's EFI VendorGUID */
extern EFI_GUID gEfiMicrosoftGuid;

/* Mosby's EFI VendorGUID */
extern EFI_GUID gEfiMosbyGuid;

/* Types of Secure Boot variables this application is able to install */
enum {
	PK,
	KEK,
	DB,
	DBX,
	DBT,
	MOK,
	SBAT,
	SSPU,
	SSPV,
	MAX_TYPES
};

/* Mosby buffer struct */
typedef struct {
	UINTN Size;
	UINT8 *Data;
} MOSBY_BUFFER;

/* Mosby Secure Boot variable struct */
typedef struct {
	UINTN Size;
	EFI_VARIABLE_AUTHENTICATION_2 *Data;
} MOSBY_VARIABLE;

/* Mosby installable entry */
typedef struct {
	UINT8 Type;
	UINT8 Flags;
	UINT8 Set;
	UINT32 Attrs;
	CHAR16 *Path;
	CHAR8 *Url; 
	CHAR8 *Description;
	MOSBY_BUFFER Buffer;
	MOSBY_VARIABLE Variable;
} MOSBY_ENTRY;

/* The list of all installable entries */
typedef struct {
	UINTN Size;
	MOSBY_ENTRY Entry[MOSBY_MAX_LIST_SIZE];
} MOSBY_LIST;

EFI_STATUS InitializeList(
	IN OUT MOSBY_LIST *List
);

EFI_STATUS PrintSystemInfo(VOID);
