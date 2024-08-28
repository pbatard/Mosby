/*
 * MSSB (More Secure Secure Boot -- "Mosby")
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

#pragma once

#include <Base.h>
#include <Uefi.h>

#include <Uefi/UefiBaseType.h>
#include <Guid/ImageAuthentication.h>
#include <UefiSecureBoot.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/SecureBootVariableLib.h>
#include <Library/TimeBaseLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "../config.h"

/* Global Image Handle for the current executable */
extern EFI_HANDLE gBaseImageHandle;

/* Types of "keys" this application is able to install */
enum {
	PK,
	KEK,
	DB,
	DBX,
	DBT,
	MOK,
	MAX_TYPES
};

/* Structure containing the list of "keys" for a specific type */
typedef struct {
	UINTN NumEntries;
	CHAR16 *Path[MOSBY_MAX_ENTRIES];
	EFI_SIGNATURE_LIST *Esl[MOSBY_MAX_ENTRIES];
} INSTALLABLE_LIST;

/* Structure containing the collection of all the lists */
typedef struct {
	CHAR8 *ListData;
	UINTN ListDataSize;
	INSTALLABLE_LIST List[MAX_TYPES];
} INSTALLABLE_COLLECTION;

/* FreePool() replacement, that NULLs the freed pointer. */
#define SafeFree(p)  do { FreePool(p); p = NULL; } while(0)

/* Error reporting macro */
#define ReportErrorAndExit(...) do { Print(__VA_ARGS__); goto exit; } while(0)
