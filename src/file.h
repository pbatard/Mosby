/*
 * Copyright 2012 James Bottomley <James.Bottomley@HansenPartnership.com>
 * Copyright 2024 Pete Batard <pete@akeo.ie>
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
#include <Guid/FileInfo.h>
#include <Library/UefiLib.h>

// None of the files we deal with should be larger than 1 MB.
#define MAX_FILE_SIZE (1024 * 1024)

// None of the paths we deal with should be longer than 512 codepoints.
#define MAX_PATH 512

EFI_STATUS SimpleFileOpenByHandle(
	IN CONST EFI_HANDLE Device,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_HANDLE *File,
	IN CONST UINT64 Mode
);

EFI_STATUS SimpleFileOpen(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_HANDLE *File,
	IN CONST UINT64 Mode
);

EFI_STATUS SimpleFileClose(
	IN CONST EFI_FILE_HANDLE File
);

EFI_STATUS SimpleDirReadAllByHandle(
	IN CONST EFI_FILE_HANDLE File,
	IN CONST CHAR16* Name,
	OUT EFI_FILE_INFO **Entries,
	OUT UINTN *Count
);

EFI_STATUS SimpleDirReadAll(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_INFO **Entries,
	OUT UINTN *Count
);

EFI_STATUS SimpleFileReadAll(
	IN CONST EFI_FILE_HANDLE File,
	OUT UINTN *Size,
	OUT VOID **Buffer
);

EFI_STATUS SimpleFileWriteAll(
	IN CONST EFI_FILE_HANDLE File,
	IN CONST UINTN Size,
	IN CONST VOID *Buffer
);

EFI_STATUS SimpleVolumeSelector(
	IN CONST CHAR16 **Title,
	OUT CHAR16 **Selected,
	OUT EFI_HANDLE *Handle
);

EFI_STATUS SimpleDirFilter(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	IN CONST CHAR16 *Filter,
	OUT CHAR16 ***Result,
	OUT UINTN *Count,
	OUT EFI_FILE_INFO **Entries
);

EFI_STATUS SimpleFileSelector(
	IN OUT EFI_HANDLE *Image,
	IN CONST CHAR16 **Title,
	IN CONST CHAR16 *Name,
	IN CONST CHAR16 *Filter,
	OUT CHAR16 **Result
);

EFI_STATUS SimpleFileReadAllByPath(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16* Path,
	OUT UINTN *Size,
	OUT VOID **Buffer
);

EFI_STATUS SimpleFileWriteAllByPath(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16* Path,
	IN CONST UINTN Size,
	IN CONST VOID *Buffer
);
