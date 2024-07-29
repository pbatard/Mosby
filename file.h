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

#include <Base.h>
#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Protocol/LoadedImage.h>
#include <Uefi/UefiBaseType.h>

// None of the files we deal with should be larger than 1 MB
#define MAX_FILE_SIZE (1024 * 1024)

EFI_STATUS GeneratePath(CHAR16* Name, EFI_LOADED_IMAGE_PROTOCOL *LoadedImage, EFI_DEVICE_PATH **Path, CHAR16 **PathName);
EFI_STATUS SimpleFileOpenByHandle(EFI_HANDLE Device, CHAR16 *Name, EFI_FILE_HANDLE *File, UINT64 Mode);
EFI_STATUS SimpleFileOpen(EFI_HANDLE Image, CHAR16 *Name, EFI_FILE_HANDLE *File, UINT64 Mode);
EFI_STATUS SimpleFileClose(EFI_FILE_HANDLE File);
EFI_STATUS SimpleDirReadAllByHandle(EFI_HANDLE Image, EFI_FILE_HANDLE File, CHAR16* Name, EFI_FILE_INFO **Entries, UINTN *Count);
EFI_STATUS SimpleDirReadAll(EFI_HANDLE Image, CHAR16 *Name, EFI_FILE_INFO **Entries, UINTN *Count);
EFI_STATUS SimpleFileReadAll(EFI_FILE_HANDLE File, UINTN *Size, VOID **Buffer);
EFI_STATUS SimpleFileWriteAll(EFI_FILE_HANDLE File, UINTN Size, VOID *Buffer);
EFI_STATUS SimpleVolumeSelector(CHAR16 **Title, CHAR16 **Selected, EFI_HANDLE *Handle);
EFI_STATUS SimpleDirFilter(EFI_HANDLE Image, CHAR16 *Name, CHAR16 *Filter, CHAR16 ***Result, UINTN *Count, EFI_FILE_INFO **Entries);
EFI_STATUS SimpleFileSelector(EFI_HANDLE *Image, CHAR16 **Title, CHAR16 *Name, CHAR16 *Filter, CHAR16 **Result);
EFI_STATUS ShellWriteAll(CONST CHAR16* Path, CONST VOID* Buffer, CONST UINTN Size);
EFI_STATUS ShellReadAll(CONST CHAR16* Path, VOID** Buffer, UINTN* Size);
