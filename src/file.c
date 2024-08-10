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
#include "mosby.h"
#include "console.h"
#include "file.h"

#include <Guid/FileSystemInfo.h>
#include <Guid/FileSystemVolumeLabelInfo.h>
#include <Protocol/LoadedImage.h>
#include <Library/ShellLib.h>

STATIC EFI_STATUS GeneratePath(
	IN CONST CHAR16* Name,
	IN CONST EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
	OUT EFI_DEVICE_PATH **Path,
	OUT CHAR16 **PathName)
{
	UINTN PathLen;
	EFI_STATUS Status = EFI_SUCCESS;
	CHAR16 *DevicePathString, *Found = NULL;
	INTN i;

	DevicePathString = ConvertDevicePathToText(LoadedImage->FilePath, TRUE, TRUE);

	for (i = 0; i < StrLen(DevicePathString); i++) {
		if (DevicePathString[i] == '/')
			DevicePathString[i] = '\\';
		if (DevicePathString[i] == '\\')
			Found = &DevicePathString[i];
	}
	if (!Found) {
		PathLen = 0;
	} else {
		while (*(Found - 1) == '\\')
			--Found;
		*Found = '\0';
		PathLen = StrLen(DevicePathString);
	}

	if (Name[0] != '\\')
		PathLen++;

	PathLen += StrLen(Name) + 1;
	*PathName = AllocateZeroPool(PathLen * sizeof(CHAR16));

	if (!*PathName) {
		Print(L"Failed to allocate path buffer\n");
		Status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	StrCpyS(*PathName, PathLen, DevicePathString);

	if (Name[0] != '\\')
		StrCatS(*PathName, PathLen, L"\\");
	StrCatS(*PathName, PathLen, Name);

	*Path = FileDevicePath(LoadedImage->DeviceHandle, *PathName);

error:
	FreePool(DevicePathString);

	return Status;
}

EFI_STATUS SimpleFileOpenByHandle(
	IN CONST EFI_HANDLE DeviceHandle,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_HANDLE *File,
	IN CONST UINT64 Mode
)
{
	EFI_STATUS Status;
	EFI_FILE_IO_INTERFACE *Drive;
	EFI_FILE_HANDLE Root;

	Status = gBS->HandleProtocol(DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&Drive);

	if (EFI_ERROR(Status)) {
		Print(L"Unable to find simple file protocol: %r\n", Status);
		goto error;
	}

	Status = Drive->OpenVolume(Drive, &Root);

	if (EFI_ERROR(Status)) {
		Print(L"Failed to open drive volume: %R\n", Status);
		goto error;
	}

	Status = Root->Open(Root, File, (CHAR16*)Name, Mode, 0);

error:
	return Status;
}

EFI_STATUS SimpleFileOpen(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_HANDLE *File,
	IN CONST UINT64 Mode
)
{
	EFI_STATUS Status;
	EFI_HANDLE Device;
	EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
	EFI_DEVICE_PATH *LoadPath = NULL;
	CHAR16 *PathName = NULL;

	Status = gBS->HandleProtocol(Image, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);

	if (EFI_ERROR(Status))
		return SimpleFileOpenByHandle(Image, Name, File, Mode);

	Status = GeneratePath(Name, LoadedImage, &LoadPath, &PathName);

	if (EFI_ERROR(Status)) {
		Print(L"Unable to generate load path for %s\n", Name);
		return Status;
	}

	Device = LoadedImage->DeviceHandle;

	Status = SimpleFileOpenByHandle(Device, PathName, File, Mode);

	FreePool(PathName);
	FreePool(LoadPath);

	return Status;
}

EFI_STATUS SimpleFileClose(
	IN CONST EFI_FILE_HANDLE File
)
{
	return (File == NULL) ? EFI_SUCCESS : File->Close(File);
}

EFI_STATUS SimpleDirReadAllByHandle(
	IN CONST EFI_FILE_HANDLE File,
	IN CONST CHAR16* Name,
	OUT EFI_FILE_INFO **Entries,
	OUT UINTN *Count
)
{
	EFI_STATUS Status;
	INTN i;
	UINT8 Buffer[4096], *Ptr;
	UINTN Size = sizeof(Buffer), Len;
	EFI_FILE_INFO *Info = (VOID *)Buffer;
	
	Status = File->GetInfo(File, &gEfiFileInfoGuid, &Size, Info);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file info\n");
		goto out;
	}
	if ((Info->Attribute & EFI_FILE_DIRECTORY) == 0) {
		Print(L"Not a directory %s\n", Name);
		Status = EFI_INVALID_PARAMETER;
		goto out;
	}
	Size = 0;
	*Count = 0;
	for (;;) {
		Len = sizeof(Buffer);
		Status = File->Read(File, &Len, Buffer);
		if (EFI_ERROR(Status) || Len == 0)
			break;
		(*Count)++;
		Size += Len;
	}
	File->SetPosition(File, 0);

	Ptr = AllocateZeroPool(Size);
	*Entries = (EFI_FILE_INFO *)Ptr;
	if (*Entries == NULL)
		return EFI_OUT_OF_RESOURCES;
	for (i = 0; i < *Count; i++) {
		Len = Size;
		File->Read(File, &Len, Ptr);
		Ptr += Len;
		Size -= Len;
	}
	Status = EFI_SUCCESS;
out:
	SimpleFileClose(File);
	if (EFI_ERROR(Status) && *Entries != NULL) {
		FreePool(*Entries);
		*Entries = NULL;
	}
	return Status;
}

EFI_STATUS SimpleDirReadAll(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	OUT EFI_FILE_INFO **Entries,
	OUT UINTN *Count
)
{
	EFI_FILE_HANDLE File;
	EFI_STATUS Status;

	Status = SimpleFileOpen(Image, Name, &File, EFI_FILE_MODE_READ);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to open file %s: %r\n", Name, Status);
		return Status;
	}

	return SimpleDirReadAllByHandle(File, Name, Entries, Count);
}

EFI_STATUS SimpleFileReadAll(
	IN CONST EFI_FILE_HANDLE File,
	OUT UINTN *Size,
	OUT VOID **Buffer
)
{
	EFI_STATUS Status;
	EFI_FILE_INFO *Info;
	UINT8 Buf[1024];

	*Size = sizeof(Buf);
	Info = (VOID *)Buf;

	Status = File->GetInfo(File, &gEfiFileInfoGuid, Size, Info);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get file info\n");
		return Status;
	}

	*Size = Info->FileSize;

	if (*Size > MAX_FILE_SIZE) {
		Print(L"File size is too large\n");
		return EFI_UNSUPPORTED;
	}

	/* Might use memory mapped, so align up to nearest page */
	/* Also + 1 so the data is always NUL terminated */
	*Buffer = AllocateZeroPool(ALIGN_VALUE(*Size + 1, 4096));
	if (*Buffer == NULL) {
		Print(L"Failed to allocate buffer of size %d\n", *Size);
		return EFI_OUT_OF_RESOURCES;
	}
	Status = File->Read(File, Size, *Buffer);

	return Status;
}

EFI_STATUS SimpleFileWriteAll(
	IN CONST EFI_FILE_HANDLE File,
	IN CONST UINTN Size,
	IN CONST VOID *Buffer
)
{
	return File->Write(File, (UINTN*)&Size, (VOID*)Buffer);
}

EFI_STATUS SimpleVolumeSelector(
	IN CONST CHAR16 **Title,
	OUT CHAR16 **Selected,
	OUT EFI_HANDLE *Handle
)
{
	UINTN Count, i;
	EFI_HANDLE *VolumeHandles = NULL;
	EFI_STATUS Status;
	CHAR16 **Entries;
	INTN Val;

	gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &Count, &VolumeHandles);

	if (Count == 0 || VolumeHandles == NULL)
		return EFI_NOT_FOUND;

	Entries = AllocateZeroPool(sizeof(CHAR16 *) * (Count + 1));
	if (Entries == NULL)
		return EFI_OUT_OF_RESOURCES;

	for (i = 0; i < Count; i++) {
		UINT8 Buffer[4096];
		UINTN Size = sizeof(Buffer);
		EFI_FILE_SYSTEM_INFO *FsInfo = (VOID *)Buffer;
		EFI_FILE_HANDLE Root;
		CHAR16 *Name;
		EFI_FILE_IO_INTERFACE *Drive;

		Status = gBS->HandleProtocol(VolumeHandles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&Drive);
		if (EFI_ERROR(Status) || Drive == NULL)
			continue;

		Status = Drive->OpenVolume(Drive, &Root);
		if (EFI_ERROR(Status))
			continue;

		Status = Root->GetInfo(Root, &gEfiFileSystemInfoGuid, &Size, FsInfo);
		/* Some UEFI firmwares return EFI_BUFFER_TOO_SMALL, even with
		   a large enough buffer, unless the exact size is requested. */
		if ((Status == EFI_BUFFER_TOO_SMALL) && (Size <= sizeof(Buffer)))
			Status = Root->GetInfo(Root, &gEfiFileSystemInfoGuid, &Size, FsInfo);
		if (EFI_ERROR(Status))
			continue;

		Name = FsInfo->VolumeLabel;

		if (Name == NULL || StrLen(Name) == 0 || StrCmp(Name, L" ") == 0)
			Name = ConvertDevicePathToText(DevicePathFromHandle(VolumeHandles[i]), FALSE, FALSE);

		Entries[i] = AllocateZeroPool((StrLen(Name) + 2) * sizeof(CHAR16));
		if (Entries[i] == NULL)
			break;
		StrCpyS(Entries[i], (StrLen(Name) + 2), Name);
	}
	Entries[i] = NULL;

	Val = ConsoleSelect(Title, (CONST CHAR16**)Entries, 0);

	if (Val >= 0) {
		*Selected = AllocateZeroPool((StrLen(Entries[Val]) + 1) * sizeof(CHAR16));
		if (*Selected) {
			StrCpyS(*Selected , (StrLen(Entries[Val]) + 1), Entries[Val]);
		}
		*Handle = VolumeHandles[Val];
	} else {
		*Selected = NULL;
		*Handle = 0;
	}

	for (i = 0; i < Count; i++) {
		if (Entries[i])
			FreePool(Entries[i]);
	}
	FreePool(Entries);
	FreePool(VolumeHandles);

	return EFI_SUCCESS;
}

EFI_STATUS SimpleDirFilter(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name,
	IN CONST CHAR16 *Filter,
	OUT CHAR16 ***Result,
	OUT UINTN *Count,
	OUT EFI_FILE_INFO **Entries
)
{
	EFI_STATUS Status;
	UINTN Len, Total, Offset = StrLen(Filter), i, c, FilterCount = 1;
	EFI_FILE_INFO *Next;
	VOID *Ptr;
	CHAR16 *NewFilter = AllocateZeroPool((StrLen(Filter) + 1) * sizeof(CHAR16)), **FilterArray;

	if (NewFilter == NULL)
		return EFI_OUT_OF_RESOURCES;

	/* Just in case efi ever stops writeable strings */
	StrCpyS(NewFilter, StrLen(Filter) + 1, Filter);

	for (i = 0; i < Offset; i++) {
		if (Filter[i] == '|')
			FilterCount++;
	}
	FilterArray = AllocateZeroPool(FilterCount * sizeof(VOID *));
	if (FilterArray == NULL)
		return EFI_OUT_OF_RESOURCES;
	c = 0;
	FilterArray[c++] = NewFilter;
	for (i = 0; i < Offset; i++) {
		if (Filter[i] == '|') {
			NewFilter[i] = '\0';
			FilterArray[c++] = &NewFilter[i+1];
		}
	}

	*Count = 0;

	Status = SimpleDirReadAll(Image, Name, Entries, &Total);

	if (EFI_ERROR(Status))
		goto out;
	Ptr = Next = *Entries;

	for (i = 0; i < Total; i++) {
		Len = StrLen(Next->FileName);

		for (c = 0; c < FilterCount; c++) {
			Offset = StrLen(FilterArray[c]);

			if (StrCmp(&Next->FileName[Len - Offset], FilterArray[c]) == 0
			    || (Next->Attribute & EFI_FILE_DIRECTORY)) {
				(*Count)++;
				break;
			}
		}
		Ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (Len + 1) * sizeof(CHAR16);
		Next = Ptr;
	}
	if (*Count)
		*Result = AllocateZeroPool(((*Count) + 1) * sizeof(VOID *));
	else
		*Result = AllocateZeroPool(2 * sizeof(VOID *));

	*Count = 0;
	Ptr = Next = *Entries;

	for (i = 0; i < Total; i++) {
		Len = StrLen(Next->FileName);

		if (StrCmp(Next->FileName, L".") == 0)
			/* Ignore . directory */
			goto next;

		if (Next->Attribute & EFI_FILE_DIRECTORY) {
				(*Result)[(*Count)] = Next->FileName;
				(*Result)[(*Count)][Len] = '/';
				(*Result)[(*Count)++][Len + 1] = '\0';
				goto next;
		}

		for (c = 0; c < FilterCount; c++) {
			Offset = StrLen(FilterArray[c]);

			if (StrCmp(&Next->FileName[Len - Offset], FilterArray[c]) == 0)
				(*Result)[(*Count)++] = Next->FileName;
			else
				continue;
			break;
		}

next:
		if (StrCmp(Next->FileName, L"../") == 0) {
			/* Place .. directory first */
			CHAR16 *Tmp = (*Result)[(*Count) - 1];

			(*Result)[(*Count) - 1] = (*Result)[0];
			(*Result)[0] = Tmp;
		}

		Ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (Len + 1) * sizeof(CHAR16);
		Next = Ptr;
	}
	if (*Count == 0) {
		/* No entries at all ... Can happen because top level dir has no . or .. */
		(*Result)[(*Count)++] = L"./";
	}
	(*Result)[*Count] = NULL;
	Status = EFI_SUCCESS;

out:
	if (EFI_ERROR(Status)) {
		if (*Entries)
			FreePool(*Entries);
		*Entries = NULL;
		if (*Result)
			FreePool(*Result);
		*Result = NULL;
	}
	return Status;
}

EFI_STATUS SimpleFileSelector(
	IN OUT EFI_HANDLE *Image,
	IN CONST CHAR16 **Title,
	IN CONST CHAR16 *Name,
	IN CONST CHAR16 *Filter,
	OUT CHAR16 **Result
)
{
	EFI_STATUS Status;
	EFI_HANDLE Handle;
	EFI_FILE_INFO *Info;
	UINTN i, Count, Select, Len;
	CHAR16 **Entries, *CurName, *NewName, *Selected, *VolumeName;

	CurName = (CHAR16*)Name;
	*Result = NULL;
	if (CurName == NULL)
		CurName = L"\\";
	if (Filter == NULL)
		Filter = L"";
	if (*Image == NULL) {
		SimpleVolumeSelector(Title, &VolumeName, &Handle);
		if (VolumeName == NULL)
			return EFI_NOT_FOUND;
		FreePool(VolumeName);
		*Image = Handle;
	}

	NewName = AllocateZeroPool((StrLen(CurName) + 1) * sizeof(CHAR16));
	if (NewName == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		goto out;
	}

	StrCpyS(NewName, StrLen(CurName) + 1, CurName);
	CurName = NewName;

redo:
	Status = SimpleDirFilter(*Image, CurName, Filter, &Entries, &Count, &Info);

	if (EFI_ERROR(Status))
		goto out_free_name;

	Select = ConsoleSelect(Title, (CONST CHAR16**)Entries, 0);
	if (Select < 0) {
		/* ESC key */
		Status = EFI_ABORTED;
		goto out_free;
	}
	Selected = Entries[Select];
	FreePool(Entries);
	Entries = NULL;
	/* Note that memory used by selected is valid until Info is freed */
	Len = StrLen(Selected);
	if (Selected[Len - 1] == '/') {
		/* Stay where we are */
		if (StrCmp(Selected, L"./") == 0) {
			FreePool(Info);
			goto redo;
		} else if (StrCmp(Selected, L"../") == 0) {
			i = StrLen(CurName) - 1;

			for (i = StrLen(CurName); i > 0; i--) {
				if (CurName[i] == '\\')
					break;
			}
			if (i == 0)
				i = 1;

			if (StrCmp(CurName, L"\\") != 0 && StrCmp(&CurName[i], L"..") != 0) {
				CurName[i] = '\0';
				FreePool(Info);
				goto redo;
			}
		}
		NewName = AllocateZeroPool((StrLen(CurName) + Len + 2) * sizeof(CHAR16));
		if (NewName == NULL) {
			Status = EFI_OUT_OF_RESOURCES;
			goto out_free;
		}
		StrCpyS(NewName, StrLen(CurName) + Len + 2, CurName);

		if (CurName[StrLen(CurName) - 1] != '\\')
			StrCatS(NewName, StrLen(CurName) + Len + 2, L"\\");
		StrCatS(NewName, StrLen(CurName) + Len + 2, Selected);
		/* Remove trailing / */
		NewName[StrLen(NewName) - 1] = '\0';

		FreePool(Info);
		FreePool(CurName);
		CurName = NewName;

		goto redo;
	}
	*Result = AllocateZeroPool((StrLen(CurName) + Len + 2) * sizeof(CHAR16));
	if (*Result == NULL) {
		Status = EFI_OUT_OF_RESOURCES;
		goto out_free;
	}
	StrCpyS(*Result, StrLen(CurName) + Len + 2, CurName);
	if (CurName[StrLen(CurName) - 1] != '\\')
		StrCatS(*Result, StrLen(CurName) + Len + 2, L"\\");
	StrCatS(*Result, StrLen(CurName) + Len + 2, Selected);
	Status = EFI_SUCCESS;

out_free:
	FreePool(Info);
	FreePool(Entries);
out_free_name:
	FreePool(CurName);
out:
	return Status;
}

STATIC CONST CHAR16* GetDeviceHandleFromPath(
	IN CONST CHAR16 *Path,
	OUT EFI_HANDLE *DeviceHandle
)
{
	EFI_STATUS Status;
	EFI_DEVICE_PATH_PROTOCOL *DevicePath;
	EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
	EFI_SHELL_PROTOCOL *ShellProtocol;
	UINTN ColumnPos;
	CHAR16 DriveName[64];

	/* Default to using the same device as our current executable */
	Status = gBS->HandleProtocol(gBaseImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
	*DeviceHandle = EFI_ERROR(Status) ? NULL : LoadedImage->DeviceHandle;

	/* Find the position of the column from the drive alias in the path, if any */
	for (ColumnPos = 0; ColumnPos < StrLen(Path) && Path[ColumnPos] != L':'; ColumnPos++);

	/* If no drive was specified we're done */
	if (ColumnPos >= StrLen(Path))
		return Path;

	/* Extract the drive alias */
	StrCpyS(DriveName, ARRAY_SIZE(DriveName), Path);
	DriveName[MIN(ColumnPos + 1, ARRAY_SIZE(DriveName) - 1)] = L'\0';

	/* Convert the drive alias to a device handle using Shell's GetDevicePathFromMap */
	Status = gBS->LocateProtocol(&gEfiShellProtocolGuid, NULL, (VOID**)&ShellProtocol);
	if (EFI_ERROR(Status))
		return Path;
	DevicePath = (EFI_DEVICE_PATH_PROTOCOL*)ShellProtocol->GetDevicePathFromMap(DriveName);
	if (DevicePath == NULL)
		return Path;
	gBS->LocateDevicePath(&gEfiDevicePathProtocolGuid, &DevicePath, DeviceHandle);

	return &Path[ColumnPos + 1];
}

EFI_STATUS SimpleFileReadAllByPath(
	IN CONST CHAR16* Path,
	OUT UINTN *Size,
	OUT VOID **Buffer
)
{
	EFI_STATUS Status;
	EFI_HANDLE DeviceHandle;
	EFI_FILE_HANDLE File = NULL;
	CONST CHAR16 *PathStart;

	PathStart = GetDeviceHandleFromPath(Path, &DeviceHandle);
	Status = SimpleFileOpen(DeviceHandle == NULL ? gBaseImageHandle: DeviceHandle,
		PathStart, &File, EFI_FILE_MODE_READ);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not open '%s'", Path);
	Status = SimpleFileReadAll(File, Size, Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not read '%s'", Path);

exit:
	SimpleFileClose(File);
	return Status;
}

EFI_STATUS SimpleFileWriteAllByPath(
	IN CONST CHAR16* Path,
	IN CONST UINTN Size,
	IN CONST VOID *Buffer
)
{
	EFI_STATUS Status;
	EFI_HANDLE DeviceHandle;
	EFI_FILE_HANDLE File = NULL;
	CONST CHAR16 *PathStart;

	PathStart = GetDeviceHandleFromPath(Path, &DeviceHandle);
	Status = SimpleFileOpen(DeviceHandle == NULL ? gBaseImageHandle: DeviceHandle,
		PathStart, &File, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not create '%s'", Path);
	Status = SimpleFileWriteAll(File, Size, Buffer);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Could not write '%s'", Path);
exit:
	SimpleFileClose(File);
	return Status;
}
