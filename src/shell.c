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
#include "shell.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/LoadedImage.h>

EFI_STATUS ArgSplit(
	IN CONST EFI_HANDLE Image,
	OUT INTN *Argc,
	OUT CHAR16*** Argv
)
{
	INTN i, Count = 1;
	EFI_STATUS Status;
	EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
	CHAR16 *Start;

	*Argc = 0;

	Status = gBS->HandleProtocol(Image,  &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
	if (EFI_ERROR(Status)) {
		Print(L"Failed to get arguments\n");
		return Status;
	}

	for (i = 0; i < LoadedImage->LoadOptionsSize; i += 2) {
		CHAR16 *c = (CHAR16 *)(LoadedImage->LoadOptions + i);
		if (*c == L' ' && *(c+1) != '\0') {
			(*Argc)++;
		}
	}

	(*Argc)++;	/* We counted spaces, so add one for initial */

	*Argv = AllocatePool(*Argc * sizeof(*Argv));
	if (*Argv == NULL)
		return EFI_OUT_OF_RESOURCES;

	(*Argv)[0] = (CHAR16 *)LoadedImage->LoadOptions;
	for (i = 0; i < LoadedImage->LoadOptionsSize; i += 2) {
		CHAR16 *c = (CHAR16 *)(LoadedImage->LoadOptions + i);
		if (*c == L' ') {
			*c = L'\0';
			if (*(c + 1) == '\0')
				/* Strip trailing space */
				break;
			Start = c + 1;
			(*Argv)[Count++] = Start;
		}
	}

	return EFI_SUCCESS;
}

