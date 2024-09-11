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
#include "console.h"

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
	CHAR16 *LoadOptions;
	BOOLEAN OpenQuote;

	*Argc = 0;

	Status = gBS->HandleProtocol(Image,  &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
	if (EFI_ERROR(Status)) {
		RecallPrint(L"Failed to get arguments\n");
		return Status;
	}

	LoadOptions = (CHAR16 *)LoadedImage->LoadOptions;
	OpenQuote = FALSE;
	for (i = 0; i < LoadedImage->LoadOptionsSize / 2; i++) {
		if (LoadOptions[i] == L'"')
			OpenQuote = !OpenQuote;
		else if (!OpenQuote && LoadOptions[i] == L' ' &&
			LoadOptions[i + 1] != ' ' && LoadOptions[i + 1] != '\0')
			(*Argc)++;
	}

	(*Argc)++;	// We counted parameters, so add one for initial

	*Argv = AllocatePool(*Argc * sizeof(*Argv));
	if (*Argv == NULL)
		return EFI_OUT_OF_RESOURCES;

	(*Argv)[0] = (CHAR16 *)LoadedImage->LoadOptions;
	OpenQuote = FALSE;
	for (i = 0; i < LoadedImage->LoadOptionsSize / 2 - 1; i++) {
		if (OpenQuote) {
			if (LoadOptions[i] == L'"') {
				OpenQuote = FALSE;
				LoadOptions[i] = L'\0';
				// If we are closing a quote with an empty parameter, remove that parameter
				if (&LoadOptions[i] == (*Argv)[Count - 1])
					Count--;
			}
		} else if (LoadOptions[i] == L' ' && LoadOptions[i + 1] != L' ') {
			LoadOptions[i] = L'\0';
			if (LoadOptions[i + 1] == L'"') {
				OpenQuote = TRUE;
				LoadOptions[++i] = L'\0';
			}
			if (LoadOptions[i + 1] == L'\0')
				// Strip trailing space
				break;
			(*Argv)[Count++] = &LoadOptions[i + 1];
		} else if (LoadOptions[i] == L' ')
			LoadOptions[i] = L'\0';
	}
	*Argc = Count;

	return EFI_SUCCESS;
}

