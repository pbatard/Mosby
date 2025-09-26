/*
 * MSSB (More Secure Secure Boot -- "Mosby") UEFI system info
 * Copyright © 2025 Pete Batard <pete@akeo.ie>
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

#include "console.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Guid/SmBios.h>

#include <IndustryStandard/SmBios.h>

#include <Uefi/UefiBaseType.h>

/*
 * Read a system configuration table from a TableGuid.
 */
static EFI_STATUS GetSystemConfigurationTable(EFI_GUID* TableGuid, VOID** Table)
{
	UINTN Index;

	for (Index = 0; Index < gST->NumberOfTableEntries; Index++) {
		if (CompareGuid(TableGuid, &(gST->ConfigurationTable[Index].VendorGuid))) {
			*Table = gST->ConfigurationTable[Index].VendorTable;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

/*
 * Return SMBIOS string given the string number.
 * Arguments:
 *  Smbios          - Pointer to SMBIOS structure
 *  StringNumber    - String number to return. 0xFFFF can be used to skip all
 *                    strings and point to the next SMBIOS structure.
 * Returns:
 *  Pointer to string, or pointer to next SMBIOS structure if StringNumber == 0xFFFF.
 */
static CHAR8* GetSmbiosString(SMBIOS_STRUCTURE_POINTER* Smbios, UINT16 StringNumber)
{
	UINT16 Index;
	CHAR8* String;

	// Skip over formatted section
	String = (CHAR8*)(Smbios->Raw + Smbios->Hdr->Length);

	// Look through unformated section
	for (Index = 1; Index <= StringNumber; Index++) {
		if (StringNumber == Index)
			return String;

		// Skip string
		for (; *String != 0; String++);
		String++;

		if (*String == 0) {
			// If double NUL then we are done.
			// Return pointer to next structure in Smbios.
			// If you pass 0xFFFF for StringNumber you always get here.
			Smbios->Raw = (UINT8*)++String;
			return NULL;
		}
	}
	return NULL;
}

/*
 * Query SMBIOS to display some info about the system hardware and UEFI firmware.
 */
EFI_STATUS PrintSystemInfo(VOID)
{
	EFI_STATUS Status;
	SMBIOS_STRUCTURE_POINTER Smbios;
	SMBIOS_TABLE_ENTRY_POINT* SmbiosTable;
	SMBIOS_TABLE_3_0_ENTRY_POINT* Smbios3Table;
	UINT8 Found = 0, *Raw;
	UINTN MaximumSize, ProcessedSize = 0;

	RecallPrint(L"UEFI v%d.%d (%s, 0x%08X)\n", gST->Hdr.Revision >> 16, gST->Hdr.Revision & 0xFFFF,
		gST->FirmwareVendor, gST->FirmwareRevision);

	Status = GetSystemConfigurationTable(&gEfiSmbios3TableGuid, (VOID**)&Smbios3Table);
	if (Status == EFI_SUCCESS) {
		Smbios.Hdr = (SMBIOS_STRUCTURE*)(UINTN)Smbios3Table->TableAddress;
		MaximumSize = (UINTN)Smbios3Table->TableMaximumSize;
	} else {
		Status = GetSystemConfigurationTable(&gEfiSmbiosTableGuid, (VOID**)&SmbiosTable);
		if (EFI_ERROR(Status))
			return EFI_NOT_FOUND;
		Smbios.Hdr = (SMBIOS_STRUCTURE*)(UINTN)SmbiosTable->TableAddress;
		MaximumSize = (UINTN)SmbiosTable->TableLength;
	}
	// Sanity check
	if (MaximumSize > 1024 * 1024) {
		RecallPrint(L"Aborting system report due to unexpected SMBIOS table length (0x%08X)\n", MaximumSize);
		return EFI_ABORTED;
	}

	while ((Smbios.Hdr->Type != 0x7F) && (Found < 2)) {
		Raw = Smbios.Raw;
		if (Smbios.Hdr->Type == 0) {
			RecallPrint(L"%a %a\n", GetSmbiosString(&Smbios, Smbios.Type0->Vendor),
				GetSmbiosString(&Smbios, Smbios.Type0->BiosVersion));
			Found++;
		}
		if (Smbios.Hdr->Type == 1) {
			RecallPrint(L"%a %a\n", GetSmbiosString(&Smbios, Smbios.Type1->Manufacturer),
				GetSmbiosString(&Smbios, Smbios.Type1->ProductName));
			Found++;
		}
		GetSmbiosString(&Smbios, 0xFFFF);
		ProcessedSize += (UINTN)Smbios.Raw - (UINTN)Raw;
		if (ProcessedSize > MaximumSize) {
			RecallPrint(L"Aborting system report due to noncompliant SMBIOS\n");
			return EFI_ABORTED;
		}
	}

	return EFI_SUCCESS;
}
