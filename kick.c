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

#include "kick.h"
#include "console.h"
#include "file.h"
#include "pki.h"

EFI_HANDLE gBaseImageHandle = NULL;
BOOLEAN gOptionSilent = FALSE;

EFI_STATUS ParseList(
	IN CONST CHAR16 *ListFileName,
	OUT INSTALLABLE_COLLECTION *Installable
)
{
	CONST CHAR8 *TypeString;
	UINTN i, Index;
	EFI_STATUS Status;

	SetMem((VOID *)Installable, sizeof(INSTALLABLE_COLLECTION), 0);

	/* NB: SimpleFileReadAllByPath() adds an extra NUL to the data read */
	Status = SimpleFileReadAllByPath(ListFileName, &Installable->ListDataSize, (VOID**)&Installable->ListData);
	if (EFI_ERROR(Status))
		goto exit;

	for (i = 0; i < Installable->ListDataSize; i++)
		if (Installable->ListData[i] == '\r' || Installable->ListData[i] == '\n')
			Installable->ListData[i] = 0;
	for (i = 0; i < Installable->ListDataSize; ) {
		/* Ignore whitespaces and control characters */
		while (Installable->ListData[i] <= ' ' && i < Installable->ListDataSize)
			i++;
		if (i >= Installable->ListDataSize)
			break;
		if (Installable->ListData[i] == '#') {
			/* Ignore comments */
		} else if (Installable->ListData[i] == '[') {
			if (AsciiStrCmp(&Installable->ListData[i], "[SILENT]") == 0) {
				gOptionSilent = TRUE;
			} else {
				Status = EFI_NO_MAPPING;
				ReportErrorAndExit(L"Unrecognized option '%a'", &Installable->ListData[i]);
			};
		} else {
			for (Index = 0; Index < MAX_TYPES; Index++) {
				TypeString = BlobName(Index);
				if (i + AsciiStrLen(TypeString) >= Installable->ListDataSize)
					continue;
				if (AsciiStrnCmp(TypeString, &Installable->ListData[i], AsciiStrLen(TypeString)) != 0)
					continue;
				if (!IsWhiteSpace(Installable->ListData[i + AsciiStrLen(TypeString)]))
					continue;
				i += AsciiStrLen(TypeString);
				while (IsWhiteSpace(Installable->ListData[i]) && i < Installable->ListDataSize)
					i++;
				if (Installable->List[Index].NumEntries < MAX_NUM_ENTRIES)
					Installable->List[Index].Path[Installable->List[Index].NumEntries++] = &Installable->ListData[i];
				break;
			}
			if (Index >= MAX_TYPES) {
				Status = EFI_NO_MAPPING;
				ReportErrorAndExit(L"Could not parse '%s'", ListFileName);
				break;
			}
		}
		while (Installable->ListData[i] != '\0' && i < Installable->ListDataSize)
			i++;
	}
	Status = EFI_SUCCESS;

exit:
	return Status;
}

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	EFI_STATUS Status;
	UINTN Type, Entry;
	CHAR16 Path[MAX_PATH];
	INSTALLABLE_COLLECTION Installable;

	gBaseImageHandle = BaseImageHandle;

	/* 1. Verify that the platform is in Setup mode */
	// TODO: Reboot into UEFI firmware if not. Or can we just force setup and reboot?

	/* 2. Initialize the random generator and validate the platform */
	Status = InitializePki();
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"This platform does not meet the minimum security requirements.");

	/* 3. Parse and validate the list file */
	Status = ParseList(LISTFILE_NAME, &Installable);
	if (EFI_ERROR(Status))
		goto exit;
	if (Installable.List[PK].NumEntries > 1) {
		ConsoleAlertBox(
			(CONST CHAR16 *[]){
				L"WARNING",
				L"",
				L"More than one PK was specified in the list file.",
				L"Only the first one will be used.",
				NULL
			});
		Installable.List[PK].NumEntries = 1;
	};

	/* 4. Prompt the user about the changes we are going to make */
	if (!gOptionSilent) {
		INTN Sel = ConsoleOkCancel(
			(CONST CHAR16 *[]){
				L"This application will update your Secure Boot entries using the latest",
				L"database and OS provider data, as well as set a UNIQUE system-specific",
				L"root certificate, that is not under the control of any third-party.",
				L"",
				L"It will also allow you to create/install your own Secure Boot signing key.",
				L"",
				L"If this is not what you want, please select 'Cancel' now.",
				NULL
			});
		if (Sel != 0)
			goto exit;
	}

	/* 5. Load and validate the support files (KEKs, DBs, DBX, etc) */
	for (Type = 0; Type < MAX_TYPES; Type++) {
		for (Entry = 0; Entry < Installable.List[Type].NumEntries && Installable.List[Type].Path[Entry] != NULL; Entry++) {

			/* DB types have a special PROMPT or GENERATE mode */
			if (Type == DB && AsciiStrCmp(Installable.List[Type].Path[Entry], "[GENERATE]") == 0)
				continue;

			if (Type == DB && AsciiStrCmp(Installable.List[Type].Path[Entry], "[PROMPT]") == 0) {
				INTN Sel = ConsoleSelect(
					(CONST CHAR16 *[]){
						L"DB credentials installation",
						L"",
						L"Do you want to SELECT an existing Secure Boot signing certificate",
						L"or GENERATE new Secure Boot signing credentials (or DON'T INSTALL",
						L"any certificate for your own usage)?",
						L"",
						L"If you don't know what to pick, we recommend to GENERATE new signing",
						L"credentials, so that you will be able to sign your own Secure Boot",
						L"binaries for this system.",
						NULL
					},
					(CONST CHAR16 *[]){
						L"SELECT",
						L"GENERATE",
						L"DON'T INSTALL",
						NULL
					}, 1);
				// TODO: handle Esc
				if (Sel == 0) {
					Installable.List[DB].Path[Entry] = "[SELECT]";
				} else if (Sel == 1) {
					Installable.List[DB].Path[Entry] = "[GENERATE]";
					continue;
				} else {
					Installable.List[DB].Path[Entry] = "[NONE]";
					continue;
				}
				break;
			}

			Status = Utf8ToUcs2(Installable.List[Type].Path[Entry], Path, ARRAY_SIZE(Path));
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Could not convert '%a'", Installable.List[Type].Path[Entry]);

			if (StrCmp(Path, L"[SELECT]") == 0) {
				CHAR16 *Blah, Title[80];
				EFI_HANDLE h = NULL;
				UnicodeSPrint(Title, ARRAY_SIZE(Title), L"Please select %a %s",
					BlobName(Type), (Type == DBX) ? L"binary" : L"certificate");
				Status = SimpleFileSelector(&h, 
					(CONST CHAR16 *[]){
						L"",
						Title,
						NULL
					}, L"\\", (Type == DBX) ? L".bin|.esl" : L".cer|.crt", &Blah);
				if (EFI_ERROR(Status))
					continue;
				StrCpyS(Path, ARRAY_SIZE(Path), Blah);
				FreePool(Blah);
			}

			if (Type == DBX)
				Installable.List[Type].Blob[Entry] = ReadDbx(Path);
			else
				Installable.List[Type].Blob[Entry] = ReadCertificate(Path);

			if (Installable.List[Type].Blob[Entry] == NULL)
				goto exit;
			Print(L"%a[%d] = '%s'\n", BlobName(Type), Entry, Path);
		}
	}

	/* 6. Generate a keyless PK cert if none was specified */
	if (Installable.List[PK].Blob[0] == NULL) {
		Installable.List[PK].Blob[0] = GenerateCredentials("Kick PK", NULL);
		if (Installable.List[PK].Blob[0] == NULL)
			goto exit;
	}

	/* 7. Generate DB credentials if requested */
	for (Entry = 0; Entry < Installable.List[DB].NumEntries &&
		AsciiStrCmp(Installable.List[DB].Path[Entry], "[GENERATE]") != 0; Entry++);
	if (Entry < Installable.List[DB].NumEntries) {
		VOID *Key;
		Installable.List[DB].Blob[Entry] = GenerateCredentials("Secure Boot signing", &Key);
		if (Installable.List[DB].Blob[Entry] == NULL)
			goto exit;
		Status = SaveCredentials(Installable.List[DB].Blob[Entry], Key, L"DB");
		if (EFI_ERROR(Status))
			goto exit;
	}
	Status = EFI_SUCCESS;

exit:
	FreePool(Installable.ListData);

	return Status;
}
