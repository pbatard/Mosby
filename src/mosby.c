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

#include "mosby.h"
#include "console.h"
#include "file.h"
#include "pki.h"
#include "shell.h"
#include "utf8.h"
#include "variables.h"
#include "version.h"

/* Globals */
EFI_HANDLE gBaseImageHandle = NULL;

STATIC BOOLEAN gOptionSilent = FALSE;

/* MokList GUID - Not yet defined in EDK2 */
STATIC EFI_GUID gEfiShimLockGuid =
	{ 0x605DAB50, 0xE046, 0x4300, { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 } };

/* Attributes for the "key" types we support */
STATIC struct {
	CHAR8 *DisplayName;
	CHAR16 *VariableName;
	EFI_GUID *VariableGuid;
} KeyInfo[MAX_TYPES] = {
	[PK] = {
		.DisplayName = "PK",
		.VariableName = EFI_PLATFORM_KEY_NAME,
		.VariableGuid = &gEfiGlobalVariableGuid,
	},
	[KEK] = {
		.DisplayName = "KEK",
		.VariableName = EFI_KEY_EXCHANGE_KEY_NAME,
		.VariableGuid = &gEfiGlobalVariableGuid,
	},
	[DB] = {
		.DisplayName = "DB",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBX] = {
		.DisplayName = "DBX",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE1,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBT] = {
		.DisplayName = "DBT",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE2,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[MOK] = {
		.DisplayName = "MOK",
		.VariableName = L"MokList",
		.VariableGuid = &gEfiShimLockGuid,
	}
};

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	// TODO: MOK may need different options
	CONST UINT32 Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
		EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	BOOLEAN TestMode = FALSE, GenDBCred = FALSE, Append;
	EFI_STATUS Status, SetStatus;
	EFI_TIME Time;
	UINTN i;
	INTN Argc, Type, Sel;
	MOSBY_CRED Cred;
	CHAR8 DbSubject[80], PkSubject[80];
	CHAR16 **Argv = NULL, **ArgvCopy, MosbyKeyPath[MAX_PATH];
	MOSBY_LIST List;

	ConsoleReset();
	RecallPrint(L"Mosby %s %a\n", ARCH_EXT, VERSION_STRING);
	gBaseImageHandle = BaseImageHandle;
	gRT->GetTime(&Time, NULL);

	/* Initialize the base entry list */
	Status = InitializeList(&List);
	if (EFI_ERROR(Status))
		goto exit;

	/* Parse arguments */
	Status = ArgSplit(gBaseImageHandle, &Argc, &Argv);
	if (Status == EFI_SUCCESS) {
		ArgvCopy = Argv;
		while (Argc > 1 && ArgvCopy[1][0] == L'-') {
			if (StrCmp(ArgvCopy[1], L"-t") == 0) {
				TestMode = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-s") == 0) {
				gOptionSilent = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-v") == 0) {
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-i") == 0) {
				Print(L"\nThis version includes:\n");
				for (i = 0; i < List.Size; i++)
					Print(L"o %a:\t%a\n\tFrom %a\n", KeyInfo[List.Entry[i].Type].DisplayName,
						List.Entry[i].Description, List.Entry[i].Url);
				goto exit;
			} else {
				// Unsupported argument
				break;
			}
		}
		// TODO: Add db, dbx, etc processing
		// TODO: Make sure only one PK can be provided by the user
	}

	/* Initialize the random generator and validate the platform */
	Status = InitializePki(TestMode);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"ERROR: This platform does not meet the minimum security requirements.\n");

	/* Verify that the platform is in Setup Mode */
	Status = CheckSetupMode(TestMode);
	if (EFI_ERROR(Status))
		goto exit;

	/* Prompt the user about the changes we are going to make */
	if (!gOptionSilent) {
		Sel = ConsoleOkCancel(
			(CONST CHAR16 *[]){
				L"NOTICE",
				L"",
				L"This application will update your Secure Boot entries using the latest    ",
				L"database and OS provider data, as well as set a UNIQUE system-specific    ",
				L"root certificate, that is not under the control of third-parties.         ",
				L"",
				L"It will also allow you to create/install your own Secure Boot signing key.",
				L"",
				L"If this is not what you want, please select 'Cancel' now.",
				NULL
			});
		RecallPrintRestore();
		if (Sel != 0)
			goto exit;
	}

	/* If we have an existing cert for a previously generated DB credential, try to reuse it */
	UnicodeSPrint(MosbyKeyPath, ARRAY_SIZE(MosbyKeyPath), L"%s.crt", MOSBY_CRED_NAME);
	if (SimpleFileExistsByPath(gBaseImageHandle, MosbyKeyPath)) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE) {
			Status = EFI_OUT_OF_RESOURCES;
			ReportErrorAndExit(L"List size is too small\n");
		}
		RecallPrint(L"Reusing existing %s certificate...\n", MosbyKeyPath);
		List.Entry[List.Size].Type = DB;
		List.Entry[List.Size].Path = MosbyKeyPath;
		List.Size++;
	} else {
		Sel = ConsoleSelect(
			(CONST CHAR16 *[]){
				L"DB credentials installation",
				L"",
				L"Do you want to SELECT an existing Secure Boot signing certificate  ",
				L"or GENERATE new Secure Boot signing credentials (or DON'T INSTALL  ",
				L"any certificate for your own usage)?                               ",
				L"",
				L"If you don't know what to use, we recommend to GENERATE new signing",
				L"credentials, so that you will be able to sign your own Secure Boot ",
				L"binaries for this system.                                          ",
				NULL
			},
			(CONST CHAR16 *[]){
				L"SELECT",
				L"GENERATE",
				L"DON'T INSTALL",
				NULL
			}, 1);
		RecallPrintRestore();
		if (Sel == 0) {
			CHAR16 Title[80];
			EFI_HANDLE Handle = NULL;
			UnicodeSPrint(Title, ARRAY_SIZE(Title), L"Please select an existing certificate");
			Status = SimpleFileSelector(&Handle,
				(CONST CHAR16 *[]){
					L"",
					Title,
					NULL
				}, L"\\", L".cer|.crt", &List.Entry[List.Size].Path);
			RecallPrintRestore();
			if (EFI_ERROR(Status) || !SimpleFileExistsByPath(gBaseImageHandle, List.Entry[List.Size].Path)) {
				SafeFree(List.Entry[List.Size].Path);
				RecallPrint(L"Invalid selection -- Will generate new signing credentials\n");
				GenDBCred = TRUE;
			}
			List.Size++;
		} else if (Sel == 1) {
			GenDBCred = TRUE;
		}
	}

	/* Process binaries that have been provided to the application */
	for (i = 0; i < List.Size; i++) {
		if (List.Entry[i].Variable.Data != NULL)
			continue;
		if (List.Entry[i].Path != NULL && List.Entry[i].Buffer.Data == NULL) {
			if (!SimpleFileExistsByPath(gBaseImageHandle, List.Entry[i].Path))
				ReportErrorAndExit(L"File '%s' does not exist\n", List.Entry[i].Path);
			Status = SimpleFileReadAllByPath(gBaseImageHandle, List.Entry[i].Path,
				&List.Entry[i].Buffer.Size, (VOID**)&List.Entry[i].Buffer.Data);
			if (EFI_ERROR(Status))
				goto exit;
		}
		Status = PopulateAuthVar(&List.Entry[i]);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to create variable - Aborting\n");
	}

	/* Generate DB credentials if requested */
	if (GenDBCred) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE) {
			Status = EFI_OUT_OF_RESOURCES;
			ReportErrorAndExit(L"List size is too small\n");
		}
		i = List.Size;
		RecallPrint(L"Generating Secure Boot signing credentials...\n");
		List.Entry[i].Type = DB;
		AsciiSPrint(DbSubject, sizeof(DbSubject), "%a [%04d.%02d.%02d]",
			MOSBY_CRED_NAME, Time.Year, Time.Month, Time.Day);
		List.Entry[i].Description = DbSubject;
		Status = GenerateCredentials(DbSubject, &Cred);
		if (EFI_ERROR(Status))
			goto exit;
		Status = CertToAuthVar(Cred.Cert, &List.Entry[i].Variable);
		if (EFI_ERROR(Status)) {
			FreeCredentials(&Cred);
			goto exit;
		}
		Status = SaveCredentials(WIDEN(MOSBY_CRED_NAME), &Cred);
		if (EFI_ERROR(Status))
			goto exit;
		RecallPrint(L"Saved Secure Boot signing credentials as '%a'\n", MOSBY_CRED_NAME);
		FreeCredentials(&Cred);
		List.Size++;
	}

	/* Generate a keyless PK cert if none was specified */
	for (i = 0; i < List.Size && List.Entry[i].Type != PK; i++);
	if (i == List.Size) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE) {
			Status = EFI_OUT_OF_RESOURCES;
			ReportErrorAndExit(L"List size is too small\n");
		}
		RecallPrint(L"Generating PK certificate...\n");
		List.Entry[i].Type = PK;
		AsciiSPrint(PkSubject, sizeof(PkSubject), "Mosby Generated PK [%04d.%02d.%02d]",
			Time.Year, Time.Month, Time.Day);
		List.Entry[i].Description = PkSubject;
		Status = GenerateCredentials(PkSubject, &Cred);
		if (EFI_ERROR(Status))
			goto exit;
		Status = CertToAuthVar(Cred.Cert, &List.Entry[i].Variable);
		if (EFI_ERROR(Status)) {
			FreeCredentials(&Cred);
			goto exit;
		}
		// PK must be signed
		Status = SignToAuthVar(KeyInfo[PK].VariableName, KeyInfo[PK].VariableGuid,
			Attributes, &List.Entry[i].Variable, &Cred);
		FreeCredentials(&Cred);
		if (EFI_ERROR(Status)) {
			SafeFree(List.Entry[i].Variable.Data);
			goto exit;
		}
		List.Size++;
	}

	/* Install the variables, making sure that we finish with the PK. */
	// Since We have a DeleteSecureBootVariables(), we might as well call it.
	DeleteSecureBootVariables();
	Status = EFI_NOT_FOUND;
	for (Type = MAX_TYPES - 1; Type >= 0; Type--) {
		Append = FALSE;
		for (i = 0; i < List.Size; i++) {
			if (List.Entry[i].Type != Type)
				continue;
			if (List.Entry[i].Description != NULL)
				RecallPrint(L"Installing %a:\t%a\n", KeyInfo[Type].DisplayName, List.Entry[i].Description);
			else
				RecallPrint(L"Installing %a:\tfrom %s\n", KeyInfo[Type].DisplayName, List.Entry[i].Path);
			SetStatus = gRT->SetVariable(KeyInfo[Type].VariableName, KeyInfo[Type].VariableGuid,
				Attributes | (Append ? EFI_VARIABLE_APPEND_WRITE : 0),
				List.Entry[i].Variable.Size, List.Entry[i].Variable.Data);
			if (EFI_ERROR(SetStatus)) {
				RecallPrint(L"Failed to set Secure Boot variable: %r\n", SetStatus);
				Status = SetStatus;
			}
			Append = TRUE;
		}
	}

exit:
	for (i = 0; i < List.Size; i++)
		FreePool(List.Entry[i].Variable.Data);
	FreePool(Argv);
	RecallPrintFree();
	return Status;
}
