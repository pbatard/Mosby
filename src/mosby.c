/*
 * MSSB (More Secure Secure Boot -- "Mosby")
 * Copyright © 2024-2025 Pete Batard <pete@akeo.ie>
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

/* Convert a Windows version to an integer */
#define WINVER_TO_UINT64(ver) (((UINT64)(ver)[0] << 48) | ((UINT64)(ver)[1] << 32) | \
                               ((UINT64)(ver)[2] << 16) | ((UINT64)(ver)[3]))

/* Globals */
EFI_HANDLE gBaseImageHandle = NULL;

STATIC BOOLEAN gOptionSilent = FALSE;

/* MokList GUID - Not yet defined in EDK2 */
STATIC EFI_GUID gEfiShimLockGuid =
	{ 0x605DAB50, 0xE046, 0x4300, { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 } };

/* Microsoft GUID - Not yet defined in EDK2 */
STATIC EFI_GUID gEfiMicrosoftGuid =
	{ 0x77FA9ABD, 0x0359, 0x4D32, { 0xBD, 0x60, 0x28, 0xF4, 0xE7, 0x8F, 0x78, 0x4B } };

/* Attributes for the "key" types we support */
STATIC struct {
	CHAR8 *DisplayName;
	CHAR16 *OptionName;
	CHAR16 *VariableName;
	EFI_GUID *VariableGuid;
} KeyInfo[MAX_TYPES] = {
	[PK] = {
		.DisplayName  = "PK:  ",
		.OptionName   = L"-pk",
		.VariableName = EFI_PLATFORM_KEY_NAME,
		.VariableGuid = &gEfiGlobalVariableGuid,
	},
	[KEK] = {
		.DisplayName  = "KEK: ",
		.OptionName   = L"-kek",
		.VariableName = EFI_KEY_EXCHANGE_KEY_NAME,
		.VariableGuid = &gEfiGlobalVariableGuid,
	},
	[DB] = {
		.DisplayName  = "DB:  ",
		.OptionName   = L"-db",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBX] = {
		.DisplayName  = "DBX: ",
		.OptionName   = L"-dbx",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE1,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBT] = {
		.DisplayName = "DBT: ",
		.OptionName   = L"-dbt",
		.VariableName = EFI_IMAGE_SECURITY_DATABASE2,
		.VariableGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[MOK] = {
		.DisplayName  = "MOK: ",
		.OptionName   = L"-mok",
		.VariableName = L"MokList",
		.VariableGuid = &gEfiShimLockGuid,
	},
	[SBAT] = {
		.DisplayName  = "SBAT:",
		.OptionName   = L"-sbat",
		.VariableName = L"SbatLevel",
		.VariableGuid = &gEfiShimLockGuid,
	},
	[SSPU] = {
		.DisplayName  = "SSPU:",
		.OptionName   = L"-sspu",
		.VariableName = L"SkuSiPolicyUpdateSigners",
		.VariableGuid = &gEfiMicrosoftGuid,
	},
	[SSPV] = {
		.DisplayName  = "SSPV:",
		.OptionName   = L"-sspv",
		.VariableName = L"SkuSiPolicyVersion",
		.VariableGuid = &gEfiMicrosoftGuid,
	}
};

STATIC EFI_STATUS ReadVariable(
	IN CHAR16 *VariableName,
	IN EFI_GUID *VendorGuid,
	IN OUT UINTN *DataSize,
	OUT VOID **Data
)
{
	EFI_STATUS Status;
	
	*DataSize = 0;
	*Data = NULL;
	Status = gRT->GetVariable(VariableName, VendorGuid, NULL, DataSize, NULL);
	if (EFI_ERROR(Status) && Status != EFI_BUFFER_TOO_SMALL)
		return Status;
	// +2 to ensure that we have NUL terminators always
	*Data = AllocateZeroPool(*DataSize + 2);
	if (*Data == NULL)
		return EFI_OUT_OF_RESOURCES;

	return gRT->GetVariable(VariableName, VendorGuid, NULL, DataSize, *Data);
}

STATIC UINT32 GetSBatVersion(
	IN CHAR8 *SBat,
	IN UINTN SBatSize
)
{
	UINT32 i, v, m;

	if (SBatSize < 17)
		goto error;
	if (SBat[0] != 's' || SBat[1] != 'b' || SBat[2] != 'a' || SBat[3] != 't' || SBat[4] != ',')
		goto error;
	for (i = 5; i < SBatSize && SBat[i] != ',' && SBat[i] != '\n'; i++);
	if (SBat[i++] != ',' || SBat[i] != '2')
		goto error;
	v = 0;
	for (m = 1000000000; m > 0; m /= 10, i++) {
		if (SBat[i] < '0' || SBat[i] > '9')
			goto error;
		v += (SBat[i] - '0') * m;
	}
	return v;

error:
	RecallPrint(L"ERROR: Unexpected SBAT data\n");
	return 0;
}

STATIC INTN RemoveDuplicates(
	UINT8 Type,
	MOSBY_LIST *List
)
{
	INTN i, LastEntry;

	LastEntry = -1;
	for (i = 0; i < List->Size; i++) {
		if (List->Entry[i].Type != Type)
			continue;
		if (LastEntry >= 0)
			List->Entry[LastEntry].Flags |= NO_INSTALL;
		LastEntry = i;
	}
	return LastEntry;
}

STATIC VOID CheckMokVariables(VOID)
{
	EFI_STATUS Status;
	CHAR16 *MokVarName[3] = { L"MokSBState", L"MokDBState", L"MokIgnoreDB" };
	UINT8 MokVar[ARRAY_SIZE(MokVarName)] = { 0 };
	UINT32 MokAttr[ARRAY_SIZE(MokVarName)];
	UINTN i, Size;
	INTN Sel;

	for (i = 0; i < ARRAY_SIZE(MokVarName); i++) {
		Size = sizeof(UINT8);
		gRT->GetVariable(MokVarName[i], &gEfiShimLockGuid, &MokAttr[i], &Size, &MokVar[i]);
	}
	for (i = 0; i < ARRAY_SIZE(MokVar) && MokVar[i] == 0; i++);
	if (i >= ARRAY_SIZE(MokVar))
		return;

	Sel = ConsoleYesNo(
		(CONST CHAR16 *[]){
			L"WARNING: Secure Boot bypass variables detected",
			L"",
			L"Mosby has detected that this system has some Shim variables set",
			L"('MokSBState', 'MokDBState', 'MokIgnoreDB') that can cause it  ",
			L"to ignore Secure Boot validation.                              ",
			L"",
			L"Do you want to revert these variables to their default values? ",
			NULL
		});
	RecallPrintRestore();
	if (Sel != 0)
		return;
	for (i = 0; i < ARRAY_SIZE(MokVarName); i++) {
		if (MokVar[i] != 0) {
			MokVar[i] = 0;
			Status = gRT->SetVariable(MokVarName[i], &gEfiShimLockGuid, MokAttr[i], sizeof(UINT8), &MokVar[i]);
			Logger(L"Resetting '%s' variable: %r\n", MokVarName[i], Status);
		}
	}
}

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	BOOLEAN TestMode = FALSE, GenDBCred = FALSE, UpdateMode = FALSE;
	BOOLEAN Append = FALSE, Reboot = FALSE, LogToFile = TRUE;
	EFI_STATUS Status;
	EFI_TIME Time;
	UINT8 Set = MOSBY_SET1;
	UINTN i, Size;
	UINT16* SystemSSPV = NULL;
	UINT32 SystemSBatVer, InstallSBatVer;
	INTN Argc, Type, Sel, LastEntry;
	MOSBY_CRED Cred;
	CHAR8 DbSubject[80], PkSubject[80], *SBat, *SBatLine;
	CHAR16 **Argv = NULL, **ArgvCopy, MosbyKeyPath[MAX_PATH];
	MOSBY_LIST List;

	gBaseImageHandle = BaseImageHandle;

	/* Initialize the base entry list */
	Status = InitializeList(&List);
	if (EFI_ERROR(Status))
		goto exit;

	/* Parse arguments */
	Status = ArgSplit(gBaseImageHandle, &Argc, &Argv);
	if (Status == EFI_SUCCESS) {
		ArgvCopy = Argv;
		while (Argc > 1) {
			if (StrCmp(ArgvCopy[1], L"-h") == 0) {
				Print(L"Usage: Mosby [-h] [-i] [-n] [-s] [-u] [-v] [-x] [-var <file>] [-var <file>] [...]\n");
				Print(L"       Supported var values: pk, kek, db, dbx, dbt, mok, sbat, sspu, sspv\n");
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-i") == 0) {
				Logger(L"Embedded data:\n");
				for (i = 0; i < List.Size; i++) {
					if (List.Entry[i].Description != NULL) {
						Logger(L"o %a %a\n        From %a\n", KeyInfo[List.Entry[i].Type].DisplayName,
							List.Entry[i].Description, List.Entry[i].Url);
						Logger(L"        %a\n", Sha256ToString(List.Entry[i].Buffer.Data, List.Entry[i].Buffer.Size));
					}
				}
				if (ReadVariable(L"SbatLevel", &gEfiShimLockGuid, &Size, (VOID**)&SBat) == EFI_SUCCESS) {
					Logger(L"\nCurrent system SBAT:\n");
					for (SBatLine = SBat; SBatLine[0] != '\0'; ) {
						for (i = 0; ; i++) {
							if (SBatLine[i] == '\n') {
								SBatLine[i] = '\0';
								Logger(L"%a\n", SBatLine);
								SBatLine = &SBatLine[i + 1];
								break;
							} else if (SBatLine[i] == '\0') {
								Logger(L"%a\n", SBatLine);
								SBatLine = &SBatLine[i];
								break;
							}
						}
					}
					SafeFree(SBat);
				}
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-n") == 0) {
				LogToFile = FALSE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-s") == 0) {
				gOptionSilent = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-t") == 0) {
				TestMode = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-u") == 0) {
				UpdateMode = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-v") == 0) {
				Print(L"Mosby %s %a\n", ARCH_EXT, VERSION_STRING);
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-x") == 0) {
				Set = MOSBY_SET2;
				ArgvCopy += 1;
				Argc -= 1;
			} else {
				for (Type = 0; Type < MAX_TYPES; Type++) {
					if ((Argc > 2) && StrCmp(ArgvCopy[1], KeyInfo[Type].OptionName) == 0) {
						if (!SimpleFileExistsByPath(gBaseImageHandle, ArgvCopy[2]))
							Abort(EFI_NOT_FOUND, L"File '%s' does not exist\n", ArgvCopy[2]);
						List.Entry[List.Size].Type = Type;
						List.Entry[List.Size].Path = ArgvCopy[2];
						List.Size++;
						ArgvCopy += 2;
						Argc -= 2;
						break;
					}
				}
				if (Type >= MAX_TYPES)
					Abort(EFI_INVALID_PARAMETER, L"Unsupported or incomplete parameter: '%s'\n", ArgvCopy[1]);
			}
		}
	}

	/* Initialize the file logger */
	if (LogToFile)
		OpenLogger(gBaseImageHandle, L"Mosby.log");
	PrintSystemInfo();
	if (UpdateMode)
		goto process_binaries;

	/* Initialize the random generator and validate the platform */
	Status = InitializePki(TestMode);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"ERROR: This platform does not meet the minimum security requirements.\n");

	/* Check and reset the Shim MOK variables if needed */
	CheckMokVariables();

	/* Verify that the platform is in Setup Mode */
	Status = CheckSetupMode();
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
	UnicodeSPrint(MosbyKeyPath, ARRAY_SIZE(MosbyKeyPath), L"%a.crt", MOSBY_CRED_NAME);
	if (SimpleFileExistsByPath(gBaseImageHandle, MosbyKeyPath)) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE)
			Abort(EFI_OUT_OF_RESOURCES, L"List size is too small\n");
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
				L"an additional certificate for your own usage)?                     ",
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
				}, L"\\", L".cer|.crt|.pfx", &List.Entry[List.Size].Path);
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

process_binaries:
	/* Process binaries that have been provided to the application */
	for (i = 0; i < List.Size; i++) {
		if (List.Entry[i].Variable.Data != NULL)
			continue;
		if (List.Entry[i].Path != NULL && List.Entry[i].Buffer.Data == NULL) {
			Status = SimpleFileReadAllByPath(gBaseImageHandle, List.Entry[i].Path,
				&List.Entry[i].Buffer.Size, (VOID**)&List.Entry[i].Buffer.Data);
			if (EFI_ERROR(Status))
				goto exit;
		}
		switch (List.Entry[i].Type) {
			case SSPV:
				if (List.Entry[i].Buffer.Size != 4 * sizeof(UINT16))
					Abort(EFI_INVALID_PARAMETER, L"Invalid SSPV size\n");
				// Fall through
			case SBAT:
			case SSPU:
				List.Entry[i].Flags = USE_BUFFER | ALLOW_UPDATE;
				List.Entry[i].Attrs = UEFI_VAR_NV_BS;
				break;
			default:
				Status = PopulateAuthVar(&List.Entry[i]);
				if (EFI_ERROR(Status))
					ReportErrorAndExit(L"Failed to create variable - Aborting\n");
				break;
		}
	}

	/* Find out if we need to update the SBAT */
	LastEntry = RemoveDuplicates(SBAT, &List);
	if (LastEntry < 0)
		Abort(EFI_NO_MAPPING, L"Internal error\n");
	SystemSBatVer = 0;
	InstallSBatVer = GetSBatVersion((CHAR8*)List.Entry[LastEntry].Buffer.Data, List.Entry[LastEntry].Buffer.Size);
	if (InstallSBatVer == 0)
		Abort(EFI_NO_MAPPING, L"Internal error\n");
	Status = ReadVariable(L"SbatLevel", &gEfiShimLockGuid, &Size, (VOID**)&SBat);
	if (Status == EFI_SUCCESS) 
		SystemSBatVer = GetSBatVersion(SBat, Size);
	if (TestMode)
		Print(L"Provided SBAT: %d, System SBAT: %d\n", InstallSBatVer, SystemSBatVer);
	if (InstallSBatVer <= SystemSBatVer) {
		// TODO: Allow override
		RecallPrint(L"Not installing SBAT since this system's SBAT is either the same or newer\n");
		List.Entry[LastEntry].Flags |= NO_INSTALL;
	}
	SafeFree(SBat);

	/* Find out if we need to update the SSP's */
	LastEntry = RemoveDuplicates(SSPU, &List);
	if (LastEntry < 0)
		Abort(EFI_NO_MAPPING, L"Internal error\n");
	LastEntry = RemoveDuplicates(SSPV, &List);
	if (LastEntry < 0)
		Abort(EFI_NO_MAPPING, L"Internal error\n");
	Size = 4 * sizeof(UINT16);
	Status = ReadVariable(L"SkuSiPolicyVersion", &gEfiMicrosoftGuid, &Size, (VOID**)&SystemSSPV);
	if (Status == EFI_SUCCESS && Size != 4 * sizeof(UINT16))
		Abort(EFI_UNSUPPORTED, L"Unexpected SSPV variable size\n");
	if (Status == EFI_SUCCESS &&
		WINVER_TO_UINT64(SystemSSPV) >= (WINVER_TO_UINT64((UINT16*)List.Entry[LastEntry].Buffer.Data))) {
		// TODO: Allow override
		RecallPrint(L"Not installing SSP vars since this system's SSPV is either the same or newer\n");
		List.Entry[LastEntry].Flags |= NO_INSTALL;
		List.Entry[RemoveDuplicates(SSPU, &List)].Flags |= NO_INSTALL;
	}
	FreePool(SystemSSPV);

	if (UpdateMode)
		goto install;

	/* Generate DB credentials if requested */
	if (GenDBCred) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE)
			Abort(EFI_OUT_OF_RESOURCES, L"List size is too small\n");
		i = List.Size;
		RecallPrint(L"Generating Secure Boot signing credentials...\n");
		List.Entry[i].Type = DB;
		Status = gRT->GetTime(&Time, NULL);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to get time - Aborting\n");
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
		List.Entry[i].Attrs = UEFI_VAR_NV_BS_RT_TIMEAUTH;
		Status = SaveCredentials(WIDEN(MOSBY_CRED_NAME), &Cred);
		if (EFI_ERROR(Status))
			goto exit;
		RecallPrint(L"Saved Secure Boot signing credentials as '%a'\n", MOSBY_CRED_NAME);
		FreeCredentials(&Cred);
		List.Size++;
	}

	/* Generate a keyless PK cert if none was specified */
	LastEntry = RemoveDuplicates(PK, &List);
	if (LastEntry < 0) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE)
			Abort(EFI_OUT_OF_RESOURCES, L"List size is too small\n");
		RecallPrint(L"Generating PK certificate...\n");
		i = List.Size;
		List.Entry[i].Type = PK;
		if (!GenDBCred) {
			Status = gRT->GetTime(&Time, NULL);
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Failed to get time - Aborting\n");
		}
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
		List.Entry[i].Attrs = UEFI_VAR_NV_BS_RT_TIMEAUTH;
		Status = SignToAuthVar(KeyInfo[PK].VariableName, KeyInfo[PK].VariableGuid,
			List.Entry[i].Attrs, &List.Entry[i].Variable, &Cred);
		FreeCredentials(&Cred);
		if (EFI_ERROR(Status)) {
			SafeFree(List.Entry[i].Variable.Data);
			goto exit;
		}
		List.Size++;
	}

	/* EDK2 provides a DeleteSecureBootVariables(), so we might as well call it. */
	DeleteSecureBootVariables();

install:
	/* Install the variables, making sure that we finish with the PK. */
	Status = EFI_NOT_FOUND;
	for (Type = MAX_TYPES - 1; Type >= 0; Type--) {
		Append = (UpdateMode && Type == DBX);
		for (i = 0; i < List.Size; i++) {
			if (List.Entry[i].Type != Type || List.Entry[i].Flags & NO_INSTALL)
				continue;
			if (List.Entry[i].Set != 0 && (List.Entry[i].Set & Set) == 0)
				continue;
			if (UpdateMode && !(List.Entry[i].Flags & ALLOW_UPDATE))
				continue;
			if (List.Entry[i].Description != NULL)
				RecallPrint(L"Installing %a '%a'\n", KeyInfo[Type].DisplayName, List.Entry[i].Description);
			else
				RecallPrint(L"Installing %a From '%s'\n", KeyInfo[Type].DisplayName, List.Entry[i].Path);
			Status = gRT->SetVariable(KeyInfo[Type].VariableName, KeyInfo[Type].VariableGuid,
					List.Entry[i].Attrs | (Append ? EFI_VARIABLE_APPEND_WRITE : 0),
					(List.Entry[i].Flags & USE_BUFFER) ? List.Entry[i].Buffer.Size : List.Entry[i].Variable.Size,
					(List.Entry[i].Flags & USE_BUFFER) ? (VOID*)List.Entry[i].Buffer.Data : (VOID*)List.Entry[i].Variable.Data);
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Failed to set Secure Boot variable: %r\n", Status);
			Append = TRUE;
		}
	}

	if (!gOptionSilent && !UpdateMode)
		Reboot = ExitNotice(GenDBCred);

exit:
	for (i = 0; i < List.Size; i++)
		FreePool(List.Entry[i].Variable.Data);
	FreePool(Argv);
	RecallPrintFree();
	CloseLogger();
	if (Reboot) {
		if (CountDown(L"Rebooting in", L"Press Esc to cancel, any other key to reboot immediately", 10000))
			gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
	}
	return Status;
}
