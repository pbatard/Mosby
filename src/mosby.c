/*
 * MSSB (More Secure Secure Boot -- "Mosby")
 * Copyright © 2024-2026 Pete Batard <pete@akeo.ie>
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

/* Substrings we search for to detect compromised PKs, such as "DO NOT TRUST - AMI Test PK",
   "RD1 BMC Test Key - DO NOT TRUST", "Phoenix PK Example". See https://pk.fail. */
STATIC CHAR8* CompromisedPk[] = { "DO NOT TRUST", "DO NOT SHIP", "PK Example" };

/* MokList GUID - Not yet defined in EDK2 */
STATIC EFI_GUID gEfiShimLockGuid =
	{ 0x605DAB50, 0xE046, 0x4300, { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 } };

/* Microsoft GUID - Not yet globally defined in EDK2 */
EFI_GUID gEfiMicrosoftGuid =
	{ 0x77FA9ABD, 0x0359, 0x4D32, { 0xBD, 0x60, 0x28, 0xF4, 0xE7, 0x8F, 0x78, 0x4B } };

/* Populate the key type attributes */
MOSBY_KEY_INFO KeyInfo[MAX_TYPES] = {
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
	BOOLEAN TestMode = FALSE, GenDBCred = FALSE, UpdateMode = FALSE, CreateNoPkFile = FALSE;
	BOOLEAN Reboot = FALSE, LogToFile = TRUE, DisplayErrorNotice = FALSE, AddDefaults = FALSE;
	EFI_STATUS Status;
	EFI_TIME Time = { 0 };
	UINT8 Set = MOSBY_SET1;
	UINTN i, j, k, l, def[3] = { 0 }, Size;
	UINT16 *SystemSSPV = NULL;
	UINT32 SystemSBatVer = 0, InstallSBatVer = 0;
	INTN Argc, Type, Sel, LastEntry;
	MOSBY_BUFFER DefaultKey[ARRAY_SIZE(def)] = { 0 }, DefaultCert, Cert;
	MOSBY_CRED PkCred = { 0 }, DbCred = { 0 };
	CHAR8 DbSubject[80], PkSubject[80], *SBat = NULL, *SBatLine = NULL, *CommonName;
	CHAR16 **Argv = NULL, **ArgvCopy, MosbyKeyPath[MAX_PATH], DefaultKeyName[ARRAY_SIZE(def)][16];
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
				Print(L"Usage: Mosby [-h] [-d] [-i] [-n] [-s] [-u] [-v] [-x] [-var <file>] [-var <file>] [...]\n");
				Print(L"       Supported var values: pk, kek, db, dbx, dbt, mok, sbat, sspu, sspv\n");
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-i") == 0) {
				Print(L"Embedded data:\n");
				for (i = 0; i < List.Size; i++) {
					if (List.Entry[i].Description != NULL) {
						Print(L"o %a %a\n        From %a\n", KeyInfo[List.Entry[i].Type].DisplayName,
							List.Entry[i].Description, List.Entry[i].Url);
						Print(L"        %a\n", Sha256ToString(&List.Entry[i].Buffer));
					}
				}
				if (ReadVariable(L"SbatLevel", &gEfiShimLockGuid, &Size, (VOID**)&SBat) == EFI_SUCCESS) {
					Print(L"\nCurrent system SBAT:\n");
					for (SBatLine = SBat; SBatLine[0] != '\0'; ) {
						for (i = 0; ; i++) {
							if (SBatLine[i] == '\n') {
								SBatLine[i] = '\0';
								Print(L"%a\n", SBatLine);
								SBatLine = &SBatLine[i + 1];
								break;
							} else if (SBatLine[i] == '\0') {
								Print(L"%a\n", SBatLine);
								SBatLine = &SBatLine[i];
								break;
							}
						}
					}
					SafeFree(SBat);
				}
				Print(L"\nManufacturer Defaults:\n");
				for (k = PK; k <= DB; k++) {
					if (k >= ARRAY_SIZE(def))
						Abort(EFI_NO_MAPPING, L"Internal error\n");
					UnicodeSPrint(DefaultKeyName[k], sizeof(DefaultKeyName[k]), L"%sDefault", KeyInfo[k].VariableName);
#if defined(DEFAULTS_FROM_FILE)
					Status = SimpleFileReadAllByPath(gBaseImageHandle, DefaultKeyName[k], &DefaultKey[k].Size, (VOID**)&DefaultKey[k].Data);
#else
					Status = ReadVariable(DefaultKeyName[k], &gEfiGlobalVariableGuid, &DefaultKey[k].Size, (VOID**)&DefaultKey[k].Data);
#endif
					if (EFI_ERROR(Status)) {
						Print(L"WHY %s: %r\n", DefaultKeyName[k], Status);
						continue;
					}
					for (j = 0; CertFromEsl(&DefaultKey[k], j, &DefaultCert) == EFI_SUCCESS; j++) {
						Cert.Size = DefaultCert.Size - OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
						Cert.Data = ((EFI_SIGNATURE_DATA*)DefaultCert.Data)->SignatureData;
						CommonName = GetCommonName(&Cert);
						if (CommonName != NULL) {
							Print(L"o %a %a\n        From %s\n", KeyInfo[k].DisplayName, CommonName, DefaultKeyName[k]);
							Print(L"        %a\n", Sha256ToString(&Cert));
							def[k]++;
						}
					}					
				}
				if (def[PK] + def[KEK] + def[DB] == 0)
					Print(L"No defaults certificates were found on this system\n");
				goto exit;
			} else if (StrCmp(ArgvCopy[1], L"-d") == 0) {
				if (UpdateMode) {
					Print(L"The -d and -u options are not compatible\n");
					goto exit;
				}
				CreateNoPkFile = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-n") == 0) {
				LogToFile = FALSE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-r") == 0) {
				if (UpdateMode) {
					Print(L"The -r and -u options are not compatible\n");
					goto exit;
				}
				AddDefaults = TRUE;
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
				if (AddDefaults) {
					Print(L"The -r and -u options are not compatible\n");
					goto exit;
				}
				if (CreateNoPkFile) {
					Print(L"The -d and -u options are not compatible\n");
					goto exit;
				}
				UpdateMode = TRUE;
				ArgvCopy += 1;
				Argc -= 1;
			} else if (StrCmp(ArgvCopy[1], L"-v") == 0) {
				Print(L"Mosby %a %s\n", VERSION_STRING, ARCH_EXT);
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

	/* Initialize the console and the file logger */
	ConsoleInit();
	if (LogToFile)
		OpenLogger(gBaseImageHandle, L"Mosby.log");
	RecallPrint(L"Mosby %a %s\n", VERSION_STRING, ARCH_EXT);
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
				L"This application will update your Secure Boot entries  using  the",
				L"current UEFI databases and OS-provider data, as  well  as  set  a",
				L"UNIQUE system-specific PK certificate,  that  is  not  under  the",
				L"control of any third-party (such as your platform OEM).          ",
				L"",
				L"It will also allow you to create or install your own  Secure Boot",
				L"signing key.                                                     ",
				L"",
				L"If this is not what you want, please select 'Cancel' now.        ",
				NULL
			});
		RecallPrintRestore();
		if (Sel != 0)
			goto exit;

		/* Display an additional warning for TPM measured boot with BitLocker */
		if (SystemHasTpm() && SystemHasBitLocker()) {
			RecallPrint(L"Notice: TPM and BitLocker detected.\n");
			STATIC CONST CHAR16 *WTF_RISC_COMPILER1[] = {
				L"TPM MEASURED BOOT WARNING",
				L"",
				L"A TPM, along with BitLocker partitions, were detected on this PC.",
				L"",
				L"Because of a feature called 'TPM Measured Boot', if  your  system",
				L"partition is encrypted, this could result in Windows refusing  to",
				L"boot after the Secure Boot variables have been updated, until you",
				L"provide it with your BitLocker recovery key...                   ",
				L"",
				L"If you have your recovery key available, or are  sure  that  your",
				L"system partition is not encrypted, you can select 'Proceed' here.",
				L"",
				L"If you are unsure about the above, and don't have your  BitLocker",
				L"recovery key, it is recommended that you select 'Abort'.         ",
				NULL
			};
			Sel = ConsoleAlertBox(WTF_RISC_COMPILER1, (CONST CHAR16 *[]){ L"PROCEED", L"ABORT", NULL });
			RecallPrintRestore();
			if (Sel != 0)
				goto exit;
		}
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
				L"Do you want to SELECT an existing Secure Boot signing certificate",
				L"or GENERATE new Secure Boot signing credentials (or DON'T INSTALL",
				L"an additional certificate for your own usage)?                   ",
				L"",
				L"If you don't know what  to  do,  we  recommend  to  GENERATE  new",
				L"signing credentials, so that you can sign  your  own  Secure Boot",
				L"binaries for this system.                                        ",
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

	/* Generate the credentials, which we use both to sign the authvars as well as PK */
	Status = gRT->GetTime(&Time, NULL);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Failed to get time - Aborting\n");
	AsciiSPrint(PkSubject, sizeof(PkSubject), "Mosby Generated PK [%04d.%02d.%02d]",
		Time.Year, Time.Month, Time.Day);
	Status = GenerateCredentials(PkSubject, &PkCred);
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"Failed to generate PK signing credentials - Aborting\n");

process_binaries:
	DisplayErrorNotice = TRUE;
	/* Process the files that were provided */
	for (i = 0; i < List.Size; i++) {
		if (List.Entry[i].Variable.Data != NULL)
			continue;
		if (List.Entry[i].Path != NULL && List.Entry[i].Buffer.Data == NULL) {
			Status = SimpleFileReadAllByPath(gBaseImageHandle, List.Entry[i].Path,
				&List.Entry[i].Buffer.Size, (VOID**)&List.Entry[i].Buffer.Data);
			if (EFI_ERROR(Status))
				goto exit;
			List.Entry[i].Flags |= ALLOCATED_BUFFER;
			List.Entry[i].Owner = &gEfiMosbyGuid;
		}
	}

	/* Optionally, add the manufacturer's default DB, KEK and PK certs we don't already include */
	for (k = PK; AddDefaults && k <= DB; k++) {
		if (k >= ARRAY_SIZE(def))
			Abort(EFI_NO_MAPPING, L"Internal error\n");
		/* Read the manufacturer's '###Default' Secure Boot variables if present */
		UnicodeSPrint(DefaultKeyName[k], sizeof(DefaultKeyName[k]), L"%sDefault", KeyInfo[k].VariableName);
#if defined(DEFAULTS_FROM_FILE)
		Status = SimpleFileReadAllByPath(gBaseImageHandle, DefaultKeyName[k], &DefaultKey[k].Size, (VOID**)&DefaultKey[k].Data);
#else
		Status = ReadVariable(DefaultKeyName[k], &gEfiGlobalVariableGuid, &DefaultKey[k].Size, (VOID**)&DefaultKey[k].Data);
#endif
		if (EFI_ERROR(Status))
			continue;

		/* Process each of the ###Default ESL's certificates */
		for (j = 0; CertFromEsl(&DefaultKey[k], j, &DefaultCert) == EFI_SUCCESS; j++) {
			Size = DefaultCert.Size - OFFSET_OF(EFI_SIGNATURE_DATA, SignatureData);
			for (i = 0; i < List.Size; i++) {
				if (List.Entry[i].Type != k || List.Entry[i].Variable.Data != NULL)
					continue;
				if (Size != List.Entry[i].Buffer.Size)
					continue;
				if (CompareMem(((EFI_SIGNATURE_DATA*)DefaultCert.Data)->SignatureData, List.Entry[i].Buffer.Data, Size) == 0)
					break;
			}
			if (i == List.Size && List.Size < MOSBY_MAX_LIST_SIZE) {
				/* Cert is not already in our list => Add the whole ESL */
				List.Entry[List.Size].Type = k;
				/* In some weird decision, whereas most platforms actively reject them, HP platforms, such as
				 * the ProDesk 600, permissively accept PK installations where the cert and signing key don't
				 * match, but *only* as long as the owner GUID for the ESL is not the same as HP's... So we
				 * force gEfiMosbyGuid for the PK (but not the KEK/DB, since HP doesn't care for these). */
				List.Entry[List.Size].Owner = (k == PK) ? &gEfiMosbyGuid : &((EFI_SIGNATURE_DATA*)DefaultCert.Data)->SignatureOwner;
				List.Entry[List.Size].Buffer.Data = ((EFI_SIGNATURE_DATA*)DefaultCert.Data)->SignatureData;
				List.Entry[List.Size].Buffer.Size = Size;
				List.Entry[List.Size].Description = GetCommonName(&List.Entry[List.Size].Buffer);
				/* Don't re-install a compromised PK! */
				for (l = 0; l < ARRAY_SIZE(CompromisedPk) &&
					AsciiStrStr(List.Entry[List.Size].Description, CompromisedPk[l]) == NULL; l++);
				if (l != ARRAY_SIZE(CompromisedPk)) {
					RecallPrint(L"Notice: Ignoring compromised default %s '%a'\n", KeyInfo[k].VariableName,
						List.Entry[List.Size].Description);
					continue;
				}
				if (List.Entry[List.Size].Description == NULL)
					List.Entry[List.Size].Path = DefaultKeyName[k];
				List.Entry[List.Size].Flags = FROM_DEFAULTS;
				List.Entry[List.Size].Attrs = (k == PK) ? UEFI_VAR_NV_BS_RT_AT : UEFI_VAR_NV_BS_RT_AT_AP;
				List.Size++;
				def[k]++;
			}
		}
	}
	if (AddDefaults) {
		if (def[PK] + def[KEK] + def[DB] > 0)
			RecallPrint(L"Reusing %d PK, %d KEK(s) and %d DB(s) from manufacturer's defaults\n", def[PK], def[KEK], def[DB]);
		else
			RecallPrint(L"Notice: No installable default PK/KEK/DB were found on this platform\n");
	}

	/* Process the finalized list, with all the certs, and generate the AuthVars */
	for (i = 0; i < List.Size; i++) {
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
				Status = PopulateAuthVar(&List.Entry[i], &PkCred);
				if (EFI_ERROR(Status) && !UpdateMode)
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
		RecallPrint(L"Generating Secure Boot DB signing credentials...\n");
		List.Entry[i].Type = DB;
		AsciiSPrint(DbSubject, sizeof(DbSubject), "%a [%04d.%02d.%02d]",
			MOSBY_CRED_NAME, Time.Year, Time.Month, Time.Day);
		List.Entry[i].Description = DbSubject;
		Status = GenerateCredentials(DbSubject, &DbCred);
		if (EFI_ERROR(Status))
			goto exit;
		Status = CertToAuthVar(DbCred.Cert, &List.Entry[i].Variable, &gEfiMosbyGuid);
		if (EFI_ERROR(Status))
			goto exit;
		Status = SaveCredentials(WIDEN(MOSBY_CRED_NAME), &DbCred);
		if (EFI_ERROR(Status))
			goto exit;
		RecallPrint(L"Saved Secure Boot DB signing credentials as '%a'\n", MOSBY_CRED_NAME);

		List.Entry[i].Attrs = UEFI_VAR_NV_BS_RT_AT_AP;
		Status = SignAuthVar(KeyInfo[DB].VariableName, KeyInfo[DB].VariableGuid,
			List.Entry[i].Attrs, &List.Entry[i].Variable, &PkCred);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to sign DB\n");
		List.Size++;
	}

	/* Set up the PK if none was specified */
	LastEntry = RemoveDuplicates(PK, &List);
	if (LastEntry < 0 || List.Entry[LastEntry].Flags & FROM_DEFAULTS) {
		if (List.Size >= MOSBY_MAX_LIST_SIZE)
			Abort(EFI_OUT_OF_RESOURCES, L"List size is too small\n");
		RecallPrint(L"Generating PK certificate...\n");
		i = List.Size;
		List.Entry[i].Type = PK;
		List.Entry[i].Description = PkSubject;
		Status = CertToAuthVar(PkCred.Cert, &List.Entry[i].Variable, &gEfiMosbyGuid);
		if (EFI_ERROR(Status))
			goto exit;
		List.Entry[i].Attrs = UEFI_VAR_NV_BS_RT_AT;
		Status = SignAuthVar(KeyInfo[PK].VariableName, KeyInfo[PK].VariableGuid,
			List.Entry[i].Attrs, &List.Entry[i].Variable, &PkCred);
		if (EFI_ERROR(Status)) {
			SafeFree(List.Entry[i].Variable.Data);
			goto exit;
		}
		List.Size++;
	}

#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
	/*
	 * There appears to be a whole sway of AMI UEFI firmwares with a rather unfortunate bug,
	 * that prevents appending to an existing KEK store (or even creating the initial KEK
	 * variable if it is done with the append flag set). Which means that, on the affected
	 * systems, if we try to write more than one KEK, using multiple SetVariable() calls,
	 * only the first can succeed and all subsequent ones fail with EFI_INVALID_PARAMETER.
	 * To work around this and since any unsigned KEK we processed above should already have
	 * been converted to an ESL (embedded in an EFI_VARIABLE_AUTHENTICATION_2 struct), we
	 * concatenate all these ESLs into a single array, which can then be written through a
	 * single SetVariable() operation.
	 * For more on this, see https://github.com/pbatard/Mosby/issues/14.
	 */
	EFI_SIGNATURE_LIST* Esl[16] = { 0 };
	UINTN EslIndex = 0, EslOffset = 0;
	UINT8 *MergedEsl = NULL;	 
	for (i = 0;  i < List.Size; i++) {
		/* Only process valid KEK entries for which we have a variable */
		if (List.Entry[i].Type != KEK || List.Entry[i].Variable.Data == NULL)
			continue;
		/* Only process variables for which we have an *unsigned* ESL */
		if (List.Entry[i].Flags & ALLOW_UPDATE)
			continue;
		if (EslIndex >= ARRAY_SIZE(Esl))
			Abort(EFI_INVALID_PARAMETER, L"More than %d KEKs to merge - Aborting\n", ARRAY_SIZE(Esl));
		if (List.Entry[i].Description != NULL)
			RecallPrint(L"Adding '%a' to Merged KEK List\n", List.Entry[i].Description);
		else
			RecallPrint(L"Adding '%s' to Merged KEK List\n", List.Entry[i].Path);
		/* Get the ESL data from EFI_VARIABLE_AUTHENTICATION_2 (at .AuthInfo.CertData) */
		Esl[EslIndex++] = (EFI_SIGNATURE_LIST*)&((UINT8*)List.Entry[i].Variable.Data)[
			((List.Entry[i].Variable.Data->AuthInfo.CertData[2] << 8) | List.Entry[i].Variable.Data->AuthInfo.CertData[3]) +
			OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) +
			OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) + 4];
		/* Remove the individual KEK from our installation list, since it will be merged */
		List.Entry[i].Flags |= NO_INSTALL;
	}
	/* Now concatenate all the ESLs from above into an array and create the variable */
	if (EslIndex > 0 && List.Size < ARRAY_SIZE(List.Entry)) {
		List.Entry[List.Size].Buffer.Size = 0;
		for (i = 0; i < EslIndex; i++)
			List.Entry[List.Size].Buffer.Size += Esl[i]->SignatureListSize;
		MergedEsl = AllocateZeroPool(List.Entry[List.Size].Buffer.Size);
		if (MergedEsl == NULL)
			Abort(EFI_OUT_OF_RESOURCES, L"Could not allocate data to merge KEKs\n");
		for (EslOffset = 0, i = 0; i < EslIndex; i++) {
			CopyMem(&MergedEsl[EslOffset], Esl[i], Esl[i]->SignatureListSize);
			EslOffset += Esl[i]->SignatureListSize;
			FreePool(Esl[i]);
		}
		List.Entry[List.Size].Buffer.Data = MergedEsl;
		List.Entry[List.Size].Type = KEK;
		List.Entry[List.Size].Attrs = UEFI_VAR_NV_BS_RT_AT;
		List.Entry[List.Size].Description = "Merged KEK List";
		List.Entry[List.Size].Path = L"Merged KEK List";
		Status = PopulateAuthVar(&List.Entry[List.Size], &PkCred);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to create merged KEK variable - Aborting\n");
		List.Size++;
		FreePool(MergedEsl);
	}
#endif

	/* EDK2 provides a DeleteSecureBootVariables(), so we might as well call it. */
	DeleteSecureBootVariables();

install:
	/* Install the variables, making sure that we finish with the PK. */
	Status = EFI_NOT_FOUND;
	for (Type = MAX_TYPES - 1; Type >= 0; Type--) {
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
			Status = gRT->SetVariable(KeyInfo[Type].VariableName, KeyInfo[Type].VariableGuid, List.Entry[i].Attrs,
					(List.Entry[i].Flags & USE_BUFFER) ? List.Entry[i].Buffer.Size : List.Entry[i].Variable.Size,
					(List.Entry[i].Flags & USE_BUFFER) ? (VOID*)List.Entry[i].Buffer.Data : (VOID*)List.Entry[i].Variable.Data);
			/* If we managed to install a PK, we're done */
			if (Type == PK && Status == EFI_SUCCESS)
				break;
			if (EFI_ERROR(Status)) {
				if ((Type == PK) && (List.Entry[i].Flags & FROM_DEFAULTS))
					RecallPrint(L"Notice: Manufacturer PK could not be reused (%r)\n", Status);
				else
					ReportErrorAndExit(L"Failed to set Secure Boot variable: %r\n", Status);
			}
		}
	}

	// If requested, create a NoPK.auth package, that can be used (with KeyTool or other utilities)
	// to delete the PK and set the platform back into Setup Mode.
	if (CreateNoPkFile && !UpdateMode) {
		MOSBY_VARIABLE NoPk = { 0 };
		if (SimpleFileExistsByPath(gBaseImageHandle, L"NoPK.auth")) {
			RecallPrint(L"WARNING: NOT creating a PK deletion package since 'NoPK.auth' already exists\n");
		} else {
			Status = CreateEmptyAuthVar(&NoPk);
			if (Status == EFI_SUCCESS)
				Status = SignAuthVar(KeyInfo[PK].VariableName, KeyInfo[PK].VariableGuid, UEFI_VAR_NV_BS_RT_AT, &NoPk, &PkCred);
			if (EFI_ERROR(Status)) {
				RecallPrint(L"WARNING: Could not create PK deletion package: %d\n", Status);
			} else {
				Status = SimpleFileWriteAllByPath(gBaseImageHandle, L"NoPK.auth", NoPk.Size, NoPk.Data);
				if (EFI_ERROR(Status))
					RecallPrint(L"WARNING: Could not create 'NoPK.auth': %d\n", Status);
				else
					RecallPrint(L"Saved PK deletion package as 'NoPK.auth'\n");
			}
			SafeFree(NoPk.Data);
		}
	}

	if (!gOptionSilent && !UpdateMode)
		Reboot = ExitNotice(GenDBCred);

exit:
	if (EFI_ERROR(Status) && DisplayErrorNotice && !gOptionSilent && !UpdateMode) {
		// The RISC-V gcc compiler adds implicit memcpy() calls here if you declare the text
		// blurb inline, *LIKE WE DO EVERYWHERE ELSE ABOVE WITHOUT ISSUE*, which of course
		// breaks UEFI app compilation. So we have to declare a static variable. WTF?!?
		STATIC CONST CHAR16 *WTF_RISC_COMPILER2[] = {
			L"ERROR",
			L"",
			L"Mosby was NOT able to install your Secure Boot variables.        ",
			L"",
			L"You will NOT be able to re-enable Secure Boot until you fix this.",
			L"",
			L"In case you used custom variables or parameters, you can  try  to",
			L"run Mosby again, with no options. Or, if that still doesn't work,",
			L"you will need to restore the Factory/Manufacturer keys  by  going",
			L"into your UEFI/BIOS firmware settings, and selecting the relevant",
			L"option, in the 'Secure Boot' menu.                               ",
			L"",
			NULL
		};
		ConsoleAlertBox(WTF_RISC_COMPILER2, (CONST CHAR16 *[]){ L"OK", NULL });
		RecallPrintRestore();
	}
	for (i = 0; i < List.Size; i++) {
		if (List.Entry[i].Flags & ALLOCATED_BUFFER)
			FreePool(List.Entry[i].Buffer.Data);
		if (List.Entry[i].Flags & FROM_DEFAULTS)
			FreePool(List.Entry[i].Description);
		FreePool(List.Entry[i].Variable.Data);
	}
	for (i = 0; i < ARRAY_SIZE(DefaultKey); i++)
		FreePool(DefaultKey[i].Data);
	FreeCredentials(&DbCred);
	FreeCredentials(&PkCred);
	FreePool(Argv);
	RecallPrintFree();
	CloseLogger();
	if (Reboot) {
		if (CountDown(L"Rebooting in", L"Press Esc to cancel, any other key to reboot immediately", 10000))
			gRT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
	}
	return Status;
}
