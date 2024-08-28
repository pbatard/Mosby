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
#include "version.h"

/* Globals */
EFI_HANDLE gBaseImageHandle = NULL;

STATIC BOOLEAN gOptionSilent = FALSE;

/* MokList GUID - Not yet defined in EDK2 */
STATIC EFI_GUID gEfiShimLockGuid =
	{ 0x605DAB50, 0xE046, 0x4300, { 0xAB, 0xB6, 0x3D, 0xD8, 0x10, 0xDD, 0x8B, 0x23 } };

/* Attributes for the "key" types we support */
STATIC struct {
	CHAR8 *Name;
	CHAR16 *VarName;
	EFI_GUID *VarGuid;
} KeyInfo[MAX_TYPES] = {
	[PK] = {
		.Name = "PK",
		.VarName = EFI_PLATFORM_KEY_NAME,
		.VarGuid = &gEfiGlobalVariableGuid,
	},
	[KEK] = {
		.Name = "KEK",
		.VarName = EFI_KEY_EXCHANGE_KEY_NAME,
		.VarGuid = &gEfiGlobalVariableGuid,
	},
	[DB] = {
		.Name = "DB",
		.VarName = EFI_IMAGE_SECURITY_DATABASE,
		.VarGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBX] = {
		.Name = "DBX",
		.VarName = EFI_IMAGE_SECURITY_DATABASE1,
		.VarGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[DBT] = {
		.Name = "DBT",
		.VarName = EFI_IMAGE_SECURITY_DATABASE2,
		.VarGuid = &gEfiImageSecurityDatabaseGuid,
	},
	[MOK] = {
		.Name = "MOK",
		.VarName = L"MokList",
		.VarGuid = &gEfiShimLockGuid,
	}
};

STATIC CHAR16* StrDup(
	IN CONST CHAR16* Src
)
{
	CHAR16* Dst;

	if (Src == NULL)
		return NULL;

	Dst = AllocateZeroPool((StrLen(Src) + 1) * sizeof(CHAR16));
	if (Dst != NULL)
		CopyMem(Dst, Src, (StrLen(Src) + 1) * sizeof(CHAR16));

	return Dst;
}

/* Convert a UTF-8 path to UTF-16 while replacing any %ARCH% token */
STATIC CHAR16* ConvertPath(
	IN CHAR8 *Src
)
{
	EFI_STATUS Status = EFI_INVALID_PARAMETER;
	CONST CHAR8 *Token = "%ARCH%";
	// Use the same arch names as the suffixes used for UEFI bootloaders
#if defined(_M_X64) || defined(__x86_64__)
	CONST CHAR16 *Rep = L"x64";
#elif defined(_M_IX86) || defined(__i386__)
	CONST CHAR16 *Rep = L"ia32";
#elif defined (_M_ARM64) || defined(__aarch64__)
	CONST CHAR16 *Rep = L"aa64";
#elif defined (_M_ARM) || defined(__arm__)
	CONST CHAR16 *Rep = L"arm";
#elif defined(_M_RISCV64) || (defined (__riscv) && (__riscv_xlen == 64))
	CONST CHAR16 *Rep = L"riscv64";
#else
#	error Unsupported architecture
#endif
	CHAR16 Dst[MAX_PATH], Frag[MAX_PATH];
	CHAR8 *Ptr, Old;

	if (AsciiStrLen(Src) > MAX_PATH)
		ReportErrorAndExit(L"Path data is longer than %d characters\n", MAX_PATH);

	*Dst = L'\0';
	while ((Ptr = AsciiStrStr(Src, Token)) != NULL) {
		Old = *Ptr;
		*Ptr = 0;
		if (*Src != '\0') {
			Status = Utf8ToUtf16(Src, Frag, ARRAY_SIZE(Frag));
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Failed to convert '%a'\n", Src);
			Status = StrCatS(Dst, MAX_PATH, Frag);
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Failed to convert '%a'\n", Src);
		}
		Status = StrCatS(Dst, MAX_PATH, Rep);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to convert '%a'\n", Src);
		Src = &Ptr[AsciiStrLen(Token)];
		*Ptr = Old;
	}
	if (*Src != '\0') {
		Status = Utf8ToUtf16(Src, Frag, ARRAY_SIZE(Frag));
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"Failed to convert '%a'\n", Src);
		Status = StrCatS(Dst, MAX_PATH, Frag);
			if (EFI_ERROR(Status))
				ReportErrorAndExit(L"Failed to convert '%a'\n", Src);
	}

exit:
	return EFI_ERROR(Status) ? NULL : StrDup(Dst);
}

EFI_STATUS ParseList(
	IN CONST CHAR16 *ListFileName,
	OUT INSTALLABLE_COLLECTION *Installable
)
{
	UINTN i, Type;
	EFI_STATUS Status;

	SetMem((VOID *)Installable, sizeof(INSTALLABLE_COLLECTION), 0);

	// NB: SimpleFileReadAllByPath() adds an extra NUL to the data read
	Status = SimpleFileReadAllByPath(gBaseImageHandle, ListFileName, &Installable->ListDataSize, (VOID**)&Installable->ListData);
	if (EFI_ERROR(Status))
		goto exit;

	for (i = 0; i < Installable->ListDataSize; i++)
		if (Installable->ListData[i] == '\r' || Installable->ListData[i] == '\n')
			Installable->ListData[i] = 0;
	for (i = 0; i < Installable->ListDataSize; ) {
		// Ignore whitespaces and control characters
		while (Installable->ListData[i] <= ' ' && i < Installable->ListDataSize)
			i++;
		if (i >= Installable->ListDataSize)
			break;
		if (Installable->ListData[i] == '#') {
			// Ignore comments
		} else if (Installable->ListData[i] == '[') {
			if (AsciiStrCmp(&Installable->ListData[i], "[SILENT]") == 0) {
				gOptionSilent = TRUE;
			} else {
				Status = EFI_NO_MAPPING;
				ReportErrorAndExit(L"Unrecognized option '%a'\n", &Installable->ListData[i]);
			};
		} else {
			for (Type = 0; Type < MAX_TYPES; Type++) {
				if (i + AsciiStrLen(KeyInfo[Type].Name) >= Installable->ListDataSize)
					continue;
				if (AsciiStrnCmp(KeyInfo[Type].Name, &Installable->ListData[i], AsciiStrLen(KeyInfo[Type].Name)) != 0)
					continue;
				if (!IsWhiteSpace(Installable->ListData[i + AsciiStrLen(KeyInfo[Type].Name)]))
					continue;
				i += AsciiStrLen(KeyInfo[Type].Name);
				while (IsWhiteSpace(Installable->ListData[i]) && i < Installable->ListDataSize)
					i++;
				if (Installable->List[Type].NumEntries < MOSBY_MAX_ENTRIES) {
					Installable->List[Type].Path[Installable->List[Type].NumEntries] =
						ConvertPath(&Installable->ListData[i]);
					if (Installable->List[Type].Path[Installable->List[Type].NumEntries] == NULL)
						return EFI_NO_MAPPING;
					Installable->List[Type].NumEntries++;
				}
				break;
			}
			if (Type >= MAX_TYPES) {
				Status = EFI_NO_MAPPING;
				ReportErrorAndExit(L"Failed to parse '%s'\n", ListFileName);
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

// We can't use EnrollFromInput() since it doesn't support Appending.
STATIC EFI_STATUS SetSecureBootVariable(
	EFI_SIGNATURE_LIST *Esl,
	UINTN Type,
	BOOLEAN Append
)
{
	// TODO: MOK may need different options
	CONST UINT32 VarAttributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS |
		EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	EFI_STATUS Status;
	EFI_TIME Time = { 0 };
	UINT8 *VarData;
	UINTN VarSize;

	Status = gRT->GetTime(&Time, NULL);
	if (EFI_ERROR(Status)) {
		RecallPrint(L"Failed to get current time: %r\n", Status);
		return Status;
	}

	// SetVariable() *will* fail with "Security Violation" unless you
	// explicitly zero these before calling CreateTimeBasedPayload()
	Time.Nanosecond = 0;
	Time.TimeZone = 0;
	Time.Daylight = 0;

	VarData = (UINT8*)Esl;
	VarSize = Esl->SignatureListSize;
	// NB: CreateTimeBasedPayload() frees the input buffer before replacing it
	Status = CreateTimeBasedPayload(&VarSize, &VarData, &Time);
	if (EFI_ERROR(Status)) {
		SafeFree(Esl);
		RecallPrint(L"Failed to create time-based data payload: %r\n", Status);
		return Status;
	}

	Status = gRT->SetVariable(KeyInfo[Type].VarName, KeyInfo[Type].VarGuid,
			VarAttributes | (Append ? EFI_VARIABLE_APPEND_WRITE : 0), VarSize, VarData);
	SafeFree(VarData);
	if (EFI_ERROR(Status))
		RecallPrint(L"Failed to set Secure Boot variable: %r\n", Status);

	return EFI_SUCCESS;
}

/*
 * Application entry-point
 */
EFI_STATUS EFIAPI efi_main(
	IN EFI_HANDLE BaseImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	BOOLEAN TestMode = FALSE;
	EFI_STATUS Status, SetStatus;
	UINT8 SecureBoot = 0, SetupMode = 0;
	UINTN Size;
	INTN Argc, Type, Entry;
	VOID *Cert, *Key;
	CHAR16 **Argv = NULL, **ArgvCopy, Path[MAX_PATH];
	INSTALLABLE_COLLECTION Installable = { 0 };

	ConsoleReset();
	RecallPrint(L"Mosby %s\n", VERSION_STRING);
	gBaseImageHandle = BaseImageHandle;

	/* 0. Parse arguments */
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
			} else {
				// Unsupported argument
				break;
			}
		}
	}

	/* 1. Verify that the platform is in Setup Mode */
	if (!TestMode) {
		Size = sizeof(SecureBoot);
		Status = gRT->GetVariable(EFI_SECURE_BOOT_MODE_NAME, &gEfiGlobalVariableGuid, NULL, &Size, &SecureBoot);
		if (EFI_ERROR(Status))
			ReportErrorAndExit(L"This platform does not support Secure Boot.\n");
		Size = sizeof(SetupMode);
		Status = gRT->GetVariable(EFI_SETUP_MODE_NAME, &gEfiGlobalVariableGuid, NULL, &Size, &SetupMode);
		if (EFI_ERROR(Status) || SecureBoot == SECURE_BOOT_MODE_ENABLE || SetupMode != SETUP_MODE) {
			Status = EFI_UNSUPPORTED;
			ReportErrorAndExit(L"ERROR: This platform is not in Setup Mode.\n");
			// TODO: More explanatory error message and possibly automate switch to Setup?
		}
	}

	/* 2. Initialize the random generator and validate the platform */
	Status = InitializePki();
	if (EFI_ERROR(Status))
		ReportErrorAndExit(L"This platform does not meet the minimum security requirements.\n");

	/* 3. Parse and validate the list file */
	Status = ParseList(MOSBY_LIST_NAME, &Installable);
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
		RecallPrintRestore();
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
		RecallPrintRestore();
		if (Sel != 0)
			goto exit;
	}

	/* 5. Load and validate the support files (KEKs, DBs, DBX, etc) */
	for (Type = 0; Type < MAX_TYPES; Type++) {
		for (Entry = 0; Entry < Installable.List[Type].NumEntries; Entry++) {

			if (Installable.List[Type].Path[Entry] == NULL)
				continue;

			// DB/PK types have modes such as [DETECT], [GENERATE], [PROMPT]
			if ((Type == DB || Type == PK) && StrCmp(Installable.List[Type].Path[Entry], L"[GENERATE]") == 0)
				continue;

			if (Type == DB && StrCmp(Installable.List[Type].Path[Entry], L"[DETECT]") == 0) {
				SafeFree(Installable.List[Type].Path[Entry]);
				// If we have an existing cert for a previously generated DB credential, try to reuse it
				UnicodeSPrint(Path, MAX_PATH, L"%s.crt", MOSBY_CRED_NAME);
				// Switch to [PROMPT] if we can't access an exisiting cert
				if (SimpleFileExistsByPath(gBaseImageHandle, Path))
					Installable.List[Type].Path[Entry] = StrDup(Path);
				else
					Installable.List[Type].Path[Entry] = StrDup(L"[PROMPT]");
			}

			if (Type == DB && StrCmp(Installable.List[Type].Path[Entry], L"[PROMPT]") == 0) {
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
				RecallPrintRestore();
				SafeFree(Installable.List[Type].Path[Entry]);
				if (Sel == 0) {
					Installable.List[Type].Path[Entry] = StrDup(L"[SELECT]");
				} else if (Sel == 1) {
					Installable.List[Type].Path[Entry] = StrDup(L"[GENERATE]");
					continue;
				} else {
					Installable.List[Type].Path[Entry] = NULL;
					continue;
				}
			}

			if (StrCmp(Installable.List[Type].Path[Entry], L"[SELECT]") == 0) {
				CHAR16 Title[80];
				EFI_HANDLE Handle = NULL;
				SafeFree(Installable.List[Type].Path[Entry]);
				UnicodeSPrint(Title, ARRAY_SIZE(Title), L"Please select %a %s",
					KeyInfo[Type].Name, (Type == DBX) ? L"binary" : L"certificate");
				Status = SimpleFileSelector(&Handle,
					(CONST CHAR16 *[]){
						L"",
						Title,
						NULL
					}, L"\\", L".cer|.crt|.esl|.bin", &Installable.List[Type].Path[Entry]);
				RecallPrintRestore();
				if (EFI_ERROR(Status))
					continue;
				if (!SimpleFileExistsByPath(gBaseImageHandle, Installable.List[Type].Path[Entry])) {
					RecallPrint(L"No valid file selected for %a[%d] - Ignoring\n", KeyInfo[Type].Name, Entry);
					continue;
				}
			}

			Installable.List[Type].Esl[Entry] = LoadToEsl(Installable.List[Type].Path[Entry]);

			if (Installable.List[Type].Esl[Entry] == NULL) {
				RecallPrint(L"Failed to load %a[%d] - Aborting\n", KeyInfo[Type].Name, Entry);
				goto exit;
			}
		}
	}

	/* 6. Generate a keyless PK cert if none was specified */
	if (Installable.List[PK].Esl[0] == NULL) {
		RecallPrint(L"Generating PK certificate...\n");
		SafeFree(Installable.List[PK].Path[0]);
		Installable.List[PK].Path[0] = StrDup(L"AutoGenerated");
		Cert = GenerateCredentials("Mosby Generated PK", NULL);
		Installable.List[PK].Esl[0] = CertToEsl(Cert);
		if (Installable.List[PK].Esl[0] == NULL) {
			SafeFree(Cert);
			goto exit;
		}
	}

	/* 7. Generate DB credentials if requested */
	for (Entry = 0; Entry < Installable.List[DB].NumEntries &&
		StrCmp(Installable.List[DB].Path[Entry], L"[GENERATE]") != 0; Entry++);
	if (Entry < Installable.List[DB].NumEntries) {
		RecallPrint(L"Generating Secure Boot signing credentials...\n");
		SafeFree(Installable.List[DB].Path[Entry]);
		Installable.List[DB].Path[Entry] = StrDup(L"AutoGenerated");
		Cert = GenerateCredentials("Secure Boot signing", &Key);;
		Installable.List[DB].Esl[Entry] = CertToEsl(Cert);
		if (Installable.List[DB].Esl[Entry] == NULL) {
			SafeFree(Cert);
			goto exit;
		}
		Status = SaveCredentials(Cert, Key, MOSBY_CRED_NAME);
		if (EFI_ERROR(Status))
			goto exit;
		RecallPrint(L"Saved Secure Boot signing credentials as '%s'\n", MOSBY_CRED_NAME);
	}

	/* 8. Install the cert and DBX variables, making sure that we finish with the PK. */
	for (Type = MAX_TYPES - 1; Type >= 0; Type--) {
		for (Entry = 0; Entry < Installable.List[Type].NumEntries; Entry++) {
			if (Installable.List[Type].Esl[Entry] != NULL) {
				RecallPrint(L"Installing %a[%d] (from %s)\n", KeyInfo[Type].Name, Entry, Installable.List[Type].Path[Entry]);
				SetStatus = SetSecureBootVariable(Installable.List[Type].Esl[Entry], Type, (Entry != 0));
				if (EFI_ERROR(SetStatus))
					Status = SetStatus;
			}
		}
	}

exit:
	for (Type = 0; Type < MAX_TYPES; Type++)
		for (Entry = 0; Entry < MOSBY_MAX_ENTRIES; Entry++) {
			FreePool(Installable.List[Type].Path[Entry]);
			FreePool(Installable.List[Type].Esl[Entry]);
		}
	FreePool(Installable.ListData);
	FreePool(Argv);
	RecallPrintFree();
	return Status;
}
