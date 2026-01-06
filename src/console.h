/*
 * Copyright 2012 James Bottomley <James.Bottomley@HansenPartnership.com>
 * Copyright 2024-2026 Pete Batard <pete@akeo.ie>
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

#pragma once

#include <Base.h>
#include <Uefi.h>

#define NOSEL 0x7fffffff

/* Error reporting macros */
#define ReportErrorAndExit(...) do { RecallPrint(__VA_ARGS__); goto exit; } while(0)
#define Abort(s, ...)           do { Status = s; RecallPrint(__VA_ARGS__); goto exit; } while(0) 

#define SetTextPosition(x, y)   gST->ConOut->SetCursorPosition(gST->ConOut, x, y)

EFI_INPUT_KEY ConsoleGetKeystroke(VOID);

INTN ConsoleCheckForKeystroke(
	IN CHAR16 Key
);

EFI_STATUS ConsolePrintBoxAt(
	IN CONST CHAR16 *StrArray[],
	IN INTN Highlight,
	IN INTN StartCol,
	IN INTN StartRow,
	IN INTN SizeCols,
	IN INTN SizeRows,
	IN INTN Offset,
	IN INTN Lines
);

VOID ConsolePrintBox(
	IN CONST CHAR16 *StrArray[],
	IN INTN Highlight
);

INTN ConsoleSelect(
	IN CONST CHAR16 *Title[],
	IN CONST CHAR16* Selectors[],
	IN INTN Start
);

INTN ConsoleYesNo(
	IN CONST CHAR16 *StrArray[]
);

INTN ConsoleOkCancel(
	IN CONST CHAR16 *StrArray[]
);

VOID ConsoleAlertBox(
	IN CONST CHAR16 *StrArray[]
);

VOID ConsoleErrorBox(
	IN CONST CHAR16 *Err
);

VOID ConsoleError(
	IN CONST CHAR16 *Err,
	IN CONST EFI_STATUS Status
);

VOID ConsoleInit(VOID);

UINTN EFIAPI Logger(
	IN  CONST CHAR16 *FormatString,
	...
);

EFI_STATUS OpenLogger(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Name
);

VOID CloseLogger(VOID);

UINTN EFIAPI RecallPrint(
	IN  CONST CHAR16 *FormatString,
	...
);

VOID RecallPrintRestore(VOID);

VOID RecallPrintFree(VOID);

BOOLEAN CountDown(
	IN CONST CHAR16* Message,
	IN CONST CHAR16* Notes,
	IN CONST UINTN Duration
);
