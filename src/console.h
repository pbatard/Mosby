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

#pragma once

#include <Base.h>
#include <Uefi.h>

#define NOSEL 0x7fffffff

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
	IN CONST CHAR16 **Title
);

VOID ConsoleErrorBox(
	IN CONST CHAR16 *Err
);

VOID ConsoleError(
	IN CONST CHAR16 *Err,
	IN CONST EFI_STATUS Status
);

VOID ConsoleReset(VOID);
