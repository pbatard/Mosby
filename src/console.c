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

#include <Base.h>
#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Uefi/UefiBaseType.h>

#define MAX_PRINT_LINES   50
#define MAX_LINE_SIZE     120

STATIC UINTN CurrentLine = 0;
STATIC CHAR16* PrintLine[MAX_PRINT_LINES] = { 0 };

STATIC __inline INTN CountLines(
	IN CONST CHAR16 *StrArray[]
)
{
	INTN i = 0;

	while (StrArray[i] != NULL)
		i++;
	return i;
}

EFI_INPUT_KEY ConsoleGetKeystroke(VOID)
{
	EFI_INPUT_KEY Key;
	UINTN EventIndex;

	gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
	gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

	return Key;
}

INTN ConsoleCheckForKeystroke(
	IN CHAR16 Key
)
{
	EFI_INPUT_KEY Input;
	EFI_STATUS Status;
	// Check for both upper and lower cases
	CHAR16 KeyUp = Key & ~0x20, KeyLow = Key | 0x20;

	// The assumption is the user has been holding the key down so empty
	// the key buffer at this point because auto repeat may have filled it
	for(;;) {
		Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Input);

		if (EFI_ERROR(Status))
			break;

		if (KeyUp == Input.UnicodeChar || KeyLow == Input.UnicodeChar)
			return 1;
	}
	return 0;
}

EFI_STATUS ConsolePrintBoxAt(
	IN CONST CHAR16 *StrArray[],
	IN INTN Highlight,
	IN INTN StartCol,
	IN INTN StartRow,
	IN INTN SizeCols,
	IN INTN SizeRows,
	IN INTN Offset,
	IN INTN Lines
)
{
	INTN i;
	SIMPLE_TEXT_OUTPUT_INTERFACE *Console = gST->ConOut;
	UINTN Rows, Cols;
	CHAR16 *Line;

	if (Lines == 0)
		return EFI_INVALID_PARAMETER;

	Console->QueryMode(Console, Console->Mode->Mode, &Cols, &Rows);

	// Last row on screen is unusable without scrolling, so ignore it
	Rows--;

	if (SizeRows < 0)
		SizeRows = Rows + SizeRows + 1;
	if (SizeCols < 0)
		SizeCols = Cols + SizeCols + 1;

	if (StartCol < 0)
		StartCol = (Cols + StartCol + 2)/2;
	if (StartRow < 0)
		StartRow = (Rows + StartRow + 2)/2;
	if (StartCol < 0)
		StartCol = 0;
	if (StartRow < 0)
		StartRow = 0;

	if (StartCol > Cols || StartRow > Rows) {
		Print(L"Starting Position (%d,%d) is off screen\n", StartCol, StartRow);
		return EFI_UNSUPPORTED;
	}
	if (SizeCols + StartCol > Cols)
		SizeCols = Cols - StartCol;
	if (SizeRows + StartRow > Rows)
		SizeRows = Rows - StartRow;

	if (Lines > SizeRows - 2)
		Lines = SizeRows - 2;

	Line = AllocatePool((SizeCols + 1) * sizeof(CHAR16));
	if (!Line) {
		Print(L"Failed Allocation\n");
		return EFI_OUT_OF_RESOURCES;
	}

	SetMem16(Line, SizeCols * 2, BOXDRAW_HORIZONTAL);

	Line[0] = BOXDRAW_DOWN_RIGHT;
	Line[SizeCols - 1] = BOXDRAW_DOWN_LEFT;
	Line[SizeCols] = L'\0';
	Console->SetCursorPosition(Console, StartCol, StartRow);
	Console->OutputString(Console, Line);

	INTN Start;
	if (Offset == 0)
		// Middle
		Start = (SizeRows - Lines) / 2 + StartRow + Offset;
	else if (Offset < 0)
		// From bottom
		Start = StartRow + SizeRows - Lines + Offset - 1;
	else
		// From top
		Start = StartRow + Offset;

	for (i = StartRow + 1; i < SizeRows + StartRow - 1; i++) {
		INTN LineNum = i - Start;

		SetMem16 (Line, SizeCols * 2, L' ');
		Line[0] = BOXDRAW_VERTICAL;
		Line[SizeCols - 1] = BOXDRAW_VERTICAL;
		Line[SizeCols] = L'\0';
		if (LineNum >= 0 && LineNum < Lines) {
			CONST CHAR16 *Str = StrArray[LineNum];
			INTN Len = StrLen(Str);
			INTN Col = (SizeCols - 2 - Len) / 2;

			if (Col < 0)
				Col = 0;

			CopyMem(Line + Col + 1, Str, MIN(Len, SizeCols - 2) * 2);
		}
		if (LineNum >= 0 && LineNum == Highlight)
			Console->SetAttribute(Console, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
		Console->SetCursorPosition(Console, StartCol, i);
		Console->OutputString(Console, Line);
		if (LineNum >= 0 && LineNum == Highlight)
			Console->SetAttribute(Console, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);
	}

	SetMem16(Line, SizeCols * 2, BOXDRAW_HORIZONTAL);
	Line[0] = BOXDRAW_UP_RIGHT;
	Line[SizeCols - 1] = BOXDRAW_UP_LEFT;
	Line[SizeCols] = L'\0';
	Console->SetCursorPosition(Console, StartCol, i);
	Console->OutputString(Console, Line);

	FreePool(Line);
	return EFI_SUCCESS;
}

VOID ConsolePrintBox(
	IN CONST CHAR16 *StrArray[],
	IN INTN Highlight
)
{
	EFI_SIMPLE_TEXT_OUTPUT_MODE SavedConsoleMode;
	SIMPLE_TEXT_OUTPUT_INTERFACE *Console = gST->ConOut;
	CopyMem(&SavedConsoleMode, Console->Mode, sizeof(SavedConsoleMode));
	Console->EnableCursor(Console, FALSE);
	Console->SetAttribute(Console, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);

	ConsolePrintBoxAt(StrArray, Highlight, 0, 0, -1, -1, 0, CountLines(StrArray));

	ConsoleGetKeystroke();

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);
	Console->SetCursorPosition(Console, SavedConsoleMode.CursorColumn, SavedConsoleMode.CursorRow);
	Console->SetAttribute(Console, SavedConsoleMode.Attribute);
}

INTN ConsoleSelect(
	IN CONST CHAR16 *Title[],
	IN CONST CHAR16* Selectors[],
	IN INTN Start
)
{
	EFI_SIMPLE_TEXT_OUTPUT_MODE SavedConsoleMode;
	SIMPLE_TEXT_OUTPUT_INTERFACE *Console = gST->ConOut;
	EFI_INPUT_KEY k;
	INTN Selector;
	INTN SelectorLines = CountLines(Selectors);
	INTN SelectorMaxCols = 0;
	INTN i, OffsetCols, OffsetRows, SizeCols, SizeRows, Lines;
	INTN SelectorOffset;
	INTN TitleLines = CountLines(Title);
	UINTN Cols, Rows;

	Console->QueryMode(Console, Console->Mode->Mode, &Cols, &Rows);

	for (i = 0; i < SelectorLines; i++) {
		INTN Len = StrLen(Selectors[i]);

		if (Len > SelectorMaxCols)
			SelectorMaxCols = Len;
	}

	if (Start < 0)
		Start = 0;
	if (Start >= SelectorLines)
		Start = SelectorLines - 1;

	OffsetCols = - SelectorMaxCols - 4;
	SizeCols = SelectorMaxCols + 4;

	if (SelectorLines > Rows - 6 - TitleLines) {
		OffsetRows = TitleLines + 2;
		SizeRows = Rows - 4 - TitleLines;
		Lines = SizeRows - 2;
	} else {
		OffsetRows = (Rows + TitleLines - 1 - SelectorLines)/2;
		SizeRows = SelectorLines + 2;
		Lines = SelectorLines;
	}

	if (Start > Lines) {
		Selector = Lines;
		SelectorOffset = Start - Lines;
	} else {
		Selector = Start;
		SelectorOffset = 0;
	}

	CopyMem(&SavedConsoleMode, Console->Mode, sizeof(SavedConsoleMode));
	Console->EnableCursor(Console, FALSE);
	Console->SetAttribute(Console, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);

	ConsolePrintBoxAt(Title, -1, 0, 0, -1, -1, 1, CountLines(Title));

	ConsolePrintBoxAt(Selectors, Selector, OffsetCols, OffsetRows, SizeCols, SizeRows, 0, Lines);

	do {
		k = ConsoleGetKeystroke();

		if (k.ScanCode == SCAN_ESC) {
			Selector = -1;
			break;
		}

		if (k.ScanCode == SCAN_UP) {
			if (Selector > 0)
				Selector--;
			else if (SelectorOffset > 0)
				SelectorOffset--;
		} else if (k.ScanCode == SCAN_DOWN) {
			if (Selector < Lines - 1)
				Selector++;
			else if (SelectorOffset < (SelectorLines - Lines))
				SelectorOffset++;
		}

		ConsolePrintBoxAt(&Selectors[SelectorOffset], Selector, OffsetCols, OffsetRows, SizeCols, SizeRows, 0, Lines);
	} while (!(k.ScanCode == SCAN_NULL && k.UnicodeChar == CHAR_CARRIAGE_RETURN));

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);
	Console->SetCursorPosition(Console, SavedConsoleMode.CursorColumn, SavedConsoleMode.CursorRow);
	Console->SetAttribute(Console, SavedConsoleMode.Attribute);

	if (Selector < 0)
		// ESC pressed
		return Selector;
	return Selector + SelectorOffset;
}


INTN ConsoleYesNo(
	IN CONST CHAR16 *StrArray[]
)
{
	return ConsoleSelect(StrArray, (CONST CHAR16 *[]){ L"Yes", L"No", NULL }, 0);
}

INTN ConsoleOkCancel(
	IN CONST CHAR16 *StrArray[]
)
{
	return ConsoleSelect(StrArray, (CONST CHAR16 *[]){ L"OK", L"Cancel", NULL }, 0);
}

VOID ConsoleAlertBox(
	IN CONST CHAR16 **Title
)
{
	ConsoleSelect(Title, (CONST CHAR16 *[]){ L"OK", 0 }, 0);
}

VOID ConsoleErrorBox(
	IN CONST CHAR16 *Err
)
{
	CONST CHAR16 **ErrArray = (CONST CHAR16 *[]){
		L"ERROR",
		L"",
		0,
		0,
	};

	ErrArray[2] = Err;

	ConsoleAlertBox(ErrArray);
}

VOID ConsoleError(
	IN CONST CHAR16 *Err,
	IN CONST EFI_STATUS Status
)
{
	CONST CHAR16 **ErrArray = (CONST CHAR16 *[]){
		L"ERROR",
		L"",
		0,
		0,
	};
	CHAR16 Str[512];

	UnicodeSPrint(Str, sizeof(Str), L"%s: (%d) %r", Err, Status, Status);

	ErrArray[2] = Str;

	ConsoleAlertBox(ErrArray);
}

VOID ConsoleReset(VOID)
{
	SIMPLE_TEXT_OUTPUT_INTERFACE *Console = gST->ConOut;

	Console->Reset(Console, TRUE);
	// Set mode 0 - required to be 80x25
	Console->SetMode(Console, 0);
	Console->ClearScreen(Console);
}

/* Set of functions enabling printed data to persist on screen after displaying a dialog */
UINTN EFIAPI RecallPrint(
	IN  CONST CHAR16 *FormatString,
	...
)
{
	// NB: VA_LIST requires the function call to be EFIAPI decorated
	VA_LIST Marker;
	UINTN Ret;

	if (CurrentLine >= MAX_PRINT_LINES)
		return 0;

	PrintLine[CurrentLine] = AllocateZeroPool(MAX_LINE_SIZE * sizeof(CHAR16));
	if (PrintLine[CurrentLine] == NULL)
		return 0;

	VA_START(Marker, FormatString);
	Ret = UnicodeVSPrint(PrintLine[CurrentLine], MAX_LINE_SIZE * sizeof(CHAR16), FormatString, Marker);
	VA_END(Marker);
	// If we truncate a line with that ends with an LF, make sure we keep the LF
	if (FormatString[StrLen(FormatString) - 1] == L'\n')
		PrintLine[CurrentLine][MAX_LINE_SIZE - 2] = L'\n';
	Print(L"%s", PrintLine[CurrentLine++]);
	return Ret;
}

VOID RecallPrintRestore(VOID)
{
	UINTN i;

	ConsoleReset();
	for (i = 0; i < CurrentLine; i++)
		Print(L"%s", PrintLine[i]);
}

VOID RecallPrintFree(VOID)
{
	UINTN i;

	for (i = 0; i < MAX_PRINT_LINES; i++) {
		FreePool(PrintLine[i]);
		PrintLine[i] = NULL;
	}
	CurrentLine = 0;
}
