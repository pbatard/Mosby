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

#include "file.h"
#include "console.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/TimeBaseLib.h> 
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Uefi/UefiBaseType.h>

#define MAX_PRINT_LINES             50
#define MAX_LINE_SIZE               120
#define DEFAULT_FOREGROUND_COLOR    EFI_LIGHTGRAY
#define DEFAULT_BACKGROUND_COLOR    EFI_BACKGROUND_BLUE

STATIC UINTN CurrentLine = 0;
STATIC CHAR16* PrintLine[MAX_PRINT_LINES] = { 0 };
STATIC CHAR16 LogPath[80];
STATIC EFI_FILE_HANDLE LogHandle = NULL;
STATIC UINTN ForeGroundColor = DEFAULT_FOREGROUND_COLOR;
STATIC UINTN BackGroundColor = DEFAULT_BACKGROUND_COLOR;

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
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;
	UINTN Cols, Rows;
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
			Console->SetAttribute(Console, ForeGroundColor | EFI_BACKGROUND_BLACK);
		Console->SetCursorPosition(Console, StartCol, i);
		Console->OutputString(Console, Line);
		if (LineNum >= 0 && LineNum == Highlight)
			Console->SetAttribute(Console, ForeGroundColor | BackGroundColor);
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
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;
	CopyMem(&SavedConsoleMode, Console->Mode, sizeof(SavedConsoleMode));
	Console->ClearScreen(Console);
	Console->EnableCursor(Console, FALSE);
	Console->SetAttribute(Console, ForeGroundColor | BackGroundColor);

	ConsolePrintBoxAt(StrArray, Highlight, 0, 0, -1, -1, 0, CountLines(StrArray));

	ConsoleGetKeystroke();

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);

	Console->EnableCursor(Console, SavedConsoleMode.CursorVisible);
	Console->SetCursorPosition(Console, SavedConsoleMode.CursorColumn, SavedConsoleMode.CursorRow);
	Console->SetAttribute(Console, SavedConsoleMode.Attribute);
}

INTN ConsoleSelect(
	IN CONST CHAR16 *Title[],
	IN CONST CHAR16 *Selectors[],
	IN INTN Start
)
{
	EFI_SIMPLE_TEXT_OUTPUT_MODE SavedConsoleMode;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;
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
	Console->ClearScreen(Console);
	Console->EnableCursor(Console, FALSE);
	Console->SetAttribute(Console, ForeGroundColor | BackGroundColor);

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
	IN CONST CHAR16 *StrArray[]
)
{
	BackGroundColor = EFI_BACKGROUND_RED;
	ConsoleSelect(StrArray, (CONST CHAR16 *[]){ L"OK", 0 }, 0);
	BackGroundColor = DEFAULT_BACKGROUND_COLOR;
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

	BackGroundColor = EFI_BACKGROUND_RED;
	ConsoleAlertBox(ErrArray);
	BackGroundColor = DEFAULT_BACKGROUND_COLOR;
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

	BackGroundColor = EFI_BACKGROUND_RED;
	ConsoleAlertBox(ErrArray);
	BackGroundColor = DEFAULT_BACKGROUND_COLOR;
}

VOID ConsoleInit(VOID)
{
	UINTN Cols, Rows;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;

	// Some broken firmware implementations (<cough>HP ProDesk 600 G1<cough>) have a default
	// console where mode 0 overshoots the screen (on a 4k monitor) until SetMode is called.
	// So we call SetMode with the current mode to fix that. Also, you do *NOT* want to call
	// Console->Reset() as it may switch from a default high res mode to low res mode 0...
	Console->QueryMode(Console, Console->Mode->Mode, &Cols, &Rows);
	Console->SetMode(Console, Console->Mode->Mode);
	Console->ClearScreen(Console);
}

EFI_STATUS GetLocalTime(EFI_TIME *Time)
{
	EFI_TIME InternalTime;
	EFI_STATUS Status;
	UINT64 Epoch;

	Status = gRT->GetTime(&InternalTime, NULL);
	if (EFI_ERROR(Status))
		return Status;

	// Convert EFI_TIME to Unix epoch
	Epoch = EfiTimeToEpoch(&InternalTime);

	// Apply timezone correction
	if (InternalTime.TimeZone != EFI_UNSPECIFIED_TIMEZONE)
		Epoch += (INTN)InternalTime.TimeZone * 60;

	// Apply DST
	if (InternalTime.Daylight & EFI_TIME_IN_DAYLIGHT)
		Epoch -= 3600;

	// Convert back to EFI_TIME
	EpochToEfiTime(Epoch, Time);
	Time->TimeZone = 0;
	Time->Daylight = 0;

	return EFI_SUCCESS;
}

EFI_STATUS OpenLogger(
	IN CONST EFI_HANDLE Image,
	IN CONST CHAR16 *Path
)
{
	EFI_TIME Time = { 0 };
	CHAR16 TimeStamp[MAX_LINE_SIZE];
	EFI_STATUS Status;
	EFI_HANDLE DeviceHandle;
	CONST CHAR16 *PathStart;

	StrCpyS(LogPath, 80, Path); 
	GetLocalTime(&Time);
	UnicodeSPrint(TimeStamp, MAX_LINE_SIZE * sizeof(CHAR16),
		L"%s[Mosby session started: %4u-%02u-%02u %02u:%02u:%02u]\n",
		SimpleFileExistsByPath(Image, Path) ? L"\r\n" : L"\uFEFF",
		Time.Year, Time.Month, Time.Day, Time.Hour, Time.Minute, Time.Second);

	PathStart = GetDeviceHandleFromPath(Image, Path, &DeviceHandle);
	Status = SimpleFileOpen(DeviceHandle == NULL ? Image : DeviceHandle,
		PathStart, &LogHandle, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE);
	if (Status == EFI_SUCCESS) {
		LogHandle->SetPosition(LogHandle, 0xFFFFFFFFFFFFFFFF);
		Status = SimpleFileWriteAll(LogHandle, StrLen(TimeStamp) * sizeof(CHAR16), TimeStamp);
	}
	return Status;
}

VOID CloseLogger(VOID)
{
	EFI_TIME Time = { 0 };
	CHAR16 TimeStamp[MAX_LINE_SIZE];

	if (LogHandle == NULL)
		return;

	GetLocalTime(&Time);
	UnicodeSPrint(TimeStamp, MAX_LINE_SIZE * sizeof(CHAR16),
		L"[Mosby session ended: %4u-%02u-%02u %02u:%02u:%02u]\n",
		Time.Year, Time.Month, Time.Day, Time.Hour, Time.Minute, Time.Second);
	SimpleFileWriteAll(LogHandle, StrLen(TimeStamp) * sizeof(CHAR16), TimeStamp);
	SimpleFileClose(LogHandle);
	Print(L"Saved log to '%s'\n", LogPath);
}

/* Console + file output */
UINTN EFIAPI Logger(
	IN  CONST CHAR16 *FormatString,
	...
)
{
	// NB: VA_LIST requires the function call to be EFIAPI decorated
	UINTN Ret;
	VA_LIST Marker;
	CHAR16 PrintLine[MAX_LINE_SIZE];

	if (StrLen(FormatString) == 0)
		return 0;
	PrintLine[0] = L'\0';
	VA_START(Marker, FormatString);
	Ret = UnicodeVSPrint(PrintLine, MAX_LINE_SIZE * sizeof(CHAR16), FormatString, Marker);
	VA_END(Marker);
	// If we truncate a line with that ends with an LF, make sure we keep the LF
	if (FormatString[StrLen(FormatString) - 1] == L'\n')
		PrintLine[MAX_LINE_SIZE - 2] = L'\n';
	if (LogHandle != NULL)
		SimpleFileWriteAll(LogHandle, StrLen(PrintLine) * sizeof(CHAR16), PrintLine);
	return Ret;
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

	if (StrLen(FormatString) == 0)
		return 0;
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
	Print(L"%s", PrintLine[CurrentLine]);
	if (LogHandle != NULL)
		SimpleFileWriteAll(LogHandle, StrLen(PrintLine[CurrentLine]) * sizeof(CHAR16), PrintLine[CurrentLine]);
	CurrentLine++;
	return Ret;
}

VOID RecallPrintRestore(VOID)
{
	UINTN i;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;

	Console->ClearScreen(Console);
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

VOID FlushKeyboardInput(VOID)
{
	EFI_INPUT_KEY Key = { 0 };

	gST->ConIn->Reset(gST->ConIn, TRUE);
	// Per specs, the above is supposed to be enough to clear the keystroke
	// buffer. However, some firmwares do not seem to be specs compliant so
	// we add additional manual flushing.
	while (gST->BootServices->CheckEvent(gST->ConIn->WaitForKey) != EFI_NOT_READY) {
		gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
		gBS->Stall(50000);
	}
}

BOOLEAN CountDown(
	IN CONST CHAR16* Message,
	IN CONST CHAR16* Notes,
	IN CONST UINTN Duration
)
{
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Console = gST->ConOut;
	EFI_INPUT_KEY Key;
	UINTN MessagePos, NotesPos, CounterPos;
	UINTN Rows, Cols;
	INTN i;
	CHAR16 EmptyLine[256] = { 0 };

	Console->QueryMode(Console, Console->Mode->Mode, &Cols, &Rows);	
	MessagePos = Cols / 2 - StrLen(Message) / 2 - 1;
	CounterPos = MessagePos + StrLen(Message) + 2;
	NotesPos = Cols / 2 - StrLen(Notes) / 2 - 1;

	for (i = 0; i < Cols; i++)
		EmptyLine[i] = L' ';
	EmptyLine[i] = L'\0';
	for (i = 2; i <= 4; i++) {
		SetTextPosition(0, Rows - i);
		Print(EmptyLine);
	}
	SetTextPosition(MessagePos, Rows - 4);
	Print(L"[%s ", Message);
	if (Notes != NULL) {
		SetTextPosition(NotesPos, Rows - 2);
		Print(Notes);
	}
	
	FlushKeyboardInput();
	for (i = (INTN)Duration; i >= 0; i -= 200) {
		// Allow the user to press a key to interrupt the countdown
		if (gST->BootServices->CheckEvent(gST->ConIn->WaitForKey) != EFI_NOT_READY) {
			if (gST->ConIn->ReadKeyStroke(gST->ConIn, &Key) == EFI_SUCCESS)
				return (Key.ScanCode != SCAN_ESC);
		}
		if (i % 1000 == 0) {
			SetTextPosition(CounterPos, Rows - 4);
			Print(L"%d]   ", i / 1000);
		}
		gBS->Stall(200000);
	}
	return TRUE;
}
