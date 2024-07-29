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

EFI_INPUT_KEY ConsoleGetKeystroke(VOID);
INTN ConsoleCheckForKeystroke(CHAR16 Key);
EFI_STATUS ConsolePrintBoxAt(CHAR16 *StrArray[], INTN Highlight, INTN StartCol,
	INTN StartRow, INTN SizeCols, INTN SizeRows, INTN Offset, INTN Lines);
VOID ConsolePrintBox(CHAR16 *StrArray[], INTN Highlight);
INTN ConsoleSelect(CHAR16 *Title[], CHAR16* Selectors[], INTN Start);
INTN ConsoleYesNo(CHAR16 *StrArray[]);
VOID ConsoleAlertBox(CHAR16 **Title);
VOID ConsoleErrorBox(CHAR16 *Err);
VOID ConsoleError(CHAR16 *Err, EFI_STATUS Status);
VOID ConsoleReset(VOID);

#define NOSEL 0x7fffffff
