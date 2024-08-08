/*
 * uefi-md5sum: UEFI MD5Sum validator - UTF-8 conversion functions
 * Copyright © 2023 Pete Batard <pete@akeo.ie>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
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

/* Shorthand for Unicode strings */
typedef UINT32              CHAR32;

/**
  Decode a Unicode character from a UTF-8 sequence.

  @param[in]  Start  A pointer to the start of the UTF-8 sequence.
  @param[out] Size   A pointer to the variable that receives the size of the decoded UTF-8 sequence.

  @return The next Unicode character or (CHAR32)-1 on error.
**/
STATIC CHAR32 GetNextUnicodeChar(
	IN CONST CHAR8* Start,
	OUT UINTN* Size
)
{
	CHAR32 UnicodeChar = (CHAR32)-1;

	if (Start == NULL || Size == NULL)
		return (CHAR32)-1;

	if ((*Start & 0x80) == 0x00) {
		// Lower ASCII character
		*Size = 1;
	} else if ((*Start & 0xE0) == 0xC0) {
		// Two-byte UTF-8 character
		*Size = 2;
	} else if ((*Start & 0xF0) == 0xE0) {
		// Three-byte UTF-8 character
		*Size = 3;
	} else if ((*Start & 0xF8) == 0xF0) {
		// Four-byte UTF-8 character
		*Size = 4;
	} else {
		// Invalid UTF-8 encoding
		*Size = 0;
		return (CHAR32)-1;
	}

	// Decode the UTF-8 sequence into a 32-bit Unicode character
	switch (*Size) {
	case 1:
		UnicodeChar = *Start;
		break;
	case 2:
		UnicodeChar = (*Start & 0x1F) << 6;
		UnicodeChar |= (*(Start + 1) & 0x3F);
		break;
	case 3:
		UnicodeChar = (*Start & 0x0F) << 12;
		UnicodeChar |= (*(Start + 1) & 0x3F) << 6;
		UnicodeChar |= (*(Start + 2) & 0x3F);
		break;
	case 4:
		UnicodeChar = (*Start & 0x07) << 18;
		UnicodeChar |= (*(Start + 1) & 0x3F) << 12;
		UnicodeChar |= (*(Start + 2) & 0x3F) << 6;
		UnicodeChar |= (*(Start + 3) & 0x3F);
		break;
	default:
		// Invalid UTF-8 encoding
		*Size = 0;
		return (CHAR32)-1;
	}

	// Return the Unicode character
	return UnicodeChar;
}

/**
  Convert a UTF-8 encoded string to a UCS-2 encoded string.

  @param[in]  Utf8String      A pointer to the input UTF-8 encoded string.
  @param[out] Ucs2String      A pointer to the output UCS-2 encoded string.
  @param[in]  Ucs2StringSize  The size of the Ucs2String buffer (in CHAR16).

  @retval EFI_SUCCESS            The conversion was successful.
  @retval EFI_INVALID_PARAMETER  One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL   The output buffer is too small to hold the result.
**/
EFI_STATUS Utf8ToUcs2(
	IN CONST CHAR8* Utf8String,
	OUT CHAR16* Ucs2String,
	IN CONST UINTN Ucs2StringSize
)
{
	CHAR32 UnicodeChar;
	UINTN Size, Index = 0, Ucs2Index = 0;

	if (Utf8String == NULL || Ucs2String == NULL)
		return EFI_INVALID_PARAMETER;

	// Iterate through the UTF-8 string
	while (Utf8String[Index] != '\0') {
		// Decode UTF-8 character to Unicode
		UnicodeChar = GetNextUnicodeChar(&Utf8String[Index], &Size);

		// Check for decoding errors
		if (UnicodeChar == (CHAR32)-1 || Size == 0)
			return EFI_INVALID_PARAMETER;

		// Increment the index by the size of the UTF-8 character
		Index += Size;

		// Encode Unicode character to UCS-2
		if (UnicodeChar > 0xFFFF) {
			// Convert to surrogate pair
			if (Ucs2Index + 2 >= Ucs2StringSize)
				return EFI_BUFFER_TOO_SMALL;
			UnicodeChar -= 0x10000;
			Ucs2String[Ucs2Index++] = (CHAR16)(0xD800 + (UnicodeChar >> 10));
			Ucs2String[Ucs2Index++] = (CHAR16)(0xDC00 + (UnicodeChar & 0x3FF));
		} else {
			if (Ucs2Index + 1 >= Ucs2StringSize)
				return EFI_BUFFER_TOO_SMALL;
			Ucs2String[Ucs2Index++] = (CHAR16)UnicodeChar;
		}
	}

	// NUL-terminate the UCS-2 string
	Ucs2String[Ucs2Index] = L'\0';

	return EFI_SUCCESS;
}
