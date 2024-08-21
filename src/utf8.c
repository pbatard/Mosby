/*
 * UTF-8 conversion functions
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
#include <Library/BaseMemoryLib.h>

/* Shorthand for Unicode strings */
typedef UINT32              CHAR32;

/**
  Decode a Unicode character from a UTF-8 sequence.

  @param[in]  Start  A pointer to the start of the UTF-8 sequence.
  @param[out] Size   A pointer to the variable that receives the size of the decoded UTF-8 sequence.

  @return The next Unicode character or (CHAR32)-1 on error.
**/
STATIC CHAR32 GetNextUnicodeChar(
	IN CONST CHAR8 *Start,
	OUT UINTN *Size
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
  Convert a UTF-8 encoded string to a UTF-16 encoded string.

  @param[in]  Utf8String         A pointer to the input UTF-8 encoded string.
  @param[out] Utf16String        A pointer to the output UTF-16 encoded string.
  @param[in]  Utf16StringSize    The size of the Utf16String buffer (in CHAR16).

  @retval EFI_SUCCESS            The conversion was successful.
  @retval EFI_INVALID_PARAMETER  One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL   The output buffer is too small to hold the result.
**/
EFI_STATUS Utf8ToUtf16(
	IN CONST CHAR8 *Utf8String,
	OUT CHAR16 *Utf16String,
	IN CONST UINTN Utf16StringSize
)
{
	CHAR32 UnicodeChar;
	UINTN Size, Utf8Index = 0, Utf16Index = 0;

	if (Utf8String == NULL || Utf16String == NULL)
		return EFI_INVALID_PARAMETER;

	// Iterate through the UTF-8 string
	while (Utf8String[Utf8Index] != '\0') {
		// Decode UTF-8 character to Unicode
		UnicodeChar = GetNextUnicodeChar(&Utf8String[Utf8Index], &Size);

		// Check for decoding errors
		if (UnicodeChar == (CHAR32)-1 || Size == 0)
			return EFI_INVALID_PARAMETER;

		// Increment the index by the size of the UTF-8 character
		Utf8Index += Size;

		// Encode Unicode character to UTF-16
		if (UnicodeChar > 0xFFFF) {
			// Convert to surrogate pair
			if (Utf16Index + 2 >= Utf16StringSize)
				return EFI_BUFFER_TOO_SMALL;
			UnicodeChar -= 0x10000;
			Utf16String[Utf16Index++] = (CHAR16)(0xD800 + (UnicodeChar >> 10));
			Utf16String[Utf16Index++] = (CHAR16)(0xDC00 + (UnicodeChar & 0x3FF));
		} else {
			if (Utf16Index + 1 >= Utf16StringSize)
				return EFI_BUFFER_TOO_SMALL;
			Utf16String[Utf16Index++] = (CHAR16)UnicodeChar;
		}
	}

	// NUL-terminate the UTF-16 string
	Utf16String[Utf16Index] = L'\0';

	return EFI_SUCCESS;
}

/**
  Encode a UTF-16 sequence into a UTF-8 sequence.

  @param[in]  Utf16Ptr   A reference to the pointer of the start of the UTF-16 sequence.
                         This pointer is incremented as the UTF-16 string is read.
  @param[out] Size       A pointer to the variable that receives the size of the encoded UTF-8 sequence.

  @return The UTF-8 sequence. On error *Size is set to 0.
**/
STATIC CHAR8* GetNextUtf8Sequence(
	IN CHAR16 **Utf16Ptr,
	OUT UINTN *Size
)
{
	STATIC CHAR8 Utf8Sequence[4];
	CHAR16 Utf16Char, HighSurrogate, LowSurrogate;
	CHAR32 UnicodeChar;

	Utf16Char = **Utf16Ptr;
	if (Utf16Char <= 0x007F) {
		Utf8Sequence[0] = (CHAR8)**Utf16Ptr;
		*Size = 1;
		// Increment only if we haven't reached the NUL terminator
		if (Utf16Char != L'\0')
			(*Utf16Ptr)++;
	} else if (Utf16Char <= 0x07FF) {
		Utf8Sequence[0] = (CHAR8)(0xC0 | ((Utf16Char >> 6) & 0x1F));
		Utf8Sequence[1] = (CHAR8)(0x80 | (Utf16Char & 0x3F));
		*Size = 2;
		(*Utf16Ptr)++;
	} else if (Utf16Char >= 0xD800 && Utf16Char <= 0xDBFF) {
		// Surrogate pair handling
		HighSurrogate = Utf16Char;
		(*Utf16Ptr)++;
		LowSurrogate = **Utf16Ptr;
		// Increment only if we haven't reached the NUL terminator
		if (LowSurrogate != L'\0')
			(*Utf16Ptr)++;
		if (LowSurrogate < 0xDC00 || LowSurrogate > 0xDFFF) {
			Utf8Sequence[0] = '\0';	// Invalid surrogate pair
			*Size = 0;
		} else {
			UnicodeChar = (((CHAR32)(HighSurrogate - 0xD800) << 10) |
						   (CHAR32)(LowSurrogate - 0xDC00)) + 0x10000;
			Utf8Sequence[0] = (CHAR8)(0xF0 | ((UnicodeChar >> 18) & 0x07));
			Utf8Sequence[1] = (CHAR8)(0x80 | ((UnicodeChar >> 12) & 0x3F));
			Utf8Sequence[2] = (CHAR8)(0x80 | ((UnicodeChar >> 6) & 0x3F));
			Utf8Sequence[3] = (CHAR8)(0x80 | (UnicodeChar & 0x3F));
			*Size = 4;
		}
	} else {
		Utf8Sequence[0] = (CHAR8)(0xE0 | ((Utf16Char >> 12) & 0x0F));
		Utf8Sequence[1] = (CHAR8)(0x80 | ((Utf16Char >> 6) & 0x3F));
		Utf8Sequence[2] = (CHAR8)(0x80 | (Utf16Char & 0x3F));
		*Size = 3;
		(*Utf16Ptr)++;
	}

	return Utf8Sequence;
}

/**
  Convert a UTF-16 encoded string to a UTF-8 encoded string.

  @param[in]  Utf16String        A pointer to the input UTF-8 encoded string.
  @param[out] Utf8String         A pointer to the output UTF-16 encoded string.
  @param[in]  Utf8StringSize     The size of the Utf8String buffer (in CHAR8).

  @retval EFI_SUCCESS            The conversion was successful.
  @retval EFI_INVALID_PARAMETER  One or more of the input parameters are invalid.
  @retval EFI_BUFFER_TOO_SMALL   The output buffer is too small to hold the result.
**/
EFI_STATUS Utf16ToUtf8(
	IN CONST CHAR16 *Utf16String,
	OUT CHAR8 *Utf8String,
	IN CONST UINTN Utf8StringSize
)
{
	UINTN Size, Utf8Index = 0;
	CHAR8 *Utf8Seq;
	CHAR16 *Utf16Ptr;

	if (Utf16String == NULL || Utf8String == NULL)
		return EFI_INVALID_PARAMETER;

	Utf16Ptr = (CHAR16*)Utf16String;
	while (*Utf16Ptr != L'\0') {
		Utf8Seq = GetNextUtf8Sequence(&Utf16Ptr, &Size);
		if (Size == 0)
			return EFI_INVALID_PARAMETER;
		if (Size + Utf8Index + 1 > Utf8StringSize)
			return EFI_BUFFER_TOO_SMALL;
		CopyMem(&Utf8String[Utf8Index], Utf8Seq, Size);
		Utf8Index += Size;
	}

	// NUL-terminate the UTF-8 string
	Utf8String[Utf8Index] = 0;

	return EFI_SUCCESS;
}
