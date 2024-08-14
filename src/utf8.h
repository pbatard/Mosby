/*
 * MSSB (More Secure Secure Boot -- "Mosby") UTF-8 functions
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

/* Check for a valid whitespace character */
STATIC __inline BOOLEAN IsWhiteSpace(CHAR8 c)
{
	return (c == ' ' || c == '\t');
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
);
