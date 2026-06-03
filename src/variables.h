/*
 * MSSB (More Secure Secure Boot -- "Mosby") Secure Boot variables handling
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

typedef struct {
	UINT64 Total;
	UINT64 Free;
	UINT64 MaxVar;
} NV_STORAGE_SIZE;

EFI_STATUS CheckSetupMode(VOID);

BOOLEAN IsOsIndicationsSupported(
	IN CONST UINT64 Indication
);

EFI_STATUS SetOsIndication(
	IN CONST UINT64 Indication
);

BOOLEAN ExitNotice(
	IN CONST BOOLEAN KeysGenerated
);

NV_STORAGE_SIZE* GetNvStorageDetails(VOID);
