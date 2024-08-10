/*
 * MSSB (More Secure Secure Boot -- "Mosby") configuration file
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

/* Number of years certs created by this application will be valid for */
#define MOSBY_VALID_YEARS           30

/* Base name for the Secure Boot signing credentials we create */
#define MOSBY_CRED_NAME             L"Mosby Secure Boot Signing"

/* Name of the file containing the list of blobs to load */
#define MOSBY_LIST_NAME             L"MosbyList.txt"

/* Maximum number of entries that can be installed for each key type */
#define MOSBY_MAX_ENTRIES           16
