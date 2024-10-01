// Self implemented common APIs used by the shellcode
// Some code is taken from Maldev Academy modules
#pragma once

#include <windows.h>
#include "Structs.h"


// given a char, return the lowercase
#define toLower(c) ((c >= 0x41 && c <= 0x5a) ? c - ('A'-'a') : c)


// like wcscmp, but case insensitive
int strcmpLowerW(LPCWSTR str1, LPCWSTR str2) {
	if (!str1 && !str2)
		return 0;
	if (!str1)
		return -1;
	if (!str2)
		return 1;

	while (*str1 && toLower(*str1) == toLower(*str2)) {
		str1++;
		str2++;
	}
	return toLower(*str1) - toLower(*str2);
}


// self-implemented strcmp
int strcmp(const char* str1, const char* str2) {
	if (!str1 && !str2)
		return 0;
	if (!str1)
		return -1;
	if (!str2)
		return 1;

	while (*str1 && *str1 == *str2) {
		str1++;
		str2++;
	}
	return *str1 - *str2;
}


// self-implemented memset
void* memset(void* dest, int x, size_t count) {
	char* destC = (char*) dest;
	while (count > 0) {
		*(destC++) = (char)x;
		count--;
	}
	return dest;
}


// self-implemented GetModuleHandle
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {
	// Getting PEB
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));

	// Getting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	// Getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// If not null
		if (pDte->FullDllName.Length != NULL) {

			// Check if both equal
			if (strcmpLowerW(pDte->FullDllName.Buffer, szModuleName) == 0) {
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
			}
		}
		else {
			break;
		}

		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}


/// self-implemented GetProcAddress
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0) {
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}

