#include <windows.h>
#include "APIs.h"

// to build, run buildShellcode.sh from a wsl

// Needed APIs function signature
typedef int (*fnMessageBoxW)(IN HWND hWnd,IN LPCWSTR lpText, IN LPCWSTR lpCaption, IN UINT uType);
typedef HMODULE (*fnLoadLibraryW)(IN LPCWSTR lpLibFileName);

// struct that contains resolved APIs
typedef struct _API_TABLE {
	fnMessageBoxW MessageBoxW;
	fnLoadLibraryW LoadLibraryW;
} API_TABLE, *PAPI_TABLE;


// struct that contains APIs and global variables
typedef struct _GLOBAL_DATA {
	API_TABLE APIs;
} GLOBAL_DATA, *PGLOBAL_DATA;

/*
 * Find the needed APIs addresses and fill the APIs table.
 *
 * @param[out] APITable pointer to the table that will contain the addresses of APIs.
 * @return	true if succeded, false otherwise.
 */
BOOL resolveAPIs(OUT PAPI_TABLE APITable) {
	// assuming kernel32.dll already loaded, otherwise we need to use LdrLoadDll from ntdll
	// Retrieve LoadLibraryW address
	wchar_t kernel32Name[] = {L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0x0};
	char LoadLibraryWName[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	HMODULE hKernel32 = GetModuleHandleReplacement(kernel32Name);
	if (!hKernel32) {
		return 0;
	}
	APITable->LoadLibraryW = (fnLoadLibraryW) GetProcAddressReplacement(hKernel32, LoadLibraryWName);
	if (!APITable->LoadLibraryW)
		return 0;

	// Retrieve MessageBoxW address
	wchar_t user32[] = {L'u', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', 0x0};
	char MessageBoxW[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'W', 0x0 };

	HMODULE hUser32 = APITable->LoadLibraryW(user32);
	if (!hKernel32)
		return 0;

	APITable->MessageBoxW = (fnMessageBoxW) GetProcAddressReplacement(hUser32, MessageBoxW);
	if (!APITable->MessageBoxW)
		return 0;
	return 1;
}


/*
 * Function that run the main shellcode code.
 *
 * @param[in] globalData struct that contains "global" variables and resolved APIs.
 */
void shellcodeWorker(IN PGLOBAL_DATA globalData) {
	wchar_t text[] = { L'S', L'p', L'a', L'w', L'n', L'e', L'd', 0x0 };
	wchar_t caption[] = { L'S', L'H', L'E', L'L', L'L', L'C', L'O', L'D', L'E', 0x0 };
	globalData->APIs.MessageBoxW(NULL, text, caption, 0);
}

/*
 * Effective entrypoint of the shellcode. This functions calls the APIs initializer and then calls the shellcode's worker function.
 */
void entrypoint() {
	GLOBAL_DATA globalData;
	if (!resolveAPIs(&(globalData.APIs)))
		return;
	shellcodeWorker(&globalData);
}

