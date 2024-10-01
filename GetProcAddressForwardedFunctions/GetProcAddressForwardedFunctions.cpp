#include <windows.h>
#include <stdio.h>



FARPROC GetProcAddressForwadedFunctions(IN HMODULE hModule, IN LPCSTR  lpProcName) {
    PBYTE pBase = (PBYTE)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
	// assuming that module names and function names are smaller than MAX_PATH (260) bytes
	char forwardedModuleName[MAX_PATH], forwardedFunctionName[MAX_PATH];

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the ordinal of the function
		WORD wFunctionOrdinal = FunctionOrdinalArray[i];

		// Getting the address of the function through it's ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);

		if (strcmp(lpProcName, pFunctionName) == 0) {
			// If the function address is still inside the export dir, it is a pointer to the forwarding string
			// to resolve, just recursively call GetProcAddress() with the forwarded function module.name
			// https://github.com/arbiter34/GetProcAddress
			// It shouldn't be necessary to load the module of the forwarded function,
			// since it is loaded as dependency of the module of the function we are searching.
			if (pFunctionAddress >= pImgExportDir && pFunctionAddress < (PVOID)(((ULONG_PTR)pImgExportDir) + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
				char* curs = (char*) pFunctionAddress;
				size_t i = 0;
				while (*curs != '.') 
					forwardedModuleName[i++] = *(curs++);
				forwardedModuleName[i] = 0;
				i = 0;
				curs++;
				while (*curs != '.')
					forwardedFunctionName[i++] = *(curs++);
				forwardedFunctionName[i] = 0;
				return GetProcAddressForwadedFunctions(GetModuleHandleA(forwardedModuleName), forwardedFunctionName);
			} else {
				return (FARPROC) pFunctionAddress;
			}
		}
	}
	return NULL;

}

int main()
{
	PVOID fun17, fun18;
	HMODULE hAdvapi = LoadLibrary(L"advapi32.dll");
	fun17 = GetProcAddress(hAdvapi, "SystemFunction017");
	fun18 = GetProcAddress(hAdvapi, "SystemFunction018");
	printf("SystemFunction017\t%p\n", fun17);
	printf("SystemFunction018\t%p\n", fun18);
	printf("-----------------------------------------------\n");
	fun17 = NULL;
	fun18 = NULL;
	fun17 = GetProcAddressForwadedFunctions(hAdvapi, "SystemFunction017");
	fun18 = GetProcAddressForwadedFunctions(hAdvapi, "SystemFunction018");
	printf("SystemFunction017\t%p\n", fun17);
	printf("SystemFunction018\t%p\n", fun18);
	WaitForSingleObject((HANDLE)-1, -1);
	return 0;
}
