#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "Structs.h"
#define HOOKING_LIBRARY L"C:\\Users\\user\\Desktop\\MaldevAcademy\\MalDevEdr\\x64\\Debug\\MalDevEdr.dll"


/*
 * Given a function and the original value of its first bytes, print if it is hooked or not.
 *
 * @param[in] functionName name of the function.
 * @param[in] functionAddr address of the function.
 * @param[in] functionCleanContent first quadword of the function's code when unhooked.
 */
VOID PrintState(IN const char* functionName, IN PVOID functionAddr, IN size_t functionCleanContent) {
	printf("[#] %s [ 0x%p ] ---> %s \n", functionName, functionAddr, (*(size_t*)functionAddr == functionCleanContent) ? "[ UNHOOKED ]" : "[ HOOKED ]");
}

#define KNOWN_DLL_PATH L"\\KnownDlls\\"

typedef NTSTATUS(NTAPI* fnNtOpenSection)( OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

/**
 * Given the name of a dll, map it content from knownDlls and return the base address to the mapped memory.
 *
 * @param[in] dllName name of the dll.
 * @param[out] ppNtdllBuf pointer to the variable the will receive the base address of the mapped dll.
 * @return	true if succeded, false otherwise.
 */
bool MapDllFromKnownDlls(IN PWCH dllName, OUT PVOID* ppNtdllBuf) {

	HANDLE    		    hSection = NULL;
	PBYTE     		    pNtdllBuffer = NULL;
	NTSTATUS            STATUS = NULL;
	UNICODE_STRING      UniStr = { 0 };
	OBJECT_ATTRIBUTES  	ObjAtr = { 0 };

	// constructing the 'UNICODE_STRING' that will contain the '\KnownDlls\ntdll.dll' string
#define KNOWN_DLL_PATH L"\\KnownDlls\\"
	UniStr.Length = (sizeof(KNOWN_DLL_PATH) - 2) + (wcslen(dllName) * sizeof(WCHAR));
	UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);
	UniStr.Buffer = (PWCH)malloc(UniStr.MaximumLength);
	if (!UniStr.Buffer) {
		printf("[!][%s] malloc failed\n", __FUNCTION__);
		return false;
	}
	swprintf(UniStr.Buffer, UniStr.Length, L"%s%s", KNOWN_DLL_PATH, dllName);

	// initializing 'ObjAtr' with 'UniStr'
	InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// getting NtOpenSection address
	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");

	// getting the handle of the known dll from KnownDlls
	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
	if (STATUS != 0x00) {
		printf("[!] NtOpenSection Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

	// mapping the view of file of the known dll
	pNtdllBuffer = (PBYTE) MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hSection)
		CloseHandle(hSection);
	if (UniStr.Buffer) {
		free(UniStr.Buffer);
		UniStr.Buffer = NULL;
	}
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}

/**
 * Copy the .text section of a mapped dll to another one.
 *
 * @param[in] localDllbase base address of the local dll that will be ovewritten (the hooked one).
 * @param[in] remoteDllBase base address of the dll that contains the clean version of the .text section.
 * @return	true if succeded, false otherwise.
 */
bool ReplaceDllTxtSection(IN PVOID localDllbase, IN PVOID remoteDllBase) {
	// getting the dos header
	PIMAGE_DOS_HEADER   pLocalDosHdr = (PIMAGE_DOS_HEADER)localDllbase;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS   pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)localDllbase + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalDllTxt = NULL,	// local hooked text section base address
				pRemoteDllTxt = NULL; // the unhooked text section base address
	SIZE_T		sDllTxtSize = NULL;	// the size of the text section


	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ( 
			*((char*)(pSectionHeader[i].Name)) == '.' && 
			*(((char*)(pSectionHeader[i].Name))+1) == 't' &&
			*(((char*)(pSectionHeader[i].Name)) + 2) == 'e' &&
			*(((char*)(pSectionHeader[i].Name)) + 3) == 'x' &&
			*(((char*)(pSectionHeader[i].Name)) + 4) == 't'
			) {
			pLocalDllTxt = (PVOID)((ULONG_PTR)localDllbase + pSectionHeader[i].VirtualAddress);
			pRemoteDllTxt = (PVOID)((ULONG_PTR)remoteDllBase + pSectionHeader[i].VirtualAddress);
			sDllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	// small check to verify that all the required information is retrieved
	if (!pLocalDllTxt || !pRemoteDllTxt || !sDllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalDllTxt != *(ULONG*)pRemoteDllTxt)
		return FALSE;

	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalDllTxt, sDllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalDllTxt, pRemoteDllTxt, sDllTxtSize);

	// restoring the old memory protection
	if (!VirtualProtect(pLocalDllTxt, sDllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

// given a wchar_t, make the lowercase
#define LowerW(c) ((c >= L'A' && c <= L'Z') ? c - (L'A' - L'a') : c)


/**
 * Return the index of the extension ".dll" in the string; case insensitive.
 *
 * @param[in] nameToLower the string to look into.
 * @return	the searched index; -1 if the substring ".dll" is not found.
 */
long int GetExtIndex(IN wchar_t *nameToLower) {
	long int lastExtIndex = -1;
	for (long int i = 0; nameToLower[i]; i++){
		if (LowerW(nameToLower[i]) == L'l' && i >= 3 && LowerW(nameToLower[i - 1]) == L'l' && LowerW(nameToLower[i - 2]) == L'd' && LowerW(nameToLower[i - 3]) == L'.')
			lastExtIndex = i - 3;
	}
	return lastExtIndex;
}

/**
 * Similar to strcmp_s, compares two strings of wchar_t; case insensitive.
 *
 * @param[in] str1 the first string to compare.
 * @param[in] str2 the first string to compare.
 * @param[in] count the number of characters to check.
 * @return 0 if the strings are equal, >0 if str1 is greater than str2, <0 otherwise.
 */
int strcmpLowerW_s(IN wchar_t* str1, IN wchar_t* str2, IN size_t count) {
	if (!str1 && !str2)
		return 0;
	if (!str1)
		return -1;
	if (!str2)
		return 1;
	for (size_t i = 0; i < count; i++) {
		if (!str1[i] && !str2[i])
			return 0;
		if (LowerW(str1[i]) != LowerW(str2[i]))
			return LowerW(str1[i]) - LowerW(str2[i]);
	}
	return 0;
}


/**
 * Given the name of a dll, check if it is present in KnownDlls.
 *
 * @param[in] dllToCheck name of the dl lto check.
 * @return true if the dll is present, false otherwise.
 */
bool IsKnownDll(IN wchar_t* dllToCheck) {
	wchar_t knownDllValue[MAX_PATH];
	long int dllToCheckExtIndex = 0;
	DWORD knownDllvalueSize = sizeof(knownDllValue);

	dllToCheckExtIndex = GetExtIndex(dllToCheck);
	if (dllToCheckExtIndex == -1)
		return false;
	dllToCheck[dllToCheckExtIndex] = 0;
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", dllToCheck, RRF_RT_ANY, NULL, &knownDllValue, &knownDllvalueSize);
	dllToCheck[dllToCheckExtIndex] = L'.';
	if (knownDllvalueSize == 0 || knownDllvalueSize > sizeof(knownDllValue) || strcmpLowerW_s(dllToCheck, knownDllValue, knownDllvalueSize) != 0)
		return false;
	else
		return true;
}


// struct that represents a dll to unhook.
// The dlls to unhook are kept in a single-linked list, with one element for each dll.
typedef struct _DLL_TO_UNHOOK {
	wchar_t* dllName;				// name of the dll
	PVOID localDllBase;				// base address of the local mapped dll (the hooked one)
	PVOID remoteDllBase;			// base address of the dll mapped from KnownDlls(the clean one)
	struct _DLL_TO_UNHOOK* next;	// pointer to the next element of the list

} DLL_TO_UNHOOK, * PDLL_TO_UNHOOK;


/**
 * Iterates through the modules loaded in the current process and build a list of the dlls that are also present in the KnownDlls directory.
 *
 * @param[out] dllsToUnhookHead pointer to a variable that receives the pointer to the head of the list.
 * @return	true if succeded, false otherwise.
 */
bool FetchLoadedKnownDlls(OUT PDLL_TO_UNHOOK* dllsToUnhookHead){
	PDLL_TO_UNHOOK lastDllToUnhook = NULL;
	
	PTEB pTeb = (PTEB)__readgsqword(0x30);
	PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
	// Getting the Ldr
	PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// If not null
		if (pDte->FullDllName.Length != NULL) {
			wchar_t* tmpDllName = (wchar_t*)malloc(pDte->FullDllName.MaximumLength);
			memcpy(tmpDllName, pDte->FullDllName.Buffer, pDte->FullDllName.MaximumLength);
			if (IsKnownDll(tmpDllName)) {
				if (!lastDllToUnhook) {
					*dllsToUnhookHead = lastDllToUnhook = (PDLL_TO_UNHOOK) malloc(sizeof(DLL_TO_UNHOOK));
				}
				else {
					lastDllToUnhook->next = (PDLL_TO_UNHOOK)malloc(sizeof(DLL_TO_UNHOOK));
					lastDllToUnhook = lastDllToUnhook->next;
				}
				lastDllToUnhook->dllName = tmpDllName;
				lastDllToUnhook->localDllBase = GetModuleHandleW(lastDllToUnhook->dllName);
				lastDllToUnhook->remoteDllBase = NULL;
				lastDllToUnhook->next = NULL;
			}
			else {
				free(tmpDllName);
			}
		}
		else {
			break;
		}

		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}
	return TRUE;
}


/**
 * Replace the .text section of all the loaded dlls that can be found in KnownDlls directory.
 *
 * @return	true if succeded, false otherwise.
 */
bool UnhookAllKnownDlls() {
	PDLL_TO_UNHOOK dllsToUnhookHead = NULL, dllToUnhook = NULL;
	
	// iterate through InMemoryOrderModuleList and fetch dlls that are contained in knowndlls
	// build list of dlls to unhook, keep dllname and dll base addr
	if (!FetchLoadedKnownDlls(&dllsToUnhookHead))
		return false;


	dllToUnhook = dllsToUnhookHead;
	while (dllToUnhook){
		wprintf(L"[i] unhooking \"%s\" \n", dllToUnhook->dllName);
		if (!MapDllFromKnownDlls(dllToUnhook->dllName, &(dllToUnhook->remoteDllBase))) {
			printf("[!][%s] MapNtdllFromKnownDlls failed\n", __FUNCTION__);
			return false;
		}
		if (!ReplaceDllTxtSection(dllToUnhook->localDllBase, dllToUnhook->remoteDllBase)) {
			printf("[!][%s] ReplaceDllTxtSection failed\n", __FUNCTION__);
			return false;
		}
		dllToUnhook = dllToUnhook->next;
	}

	// unmap remote dlls and free the list
	while (dllsToUnhookHead) {
		if (!UnmapViewOfFile(dllsToUnhookHead->remoteDllBase)) {
			printf("[!][%s] UnmapViewOfFile for dll %S failed\n", __FUNCTION__, dllToUnhook->dllName);
			return false;
		}
		dllToUnhook = dllsToUnhookHead;
		dllsToUnhookHead = dllsToUnhookHead->next;
		free(dllToUnhook);
	}
	return TRUE;

}


int main()
{
	PVOID messageBoxWAddr = NULL, messageBoxAAddr = NULL;
	size_t MessageBoxWCleanContent, MessageBoxACleanContent;

	messageBoxWAddr = MessageBoxW;
	messageBoxAAddr = MessageBoxA;
	MessageBoxWCleanContent = *((size_t*)MessageBoxW);
	MessageBoxACleanContent = *((size_t*)MessageBoxA);

	PrintState("MessageBoxW", messageBoxWAddr, MessageBoxWCleanContent);
	PrintState("MessageBoxA", messageBoxAAddr, MessageBoxACleanContent);

	MessageBoxW(NULL, L"unhooked", L"MessageBoxW", 0);
	MessageBoxA(NULL, "unhooked", "MessageBoxA", 0);

	printf("Press Enter for hooking...\n");
	getchar();
	// load the hooking library, it hooks the function MessageBoxW and blocks its execution
	LoadLibraryW(HOOKING_LIBRARY);
	WaitForSingleObject((HANDLE)-1, 2*1000);

	PrintState("MessageBoxW", messageBoxWAddr, MessageBoxWCleanContent);
	PrintState("MessageBoxA", messageBoxAAddr, MessageBoxACleanContent);
	MessageBoxW(NULL, L"hooked", L"MessageBoxW", 0);
	MessageBoxA(NULL, "unhooked", "MessageBoxA", 0);

	printf("Press Enter for unhooking...\n");
	getchar();
	if (!UnhookAllKnownDlls()) {
		printf("[!][%s] UnhookAllKnownDlls failed\n", __FUNCTION__);
		return 1;
	}
	
	PrintState("MessageBoxW", messageBoxWAddr, MessageBoxWCleanContent);
	PrintState("MessageBoxA", messageBoxAAddr, MessageBoxACleanContent);
	MessageBoxW(NULL, L"unhooked", L"MessageBoxW", 0);
	MessageBoxA(NULL, "unhooked", "MessageBoxA", 0);
	return 0;
}

