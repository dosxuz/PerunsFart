#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "functions.h"
#include "helper.h"

CreateProcessA_t CreateProcessA_p = (CreateProcessA_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateProcessA");
NtReadVirtualMemory_t NtReadVirtualMemory_p = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtReadVirtualMemory");

int main()
{
	//start process in a suspended state
	STARTUPINFOA* si = new STARTUPINFOA();
	PROCESS_INFORMATION* pi = new PROCESS_INFORMATION();
	//BOOL stat = CreateProcessA_p(nullptr, (LPSTR)"C:\\Windows\\System32\\svchost.exe", nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, si, pi);
	BOOL stat = CreateProcessA_p(nullptr, (LPSTR)"cmd.exe", nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, "C:\\Windows\\System32\\", si, pi);

	HANDLE hProcess = pi->hProcess;
	printf("PID : %d\n", pi->dwProcessId);
	getchar();
	WCHAR findname[] = L"ntdll.dll\x00";
	PVOID ntdllBase = GetDll(findname);
	printf("ntdll.dll base address : 0x%p\n", ntdllBase);

	//Read the ntdll.dll from the remote suspended process
	PIMAGE_DOS_HEADER ImgDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS ImgNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + (ImgDosHeader->e_lfanew));
	IMAGE_OPTIONAL_HEADER OptHeader = (IMAGE_OPTIONAL_HEADER)ImgNTHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER textsection = IMAGE_FIRST_SECTION(ImgNTHeaders);

	DWORD ntdllSize = OptHeader.SizeOfImage;
	LPVOID freshNtdll = VirtualAlloc(NULL, ntdllSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD bytesread = NULL;
	printf("Fresh NTDLL : 0x%p\n", freshNtdll);
	NtReadVirtualMemory_p(hProcess, ntdllBase, freshNtdll, ntdllSize, &bytesread);

	//Re-writing the original ntdll.dll with the ntdll.dll read from suspended process

	DoShit(ntdllBase, freshNtdll, textsection);
	printf("Terminating suspended process \n");
	TerminateProcess(hProcess, 0);
	printf("Done shit\n");
	getchar();
	return 0;
}

/*
NOTES :

1. When the process is in suspended state, initially only the ntdll.dll is loaded.
2. There is no loader initially
3. When you attach a debugger like windbg, the DLLs will be loaded by the debugger itself
4. Otherwise the address of the ntdll on the suspended process will be same as that of the parent process
*/