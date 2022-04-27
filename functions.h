#include <Windows.h>
#include <stdio.h>

typedef BOOL(WINAPI *CreateProcessA_t) (
    LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef NTSTATUS(WINAPI *NtReadVirtualMemory_t)(
	HANDLE               ProcessHandle,
	PVOID                BaseAddress,
	PVOID               Buffer,
	ULONG                NumberOfBytesToRead,
	PULONG              NumberOfBytesReaded
	);
