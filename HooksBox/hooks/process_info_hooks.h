#ifndef PROCESS_INFO_HOOKS_H
#define PROCESS_INFO_HOOKS_H

#include <windows.h>

// ntdll undocumented prototypes — we hook by GetProcAddress so we don't drag
// winternl.h into every translation unit.
typedef LONG /*NTSTATUS*/ (NTAPI* NtQueryInformationProcess_t)(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength);

typedef LONG /*NTSTATUS*/ (NTAPI* NtClose_t)(HANDLE Handle);

extern NtQueryInformationProcess_t original_NtQueryInformationProcess;
extern NtClose_t                   original_NtClose;

LONG NTAPI hook_NtQueryInformationProcess(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength);

LONG NTAPI hook_NtClose(HANDLE Handle);

// CloseHandle wraps NtClose; al-khaser tries both, so we mirror the SEH
// swallow at the Win32 layer too.
typedef BOOL (WINAPI* CloseHandle_t)(HANDLE);
extern CloseHandle_t original_CloseHandle;
BOOL WINAPI hook_CloseHandle(HANDLE Handle);

#endif // PROCESS_INFO_HOOKS_H
