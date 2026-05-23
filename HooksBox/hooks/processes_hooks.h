#ifndef PROCESSES_HOOKS_H
#define PROCESSES_HOOKS_H

#include <windows.h>
#include <tlhelp32.h>

typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);

// In the SDK, tagPROCESSENTRY32/PROCESSENTRY32 is macro-aliased to the wide
// struct when UNICODE is defined — there is no separate ANSI typedef
// reachable in this configuration.  Mirror the binary layout here so we can
// expose the ANSI Process32First/Next entry points without flipping the
// project-wide character set.  Field order/types must match Windows
// tagPROCESSENTRY32 exactly; only szExeFile changes WCHAR → CHAR.
struct ProcessEntry32Ansi {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    CHAR      szExeFile[MAX_PATH];
};

typedef BOOL(WINAPI* Process32First_t)(HANDLE, ProcessEntry32Ansi*);
typedef BOOL(WINAPI* Process32Next_t)(HANDLE, ProcessEntry32Ansi*);

extern Process32FirstW_t original_Process32FirstW;
extern Process32NextW_t original_Process32NextW;
extern Process32First_t original_Process32First;
extern Process32Next_t original_Process32Next;

BOOL WINAPI hook_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL WINAPI hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL WINAPI hook_Process32First(HANDLE hSnapshot, ProcessEntry32Ansi* lppe);
BOOL WINAPI hook_Process32Next(HANDLE hSnapshot, ProcessEntry32Ansi* lppe);

#endif // PROCESSES_HOOKS_H
