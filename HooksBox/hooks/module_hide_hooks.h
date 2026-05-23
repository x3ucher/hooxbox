#ifndef MODULE_HIDE_HOOKS_H
#define MODULE_HIDE_HOOKS_H

#include <windows.h>

typedef DWORD(WINAPI* GetMappedFileNameW_t)(HANDLE, LPVOID, LPWSTR, DWORD);
typedef DWORD(WINAPI* GetMappedFileNameA_t)(HANDLE, LPVOID, LPSTR, DWORD);

extern GetMappedFileNameW_t original_GetMappedFileNameW;
extern GetMappedFileNameA_t original_GetMappedFileNameA;

DWORD WINAPI hook_GetMappedFileNameW(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize);
DWORD WINAPI hook_GetMappedFileNameA(HANDLE hProcess, LPVOID lpv, LPSTR  lpFilename, DWORD nSize);

// Low-level intercept.  GetMappedFileName{W,A} forwarders chain through
// psapi → kernel32 → kernelbase on Win10/11, and the public-API hook can
// silently end up on the wrong link of that chain.  NtQueryVirtualMemory
// is the single syscall stub all of them funnel through, so a hook here
// catches them all regardless of which forwarder al-khaser binds to.
typedef LONG /*NTSTATUS*/ (NTAPI* NtQueryVirtualMemory_t)(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    ULONG    MemoryInformationClass,
    PVOID    MemoryInformation,
    SIZE_T   MemoryInformationLength,
    PSIZE_T  ReturnLength);

extern NtQueryVirtualMemory_t original_NtQueryVirtualMemory;

LONG NTAPI hook_NtQueryVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    ULONG    MemoryInformationClass,
    PVOID    MemoryInformation,
    SIZE_T   MemoryInformationLength,
    PSIZE_T  ReturnLength);

// Walk PEB->Ldr and unlink the hooksbox.dll entry from
// InLoadOrder/InMemoryOrder/InInitializationOrder and HashLinks lists.
// After unlinking, every API that enumerates modules via the LDR walk
// (EnumProcessModulesEx, Module32First/Next, LdrEnumerateLoadedModules,
// GetModuleHandleEx, GetModuleInformation, GetModuleFileNameEx, …) skips
// us.  Code remains mapped at its base address; only its directory
// listing disappears.
//
// Also exports the hooksbox.dll [base, base+SizeOfImage) range as
// g_hooksboxBase / g_hooksboxEnd so GetMappedFileName* hooks can
// suppress mapped-file disclosure for our own pages.
void HideHooksboxModule(HMODULE hSelf);

extern uintptr_t g_hooksboxBase;
extern uintptr_t g_hooksboxEnd;

#endif // MODULE_HIDE_HOOKS_H
