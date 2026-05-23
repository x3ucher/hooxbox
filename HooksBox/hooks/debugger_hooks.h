#ifndef DEBUGGER_HOOKS_H
#define DEBUGGER_HOOKS_H

#include <windows.h>

typedef BOOL(WINAPI* IsDebuggerPresent_t)(void);
typedef BOOL(WINAPI* CheckRemoteDebuggerPresent_t)(HANDLE, PBOOL);

extern IsDebuggerPresent_t original_IsDebuggerPresent;
extern CheckRemoteDebuggerPresent_t original_CheckRemoteDebuggerPresent;

BOOL WINAPI hook_IsDebuggerPresent(void);
BOOL WINAPI hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);

// Zero the user-mode debugger indicators in our own PEB:
//   PEB->BeingDebugged   (offset 0x02, BYTE)
//   PEB->NtGlobalFlag    (offset 0xBC on x64 / 0x68 on x86, ULONG)
//
// Safe to call from DllMain: only touches the current process's PEB via the
// gs/fs segment register (no LoaderLock-relevant API), and does not depend
// on COM, TLS, or thread creation.  Has no effect on a real attached
// debugger's kernel debug port — only on the user-mode flags pafish/al-khaser
// read directly.
void PatchPebDebuggerFlags();

#endif // DEBUGGER_HOOKS_H
