#include "debugger_hooks.h"
#include "log_utils.h"
#include <intrin.h>

IsDebuggerPresent_t original_IsDebuggerPresent = nullptr;
CheckRemoteDebuggerPresent_t original_CheckRemoteDebuggerPresent = nullptr;

BOOL WINAPI hook_IsDebuggerPresent(void) {
    // Always pretend nobody is debugging the current process.  This covers
    // pafish debug_isdebuggerpresent and the al-khaser equivalent.
    return FALSE;
}

BOOL WINAPI hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    // Forward to the original so that the function still validates hProcess
    // and updates GetLastError exactly as the real implementation would,
    // then unconditionally clear the out-flag.
    BOOL ok = original_CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
    if (pbDebuggerPresent) {
        *pbDebuggerPresent = FALSE;
    }
    return ok;
}

void PatchPebDebuggerFlags() {
    // Locate the PEB.  Layout: TEB is at gs:[0x30] (x64) or fs:[0x18] (x86),
    // and TEB+0x60 (x64) / TEB+0x30 (x86) is the PEB pointer — but the
    // segment-relative addresses for PEB itself (gs:[0x60] / fs:[0x30]) are
    // documented and shorter.  Pafish reads through the same locations.
    PBYTE peb = nullptr;
#if defined(_M_X64)
    peb = reinterpret_cast<PBYTE>(__readgsqword(0x60));
#elif defined(_M_IX86)
    peb = reinterpret_cast<PBYTE>(__readfsdword(0x30));
#else
#  error "Unsupported architecture for PEB patch"
#endif
    if (!peb) return;

    __try {
        // PEB+0x02 — BeingDebugged byte.  Read by IsDebuggerPresent and by
        // pafish debug_beingdebugged_peb (direct PEB walk).
        peb[0x02] = 0;

#if defined(_M_X64)
        constexpr SIZE_T kNtGlobalFlagOffset = 0xBC;
        constexpr SIZE_T kProcessHeapOffset  = 0x30;   // PEB->ProcessHeap (x64)
        constexpr SIZE_T kHeapFlagsOffset    = 0x70;   // _HEAP.Flags      (x64)
        constexpr SIZE_T kHeapForceFlagsOff  = 0x74;   // _HEAP.ForceFlags (x64)
#else
        constexpr SIZE_T kNtGlobalFlagOffset = 0x68;
        constexpr SIZE_T kProcessHeapOffset  = 0x18;   // PEB->ProcessHeap (x86)
        constexpr SIZE_T kHeapFlagsOffset    = 0x40;   // _HEAP.Flags      (x86)
        constexpr SIZE_T kHeapForceFlagsOff  = 0x44;   // _HEAP.ForceFlags (x86)
#endif
        // PEB+NtGlobalFlag — set to FLG_HEAP_ENABLE_TAIL_CHECK | … when the
        // process is launched under a debugger.  Anti-debug code reads this
        // word directly; the heap behaviour itself is fixed at process
        // start, so zeroing the field after the fact only masks the
        // detection signal — which is what we want.
        *reinterpret_cast<PULONG>(peb + kNtGlobalFlagOffset) = 0;

        // PEB->ProcessHeap->Flags / ForceFlags.  Under a debugger they
        // contain HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED
        // | HEAP_VALIDATE_PARAMETERS_ENABLED.  al-khaser's HeapFlags()
        // returns BAD if Flags > 2 (anything beyond HEAP_GROWABLE); the
        // canonical "no debugger" snapshot is Flags=2 / ForceFlags=0.
        //
        // Modifying these fields post-init is the standard anti-anti-debug
        // pattern: the heap manager applied its debug behaviour at heap
        // creation time and does not re-read these words for new
        // allocations, so the patch only masks the detection signal —
        // existing heap blocks keep their guard pages, free-checks etc.
        PBYTE pHeap = *reinterpret_cast<PBYTE*>(peb + kProcessHeapOffset);
        if (pHeap) {
            *reinterpret_cast<PULONG>(pHeap + kHeapFlagsOffset)   = 2;  // HEAP_GROWABLE
            *reinterpret_cast<PULONG>(pHeap + kHeapForceFlagsOff) = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // PEB layout drift on a future Windows version would land here;
        // worst case is that the patch silently no-ops on that build.
        DebugPrint("[DEBUGGER_HOOK] PEB patch faulted; skipped");
    }

    DebugPrint("[DEBUGGER_HOOK] PEB BeingDebugged + NtGlobalFlag + ProcessHeap flags zeroed");
}
