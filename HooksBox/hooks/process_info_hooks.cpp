#include "process_info_hooks.h"
#include "log_utils.h"

NtQueryInformationProcess_t original_NtQueryInformationProcess = nullptr;
NtClose_t                   original_NtClose                   = nullptr;
CloseHandle_t               original_CloseHandle               = nullptr;

// Process information classes we care about (winternl.h declares the first
// one; the other two are documented but not always exposed).
constexpr ULONG kProcessDebugPort         = 7;     // HANDLE
constexpr ULONG kProcessDebugObjectHandle = 0x1E;  // HANDLE
constexpr ULONG kProcessDebugFlags        = 0x1F;  // ULONG (1 == not debugged)

// NTSTATUS codes we synthesise.
constexpr LONG  kStatusPortNotSet = static_cast<LONG>(0xC0000353);   // STATUS_PORT_NOT_SET
constexpr LONG  kStatusInvalidHandle = static_cast<LONG>(0xC0000008);
constexpr LONG  kStatusSuccess    = 0;

// IMPORTANT: `IsSelfHandle` must NEVER call back into any API that itself
// uses NtQueryInformationProcess — every such call re-enters this hook and
// blows the stack.  In particular kernel32!GetProcessId calls
// ntdll!NtQueryInformationProcess(ProcessBasicInformation), so using it
// here causes infinite recursion the moment a real (non-pseudo) handle to
// any process is passed in.  al-khaser's parent-process probe opened a
// real handle and triggered exactly that crash (STATUS_STACK_OVERFLOW =
// 0xC00000FD).
//
// We therefore compare against the pseudo-handle only — that covers the
// overwhelmingly common anti-debug pattern (al-khaser, pafish, …) and
// requires zero syscalls.  Anti-debug code that uses OpenProcess(self)
// would slip past the mask, but no observed detector does this.
//
// A thread-local re-entrance flag still guards the rest of the hook body
// so any future detour additions can call helper APIs without crashing
// the host.
static thread_local int g_inQueryInformationHook = 0;

static bool IsSelfPseudoHandle(HANDLE h) {
    return h == GetCurrentProcess();   // (HANDLE)-1, no syscall
}

LONG NTAPI hook_NtQueryInformationProcess(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength)
{
    // Bypass our masking logic on re-entrant calls (Windows internals or
    // future hook additions that resolve through NtQueryInformationProcess).
    if (g_inQueryInformationHook) {
        return original_NtQueryInformationProcess(
            ProcessHandle, ProcessInformationClass,
            ProcessInformation, ProcessInformationLength, ReturnLength);
    }
    g_inQueryInformationHook = 1;

    // Only mask queries targeted at the current process — leaving everything
    // else untouched keeps system tooling (CoInitialize / RPC / Defender)
    // working normally.
    const bool self = IsSelfPseudoHandle(ProcessHandle);

    g_inQueryInformationHook = 0;

    if (self && ProcessInformationClass == kProcessDebugPort) {
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
            *reinterpret_cast<HANDLE*>(ProcessInformation) = nullptr;
        }
        if (ReturnLength) *ReturnLength = sizeof(HANDLE);
        return kStatusSuccess;
    }

    if (self && ProcessInformationClass == kProcessDebugFlags) {
        // The kernel returns the INVERSE of NoDebugInherit, so a value of 1
        // means "no debugger". al-khaser treats `NoDebugInherit == 0` as
        // BAD (which translates to "kernel returned 0", which means
        // debugger is inheriting).  Returning 1 keeps the check green.
        if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG)) {
            *reinterpret_cast<PULONG>(ProcessInformation) = 1;
        }
        if (ReturnLength) *ReturnLength = sizeof(ULONG);
        return kStatusSuccess;
    }

    if (self && ProcessInformationClass == kProcessDebugObjectHandle) {
        // al-khaser's anti-anti-debug variant aliases ProcessInformation and
        // ReturnLength to the same address and inspects three conditions:
        //
        //   (a) Status == STATUS_PORT_NOT_SET
        //   (b) hDebugObject != NULL    (i.e. *some* write happened)
        //   (c) low 32 bits of hDebugObject == ProcessInformationLength
        //       (i.e. ReturnLength was the LAST write, mimicking the real
        //       kernel's write order: handle first, then length).
        //
        // To satisfy all three we zero ProcessInformation first, then write
        // ProcessInformationLength to ReturnLength — exactly matching real
        // OS behaviour when no debug object exists.
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
            *reinterpret_cast<HANDLE*>(ProcessInformation) = nullptr;
        }
        if (ReturnLength) {
            *ReturnLength = ProcessInformationLength;
        }
        return kStatusPortNotSet;
    }

    return original_NtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);
}

// CloseHandle / NtClose anti-debug check works like this:
//   - Under a debugger, calling NtClose with an invalid handle causes the
//     kernel to dispatch a STATUS_INVALID_HANDLE exception back to the
//     process (controlled by PsRaiseExceptionOnInvalidHandleClose, set when
//     the debugger attaches).
//   - The detector wraps the call in __try/__except.  Exception caught →
//     "I'm being debugged".
//
// We swallow that exception inside our hook so the detector's __except
// block never triggers.  Real callers that pass a valid handle take the
// normal path through the original.
LONG NTAPI hook_NtClose(HANDLE Handle) {
    __try {
        return original_NtClose(Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return kStatusInvalidHandle;
    }
}

BOOL WINAPI hook_CloseHandle(HANDLE Handle) {
    __try {
        return original_CloseHandle(Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
}
