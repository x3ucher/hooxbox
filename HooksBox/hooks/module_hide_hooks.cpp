#include "module_hide_hooks.h"
#include "log_utils.h"
#include <intrin.h>
#include <cstring>

GetMappedFileNameW_t original_GetMappedFileNameW = nullptr;
GetMappedFileNameA_t original_GetMappedFileNameA = nullptr;
NtQueryVirtualMemory_t original_NtQueryVirtualMemory = nullptr;

uintptr_t g_hooksboxBase = 0;
uintptr_t g_hooksboxEnd  = 0;

// ---------------------------------------------------------------------------
// Local mirrors of ntdll structures.  We don't include winternl.h to avoid
// SDK version drift; field offsets here match Windows 10/11 x64.
// ---------------------------------------------------------------------------
struct UnicodeStringLocal {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
};

struct LdrDataTableEntryLocal {
    LIST_ENTRY  InLoadOrderLinks;          // 0x00
    LIST_ENTRY  InMemoryOrderLinks;        // 0x10
    LIST_ENTRY  InInitializationOrderLinks;// 0x20
    PVOID       DllBase;                   // 0x30
    PVOID       EntryPoint;                // 0x38
    ULONG       SizeOfImage;               // 0x40
    UnicodeStringLocal FullDllName;        // 0x48 (Length, MaxLen, Buffer)
    UnicodeStringLocal BaseDllName;        // 0x58
    ULONG       Flags;                     // 0x68
    USHORT      LoadCount;                 // 0x6C
    USHORT      TlsIndex;                  // 0x6E
    LIST_ENTRY  HashLinks;                 // 0x70  (Win7+)
    // ...remaining fields irrelevant for unlinking.
};

struct PebLdrDataLocal {
    ULONG       Length;                    // 0x00
    BOOLEAN     Initialized;               // 0x04
    PVOID       SsHandle;                  // 0x08
    LIST_ENTRY  InLoadOrderModuleList;     // 0x10
    LIST_ENTRY  InMemoryOrderModuleList;   // 0x20
    LIST_ENTRY  InInitializationOrderModuleList; // 0x30
};

// Helper: remove a node from its doubly linked list.  Safe even if the
// list is currently empty for that link (we just rewire neighbours).
static inline void UnlinkListEntry(LIST_ENTRY* le) {
    if (!le->Flink || !le->Blink) return;
    le->Blink->Flink = le->Flink;
    le->Flink->Blink = le->Blink;
    // Point both back at ourselves so anyone holding a stale pointer
    // sees a 1-element list and stops.
    le->Flink = le;
    le->Blink = le;
}

void HideHooksboxModule(HMODULE hSelf) {
    if (!hSelf) return;

    // Capture the module's [base, end) range up-front — once we unlink we
    // can't easily query it via GetModuleInformation any more.
    g_hooksboxBase = reinterpret_cast<uintptr_t>(hSelf);
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hSelf);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<BYTE*>(hSelf) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                g_hooksboxEnd = g_hooksboxBase + nt->OptionalHeader.SizeOfImage;
            }
        }
    }
    if (g_hooksboxEnd == 0) {
        g_hooksboxEnd = g_hooksboxBase + 0x100000;  // 1 MiB conservative fallback
    }

    // Locate PEB->Ldr.
#if defined(_M_X64)
    auto* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
    auto* ldr = *reinterpret_cast<PebLdrDataLocal**>(peb + 0x18);
#elif defined(_M_IX86)
    auto* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
    auto* ldr = *reinterpret_cast<PebLdrDataLocal**>(peb + 0x0C);
#else
#  error "Unsupported architecture"
#endif
    if (!ldr) return;

    __try {
        // Walk InLoadOrderModuleList (canonical list — entries appear in
        // load order).  Match by DllBase == hSelf.
        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
            auto* entry = CONTAINING_RECORD(cur, LdrDataTableEntryLocal, InLoadOrderLinks);
            if (entry->DllBase == hSelf) {
                UnlinkListEntry(&entry->InLoadOrderLinks);
                UnlinkListEntry(&entry->InMemoryOrderLinks);
                UnlinkListEntry(&entry->InInitializationOrderLinks);
                UnlinkListEntry(&entry->HashLinks);

                // Wipe the DllBase/SizeOfImage fields too.  Some
                // detectors walk the LDR via raw memory scan looking for
                // characteristic field values — clearing them removes one
                // more signature.  The fields are not consulted by the
                // loader for an already-loaded module.
                entry->DllBase = nullptr;
                entry->SizeOfImage = 0;

                // Wipe the Full/Base name strings: they leak the path
                // "...\hooksbox.dll" to anyone scanning LDR memory.
                if (entry->FullDllName.Buffer) {
                    RtlSecureZeroMemory(entry->FullDllName.Buffer,
                                        entry->FullDllName.MaximumLength);
                    entry->FullDllName.Length = 0;
                }
                if (entry->BaseDllName.Buffer) {
                    RtlSecureZeroMemory(entry->BaseDllName.Buffer,
                                        entry->BaseDllName.MaximumLength);
                    entry->BaseDllName.Length = 0;
                }

                DebugPrint("[MODHIDE_HOOK] Unlinked hooksbox.dll from PEB->Ldr lists");
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // LDR layout drift on a hypothetical future build would land here;
        // worst case is that the unlink silently no-ops.
        DebugPrint("[MODHIDE_HOOK] LDR unlink faulted; skipped");
    }
}

// ---------------------------------------------------------------------------
// GetMappedFileName{W,A} — used by al-khaser's MemoryWalk_Hidden to ask
// "which file backs this address range?" via NtQueryVirtualMemory
// (MemorySectionName).  LDR unlinking doesn't reach the section-name
// store, so we filter at the API boundary.
// ---------------------------------------------------------------------------
static bool AddrIsHooksbox(LPVOID p) {
    uintptr_t a = reinterpret_cast<uintptr_t>(p);
    return g_hooksboxBase != 0 && a >= g_hooksboxBase && a < g_hooksboxEnd;
}

DWORD WINAPI hook_GetMappedFileNameW(HANDLE hProcess, LPVOID lpv, LPWSTR lpFilename, DWORD nSize) {
    if (AddrIsHooksbox(lpv)) {
        // Mimic "no mapped file at this address" so al-khaser doesn't
        // flag the region.
        if (lpFilename && nSize > 0) lpFilename[0] = L'\0';
        SetLastError(ERROR_FILE_INVALID);
        return 0;
    }
    return original_GetMappedFileNameW(hProcess, lpv, lpFilename, nSize);
}

DWORD WINAPI hook_GetMappedFileNameA(HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize) {
    if (AddrIsHooksbox(lpv)) {
        if (lpFilename && nSize > 0) lpFilename[0] = '\0';
        SetLastError(ERROR_FILE_INVALID);
        return 0;
    }
    return original_GetMappedFileNameA(hProcess, lpv, lpFilename, nSize);
}

// ---------------------------------------------------------------------------
// NtQueryVirtualMemory — the syscall stub that GetMappedFileName{W,A} ends
// up calling internally for MemorySectionName (class 2).  On Win10+ the
// public APIs forward through psapi → kernel32 → kernelbase, and an
// MinHook patch on any one of those links can miss callers that bound to
// a different link.  Hooking the ntdll stub catches every path.
// ---------------------------------------------------------------------------
constexpr ULONG kMemorySectionName = 2;
constexpr LONG  kStatusInvalidAddress = static_cast<LONG>(0xC0000141);  // STATUS_INVALID_ADDRESS

// Self-handle helper: -1 is GetCurrentProcess() pseudo-handle.  Don't call
// GetProcessId here — it would recurse through NtQueryInformationProcess
// and our process_info_hooks already burnt the lesson into our memory.
static bool IsSelfProcessHandle(HANDLE h) {
    return h == GetCurrentProcess();
}

LONG NTAPI hook_NtQueryVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    ULONG    MemoryInformationClass,
    PVOID    MemoryInformation,
    SIZE_T   MemoryInformationLength,
    PSIZE_T  ReturnLength)
{
    // Only mask MemorySectionName probes that target our own DLL pages in
    // the current process.  Other classes (BasicInformation, RegionInfo,
    // WorkingSet) are passed through unmodified — masking them would break
    // VirtualQuery, GetProcessHeap probes, and ordinary code.
    if (MemoryInformationClass == kMemorySectionName &&
        IsSelfProcessHandle(ProcessHandle) &&
        AddrIsHooksbox(BaseAddress)) {
        if (ReturnLength) *ReturnLength = 0;
        return kStatusInvalidAddress;
    }

    return original_NtQueryVirtualMemory(
        ProcessHandle, BaseAddress, MemoryInformationClass,
        MemoryInformation, MemoryInformationLength, ReturnLength);
}
