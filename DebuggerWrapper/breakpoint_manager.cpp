#include "breakpoint_manager.h"
#include "logger.h"

namespace dbgwrap {

bool BreakpointManager::Install(HANDLE hProcess,
                                uintptr_t address,
                                BpKind kind,
                                uint8_t origByte,
                                uint8_t secondByte) {
    if (bps_.find(address) != bps_.end()) {
        return true; // already there
    }

    const uint8_t cc = 0xCC;
    SIZE_T written = 0;
    DWORD oldProt = 0;

    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        DBG_LOG_E(L"bp", L"VirtualProtectEx(write) failed at 0x%p: %s",
                  reinterpret_cast<void*>(address),
                  FormatWinError(GetLastError()).c_str());
        return false;
    }

    BOOL ok = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), &cc, 1, &written);
    DWORD writeErr = ok ? 0 : GetLastError();

    DWORD restored = 0;
    VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), 1, oldProt, &restored);

    if (!ok || written != 1) {
        DBG_LOG_E(L"bp", L"WriteProcessMemory(CC) failed at 0x%p: %s",
                  reinterpret_cast<void*>(address),
                  FormatWinError(writeErr).c_str());
        return false;
    }

    FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(address), 1);
    bps_[address] = BpInfo{ kind, origByte, secondByte };
    return true;
}

const BpInfo* BreakpointManager::Find(uintptr_t address) const {
    auto it = bps_.find(address);
    return (it == bps_.end()) ? nullptr : &it->second;
}

} // namespace dbgwrap
