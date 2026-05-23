#ifndef DBGWRAPPER_BREAKPOINT_MANAGER_H
#define DBGWRAPPER_BREAKPOINT_MANAGER_H

#include <windows.h>
#include <cstdint>
#include <unordered_map>

namespace dbgwrap {

enum class BpKind : uint8_t {
    Cpuid = 1,   // 0F A2
    Rdtsc = 2,   // 0F 31
};

struct BpInfo {
    BpKind kind;
    uint8_t  origByte;   // first byte of the instruction (0x0F) for both
    uint8_t  secondByte; // second byte (A2 or 31) — kept for diagnostics
};

class BreakpointManager {
public:
    // Try to install a soft BP (0xCC) at the given remote address. On success,
    // remembers the original byte so we can recognise the BP later. The second
    // byte is kept solely for logging — we never restore the instruction because
    // emulation skips past the whole 2-byte opcode (Rip advances 1 more byte
    // beyond the post-INT3 position; see debugger_core.cpp).
    bool Install(HANDLE hProcess, uintptr_t address, BpKind kind, uint8_t origByte, uint8_t secondByte);

    // Returns nullptr if the address is not one of ours.
    const BpInfo* Find(uintptr_t address) const;

    size_t Count() const { return bps_.size(); }

private:
    std::unordered_map<uintptr_t, BpInfo> bps_;
};

} // namespace dbgwrap

#endif // DBGWRAPPER_BREAKPOINT_MANAGER_H
