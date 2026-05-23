#ifndef DBGWRAPPER_INSTRUCTION_SCANNER_H
#define DBGWRAPPER_INSTRUCTION_SCANNER_H

#include <windows.h>
#include <cstdint>
#include "breakpoint_manager.h"

namespace dbgwrap {

struct ScanStats {
    size_t cpuidFound = 0;
    size_t rdtscFound = 0;
    size_t bpInstalled = 0;
};

// Scan executable sections of the PE image loaded at `imageBase` inside
// `hProcess`. For every 0F A2 (CPUID) and 0F 31 (RDTSC) pattern found, install
// a soft breakpoint via the supplied BreakpointManager (subject to the enable
// flags).
//
// NOTE: This is a naive linear byte scan. It cannot distinguish real
// instructions from byte sequences that *look* like 0F A2 / 0F 31 but live
// inside immediates or data. False positives are an accepted scope cost of the
// POC; if such a BP fires, it will be reported in the log so it can be
// inspected, and emulation will still skip past the 2-byte opcode. This may
// destabilise the target — known limitation, documented in the README.
ScanStats ScanAndInstallBreakpoints(HANDLE hProcess,
                                    LPVOID imageBase,
                                    BreakpointManager& bps,
                                    bool wantCpuid,
                                    bool wantRdtsc,
                                    const wchar_t* moduleNameForLog);

} // namespace dbgwrap

#endif // DBGWRAPPER_INSTRUCTION_SCANNER_H
