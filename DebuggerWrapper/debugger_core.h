#ifndef DBGWRAPPER_DEBUGGER_CORE_H
#define DBGWRAPPER_DEBUGGER_CORE_H

#include <windows.h>
#include <cstdint>
#include "config.h"
#include "breakpoint_manager.h"
#include "rdtsc_handler.h"

namespace dbgwrap {

struct RunStats {
    uint64_t cpuidIntercepts = 0;
    uint64_t rdtscIntercepts = 0;
    uint64_t bpHitsForeign   = 0;  // hits at addresses we did not install
    DWORD    exitCode        = 0;
    double   wallSeconds     = 0.0;
};

// Spawn the target under the Windows debug API and run the debug-event loop
// until the target exits or a fatal error occurs. All masking is driven by the
// supplied Config.
//
// On success, returns true and populates `stats`. On failure to launch,
// returns false (errors logged).
bool RunDebuggerLoop(const Config& cfg, RunStats& stats);

} // namespace dbgwrap

#endif // DBGWRAPPER_DEBUGGER_CORE_H
