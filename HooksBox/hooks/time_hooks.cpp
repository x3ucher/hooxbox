#include "time_hooks.h"

GetTickCount_t   original_GetTickCount   = nullptr;
GetTickCount64_t original_GetTickCount64 = nullptr;

// Constant offset added to every tick reading.  Chosen as 30 minutes
// (1_800_000 ms) so pafish gensandbox_uptime — which trips if the value is
// below 0xAFE74 ≈ 12 minutes — always passes, while preserving the real
// delta between successive calls (Sleep-patch detection relies on
// (t2 - t1) ≈ Sleep duration; a constant offset is invariant under
// subtraction).
static constexpr DWORD     kTickOffsetMs   = 1'800'000;       // 30 min
static constexpr ULONGLONG kTickOffsetMs64 = 1'800'000ULL;

DWORD WINAPI hook_GetTickCount(void) {
    return original_GetTickCount() + kTickOffsetMs;
}

ULONGLONG WINAPI hook_GetTickCount64(void) {
    return original_GetTickCount64() + kTickOffsetMs64;
}
