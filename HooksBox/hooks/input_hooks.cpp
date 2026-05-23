#include "input_hooks.h"
#include "log_utils.h"

GetLastInputInfo_t original_GetLastInputInfo = nullptr;

// al-khaser's lack_user_input loops up to 128 times, sampling every ~11 ms,
// and requires (GetTickCount() - dwTime < 100) ten times in a row to
// conclude that the user is active.  On bare metal that's trivially true,
// but our GetTickCount hook adds a +30-minute offset (so pafish uptime
// passes) and GetLastInputInfo reports the unshifted real tick count.  The
// resulting delta is ~1_800_000 — well over 100 — so the check loops 128
// times and returns BAD.
//
// Fix the asymmetry by returning a dwTime that's a few ticks BELOW our
// hooked GetTickCount.  Use 50 — well under the 100-tick threshold but
// strictly positive so the "current_tick_count < dwTime" overflow check
// never trips.
BOOL WINAPI hook_GetLastInputInfo(PLASTINPUTINFO plii) {
    if (!plii) {
        return original_GetLastInputInfo(plii);
    }
    BOOL ok = original_GetLastInputInfo(plii);
    if (ok) {
        plii->dwTime = GetTickCount() - 50;
    }
    return ok;
}
