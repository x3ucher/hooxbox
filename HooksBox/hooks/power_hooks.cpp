#include "power_hooks.h"
#include "log_utils.h"

GetPwrCapabilities_t original_GetPwrCapabilities = nullptr;

// al-khaser power_capabilities() reports VM iff
//   (SystemS1 | SystemS2 | SystemS3 | SystemS4) == 0  AND  ThermalControl == 0
// Force at least SystemS3 and ThermalControl to TRUE so the conjunction
// never holds.  Everything else passes through.
BOOLEAN WINAPI hook_GetPwrCapabilities(PSYSTEM_POWER_CAPABILITIES lpSystemPowerCapabilities)
{
    if (!original_GetPwrCapabilities)
        return FALSE;

    BOOLEAN ok = original_GetPwrCapabilities(lpSystemPowerCapabilities);
    if (ok && lpSystemPowerCapabilities)
    {
        lpSystemPowerCapabilities->SystemS3      = TRUE;
        lpSystemPowerCapabilities->ThermalControl = TRUE;
        DebugPrint("[POWER_HOOK] GetPwrCapabilities: forced SystemS3 + ThermalControl");
    }
    return ok;
}
