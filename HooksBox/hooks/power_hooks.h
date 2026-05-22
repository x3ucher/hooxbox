#ifndef POWER_HOOKS_H
#define POWER_HOOKS_H

#include <windows.h>
#include <powrprof.h>

typedef BOOLEAN (WINAPI* GetPwrCapabilities_t)(PSYSTEM_POWER_CAPABILITIES);

extern GetPwrCapabilities_t original_GetPwrCapabilities;

BOOLEAN WINAPI hook_GetPwrCapabilities(PSYSTEM_POWER_CAPABILITIES lpSystemPowerCapabilities);

#endif // POWER_HOOKS_H
