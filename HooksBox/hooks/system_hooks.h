#ifndef SYSTEM_HOOKS_H
#define SYSTEM_HOOKS_H

#include <windows.h>
#include <setupapi.h>
#include <shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

typedef BOOL(WINAPI* SetupDiEnumDeviceInfo_t)(HDEVINFO, DWORD, PSP_DEVINFO_DATA);

extern SetupDiEnumDeviceInfo_t original_SetupDiEnumDeviceInfo;

BOOL WINAPI hook_SetupDiEnumDeviceInfo(
    HDEVINFO DeviceInfoSet,
    DWORD MemberIndex,
    PSP_DEVINFO_DATA DeviceInfoData
);

void GatherVirtualDevices(HDEVINFO hDevInfo);
bool ShouldSkipDevice(DWORD index);


#endif // SYSTEM_HOOKS_H