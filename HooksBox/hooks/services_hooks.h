#ifndef SERVICES_HOOKS_H
#define SERVICES_HOOKS_H

#include <windows.h>
#include <winsvc.h>

typedef BOOL (WINAPI* EnumServicesStatusExW_t)(
    SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD,
    LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);

extern EnumServicesStatusExW_t original_EnumServicesStatusExW;

BOOL WINAPI hook_EnumServicesStatusExW(
    SC_HANDLE       hSCManager,
    SC_ENUM_TYPE    InfoLevel,
    DWORD           dwServiceType,
    DWORD           dwServiceState,
    LPBYTE          lpServices,
    DWORD           cbBufSize,
    LPDWORD         pcbBytesNeeded,
    LPDWORD         lpServicesReturned,
    LPDWORD         lpResumeHandle,
    LPCWSTR         pszGroupName);

#endif // SERVICES_HOOKS_H
