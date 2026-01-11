#ifndef NETWORK_HOOKS_H
#define NETWORK_HOOKS_H

#include <windows.h>
#include <winnetwk.h>
#include "iphlpapi.h"

// Типы оригинальных функций
typedef DWORD(WINAPI* WNetGetProviderNameW_t)(DWORD, LPWSTR, LPDWORD);
typedef IPHLPAPI_DLL_LINKAGE ULONG(WINAPI* GetAdaptersInfo_t)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

// Глобальные указатели на оригинальные функции
extern WNetGetProviderNameW_t original_WNetGetProviderNameW;
extern GetAdaptersInfo_t original_GetAdaptersInfo;

// Функции хуков
DWORD WINAPI hook_WNetGetProviderNameW(DWORD dwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize);
IPHLPAPI_DLL_LINKAGE ULONG hook_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

#endif // NETWORK_HOOKS_H