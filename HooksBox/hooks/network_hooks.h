#ifndef NETWORK_HOOKS_H
#define NETWORK_HOOKS_H

#include <winnetwk.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

// Типы оригинальных функций
typedef DWORD(WINAPI* WNetGetProviderNameW_t)(DWORD, LPWSTR, LPDWORD);
typedef IPHLPAPI_DLL_LINKAGE ULONG(WINAPI* GetAdaptersInfo_t)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
typedef IPHLPAPI_DLL_LINKAGE ULONG GetAdaptersAddresses_t(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);

// Глобальные указатели на оригинальные функции
extern WNetGetProviderNameW_t original_WNetGetProviderNameW;
extern GetAdaptersInfo_t original_GetAdaptersInfo;
extern GetAdaptersAddresses_t original_GetAdaptersAddresses;

// Функции хуков
DWORD WINAPI hook_WNetGetProviderNameW(DWORD dwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize);
IPHLPAPI_DLL_LINKAGE ULONG hook_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);
IPHLPAPI_DLL_LINKAGE ULONG hook_GetAdaptersAddresses(ULONG Family, ULONG Flags,
	PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);

#endif // NETWORK_HOOKS_H