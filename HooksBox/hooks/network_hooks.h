#ifndef NETWORK_HOOKS_H
#define NETWORK_HOOKS_H

#ifndef _WINSOCK2API_
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <iphlpapi.h>
#include <winnetwk.h>

typedef DWORD(WINAPI* WNetGetProviderNameW_t)(DWORD, LPWSTR, LPDWORD);
typedef ULONG(WINAPI* GetAdaptersInfo_t)(void*, PULONG);
typedef ULONG(WINAPI* GetAdaptersAddresses_t)(ULONG, ULONG, PVOID, void*, PULONG);

extern WNetGetProviderNameW_t original_WNetGetProviderNameW;
extern GetAdaptersInfo_t original_GetAdaptersInfo;
extern GetAdaptersAddresses_t original_GetAdaptersAddresses;

DWORD WINAPI hook_WNetGetProviderNameW(DWORD dwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize);
ULONG WINAPI hook_GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
ULONG WINAPI hook_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);

#endif // NETWORK_HOOKS_H