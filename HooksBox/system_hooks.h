#ifndef SYSTEM_HOOKS_H
#define SYSTEM_HOOKS_H

#include <windows.h>
#include "iphlpapi.h"

// Типы оригинальных функций
typedef DWORD(WINAPI* WNetGetProviderNameW_t)(DWORD, LPWSTR, LPDWORD);
typedef HWND(WINAPI* FindWindowW_t)(LPCWSTR, LPCWSTR);
typedef HWND(WINAPI* FindWindowExW_t)(HWND, HWND, LPCWSTR, LPCWSTR);
typedef IPHLPAPI_DLL_LINKAGE ULONG(WINAPI* GetAdaptersInfo_t)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

// Глобальные указатели на оригинальные функции
extern WNetGetProviderNameW_t original_WNetGetProviderNameW;
extern FindWindowW_t original_FindWindowW;
extern FindWindowExW_t original_FindWindowExW;
extern GetAdaptersInfo_t original_GetAdaptersInfo;

// Функции хуков
DWORD WINAPI hook_WNetGetProviderNameW(DWORD dwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize);
HWND WINAPI hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
HWND WINAPI hook_FindWindowExW(HWND hwndParent, HWND hwndChildAfter,
                               LPCWSTR lpClassName, LPCWSTR lpWindowName);
IPHLPAPI_DLL_LINKAGE ULONG hook_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

#endif // SYSTEM_HOOKS_H