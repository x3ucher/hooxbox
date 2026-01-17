#ifndef REGISTRY_HOOKS_H
#define REGISTRY_HOOKS_H

#include <windows.h>

// Типы оригинальных функций
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RegEnumKeyExW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);

// Глобальные указатели на оригинальные функции
extern RegOpenKeyExW_t original_RegOpenKeyExW;
extern RegQueryValueExW_t original_RegQueryValueExW;
extern RegEnumKeyExW_t original_RegEnumKeyExW;

// Функции хуков
LSTATUS WINAPI hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS WINAPI hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved,
		LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);

#endif // REGISTRY_HOOKS_H