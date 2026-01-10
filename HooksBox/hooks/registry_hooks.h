#ifndef REGISTRY_HOOKS_H
#define REGISTRY_HOOKS_H

#include <windows.h>

// Типы оригинальных функций
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

// Глобальные указатели на оригинальные функции
extern RegOpenKeyExW_t original_RegOpenKeyExW;
extern RegQueryValueExW_t original_RegQueryValueExW;

// Функции хуков
LSTATUS WINAPI hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

#endif // REGISTRY_HOOKS_H