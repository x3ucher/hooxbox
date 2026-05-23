#ifndef REGISTRY_HOOKS_H
#define REGISTRY_HOOKS_H

#include <windows.h>

// Wide function typedefs
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RegEnumKeyExW_t)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);

// ANSI function typedefs — pafish and other older detectors call the A variants
// directly; without these the W-only hooks miss every check.
typedef LSTATUS(WINAPI* RegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RegQueryValueExA_t)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI* RegEnumKeyExA_t)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);

extern RegOpenKeyExW_t original_RegOpenKeyExW;
extern RegQueryValueExW_t original_RegQueryValueExW;
extern RegEnumKeyExW_t original_RegEnumKeyExW;

extern RegOpenKeyExA_t original_RegOpenKeyExA;
extern RegQueryValueExA_t original_RegQueryValueExA;
extern RegEnumKeyExA_t original_RegEnumKeyExA;

LSTATUS WINAPI hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS WINAPI hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcName, LPDWORD lpReserved,
        LPWSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);

LSTATUS WINAPI hook_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI hook_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS WINAPI hook_RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName, LPDWORD lpReserved,
        LPSTR lpClass, LPDWORD lpcClass, PFILETIME lpftLastWriteTime);

#endif // REGISTRY_HOOKS_H
