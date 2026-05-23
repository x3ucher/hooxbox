#ifndef VBOX_FILTERS_H
#define VBOX_FILTERS_H

#include <windows.h>

#include <setupapi.h>
#include <shlwapi.h>
#include <psapi.h>
#include <string>
#include <devguid.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")


// VirtualBox key/path predicates — wide forms.
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName = nullptr);
bool IsVBoxFilePath(LPCWSTR lpFileName);
bool IsVBoxDetectionAttempt(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes);
bool IsHiddenProcessW(const WCHAR* processName);

// ANSI mirrors. Pafish/al-khaser frequently call ANSI WinAPI directly, so the
// hooks for *A entry points need filters that operate on LPCSTR without going
// through a wide-conversion round-trip (the registry-value buffers returned
// from RegQueryValueExA are ANSI strings and must not be widened).
bool IsVBoxRegistryKeyA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName = nullptr);
bool IsVBoxFilePathA(LPCSTR lpFileName);
bool IsVBoxDetectionAttemptA(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes);
bool IsHiddenProcessA(const char* processName);
bool IsVirtualBoxMAC(const BYTE* mac, DWORD length);
void MaskMACAddress(BYTE* mac, DWORD length);
bool ContainsVirtualBoxString(const BYTE* data, DWORD size);
void FilterVirtualBoxStrings(BYTE* data, DWORD size);
bool IsVirtualDevice(HDEVINFO hDevInfo, SP_DEVINFO_DATA& DeviceInfoData);
bool IsDiskDriveDevice(HDEVINFO hDevInfo);

#endif // VBOX_FILTERS_H