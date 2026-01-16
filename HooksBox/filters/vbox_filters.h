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


// Проверяет, является ли ключ реестра связанным с VirtualBox
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName = nullptr);
bool IsVBoxFilePath(LPCWSTR lpFileName);
bool IsVBoxDetectionAttempt(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes);
bool IsHiddenProcessW(const WCHAR* processName);
bool IsVirtualBoxMAC(const BYTE* mac, DWORD length);
void MaskMACAddress(BYTE* mac, DWORD length);
bool ContainsVirtualBoxString(const BYTE* data, DWORD size);
void FilterVirtualBoxStrings(BYTE* data, DWORD size);
bool IsVirtualDevice(HDEVINFO hDevInfo, SP_DEVINFO_DATA& DeviceInfoData);
bool IsDiskDriveDevice(HDEVINFO hDevInfo);

#endif // VBOX_FILTERS_H