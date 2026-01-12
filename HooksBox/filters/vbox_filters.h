#ifndef VBOX_FILTERS_H
#define VBOX_FILTERS_H

#include <windows.h>
#include <string>

// Проверяет, является ли ключ реестра связанным с VirtualBox
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName = nullptr);
bool IsVBoxFilePath(LPCWSTR lpFileName);
bool IsVBoxDetectionAttempt(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes);
bool IsHiddenProcessW(const WCHAR* processName);
bool IsVirtualBoxMAC(const BYTE* mac, DWORD length);
void MaskMACAddress(BYTE* mac, DWORD length);

#endif // VBOX_FILTERS_H