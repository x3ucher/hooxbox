#ifndef VBOX_FILTERS_H
#define VBOX_FILTERS_H

#include <windows.h>
#include <string>

// Проверяет, является ли ключ реестра связанным с VirtualBox
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName = nullptr);
bool IsVBoxFilePath(LPCWSTR lpFileName);

#endif // VBOX_FILTERS_H