#ifndef VBOX_FILTERS_H
#define VBOX_FILTERS_H

#include <windows.h>
#include <string>

// Проверяет, является ли ключ реестра связанным с VirtualBox
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName = nullptr);

#endif // VBOX_FILTERS_H