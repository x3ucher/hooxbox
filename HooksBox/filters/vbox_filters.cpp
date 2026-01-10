#include "vbox_filters.h"
#include "../config.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// Проверяет, является ли ключ реестра связанным с VirtualBox
bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName) {
    if (!lpSubKey) return false;

    // Проверяем все известные пути VBox
    for (int i = 0; i < VBOX_REGISTRY_PATHS_COUNT; i++) {
        if (wcsstr(lpSubKey, VBOX_REGISTRY_PATHS[i]) != nullptr) {
            return true;
        }
    }

    return false;
}

bool IsVBoxFilePath(LPCWSTR lpFileName) {
    if (!lpFileName) return false;

    for (int i = 0; i < VBOX_DRIVERS_PATHS_COUNT; i++) {
        if (StrStrIW(lpFileName, VBOX_DRIVERS_PATHS[i]) != nullptr) {
            return true;
        }
    }

    for (int i = 0; i < VBOX_SYSTEM_FILES_PATHS_COUNT; i++) {
        if (StrStrIW(lpFileName, VBOX_SYSTEM_FILES_PATHS[i]) != nullptr) {
            return true;
        }
    }

    return false;
}