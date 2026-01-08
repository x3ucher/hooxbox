#include "vbox_filters.h"
#include "../config.h"

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

