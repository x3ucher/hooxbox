#include "vbox_filters.h"
#include "log_utils.h"
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

bool IsVBoxDetectionAttempt(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes) {
    if (lpFileName == NULL) {
        return false;
    }

    std::wstring filename(lpFileName);

    for (int i = 0; i < VBOX_DEVICE_PATHS_COUNT; i++) {
        if (filename.find(VBOX_DEVICE_PATHS[i]) != std::wstring::npos) {
            DebugPrint("[HOOK_DLL] Found VBox device path in request");

            if (dwDesiredAccess == GENERIC_READ &&
                dwShareMode == FILE_SHARE_READ &&
                dwCreationDisposition == OPEN_EXISTING &&
                dwFlagsAndAttributes == FILE_ATTRIBUTE_NORMAL) {
                DebugPrint("[HOOK_DLL] Matches detection pattern - blocking");
                return true;
            }
        }
    }

    return false;
}

bool IsHiddenProcessW(const WCHAR* processName) {
    return _wcsicmp(processName, L"vboxservice.exe") == 0 ||
        _wcsicmp(processName, L"vboxtray.exe") == 0 ||
        _wcsicmp(processName, L"VBoxService.exe") == 0 ||
        _wcsicmp(processName, L"VBoxTray.exe") == 0;
}
