#include "registry_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"
#include <string>
#include <map>

RegOpenKeyExW_t original_RegOpenKeyExW = nullptr;
RegQueryValueExW_t original_RegQueryValueExW = nullptr;
RegEnumKeyExW_t original_RegEnumKeyExW = nullptr;

LSTATUS WINAPI hook_RegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] RegOpenKeyExW called. SubKey: %s", lpSubKey ? lpSubKey : L"null");
    DebugPrintW(debugMsg);

    if (IsVBoxRegistryKey(hKey, lpSubKey)) {
        DebugPrint("[HOOK_DLL] BLOCKED: Attempt to access VirtualBox registry key!");
        return ERROR_FILE_NOT_FOUND;
    }

    if (lpSubKey && (wcscmp(lpSubKey, L"System\\CurrentControlSet\\Enum\\IDE") == 0 ||
        wcscmp(lpSubKey, L"System\\CurrentControlSet\\Enum\\SCSI") == 0 ||
        wcsstr(lpSubKey, L"System\\CurrentControlSet\\Enum\\IDE\\") != nullptr ||
        wcsstr(lpSubKey, L"System\\CurrentControlSet\\Enum\\SCSI\\") != nullptr)) {
        DebugPrintW(L"[HOOK_DLL] Opening disk enumeration path - will filter virtual devices");
    }

    return original_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS WINAPI hook_RegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] RegQueryValueExW called. ValueName: %s",
        lpValueName ? lpValueName : L"null");
    DebugPrintW(debugMsg);

    BYTE tempBuffer[4096];
    DWORD tempSize = sizeof(tempBuffer);
    DWORD tempType = 0;
    LSTATUS result = original_RegQueryValueExW(hKey, lpValueName, lpReserved, &tempType, tempBuffer, &tempSize);

    if (result == ERROR_SUCCESS && lpValueName) {
        if (tempType == REG_SZ || tempType == REG_EXPAND_SZ || tempType == REG_MULTI_SZ) {
            wchar_t* currentValue = (wchar_t*)tempBuffer;
            bool isNumericValue = true;
            for (int i = 0; lpValueName[i]; i++) {
                if (!iswdigit(lpValueName[i])) {
                    isNumericValue = false;
                    break;
                }
            }

            if (isNumericValue && _wcsicmp(lpValueName, L"Count") != 0) {
                std::wstring currentStr(currentValue);
                std::wstring lowerValue = currentStr;
                std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::towlower);

                bool found = false;
                for (int i = 0; i < VBOX_DISK_ENUM_CHECKS_COUNT; i++) {
                    if (lowerValue.find(VBOX_DISK_ENUM_CHECKS[i]) != std::wstring::npos) {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    const wchar_t* fakeValue = L"ATA Device";
                    DWORD newSize = static_cast<DWORD>((wcslen(fakeValue) + 1) * sizeof(wchar_t));

                    if (lpData && lpcbData && *lpcbData >= newSize) {
                        wcscpy_s((wchar_t*)lpData, *lpcbData / sizeof(wchar_t), fakeValue);
                        if (lpType) *lpType = tempType;
                        if (lpcbData) *lpcbData = newSize;
                        DebugPrintW(L"[HOOK_DLL] Masked Disk\\Enum value!");
                        return ERROR_SUCCESS;
                    }
                    else if (lpcbData) {
                        *lpcbData = newSize;
                        return ERROR_MORE_DATA;
                    }
                }
            }
        }

        if (_wcsicmp(lpValueName, L"SystemBiosVersion") == 0) {
            if (wcsstr((wchar_t*)tempBuffer, L"VBOX") != NULL) {
                const wchar_t* fakeValue = L"ALASKA - 1072009";
                DWORD newSize = static_cast<DWORD>((wcslen(fakeValue) + 1) * sizeof(wchar_t));
                if (lpData && lpcbData && *lpcbData >= newSize) {
                    wcscpy_s((wchar_t*)lpData, *lpcbData / sizeof(wchar_t), fakeValue);
                    if (lpType) *lpType = tempType;
                    if (lpcbData) *lpcbData = newSize;
                    return ERROR_SUCCESS;
                }
                else if (lpcbData) {
                    *lpcbData = newSize;
                    return ERROR_MORE_DATA;
                }
            }
        }
        else if (wcscmp(lpValueName, L"Identifier") == 0) {
            if (wcsstr((wchar_t*)tempBuffer, L"VBOX") != NULL) {
                const wchar_t* fakeValue = L"ATA HARDDISK";
                DWORD newSize = static_cast<DWORD>((wcslen(fakeValue) + 1) * sizeof(wchar_t));

                if (lpData && lpcbData && *lpcbData >= newSize) {
                    wcscpy_s((wchar_t*)lpData, *lpcbData / sizeof(wchar_t), fakeValue);
                    if (lpType) *lpType = tempType;
                    if (lpcbData) *lpcbData = newSize;
                    return ERROR_SUCCESS;
                }
                else if (lpcbData) {
                    *lpcbData = newSize;
                    return ERROR_MORE_DATA;
                }
            }
        }
        else if (wcscmp(lpValueName, L"VideoBiosVersion") == 0) {
            if (wcsstr((wchar_t*)tempBuffer, L"VIRTUALBOX") != NULL ||
                wcsstr((wchar_t*)tempBuffer, L"VirtualBox") != NULL) {
                return ERROR_FILE_NOT_FOUND; 
            }
        }
        else if (wcscmp(lpValueName, L"SystemBiosDate") == 0) {
            if ((wchar_t*)tempBuffer && wcscmp((wchar_t*)tempBuffer, L"06/23/99") == 0) {
                return ERROR_FILE_NOT_FOUND; 
            }
        }
    }

    return original_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS WINAPI hook_RegEnumKeyExW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPWSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
) {
    LSTATUS result = original_RegEnumKeyExW(hKey, dwIndex, lpName, lpcName, lpReserved,
        lpClass, lpcClass, lpftLastWriteTime);

    if (result == ERROR_SUCCESS && lpName) {
        std::wstring keyName(lpName);
        std::wstring lowerName = keyName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (int i = 0; i < VBOX_DISK_ENUM_CHECKS_COUNT; i++) {
            if (lowerName.find(VBOX_DISK_ENUM_CHECKS[i]) != std::wstring::npos) {
                DebugPrintW(L"[HOOK_DLL] Hiding virtual device in enumeration");
                return ERROR_NO_MORE_ITEMS;
            }
        }
    }

    return result;
}