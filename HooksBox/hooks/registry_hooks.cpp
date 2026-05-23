#include "registry_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"
#include <string>
#include <map>
#include <cctype>
#include <cstring>

RegOpenKeyExW_t original_RegOpenKeyExW = nullptr;
RegQueryValueExW_t original_RegQueryValueExW = nullptr;
RegEnumKeyExW_t original_RegEnumKeyExW = nullptr;

RegOpenKeyExA_t original_RegOpenKeyExA = nullptr;
RegQueryValueExA_t original_RegQueryValueExA = nullptr;
RegEnumKeyExA_t original_RegEnumKeyExA = nullptr;

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

// ===========================================================================
// ANSI mirrors.
//
// Pafish, al-khaser-on-XP-SDK, and many older detectors call only the ANSI
// registry APIs (vbox_reg_key3..key10 use pafish_exists_regkey* which boil
// down to RegOpenKeyExA + RegQueryValueExA).  Windows does NOT route
// kernel32!RegOpenKeyExA through RegOpenKeyExW — both are independent thunks
// to the same ntdll worker — so the W-only hooks above silently miss every
// ANSI caller.  These mirrors close that gap.
// ===========================================================================

static const char* kVBoxDiskEnumChecksA[] = {
    "qemu", "virtio", "vmware", "vbox", "xen", "vmw", "virtual",
};

LSTATUS WINAPI hook_RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    if (IsVBoxRegistryKeyA(hKey, lpSubKey)) {
        DebugPrint("[HOOK_DLL] BLOCKED (A): VirtualBox registry key open denied");
        return ERROR_FILE_NOT_FOUND;
    }
    return original_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

LSTATUS WINAPI hook_RegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    // Mirror the W hook: peek into a private buffer first so we can decide
    // whether to mask without consuming the caller's buffer twice.
    BYTE tempBuffer[4096];
    DWORD tempSize = sizeof(tempBuffer);
    DWORD tempType = 0;
    LSTATUS result = original_RegQueryValueExA(hKey, lpValueName, lpReserved,
        &tempType, tempBuffer, &tempSize);

    if (result == ERROR_SUCCESS && lpValueName &&
        (tempType == REG_SZ || tempType == REG_EXPAND_SZ || tempType == REG_MULTI_SZ)) {

        auto write_masked = [&](const char* fakeValue) -> LSTATUS {
            DWORD newSize = static_cast<DWORD>(strlen(fakeValue) + 1);
            if (lpData && lpcbData && *lpcbData >= newSize) {
                strcpy_s(reinterpret_cast<char*>(lpData), *lpcbData, fakeValue);
                if (lpType) *lpType = tempType;
                if (lpcbData) *lpcbData = newSize;
                return ERROR_SUCCESS;
            }
            if (lpcbData) {
                *lpcbData = newSize;
                return ERROR_MORE_DATA;
            }
            return result;
        };

        const char* asValue = reinterpret_cast<const char*>(tempBuffer);

        // Mirrors hook_RegQueryValueExW's "Identifier" / disk-enum entry: the
        // numeric subkey index (e.g. "0", "1") with a value such as
        // "VBOX HARDDISK".
        bool isNumericName = true;
        for (size_t i = 0; lpValueName[i]; ++i) {
            if (!isdigit(static_cast<unsigned char>(lpValueName[i]))) { isNumericName = false; break; }
        }
        if (isNumericName && _stricmp(lpValueName, "Count") != 0) {
            // Lower-case for case-insensitive substring match.
            std::string lower(asValue);
            std::transform(lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c){ return static_cast<char>(::tolower(c)); });
            for (const char* needle : kVBoxDiskEnumChecksA) {
                if (lower.find(needle) != std::string::npos) {
                    DebugPrint("[HOOK_DLL] Masked Disk\\Enum value (A)");
                    return write_masked("ATA Device");
                }
            }
        }

        if (_stricmp(lpValueName, "SystemBiosVersion") == 0) {
            if (StrStrIA(asValue, "VBOX") != nullptr) {
                return write_masked("ALASKA - 1072009");
            }
        }
        else if (_stricmp(lpValueName, "Identifier") == 0) {
            if (StrStrIA(asValue, "VBOX") != nullptr) {
                return write_masked("ATA HARDDISK");
            }
        }
        else if (_stricmp(lpValueName, "VideoBiosVersion") == 0) {
            // Pafish compares against "VIRTUALBOX" case-insensitively after
            // uppercasing both sides; failing the query is the cleanest
            // outcome that doesn't depend on the buffer being large enough.
            if (StrStrIA(asValue, "VIRTUALBOX") != nullptr ||
                StrStrIA(asValue, "VBOX") != nullptr) {
                return ERROR_FILE_NOT_FOUND;
            }
        }
        else if (_stricmp(lpValueName, "SystemBiosDate") == 0) {
            // Pafish trips on the exact VirtualBox-default date string.
            if (strcmp(asValue, "06/23/99") == 0) {
                return ERROR_FILE_NOT_FOUND;
            }
        }
    }

    // No mask applied — pass through with the caller's buffer.  The original
    // peek above does not consume any state (RegQueryValueEx is stateless),
    // so a second call is correctness-preserving.
    return original_RegQueryValueExA(hKey, lpValueName, lpReserved,
        lpType, lpData, lpcbData);
}

LSTATUS WINAPI hook_RegEnumKeyExA(
    HKEY hKey,
    DWORD dwIndex,
    LPSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
) {
    LSTATUS result = original_RegEnumKeyExA(hKey, dwIndex, lpName, lpcName, lpReserved,
        lpClass, lpcClass, lpftLastWriteTime);

    if (result == ERROR_SUCCESS && lpName) {
        std::string lower(lpName);
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c){ return static_cast<char>(::tolower(c)); });
        for (const char* needle : kVBoxDiskEnumChecksA) {
            if (lower.find(needle) != std::string::npos) {
                DebugPrint("[HOOK_DLL] Hiding virtual device in enumeration (A)");
                return ERROR_NO_MORE_ITEMS;
            }
        }
    }
    return result;
}