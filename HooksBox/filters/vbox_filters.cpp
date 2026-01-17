#include "vbox_filters.h"
#include "log_utils.h"
#include "../config.h"

bool IsVBoxRegistryKey(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName) {
    if (!lpSubKey) return false;

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

bool IsVirtualBoxMAC(const BYTE* mac, DWORD length) {
    if (length < 6) return false;
    return mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27;
}

void MaskMACAddress(BYTE* mac, DWORD length) {
    if (length < 6) return;
    mac[0] = 0x00;
    mac[1] = 0x00;
    mac[2] = 0x00;
}

bool ContainsVirtualBoxString(const BYTE* data, DWORD size) {
    if (!data || size == 0) return false;

    static const char* vboxStrings[] = {
        "VirtualBox",
        "vbox",
        "VBOX",
        "Oracle VM VirtualBox",
        "Virtual Machine",
        "VMware",
        "QEMU",
        "Xen"
    };

    for (const auto* vboxStr : vboxStrings) {
        size_t strLen = strlen(vboxStr);
        for (DWORD i = 0; i <= size - strLen; i++) {
            if (strncmp(reinterpret_cast<const char*>(&data[i]), vboxStr, strLen) == 0) {
                return true;
            }
        }
    }

    return false;
}

void FilterVirtualBoxStrings(BYTE* data, DWORD size) {
    if (!data || size == 0) return;

    static const std::pair<const char*, const char*> replacements[] = {
        {"VirtualBox", "GenuineIntel"},
        {"vbox", "intel"},
        {"VBOX", "INTEL"},
        {"Oracle VM VirtualBox", "Intel Corporation"},
        {"Virtual Machine", "Physical Machine"},
        {"VMware", "Intel"},
        {"QEMU", "Intel"},
        {"Xen", "Intel"}
    };

    for (const auto& [search, replace] : replacements) {
        size_t searchLen = strlen(search);
        size_t replaceLen = strlen(replace);

        for (DWORD i = 0; i <= size - searchLen; i++) {
            if (strncmp(reinterpret_cast<char*>(&data[i]), search, searchLen) == 0) {
                if (i + replaceLen <= size) {
                    memcpy(&data[i], replace, replaceLen);
                    if (replaceLen < searchLen) {
                        memset(&data[i + replaceLen], ' ', searchLen - replaceLen);
                    }
                }
            }
        }
    }
}

bool IsVirtualDevice(HDEVINFO hDevInfo, SP_DEVINFO_DATA& DeviceInfoData) {
    DWORD dwPropertyRegDataType;
    LPTSTR buffer = NULL;
    DWORD dwSize = 0;
    bool isVirtual = false;

    while (!SetupDiGetDeviceRegistryProperty(
        hDevInfo, &DeviceInfoData, SPDRP_HARDWAREID, &dwPropertyRegDataType,
        (PBYTE)buffer, dwSize, &dwSize)) {

        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            if (buffer) LocalFree(buffer);
            buffer = (LPTSTR)LocalAlloc(LPTR, dwSize * 2);
            if (buffer == NULL) break;
        }
        else {
            break;
        }
    }

    if (buffer) {
        std::wstring hardwareID(buffer);
        std::transform(hardwareID.begin(), hardwareID.end(), hardwareID.begin(), ::towlower);

        if (hardwareID.find(L"vbox") != std::wstring::npos ||
            hardwareID.find(L"vmware") != std::wstring::npos ||
            hardwareID.find(L"qemu") != std::wstring::npos ||
            hardwareID.find(L"virtual") != std::wstring::npos) {
            isVirtual = true;
        }

        LocalFree(buffer);
    }

    return isVirtual;
}

bool IsDiskDriveDevice(HDEVINFO hDevInfo) {
    GUID guidDiskDrive = GUID_DEVCLASS_DISKDRIVE;
    GUID classGuid;
    DWORD requiredSize;

    if (SetupDiGetClassDevsEx(NULL, NULL, NULL, 0, NULL, NULL, NULL)) {
        return false;
    }

    return true; 
}