#include "hook_manager.h"
#include "log_utils.h"
#include "registry_hooks.h"
#include "file_hooks.h"
#include "device_hooks.h"
#include "processes_hooks.h"
#include "window_hooks.h"
#include "network_hooks.h"

#define MH_STATIC
#include "MinHook.h"

// 

// Инициализация хуков
bool InitializeHooks() {
    if (MH_Initialize() != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to initialize MinHook");
        return false;
    }

    if (!InitializeRegistryHooks()) {
        DebugPrint("[Registry]");
        return false;
    }

    if (!InitializeFileHooks()) {
        DebugPrint("[File]");
        return false;
    }

    if (!InitializeDeviceHooks()) {
        DebugPrint("[Device]");
        return false;
    }

    if (!InitializeProcessHooks()) {
        DebugPrint("[Process]");
        return false;
    }

    if (!InitializeWndHooks()) {
        DebugPrint("[Window]");
        return false;
    }

    if (!InitializeNetworkHooks()) {
        DebugPrint("[Network]");
        return false;
    }

    if (!InitializeMacAddresHooks()) {
        DebugPrint("[Network]");
        return false;
    }

    DebugPrint("[HOOK_DLL] Hooks installed successfully!");
    return true;
}

// Очистка хуков
void CleanupHooks() {
    // Отключаем все хуки
    MH_DisableHook(nullptr);
    MH_Uninitialize();
    DebugPrint("[HOOK_DLL] Hooks uninstalled");
}

bool InitializeRegistryHooks() {
    if (MH_CreateHook(&RegOpenKeyExW, &hook_RegOpenKeyExW,
        reinterpret_cast<void**>(&original_RegOpenKeyExW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegOpenKeyExW");
        return false;
    }

    if (MH_CreateHook(&RegQueryValueExW, &hook_RegQueryValueExW,
        reinterpret_cast<void**>(&original_RegQueryValueExW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegQueryValueExW");
        return false;
    }

    DebugPrint("[HOOK_DLL] Registry hooks created successfully");

    if (MH_EnableHook(&RegOpenKeyExW) != MH_OK ||
        MH_EnableHook(&RegQueryValueExW) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable hooks");
        return false;
    }

    DebugPrint("[HOOK_DLL] Registry hooks enable successfully");

    return true;
}

bool InitializeFileHooks() {
    if (MH_CreateHook(&GetFileAttributesW, &hook_GetFileAttributesW,
        reinterpret_cast<void**>(&original_GetFileAttributesW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for GetFileAttributesW");
        return false;
    }

    DebugPrint("[HOOK_DLL] File hooks created successfully");

    if (MH_EnableHook(&GetFileAttributesW) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable hooks");
        return false;
    }

    DebugPrint("[HOOK_DLL] File hooks enable successfully");
    return true;
}

bool InitializeDeviceHooks() {
    if (MH_CreateHook(&CreateFileW, &hook_CreateFileW,
        reinterpret_cast<void**>(&original_CreateFileW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for CreateFileW");
        return false;
    }

    if (MH_CreateHook(&CreateFileA, &hook_CreateFileA,
        reinterpret_cast<void**>(&original_CreateFileA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for CreateFileW");
        return false;
    }

    DebugPrint("[HOOK_DLL] Device hooks created successfully");

    if (MH_EnableHook(&CreateFileW) != MH_OK ||
        MH_EnableHook(&CreateFileA) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable hooks");
        return false;
    }

    DebugPrint("[HOOK_DLL] File hooks enable successfully");
    return true;
}

bool InitializeProcessHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        DebugPrint("[HOOK_DLL] Failed to get kernel32 handle");
        return false;
    }

    FARPROC pProcess32FirstW = GetProcAddress(hKernel32, "Process32FirstW");
    FARPROC pProcess32NextW = GetProcAddress(hKernel32, "Process32NextW");

    if (!pProcess32FirstW || !pProcess32NextW) {
        DebugPrint("[HOOK_DLL] Failed to get process functions addresses");
        return false;
    }

    if (MH_CreateHook(pProcess32FirstW, &hook_Process32FirstW,
        reinterpret_cast<void**>(&original_Process32FirstW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for Process32FirstW");
        return false;
    }

    if (MH_CreateHook(pProcess32NextW, &hook_Process32NextW,
        reinterpret_cast<void**>(&original_Process32NextW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for Process32Next");
        return false;
    }

    DebugPrint("[HOOK_DLL] Process hooks created successfully");

    if (MH_EnableHook(pProcess32FirstW) != MH_OK ||
        MH_EnableHook(pProcess32NextW) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable process hooks");
        return false;
    }

    DebugPrint("[HOOK_DLL] Process hooks enabled successfully");
    return true;
}

bool InitializeWndHooks() {
    if (MH_CreateHook(&FindWindowW, &hook_FindWindowW,
        reinterpret_cast<void**>(&original_FindWindowW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for FindWindowW");
        return false;
    }

    if (MH_CreateHook(&FindWindowExW, &hook_FindWindowExW,
        reinterpret_cast<void**>(&original_FindWindowExW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for FindWindowExW");
        return false;
    }

    DebugPrint("[HOOK_DLL] Window hooks created successfully");

    if (MH_EnableHook(&FindWindowW) != MH_OK ||
        MH_EnableHook(&FindWindowExW) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable window hooks");
        return false;
    }

    DebugPrint("[HOOK_DLL] Window hooks enabled successfully");
    return true;
}

bool InitializeNetworkHooks() {
    HMODULE hMpr = GetModuleHandleW(L"mpr.dll");
    if (!hMpr) {
        hMpr = LoadLibraryW(L"mpr.dll");
        if (!hMpr) {
            DebugPrint("[NETWORK_HOOKS] Failed to get mpr.dll handle");
            return false;
        }
    }

    FARPROC pWNetGetProviderNameW = GetProcAddress(hMpr, "WNetGetProviderNameW");
    if (!pWNetGetProviderNameW) {
        DebugPrint("[NETWORK_HOOKS] Failed to get WNetGetProviderNameW address");
        return false;
    }

    if (MH_CreateHook(pWNetGetProviderNameW, &hook_WNetGetProviderNameW,
        reinterpret_cast<void**>(&original_WNetGetProviderNameW)) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to create hook for WNetGetProviderNameW");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] WNetGetProviderNameW hook created successfully");

    if (MH_EnableHook(pWNetGetProviderNameW) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to enable WNetGetProviderNameW hook");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] WNetGetProviderNameW hook enabled successfully");
    return true;
}

bool InitializeMacAddresHooks() {
    HMODULE hIphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    if (!hIphlpapi) {
        hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
        if (!hIphlpapi) {
            DebugPrint("[NETWORK_HOOKS] Failed to get iphlpapi.dll handle");
            return false;
        }
    }

    FARPROC pGetAdaptersInfo = GetProcAddress(hIphlpapi, "GetAdaptersInfo");
    if (!pGetAdaptersInfo) {
        DebugPrint("[NETWORK_HOOKS] Failed to get GetAdaptersInfo address");
        return false;
    }

    if (MH_CreateHook(pGetAdaptersInfo, &hook_GetAdaptersInfo,
        reinterpret_cast<void**>(&original_GetAdaptersInfo)) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to create hook for GetAdaptersInfo");
        return false;
    }

    if (MH_EnableHook(pGetAdaptersInfo) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to enable GetAdaptersInfo hook");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] GetAdaptersInfo hook created and enabled successfully");

    FARPROC pGetAdaptersAddresses = GetProcAddress(hIphlpapi, "GetAdaptersAddresses");
    if (!pGetAdaptersAddresses) {
        DebugPrint("[NETWORK_HOOKS] Failed to get GetAdaptersAddresses address");
        return false;
    }

    if (MH_CreateHook(pGetAdaptersAddresses, &hook_GetAdaptersAddresses,
        reinterpret_cast<void**>(&original_GetAdaptersAddresses)) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to create hook for GetAdaptersAddresses");
        return false;
    }

    if (MH_EnableHook(pGetAdaptersAddresses) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to enable GetAdaptersAddresses hook");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] GetAdaptersAddresses hook created and enabled successfully");
    return true;

}