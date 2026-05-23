// Must be defined BEFORE the first <windows.h> include in this TU, otherwise
// windows.h pulls in the legacy <winsock.h> and the later wbemidl.h →
// winsock2.h chain (via wmi_hooks.h) produces sockaddr/fd_set/accept/...
// redefinition errors.  Already set project-wide for x64, but Win32 configs
// don't have it.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include "hook_manager.h"
#include "log_utils.h"
#include <comdef.h>

// COM/WMI libs needed by InstallWmiHooks (DLL build doesn't list them
// in vcxproj — bring them in here so a refactor of the project file is
// not required).
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

#include "registry_hooks.h"
#include "file_hooks.h"
#include "device_hooks.h"
#include "processes_hooks.h"
#include "window_hooks.h"
#include "network_hooks.h"
#include "firmwaretable_hooks.h"
#include "hypervobj_hooks.h"
#include "system_hooks.h"
#include "power_hooks.h"
#include "services_hooks.h"
#include "wmi_hooks.h"
#include "debugger_hooks.h"
#include "time_hooks.h"
#include "process_info_hooks.h"
#include "input_hooks.h"
#include "object_info_hooks.h"
#include "module_hide_hooks.h"

#define MH_STATIC
#include "MinHook.h"

// 

// ������������� �����
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
        DebugPrint("[MAC Addres]");
        return false;
    }

    if (!InitializeFirmwareTableHooks()) {
        DebugPrint("[Firmware Table]");
        return false;
    }

    if (!InitializeHyperVObjHooks()) {
        DebugPrint("[Hyper-V Objects]");
        return false;
    }

    if (!InitializeSystemHooks()) {
        DebugPrint("[System]");
        return false;
    }

    if (!InitializePowerHooks()) {
        DebugPrint("[Power]");
        return false;
    }

    if (!InitializeServicesHooks()) {
        DebugPrint("[Services]");
        return false;
    }

    if (!InitializeDebuggerHooks()) {
        DebugPrint("[Debugger]");
        return false;
    }

    if (!InitializeTimeHooks()) {
        DebugPrint("[Time]");
        return false;
    }

    if (!InitializeProcessInfoHooks()) {
        DebugPrint("[ProcessInfo]");
        return false;
    }

    if (!InitializeInputHooks()) {
        DebugPrint("[Input]");
        return false;
    }

    if (!InitializeObjectInfoHooks()) {
        DebugPrint("[ObjectInfo]");
        return false;
    }

    // Note: InitializeModuleHideHooks needs the hooksbox.dll HMODULE; it's
    // invoked separately from DllMain (DLL_PROCESS_ATTACH) where we have
    // it for free, not from this aggregate initializer.

    DebugPrint("[HOOK_DLL] Hooks installed successfully!");
    return true;
}

void CleanupHooks() {
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

    if (MH_CreateHook(&RegEnumKeyExW, &hook_RegEnumKeyExW,
        reinterpret_cast<void**>(&original_RegEnumKeyExW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegEnumKeyExW");
        return false;
    }

    if (MH_CreateHook(&RegOpenKeyExA, &hook_RegOpenKeyExA,
        reinterpret_cast<void**>(&original_RegOpenKeyExA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegOpenKeyExA");
        return false;
    }

    if (MH_CreateHook(&RegQueryValueExA, &hook_RegQueryValueExA,
        reinterpret_cast<void**>(&original_RegQueryValueExA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegQueryValueExA");
        return false;
    }

    if (MH_CreateHook(&RegEnumKeyExA, &hook_RegEnumKeyExA,
        reinterpret_cast<void**>(&original_RegEnumKeyExA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegEnumKeyExA");
        return false;
    }

    DebugPrint("[HOOK_DLL] Registry hooks created successfully");

    // The trailing W check used to omit `!= MH_OK`; it worked by coincidence
    // (MH_OK == 0) but read like a bug.  Made consistent + every hook now
    // covered, including the ANSI mirrors pafish-style detectors actually
    // call.
    if (MH_EnableHook(&RegOpenKeyExW)    != MH_OK ||
        MH_EnableHook(&RegQueryValueExW) != MH_OK ||
        MH_EnableHook(&RegEnumKeyExW)    != MH_OK ||
        MH_EnableHook(&RegOpenKeyExA)    != MH_OK ||
        MH_EnableHook(&RegQueryValueExA) != MH_OK ||
        MH_EnableHook(&RegEnumKeyExA)    != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable registry hooks");
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

    if (MH_CreateHook(&GetFileAttributesA, &hook_GetFileAttributesA,
        reinterpret_cast<void**>(&original_GetFileAttributesA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for GetFileAttributesA");
        return false;
    }

    DebugPrint("[HOOK_DLL] File hooks created successfully");

    if (MH_EnableHook(&GetFileAttributesW) != MH_OK ||
        MH_EnableHook(&GetFileAttributesA) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable file hooks");
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
    FARPROC pProcess32NextW  = GetProcAddress(hKernel32, "Process32NextW");
    FARPROC pProcess32First  = GetProcAddress(hKernel32, "Process32First");
    FARPROC pProcess32Next   = GetProcAddress(hKernel32, "Process32Next");

    if (!pProcess32FirstW || !pProcess32NextW || !pProcess32First || !pProcess32Next) {
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
        DebugPrint("[HOOK_DLL] Failed to create hook for Process32NextW");
        return false;
    }

    if (MH_CreateHook(pProcess32First, &hook_Process32First,
        reinterpret_cast<void**>(&original_Process32First)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for Process32First (A)");
        return false;
    }

    if (MH_CreateHook(pProcess32Next, &hook_Process32Next,
        reinterpret_cast<void**>(&original_Process32Next)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for Process32Next (A)");
        return false;
    }

    DebugPrint("[HOOK_DLL] Process hooks created successfully");

    if (MH_EnableHook(pProcess32FirstW) != MH_OK ||
        MH_EnableHook(pProcess32NextW)  != MH_OK ||
        MH_EnableHook(pProcess32First)  != MH_OK ||
        MH_EnableHook(pProcess32Next)   != MH_OK) {
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

    if (MH_CreateHook(&FindWindowA, &hook_FindWindowA,
        reinterpret_cast<void**>(&original_FindWindowA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for FindWindowA");
        return false;
    }

    if (MH_CreateHook(&FindWindowExA, &hook_FindWindowExA,
        reinterpret_cast<void**>(&original_FindWindowExA)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for FindWindowExA");
        return false;
    }

    DebugPrint("[HOOK_DLL] Window hooks created successfully");

    if (MH_EnableHook(&FindWindowW)   != MH_OK ||
        MH_EnableHook(&FindWindowExW) != MH_OK ||
        MH_EnableHook(&FindWindowA)   != MH_OK ||
        MH_EnableHook(&FindWindowExA) != MH_OK) {
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
    FARPROC pWNetGetProviderNameA = GetProcAddress(hMpr, "WNetGetProviderNameA");
    if (!pWNetGetProviderNameW || !pWNetGetProviderNameA) {
        DebugPrint("[NETWORK_HOOKS] Failed to get WNetGetProviderName addresses");
        return false;
    }

    if (MH_CreateHook(pWNetGetProviderNameW, &hook_WNetGetProviderNameW,
        reinterpret_cast<void**>(&original_WNetGetProviderNameW)) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to create hook for WNetGetProviderNameW");
        return false;
    }

    if (MH_CreateHook(pWNetGetProviderNameA, &hook_WNetGetProviderNameA,
        reinterpret_cast<void**>(&original_WNetGetProviderNameA)) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to create hook for WNetGetProviderNameA");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] WNetGetProviderName hooks created successfully");

    if (MH_EnableHook(pWNetGetProviderNameW) != MH_OK ||
        MH_EnableHook(pWNetGetProviderNameA) != MH_OK) {
        DebugPrint("[NETWORK_HOOKS] Failed to enable WNetGetProviderName hooks");
        return false;
    }

    DebugPrint("[NETWORK_HOOKS] WNetGetProviderName hooks enabled successfully");
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

bool InitializeFirmwareTableHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to get kernel32 handle");
        return false;
    }

    FARPROC pGetSystemFirmwareTable = GetProcAddress(hKernel32, "GetSystemFirmwareTable");
    FARPROC pEnumSystemFirmwareTables = GetProcAddress(hKernel32, "EnumSystemFirmwareTables");

    if (!pGetSystemFirmwareTable || !pEnumSystemFirmwareTables) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to get firmware table functions addresses");
        return false;
    }

    if (MH_CreateHook(pGetSystemFirmwareTable, &hook_GetSystemFirmwareTable,
        reinterpret_cast<void**>(&original_GetSystemFirmwareTable)) != MH_OK) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to create hook for GetSystemFirmwareTable");
        return false;
    }

    if (MH_EnableHook(pGetSystemFirmwareTable) != MH_OK) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to enable GetSystemFirmwareTable hook");
        return false;
    }

    DebugPrint("[FIRMWARE_TABLE_HOOK] GetSystemFirmwareTable hook created and enabled successfully");

    if (MH_CreateHook(pEnumSystemFirmwareTables, &hook_EnumSystemFirmwareTables,
        reinterpret_cast<void**>(&original_EnumSystemFirmwareTables)) != MH_OK) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to create hook for EnumSystemFirmwareTables");
        return false;
    }

    if (MH_EnableHook(pEnumSystemFirmwareTables) != MH_OK) {
        DebugPrint("[FIRMWARE_TABLE_HOOK] Failed to enable EnumSystemFirmwareTables hook");
        return false;
    }

    DebugPrint("[FIRMWARE_TABLE_HOOK] EnumSystemFirmwareTables hook created and enabled successfully");

    return true; 
}

bool InitializeHyperVObjHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[HYPER-V HOOK] Failed to get ntdll handle");
        return false;
    }

    FARPROC pNtOpenDirectoryObject = GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    FARPROC pNtQueryDirectoryObject = GetProcAddress(hNtdll, "NtQueryDirectoryObject");

    if (!pNtOpenDirectoryObject || !pNtQueryDirectoryObject) {
        DebugPrint("[HYPER-V HOOK] Failed to get hyper-v functions addresses");
        return false;
    }

    if (MH_CreateHook(pNtOpenDirectoryObject, hook_NtOpenDirectoryObject,
        (LPVOID*)&original_NtOpenDirectoryObject) != MH_OK) {
        DebugPrint("[HYPER-V HOOK] Failed to create hook for NtOpenDirectoryObject");
        return false;
    }

    if (MH_CreateHook(pNtQueryDirectoryObject, hook_NtQueryDirectoryObject,
        (LPVOID*)&original_NtQueryDirectoryObject) != MH_OK) {
        DebugPrint("[HYPER-V HOOK] Failed to create hook for NtQueryDirectoryObject");
        return false;
    }

    DebugPrint("[HYPER-V HOOK] Hyper-V hooks created successfully");


    if (MH_EnableHook(pNtOpenDirectoryObject) != MH_OK ||
        MH_EnableHook(pNtQueryDirectoryObject) != MH_OK) {
        DebugPrint("[HYPER-V HOOK] Failed to enable hyper-v hooks");
        return false;
    }

    DebugPrint("[HYPER-V HOOK] Hyper-V hooks enalebled successfully");

    return true;
}

bool InitializeSystemHooks() {
    if (MH_CreateHook(&SetupDiEnumDeviceInfo, &hook_SetupDiEnumDeviceInfo,
        reinterpret_cast<void**>(&original_SetupDiEnumDeviceInfo)) != MH_OK) {
        DebugPrint("[SYSTEM] Failed to create hook for SetupDiEnumDeviceInfo");
        return false;
    }

    DebugPrint("[SYSTEM] SetupDiEnumDeviceInfo hooks created successfully");

    if (MH_EnableHook(&SetupDiEnumDeviceInfo) != MH_OK) {
        DebugPrint("[SYSTEM] Failed to enable SetupDiEnumDeviceInfo hooks");
        return false;
    }

    if (MH_CreateHook(&GetDiskFreeSpaceExW, &hook_GetDiskFreeSpaceExW,
        reinterpret_cast<void**>(&original_GetDiskFreeSpaceExW)) != MH_OK) {
        DebugPrint("[SYSTEM] Failed to create hook for GetDiskFreeSpaceExW");
        return false;
    }

    DebugPrint("[SYSTEM] GetDiskFreeSpaceExW hooks created successfully");

    if (MH_EnableHook(&GetDiskFreeSpaceExW) != MH_OK) {
        DebugPrint("[SYSTEM] Failed to enable GetDiskFreeSpaceExW hooks");
        return false;
    }

    DebugPrint("[SYSTEM] System hooks enable successfully");
    return true;
}

bool InitializePowerHooks() {
    HMODULE hPowrprof = GetModuleHandleW(L"powrprof.dll");
    if (!hPowrprof) hPowrprof = LoadLibraryW(L"powrprof.dll");
    if (!hPowrprof) {
        DebugPrint("[POWER_HOOK] Failed to load powrprof.dll");
        return false;
    }

    FARPROC pGetPwrCapabilities = GetProcAddress(hPowrprof, "GetPwrCapabilities");
    if (!pGetPwrCapabilities) {
        DebugPrint("[POWER_HOOK] Failed to get GetPwrCapabilities address");
        return false;
    }

    if (MH_CreateHook(pGetPwrCapabilities, &hook_GetPwrCapabilities,
        reinterpret_cast<void**>(&original_GetPwrCapabilities)) != MH_OK) {
        DebugPrint("[POWER_HOOK] Failed to create hook for GetPwrCapabilities");
        return false;
    }

    if (MH_EnableHook(pGetPwrCapabilities) != MH_OK) {
        DebugPrint("[POWER_HOOK] Failed to enable GetPwrCapabilities hook");
        return false;
    }

    DebugPrint("[POWER_HOOK] GetPwrCapabilities hook installed");
    return true;
}

bool InitializeDebuggerHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        DebugPrint("[DEBUGGER_HOOK] Failed to get kernel32 handle");
        return false;
    }

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    FARPROC pCheckRemoteDbg    = GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");

    if (!pIsDebuggerPresent || !pCheckRemoteDbg) {
        DebugPrint("[DEBUGGER_HOOK] Failed to get debugger API addresses");
        return false;
    }

    if (MH_CreateHook(pIsDebuggerPresent, &hook_IsDebuggerPresent,
        reinterpret_cast<void**>(&original_IsDebuggerPresent)) != MH_OK) {
        DebugPrint("[DEBUGGER_HOOK] Failed to create hook for IsDebuggerPresent");
        return false;
    }

    if (MH_CreateHook(pCheckRemoteDbg, &hook_CheckRemoteDebuggerPresent,
        reinterpret_cast<void**>(&original_CheckRemoteDebuggerPresent)) != MH_OK) {
        DebugPrint("[DEBUGGER_HOOK] Failed to create hook for CheckRemoteDebuggerPresent");
        return false;
    }

    if (MH_EnableHook(pIsDebuggerPresent) != MH_OK ||
        MH_EnableHook(pCheckRemoteDbg)    != MH_OK) {
        DebugPrint("[DEBUGGER_HOOK] Failed to enable debugger hooks");
        return false;
    }

    // Mask the PEB-resident flags too — pafish debug_beingdebugged_peb reads
    // them directly and never goes through kernel32!IsDebuggerPresent.
    PatchPebDebuggerFlags();

    DebugPrint("[DEBUGGER_HOOK] Debugger hooks installed (incl. PEB patch)");
    return true;
}

bool InitializeTimeHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        DebugPrint("[TIME_HOOK] Failed to get kernel32 handle");
        return false;
    }

    FARPROC pGetTickCount   = GetProcAddress(hKernel32, "GetTickCount");
    FARPROC pGetTickCount64 = GetProcAddress(hKernel32, "GetTickCount64");

    if (!pGetTickCount || !pGetTickCount64) {
        DebugPrint("[TIME_HOOK] Failed to get tick-count API addresses");
        return false;
    }

    if (MH_CreateHook(pGetTickCount, &hook_GetTickCount,
        reinterpret_cast<void**>(&original_GetTickCount)) != MH_OK) {
        DebugPrint("[TIME_HOOK] Failed to create hook for GetTickCount");
        return false;
    }

    if (MH_CreateHook(pGetTickCount64, &hook_GetTickCount64,
        reinterpret_cast<void**>(&original_GetTickCount64)) != MH_OK) {
        DebugPrint("[TIME_HOOK] Failed to create hook for GetTickCount64");
        return false;
    }

    if (MH_EnableHook(pGetTickCount)   != MH_OK ||
        MH_EnableHook(pGetTickCount64) != MH_OK) {
        DebugPrint("[TIME_HOOK] Failed to enable tick-count hooks");
        return false;
    }

    DebugPrint("[TIME_HOOK] GetTickCount/GetTickCount64 hooks installed");
    return true;
}

bool InitializeProcessInfoHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[PROCINFO_HOOK] Failed to get ntdll handle");
        return false;
    }

    FARPROC pNtQueryInformationProcess =
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    FARPROC pNtClose = GetProcAddress(hNtdll, "NtClose");

    if (!pNtQueryInformationProcess || !pNtClose) {
        DebugPrint("[PROCINFO_HOOK] Failed to get ntdll function addresses");
        return false;
    }

    if (MH_CreateHook(pNtQueryInformationProcess,
        &hook_NtQueryInformationProcess,
        reinterpret_cast<void**>(&original_NtQueryInformationProcess)) != MH_OK) {
        DebugPrint("[PROCINFO_HOOK] Failed to create hook for NtQueryInformationProcess");
        return false;
    }

    if (MH_CreateHook(pNtClose, &hook_NtClose,
        reinterpret_cast<void**>(&original_NtClose)) != MH_OK) {
        DebugPrint("[PROCINFO_HOOK] Failed to create hook for NtClose");
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        DebugPrint("[PROCINFO_HOOK] Failed to get kernel32 handle");
        return false;
    }
    FARPROC pCloseHandle = GetProcAddress(hKernel32, "CloseHandle");
    if (!pCloseHandle) {
        DebugPrint("[PROCINFO_HOOK] Failed to get CloseHandle address");
        return false;
    }
    if (MH_CreateHook(pCloseHandle, &hook_CloseHandle,
        reinterpret_cast<void**>(&original_CloseHandle)) != MH_OK) {
        DebugPrint("[PROCINFO_HOOK] Failed to create hook for CloseHandle");
        return false;
    }

    if (MH_EnableHook(pNtQueryInformationProcess) != MH_OK ||
        MH_EnableHook(pNtClose)                   != MH_OK ||
        MH_EnableHook(pCloseHandle)               != MH_OK) {
        DebugPrint("[PROCINFO_HOOK] Failed to enable process-info hooks");
        return false;
    }

    DebugPrint("[PROCINFO_HOOK] NtQueryInformationProcess + NtClose + CloseHandle installed");
    return true;
}

bool InitializeInputHooks() {
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (!hUser32) hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32) {
        DebugPrint("[INPUT_HOOK] Failed to load user32.dll");
        return false;
    }
    FARPROC pGetLastInputInfo = GetProcAddress(hUser32, "GetLastInputInfo");
    if (!pGetLastInputInfo) {
        DebugPrint("[INPUT_HOOK] Failed to get GetLastInputInfo address");
        return false;
    }
    if (MH_CreateHook(pGetLastInputInfo, &hook_GetLastInputInfo,
        reinterpret_cast<void**>(&original_GetLastInputInfo)) != MH_OK) {
        DebugPrint("[INPUT_HOOK] Failed to create hook for GetLastInputInfo");
        return false;
    }
    if (MH_EnableHook(pGetLastInputInfo) != MH_OK) {
        DebugPrint("[INPUT_HOOK] Failed to enable GetLastInputInfo hook");
        return false;
    }
    DebugPrint("[INPUT_HOOK] GetLastInputInfo hook installed");
    return true;
}

bool InitializeObjectInfoHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[OBJINFO_HOOK] Failed to get ntdll handle");
        return false;
    }
    FARPROC pNtQueryObject = GetProcAddress(hNtdll, "NtQueryObject");
    if (!pNtQueryObject) {
        DebugPrint("[OBJINFO_HOOK] Failed to get NtQueryObject address");
        return false;
    }
    if (MH_CreateHook(pNtQueryObject, &hook_NtQueryObject,
        reinterpret_cast<void**>(&original_NtQueryObject)) != MH_OK) {
        DebugPrint("[OBJINFO_HOOK] Failed to create hook for NtQueryObject");
        return false;
    }
    if (MH_EnableHook(pNtQueryObject) != MH_OK) {
        DebugPrint("[OBJINFO_HOOK] Failed to enable NtQueryObject hook");
        return false;
    }
    DebugPrint("[OBJINFO_HOOK] NtQueryObject hook installed");
    return true;
}

bool InitializeModuleHideHooks(HMODULE hSelf) {
    // Step 1: unlink ourselves from PEB->Ldr lists.  This covers
    // EnumProcessModulesEx, Module32First/Next, LdrEnumerateLoadedModules,
    // direct PEB-Ldr walks, GetModuleHandleEx, GetModuleFileNameEx — all
    // of which derive their results from the LDR lists.
    HideHooksboxModule(hSelf);

    // Step 2: hook GetMappedFileName{W,A} so al-khaser's MemoryWalk_Hidden
    // can't see the file backing our address range via NtQueryVirtualMemory
    // (MemorySectionName).  LDR unlinking doesn't touch the section-name
    // store; this hook does.
    HMODULE hPsapi = GetModuleHandleW(L"psapi.dll");
    if (!hPsapi) hPsapi = LoadLibraryW(L"psapi.dll");
    if (!hPsapi) {
        // psapi is a forwarder DLL — the real symbols live in kernel32 on
        // modern Windows.  Fall back to kernel32 if psapi failed.
        hPsapi = GetModuleHandleW(L"kernel32.dll");
    }
    if (!hPsapi) {
        DebugPrint("[MODHIDE_HOOK] Failed to load psapi/kernel32");
        return false;
    }
    FARPROC pGmfW = GetProcAddress(hPsapi, "GetMappedFileNameW");
    FARPROC pGmfA = GetProcAddress(hPsapi, "GetMappedFileNameA");
    // On Windows 10+, psapi.dll forwards to KernelBase.dll's K32GetMappedFileNameW.
    // Try the K32-prefixed name as a fallback if the unprefixed lookup misses.
    if (!pGmfW) pGmfW = GetProcAddress(hPsapi, "K32GetMappedFileNameW");
    if (!pGmfA) pGmfA = GetProcAddress(hPsapi, "K32GetMappedFileNameA");
    if (!pGmfW || !pGmfA) {
        DebugPrint("[MODHIDE_HOOK] Failed to resolve GetMappedFileNameW/A addresses");
        return false;
    }
    if (MH_CreateHook(pGmfW, &hook_GetMappedFileNameW,
        reinterpret_cast<void**>(&original_GetMappedFileNameW)) != MH_OK) {
        DebugPrint("[MODHIDE_HOOK] Failed to create hook for GetMappedFileNameW");
        return false;
    }
    if (MH_CreateHook(pGmfA, &hook_GetMappedFileNameA,
        reinterpret_cast<void**>(&original_GetMappedFileNameA)) != MH_OK) {
        DebugPrint("[MODHIDE_HOOK] Failed to create hook for GetMappedFileNameA");
        return false;
    }
    if (MH_EnableHook(pGmfW) != MH_OK ||
        MH_EnableHook(pGmfA) != MH_OK) {
        DebugPrint("[MODHIDE_HOOK] Failed to enable GetMappedFileName hooks");
        return false;
    }

    // Step 3: hook the underlying ntdll syscall stub too.  The public
    // GetMappedFileName{W,A} APIs forward through psapi → kernel32 →
    // kernelbase, and which link the caller's import binds to can vary;
    // hooking the syscall stub catches every path uniformly.
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        DebugPrint("[MODHIDE_HOOK] Failed to get ntdll handle");
        return false;
    }
    FARPROC pNtQVM = GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    if (!pNtQVM) {
        DebugPrint("[MODHIDE_HOOK] Failed to resolve NtQueryVirtualMemory");
        return false;
    }
    if (MH_CreateHook(pNtQVM, &hook_NtQueryVirtualMemory,
        reinterpret_cast<void**>(&original_NtQueryVirtualMemory)) != MH_OK) {
        DebugPrint("[MODHIDE_HOOK] Failed to create hook for NtQueryVirtualMemory");
        return false;
    }
    if (MH_EnableHook(pNtQVM) != MH_OK) {
        DebugPrint("[MODHIDE_HOOK] Failed to enable NtQueryVirtualMemory hook");
        return false;
    }

    DebugPrint("[MODHIDE_HOOK] LDR unlink + GetMappedFileName + NtQueryVirtualMemory hooks installed");
    return true;
}

bool InitializeServicesHooks() {
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi32) hAdvapi32 = LoadLibraryW(L"advapi32.dll");
    if (!hAdvapi32) {
        DebugPrint("[SERVICES_HOOK] Failed to load advapi32.dll");
        return false;
    }

    FARPROC pEnumServicesStatusExW =
        GetProcAddress(hAdvapi32, "EnumServicesStatusExW");
    if (!pEnumServicesStatusExW) {
        DebugPrint("[SERVICES_HOOK] Failed to get EnumServicesStatusExW address");
        return false;
    }

    if (MH_CreateHook(pEnumServicesStatusExW, &hook_EnumServicesStatusExW,
        reinterpret_cast<void**>(&original_EnumServicesStatusExW)) != MH_OK) {
        DebugPrint("[SERVICES_HOOK] Failed to create hook for EnumServicesStatusExW");
        return false;
    }

    if (MH_EnableHook(pEnumServicesStatusExW) != MH_OK) {
        DebugPrint("[SERVICES_HOOK] Failed to enable EnumServicesStatusExW hook");
        return false;
    }

    DebugPrint("[SERVICES_HOOK] EnumServicesStatusExW hook installed");
    return true;
}

// ===========================================================================
// WMI hook installers
//
// IEnumWbemClassObject::Next is patched per-call (Hook_Next or
// Hook_Next_FilterPnP — both target the same vtable slot, only one of
// them is meaningful at a time).
//
// IWbemClassObject::Get is patched ONCE with a shared dispatcher
// (Hook_DispatcherGet) — every IWbemClassObject in ROOT\CIMV2 resolves
// Get to the same code address, so MinHook can only carry a single hook
// there.  Per-class behaviour is multiplexed by the enable flags in
// WmiMaskHooks::g_*Enabled, which Install*Hook / Remove*Hook flip.  The
// dispatcher is created on the first Install* call and torn down by the
// last Remove* call.
// ===========================================================================

static LPVOID s_pNextTarget       = nullptr;
static LPVOID s_pFilterTarget     = nullptr;
static LPVOID s_pDispatcherTarget = nullptr;

static bool EnsureMinHookInitialized()
{
    MH_STATUS st = MH_Initialize();
    return (st == MH_OK || st == MH_ERROR_ALREADY_INITIALIZED);
}

static void LogHookInstalled(const wchar_t* name, LPVOID target)
{
    uintptr_t addr = reinterpret_cast<uintptr_t>(target);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(std::wstring(name) + L": installed at 0x" + hex);
}

// Pin the module that owns the just-hooked code so CoFreeUnusedLibraries
// cannot unload it between tests.  COM proxies (wbemprox/fastprox) are
// otherwise dropped the moment WmiSession::~WmiSession runs CoUninitialize
// and the per-thread COM refcount falls to zero — taking our patched
// function bodies with them and silently disabling every subsequent hook.
static void PinModuleContaining(LPVOID addr)
{
    if (!addr) return;
    HMODULE hMod = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(addr),
        &hMod);
}

// ---------------------------------------------------------------------------
// Next hooks
// ---------------------------------------------------------------------------
bool InitializeWmiNextHook(IEnumWbemClassObject* pEnum)
{
    if (!pEnum)
    {
        WMIHOOK_ERROR(L"InitializeWmiNextHook: pEnum is null");
        return false;
    }

    void** vtbl   = *reinterpret_cast<void***>(pEnum);
    s_pNextTarget = vtbl[WmiMaskHooks::kVtblSlot_Next];

    if (!EnsureMinHookInitialized())
    {
        WMIHOOK_ERROR(L"InitializeWmiNextHook: MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(s_pNextTarget,
                      reinterpret_cast<LPVOID>(&WmiMaskHooks::Hook_Next),
                      reinterpret_cast<LPVOID*>(&WmiMaskHooks::g_pOrigNext)) != MH_OK)
    {
        WMIHOOK_ERROR(L"InitializeWmiNextHook: MH_CreateHook failed");
        s_pNextTarget = nullptr;
        return false;
    }

    if (MH_EnableHook(s_pNextTarget) != MH_OK)
    {
        MH_RemoveHook(s_pNextTarget);
        WMIHOOK_ERROR(L"InitializeWmiNextHook: MH_EnableHook failed");
        s_pNextTarget = nullptr;
        return false;
    }

    PinModuleContaining(s_pNextTarget);
    LogHookInstalled(L"InitializeWmiNextHook", s_pNextTarget);
    return true;
}

void CleanupWmiNextHook()
{
    if (!s_pNextTarget) return;

    MH_DisableHook(s_pNextTarget);
    MH_RemoveHook(s_pNextTarget);
    WMIHOOK_INFO(L"CleanupWmiNextHook: hook removed");
    s_pNextTarget              = nullptr;
    WmiMaskHooks::g_pOrigNext  = nullptr;
}

bool InitializeWmiFilterPnPHook(IEnumWbemClassObject* pEnum)
{
    if (!pEnum)
    {
        WMIHOOK_ERROR(L"InitializeWmiFilterPnPHook: pEnum is null");
        return false;
    }

    void** vtbl     = *reinterpret_cast<void***>(pEnum);
    s_pFilterTarget = vtbl[WmiMaskHooks::kVtblSlot_Next];

    if (!EnsureMinHookInitialized())
    {
        WMIHOOK_ERROR(L"InitializeWmiFilterPnPHook: MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(s_pFilterTarget,
                      reinterpret_cast<LPVOID>(&WmiMaskHooks::Hook_Next_FilterPnP),
                      reinterpret_cast<LPVOID*>(&WmiMaskHooks::g_pOrigNextFilter)) != MH_OK)
    {
        WMIHOOK_ERROR(L"InitializeWmiFilterPnPHook: MH_CreateHook failed");
        s_pFilterTarget = nullptr;
        return false;
    }

    if (MH_EnableHook(s_pFilterTarget) != MH_OK)
    {
        MH_RemoveHook(s_pFilterTarget);
        WMIHOOK_ERROR(L"InitializeWmiFilterPnPHook: MH_EnableHook failed");
        s_pFilterTarget = nullptr;
        return false;
    }

    PinModuleContaining(s_pFilterTarget);
    LogHookInstalled(L"InitializeWmiFilterPnPHook", s_pFilterTarget);
    return true;
}

void CleanupWmiFilterPnPHook()
{
    if (!s_pFilterTarget) return;

    MH_DisableHook(s_pFilterTarget);
    MH_RemoveHook(s_pFilterTarget);
    WMIHOOK_INFO(L"CleanupWmiFilterPnPHook: hook removed");
    s_pFilterTarget                  = nullptr;
    WmiMaskHooks::g_pOrigNextFilter  = nullptr;
}

// ---------------------------------------------------------------------------
// Shared Get dispatcher
// ---------------------------------------------------------------------------
static bool EnsureDispatcherInstalled(IWbemClassObject* pObj)
{
    if (s_pDispatcherTarget) return true;
    if (!pObj)
    {
        WMIHOOK_ERROR(L"EnsureDispatcherInstalled: pObj is null");
        return false;
    }

    void** vtbl  = *reinterpret_cast<void***>(pObj);
    LPVOID target = vtbl[WmiMaskHooks::kVtblSlot_WbemGet];

    if (!EnsureMinHookInitialized())
    {
        WMIHOOK_ERROR(L"EnsureDispatcherInstalled: MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(target,
                      reinterpret_cast<LPVOID>(&WmiMaskHooks::Hook_DispatcherGet),
                      reinterpret_cast<LPVOID*>(&WmiMaskHooks::g_pOrigGet)) != MH_OK)
    {
        WMIHOOK_ERROR(L"EnsureDispatcherInstalled: MH_CreateHook failed");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK)
    {
        MH_RemoveHook(target);
        WMIHOOK_ERROR(L"EnsureDispatcherInstalled: MH_EnableHook failed");
        return false;
    }

    s_pDispatcherTarget = target;
    PinModuleContaining(s_pDispatcherTarget);
    LogHookInstalled(L"DispatcherGet", target);
    return true;
}

static void MaybeRemoveDispatcher()
{
    if (!s_pDispatcherTarget) return;

    if (WmiMaskHooks::g_BaseBoardEnabled || WmiMaskHooks::g_BusEnabled ||
        WmiMaskHooks::g_PnPDeviceEnabled || WmiMaskHooks::g_BiosEnabled ||
        WmiMaskHooks::g_ComputerSystemEnabled || WmiMaskHooks::g_VideoEnabled)
        return;

    MH_DisableHook(s_pDispatcherTarget);
    MH_RemoveHook(s_pDispatcherTarget);
    WMIHOOK_INFO(L"DispatcherGet: hook removed");
    s_pDispatcherTarget       = nullptr;
    WmiMaskHooks::g_pOrigGet  = nullptr;
}

// ---------------------------------------------------------------------------
// Per-class Install / Remove — flip a flag + ensure the dispatcher is up.
// ---------------------------------------------------------------------------
#define DEFINE_GETHOOK(Name, Flag)                                                \
    bool Install##Name##Hook(IWbemClassObject* pObj)                              \
    {                                                                             \
        if (!EnsureDispatcherInstalled(pObj)) return false;                       \
        WmiMaskHooks::Flag = true;                                                \
        WMIHOOK_INFO(L"Install" L#Name L"Hook: enabled");                         \
        return true;                                                              \
    }                                                                             \
    void Remove##Name##Hook()                                                     \
    {                                                                             \
        WmiMaskHooks::Flag = false;                                               \
        WMIHOOK_INFO(L"Remove" L#Name L"Hook: disabled");                         \
        MaybeRemoveDispatcher();                                                  \
    }

DEFINE_GETHOOK(BaseBoard,      g_BaseBoardEnabled)
DEFINE_GETHOOK(Bus,            g_BusEnabled)
DEFINE_GETHOOK(PnPDevice,      g_PnPDeviceEnabled)
DEFINE_GETHOOK(Bios,           g_BiosEnabled)
DEFINE_GETHOOK(ComputerSystem, g_ComputerSystemEnabled)
DEFINE_GETHOOK(Video,          g_VideoEnabled)
DEFINE_GETHOOK(Processor,      g_ProcessorEnabled)
DEFINE_GETHOOK(LogicalDisk,    g_LogicalDiskEnabled)
DEFINE_GETHOOK(Thermal,        g_ThermalEnabled)
DEFINE_GETHOOK(EventLog,       g_EventLogEnabled)

#undef DEFINE_GETHOOK

// ---------------------------------------------------------------------------
// All-in-one
// ---------------------------------------------------------------------------
bool InstallAllHooks(IWbemClassObject* pObj)
{
    if (!EnsureDispatcherInstalled(pObj)) return false;
    WmiMaskHooks::g_BaseBoardEnabled      = true;
    WmiMaskHooks::g_BusEnabled            = true;
    WmiMaskHooks::g_PnPDeviceEnabled      = true;
    WmiMaskHooks::g_BiosEnabled           = true;
    WmiMaskHooks::g_ComputerSystemEnabled = true;
    WmiMaskHooks::g_VideoEnabled          = true;
    WmiMaskHooks::g_ProcessorEnabled      = true;
    WmiMaskHooks::g_LogicalDiskEnabled    = true;
    WmiMaskHooks::g_ThermalEnabled        = true;
    WmiMaskHooks::g_EventLogEnabled       = true;
    WMIHOOK_INFO(L"InstallAllHooks: all class spoofs enabled");
    return true;
}

void RemoveAllHooks()
{
    WmiMaskHooks::g_BaseBoardEnabled      = false;
    WmiMaskHooks::g_BusEnabled            = false;
    WmiMaskHooks::g_PnPDeviceEnabled      = false;
    WmiMaskHooks::g_BiosEnabled           = false;
    WmiMaskHooks::g_ComputerSystemEnabled = false;
    WmiMaskHooks::g_VideoEnabled          = false;
    WmiMaskHooks::g_ProcessorEnabled      = false;
    WmiMaskHooks::g_LogicalDiskEnabled    = false;
    WmiMaskHooks::g_ThermalEnabled        = false;
    WmiMaskHooks::g_EventLogEnabled       = false;
    WMIHOOK_INFO(L"RemoveAllHooks: all class spoofs disabled");
    MaybeRemoveDispatcher();
}

// ---------------------------------------------------------------------------
// IWbemServices::ExecQuery hook (non-empty injection bootstrap)
// ---------------------------------------------------------------------------
static LPVOID s_pExecQueryTarget = nullptr;

bool InstallExecQueryHook(IWbemServices* pSvc)
{
    if (!pSvc)
    {
        WMIHOOK_ERROR(L"InstallExecQueryHook: pSvc is null");
        return false;
    }
    if (s_pExecQueryTarget) { WmiMaskHooks::g_NonEmptyEnabled = true; return true; }

    void** vtbl       = *reinterpret_cast<void***>(pSvc);
    s_pExecQueryTarget = vtbl[WmiMaskHooks::kVtblSlot_ExecQuery];

    if (!EnsureMinHookInitialized())
    {
        WMIHOOK_ERROR(L"InstallExecQueryHook: MH_Initialize failed");
        return false;
    }

    if (MH_CreateHook(s_pExecQueryTarget,
                      reinterpret_cast<LPVOID>(&WmiMaskHooks::Hook_ExecQuery),
                      reinterpret_cast<LPVOID*>(&WmiMaskHooks::g_pOrigExecQuery)) != MH_OK)
    {
        WMIHOOK_ERROR(L"InstallExecQueryHook: MH_CreateHook failed");
        s_pExecQueryTarget = nullptr;
        return false;
    }
    if (MH_EnableHook(s_pExecQueryTarget) != MH_OK)
    {
        MH_RemoveHook(s_pExecQueryTarget);
        s_pExecQueryTarget = nullptr;
        WMIHOOK_ERROR(L"InstallExecQueryHook: MH_EnableHook failed");
        return false;
    }

    PinModuleContaining(s_pExecQueryTarget);
    WmiMaskHooks::g_NonEmptyEnabled = true;
    LogHookInstalled(L"InstallExecQueryHook", s_pExecQueryTarget);
    return true;
}

void RemoveExecQueryHook()
{
    WmiMaskHooks::g_NonEmptyEnabled = false;
    if (!s_pExecQueryTarget) return;

    MH_DisableHook(s_pExecQueryTarget);
    MH_RemoveHook(s_pExecQueryTarget);
    WMIHOOK_INFO(L"RemoveExecQueryHook: hook removed");
    s_pExecQueryTarget               = nullptr;
    WmiMaskHooks::g_pOrigExecQuery   = nullptr;
}

// ===========================================================================
// Lazy WMI bootstrap via a CoCreateInstance trampoline.
//
// COM cannot be touched from DllMain — CoCreateInstance(CLSID_WbemLocator)
// would LoadLibrary("wbemprox.dll") under loader lock and deadlock the
// injecting thread.  Instead, DllMain installs ONE tiny patch on the
// ole32 (or combase) CoCreateInstance entry point.  That patch is just
// a memory write — no COM, no LoadLibrary.
//
// The host process resumes, runs its CRT/main, and at some point calls
// CoCreateInstance(CLSID_WbemLocator, ...).  Our trampoline fires AFTER
// the loader lock is released, so it can safely call ConnectServer /
// ExecQuery / Next to obtain seed objects and install the FilterPnP
// Next hook plus the shared Get dispatcher.  Subsequent calls by the
// host go through the now-active WMI hooks.
// ===========================================================================

static LONG     s_wmiBootstrapped         = 0;
static LPVOID   s_CoCreateInstanceTarget  = nullptr;

typedef HRESULT (WINAPI *FnCoCreateInstance)(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
    REFIID riid, LPVOID* ppv);
static FnCoCreateInstance original_CoCreateInstance = nullptr;

static void DoWmiInstall(IWbemLocator* pLocator)
{
    IWbemServices* pServices = nullptr;
    HRESULT hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"),
                                          nullptr, nullptr, nullptr,
                                          0, nullptr, nullptr, &pServices);
    if (FAILED(hr) || !pServices)
    {
        WMIHOOK_ERROR(L"DoWmiInstall: ConnectServer failed");
        return;
    }

    CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                      nullptr, RPC_C_AUTHN_LEVEL_CALL,
                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    // ExecQuery hook — pSvc IS the seed IWbemServices, no extra query
    // needed.  Installs the patch and flips g_NonEmptyEnabled.
    InstallExecQueryHook(pServices);

    // FilterPnP next hook — seed: any IEnumWbemClassObject.
    {
        IEnumWbemClassObject* pEnum = nullptr;
        if (SUCCEEDED(pServices->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(L"SELECT * FROM Win32_PnPEntity"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnum)) && pEnum)
        {
            InitializeWmiFilterPnPHook(pEnum);
            pEnum->Release();
        }
        else
        {
            WMIHOOK_ERROR(L"DoWmiInstall: enumerator seed query failed");
        }
    }

    // Dispatcher Get hook — seed: any IWbemClassObject.
    {
        IEnumWbemClassObject* pSeedEnum = nullptr;
        if (SUCCEEDED(pServices->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(L"SELECT * FROM Win32_ComputerSystem"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pSeedEnum)) && pSeedEnum)
        {
            IWbemClassObject* pSeed = nullptr;
            ULONG returned = 0;
            if (pSeedEnum->Next(WBEM_INFINITE, 1, &pSeed, &returned) == S_OK &&
                returned > 0 && pSeed)
            {
                InstallAllHooks(pSeed);
                pSeed->Release();
            }
            else
            {
                WMIHOOK_ERROR(L"DoWmiInstall: no seed IWbemClassObject");
            }
            pSeedEnum->Release();
        }
        else
        {
            WMIHOOK_ERROR(L"DoWmiInstall: object seed query failed");
        }
    }

    pServices->Release();
    WMIHOOK_INFO(L"DoWmiInstall: completed");
}

static HRESULT WINAPI hook_CoCreateInstance(
    REFCLSID rclsid, LPUNKNOWN pUnkOuter,
    DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
    HRESULT hr = original_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

    if (SUCCEEDED(hr) && ppv && *ppv &&
        IsEqualCLSID(rclsid, CLSID_WbemLocator) &&
        InterlockedCompareExchange(&s_wmiBootstrapped, 1, 0) == 0)
    {
        IWbemLocator* pLocator = nullptr;
        if (IsEqualIID(riid, IID_IWbemLocator))
        {
            pLocator = reinterpret_cast<IWbemLocator*>(*ppv);
            pLocator->AddRef();
        }
        else
        {
            static_cast<IUnknown*>(*ppv)->QueryInterface(
                IID_IWbemLocator, reinterpret_cast<void**>(&pLocator));
        }
        if (pLocator)
        {
            DoWmiInstall(pLocator);
            pLocator->Release();
        }
    }
    return hr;
}

// Installs the CoCreateInstance bootstrap patch.  Safe from DllMain:
// only does GetModuleHandle / GetProcAddress / MinHook code patching —
// no LoadLibrary of foreign DLLs, no COM, no thread creation.
bool InstallWmiHooks()
{
    HMODULE hMod = GetModuleHandleW(L"combase.dll");
    if (!hMod) hMod = GetModuleHandleW(L"ole32.dll");
    if (!hMod)
    {
        WMIHOOK_ERROR(L"InstallWmiHooks: ole32/combase not loaded");
        return false;
    }
    FARPROC pCCI = GetProcAddress(hMod, "CoCreateInstance");
    if (!pCCI)
    {
        WMIHOOK_ERROR(L"InstallWmiHooks: GetProcAddress(CoCreateInstance) failed");
        return false;
    }

    if (!EnsureMinHookInitialized())
    {
        WMIHOOK_ERROR(L"InstallWmiHooks: MH_Initialize failed");
        return false;
    }

    s_CoCreateInstanceTarget = reinterpret_cast<LPVOID>(pCCI);
    if (MH_CreateHook(s_CoCreateInstanceTarget,
                      reinterpret_cast<LPVOID>(&hook_CoCreateInstance),
                      reinterpret_cast<LPVOID*>(&original_CoCreateInstance)) != MH_OK)
    {
        WMIHOOK_ERROR(L"InstallWmiHooks: MH_CreateHook(CoCreateInstance) failed");
        s_CoCreateInstanceTarget = nullptr;
        return false;
    }
    if (MH_EnableHook(s_CoCreateInstanceTarget) != MH_OK)
    {
        MH_RemoveHook(s_CoCreateInstanceTarget);
        s_CoCreateInstanceTarget = nullptr;
        WMIHOOK_ERROR(L"InstallWmiHooks: MH_EnableHook(CoCreateInstance) failed");
        return false;
    }

    PinModuleContaining(s_CoCreateInstanceTarget);
    WMIHOOK_INFO(L"InstallWmiHooks: CoCreateInstance bootstrap armed");
    return true;
}
