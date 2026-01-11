#include "hook_manager.h"
#include "log_utils.h"
#include "registry_hooks.h"
#include "file_hooks.h"
#include "device_hooks.h"
#include "processes_hooks.h"

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
        return false;
    }

    if (!InitializeFileHooks()) {
        return false;
    }

    if (!InitializeDeviceHooks()) {
        return false;
    }

    if (!InitializeProcessHooks()) {
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
    // Создаем хук для RegOpenKeyExW
    if (MH_CreateHook(&RegOpenKeyExW, &hook_RegOpenKeyExW,
        reinterpret_cast<void**>(&original_RegOpenKeyExW)) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to create hook for RegOpenKeyExW");
        return false;
    }

    // Создаем хук для RegQueryValueExW
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
    // Создаем хук для GetFileAttributes
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
    // Создаем хук для CreateFileW
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