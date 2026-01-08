#include "hook_manager.h"
#include "../utils/log_utils.h"
#include "../hooks/registry_hooks.h"

#define MH_STATIC
#include "MinHook.h"

// 

// Инициализация хуков
bool InitializeHooks() {
    if (MH_Initialize() != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to initialize MinHook");
        return false;
    }

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

    // Включаем хуки
    if (MH_EnableHook(&RegOpenKeyExW) != MH_OK ||
        MH_EnableHook(&RegQueryValueExW) != MH_OK) {
        DebugPrint("[HOOK_DLL] Failed to enable hooks");
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