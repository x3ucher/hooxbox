#include "hook_dll_main.h"
#include "utils/log_utils.h"
#include "hook_manager.h"

// Точка входа DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Отключаем вызов DLL_THREAD_ATTACH/DETACH для оптимизации
        DisableThreadLibraryCalls(hModule);

        // Инициализируем хуки
        if (!InitializeHooks()) {
            DebugPrint("[HOOK_DLL] Failed to initialize hooks");
            return FALSE;
        }
        DebugPrint("[HOOK_DLL] Injected successfully!");
        break;

    case DLL_PROCESS_DETACH:
        // Отключаем хуки при выгрузке
        CleanupHooks();
        DebugPrint("[HOOK_DLL] Unloaded successfully!");
        break;
    }
    return TRUE;
}

// Экспортируем функцию для ручной инициализации
extern "C" __declspec(dllexport) void InitializeMyHooks() {
    InitializeHooks();
}