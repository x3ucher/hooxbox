#include "hook_dll_main.h"
#include "utils/log_utils.h"
#include "hook_manager.h"

// ����� ����� DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // ��������� ����� DLL_THREAD_ATTACH/DETACH ��� �����������
        DisableThreadLibraryCalls(hModule);

        // �������������� ����
        if (!InitializeHooks()) {
            DebugPrint("[HOOK_DLL] Failed to initialize hooks");
            return FALSE;
        }
        // WMI hooks need a live COM session to resolve their vtable
        // targets; do that synchronously here so they are in place
        // before the host process resumes and runs its first WMI query.
        if (!InstallWmiHooks()) {
            DebugPrint("[HOOK_DLL] WMI hook install failed (continuing)");
        }
        DebugPrint("[HOOK_DLL] Injected successfully!");
        break;

    case DLL_PROCESS_DETACH:
        // ��������� ���� ��� ��������
        CleanupHooks();
        DebugPrint("[HOOK_DLL] Unloaded successfully!");
        break;
    }
    return TRUE;
}

// ������������ ������� ��� ������ �������������
extern "C" __declspec(dllexport) void InitializeMyHooks() {
    InitializeHooks();
}