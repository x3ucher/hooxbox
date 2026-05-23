#include "hook_dll_main.h"
#include "utils/log_utils.h"
#include "hook_manager.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (!InitializeHooks()) {
            WriteFileLog(L"ERROR", L"DllMain: InitializeHooks() failed");
            return FALSE;
        }
        if (!InstallWmiHooks()) {
            WriteFileLog(L"WARN", L"DllMain: InstallWmiHooks() failed (continuing)");
        }
        WriteFileLog(L"INFO", L"DllMain: hooksbox.dll attached");
        break;

    case DLL_PROCESS_DETACH:
        CleanupHooks();
        WriteFileLog(L"INFO", L"DllMain: hooksbox.dll detached");
        break;
    }
    return TRUE;
}

// ������������ ������� ��� ������ �������������
extern "C" __declspec(dllexport) void InitializeMyHooks() {
    InitializeHooks();
}