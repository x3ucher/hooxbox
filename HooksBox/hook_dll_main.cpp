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
        // Module-hide layer needs our own HMODULE — DllMain is the only
        // place we get it for free without a syscall.  Runs after the
        // regular hook chain so the LDR walk we hide from is fully set up.
        if (!InitializeModuleHideHooks(hModule)) {
            WriteFileLog(L"WARN", L"DllMain: InitializeModuleHideHooks() failed (continuing)");
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