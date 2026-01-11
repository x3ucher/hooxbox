#include "processes_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <string>
#include <map>

Process32FirstW_t original_Process32FirstW = nullptr;
Process32NextW_t original_Process32NextW = nullptr;

BOOL WINAPI hook_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    DebugPrintW(L"[HOOK_DLL] Process32FirstW called");
    BOOL result = original_Process32FirstW(hSnapshot, lppe);
    while (result && IsHiddenProcessW(lppe->szExeFile)) {
        result = original_Process32NextW(hSnapshot, lppe);
    }

    return result;
}

BOOL WINAPI hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    DebugPrintW(L"[HOOK_DLL] Process32NextW called");
    do {
        BOOL result = original_Process32NextW(hSnapshot, lppe);
        if (!result) return FALSE;

        if (!IsHiddenProcessW(lppe->szExeFile)) {
            return TRUE;
        }
    } while (true);
}
