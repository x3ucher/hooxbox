#include "processes_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <string>
#include <map>

Process32FirstW_t original_Process32FirstW = nullptr;
Process32NextW_t original_Process32NextW = nullptr;
Process32First_t original_Process32First = nullptr;
Process32Next_t original_Process32Next = nullptr;

BOOL WINAPI hook_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    BOOL result = original_Process32FirstW(hSnapshot, lppe);
    while (result && IsHiddenProcessW(lppe->szExeFile)) {
        result = original_Process32NextW(hSnapshot, lppe);
    }
    return result;
}

BOOL WINAPI hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    do {
        BOOL result = original_Process32NextW(hSnapshot, lppe);
        if (!result) return FALSE;
        if (!IsHiddenProcessW(lppe->szExeFile)) {
            return TRUE;
        }
    } while (true);
}

// ANSI mirrors — pafish vbox_processes uses ANSI Process32First/Next.
BOOL WINAPI hook_Process32First(HANDLE hSnapshot, ProcessEntry32Ansi* lppe) {
    BOOL result = original_Process32First(hSnapshot, lppe);
    while (result && IsHiddenProcessA(lppe->szExeFile)) {
        result = original_Process32Next(hSnapshot, lppe);
    }
    return result;
}

BOOL WINAPI hook_Process32Next(HANDLE hSnapshot, ProcessEntry32Ansi* lppe) {
    do {
        BOOL result = original_Process32Next(hSnapshot, lppe);
        if (!result) return FALSE;
        if (!IsHiddenProcessA(lppe->szExeFile)) {
            return TRUE;
        }
    } while (true);
}
