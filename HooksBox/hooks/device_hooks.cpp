#include "device_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <string>
#include <map>

// Инициализация указателей на оригинальные функции
CreateFileW_t original_CreateFileW = nullptr;
CreateFileA_t original_CreateFileA = nullptr;


// Хук для GetFileAttributes
HANDLE WINAPI hook_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    if (lpFileName == NULL) {
        return original_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition,
            dwFlagsAndAttributes, hTemplateFile);
    }

    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] CreateFileW called: %s", lpFileName);
    DebugPrintW(debugMsg);

    if (IsVBoxDetectionAttempt(lpFileName, dwDesiredAccess, dwShareMode,
        dwCreationDisposition, dwFlagsAndAttributes)) {
        DebugPrint("[HOOK_DLL] Blocking VBox device detection attempt");

        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return original_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI hook_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    if (lpFileName == NULL) {
        return original_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition,
            dwFlagsAndAttributes, hTemplateFile);
    }

    wchar_t wideFileName[MAX_PATH];
    size_t convertedChars = 0;
    mbstowcs_s(&convertedChars, wideFileName, MAX_PATH, lpFileName, _TRUNCATE);

    if (IsVBoxDetectionAttempt(wideFileName, dwDesiredAccess, dwShareMode,
        dwCreationDisposition, dwFlagsAndAttributes)) {
        DebugPrint("[HOOK_DLL] Blocking VBox device detection attempt (ANSI)");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return original_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile);
}