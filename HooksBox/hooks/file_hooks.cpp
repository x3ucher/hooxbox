#include "file_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <string>
#include <map>

// Инициализация указателей на оригинальные функции
GetFileAttributesW_t original_GetFileAttributesW = nullptr;

// Хук для GetFileAttributes
LSTATUS WINAPI hook_GetFileAttributesW(
    LPCWSTR lpFileName
) {
    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] GetFileAttributes called. FileName: %s", lpFileName ? lpFileName : L"null");
    DebugPrintW(debugMsg);

    if (IsVBoxFilePath(lpFileName)) {
        DebugPrint("[HOOK_DLL] BLOCKED: Attempt to access VirtualBox file!");
        return INVALID_FILE_ATTRIBUTES;
    }

    return original_GetFileAttributesW(lpFileName);
}