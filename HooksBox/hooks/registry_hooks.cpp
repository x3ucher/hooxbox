#include "registry_hooks.h"
#include "../utils/log_utils.h"
#include "../filters/vbox_filters.h"
#include <string>
#include <map>

// Инициализация указателей на оригинальные функции
RegOpenKeyExW_t original_RegOpenKeyExW = nullptr;
RegQueryValueExW_t original_RegQueryValueExW = nullptr;

// Хук для RegOpenKeyExW
LSTATUS WINAPI hook_RegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    // Выводим информацию в отладчик
    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] RegOpenKeyExW called. SubKey: %s", lpSubKey ? lpSubKey : L"null");
    DebugPrintW(debugMsg);

    // Проверяем, не пытаются ли открыть VBox ключ
    if (IsVBoxRegistryKey(hKey, lpSubKey)) {
        DebugPrint("[HOOK_DLL] BLOCKED: Attempt to access VirtualBox registry key!");
        return ERROR_ACCESS_DENIED; // Блокируем доступ
    }

    // Вызываем оригинальную функцию
    return original_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

// Хук для RegQueryValueExW
LSTATUS WINAPI hook_RegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    wchar_t debugMsg[512];
    swprintf_s(debugMsg, L"[HOOK_DLL] RegQueryValueExW called. ValueName: %s",
        lpValueName ? lpValueName : L"null");
    DebugPrintW(debugMsg);

    return original_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}