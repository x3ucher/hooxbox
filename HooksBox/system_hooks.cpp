#include "system_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"

WNetGetProviderNameW_t original_WNetGetProviderNameW = nullptr;
FindWindowW_t original_FindWindowW = nullptr;
FindWindowExW_t original_FindWindowExW = nullptr;
GetAdaptersInfo_t original_GetAdaptersInfo = nullptr;

HWND WINAPI hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
    static const std::vector<std::wstring> hiddenPatterns = {
        L"VBoxTrayToolWndClass",
        L"VBoxTrayToolWnd",
        L"VirtualBox", 
    };

    auto checkAndBlock = [&](const std::wstring& str) -> bool {
        for (const auto& pattern : hiddenPatterns)
        {
            if (EqualsCaseInsensitive(str, pattern))
            {
                DebugPrint("[Window Hook] Blocked VirtualBox pattern");
                return true;
            }
        }
        return false;
        };

    if (lpClassName)
    {
        std::wstring className(lpClassName);
        if (checkAndBlock(className))
            return NULL;
    }

    if (lpWindowName)
    {
        std::wstring windowName(lpWindowName);
        if (checkAndBlock(windowName))
            return NULL;
    }

    HWND result = original_FindWindowW(lpClassName, lpWindowName);
    return result;
}

HWND WINAPI hook_FindWindowExW(HWND hwndParent, HWND hwndChildAfter,
    LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
    // Та же логика маскировки, что и для FindWindowW
    if (lpClassName)
    {
        std::wstring className(lpClassName);
        if (className == L"VBoxTrayToolWndClass" ||
            className == L"VBoxTrayToolWnd")
        {
            return NULL;
        }
    }

    if (lpWindowName)
    {
        std::wstring windowName(lpWindowName);
        if (windowName == L"VBoxTrayToolWnd" ||
            windowName == L"VBoxTrayToolWndClass")
        {
            return NULL;
        }
    }

    return original_FindWindowExW(hwndParent, hwndChildAfter, lpClassName, lpWindowName);
}