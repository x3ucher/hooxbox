#include "window_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"

FindWindowW_t original_FindWindowW = nullptr;
FindWindowExW_t original_FindWindowExW = nullptr;
FindWindowA_t original_FindWindowA = nullptr;
FindWindowExA_t original_FindWindowExA = nullptr;

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
    // �� �� ������ ����������, ��� � ��� FindWindowW
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

// ---------------------------------------------------------------------------
// ANSI mirrors.  Pafish vbox_traywindow uses FindWindow (which is
// FindWindowA when UNICODE is not defined).  Without these hooks pafish
// trivially finds VBoxTrayToolWnd[Class] regardless of the W hooks above.
// ---------------------------------------------------------------------------
static bool MatchVBoxAnsi(LPCSTR s) {
    if (!s) return false;
    return _stricmp(s, "VBoxTrayToolWndClass") == 0 ||
           _stricmp(s, "VBoxTrayToolWnd") == 0 ||
           _stricmp(s, "VirtualBox") == 0;
}

HWND WINAPI hook_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    if (MatchVBoxAnsi(lpClassName) || MatchVBoxAnsi(lpWindowName)) {
        DebugPrint("[Window Hook] Blocked VirtualBox pattern (A)");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return nullptr;
    }
    return original_FindWindowA(lpClassName, lpWindowName);
}

HWND WINAPI hook_FindWindowExA(HWND hwndParent, HWND hwndChildAfter,
    LPCSTR lpClassName, LPCSTR lpWindowName)
{
    if (MatchVBoxAnsi(lpClassName) || MatchVBoxAnsi(lpWindowName)) {
        DebugPrint("[Window Hook] Blocked VirtualBox pattern (Ex/A)");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return nullptr;
    }
    return original_FindWindowExA(hwndParent, hwndChildAfter, lpClassName, lpWindowName);
}