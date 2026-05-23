#ifndef WINDOW_HOOKS_H
#define WINDOW_HOOKS_H

#include <windows.h>

typedef HWND(WINAPI* FindWindowW_t)(LPCWSTR, LPCWSTR);
typedef HWND(WINAPI* FindWindowExW_t)(HWND, HWND, LPCWSTR, LPCWSTR);
typedef HWND(WINAPI* FindWindowA_t)(LPCSTR, LPCSTR);
typedef HWND(WINAPI* FindWindowExA_t)(HWND, HWND, LPCSTR, LPCSTR);

extern FindWindowW_t original_FindWindowW;
extern FindWindowExW_t original_FindWindowExW;
extern FindWindowA_t original_FindWindowA;
extern FindWindowExA_t original_FindWindowExA;

HWND WINAPI hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
HWND WINAPI hook_FindWindowExW(HWND hwndParent, HWND hwndChildAfter,
                               LPCWSTR lpClassName, LPCWSTR lpWindowName);
HWND WINAPI hook_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName);
HWND WINAPI hook_FindWindowExA(HWND hwndParent, HWND hwndChildAfter,
                               LPCSTR lpClassName, LPCSTR lpWindowName);

#endif // WINDOW_HOOKS_H
