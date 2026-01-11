#ifndef WINDOW_HOOKS_H
#define WINDOW_HOOKS_H

#include <windows.h>

// Типы оригинальных функций
typedef HWND(WINAPI* FindWindowW_t)(LPCWSTR, LPCWSTR);
typedef HWND(WINAPI* FindWindowExW_t)(HWND, HWND, LPCWSTR, LPCWSTR);

// Глобальные указатели на оригинальные функции
extern FindWindowW_t original_FindWindowW;
extern FindWindowExW_t original_FindWindowExW;

// Функции хуков
HWND WINAPI hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName);
HWND WINAPI hook_FindWindowExW(HWND hwndParent, HWND hwndChildAfter,
                               LPCWSTR lpClassName, LPCWSTR lpWindowName);

#endif // WINDOW_HOOKS_H