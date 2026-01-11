#ifndef PROCESSES_HOOKS_H
#define PROCESSES_HOOKS_H

#include <windows.h>
#include <tlhelp32.h>

typedef BOOL(WINAPI* Process32FirstW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL(WINAPI* Process32NextW_t)(HANDLE, LPPROCESSENTRY32W);

extern Process32FirstW_t original_Process32FirstW;
extern Process32NextW_t original_Process32NextW;

// Функции хуков
BOOL WINAPI hook_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL WINAPI hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

#endif // PROCESSES_HOOKS_H