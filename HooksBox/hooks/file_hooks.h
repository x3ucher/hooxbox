#ifndef FILE_HOOKS_H
#define FILE_HOOKS_H

#include <windows.h>

typedef LSTATUS(WINAPI* GetFileAttributesW_t)(LPCWSTR);

// Глобальные указатели на оригинальные функции
extern GetFileAttributesW_t original_GetFileAttributesW;

LSTATUS WINAPI hook_GetFileAttributesW(LPCWSTR lpFileName);
// LSTATUS WINAPI hook_GetFileAttributesA(LPCSTR lpFileName);


#endif // FILE_HOOKS_H
