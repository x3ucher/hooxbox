#ifndef FILE_HOOKS_H
#define FILE_HOOKS_H

#include <windows.h>

typedef DWORD(WINAPI* GetFileAttributesW_t)(LPCWSTR);
typedef DWORD(WINAPI* GetFileAttributesA_t)(LPCSTR);

extern GetFileAttributesW_t original_GetFileAttributesW;
extern GetFileAttributesA_t original_GetFileAttributesA;

DWORD WINAPI hook_GetFileAttributesW(LPCWSTR lpFileName);
DWORD WINAPI hook_GetFileAttributesA(LPCSTR lpFileName);

#endif // FILE_HOOKS_H
