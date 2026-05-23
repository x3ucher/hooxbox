#ifndef TIME_HOOKS_H
#define TIME_HOOKS_H

#include <windows.h>

typedef DWORD(WINAPI* GetTickCount_t)(void);
typedef ULONGLONG(WINAPI* GetTickCount64_t)(void);

extern GetTickCount_t original_GetTickCount;
extern GetTickCount64_t original_GetTickCount64;

DWORD WINAPI hook_GetTickCount(void);
ULONGLONG WINAPI hook_GetTickCount64(void);

#endif // TIME_HOOKS_H
