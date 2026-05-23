#ifndef INPUT_HOOKS_H
#define INPUT_HOOKS_H

#include <windows.h>

typedef BOOL(WINAPI* GetLastInputInfo_t)(PLASTINPUTINFO);

extern GetLastInputInfo_t original_GetLastInputInfo;

BOOL WINAPI hook_GetLastInputInfo(PLASTINPUTINFO plii);

#endif // INPUT_HOOKS_H
