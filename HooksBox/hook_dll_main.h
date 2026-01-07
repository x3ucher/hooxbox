#ifndef HOOK_DLL_MAIN_H
#define HOOK_DLL_MAIN_H

#include <windows.h>

// Точка входа DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// Экспортируемая функция для ручной инициализации
extern "C" __declspec(dllexport) void InitializeMyHooks();

#endif // HOOK_DLL_MAIN_H