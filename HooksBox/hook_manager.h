#ifndef HOOK_MANAGER_H
#define HOOK_MANAGER_H

#include <windows.h>


// Инициализация всех хуков
bool InitializeHooks();

// Очистка хуков
void CleanupHooks();

// 
bool InitializeRegistryHooks();
bool InitializeFileHooks();
bool InitializeDeviceHooks();
bool InitializeProcessHooks();

#endif // HOOK_MANAGER_H