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

#endif // HOOK_MANAGER_H