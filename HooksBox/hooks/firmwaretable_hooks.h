#ifndef FIRMWARETABLE_HOOKS_H
#define FIRMWARETABLE_HOOKS_H

#include <windows.h>

typedef DWORD(WINAPI* GetSystemFirmwareTable_t)(DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize);

typedef DWORD(WINAPI* EnumSystemFirmwareTables_t)(DWORD FirmwareTableProviderSignature,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize);

extern GetSystemFirmwareTable_t original_GetSystemFirmwareTable;
extern EnumSystemFirmwareTables_t original_EnumSystemFirmwareTables;

DWORD WINAPI hook_GetSystemFirmwareTable(
    DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
);

DWORD WINAPI hook_EnumSystemFirmwareTables(
    DWORD FirmwareTableProviderSignature,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
);

// Добавим forward-декларации структур
struct FakeAcpiTable;
struct FakeSmbiosTable;

// Объявления функций
FakeAcpiTable CreateFakeAcpiTable();
FakeSmbiosTable CreateFakeSmbiosTable();

#endif // FIRMWARETABLE_HOOKS_H