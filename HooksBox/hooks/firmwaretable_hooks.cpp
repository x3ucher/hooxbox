#include "firmwaretable_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"

GetSystemFirmwareTable_t original_GetSystemFirmwareTable = nullptr;
EnumSystemFirmwareTables_t original_EnumSystemFirmwareTables = nullptr;

DWORD WINAPI hook_GetSystemFirmwareTable(
    DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
) {
    if (FirmwareTableProviderSignature != 'ACPI' || FirmwareTableID != 0x12345678) {
        return original_GetSystemFirmwareTable(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    }

    static FakeAcpiTable fakeTable;
    DWORD requiredSize = sizeof(FakeAcpiTable);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy(pFirmwareTableBuffer, &fakeTable, sizeof(FakeAcpiTable));
    return requiredSize;
}

DWORD WINAPI hook_EnumSystemFirmwareTables(
    DWORD FirmwareTableProviderSignature,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
) {
    if (FirmwareTableProviderSignature != 'ACPI') {
        return original_EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);
    }

    DWORD tableId = 0x12345678;
    DWORD requiredSize = sizeof(DWORD);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy(pFirmwareTableBuffer, &tableId, sizeof(DWORD));
    return requiredSize;
}
