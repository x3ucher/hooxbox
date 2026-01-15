#include "firmwaretable_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"

GetSystemFirmwareTable_t original_GetSystemFirmwareTable = nullptr;
EnumSystemFirmwareTables_t original_EnumSystemFirmwareTables = nullptr;

static DWORD HandleAcpiRequest(DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
static DWORD HandleSmbiosRequest(DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
static DWORD EnumerateAcpiTables(PVOID pFirmwareTableBuffer, DWORD BufferSize);
static DWORD EnumerateSmbiosTables(PVOID pFirmwareTableBuffer, DWORD BufferSize);

DWORD WINAPI hook_GetSystemFirmwareTable(
    DWORD FirmwareTableProviderSignature,
    DWORD FirmwareTableID,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
) {
    DebugPrint("[FIRMWARE_HOOK] GetSystemFirmwareTable called");

    if (FirmwareTableProviderSignature == 'ACPI') {
        DebugPrint("[FIRMWARE_HOOK] Handling ACPI request");
        return HandleAcpiRequest(FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    }
    else if (FirmwareTableProviderSignature == 'RSMB' || FirmwareTableProviderSignature == 0x52534D42) {
        DebugPrint("[FIRMWARE_HOOK] Handling SMBIOS request");
        return HandleSmbiosRequest(FirmwareTableID, pFirmwareTableBuffer, BufferSize);
    }
    else if (FirmwareTableProviderSignature == 'FIRM' || FirmwareTableProviderSignature == 'RAW ') {
        DebugPrint("[FIRMWARE_HOOK] Passing through to original for signature");
        DWORD result = original_GetSystemFirmwareTable(
            FirmwareTableProviderSignature,
            FirmwareTableID,
            pFirmwareTableBuffer,
            BufferSize
        );

        if (result > 0 && pFirmwareTableBuffer != NULL) {
            DebugPrint("[FIRMWARE_HOOK] Filtering returned data, size");
            FilterVirtualBoxStrings(static_cast<BYTE*>(pFirmwareTableBuffer), result);
        }

        return result;
    }
    else {
        DebugPrint("[FIRMWARE_HOOK] Original call for signature");
        return original_GetSystemFirmwareTable(
            FirmwareTableProviderSignature,
            FirmwareTableID,
            pFirmwareTableBuffer,
            BufferSize
        );
    }
}

DWORD WINAPI hook_EnumSystemFirmwareTables(
    DWORD FirmwareTableProviderSignature,
    PVOID pFirmwareTableBuffer,
    DWORD BufferSize
) {
    DebugPrint("[FIRMWARE_HOOK] EnumSystemFirmwareTables called");

    if (FirmwareTableProviderSignature == 'ACPI') {
        DebugPrint("[FIRMWARE_HOOK] Enumerating ACPI tables");
        return EnumerateAcpiTables(pFirmwareTableBuffer, BufferSize);
    }
    else if (FirmwareTableProviderSignature == 'RSMB' || FirmwareTableProviderSignature == 0x52534D42) {
        DebugPrint("[FIRMWARE_HOOK] Enumerating SMBIOS tables");
        return EnumerateSmbiosTables(pFirmwareTableBuffer, BufferSize);
    }
    else {
        DebugPrint("[FIRMWARE_HOOK] Original enumeration for signature");
        return original_EnumSystemFirmwareTables(
            FirmwareTableProviderSignature,
            pFirmwareTableBuffer,
            BufferSize
        );
    }
}

static DWORD HandleAcpiRequest(DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    static FakeAcpiTable fakeTable = CreateFakeAcpiTable();
    DWORD requiredSize = sizeof(FakeAcpiTable);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy(pFirmwareTableBuffer, &fakeTable, requiredSize);
    return requiredSize;
}

static DWORD HandleSmbiosRequest(DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    static FakeSmbiosTable fakeTable = CreateFakeSmbiosTable();
    DWORD requiredSize = sizeof(FakeSmbiosTable);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy(pFirmwareTableBuffer, &fakeTable, requiredSize);
    return requiredSize;
}

static DWORD EnumerateAcpiTables(PVOID pFirmwareTableBuffer, DWORD BufferSize) {
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

static DWORD EnumerateSmbiosTables(PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    DWORD tableId = 0x0000;
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

FakeAcpiTable CreateFakeAcpiTable() {
    FakeAcpiTable table;
    BYTE sum = 0;
    BYTE* ptr = reinterpret_cast<BYTE*>(&table);
    for (size_t i = 0; i < sizeof(FakeAcpiTable); i++) {
        sum += ptr[i];
    }
    table.checksum = -sum; 
    return table;
}

FakeSmbiosTable CreateFakeSmbiosTable() {
    FakeSmbiosTable table;
    BYTE* ptr = reinterpret_cast<BYTE*>(&table);
    BYTE mainSum = 0;
    for (int i = 0; i < 16; i++) {
        mainSum += ptr[i];
    }

    BYTE intermediateSum = 0;
    for (int i = 16; i < 24; i++) {
        intermediateSum += ptr[i];
    }
    table.intermediateChecksum = -intermediateSum;

    return table;
}