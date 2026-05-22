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
        // Pass-through + two-stage post-process:
        //   1. Scrub any "VirtualBox" / "VBOX" / "vbox" byte-strings in
        //      the real SMBIOS in place.
        //   2. Inflate the table count by appending empty Type-40
        //      structures right before the End-Of-Table marker.  VBox
        //      guests ship with ~6-8 SMBIOS tables, which trips
        //      al-khaser-style `number_SMBIOS_tables` thresholds; this
        //      pushes the count comfortably above any reasonable cutoff.
        DebugPrint("[FIRMWARE_HOOK] SMBIOS: passing through + scrubbing + inflating");
        DWORD result = original_GetSystemFirmwareTable(
            FirmwareTableProviderSignature,
            FirmwareTableID,
            pFirmwareTableBuffer,
            BufferSize);

        if (result > 0 && pFirmwareTableBuffer != NULL && result <= BufferSize) {
            BYTE* buf = static_cast<BYTE*>(pFirmwareTableBuffer);

            FilterVirtualBoxStrings(buf, result);

            // ---- inflate table count ----
            // SMBIOS layout: RawSMBIOSData header (8 bytes), then
            // TableData of length = *(DWORD*)(buf+4).  Each structure
            // is header(4) + formatted area(length-4) + strings section
            // terminated by a double-null.  Type 127 marks end-of-table.
            const int kTargetMinTables = 12;
            DWORD tableDataLen = *reinterpret_cast<DWORD*>(buf + 4);
            if (8 + tableDataLen > result) tableDataLen = result - 8;

            BYTE* tableBegin = buf + 8;
            BYTE* tableEnd   = tableBegin + tableDataLen;

            // Locate the end-of-table marker (type 127).  Count
            // real tables encountered along the way.
            BYTE* p          = tableBegin;
            BYTE* endMarker  = NULL;
            int   realCount  = 0;
            while (p + 4 <= tableEnd) {
                BYTE type = p[0];
                BYTE len  = p[1];
                if (len < 4 || p + len > tableEnd) break;
                BYTE* s = p + len;
                while (s + 1 < tableEnd && !(s[0] == 0 && s[1] == 0)) ++s;
                if (s + 1 >= tableEnd) break;
                if (type == 127) { endMarker = p; break; }
                ++realCount;
                p = s + 2;
            }

            if (endMarker && realCount < kTargetMinTables) {
                // Each dummy: 4-byte header (type=40 "Additional Information"
                // is benign and rarely consulted) + 2-byte string-section
                // terminator (\0\0) = 6 bytes.
                int   need      = kTargetMinTables - realCount;
                DWORD growBytes = static_cast<DWORD>(need * 6);

                // Make sure caller-supplied buffer can hold the extra bytes.
                if (result + growBytes <= BufferSize) {
                    // Shift the end-of-table forward to free room.
                    DWORD tailBytes = static_cast<DWORD>(
                        (buf + result) - endMarker);
                    memmove(endMarker + growBytes, endMarker, tailBytes);

                    BYTE* w = endMarker;
                    for (int i = 0; i < need; ++i) {
                        w[0] = 40;             // SMBIOS type 40
                        w[1] = 4;              // formatted-area length = 4 (header only)
                        WORD handle = 0xA000 + i;
                        w[2] = (BYTE)(handle & 0xFF);
                        w[3] = (BYTE)(handle >> 8);
                        w[4] = 0;              // empty strings section
                        w[5] = 0;
                        w += 6;
                    }

                    result += growBytes;
                    *reinterpret_cast<DWORD*>(buf + 4) =
                        tableDataLen + growBytes;
                    DebugPrint("[FIRMWARE_HOOK] SMBIOS: inflated table count");
                }
            }
        }
        return result;
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
    static FakeAcpiTable fakeTable;
    static bool initialized = false;

    if (!initialized) {
        const char* signature = "RSD ";
        const size_t sigLen = strlen(signature);
        if (sigLen < sizeof(fakeTable.signature)) {
            strcpy_s(fakeTable.signature, sizeof(fakeTable.signature), signature);
        }
        else {
            memcpy_s(fakeTable.signature, sizeof(fakeTable.signature), signature, sizeof(fakeTable.signature) - 1);
            fakeTable.signature[sizeof(fakeTable.signature) - 1] = 0;
        }

        const char* oemid = "AWARE ";
        const size_t oemidLen = strlen(oemid);
        if (oemidLen < sizeof(fakeTable.oemid)) {
            strcpy_s(fakeTable.oemid, sizeof(fakeTable.oemid), oemid);
        }
        else {
            memcpy_s(fakeTable.oemid, sizeof(fakeTable.oemid), oemid, sizeof(fakeTable.oemid) - 1);
            fakeTable.oemid[sizeof(fakeTable.oemid) - 1] = 0;
        }

        const char* oemtableid = "GENUINE ";
        const size_t oemtableidLen = strlen(oemtableid);
        if (oemtableidLen < sizeof(fakeTable.oemtableid)) {
            strcpy_s(fakeTable.oemtableid, sizeof(fakeTable.oemtableid), oemtableid);
        }
        else {
            memcpy_s(fakeTable.oemtableid, sizeof(fakeTable.oemtableid), oemtableid, sizeof(fakeTable.oemtableid) - 1);
            fakeTable.oemtableid[sizeof(fakeTable.oemtableid) - 1] = 0;
        }

        BYTE sum = 0;
        BYTE* ptr = reinterpret_cast<BYTE*>(&fakeTable);
        for (size_t i = 0; i < sizeof(FakeAcpiTable); i++) {
            sum += ptr[i];
        }
        fakeTable.checksum = (BYTE)(0x100 - sum);

        initialized = true;
    }

    DWORD requiredSize = sizeof(FakeAcpiTable);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy_s(pFirmwareTableBuffer, BufferSize, &fakeTable, requiredSize);
    return requiredSize;
}

static DWORD HandleSmbiosRequest(DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    if (FirmwareTableID == 0x0000) {
#pragma pack(push, 1)
        struct RawSMBIOSData {
            BYTE method;
            BYTE mjVer;
            BYTE mnVer;
            BYTE dmiRev;
            DWORD length;
            BYTE tableData[1];
        };
#pragma pack(pop)

        struct SmbiosTableHeader {
            BYTE type;
            BYTE length;
            WORD handle;
        };

        struct BiosInfoTable {
            SmbiosTableHeader header;
            BYTE vendor;
            BYTE version;
            WORD startSegment;
            BYTE releaseDate;
            BYTE romSize;
            BYTE characteristics[8];
            BYTE characteristicsExt[2];
            BYTE majorVersion;
            BYTE minorVersion;
            BYTE ecMajorVersion;
            BYTE ecMinorVersion;
        };

        struct EndOfTable {
            SmbiosTableHeader header;
        };

        BiosInfoTable biosTable = {};
        biosTable.header.type = 0;
        biosTable.header.length = sizeof(BiosInfoTable);
        biosTable.header.handle = 0x0000;
        biosTable.vendor = 1;           
        biosTable.version = 2;          
        biosTable.startSegment = 0xF000;
        biosTable.releaseDate = 3;      
        biosTable.romSize = 0x78;       
        biosTable.majorVersion = 2;
        biosTable.minorVersion = 7;

        EndOfTable endTable = {};
        endTable.header.type = 127;
        endTable.header.length = sizeof(EndOfTable);
        endTable.header.handle = 0x0001;

        const char* strings = "American Megatrends Inc.\0" "2.7\0" "01/01/2020\0\0";

        DWORD tableSize = sizeof(biosTable) + strlen(strings) + 1 + sizeof(endTable) + 2;
        DWORD totalSize = 8 + tableSize;

        if (pFirmwareTableBuffer == NULL) {
            return totalSize;
        }

        if (BufferSize < totalSize) {
            return totalSize;
        }

        RawSMBIOSData* pData = static_cast<RawSMBIOSData*>(pFirmwareTableBuffer);
        pData->method = 0;
        pData->mjVer = 2;
        pData->mnVer = 7;
        pData->dmiRev = 0;
        pData->length = tableSize;

        BYTE* ptr = pData->tableData;
        memcpy(ptr, &biosTable, sizeof(biosTable));
        ptr += sizeof(biosTable);

        memcpy(ptr, strings, strlen(strings) + 1);
        ptr += strlen(strings) + 1;

        memcpy(ptr, &endTable, sizeof(endTable));
        ptr += sizeof(endTable);

        *ptr++ = 0;
        *ptr++ = 0;

        return totalSize;
    }
    else {
        return 0;
    }
}

static DWORD EnumerateAcpiTables(PVOID pFirmwareTableBuffer, DWORD BufferSize) {
    DWORD tableIds[] = {
        0x52534420,  // 'RSD ' little-endian
        0x46414350,  // 'PCAF' little-endian
        0x57534D54,  // 'TMSW' little-endian
        0x54445344,  // 'DSDT' little-endian
        0x50434146,  // 'FACP' little-endian
        0x54445353   // 'SSDT' little-endian
    };

    DWORD requiredSize = sizeof(tableIds);

    if (pFirmwareTableBuffer == NULL) {
        return requiredSize;
    }

    if (BufferSize < requiredSize) {
        return requiredSize;
    }

    memcpy(pFirmwareTableBuffer, tableIds, requiredSize);
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
    table.signature[0] = 'R';
    table.signature[1] = 'S';
    table.signature[2] = 'D';
    table.signature[3] = ' ';

    table.oemid[0] = 'A';
    table.oemid[1] = 'W';
    table.oemid[2] = 'A';
    table.oemid[3] = 'R';
    table.oemid[4] = 'E';
    table.oemid[5] = ' ';

    table.oemtableid[0] = 'G';
    table.oemtableid[1] = 'E';
    table.oemtableid[2] = 'N';
    table.oemtableid[3] = 'U';
    table.oemtableid[4] = 'I';
    table.oemtableid[5] = 'N';
    table.oemtableid[6] = 'E';
    table.oemtableid[7] = ' ';

    BYTE sum = 0;
    BYTE* ptr = reinterpret_cast<BYTE*>(&table);
    for (size_t i = 0; i < sizeof(FakeAcpiTable); i++) {
        sum += ptr[i];
    }
    table.checksum = (BYTE)(0x100 - sum);

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