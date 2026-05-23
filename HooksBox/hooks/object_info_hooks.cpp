#include "object_info_hooks.h"
#include "log_utils.h"
#include <cstring>

NtQueryObject_t original_NtQueryObject = nullptr;

// OBJECT_INFORMATION_CLASS we care about.  Class 3 returns one
// OBJECT_ALL_INFORMATION header followed by an array of
// OBJECT_TYPE_INFORMATION records, each describing one object type the
// kernel knows about — including "DebugObject" (created when a process is
// being debugged via the kernel debug port).  al-khaser walks the array
// looking for "DebugObject" with TotalNumberOfObjects > 0.
constexpr ULONG kObjectAllTypesInformation = 3;

// Layouts mirrored from winternl.h / ProcessHacker.  We don't pull
// winternl.h in to avoid Windows header surface drift.
struct UnicodeStringLocal {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
};

struct ObjectTypeInformationLocal {
    UnicodeStringLocal TypeName;
    ULONG  TotalNumberOfObjects;
    ULONG  TotalNumberOfHandles;
    ULONG  TotalPagedPoolUsage;
    ULONG  TotalNonPagedPoolUsage;
    ULONG  TotalNamePoolUsage;
    ULONG  TotalHandleTableUsage;
    ULONG  HighWaterNumberOfObjects;
    ULONG  HighWaterNumberOfHandles;
    ULONG  HighWaterPagedPoolUsage;
    ULONG  HighWaterNonPagedPoolUsage;
    ULONG  HighWaterNamePoolUsage;
    ULONG  HighWaterHandleTableUsage;
    ULONG  InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG  ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR  TypeIndex;
    CHAR   ReservedByte;
    ULONG  PoolType;
    ULONG  DefaultPagedPoolCharge;
    ULONG  DefaultNonPagedPoolCharge;
};

struct ObjectAllInformationLocal {
    ULONG  NumberOfObjects;
    ObjectTypeInformationLocal ObjectTypeInformation[1];
};

LONG NTAPI hook_NtQueryObject(
    HANDLE  Handle,
    ULONG   ObjectInformationClass,
    PVOID   ObjectInformation,
    ULONG   ObjectInformationLength,
    PULONG  ReturnLength)
{
    LONG status = original_NtQueryObject(
        Handle, ObjectInformationClass,
        ObjectInformation, ObjectInformationLength, ReturnLength);

    if (status != 0 ||
        ObjectInformationClass != kObjectAllTypesInformation ||
        !ObjectInformation ||
        ObjectInformationLength < sizeof(ObjectAllInformationLocal)) {
        return status;
    }

    // Walk the variable-length array of OBJECT_TYPE_INFORMATION records.
    // Layout: ULONG NumberOfObjects, then records packed back-to-back.
    // Each record's TypeName.Buffer points into the same allocation,
    // immediately after the record (aligned to sizeof(void*)).
    auto* all = static_cast<ObjectAllInformationLocal*>(ObjectInformation);
    ULONG count = all->NumberOfObjects;
    auto* p = reinterpret_cast<UCHAR*>(&all->ObjectTypeInformation[0]);
    UCHAR* bufEnd = static_cast<UCHAR*>(ObjectInformation) + ObjectInformationLength;

    for (ULONG i = 0; i < count; ++i) {
        if (p + sizeof(ObjectTypeInformationLocal) > bufEnd) break;
        auto* rec = reinterpret_cast<ObjectTypeInformationLocal*>(p);

        if (rec->TypeName.Buffer &&
            rec->TypeName.Length >= sizeof(L"DebugObject") - sizeof(WCHAR)) {
            // Compare without including the trailing NUL — TypeName.Buffer
            // is not always NUL-terminated.
            if (wcsncmp(rec->TypeName.Buffer, L"DebugObject", 11) == 0 &&
                rec->TypeName.Length == 11 * sizeof(WCHAR)) {
                rec->TotalNumberOfObjects = 0;
                rec->TotalNumberOfHandles = 0;
                DebugPrint("[OBJINFO_HOOK] Masked DebugObject TotalNumberOfObjects=0");
                // No need to continue iterating — DebugObject only appears
                // once.
                break;
            }
        }

        // Advance past the record + its inline name buffer to the next
        // ObjectTypeInformation.  Pointer math mirrors al-khaser's
        // traversal (line 70-82 of NtQueryObject_AllTypesInformation.cpp).
        auto* nameEnd = reinterpret_cast<UCHAR*>(rec->TypeName.Buffer) + rec->TypeName.MaximumLength;
        // Align up to sizeof(void*) (8 on x64).
        ULONG_PTR aligned = reinterpret_cast<ULONG_PTR>(nameEnd);
        aligned = (aligned + (sizeof(void*) - 1)) & ~(sizeof(void*) - 1);
        p = reinterpret_cast<UCHAR*>(aligned);
    }

    return status;
}
