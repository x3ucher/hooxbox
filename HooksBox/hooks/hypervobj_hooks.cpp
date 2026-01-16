#include "hypervobj_hooks.h"
#include "log_utils.h"
#include <vector>
#include <string>
#include <algorithm>
#include <cwchar>

NtQueryDirectoryObject_t original_NtQueryDirectoryObject = nullptr;
NtOpenDirectoryObject_t original_NtOpenDirectoryObject = nullptr;

NTSTATUS NTAPI hook_NtQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnedLength
) {
    NTSTATUS status = original_NtQueryDirectoryObject(
        DirectoryHandle, Buffer, BufferLength,
        ReturnSingleEntry, RestartScan, Context, ReturnedLength
    );

    if (status >= 0 && Buffer && ReturnedLength && *ReturnedLength > 0) {
        PBYTE currentBuffer = (PBYTE)Buffer;
        ULONG bytesProcessed = 0;

        while (bytesProcessed < *ReturnedLength) {
            POBJECT_DIRECTORY_INFORMATION current = (POBJECT_DIRECTORY_INFORMATION)currentBuffer;

            if (current->Name.Buffer == nullptr || current->Name.Length == 0) {
                break;
            }

            std::wstring name(current->Name.Buffer, current->Name.Length / sizeof(wchar_t));
            bool shouldHide = false;

            if (name.find(L"VMBUS") != std::wstring::npos ||
                name.find(L"VDRVROOT") != std::wstring::npos ||
                name.find(L"VmGenerationCounter") != std::wstring::npos ||
                name.find(L"VmGid") != std::wstring::npos ||
                name.find(L"VPCI") != std::wstring::npos ||
                name.find(L"VID") != std::wstring::npos ||
                name.find(L"HvSocket") != std::wstring::npos ||
                name.find(L"Hyper-V") != std::wstring::npos) {
                shouldHide = true;
            }

            std::wstring lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            if (lowerName.find(L"vbox") != std::wstring::npos ||
                lowerName.find(L"virtualbox") != std::wstring::npos ||
                lowerName.find(L"vbx") != std::wstring::npos ||
                name.find(L"VBox") != std::wstring::npos) {
                shouldHide = true;
            }

            if (shouldHide) {
                current->Name.Length = 0;
                current->Name.MaximumLength = 0;

                current->TypeName.Length = 0;
                current->TypeName.MaximumLength = 0;
            }
            ULONG entrySize = sizeof(OBJECT_DIRECTORY_INFORMATION);
            entrySize = (entrySize + 7) & ~7; 

            currentBuffer += entrySize;
            bytesProcessed += entrySize;

            if (entrySize == 0) break;
        }
    }

    return status;
}

NTSTATUS NTAPI hook_NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    return original_NtOpenDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
}