#ifndef HYPERVOBJ_HOOKS_H
#define HYPERVOBJ_HOOKS_H

#include <windows.h>
#include <winternl.h> 

#ifndef _OBJECT_DIRECTORY_INFORMATION_DEFINED
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#endif

typedef NTSTATUS(NTAPI* NtOpenDirectoryObject_t)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* NtQueryDirectoryObject_t)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnedLength
    );


// #ifndef _OBJECT_DIRECTORY_INFORMATION_DEFINED
// #define _OBJECT_DIRECTORY_INFORMATION_DEFINED
// typedef struct _OBJECT_DIRECTORY_INFORMATION {
//     UNICODE_STRING Name;
//     UNICODE_STRING TypeName;
// } OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
// #endif

// Определения типов функций
extern NtQueryDirectoryObject_t original_NtQueryDirectoryObject;
extern NtOpenDirectoryObject_t original_NtOpenDirectoryObject;

// Объявления функций-хуков с NTAPI
NTSTATUS NTAPI hook_NtQueryDirectoryObject(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnedLength
);

NTSTATUS NTAPI hook_NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

#endif // HYPERVOBJ_HOOKS_H