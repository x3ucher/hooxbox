#ifndef OBJECT_INFO_HOOKS_H
#define OBJECT_INFO_HOOKS_H

#include <windows.h>

typedef LONG /*NTSTATUS*/ (NTAPI* NtQueryObject_t)(
    HANDLE  Handle,
    ULONG   ObjectInformationClass,
    PVOID   ObjectInformation,
    ULONG   ObjectInformationLength,
    PULONG  ReturnLength);

extern NtQueryObject_t original_NtQueryObject;

LONG NTAPI hook_NtQueryObject(
    HANDLE  Handle,
    ULONG   ObjectInformationClass,
    PVOID   ObjectInformation,
    ULONG   ObjectInformationLength,
    PULONG  ReturnLength);

#endif // OBJECT_INFO_HOOKS_H
