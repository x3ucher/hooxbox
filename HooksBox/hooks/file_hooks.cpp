#include "file_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <string>
#include <map>

GetFileAttributesW_t original_GetFileAttributesW = nullptr;
GetFileAttributesA_t original_GetFileAttributesA = nullptr;

DWORD WINAPI hook_GetFileAttributesW(
    LPCWSTR lpFileName
) {
    if (IsVBoxFilePath(lpFileName)) {
        DebugPrint("[HOOK_DLL] BLOCKED (W): VirtualBox file probe denied");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return original_GetFileAttributesW(lpFileName);
}

// ANSI mirror. Pafish vbox_sysfile1/2 and gensandbox_common_names call
// GetFileAttributesA via pafish_exists_file; without this hook every
// driver-file probe goes through to the real filesystem.
DWORD WINAPI hook_GetFileAttributesA(
    LPCSTR lpFileName
) {
    if (IsVBoxFilePathA(lpFileName)) {
        DebugPrint("[HOOK_DLL] BLOCKED (A): VirtualBox file probe denied");
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return original_GetFileAttributesA(lpFileName);
}
