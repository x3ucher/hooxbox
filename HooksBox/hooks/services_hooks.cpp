#include "services_hooks.h"
#include "log_utils.h"
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

EnumServicesStatusExW_t original_EnumServicesStatusExW = nullptr;

static const wchar_t* const kVMServices[] = {
    L"VBoxWddm",   L"VBoxSF",      L"VBoxMouse",
    L"VBoxGuest",  L"VBoxService", L"VBoxVideo",
    L"vmci",       L"vmhgfs",      L"vmmouse",
    L"vmmemctl",   L"vmusb",       L"vmusbmouse",
    L"vmx_svga",   L"vmxnet",      L"vmx86",
};
static const ULONG kVMServicesCount =
    sizeof(kVMServices) / sizeof(kVMServices[0]);

static bool IsVMServiceName(LPCWSTR name)
{
    if (!name) return false;
    for (ULONG i = 0; i < kVMServicesCount; ++i)
        if (StrCmpIW(name, kVMServices[i]) == 0)
            return true;
    return false;
}

BOOL WINAPI hook_EnumServicesStatusExW(
    SC_HANDLE       hSCManager,
    SC_ENUM_TYPE    InfoLevel,
    DWORD           dwServiceType,
    DWORD           dwServiceState,
    LPBYTE          lpServices,
    DWORD           cbBufSize,
    LPDWORD         pcbBytesNeeded,
    LPDWORD         lpServicesReturned,
    LPDWORD         lpResumeHandle,
    LPCWSTR         pszGroupName)
{
    if (!original_EnumServicesStatusExW)
        return FALSE;

    BOOL ok = original_EnumServicesStatusExW(
        hSCManager, InfoLevel, dwServiceType, dwServiceState,
        lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned,
        lpResumeHandle, pszGroupName);

    if (!ok || InfoLevel != SC_ENUM_PROCESS_INFO ||
        !lpServices || !lpServicesReturned || *lpServicesReturned == 0)
        return ok;

    auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(lpServices);
    DWORD count = *lpServicesReturned;
    DWORD masked = 0;
    for (DWORD i = 0; i < count; ++i)
    {
        if (IsVMServiceName(services[i].lpServiceName))
        {
            // Mutate the first character so case-insensitive equality
            // to any known VM-driver name breaks.  The string is in the
            // caller's buffer — safe to write.
            services[i].lpServiceName[0] = L'_';
            ++masked;
        }
    }
    if (masked)
    {
        char buf[80];
        sprintf_s(buf, "[SERVICES_HOOK] masked %lu VM service name(s)", masked);
        DebugPrint(buf);
    }
    return ok;
}
