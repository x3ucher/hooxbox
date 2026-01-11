#include "network_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"

WNetGetProviderNameW_t original_WNetGetProviderNameW = nullptr;
GetAdaptersInfo_t original_GetAdaptersInfo = nullptr;

DWORD WINAPI hook_WNetGetProviderNameW(DWORD dwNetType, LPWSTR lpProviderName, LPDWORD lpBufferSize) {
    DWORD result = original_WNetGetProviderNameW(dwNetType, lpProviderName, lpBufferSize);
    if (result == NO_ERROR && lpProviderName && lpBufferSize && *lpBufferSize > 0) {
        std::wstring providerName(lpProviderName);
        if (EqualsCaseInsensitive(providerName, VIRTUALBOX_PROVIDER_NAME)) {
            return ERROR_NO_NETWORK;
        }
    }
    return result;
}

IPHLPAPI_DLL_LINKAGE ULONG hook_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);