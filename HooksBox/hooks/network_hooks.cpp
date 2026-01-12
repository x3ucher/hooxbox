#include "network_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include "../config.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


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

IPHLPAPI_DLL_LINKAGE ULONG WINAPI hook_GetAdaptersInfo(
    PIP_ADAPTER_INFO pAdapterInfo,
    PULONG pOutBufLen
) {
    if (!original_GetAdaptersInfo) {
        return ERROR_INVALID_FUNCTION;
    }

    ULONG result = original_GetAdaptersInfo(pAdapterInfo, pOutBufLen);

    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (!pAdapterInfo) {
        return result;
    }

    PIP_ADAPTER_INFO current = pAdapterInfo;
    PIP_ADAPTER_INFO prev = nullptr;

    while (current) {
        if (IsVirtualBoxMAC(current->Address, current->AddressLength)) {
            MaskMACAddress(current->Address, current->AddressLength);
            std::string description(current->Description);
            std::transform(description.begin(), description.end(), description.begin(), ::tolower);

            if (description.find("virtualbox") != std::string::npos ||
                description.find("vbox") != std::string::npos) {
                strncpy_s(current->Description, sizeof(current->Description),
                    "Microsoft Network Adapter", _TRUNCATE);
            }
        }
        current = current->Next;
    }
    return result;
}

IPHLPAPI_DLL_LINKAGE ULONG WINAPI hook_GetAdaptersAddresses(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer
) {
    if (!original_GetAdaptersAddresses) {
        return ERROR_INVALID_FUNCTION;
    }

    ULONG result = original_GetAdaptersAddresses(
        Family, Flags, Reserved, AdapterAddresses, SizePointer
    );

    if (result != ERROR_SUCCESS) {
        return result;
    }

    if (!AdapterAddresses) {
        return result;
    }

    PIP_ADAPTER_ADDRESSES current = AdapterAddresses;

    while (current) {
        if (IsVirtualBoxMAC(current->PhysicalAddress, current->PhysicalAddressLength)) {
            MaskMACAddress(current->PhysicalAddress, current->PhysicalAddressLength);
            if (current->FriendlyName) {
                std::string friendlyName(current->FriendlyName);
                std::transform(friendlyName.begin(), friendlyName.end(), friendlyName.begin(), ::tolower);

                if (friendlyName.find("virtualbox") != std::string::npos ||
                    friendlyName.find("vbox") != std::string::npos) {
                    if (Flags & GAA_FLAG_INCLUDE_PREFIX) {
                        wcscpy_s(current->FriendlyName, wcslen(current->FriendlyName) + 1,
                            L"Microsoft Hyper-V Virtual Ethernet Adapter");
                    }
                }
            }

            if (current->Description) {
                std::string description(current->Description);
                std::transform(description.begin(), description.end(), description.begin(), ::tolower);

                if (description.find("virtualbox") != std::string::npos ||
                    description.find("vbox") != std::string::npos) {
                    strcpy_s(current->Description, strlen(current->Description) + 1,
                        "Microsoft Hyper-V Virtual Ethernet Adapter");
                }
            }

            if (current->AdapterName) {
                std::string adapterName(current->AdapterName);
                std::transform(adapterName.begin(), adapterName.end(), adapterName.begin(), ::tolower);

                if (adapterName.find("virtualbox") != std::string::npos ||
                    adapterName.find("vbox") != std::string::npos) {
                    strcpy_s(current->AdapterName, strlen(current->AdapterName) + 1,
                        "Hyper-V Virtual Ethernet Adapter");
                }
            }
        }

        if (current->DnsSuffix) {
            std::string dnsSuffix(current->DnsSuffix);
            std::transform(dnsSuffix.begin(), dnsSuffix.end(), dnsSuffix.begin(), ::tolower);

            if (dnsSuffix.find("virtualbox") != std::string::npos ||
                dnsSuffix.find("vbox") != std::string::npos) {
                strcpy_s(current->DnsSuffix, strlen(current->DnsSuffix) + 1, "");
            }
        }

        current = current->Next;
    }

    return result;
}