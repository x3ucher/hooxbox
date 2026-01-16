#include "system_hooks.h"
#include "log_utils.h"
#include "vbox_filters.h"
#include <vector>
#include <string>
#include <algorithm>

SetupDiEnumDeviceInfo_t original_SetupDiEnumDeviceInfo = nullptr;
static std::vector<DWORD> g_hiddenDeviceIndices;

void GatherVirtualDevices(HDEVINFO hDevInfo) {
    g_hiddenDeviceIndices.clear();

    SP_DEVINFO_DATA DeviceInfoData;
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; ; i++) {
        if (!original_SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData)) {
            break;
        }

        if (IsVirtualDevice(hDevInfo, DeviceInfoData)) {
            g_hiddenDeviceIndices.push_back(i);
        }
    }
}

bool ShouldSkipDevice(DWORD index) {
    return std::find(g_hiddenDeviceIndices.begin(),
        g_hiddenDeviceIndices.end(), index) != g_hiddenDeviceIndices.end();
}

BOOL WINAPI hook_SetupDiEnumDeviceInfo(
    HDEVINFO         DeviceInfoSet,
    DWORD            MemberIndex,
    PSP_DEVINFO_DATA DeviceInfoData
) {
    static bool initialized = false;
    static HDEVINFO lastDevInfoSet = NULL;

    if (!initialized || lastDevInfoSet != DeviceInfoSet) {
        SP_DEVINFO_DATA tempData;
        tempData.cbSize = sizeof(SP_DEVINFO_DATA);
        DWORD realCount = 0;

        while (original_SetupDiEnumDeviceInfo(DeviceInfoSet, realCount, &tempData)) {
            realCount++;
        }

        GatherVirtualDevices(DeviceInfoSet);

        initialized = true;
        lastDevInfoSet = DeviceInfoSet;
    }

    DWORD currentIndex = MemberIndex;
    DWORD attempts = 0;
    const DWORD MAX_ATTEMPTS = 100; // Защита от бесконечного цикла

    while (attempts++ < MAX_ATTEMPTS) {
        DWORD realIndex = currentIndex;
        DWORD hiddenBefore = 0;

        for (DWORD hiddenIdx : g_hiddenDeviceIndices) {
            if (hiddenIdx <= realIndex + hiddenBefore) {
                hiddenBefore++;
            }
        }

        realIndex += hiddenBefore;

        BOOL result = original_SetupDiEnumDeviceInfo(DeviceInfoSet, realIndex, DeviceInfoData);

        if (!result) {
            return FALSE;
        }

        if (!IsVirtualDevice(DeviceInfoSet, *DeviceInfoData)) {
            return TRUE;
        }

        // Нашли виртуальное устройство - добавляем в скрытые и пробуем следующий
        if (std::find(g_hiddenDeviceIndices.begin(), g_hiddenDeviceIndices.end(), realIndex)
            == g_hiddenDeviceIndices.end()) {
            g_hiddenDeviceIndices.push_back(realIndex);
            std::sort(g_hiddenDeviceIndices.begin(), g_hiddenDeviceIndices.end());
        }

        currentIndex++;
    }

    SetLastError(ERROR_NO_MORE_ITEMS);
    return FALSE;
}