#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define MH_STATIC
#include "MinHook.h"

#include "wmi_hooks.h"

#include <wbemidl.h>
#include <string>

// ===========================================================================
// Logger
// ===========================================================================

static CRITICAL_SECTION s_logCs;
static LONG             s_logCsInit = 0;  // 0=uninit, 1=initing, 2=ready

static void EnsureLogCsInit()
{
    if (InterlockedCompareExchange(&s_logCsInit, 1, 0) == 0)
    {
        InitializeCriticalSection(&s_logCs);
        InterlockedExchange(&s_logCsInit, 2);
    }
    while (InterlockedCompareExchange(&s_logCsInit, 2, 2) != 2)
        Sleep(0);
}

static std::string ToUtf8(const wchar_t* wide)
{
    if (!wide || !*wide) return {};
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string s(bytes - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &s[0], bytes, nullptr, nullptr);
    return s;
}

void WmiHooks::Log(const wchar_t* level, const std::wstring& msg)
{
    EnsureLogCsInit();
    EnterCriticalSection(&s_logCs);

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t timeBuf[32];
    swprintf_s(timeBuf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond);

    std::wstring line = std::wstring(timeBuf) + L" [" + level + L"] " + msg + L"\n";
    std::string utf8 = ToUtf8(line.c_str());

    // Write UTF-8 BOM on first write to an empty file.
    static bool s_bomWritten = false;
    HANDLE hFile = CreateFileW(L"sandbox_evasion.log", GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (!s_bomWritten)
        {
            LARGE_INTEGER size = {};
            GetFileSizeEx(hFile, &size);
            if (size.QuadPart == 0)
            {
                DWORD wr = 0;
                const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
                WriteFile(hFile, bom, sizeof(bom), &wr, nullptr);
            }
            s_bomWritten = true;
        }
        SetFilePointer(hFile, 0, nullptr, FILE_END);
        DWORD wr = 0;
        WriteFile(hFile, utf8.c_str(), (DWORD)utf8.size(), &wr, nullptr);
        CloseHandle(hFile);
    }

    LeaveCriticalSection(&s_logCs);
}

// ===========================================================================
// IEnumWbemClassObject vtable layout — x64, MSVC COM ABI
//
//  slot  method
//   0    IUnknown::QueryInterface
//   1    IUnknown::AddRef
//   2    IUnknown::Release
//   3    IEnumWbemClassObject::Reset
//   4    IEnumWbemClassObject::Next          <-- hook target
//   5    IEnumWbemClassObject::NextAsync
//   6    IEnumWbemClassObject::Clone
//   7    IEnumWbemClassObject::Skip
// ===========================================================================

static const int kVtblSlot_Next = 4;

typedef HRESULT (STDMETHODCALLTYPE *FnNext)(
    IEnumWbemClassObject* pThis,
    LONG                  lTimeout,
    ULONG                 uCount,
    IWbemClassObject**    apObjects,
    ULONG*                puReturned);

static FnNext  g_pOrigNext   = nullptr;
static LPVOID  g_pNextTarget = nullptr;

// ---------------------------------------------------------------------------
// Hook_Next — detour for IEnumWbemClassObject::Next
// ---------------------------------------------------------------------------
static HRESULT STDMETHODCALLTYPE Hook_Next(
    IEnumWbemClassObject* pThis,
    LONG                  lTimeout,
    ULONG                 uCount,
    IWbemClassObject**    apObjects,
    ULONG*                puReturned)
{
    HRESULT hr = g_pOrigNext(pThis, lTimeout, uCount, apObjects, puReturned);
    ULONG returned = (puReturned ? *puReturned : 0);
    WMIHOOK_INFO(L"Next hooked, returned " + std::to_wstring(returned) + L" objects");
    return hr;
}

// ---------------------------------------------------------------------------
// HookEnumeratorNext
// ---------------------------------------------------------------------------
bool HookEnumeratorNext(IEnumWbemClassObject* pEnum)
{
    if (!pEnum)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext: pEnum is null");
        return false;
    }

    void** vtbl   = *reinterpret_cast<void***>(pEnum);
    g_pNextTarget = vtbl[kVtblSlot_Next];

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext: MH_Initialize failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        return false;
    }

    st = MH_CreateHook(g_pNextTarget,
                       reinterpret_cast<LPVOID>(&Hook_Next),
                       reinterpret_cast<LPVOID*>(&g_pOrigNext));
    if (st != MH_OK)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext: MH_CreateHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pNextTarget = nullptr;
        return false;
    }

    st = MH_EnableHook(g_pNextTarget);
    if (st != MH_OK)
    {
        MH_RemoveHook(g_pNextTarget);
        WMIHOOK_ERROR(L"HookEnumeratorNext: MH_EnableHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pNextTarget = nullptr;
        return false;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(g_pNextTarget);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(L"HookEnumeratorNext: installed at 0x" + hex);
    return true;
}

// ---------------------------------------------------------------------------
// UnhookEnumeratorNext
// ---------------------------------------------------------------------------
void UnhookEnumeratorNext()
{
    if (!g_pNextTarget) return;

    MH_DisableHook(g_pNextTarget);
    MH_RemoveHook(g_pNextTarget);
    MH_Uninitialize();

    WMIHOOK_INFO(L"UnhookEnumeratorNext: hook removed");
    g_pNextTarget = nullptr;
    g_pOrigNext   = nullptr;
}

// ===========================================================================
// PnP Name filter hook
//
// Removes WMI objects whose Name contains a known VM-indicator substring.
// When the original Next returns a batch that is entirely filtered out, the
// hook calls Next again internally so the caller's enumeration loop continues
// correctly without seeing spurious empty results mid-stream.
// ===========================================================================

static const wchar_t* kPnPNameSubstrings[] = {
    L"82801FB", L"82441FX", L"82371SB", L"OpenHCD", L"VBOX"
};
static const ULONG kPnPNameFilterCount =
    sizeof(kPnPNameSubstrings) / sizeof(kPnPNameSubstrings[0]);

// Exact DeviceID values to suppress.
static const wchar_t* kPnPDeviceIdFilters[] = {
    L"PCI\\VEN_80EE&DEV_CAFE"
};
static const ULONG kPnPDeviceIdFilterCount =
    sizeof(kPnPDeviceIdFilters) / sizeof(kPnPDeviceIdFilters[0]);

static FnNext  g_pOrigNextFilter = nullptr;
static LPVOID  g_pFilterTarget   = nullptr;

// ---------------------------------------------------------------------------
// ShouldFilterPnPObject
//
// Returns true (and sets outReason) when the object should be suppressed:
//   - Name property contains a known VM-indicator substring, OR
//   - DeviceID property exactly matches a known VM device ID.
//
// Properties absent from the result set (partial SELECT) are silently skipped.
// ---------------------------------------------------------------------------
static bool ShouldFilterPnPObject(IWbemClassObject* pObj, std::wstring& outReason)
{
    // Check Name substrings.
    VARIANT vtName;
    VariantInit(&vtName);
    if (SUCCEEDED(pObj->Get(L"Name", 0, &vtName, nullptr, nullptr)) &&
        vtName.vt == VT_BSTR && vtName.bstrVal)
    {
        std::wstring name = vtName.bstrVal;
        for (ULONG k = 0; k < kPnPNameFilterCount; ++k)
        {
            if (name.find(kPnPNameSubstrings[k]) != std::wstring::npos)
            {
                outReason = L"Name='" + name + L"'";
                VariantClear(&vtName);
                return true;
            }
        }
    }
    VariantClear(&vtName);

    // Check DeviceID exact matches.
    VARIANT vtId;
    VariantInit(&vtId);
    if (SUCCEEDED(pObj->Get(L"DeviceID", 0, &vtId, nullptr, nullptr)) &&
        vtId.vt == VT_BSTR && vtId.bstrVal)
    {
        for (ULONG k = 0; k < kPnPDeviceIdFilterCount; ++k)
        {
            if (wcsstr(vtId.bstrVal, kPnPDeviceIdFilters[k]) != nullptr)
            {
                outReason = L"DeviceID='" + std::wstring(vtId.bstrVal) + L"'";
                VariantClear(&vtId);
                return true;
            }
        }
    }
    VariantClear(&vtId);

    return false;
}

static HRESULT STDMETHODCALLTYPE Hook_Next_FilterPnP(
    IEnumWbemClassObject* pThis,
    LONG                  lTimeout,
    ULONG                 uCount,
    IWbemClassObject**    apObjects,
    ULONG*                puReturned)
{
    ULONG   out = 0;
    HRESULT hr  = S_OK;

    do {
        ULONG got = 0;
        hr = g_pOrigNextFilter(pThis, lTimeout, uCount, apObjects, &got);
        if (FAILED(hr) || got == 0)
        {
            if (puReturned) *puReturned = 0;
            return hr;
        }

        out = 0;
        for (ULONG i = 0; i < got; ++i)
        {
            IWbemClassObject* pObj = apObjects[i];
            std::wstring reason;
            if (ShouldFilterPnPObject(pObj, reason))
            {
                WMIHOOK_INFO(L"FilterPnP: skipped " + reason);
                pObj->Release();
            }
            else
            {
                apObjects[out++] = pObj;  // pack kept objects to front
            }
        }
    } while (out == 0);  // entire batch filtered — fetch next batch

    if (puReturned) *puReturned = out;
    return hr;
}

// ---------------------------------------------------------------------------
// HookEnumeratorNext_FilterPnPName
// ---------------------------------------------------------------------------
bool HookEnumeratorNext_FilterPnPName(IEnumWbemClassObject* pEnum)
{
    if (!pEnum)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext_FilterPnPName: pEnum is null");
        return false;
    }

    void** vtbl      = *reinterpret_cast<void***>(pEnum);
    g_pFilterTarget  = vtbl[kVtblSlot_Next];

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext_FilterPnPName: MH_Initialize failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        return false;
    }

    st = MH_CreateHook(g_pFilterTarget,
                       reinterpret_cast<LPVOID>(&Hook_Next_FilterPnP),
                       reinterpret_cast<LPVOID*>(&g_pOrigNextFilter));
    if (st != MH_OK)
    {
        WMIHOOK_ERROR(L"HookEnumeratorNext_FilterPnPName: MH_CreateHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pFilterTarget = nullptr;
        return false;
    }

    st = MH_EnableHook(g_pFilterTarget);
    if (st != MH_OK)
    {
        MH_RemoveHook(g_pFilterTarget);
        WMIHOOK_ERROR(L"HookEnumeratorNext_FilterPnPName: MH_EnableHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pFilterTarget = nullptr;
        return false;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(g_pFilterTarget);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(L"HookEnumeratorNext_FilterPnPName: installed at 0x" + hex);
    return true;
}

// ---------------------------------------------------------------------------
// UnhookEnumeratorNext_FilterPnPName
// ---------------------------------------------------------------------------
void UnhookEnumeratorNext_FilterPnPName()
{
    if (!g_pFilterTarget) return;

    MH_DisableHook(g_pFilterTarget);
    MH_RemoveHook(g_pFilterTarget);
    MH_Uninitialize();

    WMIHOOK_INFO(L"UnhookEnumeratorNext_FilterPnPName: hook removed");
    g_pFilterTarget   = nullptr;
    g_pOrigNextFilter = nullptr;
}

// ===========================================================================
// Win32_BaseBoard Get hook
//
// IWbemClassObject vtable layout (x64, MSVC COM ABI):
//
//  slot  method
//   0    IUnknown::QueryInterface
//   1    IUnknown::AddRef
//   2    IUnknown::Release
//   3    IWbemClassObject::GetQualifierSet
//   4    IWbemClassObject::Get              <-- hook target
//   5    IWbemClassObject::Put
//   ...
//
// The hook intercepts Get and substitutes values only when __CLASS is
// "Win32_BaseBoard".  __CLASS is a WMI system property always present on
// every object regardless of which properties were SELECTed.
// The original Get is used (a) for the __CLASS check and (b) for all other
// property names, so there is no recursion.
// ===========================================================================

static const int kVtblSlot_WbemGet = 4;

typedef HRESULT (STDMETHODCALLTYPE *FnWbemGet)(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor);

static FnWbemGet  g_pOrigWbemGet   = nullptr;
static LPVOID     g_pWbemGetTarget = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_WbemGet(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor)
{
    // Determine object class via original Get — no recursion.
    bool isBaseBoard = false;
    VARIANT vtClass;
    VariantInit(&vtClass);
    if (SUCCEEDED(g_pOrigWbemGet(pThis, L"__CLASS", 0, &vtClass, nullptr, nullptr)) &&
        vtClass.vt == VT_BSTR && vtClass.bstrVal)
    {
        isBaseBoard = (wcscmp(vtClass.bstrVal, L"Win32_BaseBoard") == 0);
    }
    VariantClear(&vtClass);

    if (isBaseBoard && wszName)
    {
        const wchar_t* spoof = nullptr;
        if (wcscmp(wszName, L"Product") == 0)
            spoof = L"Standard PC";
        else if (wcscmp(wszName, L"Manufacturer") == 0)
            spoof = L"Microsoft Corporation";

        if (spoof)
        {
            if (pVal)
            {
                VariantInit(pVal);
                pVal->vt      = VT_BSTR;
                pVal->bstrVal = SysAllocString(spoof);
            }
            if (pType)    *pType    = CIM_STRING;
            if (plFlavor) *plFlavor = 0;
            WMIHOOK_INFO(std::wstring(L"BaseBoardGet: spoofed ") + wszName +
                         L" -> '" + spoof + L"'");
            return S_OK;
        }
    }

    return g_pOrigWbemGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
}

// ---------------------------------------------------------------------------
// HookBaseBoardGet
// ---------------------------------------------------------------------------
bool HookBaseBoardGet(IWbemClassObject* pObj)
{
    if (!pObj)
    {
        WMIHOOK_ERROR(L"HookBaseBoardGet: pObj is null");
        return false;
    }

    void** vtbl        = *reinterpret_cast<void***>(pObj);
    g_pWbemGetTarget   = vtbl[kVtblSlot_WbemGet];

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        WMIHOOK_ERROR(L"HookBaseBoardGet: MH_Initialize failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        return false;
    }

    st = MH_CreateHook(g_pWbemGetTarget,
                       reinterpret_cast<LPVOID>(&Hook_WbemGet),
                       reinterpret_cast<LPVOID*>(&g_pOrigWbemGet));
    if (st != MH_OK)
    {
        WMIHOOK_ERROR(L"HookBaseBoardGet: MH_CreateHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pWbemGetTarget = nullptr;
        return false;
    }

    st = MH_EnableHook(g_pWbemGetTarget);
    if (st != MH_OK)
    {
        MH_RemoveHook(g_pWbemGetTarget);
        WMIHOOK_ERROR(L"HookBaseBoardGet: MH_EnableHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pWbemGetTarget = nullptr;
        return false;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(g_pWbemGetTarget);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(L"HookBaseBoardGet: installed at 0x" + hex);
    return true;
}

// ---------------------------------------------------------------------------
// UnhookBaseBoardGet
// ---------------------------------------------------------------------------
void UnhookBaseBoardGet()
{
    if (!g_pWbemGetTarget) return;

    MH_DisableHook(g_pWbemGetTarget);
    MH_RemoveHook(g_pWbemGetTarget);
    MH_Uninitialize();

    WMIHOOK_INFO(L"UnhookBaseBoardGet: hook removed");
    g_pWbemGetTarget = nullptr;
    g_pOrigWbemGet   = nullptr;
}

// ===========================================================================
// Win32_Bus Get hook
//
// Intercepts IWbemClassObject::Get (same vtable slot 4) for Win32_Bus
// objects. For the "Name" property, calls the original Get first, then
// replaces the exact VM-indicator substrings so detection routines that
// search for "ACPIBus_BUS_0" / "PCI_BUS_0" / "PNP_BUS_0" find nothing.
// ===========================================================================

struct BusNameRemap { const wchar_t* from; const wchar_t* to; };

static const BusNameRemap kBusRemap[] = {
    { L"ACPIBus_BUS_0", L"ACPIBus_BUS_1" },
    { L"PCI_BUS_0",     L"PCI_BUS_1"     },
    { L"PNP_BUS_0",     L"PNP_BUS_1"     },
};
static const ULONG kBusRemapCount = sizeof(kBusRemap) / sizeof(kBusRemap[0]);

static FnWbemGet  g_pOrigBusGet   = nullptr;
static LPVOID     g_pBusGetTarget = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_BusGet(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor)
{
    // Class check via original Get — no recursion.
    bool isBus = false;
    VARIANT vtClass;
    VariantInit(&vtClass);
    if (SUCCEEDED(g_pOrigBusGet(pThis, L"__CLASS", 0, &vtClass, nullptr, nullptr)) &&
        vtClass.vt == VT_BSTR && vtClass.bstrVal)
    {
        isBus = (wcscmp(vtClass.bstrVal, L"Win32_Bus") == 0);
    }
    VariantClear(&vtClass);

    if (isBus && wszName && wcscmp(wszName, L"Name") == 0)
    {
        // Get the real Name first.
        HRESULT hr = g_pOrigBusGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
        if (SUCCEEDED(hr) && pVal && pVal->vt == VT_BSTR && pVal->bstrVal)
        {
            std::wstring name = pVal->bstrVal;
            for (ULONG k = 0; k < kBusRemapCount; ++k)
            {
                size_t pos = name.find(kBusRemap[k].from);
                if (pos != std::wstring::npos)
                {
                    name.replace(pos, wcslen(kBusRemap[k].from), kBusRemap[k].to);
                    SysFreeString(pVal->bstrVal);
                    pVal->bstrVal = SysAllocString(name.c_str());
                    WMIHOOK_INFO(std::wstring(L"BusGet: masked '") +
                                 kBusRemap[k].from + L"' -> '" + kBusRemap[k].to + L"'");
                    break;
                }
            }
        }
        return hr;
    }

    return g_pOrigBusGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
}

// ---------------------------------------------------------------------------
// HookBusGet
// ---------------------------------------------------------------------------
bool HookBusGet(IWbemClassObject* pObj)
{
    if (!pObj)
    {
        WMIHOOK_ERROR(L"HookBusGet: pObj is null");
        return false;
    }

    void** vtbl       = *reinterpret_cast<void***>(pObj);
    g_pBusGetTarget   = vtbl[kVtblSlot_WbemGet];

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        WMIHOOK_ERROR(L"HookBusGet: MH_Initialize failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        return false;
    }

    st = MH_CreateHook(g_pBusGetTarget,
                       reinterpret_cast<LPVOID>(&Hook_BusGet),
                       reinterpret_cast<LPVOID*>(&g_pOrigBusGet));
    if (st != MH_OK)
    {
        WMIHOOK_ERROR(L"HookBusGet: MH_CreateHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pBusGetTarget = nullptr;
        return false;
    }

    st = MH_EnableHook(g_pBusGetTarget);
    if (st != MH_OK)
    {
        MH_RemoveHook(g_pBusGetTarget);
        WMIHOOK_ERROR(L"HookBusGet: MH_EnableHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pBusGetTarget = nullptr;
        return false;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(g_pBusGetTarget);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(L"HookBusGet: installed at 0x" + hex);
    return true;
}

// ---------------------------------------------------------------------------
// UnhookBusGet
// ---------------------------------------------------------------------------
void UnhookBusGet()
{
    if (!g_pBusGetTarget) return;

    MH_DisableHook(g_pBusGetTarget);
    MH_RemoveHook(g_pBusGetTarget);
    MH_Uninitialize();

    WMIHOOK_INFO(L"UnhookBusGet: hook removed");
    g_pBusGetTarget = nullptr;
    g_pOrigBusGet   = nullptr;
}

// ===========================================================================
// Win32_PnPDevice Get hook
//
// Intercepts IWbemClassObject::Get (vtable slot 4) for Win32_PnPDevice
// objects. For Name, Caption, and PNPDeviceID properties, replaces
// "VEN_VBOX" with "VEN_GENERIC" and remaining "VBOX" with "Generic" so
// substring searches for those tokens find nothing.
// ===========================================================================

static std::wstring MaskVboxString(const std::wstring& s)
{
    struct { const wchar_t* f; const wchar_t* t; } patches[] = {
        { L"VEN_VBOX", L"VEN_GENERIC" },
        { L"VBOX",     L"Generic"     },
    };
    std::wstring r = s;
    for (auto& p : patches)
    {
        size_t flen = wcslen(p.f), tlen = wcslen(p.t), pos = 0;
        while ((pos = r.find(p.f, pos)) != std::wstring::npos)
        {
            r.replace(pos, flen, p.t);
            pos += tlen;
        }
    }
    return r;
}

static const wchar_t* kPnPDevPropsToMask[] = {
    L"Name", L"Caption", L"PNPDeviceID"
};
static const ULONG kPnPDevPropCount =
    sizeof(kPnPDevPropsToMask) / sizeof(kPnPDevPropsToMask[0]);

static FnWbemGet  g_pOrigPnPDevGet   = nullptr;
static LPVOID     g_pPnPDevGetTarget = nullptr;

static HRESULT STDMETHODCALLTYPE Hook_PnPDeviceGet(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor)
{
    // Class check via original Get — no recursion.
    bool isPnPDevice = false;
    VARIANT vtClass;
    VariantInit(&vtClass);
    if (SUCCEEDED(g_pOrigPnPDevGet(pThis, L"__CLASS", 0, &vtClass, nullptr, nullptr)) &&
        vtClass.vt == VT_BSTR && vtClass.bstrVal)
    {
        isPnPDevice = (wcscmp(vtClass.bstrVal, L"Win32_PnPDevice") == 0);
    }
    VariantClear(&vtClass);

    if (isPnPDevice && wszName)
    {
        bool isMaskedProp = false;
        for (ULONG k = 0; k < kPnPDevPropCount; ++k)
        {
            if (wcscmp(wszName, kPnPDevPropsToMask[k]) == 0)
            {
                isMaskedProp = true;
                break;
            }
        }

        if (isMaskedProp)
        {
            HRESULT hr = g_pOrigPnPDevGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
            if (SUCCEEDED(hr) && pVal && pVal->vt == VT_BSTR && pVal->bstrVal &&
                wcsstr(pVal->bstrVal, L"VBOX") != nullptr)
            {
                std::wstring masked = MaskVboxString(pVal->bstrVal);
                SysFreeString(pVal->bstrVal);
                pVal->bstrVal = SysAllocString(masked.c_str());
                WMIHOOK_INFO(std::wstring(L"PnPDeviceGet: masked ") + wszName +
                             L" -> '" + masked + L"'");
            }
            return hr;
        }
    }

    return g_pOrigPnPDevGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
}

// ---------------------------------------------------------------------------
// HookPnPDeviceGet
// ---------------------------------------------------------------------------
bool HookPnPDeviceGet(IWbemClassObject* pObj)
{
    if (!pObj)
    {
        WMIHOOK_ERROR(L"HookPnPDeviceGet: pObj is null");
        return false;
    }

    void** vtbl          = *reinterpret_cast<void***>(pObj);
    g_pPnPDevGetTarget   = vtbl[kVtblSlot_WbemGet];

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED)
    {
        WMIHOOK_ERROR(L"HookPnPDeviceGet: MH_Initialize failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        return false;
    }

    st = MH_CreateHook(g_pPnPDevGetTarget,
                       reinterpret_cast<LPVOID>(&Hook_PnPDeviceGet),
                       reinterpret_cast<LPVOID*>(&g_pOrigPnPDevGet));
    if (st != MH_OK)
    {
        WMIHOOK_ERROR(L"HookPnPDeviceGet: MH_CreateHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pPnPDevGetTarget = nullptr;
        return false;
    }

    st = MH_EnableHook(g_pPnPDevGetTarget);
    if (st != MH_OK)
    {
        MH_RemoveHook(g_pPnPDevGetTarget);
        WMIHOOK_ERROR(L"HookPnPDeviceGet: MH_EnableHook failed, st=" +
                      std::to_wstring(static_cast<int>(st)));
        g_pPnPDevGetTarget = nullptr;
        return false;
    }

    uintptr_t addr = reinterpret_cast<uintptr_t>(g_pPnPDevGetTarget);
    std::wstring hex(16, L'0');
    for (int i = 15; i >= 0; --i, addr >>= 4)
        hex[i] = L"0123456789ABCDEF"[addr & 0xF];
    WMIHOOK_INFO(L"HookPnPDeviceGet: installed at 0x" + hex);
    return true;
}

// ---------------------------------------------------------------------------
// UnhookPnPDeviceGet
// ---------------------------------------------------------------------------
void UnhookPnPDeviceGet()
{
    if (!g_pPnPDevGetTarget) return;

    MH_DisableHook(g_pPnPDevGetTarget);
    MH_RemoveHook(g_pPnPDevGetTarget);
    MH_Uninitialize();

    WMIHOOK_INFO(L"UnhookPnPDeviceGet: hook removed");
    g_pPnPDevGetTarget = nullptr;
    g_pOrigPnPDevGet   = nullptr;
}
