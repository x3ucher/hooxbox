#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "wmi_hooks.h"

#include <wbemidl.h>
#include <shlwapi.h>
#include <string>
#include <map>
#include <cwctype>

#pragma comment(lib, "shlwapi.lib")

namespace WmiMaskHooks {

// Globals — definitions
FnNext       g_pOrigNext       = nullptr;
FnNext       g_pOrigNextFilter = nullptr;
FnWbemGet    g_pOrigGet        = nullptr;
FnExecQuery  g_pOrigExecQuery  = nullptr;

bool g_BaseBoardEnabled       = false;
bool g_BusEnabled             = false;
bool g_PnPDeviceEnabled       = false;
bool g_BiosEnabled            = false;
bool g_ComputerSystemEnabled  = false;
bool g_VideoEnabled           = false;
bool g_ProcessorEnabled       = false;
bool g_LogicalDiskEnabled     = false;
bool g_ThermalEnabled         = false;
bool g_EventLogEnabled        = false;
bool g_NonEmptyEnabled        = false;

static const wchar_t* kCriticalClasses[] = {
    L"Win32_Fan",
    L"Win32_CacheMemory",
    L"Win32_PhysicalMemory",
    L"Win32_MemoryDevice",
    L"Win32_MemoryArray",
    L"Win32_VoltageProbe",
    L"Win32_PortConnector",
    L"Win32_SMBIOSMemory",
    L"Win32_PerfFormattedData_Counters_ThermalZoneInformation",
    L"CIM_Memory",
    L"CIM_NumericSensor",
    L"CIM_PhysicalConnector",
    L"CIM_Sensor",
    L"CIM_Slot",
    L"CIM_TemperatureSensor",
    L"CIM_VoltageSensor",
    // root\WMI namespace — same MinHook patches catch it because the
    // Next / Get / ExecQuery function bodies are shared across all
    // IWbemServices instances regardless of which namespace they bind to.
    L"MSAcpi_ThermalZoneTemperature",
};
static const ULONG kCriticalClassCount =
    sizeof(kCriticalClasses) / sizeof(kCriticalClasses[0]);

static bool IsCriticalClass(const std::wstring& cls)
{
    if (cls.empty()) return false;
    for (ULONG k = 0; k < kCriticalClassCount; ++k)
        if (_wcsicmp(cls.c_str(), kCriticalClasses[k]) == 0)
            return true;
    return false;
}

// Extracts the class name from a WQL "SELECT … FROM <class> [WHERE …]"
// string.  Case-insensitive.  Returns empty on malformed input.
static std::wstring ParseClassFromWql(BSTR wql)
{
    if (!wql) return {};
    // StrStrIW finds case-insensitive substring; look for " FROM "
    // first, fall back to "FROM " at the very start.
    const wchar_t* from = StrStrIW(wql, L" FROM ");
    if (from)
        from += 6;
    else if (_wcsnicmp(wql, L"FROM ", 5) == 0)
        from = wql + 5;
    else
        return {};

    while (*from && iswspace(*from)) ++from;
    const wchar_t* start = from;
    while (*from && (iswalnum(*from) || *from == L'_')) ++from;
    return std::wstring(start, from - start);
}

struct EnumState
{
    std::wstring cls;
    bool         hasReturnedReal = false;
    bool         injected        = false;
};

static std::map<IEnumWbemClassObject*, EnumState> s_enumStates;
static CRITICAL_SECTION                            s_enumStatesCs;
static LONG                                        s_enumStatesCsInit = 0;

static void EnsureEnumStatesCsInit()
{
    if (InterlockedCompareExchange(&s_enumStatesCsInit, 1, 0) == 0)
    {
        InitializeCriticalSection(&s_enumStatesCs);
        InterlockedExchange(&s_enumStatesCsInit, 2);
    }
    while (InterlockedCompareExchange(&s_enumStatesCsInit, 2, 2) != 2)
        Sleep(0);
}

static void RegisterCriticalEnum(IEnumWbemClassObject* pEnum, const std::wstring& cls)
{
    EnsureEnumStatesCsInit();
    EnterCriticalSection(&s_enumStatesCs);
    s_enumStates[pEnum] = EnumState{ cls, false, false };
    LeaveCriticalSection(&s_enumStatesCs);
}

// Returns the class name iff this enumerator is critical AND has not yet
// returned any real object AND has not yet been given a fake one.
// Atomically marks `injected = true` on success.
static std::wstring ClaimInjectionSlot(IEnumWbemClassObject* pEnum)
{
    if (!g_NonEmptyEnabled) return {};

    EnsureEnumStatesCsInit();
    std::wstring result;
    EnterCriticalSection(&s_enumStatesCs);
    auto it = s_enumStates.find(pEnum);
    if (it != s_enumStates.end() &&
        !it->second.hasReturnedReal &&
        !it->second.injected)
    {
        result = it->second.cls;
        it->second.injected = true;
    }
    LeaveCriticalSection(&s_enumStatesCs);
    return result;
}

// Called when Next really returned >=1 object so we never inject after
// the caller has already seen a real instance.
static void MarkEnumYieldedReal(IEnumWbemClassObject* pEnum)
{
    EnsureEnumStatesCsInit();
    EnterCriticalSection(&s_enumStatesCs);
    auto it = s_enumStates.find(pEnum);
    if (it != s_enumStates.end())
        it->second.hasReturnedReal = true;
    LeaveCriticalSection(&s_enumStatesCs);
}

class FakeWbemObject : public IWbemClassObject
{
public:
    explicit FakeWbemObject(const std::wstring& cls)
        : m_ref(1), m_class(cls) {}

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IWbemClassObject)
        {
            *ppv = static_cast<IWbemClassObject*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override
    {
        return (ULONG)InterlockedIncrement(&m_ref);
    }
    ULONG STDMETHODCALLTYPE Release() override
    {
        LONG n = InterlockedDecrement(&m_ref);
        if (n == 0) delete this;
        return (ULONG)n;
    }

    // IWbemClassObject::Get — class-aware: returns plausible values for
    // properties whose detectors actually inspect the value.
    HRESULT STDMETHODCALLTYPE Get(LPCWSTR wszName, LONG /*lFlags*/,
                                   VARIANT* pVal, CIMTYPE* pType,
                                   LONG* plFlavor) override
    {
        // __CLASS — let callers identify what we're pretending to be.
        if (wszName && wcscmp(wszName, L"__CLASS") == 0)
        {
            if (pVal)
            {
                VariantInit(pVal);
                pVal->vt      = VT_BSTR;
                pVal->bstrVal = SysAllocString(m_class.c_str());
            }
            if (pType)    *pType    = CIM_STRING;
            if (plFlavor) *plFlavor = 0;
            return WBEM_S_NO_ERROR;
        }

        // MSAcpi_ThermalZoneTemperature.CurrentTemperature → 300 (uint32).
        if (wszName &&
            m_class == L"MSAcpi_ThermalZoneTemperature" &&
            wcscmp(wszName, L"CurrentTemperature") == 0)
        {
            if (pVal)
            {
                VariantInit(pVal);
                pVal->vt   = VT_I4;
                pVal->lVal = 300;
            }
            if (pType)    *pType    = CIM_UINT32;
            if (plFlavor) *plFlavor = 0;
            return WBEM_S_NO_ERROR;
        }

        // Default: empty BSTR so callers that just dereference bstrVal
        // don't crash on a NULL.
        if (pVal)
        {
            VariantInit(pVal);
            pVal->vt      = VT_BSTR;
            pVal->bstrVal = SysAllocString(L"");
        }
        if (pType)    *pType    = CIM_STRING;
        if (plFlavor) *plFlavor = 0;
        return WBEM_S_NO_ERROR;
    }

    // Stub everything else with E_NOTIMPL.
    HRESULT STDMETHODCALLTYPE GetQualifierSet(IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Put(LPCWSTR, LONG, VARIANT*, CIMTYPE) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Delete(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetNames(LPCWSTR, LONG, VARIANT*, SAFEARRAY**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE BeginEnumeration(LONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Next(LONG, BSTR*, VARIANT*, CIMTYPE*, LONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EndEnumeration() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyQualifierSet(LPCWSTR, IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Clone(IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetObjectText(LONG, BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SpawnDerivedClass(LONG, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SpawnInstance(LONG, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CompareTo(LONG, IWbemClassObject*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPropertyOrigin(LPCWSTR, BSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE InheritsFrom(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethod(LPCWSTR, LONG, IWbemClassObject**, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE PutMethod(LPCWSTR, LONG, IWbemClassObject*, IWbemClassObject*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DeleteMethod(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE BeginMethodEnumeration(LONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE NextMethod(LONG, BSTR*, IWbemClassObject**, IWbemClassObject**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EndMethodEnumeration() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethodQualifierSet(LPCWSTR, IWbemQualifierSet**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMethodOrigin(LPCWSTR, BSTR*) override { return E_NOTIMPL; }

private:
    LONG          m_ref;
    std::wstring  m_class;
};

HRESULT STDMETHODCALLTYPE Hook_ExecQuery(
    IWbemServices*         pThis,
    BSTR                   strQueryLanguage,
    BSTR                   strQuery,
    LONG                   lFlags,
    IWbemContext*          pCtx,
    IEnumWbemClassObject** ppEnum)
{
    HRESULT hr = g_pOrigExecQuery(pThis, strQueryLanguage, strQuery,
                                   lFlags, pCtx, ppEnum);
    if (SUCCEEDED(hr) && ppEnum && *ppEnum && g_NonEmptyEnabled)
    {
        std::wstring cls = ParseClassFromWql(strQuery);
        if (IsCriticalClass(cls))
        {
            RegisterCriticalEnum(*ppEnum, cls);
            WMIHOOK_INFO(L"ExecQuery: tracking critical class " + cls);
        }
    }
    return hr;
}

// IEnumWbemClassObject::Next — plain logging detour.
HRESULT STDMETHODCALLTYPE Hook_Next(
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

// PnP Name + DeviceID filter hook.
static const wchar_t* kPnPNameSubstrings[] = {
    L"82801FB", L"82441FX", L"82371SB", L"OpenHCD", L"VBOX"
};
static const ULONG kPnPNameFilterCount =
    sizeof(kPnPNameSubstrings) / sizeof(kPnPNameSubstrings[0]);

static const wchar_t* kPnPDeviceIdFilters[] = {
    L"PCI\\VEN_80EE&DEV_CAFE"
};
static const ULONG kPnPDeviceIdFilterCount =
    sizeof(kPnPDeviceIdFilters) / sizeof(kPnPDeviceIdFilters[0]);

static bool ShouldFilterPnPObject(IWbemClassObject* pObj, std::wstring& outReason)
{
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

HRESULT STDMETHODCALLTYPE Hook_Next_FilterPnP(
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
            // Non-empty fallback: if this enumerator was tagged by
            // Hook_ExecQuery as a critical class and has not yet
            // surrendered any real or synthetic object, give the caller
            // exactly one fake row.  We inject on either WBEM_S_FALSE
            // (the empty-success path used by root\CIMV2 providers) AND
            // on FAILED hr (root\WMI providers like the ACPI thermal
            // zone often return WBEM_E_NOT_SUPPORTED / E_PROVIDER_*
            // when the class is empty or unavailable).  al-khaser-style
            // probes look at uReturn only, never at hr, so masking the
            // underlying error with WBEM_S_NO_ERROR is safe.
            if (got == 0 && uCount >= 1 && apObjects)
            {
                std::wstring cls = ClaimInjectionSlot(pThis);
                if (!cls.empty())
                {
                    apObjects[0] = new FakeWbemObject(cls);
                    if (puReturned) *puReturned = 1;
                    WMIHOOK_INFO(L"FilterPnP: injected fake " + cls +
                                 L" instance (hr=0x" +
                                 std::to_wstring((unsigned long)hr) + L")");
                    return WBEM_S_NO_ERROR;
                }
            }

            if (puReturned) *puReturned = 0;
            WMIHOOK_INFO(L"Next hooked, returned 0 objects");
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
                apObjects[out++] = pObj;
            }
        }
    } while (out == 0);

    // Real objects flowed through — block any later injection on this
    // enumerator regardless of what subsequent Next calls return.
    MarkEnumYieldedReal(pThis);

    if (puReturned) *puReturned = out;
    WMIHOOK_INFO(L"Next hooked, returned " + std::to_wstring(out) + L" objects");
    return hr;
}

// Per-class spoofing helpers — same rules as the previous per-class detours.

// VEN_VBOX → VEN_GENERIC, then any remaining VBOX → Generic.
std::wstring MaskVboxString(const std::wstring& s)
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

void SetBstrResult(VARIANT* pVal, CIMTYPE* pType, LONG* plFlavor,
                   const wchar_t* spoof)
{
    if (pVal)
    {
        VariantInit(pVal);
        pVal->vt      = VT_BSTR;
        pVal->bstrVal = SysAllocString(spoof);
    }
    if (pType)    *pType    = CIM_STRING;
    if (plFlavor) *plFlavor = 0;
}

// Hook_DispatcherGet — single shared IWbemClassObject::Get detour.
//
// Reads __CLASS via the original Get (no recursion), then runs a per-class
// block when the matching enable flag is set.  Unhandled / disabled paths
// fall through to the original Get unchanged.
HRESULT STDMETHODCALLTYPE Hook_DispatcherGet(
    IWbemClassObject* pThis,
    LPCWSTR           wszName,
    LONG              lFlags,
    VARIANT*          pVal,
    CIMTYPE*          pType,
    LONG*             plFlavor)
{
    if (!wszName)
        return g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);

    // Determine the object class via the ORIGINAL Get — no recursion.
    std::wstring cls;
    {
        VARIANT vtClass;
        VariantInit(&vtClass);
        if (SUCCEEDED(g_pOrigGet(pThis, L"__CLASS", 0, &vtClass, nullptr, nullptr)) &&
            vtClass.vt == VT_BSTR && vtClass.bstrVal)
        {
            cls = vtClass.bstrVal;
        }
        VariantClear(&vtClass);
    }

    if (cls.empty())
        return g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);

    // Win32_BaseBoard — spoof Product / Manufacturer.
    if (g_BaseBoardEnabled && cls == L"Win32_BaseBoard")
    {
        const wchar_t* spoof = nullptr;
        if (wcscmp(wszName, L"Product") == 0)
            spoof = L"Standard PC";
        else if (wcscmp(wszName, L"Manufacturer") == 0)
            spoof = L"Microsoft Corporation";

        if (spoof)
        {
            SetBstrResult(pVal, pType, plFlavor, spoof);
            WMIHOOK_INFO(std::wstring(L"BaseBoardGet: spoofed ") + wszName +
                         L" -> '" + spoof + L"'");
            return S_OK;
        }
    }

    // Win32_Bus — rewrite Name (ACPIBus_BUS_0 → _1, etc.).
    if (g_BusEnabled && cls == L"Win32_Bus" && wcscmp(wszName, L"Name") == 0)
    {
        HRESULT hr = g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
        if (SUCCEEDED(hr) && pVal && pVal->vt == VT_BSTR && pVal->bstrVal)
        {
            static const struct { const wchar_t* f; const wchar_t* t; } kBusRemap[] = {
                { L"ACPIBus_BUS_0", L"ACPIBus_BUS_1" },
                { L"PCI_BUS_0",     L"PCI_BUS_1"     },
                { L"PNP_BUS_0",     L"PNP_BUS_1"     },
            };
            std::wstring name = pVal->bstrVal;
            for (auto& m : kBusRemap)
            {
                size_t pos = name.find(m.f);
                if (pos != std::wstring::npos)
                {
                    name.replace(pos, wcslen(m.f), m.t);
                    SysFreeString(pVal->bstrVal);
                    pVal->bstrVal = SysAllocString(name.c_str());
                    WMIHOOK_INFO(std::wstring(L"BusGet: masked '") + m.f +
                                 L"' -> '" + m.t + L"'");
                    break;
                }
            }
        }
        return hr;
    }


    // Win32_PnPDevice — mask VBOX in Name/Caption/PNPDeviceID.
    if (g_PnPDeviceEnabled && cls == L"Win32_PnPDevice")
    {
        static const wchar_t* kPnPDevProps[] = { L"Name", L"Caption", L"PNPDeviceID" };
        bool match = false;
        for (auto p : kPnPDevProps)
            if (wcscmp(wszName, p) == 0) { match = true; break; }

        if (match)
        {
            HRESULT hr = g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
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


    // Win32_BIOS — spoof SerialNumber to a value that does not match
    if (g_BiosEnabled && cls == L"Win32_BIOS" &&
        wcscmp(wszName, L"SerialNumber") == 0)
    {
        SetBstrResult(pVal, pType, plFlavor, L"System Serial");
        WMIHOOK_INFO(L"BiosGet: spoofed SerialNumber -> 'System Serial'");
        return S_OK;
    }

    // Win32_ComputerSystem — spoof Model / Manufacturer.
    if (g_ComputerSystemEnabled && cls == L"Win32_ComputerSystem")
    {
        const wchar_t* spoof = nullptr;
        if (wcscmp(wszName, L"Model") == 0)
            spoof = L"Standard PC";
        else if (wcscmp(wszName, L"Manufacturer") == 0)
            spoof = L"Microsoft Corporation";

        if (spoof)
        {
            SetBstrResult(pVal, pType, plFlavor, spoof);
            WMIHOOK_INFO(std::wstring(L"ComputerSystemGet: spoofed ") + wszName +
                         L" -> '" + spoof + L"'");
            return S_OK;
        }
    }

    // Win32_VideoController — spoof Caption.
    if (g_VideoEnabled && cls == L"Win32_VideoController" &&
        wcscmp(wszName, L"Caption") == 0)
    {
        SetBstrResult(pVal, pType, plFlavor, L"Generic VGA");
        WMIHOOK_INFO(L"VideoGet: spoofed Caption -> 'Generic VGA'");
        return S_OK;
    }

    // Win32_Processor — spoof NumberOfCores (must be >= 2) and
    // ProcessorId (must not be NULL).  WMI normally hands uint32
    // properties back as VT_I4; the al-khaser-style check reads them
    // via vtProp.uintVal which shares storage with lVal in the VARIANT
    // union, so writing lVal = 4 is read back as 4 either way.
    if (g_ProcessorEnabled && cls == L"Win32_Processor")
    {
        if (wcscmp(wszName, L"NumberOfCores") == 0)
        {
            if (pVal)
            {
                VariantInit(pVal);
                pVal->vt   = VT_I4;
                pVal->lVal = 4;
            }
            if (pType)    *pType    = CIM_UINT32;
            if (plFlavor) *plFlavor = 0;
            WMIHOOK_INFO(L"ProcessorGet: spoofed NumberOfCores -> 4");
            return S_OK;
        }
        if (wcscmp(wszName, L"ProcessorId") == 0)
        {
            SetBstrResult(pVal, pType, plFlavor, L"BFEBFBFF000906E9");
            WMIHOOK_INFO(L"ProcessorGet: spoofed ProcessorId -> 'BFEBFBFF000906E9'");
            return S_OK;
        }
    }

    // Win32_LogicalDisk — spoof Size (BSTR; al-khaser parses it via
    // _wcstoui64 and fails the probe if the result is below 80 GB).
    // 128_000_000_000 ≈ 119.2 GiB — comfortably above the threshold
    // regardless of whether the detector uses GB or GiB.
    if (g_LogicalDiskEnabled && cls == L"Win32_LogicalDisk" &&
        wcscmp(wszName, L"Size") == 0)
    {
        SetBstrResult(pVal, pType, plFlavor, L"128000000000");
        WMIHOOK_INFO(L"LogicalDiskGet: spoofed Size -> '128000000000'");
        return S_OK;
    }

    // MSAcpi_ThermalZoneTemperature (root\WMI namespace) — spoof
    // CurrentTemperature for the case where the real WMI provider does
    // return a row.  The "empty result" case is covered separately by
    // the critical-class fake injection in Hook_Next_FilterPnP.
    if (g_ThermalEnabled && cls == L"MSAcpi_ThermalZoneTemperature" &&
        wcscmp(wszName, L"CurrentTemperature") == 0)
    {
        if (pVal)
        {
            VariantInit(pVal);
            pVal->vt   = VT_I4;
            pVal->lVal = 300;
        }
        if (pType)    *pType    = CIM_UINT32;
        if (plFlavor) *plFlavor = 0;
        WMIHOOK_INFO(L"ThermalGet: spoofed CurrentTemperature -> 300");
        return S_OK;
    }

    // Win32_NTEventlogFile.Sources — rewrite VBox-named event log
    // sources (vboxvideo / VBoxVideoW8 / VBoxWddm / VBoxSF /
    // VBoxMouse / VBoxGuest) inside the returned SAFEARRAY of BSTR in
    // place.  Any matching entry becomes "Generic", which doesn't
    // collide with the al-khaser source list.
    if (g_EventLogEnabled && cls == L"Win32_NTEventlogFile" &&
        wcscmp(wszName, L"Sources") == 0)
    {
        HRESULT hr = g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
        if (SUCCEEDED(hr) && pVal &&
            pVal->vt == (VT_BSTR | VT_ARRAY) && pVal->parray)
        {
            static const wchar_t* kVBoxSources[] = {
                L"vboxvideo", L"VBoxVideoW8", L"VBoxWddm",
                L"VBoxSF",    L"VBoxMouse",   L"VBoxGuest",
                L"VBoxService"
            };

            SAFEARRAY* sa = pVal->parray;
            BSTR* items = nullptr;
            if (SUCCEEDED(SafeArrayAccessData(sa, (void**)&items)))
            {
                LONG lo = 0, hi = 0;
                SafeArrayGetLBound(sa, 1, &lo);
                SafeArrayGetUBound(sa, 1, &hi);
                ULONG masked = 0;
                for (LONG i = lo; i <= hi; ++i)
                {
                    if (!items[i]) continue;
                    bool match = false;
                    for (auto pat : kVBoxSources)
                    {
                        if (_wcsicmp(items[i], pat) == 0) { match = true; break; }
                    }
                    if (match)
                    {
                        SysFreeString(items[i]);
                        items[i] = SysAllocString(L"Generic");
                        ++masked;
                    }
                }
                SafeArrayUnaccessData(sa);
                if (masked)
                {
                    WMIHOOK_INFO(L"EventLogGet: masked " +
                                 std::to_wstring(masked) +
                                 L" VBox source(s) in Sources[]");
                }
            }
        }
        return hr;
    }

    // Fall-through: unmodified original call.
    return g_pOrigGet(pThis, wszName, lFlags, pVal, pType, plFlavor);
}

} // namespace WmiMaskHooks
