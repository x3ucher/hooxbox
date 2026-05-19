// Build (from HooksBox/tests/, x64 Developer Command Prompt):
//   cl /nologo /W3 /WX /EHsc /std:c++17 /utf-8
//      /I"..\..\tools\MinHook\include"
//      wmi_test.cpp ..\hooks\wmi_hooks.cpp
//      /link wbemuuid.lib ole32.lib oleaut32.lib advapi32.lib
//            ..\..\tools\MinHook\lib\libMinHook.x64.lib

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>

#include "..\hooks\wmi_hooks.h"

// ---------------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------------
static HANDLE g_hOut = nullptr;

static void WPrint(const wchar_t* s)
{
    DWORD wr = 0;
    WriteConsoleW(g_hOut, s, (DWORD)wcslen(s), &wr, nullptr);
}
static void WPrintLine(const wchar_t* s) { WPrint(s); WPrint(L"\n"); }

// ---------------------------------------------------------------------------
// Returns true if the UTF-8 log file contains the given wide substring.
// ---------------------------------------------------------------------------
static bool LogContains(const wchar_t* needle)
{
    HANDLE hFile = CreateFileW(L"sandbox_evasion.log", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD sz = GetFileSize(hFile, nullptr);
    std::string raw(sz, '\0');
    DWORD bytesRead = 0;
    ReadFile(hFile, &raw[0], sz, &bytesRead, nullptr);
    CloseHandle(hFile);
    raw.resize(bytesRead);

    int wLen = MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), (int)raw.size(), nullptr, 0);
    if (wLen <= 0) return false;
    std::wstring wide(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), (int)raw.size(), &wide[0], wLen);
    return wide.find(needle) != std::wstring::npos;
}

static void PrintUtf8FileToConsole(const wchar_t* path)
{
    HANDLE hFile = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { std::cerr << "Log not found.\n"; return; }

    DWORD sz = GetFileSize(hFile, nullptr);
    std::string raw(sz, '\0');
    DWORD br = 0;
    ReadFile(hFile, &raw[0], sz, &br, nullptr);
    CloseHandle(hFile);
    raw.resize(br);
    if (raw.empty()) return;

    size_t off = 0;
    if (raw.size() >= 3 &&
        (unsigned char)raw[0] == 0xEF &&
        (unsigned char)raw[1] == 0xBB &&
        (unsigned char)raw[2] == 0xBF) off = 3;

    int wLen = MultiByteToWideChar(CP_UTF8, 0,
                                   raw.c_str() + off, (int)(raw.size() - off),
                                   nullptr, 0);
    if (wLen <= 0) return;
    std::wstring wide(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        raw.c_str() + off, (int)(raw.size() - off),
                        &wide[0], wLen);
    DWORD wr = 0;
    WriteConsoleW(g_hOut, wide.c_str(), (DWORD)wide.size(), &wr, nullptr);
}

// ---------------------------------------------------------------------------
// WmiSession - RAII wrapper for COM + IWbemServices lifetime
// ---------------------------------------------------------------------------
struct WmiSession
{
    IWbemLocator*  pLocator  = nullptr;
    IWbemServices* pServices = nullptr;
    bool           comInit   = false;

    bool Init()
    {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
        {
            std::cerr << "CoInitializeEx failed: 0x" << std::hex << hr << "\n";
            return false;
        }
        comInit = SUCCEEDED(hr);

        hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                  RPC_C_AUTHN_LEVEL_DEFAULT,
                                  RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE, nullptr);
        if (FAILED(hr) && hr != RPC_E_TOO_LATE)
        {
            std::cerr << "CoInitializeSecurity failed: 0x" << std::hex << hr << "\n";
            if (comInit) CoUninitialize();
            return false;
        }

        hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator, reinterpret_cast<void**>(&pLocator));
        if (FAILED(hr))
        {
            std::cerr << "CoCreateInstance(WbemLocator) failed: 0x" << std::hex << hr << "\n";
            if (comInit) CoUninitialize();
            return false;
        }

        hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr,
                                     nullptr, 0, nullptr, nullptr, &pServices);
        if (FAILED(hr))
        {
            std::cerr << "ConnectServer failed: 0x" << std::hex << hr << "\n";
            pLocator->Release(); pLocator = nullptr;
            if (comInit) CoUninitialize();
            return false;
        }

        hr = CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                               nullptr, RPC_C_AUTHN_LEVEL_CALL,
                               RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        if (FAILED(hr))
        {
            std::cerr << "CoSetProxyBlanket failed: 0x" << std::hex << hr << "\n";
            pServices->Release(); pServices = nullptr;
            pLocator->Release();  pLocator  = nullptr;
            if (comInit) CoUninitialize();
            return false;
        }

        return true;
    }

    IEnumWbemClassObject* ExecQuery(const wchar_t* wql)
    {
        IEnumWbemClassObject* pEnum = nullptr;
        pServices->ExecQuery(_bstr_t(L"WQL"), _bstr_t(wql),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                             nullptr, &pEnum);
        return pEnum;
    }

    ~WmiSession()
    {
        if (pServices) { pServices->Release(); pServices = nullptr; }
        if (pLocator)  { pLocator->Release();  pLocator  = nullptr; }
        if (comInit)   { CoUninitialize(); comInit = false; }
    }
};

// ---------------------------------------------------------------------------
// QueryBaseBoard — reads Product and Manufacturer from Win32_BaseBoard.
// Goes through any active IWbemClassObject::Get hook transparently.
// ---------------------------------------------------------------------------
struct BaseBoardSnapshot { std::wstring product; std::wstring manufacturer; };

static bool QueryBaseBoard(WmiSession& wmi, BaseBoardSnapshot& out)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Product, Manufacturer FROM Win32_BaseBoard");
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    bool found = false;
    if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        VARIANT vtP, vtM;
        VariantInit(&vtP); VariantInit(&vtM);
        if (SUCCEEDED(pObj->Get(L"Product",      0, &vtP, nullptr, nullptr)) && vtP.vt == VT_BSTR)
            out.product      = vtP.bstrVal ? vtP.bstrVal : L"";
        if (SUCCEEDED(pObj->Get(L"Manufacturer", 0, &vtM, nullptr, nullptr)) && vtM.vt == VT_BSTR)
            out.manufacturer = vtM.bstrVal ? vtM.bstrVal : L"";
        VariantClear(&vtP); VariantClear(&vtM);
        pObj->Release();
        found = true;
    }
    pEnum->Release();
    return found;
}

// ---------------------------------------------------------------------------
// Test_BaseBoardHook
//
// Flow:
//   1. Query Win32_BaseBoard without hook; print real Product and Manufacturer.
//   2. Obtain a BaseBoard object to read the vtable, then call HookBaseBoardGet.
//      MinHook patches IWbemClassObject::Get in the function body; the hook
//      survives releasing the seed object and applies to all future objects of
//      the same concrete COM class.
//   3. Re-query Win32_BaseBoard; the hook substitutes "Standard PC" and
//      "Microsoft Corporation" for Win32_BaseBoard objects only.
//   4. PASS if both spoofed values are returned; FAIL otherwise.
//   5. Unhook.
// ---------------------------------------------------------------------------
void Test_BaseBoardHook()
{
    WPrintLine(L"\n--- Test_BaseBoardHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    // Step 1: read without hook.
    BaseBoardSnapshot before;
    if (!QueryBaseBoard(wmi, before))
    {
        std::cerr << "FAIL: Win32_BaseBoard query\n";
        return;
    }
    WPrint(L"  Before — Product      : "); WPrintLine(before.product.c_str());
    WPrint(L"  Before — Manufacturer : "); WPrintLine(before.manufacturer.c_str());

    // Step 2: get a seed object to locate the vtable, then install hook.
    IEnumWbemClassObject* pSeedEnum =
        wmi.ExecQuery(L"SELECT Product FROM Win32_BaseBoard");
    if (!pSeedEnum) { std::cerr << "FAIL: ExecQuery for hook seed\n"; return; }

    IWbemClassObject* pSeed = nullptr;
    ULONG returned = 0;
    if (pSeedEnum->Next(WBEM_INFINITE, 1, &pSeed, &returned) != S_OK || !returned)
    {
        std::cerr << "FAIL: no Win32_BaseBoard object on this system\n";
        pSeedEnum->Release();
        return;
    }
    pSeedEnum->Release();

    if (!HookBaseBoardGet(pSeed))
    {
        std::cerr << "FAIL: HookBaseBoardGet\n";
        pSeed->Release();
        return;
    }
    pSeed->Release();  // hook lives in the function body, survives this release

    // Step 3: re-query; hook substitutes values for Win32_BaseBoard objects.
    BaseBoardSnapshot after;
    QueryBaseBoard(wmi, after);
    WPrint(L"  After  — Product      : "); WPrintLine(after.product.c_str());
    WPrint(L"  After  — Manufacturer : "); WPrintLine(after.manufacturer.c_str());

    bool pass = (after.product      == L"Standard PC" &&
                 after.manufacturer == L"Microsoft Corporation");
    WPrintLine(pass ? L"BASEBOARD HOOK TEST PASS" : L"BASEBOARD HOOK TEST FAIL");

    UnhookBaseBoardGet();
}

// ---------------------------------------------------------------------------
// VBoxBusCheck — C++ reimplementation of vbox_bus_wmi().
//
// Returns true iff Win32_Bus has exactly 3 instances whose Names contain
// "ACPIBus_BUS_0", "PCI_BUS_0", "PNP_BUS_0" respectively (one each).
// Goes through any active IWbemClassObject::Get hook transparently.
// ---------------------------------------------------------------------------
static bool VBoxBusCheck(WmiSession& wmi)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_Bus");
    if (!pEnum) return false;

    static const wchar_t* kExpected[] = {
        L"ACPIBus_BUS_0", L"PCI_BUS_0", L"PNP_BUS_0"
    };
    static const int kThreshold = 3;

    int count     = 0;
    int findCount = 0;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        count++;
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"Name", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            for (int k = 0; k < kThreshold; ++k)
                if (wcsstr(vt.bstrVal, kExpected[k]))
                    { findCount++; break; }
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();

    return (count == kThreshold && findCount == kThreshold);
}

// ---------------------------------------------------------------------------
// Test_BusHook
//
// Flow:
//   1. Call VBoxBusCheck without hook. On a VirtualBox VM this returns TRUE.
//      If FALSE on this machine (no matching bus configuration), skip.
//   2. Obtain a Win32_Bus object to read the vtable, install HookBusGet.
//      The hook rewrites ACPIBus_BUS_0/PCI_BUS_0/PNP_BUS_0 → *_1 variants,
//      so wcsstr-based checks find nothing and findCount stays at 0.
//   3. Call VBoxBusCheck again; it should now return FALSE (count==3, findCount==0).
//   4. PASS if detection was suppressed; FAIL otherwise.
//   5. Unhook.
// ---------------------------------------------------------------------------
void Test_BusHook()
{
    WPrintLine(L"\n--- Test_BusHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    // Step 1: baseline.
    bool detectedBefore = VBoxBusCheck(wmi);
    std::cout << "  vbox_bus_wmi() before hook: "
              << (detectedBefore ? "TRUE" : "FALSE") << "\n";

    if (!detectedBefore)
    {
        WPrintLine(L"BUS HOOK TEST SKIP (VBox bus signature not present on this system)");
        return;
    }

    // Step 2: get a seed Win32_Bus object to locate the vtable.
    IEnumWbemClassObject* pSeedEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_Bus");
    if (!pSeedEnum) { std::cerr << "FAIL: ExecQuery for hook seed\n"; return; }

    IWbemClassObject* pSeed = nullptr;
    ULONG returned = 0;
    if (pSeedEnum->Next(WBEM_INFINITE, 1, &pSeed, &returned) != S_OK || !returned)
    {
        std::cerr << "FAIL: no Win32_Bus object\n";
        pSeedEnum->Release();
        return;
    }
    pSeedEnum->Release();

    if (!HookBusGet(pSeed))
    {
        std::cerr << "FAIL: HookBusGet\n";
        pSeed->Release();
        return;
    }
    pSeed->Release();  // hook lives in the function body

    // Step 3: detection with hook active.
    bool detectedAfter = VBoxBusCheck(wmi);
    std::cout << "  vbox_bus_wmi() after  hook: "
              << (detectedAfter ? "TRUE" : "FALSE") << "\n";

    WPrintLine(!detectedAfter ? L"BUS HOOK TEST PASS" : L"BUS HOOK TEST FAIL");

    UnhookBusGet();
}

// ---------------------------------------------------------------------------
// CountPnPEntities — enumerate Win32_PnPEntity and return the total count.
// ---------------------------------------------------------------------------
static ULONG CountPnPEntities(WmiSession& wmi)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_PnPEntity");
    if (!pEnum) return 0;

    ULONG total = 0;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        if (pObj) { pObj->Release(); pObj = nullptr; }
        total += returned;
    }
    pEnum->Release();
    return total;
}

// ---------------------------------------------------------------------------
// Test_HookNext
//
// Flow:
//   1. Init WMI via COM directly
//   2. ExecQuery("SELECT Name FROM Win32_ComputerSystem")
//   3. HookEnumeratorNext - patches IEnumWbemClassObject::Next in place
//   4. Enumerate to end; each Next() call goes through Hook_Next
//   5. Verify "Next hooked" appears in the log file
//   6. UnhookEnumeratorNext + Release all COM objects
// ---------------------------------------------------------------------------
void Test_HookNext()
{
    WPrintLine(L"\n--- Test_HookNext ---");

    WmiSession wmi;
    if (!wmi.Init())
    {
        std::cerr << "FAIL: WMI init\n";
        return;
    }

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_ComputerSystem");
    if (!pEnum)
    {
        std::cerr << "FAIL: ExecQuery\n";
        return;
    }

    if (!HookEnumeratorNext(pEnum))
    {
        std::cerr << "FAIL: HookEnumeratorNext\n";
        pEnum->Release();
        return;
    }

    ULONG total = 0;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"Name", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR)
        {
            WPrint(L"  Win32_ComputerSystem.Name = ");
            WPrintLine(vt.bstrVal ? vt.bstrVal : L"(null)");
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
        total += returned;
    }
    std::cout << "  Objects enumerated: " << total << "\n";

    bool hookSeen = LogContains(L"Next hooked");
    WPrintLine(hookSeen ? L"HOOK TEST PASS" : L"HOOK TEST FAIL");

    UnhookEnumeratorNext();
    pEnum->Release();
}

// ---------------------------------------------------------------------------
// FindDeviceID — returns true if targetId appears in Win32_PnPEntity results.
// Uses the current Next hook (if any) transparently.
// ---------------------------------------------------------------------------
static bool FindDeviceID(WmiSession& wmi, const wchar_t* targetId)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_PnPEntity");
    if (!pEnum) return false;

    bool found = false;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (!found &&
           pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK &&
           returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"DeviceID", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal &&
            wcsstr(vt.bstrVal, targetId) != nullptr)
        {
            found = true;
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ---------------------------------------------------------------------------
// Test_FilterDeviceID
//
// Flow:
//   1. Query Win32_PnPEntity without hook; check for L"PCI\\VEN_80EE&DEV_CAFE".
//      If absent, the test is inconclusive on this machine — print SKIP.
//   2. Install HookEnumeratorNext_FilterPnPName (now also filters DeviceID).
//   3. Re-run the same query through the hook; verify the device is gone.
//   4. PASS if it disappeared, FAIL otherwise.
//   5. Unhook.
// ---------------------------------------------------------------------------
void Test_FilterDeviceID()
{
    WPrintLine(L"\n--- Test_FilterDeviceID ---");

    WmiSession wmi;
    if (!wmi.Init())
    {
        std::cerr << "FAIL: WMI init\n";
        return;
    }

    const wchar_t* kTargetId = L"PCI\\VEN_80EE&DEV_CAFE";

    // Step 1: check presence without hook.
    bool foundBefore = FindDeviceID(wmi, kTargetId);
    WPrint(foundBefore ? L"  [found]   " : L"  [missing] ");
    WPrint(kTargetId);
    WPrintLine(foundBefore ? L" (before hook)" : L" — SKIP (not present on this system)");

    if (!foundBefore)
    {
        WPrintLine(L"DEVICEID FILTER TEST SKIP");
        return;
    }

    // Step 2: install filter hook.
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_PnPEntity");
    if (!pEnum)
    {
        std::cerr << "FAIL: ExecQuery for hook install\n";
        return;
    }
    if (!HookEnumeratorNext_FilterPnPName(pEnum))
    {
        std::cerr << "FAIL: HookEnumeratorNext_FilterPnPName\n";
        pEnum->Release();
        return;
    }
    pEnum->Release();

    // Step 3: verify device is gone with hook active.
    bool foundAfter = FindDeviceID(wmi, kTargetId);
    WPrint(foundAfter ? L"  [found]   " : L"  [hidden]  ");
    WPrint(kTargetId);
    WPrintLine(foundAfter ? L" (hook missed it)" : L" (filtered by hook)");

    WPrintLine(!foundAfter ? L"DEVICEID FILTER TEST PASS" : L"DEVICEID FILTER TEST FAIL");

    UnhookEnumeratorNext_FilterPnPName();
}

// ---------------------------------------------------------------------------
// Test_FilterPnPName
//
// Flow:
//   1. Count all Win32_PnPEntity objects with no hook (count_before).
//   2. Install HookEnumeratorNext_FilterPnPName using a throwaway enumerator
//      (the hook patches the function body; it applies to all future enum
//      instances of the same concrete class).
//   3. Re-run the same query; CountPnPEntities goes through the filter hook.
//   4. PASS if the log contains "FilterPnP: skipped" entries AND
//      count_after is 0 or less than count_before.
//   5. Unhook.
// ---------------------------------------------------------------------------
void Test_FilterPnPName()
{
    WPrintLine(L"\n--- Test_FilterPnPName ---");

    WmiSession wmi;
    if (!wmi.Init())
    {
        std::cerr << "FAIL: WMI init\n";
        return;
    }

    // Step 1: baseline count (no hook).
    ULONG countBefore = CountPnPEntities(wmi);
    std::cout << "  PnP entities before filter: " << countBefore << "\n";

    if (countBefore == 0)
    {
        WPrintLine(L"FILTER TEST SKIP (no PnP entities found)");
        return;
    }

    // Step 2: install filter hook via any enumerator of the target class.
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_PnPEntity");
    if (!pEnum)
    {
        std::cerr << "FAIL: ExecQuery for hook install\n";
        return;
    }
    if (!HookEnumeratorNext_FilterPnPName(pEnum))
    {
        std::cerr << "FAIL: HookEnumeratorNext_FilterPnPName\n";
        pEnum->Release();
        return;
    }
    pEnum->Release();  // hook lives in the function body, not in this object

    // Step 3: filtered count (new query, same vtable => goes through hook).
    ULONG countAfter = CountPnPEntities(wmi);
    std::cout << "  PnP entities after  filter: " << countAfter << "\n";

    bool skipped = LogContains(L"FilterPnP: skipped");
    bool pass    = skipped && (countAfter == 0 || countAfter < countBefore);
    WPrintLine(pass ? L"FILTER TEST PASS" : L"FILTER TEST FAIL");

    if (!skipped)
        WPrintLine(L"  (no VM-indicator device names found on this system)");

    UnhookEnumeratorNext_FilterPnPName();
}

// ---------------------------------------------------------------------------
// HasVboxInPnPDeviceQuery
//
// Returns true if any Win32_PnPDevice object has "VBOX" in Name, Caption,
// or PNPDeviceID. Goes through the active Get hook transparently.
// ---------------------------------------------------------------------------
static bool HasVboxInPnPDeviceQuery(WmiSession& wmi)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name, Caption, PNPDeviceID FROM Win32_PnPDevice");
    if (!pEnum) return false;

    static const wchar_t* kProps[] = { L"Name", L"Caption", L"PNPDeviceID" };

    bool found = false;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (!found &&
           pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK &&
           returned > 0)
    {
        for (int k = 0; k < 3 && !found; ++k)
        {
            VARIANT vt;
            VariantInit(&vt);
            if (SUCCEEDED(pObj->Get(kProps[k], 0, &vt, nullptr, nullptr)) &&
                vt.vt == VT_BSTR && vt.bstrVal &&
                wcsstr(vt.bstrVal, L"VBOX") != nullptr)
            {
                found = true;
            }
            VariantClear(&vt);
        }
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ---------------------------------------------------------------------------
// Test_PnPDeviceHook
//
// Flow:
//   1. Query Win32_PnPDevice; if no VBOX strings found, SKIP.
//   2. Get a seed Win32_PnPDevice object, install HookPnPDeviceGet.
//      Hook patches the function body and survives releasing the seed.
//   3. Re-query; check that all VBOX strings are gone.
//   4. PASS if none found after hook; FAIL otherwise.
//   5. Unhook.
// ---------------------------------------------------------------------------
void Test_PnPDeviceHook()
{
    WPrintLine(L"\n--- Test_PnPDeviceHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    // Step 1: baseline.
    bool vboxBefore = HasVboxInPnPDeviceQuery(wmi);
    std::cout << "  Win32_PnPDevice VBOX before hook: "
              << (vboxBefore ? "YES" : "NO") << "\n";

    if (!vboxBefore)
    {
        WPrintLine(L"PNPDEVICE HOOK TEST SKIP (no VBOX strings on this system)");
        return;
    }

    // Step 2: get a seed Win32_PnPDevice object to locate the vtable.
    IEnumWbemClassObject* pSeedEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_PnPDevice");
    if (!pSeedEnum) { std::cerr << "FAIL: ExecQuery for hook seed\n"; return; }

    IWbemClassObject* pSeed = nullptr;
    ULONG returned = 0;
    if (pSeedEnum->Next(WBEM_INFINITE, 1, &pSeed, &returned) != S_OK || !returned)
    {
        std::cerr << "FAIL: no Win32_PnPDevice object\n";
        pSeedEnum->Release();
        return;
    }
    pSeedEnum->Release();

    if (!HookPnPDeviceGet(pSeed))
    {
        std::cerr << "FAIL: HookPnPDeviceGet\n";
        pSeed->Release();
        return;
    }
    pSeed->Release();  // hook lives in the function body, survives this release

    // Step 3: detection with hook active.
    bool vboxAfter = HasVboxInPnPDeviceQuery(wmi);
    std::cout << "  Win32_PnPDevice VBOX after  hook: "
              << (vboxAfter ? "YES" : "NO") << "\n";

    WPrintLine(!vboxAfter ? L"PNPDEVICE HOOK TEST PASS" : L"PNPDEVICE HOOK TEST FAIL");

    UnhookPnPDeviceGet();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    WPrintLine(L"=== WMI hook test suite ===");

    Test_HookNext();
    Test_FilterDeviceID();
    Test_FilterPnPName();
    Test_BaseBoardHook();
    Test_BusHook();
    Test_PnPDeviceHook();

    WMIHOOK_INFO(L"wmi_test completed.");

    WPrintLine(L"\n--- Log file ---");
    PrintUtf8FileToConsole(L"sandbox_evasion.log");

    return 0;
}
