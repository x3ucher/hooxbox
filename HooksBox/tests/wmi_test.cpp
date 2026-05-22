// Build (from HooksBox/tests/, x64 Developer Command Prompt):
//   cl /nologo /W3 /WX /EHsc /std:c++17 /utf-8 wmi_test.cpp
//      /link wbemuuid.lib ole32.lib oleaut32.lib
//
// All tests assume hooks have been INJECTED EXTERNALLY into this process
// before it starts.  Each test queries WMI once and decides PASS/FAIL by
// whether the corresponding VM artefact is still visible.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shlwapi.h>
#include <powrprof.h>
#include <winsvc.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "advapi32.lib")

#include "wmi_test.h"

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

    bool Init(const wchar_t* ns = L"ROOT\\CIMV2")
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

        // ROOT\CIMV2 is the default; ROOT\WMI (for MSAcpi_*) typically
        // requires admin rights and returns E_ACCESSDENIED for limited
        // users — caller is expected to treat a failed Init() gracefully.
        hr = pLocator->ConnectServer(_bstr_t(ns), nullptr, nullptr,
                                     nullptr, 0, nullptr, nullptr, &pServices);
        if (FAILED(hr))
        {
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
// VBoxBusCheck — count==3 && findCount==3 for ACPIBus_BUS_0/PCI_BUS_0/PNP_BUS_0.
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
// CountPnPEntities
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
// FindDeviceID
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
// HasVboxInPnPDeviceQuery
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

// ===========================================================================
// Detection routines for Test_BiosComputerVideo
//
// Verbatim al-khaser checks (StrStrIW = case-insensitive substring search;
// "0" on Win32_BIOS.SerialNumber is matched with wcscmp because VBox
// returns exactly "0").  Each function returns true ("Detected") when the
// WMI value matches one of the well-known VM patterns; the injected hook
// rewrites the value so the same check returns false ("Not detected").
// ===========================================================================

// Win32_BIOS.SerialNumber — al-khaser (VMWare / "0" / Xen / Virtual / A M I)
// PLUS VBOX / VirtualBox.  al-khaser only catches VBox via the legacy
// wcscmp(..., L"0") path (older VBox BIOS) — modern VBox builds can carry
// "VBOX" tokens in the serial that the verbatim al-khaser check misses.
static bool serial_number_bios_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_BIOS");
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
        if (SUCCEEDED(pObj->Get(L"SerialNumber", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            if (StrStrIW(vt.bstrVal, L"VMWare")     != nullptr ||
                wcscmp (vt.bstrVal, L"0")           == 0       ||
                StrStrIW(vt.bstrVal, L"Xen")        != nullptr ||
                StrStrIW(vt.bstrVal, L"Virtual")    != nullptr ||
                StrStrIW(vt.bstrVal, L"A M I")      != nullptr ||
                StrStrIW(vt.bstrVal, L"VBOX")       != nullptr ||
                StrStrIW(vt.bstrVal, L"VirtualBox") != nullptr)
            {
                found = true;
            }
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// Win32_ComputerSystem.Model — VirtualBox / HVM domU (Xen) / VMWare.
static bool model_computer_system_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_ComputerSystem");
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
        if (SUCCEEDED(pObj->Get(L"Model", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            if (StrStrIW(vt.bstrVal, L"VirtualBox") != nullptr ||
                StrStrIW(vt.bstrVal, L"HVM domU")   != nullptr ||
                StrStrIW(vt.bstrVal, L"VMWare")     != nullptr)
            {
                found = true;
            }
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// Win32_ComputerSystem.Manufacturer — al-khaser (VMWare / Xen /
// innotek GmbH / QEMU) PLUS Oracle Corporation.  Oracle inherited VBox
// from innotek; modern VBox guests can report "Oracle Corporation" as
// the Manufacturer, which the verbatim al-khaser check would let slip.
static bool manufacturer_computer_system_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_ComputerSystem");
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
        if (SUCCEEDED(pObj->Get(L"Manufacturer", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            if (StrStrIW(vt.bstrVal, L"VMWare")       != nullptr ||
                StrStrIW(vt.bstrVal, L"Xen")          != nullptr ||
                StrStrIW(vt.bstrVal, L"innotek GmbH") != nullptr ||
                StrStrIW(vt.bstrVal, L"QEMU")         != nullptr ||
                StrStrIW(vt.bstrVal, L"Oracle")       != nullptr)
            {
                found = true;
            }
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ===========================================================================
// Non-empty-class probes (al-khaser AntiVM/Generic.cpp pattern):
//   "If WMI returns 0 rows for this class, declare VM detected."
// Each probe returns true ⇒ class was empty ⇒ suspect VM.
// The injected ExecQuery+Next hooks rewrite this so a critical class
// always yields at least one (synthetic) row → probe returns false.
// ===========================================================================
static bool IsClassEmpty(const wchar_t* class_name)
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    std::wstring q = L"SELECT * FROM ";
    q += class_name;

    IEnumWbemClassObject* pEnum = wmi.ExecQuery(q.c_str());
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned);
    bool empty = (returned == 0);
    if (pObj) pObj->Release();
    pEnum->Release();
    return empty;
}

static bool fan_wmi()                  { return IsClassEmpty(L"Win32_Fan"); }
static bool cachememory_wmi()          { return IsClassEmpty(L"Win32_CacheMemory"); }
static bool physicalmemory_wmi()       { return IsClassEmpty(L"Win32_PhysicalMemory"); }
static bool memorydevice_wmi()         { return IsClassEmpty(L"Win32_MemoryDevice"); }
static bool memoryarray_wmi()          { return IsClassEmpty(L"Win32_MemoryArray"); }
static bool voltageprobe_wmi()         { return IsClassEmpty(L"Win32_VoltageProbe"); }
static bool portconnector_wmi()        { return IsClassEmpty(L"Win32_PortConnector"); }
static bool smbiosmemory_wmi()         { return IsClassEmpty(L"Win32_SMBIOSMemory"); }
static bool thermalzone_wmi()          { return IsClassEmpty(
    L"Win32_PerfFormattedData_Counters_ThermalZoneInformation"); }
static bool cim_memory_wmi()           { return IsClassEmpty(L"CIM_Memory"); }
static bool cim_numericsensor_wmi()    { return IsClassEmpty(L"CIM_NumericSensor"); }
static bool cim_physicalconnector_wmi(){ return IsClassEmpty(L"CIM_PhysicalConnector"); }
static bool cim_sensor_wmi()           { return IsClassEmpty(L"CIM_Sensor"); }
static bool cim_slot_wmi()             { return IsClassEmpty(L"CIM_Slot"); }
static bool cim_temperaturesensor_wmi(){ return IsClassEmpty(L"CIM_TemperatureSensor"); }
static bool cim_voltagesensor_wmi()    { return IsClassEmpty(L"CIM_VoltageSensor"); }

// Win32_VideoController.Caption — al-khaser (Hyper-V / VMWare) PLUS
// VirtualBox patterns (VirtualBox / VBox).  al-khaser's Caption check
// omits VirtualBox, but VBox is this project's primary detection target
// — a real "VirtualBox Graphics Adapter for Windows" string on the host
// would otherwise slip past.
static bool caption_video_controller_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_VideoController");
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
        if (SUCCEEDED(pObj->Get(L"Caption", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            if (StrStrIW(vt.bstrVal, L"Hyper-V")    != nullptr ||
                StrStrIW(vt.bstrVal, L"VMWare")     != nullptr ||
                StrStrIW(vt.bstrVal, L"VirtualBox") != nullptr ||
                StrStrIW(vt.bstrVal, L"VBox")       != nullptr)
            {
                found = true;
            }
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ===========================================================================
// Win32_Processor probes (al-khaser AntiVM/Generic.cpp pattern):
//   - NumberOfCores < 2  ⇒ suspect VM
//   - ProcessorId == NULL ⇒ suspect VM
// The injected hook spoofs NumberOfCores → 4 and ProcessorId →
// "BFEBFBFF000906E9" so both checks return false.
// ===========================================================================
static bool number_cores_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_Processor");
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
        if (SUCCEEDED(pObj->Get(L"NumberOfCores", 0, &vt, nullptr, nullptr)))
        {
            if (vt.uintVal < 2)
                found = true;
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

static bool process_id_processor_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_Processor");
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
        if (SUCCEEDED(pObj->Get(L"ProcessorId", 0, &vt, nullptr, nullptr)))
        {
            if (vt.vt != VT_BSTR || vt.bstrVal == nullptr)
                found = true;
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ===========================================================================
// Win32_LogicalDisk.Size — al-khaser pattern: any logical disk whose
// Size (parsed from BSTR via _wcstoui64) is below 80 GB ⇒ suspect VM.
// The injected hook spoofs Size to "128000000000".
// ===========================================================================
static bool disk_size_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_LogicalDisk");
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
        if (SUCCEEDED(pObj->Get(L"Size", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            ULONGLONG size = _wcstoui64(vt.bstrVal, nullptr, 10);
            if (size > 0 && size < (80ULL * 1024 * 1024 * 1024))
                found = true;
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ===========================================================================
// MSAcpi_ThermalZoneTemperature (root\WMI) — al-khaser pattern: query
// returns 0 rows ⇒ suspect VM.  Requires admin in most installations;
// when the user has no rights, ConnectServer fails and this probe
// returns false (cannot tell — treated as "not detected").
//
// Coverage with hooks on:
//   • ExecQuery hook tags the enumerator (class is in kCriticalClasses).
//   • If the real provider returns 0 rows, Hook_Next_FilterPnP injects
//     a FakeWbemObject — uReturn == 1 ⇒ probe returns false.
//   • If the provider returns real rows, Hook_DispatcherGet spoofs
//     CurrentTemperature to 300.
// ===========================================================================
static bool current_temperature_acpi_wmi()
{
    WmiSession wmi;
    if (!wmi.Init(L"ROOT\\WMI")) return false;  // no admin or unavailable

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM MSAcpi_ThermalZoneTemperature");
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned);
    bool empty = (returned == 0);
    if (pObj) pObj->Release();
    pEnum->Release();
    return empty;
}

// ===========================================================================
// Win32_NTEventlogFile.Sources — al-khaser vbox_eventlogfile_wmi():
// iterate Win32_NTEventlogFile, find entry whose FileName == "System",
// scan its Sources SAFEARRAY for known VBox driver names.
// Hooked dispatcher rewrites those names in place to "Generic".
// ===========================================================================
static bool vbox_eventlogfile_wmi()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_NTEventlogFile");
    if (!pEnum) return false;

    static const wchar_t* kVBoxSources[] = {
        L"vboxvideo", L"VBoxVideoW8", L"VBoxWddm"
    };
    const ULONG kVBoxSourcesCount =
        sizeof(kVBoxSources) / sizeof(kVBoxSources[0]);

    bool found = false;
    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (!found &&
           pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK &&
           returned > 0)
    {
        VARIANT vtName;
        VariantInit(&vtName);
        if (SUCCEEDED(pObj->Get(L"FileName", 0, &vtName, nullptr, nullptr)) &&
            vtName.vt == VT_BSTR && vtName.bstrVal &&
            StrCmpIW(vtName.bstrVal, L"System") == 0)
        {
            VARIANT vtSources;
            VariantInit(&vtSources);
            if (SUCCEEDED(pObj->Get(L"Sources", 0, &vtSources, nullptr, nullptr)) &&
                vtSources.vt == (VT_BSTR | VT_ARRAY) && vtSources.parray)
            {
                BSTR* items = nullptr;
                if (SUCCEEDED(SafeArrayAccessData(vtSources.parray,
                                                   (void**)&items)))
                {
                    LONG lo = 0, hi = 0;
                    SafeArrayGetLBound(vtSources.parray, 1, &lo);
                    SafeArrayGetUBound(vtSources.parray, 1, &hi);
                    for (LONG i = lo; i <= hi && !found; ++i)
                    {
                        if (!items[i]) continue;
                        for (ULONG k = 0; k < kVBoxSourcesCount; ++k)
                            if (_wcsicmp(items[i], kVBoxSources[k]) == 0)
                            {
                                found = true;
                                break;
                            }
                    }
                    SafeArrayUnaccessData(vtSources.parray);
                }
            }
            VariantClear(&vtSources);
        }
        VariantClear(&vtName);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return found;
}

// ===========================================================================
// VMDriverServices — al-khaser pattern: enumerate driver services via
// EnumServicesStatusExW, return true iff any service name matches a
// well-known VBox/VMware driver list.  Hook patches the first character
// of the service name in the caller buffer so case-insensitive equality
// against the list no longer holds.
// ===========================================================================
static bool VMDriverServices()
{
    static const wchar_t* kKnownVMServices[] = {
        L"VBoxWddm",   L"VBoxSF",      L"VBoxMouse",
        L"VBoxGuest",  L"VBoxService", L"VBoxVideo",
        L"vmci",       L"vmhgfs",      L"vmmouse",
        L"vmmemctl",   L"vmusb",       L"vmusbmouse",
        L"vmx_svga",   L"vmxnet",      L"vmx86",
    };
    const int kKnownVMServicesCount =
        sizeof(kKnownVMServices) / sizeof(kKnownVMServices[0]);

    // SERVICES_ACTIVE_DATABASE is an ANSI-only literal in winsvc.h.
    // nullptr opens the default (active) database, which is exactly what
    // the al-khaser probe wants.
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr,
                                     SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return false;

    DWORD bytesNeeded = 0, count = 0, resumeHandle = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                          SERVICE_STATE_ALL, nullptr, 0,
                          &bytesNeeded, &count, &resumeHandle, nullptr);
    if (bytesNeeded == 0) { CloseServiceHandle(hSCM); return false; }

    std::vector<BYTE> buffer(bytesNeeded);
    BOOL ok = EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
                                     SERVICE_STATE_ALL, buffer.data(),
                                     (DWORD)buffer.size(), &bytesNeeded,
                                     &count, &resumeHandle, nullptr);
    bool found = false;
    if (ok)
    {
        auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < count && !found; ++i)
        {
            if (!services[i].lpServiceName) continue;
            for (int s = 0; s < kKnownVMServicesCount; ++s)
            {
                if (StrCmpIW(services[i].lpServiceName,
                             kKnownVMServices[s]) == 0)
                {
                    found = true;
                    break;
                }
            }
        }
    }
    CloseServiceHandle(hSCM);
    return found;
}

// ===========================================================================
// power_capabilities — al-khaser pattern: VM iff
//   none of SystemS1..S4 supported  AND  ThermalControl absent.
// Hook on GetPwrCapabilities forces SystemS3 + ThermalControl true.
// ===========================================================================
static bool power_capabilities()
{
    SYSTEM_POWER_CAPABILITIES caps = {};
    if (!GetPwrCapabilities(&caps)) return false;

    if ((caps.SystemS1 | caps.SystemS2 | caps.SystemS3 | caps.SystemS4) == FALSE)
        return (caps.ThermalControl == FALSE);
    return false;
}

// ===========================================================================
// vbox_firmware_SMBIOS — al-khaser pattern: pull the raw RSMB firmware
// table via GetSystemFirmwareTable, byte-search for "VirtualBox", "vbox",
// "VBOX".  Existing firmware hook replaces the SMBIOS buffer wholesale
// with a fake AMI table — no VBox strings remain.
// ===========================================================================
static bool find_substr(const BYTE* hay, DWORD hayLen,
                        const char* needle, size_t needleLen)
{
    if (hayLen < needleLen) return false;
    for (DWORD i = 0; i <= hayLen - needleLen; ++i)
        if (memcmp(hay + i, needle, needleLen) == 0)
            return true;
    return false;
}

static bool vbox_firmware_SMBIOS()
{
    DWORD bufSize = 4096;
    std::vector<BYTE> buffer(bufSize);
    DWORD result = GetSystemFirmwareTable('RSMB', 0x0000,
                                           buffer.data(), bufSize);
    if (result == 0) return false;
    if (result > bufSize)
    {
        buffer.resize(result);
        result = GetSystemFirmwareTable('RSMB', 0x0000,
                                         buffer.data(), result);
        if (result == 0) return false;
    }

    return find_substr(buffer.data(), result, "VirtualBox", 10) ||
           find_substr(buffer.data(), result, "vbox",       4)  ||
           find_substr(buffer.data(), result, "VBOX",       4);
}

// ===========================================================================
// number_SMBIOS_tables — al-khaser pattern: count the SMBIOS structures
// in the raw RSMB buffer; a count below ~7 is a strong VM indicator
// because real hardware exposes BIOS+System+Baseboard+Chassis+Processor+
// CacheL1/L2/L3+Memory devices+slots+ports… typically 20-30 entries.
// VBox/VMware guests ship with the bare minimum.
//
// Returns true (= "VM detected") if the count is below kThreshold.
// ===========================================================================
static int count_smbios_tables(const BYTE* buf, DWORD bufLen)
{
    // RawSMBIOSData header is 8 bytes; actual table data starts at +8.
    if (!buf || bufLen < 8) return 0;
    DWORD tableDataLen = *reinterpret_cast<const DWORD*>(buf + 4);
    if (tableDataLen == 0 || 8 + tableDataLen > bufLen)
        tableDataLen = bufLen - 8;

    const BYTE* p   = buf + 8;
    const BYTE* end = buf + 8 + tableDataLen;

    int count = 0;
    while (p + 4 <= end)
    {
        BYTE type   = p[0];
        BYTE length = p[1];
        if (length < 4) break;                   // malformed
        if (p + length > end) break;             // truncated

        // Skip formatted area, then walk the strings section to the
        // double-null that terminates it.
        const BYTE* s = p + length;
        while (s + 1 < end && !(s[0] == 0 && s[1] == 0)) ++s;
        if (s + 1 >= end) break;
        const BYTE* next = s + 2;

        ++count;
        if (type == 127) break;                  // end-of-table marker
        p = next;
    }
    return count;
}

static bool number_SMBIOS_tables()
{
    static const int kThreshold = 7;      // matches the al-khaser cutoff

    DWORD bufSize = 4096;
    std::vector<BYTE> buffer(bufSize);
    DWORD result = GetSystemFirmwareTable('RSMB', 0x0000,
                                           buffer.data(), bufSize);
    if (result == 0) return false;
    if (result > bufSize)
    {
        buffer.resize(result);
        result = GetSystemFirmwareTable('RSMB', 0x0000,
                                         buffer.data(), result);
        if (result == 0) return false;
    }

    int count = count_smbios_tables(buffer.data(), result);
    std::cout << "  [diag] SMBIOS table count = " << count
              << " (threshold = " << kThreshold << ")\n";
    return count < kThreshold;
}

// ===========================================================================
// Tests — first six expect external hook injection;
// Test_BiosComputerVideo manages its own hook lifecycle.
// ===========================================================================
void Test_HookNext()
{
    WPrintLine(L"\n--- Test_HookNext ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_ComputerSystem");
    if (!pEnum) { std::cerr << "FAIL: ExecQuery\n"; return; }

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
    pEnum->Release();

    bool hookSeen = LogContains(L"Next hooked");
    WPrintLine(hookSeen ? L"HOOK TEST PASS"
                        : L"HOOK TEST FAIL (no 'Next hooked' in log)");
}

void Test_FilterDeviceID()
{
    WPrintLine(L"\n--- Test_FilterDeviceID ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    const wchar_t* kTargetId = L"PCI\\VEN_80EE&DEV_CAFE";
    bool found = FindDeviceID(wmi, kTargetId);

    WPrint(found ? L"  [found]   " : L"  [hidden]  ");
    WPrintLine(kTargetId);

    WPrintLine(!found ? L"DEVICEID FILTER TEST PASS"
                      : L"DEVICEID FILTER TEST FAIL (device still visible)");
}

void Test_FilterPnPName()
{
    WPrintLine(L"\n--- Test_FilterPnPName ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    ULONG count = CountPnPEntities(wmi);
    std::cout << "  PnP entities visible: " << count << "\n";

    bool skipped = LogContains(L"FilterPnP: skipped");
    WPrintLine(skipped ? L"FILTER TEST PASS"
                       : L"FILTER TEST FAIL (no 'FilterPnP: skipped' in log)");
}

void Test_BaseBoardHook()
{
    WPrintLine(L"\n--- Test_BaseBoardHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    BaseBoardSnapshot snap;
    if (!QueryBaseBoard(wmi, snap))
    {
        std::cerr << "FAIL: Win32_BaseBoard query\n";
        return;
    }
    WPrint(L"  Product      : "); WPrintLine(snap.product.c_str());
    WPrint(L"  Manufacturer : "); WPrintLine(snap.manufacturer.c_str());

    bool pass = (snap.product      == L"Standard PC" &&
                 snap.manufacturer == L"Microsoft Corporation");
    WPrintLine(pass ? L"BASEBOARD HOOK TEST PASS"
                    : L"BASEBOARD HOOK TEST FAIL");
}

void Test_BusHook()
{
    WPrintLine(L"\n--- Test_BusHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    bool detected = VBoxBusCheck(wmi);
    std::cout << "  vbox_bus_wmi(): " << (detected ? "TRUE" : "FALSE") << "\n";

    WPrintLine(!detected ? L"BUS HOOK TEST PASS"
                         : L"BUS HOOK TEST FAIL (VBox bus signature still visible)");
}

void Test_PnPDeviceHook()
{
    WPrintLine(L"\n--- Test_PnPDeviceHook ---");

    WmiSession wmi;
    if (!wmi.Init()) { std::cerr << "FAIL: WMI init\n"; return; }

    bool vbox = HasVboxInPnPDeviceQuery(wmi);
    std::cout << "  Win32_PnPDevice VBOX visible: " << (vbox ? "YES" : "NO") << "\n";

    WPrintLine(!vbox ? L"PNPDEVICE HOOK TEST PASS"
                     : L"PNPDEVICE HOOK TEST FAIL (VBOX still visible)");
}

// ---------------------------------------------------------------------------
// Helpers that pull the raw WMI string a detector inspects, so the test
// can show *what* was checked alongside the Detected/Not detected verdict.
// ---------------------------------------------------------------------------
static std::wstring QuerySingleProp(WmiSession& wmi,
                                    const wchar_t* wql,
                                    const wchar_t* prop)
{
    std::wstring result;
    IEnumWbemClassObject* pEnum = wmi.ExecQuery(wql);
    if (!pEnum) return result;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(prop, 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            result = vt.bstrVal;
        }
        VariantClear(&vt);
        pObj->Release();
    }
    pEnum->Release();
    return result;
}

// Win32_VideoController may report multiple adapters — join them so the
// detector's view of the data is visible in full.
static std::wstring QueryAllCaptions(WmiSession& wmi)
{
    std::wstring result;
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT * FROM Win32_VideoController");
    if (!pEnum) return result;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"Caption", 0, &vt, nullptr, nullptr)) &&
            vt.vt == VT_BSTR && vt.bstrVal)
        {
            if (!result.empty()) result += L" | ";
            result += vt.bstrVal;
        }
        VariantClear(&vt);
        pObj->Release();
        pObj = nullptr;
    }
    pEnum->Release();
    return result;
}

// ---------------------------------------------------------------------------
// Test_BiosComputerVideo
//
// Runs the four al-khaser-style detectors and reports PASS iff every one
// of them returns "Not detected" — i.e. the externally injected hooks
// have rewritten BIOS.SerialNumber, ComputerSystem.Model/Manufacturer and
// VideoController.Caption away from the patterns al-khaser searches for.
//
// On bare-metal hardware that simply lacks those patterns (e.g. a Dell
// physical machine without Hyper-V), every detector will report "Not
// detected" *before* injection too — that is correct al-khaser behaviour,
// not a bug in the test.  The raw WMI values are printed alongside the
// verdict so you can see exactly what the detectors examined.
// ---------------------------------------------------------------------------
void Test_BiosComputerVideo()
{
    WPrintLine(L"\n--- Test_BiosComputerVideo ---");

    // Diagnostic: show the actual WMI strings the detectors look at.
    {
        WmiSession diag;
        if (diag.Init())
        {
            WPrint(L"    BIOS.SerialNumber          = ");
            WPrintLine(QuerySingleProp(diag,
                L"SELECT * FROM Win32_BIOS",            L"SerialNumber").c_str());
            WPrint(L"    ComputerSystem.Model       = ");
            WPrintLine(QuerySingleProp(diag,
                L"SELECT * FROM Win32_ComputerSystem",  L"Model").c_str());
            WPrint(L"    ComputerSystem.Manufacturer= ");
            WPrintLine(QuerySingleProp(diag,
                L"SELECT * FROM Win32_ComputerSystem",  L"Manufacturer").c_str());
            WPrint(L"    VideoController.Caption    = ");
            WPrintLine(QueryAllCaptions(diag).c_str());
        }
    }

    bool d1 = serial_number_bios_wmi();
    bool d2 = model_computer_system_wmi();
    bool d3 = manufacturer_computer_system_wmi();
    bool d4 = caption_video_controller_wmi();

    WPrint(L"    BIOS.SerialNumber          : ");
    WPrintLine(d1 ? L"Detected" : L"Not detected");
    WPrint(L"    ComputerSystem.Model       : ");
    WPrintLine(d2 ? L"Detected" : L"Not detected");
    WPrint(L"    ComputerSystem.Manufacturer: ");
    WPrintLine(d3 ? L"Detected" : L"Not detected");
    WPrint(L"    VideoController.Caption    : ");
    WPrintLine(d4 ? L"Detected" : L"Not detected");

    bool pass = !d1 && !d2 && !d3 && !d4;
    WPrintLine(pass ? L"BIOS/COMPUTER/VIDEO HOOK TEST PASS"
                    : L"BIOS/COMPUTER/VIDEO HOOK TEST FAIL");
}

// ---------------------------------------------------------------------------
// Test_NonEmptyClasses
//
// 16 al-khaser-style "is this class empty?" probes.  Each one returns
// true iff the WQL enumerator gave back 0 rows — a classic "must be a
// VM" heuristic, since these classes are populated on bare metal but
// often blank inside VirtualBox/VMware guests.
//
// With the injected ExecQuery+Next hooks active, every critical class
// gets one synthetic IWbemClassObject on first Next, so every probe
// should report "populated" and the test PASSes.
// ---------------------------------------------------------------------------
void Test_NonEmptyClasses()
{
    WPrintLine(L"\n--- Test_NonEmptyClasses ---");

    struct Probe { const wchar_t* name; bool (*fn)(); };
    static const Probe probes[] = {
        { L"Win32_Fan",                                                fan_wmi                   },
        { L"Win32_CacheMemory",                                        cachememory_wmi           },
        { L"Win32_PhysicalMemory",                                     physicalmemory_wmi        },
        { L"Win32_MemoryDevice",                                       memorydevice_wmi          },
        { L"Win32_MemoryArray",                                        memoryarray_wmi           },
        { L"Win32_VoltageProbe",                                       voltageprobe_wmi          },
        { L"Win32_PortConnector",                                      portconnector_wmi         },
        { L"Win32_SMBIOSMemory",                                       smbiosmemory_wmi          },
        { L"Win32_PerfFormattedData_Counters_ThermalZoneInformation",  thermalzone_wmi           },
        { L"CIM_Memory",                                               cim_memory_wmi            },
        { L"CIM_NumericSensor",                                        cim_numericsensor_wmi     },
        { L"CIM_PhysicalConnector",                                    cim_physicalconnector_wmi },
        { L"CIM_Sensor",                                               cim_sensor_wmi            },
        { L"CIM_Slot",                                                 cim_slot_wmi              },
        { L"CIM_TemperatureSensor",                                    cim_temperaturesensor_wmi },
        { L"CIM_VoltageSensor",                                        cim_voltagesensor_wmi     },
    };

    int empties = 0;
    for (const auto& p : probes)
    {
        bool empty = p.fn();
        WPrint(L"    ");
        WPrint(p.name);
        // pad-aligned column so verdicts line up visually
        for (size_t pad = wcslen(p.name); pad < 56; ++pad) WPrint(L" ");
        WPrint(L": ");
        WPrintLine(empty ? L"EMPTY (suspected VM)" : L"populated");
        if (empty) ++empties;
    }

    bool pass = (empties == 0);
    WPrintLine(pass ? L"NON-EMPTY HOOK TEST PASS"
                    : L"NON-EMPTY HOOK TEST FAIL");
}

// ---------------------------------------------------------------------------
// Test_ProcessorHook
//
//   number_cores_wmi()       → true if Win32_Processor.NumberOfCores < 2
//   process_id_processor_wmi → true if Win32_Processor.ProcessorId == NULL
//
// The injected hook spoofs both, so both must return false after
// injection.  PASS iff both report "Not detected".
// ---------------------------------------------------------------------------
void Test_ProcessorHook()
{
    WPrintLine(L"\n--- Test_ProcessorHook ---");

    bool d1 = number_cores_wmi();
    bool d2 = process_id_processor_wmi();

    WPrint(L"    Processor.NumberOfCores < 2  : ");
    WPrintLine(d1 ? L"Detected" : L"Not detected");
    WPrint(L"    Processor.ProcessorId == NULL: ");
    WPrintLine(d2 ? L"Detected" : L"Not detected");

    bool pass = !d1 && !d2;
    WPrintLine(pass ? L"PROCESSOR HOOK TEST PASS"
                    : L"PROCESSOR HOOK TEST FAIL");
}

// ---------------------------------------------------------------------------
// Test_DiskAndThermal
//
//   disk_size_wmi()                 → true if any Win32_LogicalDisk
//                                      has Size < 80 GB.
//   current_temperature_acpi_wmi()  → true if MSAcpi_ThermalZoneTemperature
//                                      query returned zero rows.
//                                      Requires admin to reach root\WMI;
//                                      without admin it can't connect
//                                      and returns false (not detected).
//
// PASS iff both probes report "Not detected".  Limited-rights users see
// the thermal probe as "Not detected" by virtue of the failed connect
// even with hooks off — that's the expected fallback path.
// ---------------------------------------------------------------------------
void Test_DiskAndThermal()
{
    WPrintLine(L"\n--- Test_DiskAndThermal ---");

    bool d1 = disk_size_wmi();
    bool d2 = current_temperature_acpi_wmi();

    WPrint(L"    LogicalDisk.Size < 80GB                  : ");
    WPrintLine(d1 ? L"Detected" : L"Not detected");
    WPrint(L"    MSAcpi_ThermalZoneTemperature empty/fail : ");
    WPrintLine(d2 ? L"Detected" : L"Not detected");

    bool pass = !d1 && !d2;
    WPrintLine(pass ? L"DISK/THERMAL HOOK TEST PASS"
                    : L"DISK/THERMAL HOOK TEST FAIL");
}

// ---------------------------------------------------------------------------
// Test_EventLogPowerServicesSmbios
//
// Four heterogeneous VM-fingerprint probes:
//   • vbox_eventlogfile_wmi   → WMI Win32_NTEventlogFile.Sources VBox names
//   • VMDriverServices        → EnumServicesStatusExW VBox/VMware drivers
//   • power_capabilities      → GetPwrCapabilities all-S-states-off + no thermal
//   • vbox_firmware_SMBIOS    → "VirtualBox" / "vbox" / "VBOX" in raw SMBIOS
//
// Each maps to a distinct hook (WMI dispatcher EventLog block,
// EnumServicesStatusExW patch, GetPwrCapabilities patch, existing
// GetSystemFirmwareTable replacement).  PASS iff all four report
// "Not detected".
// ---------------------------------------------------------------------------
void Test_EventLogPowerServicesSmbios()
{
    WPrintLine(L"\n--- Test_EventLogPowerServicesSmbios ---");

    bool d1 = vbox_eventlogfile_wmi();
    bool d2 = VMDriverServices();
    bool d3 = power_capabilities();
    bool d4 = vbox_firmware_SMBIOS();
    bool d5 = number_SMBIOS_tables();

    WPrint(L"    Win32_NTEventlogFile.Sources VBox        : ");
    WPrintLine(d1 ? L"Detected" : L"Not detected");
    WPrint(L"    EnumServicesStatusExW VM driver          : ");
    WPrintLine(d2 ? L"Detected" : L"Not detected");
    WPrint(L"    GetPwrCapabilities S-states+thermal off  : ");
    WPrintLine(d3 ? L"Detected" : L"Not detected");
    WPrint(L"    GetSystemFirmwareTable SMBIOS VBox string: ");
    WPrintLine(d4 ? L"Detected" : L"Not detected");
    WPrint(L"    GetSystemFirmwareTable SMBIOS table count: ");
    WPrintLine(d5 ? L"Detected" : L"Not detected");

    bool pass = !d1 && !d2 && !d3 && !d4 && !d5;
    WPrintLine(pass ? L"EVENTLOG/POWER/SERVICES/SMBIOS HOOK TEST PASS"
                    : L"EVENTLOG/POWER/SERVICES/SMBIOS HOOK TEST FAIL");
}

// ===========================================================================
// Pafish WMI probes — verbatim translation of the two WMI checks in
// pafish source (vbox.c / vmware.c).  Both expected to return false
// when the existing HooksBox WMI hooks are active:
//
//   pafish_vbox_wmi_devices  → defeated by Hook_Next_FilterPnP
//                               (drops Win32_PnPEntity rows whose
//                               DeviceID contains PCI\VEN_80EE&DEV_CAFE)
//
//   pafish_vmware_wmi_serial → defeated by Hook_DispatcherGet BIOS
//                               block (spoofs Win32_BIOS.SerialNumber
//                               to "System Serial")
//
// Pafish requests up to 10 rows per Next() call — Hook_Next_FilterPnP
// handles batch sizes correctly via its filter-and-repack loop.
// ===========================================================================

// pafish/vbox.c::vbox_wmi_devices
static bool pafish_vbox_wmi_devices()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT DeviceId FROM Win32_PnPEntity");
    if (!pEnum) return false;

    bool   found       = false;
    HRESULT lastResult = WBEM_S_NO_ERROR;
    IWbemClassObject* batch[10] = { nullptr };

    while (lastResult == WBEM_S_NO_ERROR && !found)
    {
        ULONG count = 0;
        lastResult = pEnum->Next(WBEM_INFINITE, 10, batch, &count);
        if (!SUCCEEDED(lastResult)) continue;
        if (count == 0) break;

        for (ULONG i = 0; i < count && !found; ++i)
        {
            VARIANT v;
            CIMTYPE t = CIM_ILLEGAL;
            VariantInit(&v);
            HRESULT hr = batch[i]->Get(L"DeviceId", 0, &v, &t, 0);
            if (SUCCEEDED(hr) && V_VT(&v) != VT_NULL && t == CIM_STRING)
            {
                if (wcsstr(V_BSTR(&v), L"PCI\\VEN_80EE&DEV_CAFE") != nullptr)
                    found = true;
            }
            VariantClear(&v);
            batch[i]->Release();
        }
    }
    pEnum->Release();
    return found;
}

// pafish/vmware.c::vmware_wmi_serial
static bool pafish_vmware_wmi_serial()
{
    WmiSession wmi;
    if (!wmi.Init()) return false;

    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT SerialNumber FROM Win32_Bios");
    if (!pEnum) return false;

    bool   found       = false;
    HRESULT lastResult = WBEM_S_NO_ERROR;
    IWbemClassObject* batch[10] = { nullptr };

    while (lastResult == WBEM_S_NO_ERROR && !found)
    {
        ULONG count = 0;
        lastResult = pEnum->Next(WBEM_INFINITE, 10, batch, &count);
        if (!SUCCEEDED(lastResult)) continue;
        if (count == 0) break;

        for (ULONG i = 0; i < count && !found; ++i)
        {
            VARIANT v;
            CIMTYPE t = CIM_ILLEGAL;
            VariantInit(&v);
            HRESULT hr = batch[i]->Get(L"SerialNumber", 0, &v, &t, 0);
            if (SUCCEEDED(hr) && V_VT(&v) != VT_NULL && t == CIM_STRING)
            {
                if (wcsstr(V_BSTR(&v), L"VMware") != nullptr)
                    found = true;
            }
            VariantClear(&v);
            batch[i]->Release();
        }
    }
    pEnum->Release();
    return found;
}

// ---------------------------------------------------------------------------
// Test_PafishWmi
//
// Runs both pafish WMI probes against the running WMI provider.
// Without injection both can detect a VBox guest; with injection both
// should return false thanks to the existing Hook_Next_FilterPnP +
// Hook_DispatcherGet (Bios) hooks.
// ---------------------------------------------------------------------------
void Test_PafishWmi()
{
    WPrintLine(L"\n--- Test_PafishWmi ---");

    bool d1 = pafish_vbox_wmi_devices();
    bool d2 = pafish_vmware_wmi_serial();

    WPrint(L"    pafish vbox_wmi_devices   (Win32_PnPEntity.DeviceId) : ");
    WPrintLine(d1 ? L"Detected" : L"Not detected");
    WPrint(L"    pafish vmware_wmi_serial  (Win32_Bios.SerialNumber)  : ");
    WPrintLine(d2 ? L"Detected" : L"Not detected");

    bool pass = !d1 && !d2;
    WPrintLine(pass ? L"PAFISH WMI HOOK TEST PASS"
                    : L"PAFISH WMI HOOK TEST FAIL");
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    WPrintLine(L"=== WMI hook test suite ===");
    WPrintLine(L"(hooks must be injected externally before this process starts)");

    Test_HookNext();
    Test_FilterDeviceID();
    Test_FilterPnPName();
    Test_BaseBoardHook();
    Test_BusHook();
    Test_PnPDeviceHook();
    Test_BiosComputerVideo();
    Test_NonEmptyClasses();
    Test_ProcessorHook();
    Test_DiskAndThermal();
    Test_EventLogPowerServicesSmbios();
    Test_PafishWmi();

    WPrintLine(L"\n--- Log file ---");
    PrintUtf8FileToConsole(L"sandbox_evasion.log");

    return 0;
}
