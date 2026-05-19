#include "WmiHelper.h"
#include <iostream>
#include <string>

// ---------------------------------------------------------------------------
// Console helpers — use WriteConsoleW to display Unicode without codepage
// translation (avoids mojibake on OEM CP866 / CP437 consoles).
// ---------------------------------------------------------------------------
static HANDLE g_hOut = nullptr;

static void WPrint(const wchar_t* s)
{
    DWORD wr = 0;
    WriteConsoleW(g_hOut, s, (DWORD)wcslen(s), &wr, nullptr);
}

static void WPrintLine(const wchar_t* s)
{
    WPrint(s);
    WPrint(L"\n");
}

static void PrintResult(const char* label, bool ok)
{
    std::cout << label << ": " << (ok ? "PASS" : "FAIL") << "\n";
}

// ---------------------------------------------------------------------------
// Read the UTF-8 log file and display it via WriteConsoleW.
// ---------------------------------------------------------------------------
static void PrintUtf8FileToConsole(const wchar_t* path)
{
    HANDLE hFile = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Log file not found.\n";
        return;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::string raw(fileSize, '\0');
    DWORD bytesRead = 0;
    ReadFile(hFile, &raw[0], fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    raw.resize(bytesRead);
    if (raw.empty()) return;

    // Strip UTF-8 BOM if present.
    size_t offset = 0;
    if (raw.size() >= 3 &&
        (unsigned char)raw[0] == 0xEF &&
        (unsigned char)raw[1] == 0xBB &&
        (unsigned char)raw[2] == 0xBF)
        offset = 3;

    int wLen = MultiByteToWideChar(CP_UTF8, 0,
                                   raw.c_str() + offset,
                                   (int)(raw.size() - offset),
                                   nullptr, 0);
    if (wLen <= 0) return;

    std::wstring wide(wLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0,
                        raw.c_str() + offset,
                        (int)(raw.size() - offset),
                        &wide[0], wLen);

    DWORD wr = 0;
    WriteConsoleW(g_hOut, wide.c_str(), (DWORD)wide.size(), &wr, nullptr);
}

// ---------------------------------------------------------------------------
// WMI ExecQuery smoke test
// ---------------------------------------------------------------------------
static bool RunWmiQueryTest(WmiHelper& wmi)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Name FROM Win32_ComputerSystem");
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    if (SUCCEEDED(pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned)) && returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"Name", 0, &vt, 0, 0)))
        {
            WPrint(L"Computer name: ");
            WPrintLine(vt.bstrVal);
            VariantClear(&vt);
        }
        pObj->Release();
    }
    pEnum->Release();
    return true;
}

// ---------------------------------------------------------------------------
// Query Win32_PnPEntity.Name for a given DeviceID.
// Returns the Name, or empty string if not found.
// ---------------------------------------------------------------------------
static std::wstring QueryPnPName(WmiHelper& wmi, const wchar_t* deviceId)
{
    std::wstring query =
        std::wstring(L"SELECT Name FROM Win32_PnPEntity WHERE DeviceID='") +
        deviceId + L"'";

    IEnumWbemClassObject* pEnum = wmi.ExecQuery(query);
    if (!pEnum) return {};

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    std::wstring result;
    if (SUCCEEDED(pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned)) && returned > 0)
    {
        VARIANT vt;
        VariantInit(&vt);
        if (SUCCEEDED(pObj->Get(L"Name", 0, &vt, 0, 0)) && vt.vt == VT_BSTR)
            result = vt.bstrVal ? vt.bstrVal : L"";
        VariantClear(&vt);
        pObj->Release();
    }
    pEnum->Release();
    return result;
}

// ---------------------------------------------------------------------------
// Fetch the first available PnP device that has a DeviceID and Name.
// Returns false if none found.
// ---------------------------------------------------------------------------
static bool FindAnyPnPDevice(WmiHelper& wmi,
                              std::wstring& outDeviceId,
                              std::wstring& outName)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT DeviceID, Name FROM Win32_PnPEntity "
                      L"WHERE Name != NULL AND DeviceID != NULL");
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    bool found = false;
    while (!found &&
           SUCCEEDED(pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned)) &&
           returned > 0)
    {
        VARIANT vtId, vtName;
        VariantInit(&vtId);
        VariantInit(&vtName);
        if (SUCCEEDED(pObj->Get(L"DeviceID", 0, &vtId,   0, 0)) &&
            SUCCEEDED(pObj->Get(L"Name",     0, &vtName, 0, 0)) &&
            vtId.vt   == VT_BSTR && vtId.bstrVal   && vtId.bstrVal[0]   &&
            vtName.vt == VT_BSTR && vtName.bstrVal && vtName.bstrVal[0])
        {
            outDeviceId = vtId.bstrVal;
            outName     = vtName.bstrVal;
            found       = true;
        }
        VariantClear(&vtId);
        VariantClear(&vtName);
        pObj->Release();
    }
    pEnum->Release();
    return found;
}

// ---------------------------------------------------------------------------
// Win32_BaseBoard query helper
// ---------------------------------------------------------------------------
struct BaseBoardSnapshot
{
    std::wstring product;
    std::wstring manufacturer;
};

static bool QueryBaseBoard(WmiHelper& wmi, BaseBoardSnapshot& out)
{
    IEnumWbemClassObject* pEnum =
        wmi.ExecQuery(L"SELECT Product, Manufacturer FROM Win32_BaseBoard");
    if (!pEnum) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    bool found = false;
    if (SUCCEEDED(pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned)) && returned > 0)
    {
        VARIANT vtP, vtM;
        VariantInit(&vtP); VariantInit(&vtM);
        if (SUCCEEDED(pObj->Get(L"Product",      0, &vtP, 0, 0)) && vtP.vt == VT_BSTR)
            out.product      = vtP.bstrVal ? vtP.bstrVal : L"";
        if (SUCCEEDED(pObj->Get(L"Manufacturer", 0, &vtM, 0, 0)) && vtM.vt == VT_BSTR)
            out.manufacturer = vtM.bstrVal ? vtM.bstrVal : L"";
        VariantClear(&vtP);
        VariantClear(&vtM);
        pObj->Release();
        found = true;
    }
    pEnum->Release();
    return found;
}

static void PrintBaseBoard(const BaseBoardSnapshot& s, const wchar_t* label)
{
    WPrint(L"  "); WPrint(label); WPrint(L"\n");
    WPrint(L"    Product      : "); WPrintLine(s.product.c_str());
    WPrint(L"    Manufacturer : "); WPrintLine(s.manufacturer.c_str());
}

// ---------------------------------------------------------------------------
// MaskBaseBoardViaMof tests
//
// Win32_BaseBoard is a DYNAMIC class (CIMWin32, reads SMBIOS at query time).
// PutInstance is rejected — mofcomp exits 3 (WBEM_E_PROVIDER_NOT_CAPABLE).
// WMI values are unchanged before and after the MOF attempt.
// ---------------------------------------------------------------------------
static void RunBaseBoardTests(WmiHelper& wmi)
{
    std::cout << "\n--- MaskBaseBoardViaMof tests ---\n";

    // Validation: null inputs.
    PrintResult("BaseBoard null newProduct",
                !WmiHelper::MaskBaseBoardViaMof(nullptr, L"Microsoft Corporation"));
    PrintResult("BaseBoard null newManufacturer",
                !WmiHelper::MaskBaseBoardViaMof(L"Standard PC", nullptr));

    // Query current WMI state BEFORE the MOF attempt.
    BaseBoardSnapshot before;
    if (!QueryBaseBoard(wmi, before))
    {
        std::cout << "  SKIP: Win32_BaseBoard query failed\n";
        return;
    }
    PrintBaseBoard(before, L"Win32_BaseBoard BEFORE MOF:");

    // Apply substitution rules: "VirtualBox" → "Standard PC",
    // "Oracle Corporation" → "Microsoft Corporation".
    std::wstring newProduct      = before.product;
    std::wstring newManufacturer = before.manufacturer;

    if (newProduct.find(L"VirtualBox") != std::wstring::npos)
        newProduct = L"Standard PC";
    if (newManufacturer == L"Oracle Corporation")
        newManufacturer = L"Microsoft Corporation";

    // If values already clean, use fixed VM strings to exercise the path.
    if (newProduct == before.product && newManufacturer == before.manufacturer)
    {
        std::cout << "  (no VM strings detected — using fixed test values)\n";
        newProduct      = L"Standard PC";
        newManufacturer = L"Microsoft Corporation";
    }

    WPrint(L"  Substituted values:\n");
    WPrint(L"    Product      : "); WPrintLine(newProduct.c_str());
    WPrint(L"    Manufacturer : "); WPrintLine(newManufacturer.c_str());

    // Attempt MOF compilation — expected to fail (exit 3, dynamic class).
    bool mofFailed = !WmiHelper::MaskBaseBoardViaMof(
        newProduct.c_str(), newManufacturer.c_str());
    PrintResult("BaseBoard MOF rejected by provider (expected)", mofFailed);

    // Query WMI state AFTER the MOF attempt — must be unchanged.
    BaseBoardSnapshot after;
    QueryBaseBoard(wmi, after);
    PrintBaseBoard(after, L"Win32_BaseBoard AFTER MOF:");

    bool unchanged = (after.product == before.product &&
                      after.manufacturer == before.manufacturer);
    PrintResult("WMI values unchanged (expected)", unchanged);

    std::cout << "  => SMBIOS-backed dynamic class; MOF PutInstance always rejected.\n"
                 "     Real masking: hook IWbemClassObject::Get or patch SMBIOS buffer.\n";
}

// ---------------------------------------------------------------------------
// SetPnPDeviceNameViaMof tests
//
// Win32_PnPEntity is a DYNAMIC class — all properties carry [read : ToSubclass].
// mofcomp calls PutInstance on the CIMWin32 provider, which rejects it with
// WBEM_E_PROVIDER_NOT_CAPABLE (0x80041024) and exits with code 3.
// SetPnPDeviceNameViaMof therefore returns false for any real DeviceID.
// ---------------------------------------------------------------------------
static void RunMofRenameTests()
{
    std::cout << "\n--- SetPnPDeviceNameViaMof tests ---\n";

    // Test 1: null deviceId -> input validation, no disk I/O.
    PrintResult("MOF null deviceId",
                !WmiHelper::SetPnPDeviceNameViaMof(nullptr, L"Generic Device"));

    // Test 2: null newName -> same.
    PrintResult("MOF null newName",
                !WmiHelper::SetPnPDeviceNameViaMof(
                    L"USB\\VID_80EE&PID_CAFE\\1234", nullptr));

    // Test 3: valid-format DeviceID.
    // Expected: false — mofcomp exits 3 (WBEM_E_PROVIDER_NOT_CAPABLE).
    // The provider rejects PutInstance; MOF cannot modify dynamic classes.
    bool mofFailed = !WmiHelper::SetPnPDeviceNameViaMof(
        L"USB\\VID_80EE&PID_CAFE\\5&3A2A5854&0&4",
        L"Generic Device");
    PrintResult("MOF rejected by provider (expected)", mofFailed);

    std::cout << "  => mofcomp exit 3 = WBEM_E_PROVIDER_NOT_CAPABLE; "
                 "use SetPnPDeviceNameViaRegistry for real renames\n";
}

// ---------------------------------------------------------------------------
// SetPnPDeviceNameViaRegistry + verification tests
// ---------------------------------------------------------------------------
static void RunRegistryRenameTests(WmiHelper& wmi)
{
    std::cout << "\n--- SetPnPDeviceNameViaRegistry tests ---\n";

    // Test 1: null inputs.
    PrintResult("Registry null deviceId",
                !WmiHelper::SetPnPDeviceNameViaRegistry(nullptr, L"Generic Device"));
    PrintResult("Registry null newName",
                !WmiHelper::SetPnPDeviceNameViaRegistry(
                    L"USB\\VID_80EE&PID_CAFE\\1234", nullptr));

    // Test 2: non-existent device ID -> registry key not found -> false.
    PrintResult("Registry nonexistent DeviceID",
                !WmiHelper::SetPnPDeviceNameViaRegistry(
                    L"NONEXISTENT\\DEVICE\\00000000",
                    L"Generic Device"));

    // Test 3: real device — rename, verify via WMI, restore original name.
    std::wstring deviceId, originalName;
    if (!FindAnyPnPDevice(wmi, deviceId, originalName))
    {
        std::cout << "Registry real device: SKIP (no PnP device found via WMI)\n";
        return;
    }

    WPrint(L"Registry test device: ");
    WPrintLine(deviceId.c_str());
    WPrint(L"  Original Name : ");
    WPrintLine(originalName.c_str());

    // 3a. Rename to "Generic Device".
    const wchar_t* kNewName = L"Generic Device";
    bool renameOk = WmiHelper::SetPnPDeviceNameViaRegistry(
        deviceId.c_str(), kNewName);
    PrintResult("Registry rename to Generic Device", renameOk);

    if (renameOk)
    {
        // 3b. Verify: WMI must now return "Generic Device".
        // Note: WMI caches provider data; a re-query on the same IWbemServices
        // should reflect the updated FriendlyName immediately for most devices.
        std::wstring nameAfter = QueryPnPName(wmi, deviceId.c_str());
        WPrint(L"  Name after rename : ");
        WPrintLine(nameAfter.c_str());
        bool verified = (nameAfter == kNewName);
        PrintResult("WMI reports Generic Device", verified);
        if (!verified)
            std::cout << "  (WMI may cache; reboot or device re-enumeration needed)\n";

        // 3c. Restore original name so the test is non-destructive.
        bool restoreOk = WmiHelper::SetPnPDeviceNameViaRegistry(
            deviceId.c_str(), originalName.c_str());
        PrintResult("Restore original name", restoreOk);

        std::wstring nameRestored = QueryPnPName(wmi, deviceId.c_str());
        WPrint(L"  Name after restore: ");
        WPrintLine(nameRestored.c_str());
    }
    else
    {
        std::cout << "  (rename skipped — likely need admin rights)\n";
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    g_hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    std::cout << "=== WmiHelper test suite ===\n\n";

    WmiHelper wmi;
    if (!wmi.Initialize())
    {
        std::cerr << "Failed to initialize WMI.\n";
        return 1;
    }

    std::cout << "--- WMI query test ---\n";
    PrintResult("WMI ExecQuery", RunWmiQueryTest(wmi));

    RunBaseBoardTests(wmi);
    RunMofRenameTests();
    RunRegistryRenameTests(wmi);

    LOG_INFO(L"Test suite completed.");

    std::cout << "\n--- Log file contents ---\n";
    PrintUtf8FileToConsole(L"sandbox_evasion.log");

    return 0;
}
