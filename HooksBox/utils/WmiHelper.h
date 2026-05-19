#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// ---------------------------------------------------------------------------
// File logger — writes to sandbox_evasion.log in the process working dir.
// Thread-safe; caller owns the CRITICAL_SECTION lifetime via WmiHelper.
// ---------------------------------------------------------------------------
#define LOG_INFO(msg)  WmiHelper::Log(L"INFO",  (msg))
#define LOG_WARN(msg)  WmiHelper::Log(L"WARN",  (msg))
#define LOG_ERROR(msg) WmiHelper::Log(L"ERROR", (msg))

class WmiHelper {
public:
    WmiHelper();
    ~WmiHelper();

    // Initialises COM (COINIT_MULTITHREADED) and connects to ROOT\CIMV2.
    // Must be called once before ExecQuery.  Returns false on any failure.
    bool Initialize();

    // Executes a WQL query.  Returns a forward-only enumerator; caller must
    // Release() it when done.  Returns nullptr on error.
    IEnumWbemClassObject* ExecQuery(const std::wstring& query);

    // Static so the LOG_* macros work without an instance pointer.
    static void Log(const wchar_t* level, const std::wstring& message);

    // Runs "mofcomp.exe <mofPath>", captures stdout+stderr, logs everything.
    // Returns true iff mofcomp exits with code 0.
    static bool CompileMOF(const wchar_t* mofPath);

    // Generates a MOF file in %TEMP% that declares an instance of
    // Win32_PnPEntity with the given DeviceID and newName, then compiles it.
    //
    // Win32_PnPEntity is a DYNAMIC class (CIMWin32 provider, all properties
    // read-only).  mofcomp validates syntax and exits 0, but the CIMWin32
    // provider rejects PutInstance at runtime, so the Name visible via WMI
    // queries will NOT change.  Use SetPnPDeviceNameViaRegistry for that.
    //
    // Returns true iff mofcomp exits with code 0 (syntax accepted).
    static bool SetPnPDeviceNameViaMof(const wchar_t* deviceId,
                                       const wchar_t* newName);

    // Writes newName to the FriendlyName registry value under
    //   HKLM\SYSTEM\CurrentControlSet\Enum\<deviceId>
    // This is the authoritative source for Win32_PnPEntity.Name.
    // Requires administrator privileges.  Returns true on success.
    static bool SetPnPDeviceNameViaRegistry(const wchar_t* deviceId,
                                            const wchar_t* newName);

    // Generates a MOF file in %TEMP% that declares an instance of
    // Win32_BaseBoard with the specified Product and Manufacturer, then
    // compiles it.  Win32_BaseBoard is a DYNAMIC class backed by the
    // CIMWin32 SMBIOS provider.  PutInstance is rejected by the provider
    // (WBEM_E_PROVIDER_NOT_CAPABLE, mofcomp exit 3), so WMI values do NOT
    // change.  Returns false for any real system (same limitation as
    // Win32_PnPEntity).  To suppress SMBIOS-based VM fingerprints, hook
    // the WMI COM interface or patch IWbemClassObject::Get.
    static bool MaskBaseBoardViaMof(const wchar_t* newProduct,
                                    const wchar_t* newManufacturer);

private:
    IWbemLocator*  m_pLocator;
    IWbemServices* m_pServices;
    bool           m_bInitialized;
    bool           m_bComInitialized;

    static CRITICAL_SECTION s_logCs;
    static LONG             s_logCsInit;   // guards one-time CS initialisation
};
