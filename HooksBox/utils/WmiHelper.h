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

private:
    IWbemLocator*  m_pLocator;
    IWbemServices* m_pServices;
    bool           m_bInitialized;
    bool           m_bComInitialized;

    static CRITICAL_SECTION s_logCs;
    static LONG             s_logCsInit;   // guards one-time CS initialisation
};
