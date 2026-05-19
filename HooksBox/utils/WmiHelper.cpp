#include "WmiHelper.h"

// ---------------------------------------------------------------------------
// Statics
// ---------------------------------------------------------------------------
CRITICAL_SECTION WmiHelper::s_logCs;
LONG             WmiHelper::s_logCsInit = 0;

static const wchar_t* k_LogPath = L"sandbox_evasion.log";

// ---------------------------------------------------------------------------
// Internal helper — converts a wide string to a UTF-8 std::string.
// ---------------------------------------------------------------------------
static std::string ToUtf8(const wchar_t* wide)
{
    if (!wide || wide[0] == L'\0') return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string buf(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &buf[0], n, nullptr, nullptr);
    buf.resize(buf.size() - 1); // strip null terminator
    return buf;
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
void WmiHelper::Log(const wchar_t* level, const std::wstring& message)
{
    // One-time CRITICAL_SECTION initialisation (safe for concurrent callers).
    if (InterlockedCompareExchange(&s_logCsInit, 1, 0) == 0)
        InitializeCriticalSection(&s_logCs);

    SYSTEMTIME st = {};
    GetLocalTime(&st);

    // Build the log line as UTF-8.
    std::string narrowLevel   = ToUtf8(level);
    std::string narrowMessage = ToUtf8(message.c_str());

    char lineBuf[2048];
    int  lineLen = _snprintf_s(lineBuf, sizeof(lineBuf), _TRUNCATE,
        "[%04d-%02d-%02d %02d:%02d:%02d] [%-5s] %s\r\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        narrowLevel.c_str(), narrowMessage.c_str());

    if (lineLen <= 0) return;

    EnterCriticalSection(&s_logCs);

    HANDLE hFile = CreateFileW(
        k_LogPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwWritten = 0;
        WriteFile(hFile, lineBuf, static_cast<DWORD>(lineLen), &dwWritten, nullptr);
        CloseHandle(hFile);
    }

    LeaveCriticalSection(&s_logCs);
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
WmiHelper::WmiHelper()
    : m_pLocator(nullptr)
    , m_pServices(nullptr)
    , m_bInitialized(false)
    , m_bComInitialized(false)
{
}

WmiHelper::~WmiHelper()
{
    if (m_pServices) { m_pServices->Release(); m_pServices = nullptr; }
    if (m_pLocator)  { m_pLocator->Release();  m_pLocator  = nullptr; }
    if (m_bComInitialized) CoUninitialize();
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------
bool WmiHelper::Initialize()
{
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        LOG_ERROR(L"CoInitializeEx failed: 0x" + std::to_wstring(static_cast<DWORD>(hr)));
        return false;
    }
    m_bComInitialized = SUCCEEDED(hr);

    hr = CoInitializeSecurity(
        nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    // RPC_E_TOO_LATE means security was already set — acceptable in a DLL.
    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        LOG_WARN(L"CoInitializeSecurity non-fatal: 0x" + std::to_wstring(static_cast<DWORD>(hr)));
    }

    hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<void**>(&m_pLocator));

    if (FAILED(hr))
    {
        LOG_ERROR(L"CoCreateInstance(IWbemLocator) failed: 0x" + std::to_wstring(static_cast<DWORD>(hr)));
        return false;
    }

    hr = m_pLocator->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr, nullptr, nullptr,
        0L, nullptr, nullptr,
        &m_pServices);

    if (FAILED(hr))
    {
        LOG_ERROR(L"ConnectServer(ROOT\\CIMV2) failed: 0x" + std::to_wstring(static_cast<DWORD>(hr)));
        return false;
    }

    hr = CoSetProxyBlanket(
        m_pServices,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);

    if (FAILED(hr))
        LOG_WARN(L"CoSetProxyBlanket failed (non-fatal): 0x" + std::to_wstring(static_cast<DWORD>(hr)));

    m_bInitialized = true;
    LOG_INFO(L"WMI ready — connected to ROOT\\CIMV2");
    return true;
}

// ---------------------------------------------------------------------------
// ExecQuery
// Caller must Release() the returned enumerator when done.
// ---------------------------------------------------------------------------
IEnumWbemClassObject* WmiHelper::ExecQuery(const std::wstring& query)
{
    if (!m_bInitialized)
    {
        LOG_ERROR(L"ExecQuery called before Initialize()");
        return nullptr;
    }

    IEnumWbemClassObject* pEnum = nullptr;
    HRESULT hr = m_pServices->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnum);

    if (FAILED(hr))
    {
        LOG_ERROR(L"ExecQuery failed [" + query + L"]: 0x" + std::to_wstring(static_cast<DWORD>(hr)));
        return nullptr;
    }

    LOG_INFO(L"ExecQuery OK: " + query);
    return pEnum;
}

// ---------------------------------------------------------------------------
// CompileMOF
// Launches "mofcomp.exe <mofPath>", captures combined stdout/stderr via a pipe,
// converts OEM output to UTF-8 for the log, and returns true on exit code 0.
// ---------------------------------------------------------------------------
bool WmiHelper::CompileMOF(const wchar_t* mofPath)
{
    if (!mofPath || mofPath[0] == L'\0')
    {
        LOG_ERROR(L"CompileMOF: mofPath is null or empty");
        return false;
    }

    std::wstring cmdLine = L"mofcomp.exe \"";
    cmdLine += mofPath;
    cmdLine += L'"';

    LOG_INFO(L"CompileMOF: running -> " + cmdLine);

    // Inheritable pipe: child writes, we read.
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;

    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        LOG_ERROR(L"CompileMOF: CreatePipe failed, GLE=" + std::to_wstring(GetLastError()));
        return false;
    }
    // Read end must not be inherited by the child.
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si  = {};
    si.cb            = sizeof(si);
    si.dwFlags       = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow   = SW_HIDE;
    si.hStdOutput    = hWrite;
    si.hStdError     = hWrite;   // merge stderr into stdout
    si.hStdInput     = nullptr;

    PROCESS_INFORMATION pi = {};

    BOOL created = CreateProcessW(
        nullptr,
        &cmdLine[0],      // CreateProcessW may modify the buffer
        nullptr, nullptr,
        TRUE,             // inherit handles
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    CloseHandle(hWrite);  // close child's write-end before reading

    if (!created)
    {
        DWORD gle = GetLastError();
        CloseHandle(hRead);
        LOG_ERROR(L"CompileMOF: CreateProcess failed, GLE=" + std::to_wstring(gle));
        return false;
    }

    // Drain the pipe until the child closes its write-end.
    std::string rawOutput;
    char buf[4096];
    DWORD dwRead = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &dwRead, nullptr) && dwRead > 0)
        rawOutput.append(buf, dwRead);
    CloseHandle(hRead);

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // mofcomp writes its own messages in CP_OEMCP (OEM codepage), but WMI
    // error descriptions embedded in the same output use CP_ACP (ANSI).
    // On Russian Windows: OEM=CP866, ANSI=CP1251 — different encodings.
    // We decode line-by-line: try OEM first; if the result contains box-drawing
    // characters (U+2500–U+257F), those bytes are actually CP1251, so re-decode
    // that line with CP_ACP.  Mixed lines (OEM prefix + CP1251 WMI error suffix)
    // cannot be fully fixed — the CP1251 portion will be readable, OEM prefix wrong.
    if (!rawOutput.empty())
    {
        auto decodeSlice = [](const char* p, int len, UINT cp) -> std::wstring {
            int n = MultiByteToWideChar(cp, 0, p, len, nullptr, 0);
            if (n <= 0) return {};
            std::wstring w(n, L'\0');
            MultiByteToWideChar(cp, 0, p, len, &w[0], n);
            return w;
        };
        auto hasBoxDrawing = [](const std::wstring& s) {
            for (wchar_t c : s)
                if (c >= 0x2500 && c <= 0x257F) return true;
            return false;
        };

        std::wstring wOutput;
        const char* p   = rawOutput.c_str();
        const char* end = p + rawOutput.size();
        while (p < end)
        {
            const char* nl = p;
            while (nl < end && *nl != '\n') ++nl;

            int rawLen = (int)(nl - p);
            int decLen = (rawLen > 0 && p[rawLen - 1] == '\r') ? rawLen - 1 : rawLen;

            if (decLen > 0)
            {
                std::wstring line = decodeSlice(p, decLen, CP_OEMCP);
                if (hasBoxDrawing(line))
                    line = decodeSlice(p, decLen, CP_ACP);
                wOutput += line;
            }
            wOutput += L'\n';
            p = nl + (nl < end ? 1 : 0);
        }

        while (!wOutput.empty() &&
               (wOutput.back() == L'\r' || wOutput.back() == L'\n'))
            wOutput.pop_back();

        if (!wOutput.empty())
            LOG_INFO(L"CompileMOF output: " + wOutput);
    }

    if (exitCode == 0)
    {
        LOG_INFO(L"CompileMOF: SUCCESS (exit 0) -> " + std::wstring(mofPath));
        return true;
    }

    LOG_ERROR(L"CompileMOF: FAILED (exit " + std::to_wstring(exitCode) +
              L") -> " + std::wstring(mofPath));
    return false;
}

// ---------------------------------------------------------------------------
// Internal helpers for MOF generation
// ---------------------------------------------------------------------------

// Escapes a wide string for embedding as a MOF string literal.
// MOF uses backslash as escape: \\ = one \, \" = one ".
static std::wstring EscapeForMof(const wchar_t* s)
{
    std::wstring out;
    for (const wchar_t* p = s; p && *p; ++p)
    {
        if      (*p == L'\\') out += L"\\\\";
        else if (*p == L'"')  out += L"\\\"";
        else                  out += *p;
    }
    return out;
}

// Writes a wide string to a file as UTF-8 bytes.
static bool WriteUtf8File(const wchar_t* path, const std::wstring& content)
{
    int cb = WideCharToMultiByte(CP_UTF8, 0,
                                 content.c_str(), (int)content.size(),
                                 nullptr, 0, nullptr, nullptr);
    if (cb <= 0) return false;

    std::string utf8(cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0,
                        content.c_str(), (int)content.size(),
                        &utf8[0], cb, nullptr, nullptr);

    HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL ok = WriteFile(hf, utf8.c_str(), (DWORD)utf8.size(), &written, nullptr);
    CloseHandle(hf);
    return ok && written == (DWORD)utf8.size();
}

// ---------------------------------------------------------------------------
// SetPnPDeviceNameViaMof
//
// Example of generated MOF (DeviceID = "USB\VID_80EE&PID_CAFE\1234"):
//
//   #pragma autorecover
//   #pragma namespace("\\\\.\\Root\\CIMV2")
//
//   instance of Win32_PnPEntity
//   {
//       DeviceID = "USB\\VID_80EE&PID_CAFE\\1234";
//       Name     = "Generic Device";
//   };
//
// Win32_PnPEntity is a DYNAMIC class (CIMWin32 provider).  All properties
// carry [read : ToSubclass] — the provider rejects PutInstance with
// WBEM_E_PROVIDER_NOT_CAPABLE (0x80041024), so mofcomp exits with code 3.
// This function therefore returns false for any real DeviceID.
// Use SetPnPDeviceNameViaRegistry to actually change what WMI returns.
// ---------------------------------------------------------------------------
bool WmiHelper::SetPnPDeviceNameViaMof(const wchar_t* deviceId,
                                       const wchar_t* newName)
{
    if (!deviceId || deviceId[0] == L'\0' || !newName || newName[0] == L'\0')
    {
        LOG_ERROR(L"SetPnPDeviceNameViaMof: deviceId or newName is null/empty");
        return false;
    }

    wchar_t tmpDir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmpDir))
    {
        LOG_ERROR(L"SetPnPDeviceNameViaMof: GetTempPathW failed, GLE=" +
                  std::to_wstring(GetLastError()));
        return false;
    }
    std::wstring mofPath = std::wstring(tmpDir) + L"wmihelper_pnp_rename.mof";

    // Namespace path \\.\Root\CIMV2 — each \ becomes \\ in MOF string literal.
    std::wstring nsPath = L"\\\\.\\Root\\CIMV2"; // C++ literal = \\.\Root\CIMV2

    std::wstring mof;
    mof += L"// Auto-generated by WmiHelper::SetPnPDeviceNameViaMof\r\n";
    mof += L"// Win32_PnPEntity is dynamic; provider rejects PutInstance\r\n";
    mof += L"// (WBEM_E_PROVIDER_NOT_CAPABLE, exit 3).  Name does not change.\r\n\r\n";
    mof += L"#pragma autorecover\r\n";
    mof += L"#pragma namespace(\"" + EscapeForMof(nsPath.c_str()) + L"\")\r\n\r\n";
    mof += L"instance of Win32_PnPEntity\r\n";
    mof += L"{\r\n";
    mof += L"    DeviceID = \"" + EscapeForMof(deviceId) + L"\";\r\n";
    mof += L"    Name     = \"" + EscapeForMof(newName)  + L"\";\r\n";
    mof += L"};\r\n";

    LOG_INFO(L"SetPnPDeviceNameViaMof: writing -> " + mofPath);
    LOG_INFO(L"SetPnPDeviceNameViaMof: DeviceID=" + std::wstring(deviceId) +
             L" | NewName=" + std::wstring(newName));

    if (!WriteUtf8File(mofPath.c_str(), mof))
    {
        LOG_ERROR(L"SetPnPDeviceNameViaMof: WriteUtf8File failed, GLE=" +
                  std::to_wstring(GetLastError()));
        return false;
    }

    bool ok = CompileMOF(mofPath.c_str());
    DeleteFileW(mofPath.c_str());

    if (ok)
        LOG_INFO(L"SetPnPDeviceNameViaMof: mofcomp accepted (exit 0)");
    else
        LOG_WARN(L"SetPnPDeviceNameViaMof: mofcomp failed — expected for dynamic "
                 L"Win32_PnPEntity (WBEM_E_PROVIDER_NOT_CAPABLE)");

    return ok;
}

// ---------------------------------------------------------------------------
// SetPnPDeviceNameViaRegistry
//
// Win32_PnPEntity.Name is resolved by the CIMWin32 provider from:
//   HKLM\SYSTEM\CurrentControlSet\Enum\<DeviceID>\FriendlyName  (preferred)
//   HKLM\SYSTEM\CurrentControlSet\Enum\<DeviceID>\DeviceDesc    (fallback)
//
// Writing FriendlyName is the correct way to change what WMI reports.
// The DeviceID in WMI ("USB\VID_xxx\...") maps directly to the registry
// path under HKLM\SYSTEM\CurrentControlSet\Enum\.
// Requires administrator privileges.
// ---------------------------------------------------------------------------
bool WmiHelper::SetPnPDeviceNameViaRegistry(const wchar_t* deviceId,
                                            const wchar_t* newName)
{
    if (!deviceId || deviceId[0] == L'\0' || !newName || newName[0] == L'\0')
    {
        LOG_ERROR(L"SetPnPDeviceNameViaRegistry: deviceId or newName is null/empty");
        return false;
    }

    std::wstring regPath =
        std::wstring(L"SYSTEM\\CurrentControlSet\\Enum\\") + deviceId;

    HKEY hKey = nullptr;
    LONG res = RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(),
                              0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS)
    {
        LOG_ERROR(L"SetPnPDeviceNameViaRegistry: RegOpenKeyEx failed "
                  L"(not found or no admin rights), path=" + regPath +
                  L", error=" + std::to_wstring(res));
        return false;
    }

    DWORD cbValue = static_cast<DWORD>((wcslen(newName) + 1) * sizeof(wchar_t));
    res = RegSetValueExW(hKey, L"FriendlyName", 0, REG_SZ,
                          reinterpret_cast<const BYTE*>(newName), cbValue);
    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS)
    {
        LOG_ERROR(L"SetPnPDeviceNameViaRegistry: RegSetValueEx failed, error=" +
                  std::to_wstring(res));
        return false;
    }

    LOG_INFO(L"SetPnPDeviceNameViaRegistry: FriendlyName set to \"" +
             std::wstring(newName) + L"\" for DeviceID=" + std::wstring(deviceId));
    return true;
}

// ---------------------------------------------------------------------------
// MaskBaseBoardViaMof
//
// Generated MOF example (newProduct="Standard PC",
//                         newManufacturer="Microsoft Corporation"):
//
//   #pragma autorecover
//   #pragma namespace("\\\\.\\Root\\CIMV2")
//
//   instance of Win32_BaseBoard
//   {
//       Tag          = "Base Board";
//       Product      = "Standard PC";
//       Manufacturer = "Microsoft Corporation";
//   };
//
// Win32_BaseBoard is a DYNAMIC class.  CIMWin32 reads Product and
// Manufacturer from SMBIOS at query time.  PutInstance is rejected with
// WBEM_E_PROVIDER_NOT_CAPABLE (0x80041024), mofcomp exits 3 → false.
// "Tag" is the [key] property; "Base Board" is the standard value for the
// primary baseboard (CIM_PhysicalElement.Tag).
// ---------------------------------------------------------------------------
bool WmiHelper::MaskBaseBoardViaMof(const wchar_t* newProduct,
                                    const wchar_t* newManufacturer)
{
    if (!newProduct      || newProduct[0]      == L'\0' ||
        !newManufacturer || newManufacturer[0] == L'\0')
    {
        LOG_ERROR(L"MaskBaseBoardViaMof: newProduct or newManufacturer is null/empty");
        return false;
    }

    wchar_t tmpDir[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmpDir))
    {
        LOG_ERROR(L"MaskBaseBoardViaMof: GetTempPathW failed, GLE=" +
                  std::to_wstring(GetLastError()));
        return false;
    }
    std::wstring mofPath = std::wstring(tmpDir) + L"wmihelper_baseboard_mask.mof";

    std::wstring nsPath = L"\\\\.\\Root\\CIMV2"; // C++ literal = \\.\Root\CIMV2

    std::wstring mof;
    mof += L"// Auto-generated by WmiHelper::MaskBaseBoardViaMof\r\n";
    mof += L"// Win32_BaseBoard is dynamic (CIMWin32/SMBIOS).\r\n";
    mof += L"// Provider rejects PutInstance (WBEM_E_PROVIDER_NOT_CAPABLE, exit 3).\r\n";
    mof += L"// Hook WMI COM or IWbemClassObject::Get for real masking.\r\n\r\n";
    mof += L"#pragma autorecover\r\n";
    mof += L"#pragma namespace(\"" + EscapeForMof(nsPath.c_str()) + L"\")\r\n\r\n";
    mof += L"instance of Win32_BaseBoard\r\n";
    mof += L"{\r\n";
    mof += L"    Tag          = \"Base Board\";\r\n";
    mof += L"    Product      = \"" + EscapeForMof(newProduct)      + L"\";\r\n";
    mof += L"    Manufacturer = \"" + EscapeForMof(newManufacturer) + L"\";\r\n";
    mof += L"};\r\n";

    LOG_INFO(L"MaskBaseBoardViaMof: writing -> " + mofPath);
    LOG_INFO(L"MaskBaseBoardViaMof: Product=" + std::wstring(newProduct) +
             L" | Manufacturer=" + std::wstring(newManufacturer));

    if (!WriteUtf8File(mofPath.c_str(), mof))
    {
        LOG_ERROR(L"MaskBaseBoardViaMof: WriteUtf8File failed, GLE=" +
                  std::to_wstring(GetLastError()));
        return false;
    }

    bool ok = CompileMOF(mofPath.c_str());
    DeleteFileW(mofPath.c_str());

    if (ok)
        LOG_INFO(L"MaskBaseBoardViaMof: mofcomp accepted (exit 0)");
    else
        LOG_WARN(L"MaskBaseBoardViaMof: mofcomp failed — expected for dynamic "
                 L"Win32_BaseBoard (WBEM_E_PROVIDER_NOT_CAPABLE)");

    return ok;
}
