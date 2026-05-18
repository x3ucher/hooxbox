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
