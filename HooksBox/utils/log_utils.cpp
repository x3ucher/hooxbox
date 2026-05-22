#include "log_utils.h"
#include <iostream>

void DebugPrint(const char* text) {
    OutputDebugStringA(text);
    OutputDebugStringA("\n");
    //std::cout << text << std::endl;
}

void DebugPrintW(const wchar_t* text) {
    OutputDebugStringW(text);
    OutputDebugStringW(L"\n");
    //std::cout << text << std::endl;
}

bool EqualsCaseInsensitive(const std::wstring& str1, const std::wstring& str2) {
    if (str1.length() != str2.length())
        return false;

    for (size_t i = 0; i < str1.length(); ++i)
    {
        if (std::towlower(str1[i]) != std::towlower(str2[i]))
            return false;
    }
    return true;
}

// File logger — thread-safe UTF-8 writer for sandbox_evasion.log
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

void WriteFileLog(const wchar_t* level, const std::wstring& msg)
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
