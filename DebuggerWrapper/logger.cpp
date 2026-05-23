#include "logger.h"

#include <cstdarg>
#include <cstdio>
#include <vector>
#include <iostream>

namespace dbgwrap {

Logger& Logger::Instance() {
    static Logger inst;
    return inst;
}

void Logger::Init(const std::wstring& logFile, LogLevel level, bool alsoStdout) {
    if (!csInited_) {
        InitializeCriticalSection(&cs_);
        csInited_ = true;
    }
    level_      = level;
    alsoStdout_ = alsoStdout;

    if (file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }

    if (!logFile.empty()) {
        file_ = CreateFileW(logFile.c_str(),
                            GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
    }
}

void Logger::Shutdown() {
    if (file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
    if (csInited_) {
        DeleteCriticalSection(&cs_);
        csInited_ = false;
    }
}

static const wchar_t* LevelTag(LogLevel l) {
    switch (l) {
    case LogLevel::Error: return L"ERROR";
    case LogLevel::Info:  return L"INFO";
    case LogLevel::Debug: return L"DEBUG";
    }
    return L"?";
}

static std::string Utf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

void Logger::Log(LogLevel lvl, const wchar_t* component, const wchar_t* fmt, ...) {
    if (static_cast<int>(lvl) > static_cast<int>(level_)) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    int n = _vscwprintf(fmt, args_copy);
    va_end(args_copy);

    std::wstring buf;
    if (n > 0) {
        buf.resize(static_cast<size_t>(n));
        _vsnwprintf_s(buf.data(), buf.size() + 1, _TRUNCATE, fmt, args);
    }
    va_end(args);

    WriteLine(lvl, component, buf);
}

void Logger::WriteLine(LogLevel lvl, const wchar_t* component, const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t prefix[96];
    swprintf_s(prefix,
        L"[%04d-%02d-%02d %02d:%02d:%02d.%03d][%-5s][%s] ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        LevelTag(lvl),
        component ? component : L"-");

    std::wstring line = std::wstring(prefix) + msg + L"\n";
    std::string utf8 = Utf8(line.c_str());

    if (csInited_) EnterCriticalSection(&cs_);

    if (file_ != INVALID_HANDLE_VALUE) {
        if (!bomWritten_) {
            DWORD wr = 0;
            const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
            WriteFile(file_, bom, sizeof(bom), &wr, nullptr);
            bomWritten_ = true;
        }
        DWORD wr = 0;
        WriteFile(file_, utf8.c_str(), static_cast<DWORD>(utf8.size()), &wr, nullptr);
    }

    if (alsoStdout_) {
        // stdout — keep wide so non-ASCII renders if the console is set up for it.
        fputws(line.c_str(), stdout);
        fflush(stdout);
    }

    if (csInited_) LeaveCriticalSection(&cs_);
}

std::wstring FormatWinError(DWORD err) {
    LPWSTR msg = nullptr;
    DWORD n = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&msg),
        0,
        nullptr);

    std::wstring out;
    if (n && msg) {
        out.assign(msg, n);
        // FormatMessage often appends \r\n
        while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n' || out.back() == L' '))
            out.pop_back();
    } else {
        out = L"<no description>";
    }
    if (msg) LocalFree(msg);

    wchar_t buf[32];
    swprintf_s(buf, L" (0x%08X)", err);
    out += buf;
    return out;
}

} // namespace dbgwrap
