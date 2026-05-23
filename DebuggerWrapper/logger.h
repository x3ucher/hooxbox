#ifndef DBGWRAPPER_LOGGER_H
#define DBGWRAPPER_LOGGER_H

#include <windows.h>
#include <string>
#include <cstdint>

namespace dbgwrap {

enum class LogLevel : int {
    Error = 0,
    Info  = 1,
    Debug = 2,
};

class Logger {
public:
    static Logger& Instance();

    void Init(const std::wstring& logFile, LogLevel level, bool alsoStdout);
    void Shutdown();

    void Log(LogLevel lvl, const wchar_t* component, const wchar_t* fmt, ...);

    LogLevel CurrentLevel() const { return level_; }

private:
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void WriteLine(LogLevel lvl, const wchar_t* component, const std::wstring& msg);

    HANDLE          file_       = INVALID_HANDLE_VALUE;
    CRITICAL_SECTION cs_        = {};
    bool            csInited_   = false;
    bool            alsoStdout_ = true;
    LogLevel        level_      = LogLevel::Info;
    bool            bomWritten_ = false;
};

// Convenience macros — keep call sites compact and machine-greppable.
// Format: [YYYY-MM-DD HH:MM:SS.mmm][LEVEL][component] message
#define DBG_LOG_E(comp, fmt, ...) ::dbgwrap::Logger::Instance().Log(::dbgwrap::LogLevel::Error, comp, fmt, __VA_ARGS__)
#define DBG_LOG_I(comp, fmt, ...) ::dbgwrap::Logger::Instance().Log(::dbgwrap::LogLevel::Info,  comp, fmt, __VA_ARGS__)
#define DBG_LOG_D(comp, fmt, ...) ::dbgwrap::Logger::Instance().Log(::dbgwrap::LogLevel::Debug, comp, fmt, __VA_ARGS__)

std::wstring FormatWinError(DWORD err);

} // namespace dbgwrap

#endif // DBGWRAPPER_LOGGER_H
