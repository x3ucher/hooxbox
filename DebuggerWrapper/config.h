#ifndef DBGWRAPPER_CONFIG_H
#define DBGWRAPPER_CONFIG_H

#include "logger.h"
#include <string>
#include <cstdint>

namespace dbgwrap {

struct Config {
    std::wstring targetPath;                     // --target (required)
    std::wstring targetArgs;                     // --args   (optional, single string)
    std::wstring logPath = L"debugger_wrapper.log"; // --log
    LogLevel     logLevel = LogLevel::Info;      // --level ERROR|INFO|DEBUG
    bool         alsoStdout = true;              // --no-stdout to disable
    bool         enableCpuid = true;             // --no-cpuid
    bool         enableRdtsc = true;             // --no-rdtsc
    uint32_t     jitterMin = 80;                 // --jitter-min
    uint32_t     jitterMax = 200;                // --jitter-max
    // Whether to scan modules other than the target .exe. Off by default:
    // a naive byte-scan inside system DLLs (ntdll, ucrtbased, ...) places
    // BPs on byte patterns that are NOT real CPUID/RDTSC instructions,
    // which corrupts execution. The target's own anti-VM checks live in
    // its own .text via intrinsics, so exe-only is the safe default.
    // Enable --scan-dlls only for known-clean modules / research builds.
    bool         scanDlls   = false;             // --scan-dlls
    // Optional DLL to load into the target via CreateRemoteThread +
    // LoadLibraryW at CREATE_PROCESS_DEBUG_EVENT, before the target's main
    // thread runs. Used to compose with hooksbox.dll (API-hook layer) so
    // both masking layers can be active simultaneously.
    std::wstring injectDll;                      // --inject <path>
};

// Returns true if argv parsed successfully and contains required fields.
// Writes a short usage message to stderr if parsing fails or --help is given.
bool ParseCommandLine(int argc, wchar_t** argv, Config& cfg, std::wstring& errMsg);

void PrintUsage();

} // namespace dbgwrap

#endif // DBGWRAPPER_CONFIG_H
