#include "config.h"

#include <iostream>
#include <cstdlib>
#include <cwctype>

namespace dbgwrap {

static bool ParseLevel(const std::wstring& s, LogLevel& out) {
    std::wstring up;
    up.reserve(s.size());
    for (wchar_t c : s) up.push_back(static_cast<wchar_t>(std::towupper(c)));
    if (up == L"ERROR") { out = LogLevel::Error; return true; }
    if (up == L"INFO")  { out = LogLevel::Info;  return true; }
    if (up == L"DEBUG") { out = LogLevel::Debug; return true; }
    return false;
}

void PrintUsage() {
    std::wcerr <<
        L"DebuggerWrapper — user-mode debugger that masks CPUID/RDTSC for the target process.\n"
        L"\n"
        L"Usage:\n"
        L"  DebuggerWrapper.exe --target <path.exe> [options]\n"
        L"\n"
        L"Required:\n"
        L"  --target <path>        Path to the target executable to run under the debugger.\n"
        L"\n"
        L"Optional:\n"
        L"  --args   <string>      Command line passed to the target (single quoted string).\n"
        L"  --log    <path>        Log file path (default: debugger_wrapper.log in cwd).\n"
        L"  --level  ERROR|INFO|DEBUG   Log verbosity (default: INFO).\n"
        L"  --no-stdout            Don't echo logs to stdout.\n"
        L"  --cpuid                Intercept CPUID (off by default — leaks BPs\n"
        L"                         under some debug builds; enable only in a\n"
        L"                         hypervisor guest where hypervisor bit + vendor\n"
        L"                         leaves need masking).\n"
        L"  --no-cpuid             Explicitly disable CPUID interception (default).\n"
        L"  --no-rdtsc             Don't intercept RDTSC instructions.\n"
        L"  --jitter-min <N>       Min ticks added per virtual RDTSC (default: 80).\n"
        L"  --jitter-max <N>       Max ticks added per virtual RDTSC (default: 200).\n"
        L"  --scan-dlls            Also scan loaded DLLs (off by default — naive\n"
        L"                         byte scanning of system DLLs causes false BPs).\n"
        L"  --inject <path>        LoadLibraryW the given DLL into the target via\n"
        L"                         CreateRemoteThread, before its main thread runs.\n"
        L"                         Used to combine with hooksbox.dll API-hook layer.\n"
        L"  --help                 Show this help and exit.\n"
        L"\n"
        L"Example:\n"
        L"  DebuggerWrapper.exe --target C:\\path\\vmcheck.exe --level DEBUG\n";
}

bool ParseCommandLine(int argc, wchar_t** argv, Config& cfg, std::wstring& errMsg) {
    auto needValue = [&](int i, const wchar_t* flag) -> bool {
        if (i + 1 >= argc) {
            errMsg = std::wstring(flag) + L" requires a value";
            return false;
        }
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h" || a == L"/?") {
            errMsg = L"<help>";
            return false;
        } else if (a == L"--target") {
            if (!needValue(i, L"--target")) return false;
            cfg.targetPath = argv[++i];
        } else if (a == L"--args") {
            if (!needValue(i, L"--args")) return false;
            cfg.targetArgs = argv[++i];
        } else if (a == L"--log") {
            if (!needValue(i, L"--log")) return false;
            cfg.logPath = argv[++i];
        } else if (a == L"--level") {
            if (!needValue(i, L"--level")) return false;
            if (!ParseLevel(argv[++i], cfg.logLevel)) {
                errMsg = L"--level must be ERROR, INFO, or DEBUG";
                return false;
            }
        } else if (a == L"--no-stdout") {
            cfg.alsoStdout = false;
        } else if (a == L"--no-cpuid") {
            cfg.enableCpuid = false;
        } else if (a == L"--cpuid") {
            // Explicit opt-in: CPUID interception is OFF by default — see
            // config.h for the rationale.  Enable only when running inside
            // a hypervisor guest where leaf 1 / leaf 0x40000000 need
            // masking.
            cfg.enableCpuid = true;
        } else if (a == L"--no-rdtsc") {
            cfg.enableRdtsc = false;
        } else if (a == L"--scan-dlls") {
            cfg.scanDlls = true;
        } else if (a == L"--inject") {
            if (!needValue(i, L"--inject")) return false;
            cfg.injectDll = argv[++i];
        } else if (a == L"--jitter-min") {
            if (!needValue(i, L"--jitter-min")) return false;
            cfg.jitterMin = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (a == L"--jitter-max") {
            if (!needValue(i, L"--jitter-max")) return false;
            cfg.jitterMax = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else {
            errMsg = L"Unknown argument: " + a;
            return false;
        }
    }

    if (cfg.targetPath.empty()) {
        errMsg = L"--target is required";
        return false;
    }
    if (cfg.jitterMin > cfg.jitterMax) {
        errMsg = L"--jitter-min must be <= --jitter-max";
        return false;
    }
    return true;
}

} // namespace dbgwrap
