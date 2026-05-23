// DebuggerWrapper — user-mode debugger that intercepts CPUID/RDTSC in a target
// process and rewrites their results to defeat common anti-VM checks (HV-bit
// in CPUID leaf 0x1, hypervisor-vendor leaves 0x40000000+, and the
// RDTSC->CPUID->RDTSC timing test). POC component of the HooksBox anti-VM
// research project.

#include <windows.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>

#include "config.h"
#include "logger.h"
#include "debugger_core.h"

namespace dw = dbgwrap;

int wmain(int argc, wchar_t** argv) {
    // Make wide stdout work for non-ASCII (paths with cyrillics etc.).
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    dw::Config cfg;
    std::wstring err;
    if (!dw::ParseCommandLine(argc, argv, cfg, err)) {
        if (err != L"<help>") {
            std::wcerr << L"argument error: " << err << L"\n\n";
        }
        dw::PrintUsage();
        return (err == L"<help>") ? 0 : 2;
    }

    dw::Logger::Instance().Init(cfg.logPath, cfg.logLevel, cfg.alsoStdout);

    DBG_LOG_I(L"main",
              L"DebuggerWrapper starting. target=%s level=%d cpuid=%s rdtsc=%s jitter=[%u,%u] scan-dlls=%s inject=%s log=%s",
              cfg.targetPath.c_str(),
              static_cast<int>(cfg.logLevel),
              cfg.enableCpuid ? L"on" : L"off",
              cfg.enableRdtsc ? L"on" : L"off",
              cfg.jitterMin, cfg.jitterMax,
              cfg.scanDlls ? L"on" : L"off",
              cfg.injectDll.empty() ? L"(none)" : cfg.injectDll.c_str(),
              cfg.logPath.c_str());

    // Note on agent test environment vs project target:
    //   The HV-bit / leaf-0x40000000 masks are applied regardless of which
    //   vendor the host actually reports — see cpuid_handler.cpp. On the
    //   developer machine (Hyper-V parent partition) the raw cpuid reads
    //   "Microsoft Hv"; in the project's target deployment (a VirtualBox VM)
    //   it would read "VBoxVBoxVBox". Both paths are exercised by the same
    //   masking code; the log records both the raw and masked values per hit.
    DBG_LOG_I(L"main",
              L"Note: masking is vendor-agnostic. Logs show raw host CPUID (likely 'Microsoft Hv' on dev box, 'VBoxVBoxVBox' on the project's target VM) alongside the masked result.");

    dw::RunStats stats;
    const bool ok = dw::RunDebuggerLoop(cfg, stats);

    DBG_LOG_I(L"main", L"DebuggerWrapper finished. ok=%s", ok ? L"true" : L"false");

    dw::Logger::Instance().Shutdown();
    return ok ? 0 : 1;
}
