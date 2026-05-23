#include "debugger_core.h"
#include "logger.h"
#include "instruction_scanner.h"
#include "cpuid_handler.h"

#include <psapi.h>
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>

namespace dbgwrap {

namespace {

constexpr wchar_t COMP_CORE[]  = L"core";
constexpr wchar_t COMP_CPUID[] = L"cpuid";
constexpr wchar_t COMP_RDTSC[] = L"rdtsc";

// Inject a DLL into the debugged process by writing its path string into
// remote memory and creating a remote thread that calls LoadLibraryW on it.
//
// Called at CREATE_PROCESS_DEBUG_EVENT, when the target's threads are still
// suspended by the debug subsystem. The injector thread we create here will
// only start running once we ContinueDebugEvent — and crucially, it competes
// with the target's main thread under normal scheduling after that point.
//
// In practice this races against the target's CRT init, but for HooksBox the
// race is benign: hooksbox.dll's MinHook hooks intercept WinAPI calls that
// happen *after* CRT init (they aren't called from CRT itself), and CPUID
// from CRT init is already covered by the INT3 layer installed before this
// inject runs. Returns the remote thread's TID on success so the event loop
// can recognise and log its LOAD_DLL / EXIT_THREAD events.
//
// Layout of remote memory: a single contiguous block holding the wide-char
// path of the DLL, NUL-terminated. The block is leaked deliberately — the
// target process owns it and exits soon enough that cleanup is moot.
static DWORD InjectDllViaRemoteThread(HANDLE hProcess, const std::wstring& dllPath) {
    // Resolve to an absolute path. LoadLibraryW inside the remote thread
    // uses the *target* process's DLL search order, not ours; passing a
    // relative path can silently miss the actual DLL even when it sits next
    // to DebuggerWrapper.exe. GetFullPathNameW gives us a canonical
    // launcher-CWD-anchored path so the target loader always finds it.
    wchar_t abs[MAX_PATH * 2] = {0};
    DWORD n = GetFullPathNameW(dllPath.c_str(), ARRAYSIZE(abs), abs, nullptr);
    const std::wstring resolved = (n > 0 && n < ARRAYSIZE(abs)) ? std::wstring(abs) : dllPath;
    if (resolved != dllPath) {
        DBG_LOG_I(L"inject", L"Resolved \"%s\" -> \"%s\"", dllPath.c_str(), resolved.c_str());
    }
    if (GetFileAttributesW(resolved.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DBG_LOG_E(L"inject", L"DLL not found at resolved path: %s", resolved.c_str());
        return 0;
    }

    const SIZE_T bytes = (resolved.size() + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        DBG_LOG_E(L"inject", L"VirtualAllocEx failed: %s",
                  FormatWinError(GetLastError()).c_str());
        return 0;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, resolved.c_str(), bytes, &written) || written != bytes) {
        DBG_LOG_E(L"inject", L"WriteProcessMemory failed: %s",
                  FormatWinError(GetLastError()).c_str());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return 0;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hKernel32, "LoadLibraryW"));
    if (!pLoadLibraryW) {
        DBG_LOG_E(L"inject", L"GetProcAddress(LoadLibraryW) failed: %s",
                  FormatWinError(GetLastError()).c_str());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return 0;
    }

    DWORD remoteTid = 0;
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0,
                                              pLoadLibraryW, remoteMem,
                                              0, &remoteTid);
    if (!hRemoteThread) {
        DBG_LOG_E(L"inject", L"CreateRemoteThread failed: %s",
                  FormatWinError(GetLastError()).c_str());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return 0;
    }
    // The debug loop will reap this thread via EXIT_THREAD; we just close our
    // own handle here.
    CloseHandle(hRemoteThread);

    DBG_LOG_I(L"inject", L"Queued LoadLibraryW(\"%s\") in remote thread TID=%lu",
              resolved.c_str(), remoteTid);
    return remoteTid;
}

std::wstring ReadRemoteImageName(HANDLE hProc, LPVOID base, HANDLE hFile) {
    // Preferred path: GetFinalPathNameByHandleW on the LOAD_DLL_DEBUG_EVENT.hFile.
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        wchar_t buf[MAX_PATH] = {0};
        DWORD n = GetFinalPathNameByHandleW(hFile, buf, MAX_PATH, FILE_NAME_NORMALIZED);
        if (n > 0 && n < MAX_PATH) {
            std::wstring s(buf);
            // GetFinalPathNameByHandleW prepends \\?\ — strip it for readability.
            if (s.rfind(L"\\\\?\\", 0) == 0) s.erase(0, 4);
            return s;
        }
    }
    // Fallback: GetMappedFileNameW
    wchar_t mapped[MAX_PATH] = {0};
    if (GetMappedFileNameW(hProc, base, mapped, MAX_PATH) > 0) {
        return std::wstring(mapped);
    }
    return L"<unknown>";
}

// CPUID is `0F A2` (2 bytes). When INT3 (0xCC) fires, the CPU has *already*
// advanced Rip past the 0xCC byte — so context.Rip on entry to our handler
// points 1 byte past the start of the original instruction (i.e., at the
// second byte of the 2-byte opcode). To fully skip a 2-byte instruction we
// therefore advance by ONE more byte, not two. Same for RDTSC (0F 31).
constexpr DWORD64 RIP_ADVANCE_AFTER_INT3 = 1;

bool HandleCpuidBp(HANDLE hThread, RunStats& stats) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        DBG_LOG_E(COMP_CPUID, L"GetThreadContext failed: %s", FormatWinError(GetLastError()).c_str());
        return false;
    }

    const uint32_t leaf    = static_cast<uint32_t>(ctx.Rax);
    const uint32_t subleaf = static_cast<uint32_t>(ctx.Rcx);

    CpuidRegs rawHost{};
    CpuidRegs masked = EmulateAndMaskCpuid(leaf, subleaf, rawHost);

    DBG_LOG_D(COMP_CPUID,
              L"hit @ 0x%llx, eax(leaf)=0x%08X ecx(sub)=0x%08X | host eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X | masked eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X",
              static_cast<unsigned long long>(ctx.Rip),
              leaf, subleaf,
              rawHost.eax, rawHost.ebx, rawHost.ecx, rawHost.edx,
              masked.eax,  masked.ebx,  masked.ecx,  masked.edx);

    // CPUID writes to EAX/EBX/ECX/EDX (high 32 bits of R* are zeroed by the CPU).
    ctx.Rax = masked.eax;
    ctx.Rbx = masked.ebx;
    ctx.Rcx = masked.ecx;
    ctx.Rdx = masked.edx;
    ctx.Rip += RIP_ADVANCE_AFTER_INT3;

    if (!SetThreadContext(hThread, &ctx)) {
        DBG_LOG_E(COMP_CPUID, L"SetThreadContext failed: %s", FormatWinError(GetLastError()).c_str());
        return false;
    }

    stats.cpuidIntercepts++;
    return true;
}

bool HandleRdtscBp(HANDLE hThread, VirtualTsc& vtsc, RunStats& stats) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        DBG_LOG_E(COMP_RDTSC, L"GetThreadContext failed: %s", FormatWinError(GetLastError()).c_str());
        return false;
    }

    const uint64_t before = vtsc.Current();
    const uint64_t now    = vtsc.Tick();

    // RDTSC writes EDX:EAX = TSC; high 32 bits of R* are zero.
    ctx.Rax = now & 0xFFFFFFFFull;
    ctx.Rdx = (now >> 32) & 0xFFFFFFFFull;
    ctx.Rip += RIP_ADVANCE_AFTER_INT3;

    DBG_LOG_D(COMP_RDTSC,
              L"hit @ 0x%llx, virtTsc %llu -> %llu (delta=%llu)",
              static_cast<unsigned long long>(ctx.Rip - RIP_ADVANCE_AFTER_INT3),
              static_cast<unsigned long long>(before),
              static_cast<unsigned long long>(now),
              static_cast<unsigned long long>(now - before));

    if (!SetThreadContext(hThread, &ctx)) {
        DBG_LOG_E(COMP_RDTSC, L"SetThreadContext failed: %s", FormatWinError(GetLastError()).c_str());
        return false;
    }

    stats.rdtscIntercepts++;
    return true;
}

} // anonymous

bool RunDebuggerLoop(const Config& cfg, RunStats& stats) {
    const auto t0 = std::chrono::steady_clock::now();

    // Build the command line for the target. CreateProcessW requires a
    // writable buffer for lpCommandLine.
    std::wstring cmdLine;
    cmdLine.reserve(cfg.targetPath.size() + 2 + cfg.targetArgs.size() + 1);
    cmdLine.push_back(L'"');
    cmdLine += cfg.targetPath;
    cmdLine.push_back(L'"');
    if (!cfg.targetArgs.empty()) {
        cmdLine.push_back(L' ');
        cmdLine += cfg.targetArgs;
    }
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    DBG_LOG_I(COMP_CORE, L"Launching target: %s", cmdLine.c_str());
    if (!CreateProcessW(nullptr,
                        cmdBuf.data(),
                        nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS,
                        nullptr, nullptr,
                        &si, &pi)) {
        DBG_LOG_E(COMP_CORE, L"CreateProcess failed: %s", FormatWinError(GetLastError()).c_str());
        return false;
    }
    DBG_LOG_I(COMP_CORE, L"Target launched. PID=%lu, TID=%lu", pi.dwProcessId, pi.dwThreadId);

    BreakpointManager bps;
    VirtualTsc vtsc;
    vtsc.Init(cfg.jitterMin, cfg.jitterMax);
    DBG_LOG_I(COMP_RDTSC, L"Virtual TSC initialised; jitter range [%u, %u]; start=%llu",
              cfg.jitterMin, cfg.jitterMax,
              static_cast<unsigned long long>(vtsc.Current()));

    // Track threads (so we can close their handles on exit).
    std::unordered_map<DWORD, HANDLE> threadHandles;

    // TID of the LoadLibraryW remote thread (if --inject was used), so we can
    // recognise its events in the loop and report when injection completed.
    DWORD injectorTid = 0;
    // Whether we observed LOAD_DLL_DEBUG_EVENT for the injected DLL. On modern
    // Windows the kernel zeroes RAX in the thread-exit thunk for security, so
    // the injector thread's exit code is always 0 regardless of LoadLibraryW
    // success/failure. The LOAD_DLL event is the authoritative signal.
    bool injectedDllLoaded = false;
    std::wstring injectedDllPathLower;  // lowercased absolute path for matching
    if (!cfg.injectDll.empty()) {
        wchar_t abs[MAX_PATH * 2] = {0};
        DWORD n = GetFullPathNameW(cfg.injectDll.c_str(), ARRAYSIZE(abs), abs, nullptr);
        injectedDllPathLower = (n > 0 && n < ARRAYSIZE(abs)) ? std::wstring(abs) : cfg.injectDll;
        for (auto& c : injectedDllPathLower) c = static_cast<wchar_t>(towlower(c));
    }

    bool running = true;
    while (running) {
        DEBUG_EVENT de{};
        if (!WaitForDebugEvent(&de, INFINITE)) {
            DBG_LOG_E(COMP_CORE, L"WaitForDebugEvent failed: %s", FormatWinError(GetLastError()).c_str());
            break;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (de.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            const auto& info = de.u.CreateProcessInfo;
            std::wstring name = ReadRemoteImageName(info.hProcess, info.lpBaseOfImage, info.hFile);
            DBG_LOG_I(COMP_CORE, L"CREATE_PROCESS: PID=%lu base=0x%p file=%s",
                      de.dwProcessId, info.lpBaseOfImage, name.c_str());

            ScanAndInstallBreakpoints(info.hProcess,
                                      info.lpBaseOfImage,
                                      bps,
                                      cfg.enableCpuid,
                                      cfg.enableRdtsc,
                                      name.c_str());

            // Optional DLL injection: queue LoadLibraryW in a remote thread.
            // This must happen here (target threads still suspended) so the
            // injector thread starts running as soon as we ContinueDebugEvent,
            // ideally before the target's CRT init reaches user code.
            if (!cfg.injectDll.empty()) {
                injectorTid = InjectDllViaRemoteThread(info.hProcess, cfg.injectDll);
                if (injectorTid == 0) {
                    DBG_LOG_E(COMP_CORE, L"DLL injection failed; continuing without it.");
                }
            }

            if (info.hFile) CloseHandle(info.hFile);
            threadHandles[de.dwThreadId] = info.hThread;
            break;
        }

        case LOAD_DLL_DEBUG_EVENT: {
            const auto& info = de.u.LoadDll;
            std::wstring name = ReadRemoteImageName(pi.hProcess, info.lpBaseOfDll, info.hFile);
            DBG_LOG_I(COMP_CORE, L"LOAD_DLL: base=0x%p file=%s%s",
                      info.lpBaseOfDll, name.c_str(),
                      cfg.scanDlls ? L"" : L" (scan skipped — --scan-dlls off)");

            // Match against the injected DLL path (case-insensitive). If the
            // loader maps it, we've confirmed the inject worked regardless of
            // whatever the injector thread's exit code will be.
            if (!injectedDllPathLower.empty() && !injectedDllLoaded) {
                std::wstring lowered = name;
                for (auto& c : lowered) c = static_cast<wchar_t>(towlower(c));
                if (lowered == injectedDllPathLower) {
                    injectedDllLoaded = true;
                    DBG_LOG_I(COMP_CORE, L"Confirmed inject DLL is mapped at 0x%p", info.lpBaseOfDll);
                }
            }

            if (cfg.scanDlls) {
                ScanAndInstallBreakpoints(pi.hProcess,
                                          info.lpBaseOfDll,
                                          bps,
                                          cfg.enableCpuid,
                                          cfg.enableRdtsc,
                                          name.c_str());
            }

            if (info.hFile) CloseHandle(info.hFile);
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT: {
            DBG_LOG_D(COMP_CORE, L"UNLOAD_DLL: base=0x%p", de.u.UnloadDll.lpBaseOfDll);
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT: {
            const bool isInjector = (de.dwThreadId == injectorTid);
            DBG_LOG_D(COMP_CORE, L"CREATE_THREAD: TID=%lu start=0x%p%s",
                      de.dwThreadId, de.u.CreateThread.lpStartAddress,
                      isInjector ? L"  (injector — LoadLibraryW)" : L"");
            threadHandles[de.dwThreadId] = de.u.CreateThread.hThread;
            break;
        }

        case EXIT_THREAD_DEBUG_EVENT: {
            const DWORD code = de.u.ExitThread.dwExitCode;
            if (de.dwThreadId == injectorTid) {
                // The injector thread is LoadLibraryW. On modern Windows the
                // kernel zeroes RAX in the thread-exit thunk as an info-
                // disclosure mitigation, so `code` here is always 0 regardless
                // of success/failure. The authoritative signal is whether we
                // observed LOAD_DLL_DEBUG_EVENT for the injected DLL path.
                if (injectedDllLoaded) {
                    DBG_LOG_I(COMP_CORE,
                              L"EXIT_THREAD: injector TID=%lu finished; DLL confirmed loaded",
                              de.dwThreadId);
                } else {
                    DBG_LOG_E(COMP_CORE,
                              L"EXIT_THREAD: injector TID=%lu finished BUT no LOAD_DLL event was seen for the inject path — load failed",
                              de.dwThreadId);
                }
            } else {
                DBG_LOG_D(COMP_CORE, L"EXIT_THREAD: TID=%lu code=%lu",
                          de.dwThreadId, code);
            }
            threadHandles.erase(de.dwThreadId);
            break;
        }

        case OUTPUT_DEBUG_STRING_EVENT: {
            DBG_LOG_D(COMP_CORE, L"OUTPUT_DEBUG_STRING (len=%u)", de.u.DebugString.nDebugStringLength);
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_RECORD& er = de.u.Exception.ExceptionRecord;
            const auto code = er.ExceptionCode;

            if (code == EXCEPTION_BREAKPOINT) {
                const uintptr_t addr = reinterpret_cast<uintptr_t>(er.ExceptionAddress);
                auto it = threadHandles.find(de.dwThreadId);
                HANDLE hThread = (it == threadHandles.end()) ? nullptr : it->second;
                if (!hThread) {
                    // First-chance system BP at process start lives in ntdll
                    // before our CREATE_THREAD event for the main thread —
                    // open it on demand.
                    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                         FALSE, de.dwThreadId);
                }

                const BpInfo* info = bps.Find(addr);
                if (info && hThread) {
                    bool ok = false;
                    if (info->kind == BpKind::Cpuid) {
                        ok = HandleCpuidBp(hThread, stats);
                    } else if (info->kind == BpKind::Rdtsc) {
                        ok = HandleRdtscBp(hThread, vtsc, stats);
                    }
                    if (!ok) {
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                } else {
                    // Either the initial ntdll loader BP, or a BP we didn't
                    // install. Let it pass: DBG_CONTINUE for the very first
                    // (expected) system BP, NOT_HANDLED otherwise so the
                    // target can act on its own debugger logic if any.
                    static bool sawInitialSystemBp = false;
                    if (!sawInitialSystemBp) {
                        sawInitialSystemBp = true;
                        DBG_LOG_I(COMP_CORE, L"Initial system breakpoint at 0x%p — continuing", er.ExceptionAddress);
                    } else {
                        stats.bpHitsForeign++;
                        DBG_LOG_D(COMP_CORE, L"Foreign BP at 0x%p (firstChance=%lu) — passing through",
                                  er.ExceptionAddress, de.u.Exception.dwFirstChance);
                        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                if (hThread && (it == threadHandles.end())) {
                    CloseHandle(hThread);
                }
            } else if (code == EXCEPTION_SINGLE_STEP) {
                DBG_LOG_D(COMP_CORE, L"single-step @ 0x%p — passing through", er.ExceptionAddress);
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            } else {
                DBG_LOG_I(COMP_CORE,
                          L"Exception code=0x%08X firstChance=%lu at 0x%p — passing through to target",
                          code, de.u.Exception.dwFirstChance, er.ExceptionAddress);
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT: {
            stats.exitCode = de.u.ExitProcess.dwExitCode;
            DBG_LOG_I(COMP_CORE, L"EXIT_PROCESS: code=%lu", stats.exitCode);
            running = false;
            break;
        }

        default:
            DBG_LOG_D(COMP_CORE, L"unhandled debug event code=%lu", de.dwDebugEventCode);
            break;
        }

        if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus)) {
            DBG_LOG_E(COMP_CORE, L"ContinueDebugEvent failed: %s", FormatWinError(GetLastError()).c_str());
            break;
        }
    }

    for (auto& kv : threadHandles) {
        // Thread handles received via debug events are owned by us; close them.
        if (kv.second) CloseHandle(kv.second);
    }
    threadHandles.clear();

    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);

    const auto t1 = std::chrono::steady_clock::now();
    stats.wallSeconds = std::chrono::duration<double>(t1 - t0).count();

    DBG_LOG_I(COMP_CORE,
              L"Run summary: CPUID intercepts=%llu, RDTSC intercepts=%llu, foreign BPs=%llu, BPs total=%zu, target exit=%lu, wall=%.3fs",
              static_cast<unsigned long long>(stats.cpuidIntercepts),
              static_cast<unsigned long long>(stats.rdtscIntercepts),
              static_cast<unsigned long long>(stats.bpHitsForeign),
              bps.Count(),
              stats.exitCode,
              stats.wallSeconds);
    return true;
}

} // namespace dbgwrap
