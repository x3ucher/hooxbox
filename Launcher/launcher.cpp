#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Suspended-process + DLL injection helpers (the classic launcher flow).
// ---------------------------------------------------------------------------

// Verify the target process has a module whose path matches `dllPath`
// (case-insensitive). Used in lieu of LoadLibraryW's thread exit code, which
// is unreliable on modern Windows: the kernel zeroes RAX in the thread-exit
// thunk as an info-disclosure mitigation, so GetExitCodeThread returns 0
// regardless of whether the load succeeded.
static bool IsModuleLoadedInProcess(DWORD pid, const std::wstring& dllPath) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        // Snapshot can race against module load; the caller can retry.
        return false;
    }
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szExePath, dllPath.c_str()) == 0) { found = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

bool InjectIntoProcess(HANDLE hProcess, const std::wstring& dllPath) {
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMemory) {
        std::wcerr << L"Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), pathSize, NULL)) {
        std::wcerr << L"Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);

    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Wait for LoadLibraryW to finish; the thread exit code is not informative
    // (see note above) — we verify via the module list instead.
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    if (!IsModuleLoadedInProcess(GetProcessId(hProcess), dllPath)) {
        std::wcerr << L"DLL load could not be confirmed via module-list check. "
                   << L"Common causes: arch mismatch, missing dependency, "
                   << L"DllMain returned FALSE." << std::endl;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Diagnostic: read the target PE's IMAGE_FILE_HEADER.Machine and compare with
// the launcher's own architecture. This catches the common 0xC0000020
// (STATUS_INVALID_IMAGE_FORMAT) scenario before the user sees a Windows
// dialog: injecting an x64 DLL into an x86 process (or vice versa) fails
// with that exact error.
// ---------------------------------------------------------------------------
enum class PeArch { Unknown, X86, X64, Arm64, Other };

static PeArch ReadPeMachineArch(const std::wstring& exePath) {
    HANDLE hFile = CreateFileW(exePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return PeArch::Unknown;

    IMAGE_DOS_HEADER dos{};
    DWORD got = 0;
    if (!ReadFile(hFile, &dos, sizeof(dos), &got, nullptr) || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return PeArch::Unknown;
    }
    if (SetFilePointer(hFile, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return PeArch::Unknown;
    }
    // Read just the signature + FileHeader; OptionalHeader varies by arch and
    // we don't need it.
    DWORD signature = 0;
    IMAGE_FILE_HEADER fh{};
    if (!ReadFile(hFile, &signature, sizeof(signature), &got, nullptr) || got != sizeof(signature) ||
        signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return PeArch::Unknown;
    }
    if (!ReadFile(hFile, &fh, sizeof(fh), &got, nullptr) || got != sizeof(fh)) {
        CloseHandle(hFile);
        return PeArch::Unknown;
    }
    CloseHandle(hFile);

    switch (fh.Machine) {
    case IMAGE_FILE_MACHINE_I386:  return PeArch::X86;
    case IMAGE_FILE_MACHINE_AMD64: return PeArch::X64;
    case IMAGE_FILE_MACHINE_ARM64: return PeArch::Arm64;
    default:                       return PeArch::Other;
    }
}

static const wchar_t* PeArchName(PeArch a) {
    switch (a) {
    case PeArch::X86:   return L"x86 (32-bit)";
    case PeArch::X64:   return L"x64 (64-bit)";
    case PeArch::Arm64: return L"ARM64";
    case PeArch::Other: return L"unknown machine";
    default:            return L"<unreadable>";
    }
}

static constexpr PeArch kLauncherArch =
#if defined(_M_X64) || defined(__x86_64__)
    PeArch::X64;
#elif defined(_M_IX86) || defined(__i386__)
    PeArch::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
    PeArch::Arm64;
#else
    PeArch::Other;
#endif

// ---------------------------------------------------------------------------
// Small input helpers.
// ---------------------------------------------------------------------------

// Strip leading/trailing whitespace and an enclosing pair of double quotes
// (so a user-pasted "C:\Program Files\foo.exe" still resolves).
static std::wstring TrimAndUnquote(std::wstring s) {
    while (!s.empty() && (s.front() == L' ' || s.front() == L'\t' ||
                          s.front() == L'\r' || s.front() == L'\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\t' ||
                          s.back() == L'\r' || s.back() == L'\n'))
        s.pop_back();
    if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"') {
        s.erase(s.begin());
        s.pop_back();
    }
    return s;
}

// Yes/no prompt. `defaultYes` controls how an empty answer is interpreted
// and which letter is shown in upper-case.
static bool PromptYesNo(const wchar_t* question, bool defaultYes) {
    std::wcout << question << L" [" << (defaultYes ? L"Y/n" : L"y/N") << L"]: ";
    std::wstring line;
    if (!std::getline(std::wcin, line)) return defaultYes;
    line = TrimAndUnquote(line);
    if (line.empty()) return defaultYes;
    wchar_t c = static_cast<wchar_t>(towlower(line[0]));
    if (c == L'y') return true;
    if (c == L'n') return false;
    return defaultYes;
}

// ---------------------------------------------------------------------------
// Three operational modes:
//   1. raw       — start target as-is (no masking layer).
//   2. inject    — start target SUSPENDED + LoadLibrary hooksbox.dll + resume.
//   3. debug     — hand off to DebuggerWrapper.exe (with optional --inject).
// Mode 3 covers both "debug only" and "debug + inject" via the --inject flag
// of DebuggerWrapper.
// ---------------------------------------------------------------------------

static int RunRawMode(const std::wstring& targetPath) {
    std::wcout << L"\n[mode: raw] Starting target without any masking..." << std::endl;
    std::vector<wchar_t> cmdBuf(targetPath.begin(), targetPath.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"CreateProcess failed. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"   Process started. PID: " << pi.dwProcessId << std::endl;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

static int RunInjectMode(const std::wstring& targetPath, const std::wstring& dllPath) {
    std::wcout << L"\n[mode: inject] Suspended start + hooksbox.dll injection..." << std::endl;

    std::vector<wchar_t> cmdBuf(targetPath.begin(), targetPath.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"CreateProcess failed. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"   1. Created suspended process, PID=" << pi.dwProcessId << std::endl;
    std::wcout << L"   2. Injecting " << dllPath << L"..." << std::endl;
    if (!InjectIntoProcess(pi.hProcess, dllPath)) {
        std::wcerr << L"   Injection failed — terminating target." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    std::wcout << L"   3. Resuming target main thread..." << std::endl;
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::wcerr << L"   ResumeThread failed. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    std::wcout << L"   Target running with hooksbox.dll loaded." << std::endl;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

// Spawn DebuggerWrapper.exe (sibling of this launcher) on `target`. If
// `dllToInject` is non-empty, forward it via DebuggerWrapper's --inject flag
// so the CPUID/RDTSC layer and the API-hook DLL run simultaneously.
//
// Implemented as a separate process rather than as a library function so that:
//   - the launcher's footprint stays minimal (no Debug API linkage);
//   - a crash in the debugger module cannot take down the launcher;
//   - the debugger keeps its own log file separate from hooksbox.dll's.
static int RunDebugMode(const std::wstring& launcherDir,
                        const std::wstring& targetPath,
                        const std::wstring& dllToInject,
                        const std::vector<std::wstring>& forwardedArgs) {
    std::wstring wrapperExe = launcherDir + L"DebuggerWrapper.exe";
    if (GetFileAttributesW(wrapperExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"DebuggerWrapper.exe not found at: " << wrapperExe << std::endl;
        return 1;
    }

    std::wstring cmd;
    cmd.reserve(wrapperExe.size() + targetPath.size() + dllToInject.size() + 128);
    cmd.push_back(L'"');
    cmd += wrapperExe;
    cmd += L"\" --target \"";
    cmd += targetPath;
    cmd.push_back(L'"');
    if (!dllToInject.empty()) {
        cmd += L" --inject \"";
        cmd += dllToInject;
        cmd.push_back(L'"');
    }
    for (const auto& a : forwardedArgs) {
        cmd.push_back(L' ');
        cmd += a;
    }

    std::wcout << L"\n[mode: debug] Spawning DebuggerWrapper:\n   " << cmd << std::endl;

    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"CreateProcess(DebuggerWrapper) failed: " << GetLastError() << std::endl;
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    std::wcout << L"[launcher] DebuggerWrapper exited with code " << code << std::endl;
    return static_cast<int>(code);
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv) {
    std::wcout << L"=== HooksBox Launcher ===" << std::endl;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring launcherDir(exePath);
    size_t pos = launcherDir.find_last_of(L"\\/");
    launcherDir = launcherDir.substr(0, pos + 1);

    const std::wstring dllPath = launcherDir + L"hooksbox.dll";

    // Argv shortcut for power users / scripting. The interactive prompts
    // still work without any args.
    //   launcher.exe <target>
    //   launcher.exe --inject <target>
    //   launcher.exe --debug  <target> [extra DebuggerWrapper args ...]
    //   launcher.exe --debug-inject <target> [extra DebuggerWrapper args ...]
    bool argMode      = false;
    bool argInject    = false;
    bool argDebug     = false;
    std::wstring argTarget;
    std::vector<std::wstring> debugExtraArgs;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--inject") {
            argMode = true; argInject = true;
        } else if (a == L"--debug") {
            argMode = true; argDebug = true;
        } else if (a == L"--debug-inject") {
            argMode = true; argDebug = true; argInject = true;
        } else if (argTarget.empty()) {
            argTarget = a;
        } else {
            // Anything after the target in --debug mode is forwarded to
            // DebuggerWrapper unchanged.
            debugExtraArgs.emplace_back(a);
        }
    }

    std::wstring targetPath;
    bool wantInject  = false;
    bool wantDebug   = false;

    if (argMode && !argTarget.empty()) {
        targetPath = TrimAndUnquote(argTarget);
        wantInject = argInject;
        wantDebug  = argDebug;
    } else {
        // Interactive flow.
        std::wcout << L"\nTarget executable path (full or relative): ";
        std::wstring line;
        if (!std::getline(std::wcin, line)) return 1;
        targetPath = TrimAndUnquote(line);
        if (targetPath.empty()) {
            std::wcerr << L"No path given." << std::endl;
            return 1;
        }
        wantInject = PromptYesNo(L"Inject hooksbox.dll (API-hook layer)?", true);
        wantDebug  = PromptYesNo(L"Mask CPUID/RDTSC via DebuggerWrapper (instruction layer)?", false);
    }

    // -----------------------------------------------------------------------
    // Sanity checks before we touch the OS.
    // -----------------------------------------------------------------------
    if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Target not found: " << targetPath << std::endl;
        return 1;
    }
    if (wantInject) {
        if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::wcerr << L"hooksbox.dll not found next to launcher: " << dllPath << std::endl;
            return 1;
        }
        const PeArch targetArch = ReadPeMachineArch(targetPath);
        const PeArch dllArch    = ReadPeMachineArch(dllPath);
        std::wcout << L"   target arch : " << PeArchName(targetArch) << std::endl;
        std::wcout << L"   hooksbox.dll: " << PeArchName(dllArch)    << std::endl;
        if (targetArch != PeArch::Unknown && dllArch != PeArch::Unknown &&
            targetArch != dllArch) {
            std::wcerr << L"\n*** ARCH MISMATCH: cannot inject "
                       << PeArchName(dllArch) << L" DLL into "
                       << PeArchName(targetArch) << L" process.\n"
                       << L"    This is exactly the case that surfaces as Windows error 0xC0000020\n"
                       << L"    (\"the program is not designed to run on this Windows version\").\n"
                       << L"    Rebuild HooksBox for the matching architecture, or pick a target with\n"
                       << L"    the matching arch.\n" << std::endl;
            return 1;
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch.
    // -----------------------------------------------------------------------
    if (wantDebug) {
        // Debug layer is on; pass the DLL to DebuggerWrapper if also injecting.
        return RunDebugMode(launcherDir, targetPath,
                            wantInject ? dllPath : std::wstring{},
                            debugExtraArgs);
    }
    if (wantInject) {
        return RunInjectMode(targetPath, dllPath);
    }
    return RunRawMode(targetPath);
}
