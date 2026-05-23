# HooksBox — Advanced Anti-Detection Sandbox for Windows

**HooksBox** is a sandbox-environment protection toolkit that conceals
virtualization artifacts from malware-analysis-aware samples. Two complementary
masking layers are shipped:

1. **`hooksbox.dll`** — user-mode API hook DLL (MinHook). Intercepts WinAPI /
   COM calls used by `pafish`, `al-khaser`, and similar detectors and rewrites
   their results so they no longer match VirtualBox / VMware / Hyper-V / QEMU
   patterns.
2. **`DebuggerWrapper.exe`** — standalone user-mode debugger. Patches `CPUID`
   and `RDTSC` instructions in the target via Windows Debug API + INT3 soft
   breakpoints, then emulates them with masked results — defeats the
   CPUID-vendor / HV-bit / `RDTSC→CPUID→RDTSC` timing tests that no API hook
   can touch.

A small validation target (`vmcheck.exe`) reproduces the pafish-style CPUID
and timing probes so you can check the masking end-to-end.

## 🛡️ The problem

Modern malware uses many independent signals to decide it is running in a
sandbox. Conceal one and three more still fire. Two surfaces in particular sit
*below* a typical user-mode API hook:

- `CPUID` is a single instruction returning the hypervisor signature
  (`VBoxVBoxVBox`, `Microsoft Hv`, `VMwareVMware`, …) and the HV-present bit
  in leaf 0x1. No DLL hook intercepts it.
- `RDTSC` is a 1-cycle instruction on bare metal that costs thousands of
  cycles on a VM exit. Measuring it around a `CPUID` is a robust VM check
  that, again, no DLL hook can mask.

`hooksbox.dll` handles everything reachable via WinAPI / COM; `DebuggerWrapper`
handles the two instruction-level probes above.

## ✨ The solution

| Layer | What it masks | How |
|---|---|---|
| `hooksbox.dll` | Registry keys (`HKLM\HARDWARE\...`), files (`vbox*.sys`, …), processes, WMI classes (`Win32_BIOS`, `Win32_VideoController`, `Win32_PnPDevice`, `MSAcpi_ThermalZoneTemperature`, …), `SetupDiEnum*` device IDs, firmware tables, network MACs, `IsNativeVhdBoot`, etc. | MinHook trampolines on the relevant WinAPI / COM-vtable entries. |
| `DebuggerWrapper.exe` | `CPUID` (clear leaf-1 ECX bit 31; zero leaves 0x40000000–0x400000FF); `RDTSC` (virtual TSC that does NOT advance during emulated CPUID, plus configurable jitter). | INT3 soft BPs in the target's `.text`, debug-event loop, full instruction emulation. |

Masking in both layers is **vendor-agnostic**: it removes any hypervisor
signature regardless of which one the host actually runs. Project priority is
VirtualBox closure (`VBoxVBoxVBox`, `VEN_VBOX`, `VBoxGuest`, …) but the same
code paths cover Hyper-V, VMware, QEMU.

## 🔧 Key features

- **API hooking engine** — real-time interception of critical Windows APIs via MinHook
- **VirtualBox artifact masking** — registry, files, processes, devices, WMI rows, MAC OUI
- **WMI fake-row injection** — when a critical class (`Win32_Fan`, `MSAcpi_ThermalZoneTemperature`, …) returns 0 instances, a synthetic row is supplied so the "empty == VM" probe fails
- **Instruction-level masking** via `DebuggerWrapper.exe` — CPUID and RDTSC patched and emulated
- **Validation target** `vmcheck.exe` — reproduces pafish HV-bit / vendor-leaf / RDTSC-diff checks; reports `TRACED` or `CLEAN` per check
- **Customizable hooks** — easily extendable to new detection vectors
- **Lightweight** — minimal performance impact

## 📊 Profiles of operation

`hooksbox.dll` supports three operational profiles to balance coverage,
performance, and stability:

- **Minimal** — registry + file system + basic network indicators; focused on stability.
- **Advanced** — adds WMI / devices; covers most mass-detection methods.
- **Enhanced** — includes a kernel driver for low-level indicators and timings; maximum coverage.

The CPUID/RDTSC masking in `DebuggerWrapper.exe` is orthogonal to these
profiles — it runs as a separate process at the debugger layer.

## 🏗️ Architecture

<img width="1314" height="713" alt="image" src="https://github.com/user-attachments/assets/46bf1f22-a8a8-4af4-9d95-4d967526f696" />

## 🚀 Getting started

### Prerequisites
- Windows 10 / 11 (64-bit)
- Visual Studio 2022 with the *Desktop development with C++* workload
- Administrative privileges only if installing the optional kernel driver (Enhanced profile)

### Build

Clone, then build all four projects (one solution, four outputs):

```powershell
git clone https://github.com/yourusername/hooksbox.git
cd hooksbox
```

In Visual Studio: open `HooksBox.sln`, choose **Debug | x64** (or **Release | x64**),
**Build → Build Solution**.

From a Developer Command Prompt:

```powershell
msbuild HooksBox.sln /p:Configuration=Debug /p:Platform=x64
```

The build produces, all in `x64\Debug\` (or `x64\Release\`):

| Artifact | Project | Purpose |
|---|---|---|
| `hooksbox.dll` | `HooksBox` | API-hook DLL, injected into the target. |
| `launcher.exe` | `Launcher` | Spawns the target suspended, injects `hooksbox.dll`, resumes — or, with `--debug`, hands off to `DebuggerWrapper`. |
| `DebuggerWrapper.exe` | `DebuggerWrapper` | User-mode CPUID/RDTSC masking debugger. |
| `vmcheck.exe` | `vmcheck` | Pafish-style validation target. |

All four projects use PlatformToolset v143, target Windows SDK 10.0, x64
configurations. Win32 builds are not maintained (Launcher's Win32 config
still exists for historical reasons and just maps to the x64 output).

## ▶️ Running

All commands below assume you are in `x64\Debug\` (or `x64\Release\`). Every
artifact looks for its peers in its own directory, so do **not** move them
apart.

### 1. `vmcheck.exe` — standalone baseline

Run by itself to see what your machine looks like to a basic VM detector:

```powershell
.\vmcheck.exe
```

Output on this dev machine (bare-metal AMD):

```
vmcheck — anti-VM probe (DebuggerWrapper validation target)
------------------------------------------------------------
[CHECK] rdtsc_diff             : CLEAN
[CHECK] rdtsc_diff_vmexit      : CLEAN
[CHECK] cpuid_hv_bit           : CLEAN
[CHECK] cpuid_vendor_leaf      : CLEAN    -- (zeros)
------------------------------------------------------------
Done.
```

Inside VirtualBox the same binary will print `TRACED` for at least
`cpuid_hv_bit`, `cpuid_vendor_leaf` (showing `VBoxVBoxVBox`), and
`rdtsc_diff_vmexit`.

### 2. `launcher.exe` — inject `hooksbox.dll` into a target (default mode)

Interactive mode. The launcher creates the target in suspended state,
`LoadLibrary`-injects `hooksbox.dll`, then resumes:

```powershell
.\launcher.exe
=== Launcher with Early Injection ===
<paste full path to target .exe and press Enter>
```

Sequence the launcher prints:

```
1. Creating suspended process: C:\path\to\target.exe
   Process created. PID: 12345
2. Injecting DLL: C:\...\x64\Debug\hooksbox.dll
   DLL injected successfully!
3. Resuming process...
```

After this the target runs normally; every WinAPI / COM call the DLL hooks is
silently rewritten. The hook activity is logged to `sandbox_evasion.log`
(UTF-8) in the target's working directory.

> **Note**: `launcher.exe` reads the target path from `stdin` (`std::wcin`),
> not from `argv`. Type the full path and press Enter. If you want to script
> it, pipe the path in: `echo C:\path\to\target.exe | .\launcher.exe`.

Typical drivers to validate the masking:

- [Al-Khaser](https://github.com/ayoubfaouzi/al-khaser) — `al-khaser.exe -Sandbox -Anti-VM`
- [pafish](https://github.com/a0rtega/pafish) — `pafish.exe`
- [VMDetect](https://github.com/PerryWerneck/vmdetect/)

### 3. `launcher.exe --debug <target>` — CPUID/RDTSC masking via DebuggerWrapper

Launcher's second mode delegates to `DebuggerWrapper.exe`, which lives next to
it. Use this when the target probes CPUID/RDTSC (most modern anti-VM checks
do):

```powershell
.\launcher.exe --debug "C:\full\path\to\vmcheck.exe"
```

Everything after `--debug <target>` is forwarded to `DebuggerWrapper.exe` as
extra args, so e.g.:

```powershell
.\launcher.exe --debug "C:\path\to\vmcheck.exe" --level DEBUG --log my.log
```

is equivalent to running `DebuggerWrapper.exe` directly (see #4).

### 4. `DebuggerWrapper.exe` — direct invocation

```
DebuggerWrapper.exe --target <path.exe> [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--target <path>` | *required* | Target executable to run under the debugger. |
| `--args <string>` | *(none)* | Command line passed to the target (single quoted string). |
| `--log <path>` | `debugger_wrapper.log` | Log file. UTF-8 with BOM. |
| `--level ERROR\|INFO\|DEBUG` | `INFO` | Verbosity. `DEBUG` logs every CPUID/RDTSC intercept and every BP install. |
| `--no-stdout` | off | Suppress stdout mirror of the log. |
| `--no-cpuid` | off | Don't intercept CPUID. |
| `--no-rdtsc` | off | Don't intercept RDTSC. |
| `--scan-dlls` | **off** | Also scan loaded DLLs. Off by default because naive byte-scan inside system DLLs (ntdll, ucrtbased, …) places BPs on byte patterns that aren't real instructions and crashes the target. |
| `--jitter-min <N>` | 80 | Min ticks added per virtual RDTSC. |
| `--jitter-max <N>` | 200 | Max ticks added per virtual RDTSC. |
| `--help` | — | Show usage and exit. |

End-to-end verification example, on this dev machine:

```powershell
.\DebuggerWrapper.exe --target .\vmcheck.exe --level DEBUG --log run.log
```

Tail of `run.log`:

```
[cpuid] hit @ 0x7ff...1907, leaf=0x00000001 sub=0x0 | host ecx=0x7ED8320B | masked ecx=0x7ED8320B
[cpuid] hit @ 0x7ff...1a03, leaf=0x40000000 sub=0x0 | host eax=0 ebx=0 ecx=0 edx=0 | masked eax=0 ebx=0 ecx=0 edx=0
[rdtsc] hit @ 0x7ff...1c9f, virtTsc N -> N+160
...
[core]  Run summary: CPUID intercepts=11, RDTSC intercepts=20, foreign BPs=0, BPs total=12, exit=0
```

The dev box here is bare-metal, so masking is a no-op (HV bit already 0, leaf
0x40000000 already zeros). The same code inside VirtualBox would observe
non-zero raw values in those leaves and rewrite them to the same zero result —
the masking logic is vendor-agnostic.

### 5. Combining layers

Most realistic test runs need BOTH layers active. There is currently no
single-command combined runner — the workflow is:

1. Start the target under `DebuggerWrapper.exe` (CPUID/RDTSC layer).
2. Inside that target's process, separately load `hooksbox.dll` — either by
   building the target to call `LoadLibraryW(L"hooksbox.dll")` at startup,
   or by using a side-loader.

A unified launcher that does both in one shot is on the roadmap (see *Future
Enhancements*).

## 🔬 Testing the protection

Recommended detectors:

- [Al-Khaser](https://github.com/ayoubfaouzi/al-khaser) — broad anti-VM / anti-sandbox / anti-debug.
- [pafish](https://github.com/a0rtega/pafish) — paranoid fish; very close to the threat model HooksBox is tuned against.
- [VMDetect](https://github.com/PerryWerneck/vmdetect/) — second-opinion VM detector.
- `vmcheck.exe` (shipped here) — minimal local sanity check, focused on CPUID + RDTSC paths.

Example al-khaser run with `hooksbox.dll` active:

![collblack](https://github.com/user-attachments/assets/6d55dcf9-ec3a-4cb7-ab18-4c51b9b2e896)

## 📁 Project structure

```
hooxbox/
├── HooksBox.sln
├── HooksBox/                  # → hooksbox.dll
│   ├── HooksBox.vcxproj
│   ├── hook_dll_main.cpp      # DllMain, WMI async worker thread bootstrap
│   ├── hook_manager.{cpp,h}   # MinHook install/remove orchestration
│   ├── config.h               # FakeAcpiTable, masking constants
│   ├── filter_engine.{cpp,h}
│   ├── filters/
│   │   └── vbox_filters.{cpp,h}
│   ├── hooks/                 # One file per masked subsystem
│   │   ├── registry_hooks.cpp     # Reg{Open,QueryValue,EnumKey,EnumValue}*
│   │   ├── file_hooks.cpp         # CreateFile*, FindFirstFile*
│   │   ├── wmi_hooks.cpp          # IWbemServices::ExecQuery, IEnumWbemClassObject::Next, IWbemClassObject::Get + fake-row injection
│   │   ├── firmwaretable_hooks.cpp# Enum/GetSystemFirmwareTable, SMBIOS rewriting
│   │   ├── hypervobj_hooks.cpp    # NtQuerySystemInformation hypervisor objects
│   │   ├── processes_hooks.cpp    # Process32First/Next masking VBoxService etc.
│   │   ├── system_hooks.cpp       # SetupDiEnumDeviceInfo, GetDiskFreeSpaceExW
│   │   ├── network_hooks.cpp      # GetAdaptersAddresses MAC OUI rewrite
│   │   ├── device_hooks.cpp
│   │   ├── power_hooks.cpp
│   │   ├── services_hooks.cpp
│   │   └── window_hooks.cpp
│   ├── tests/
│   └── utils/
│       └── log_utils.{cpp,h}  # sandbox_evasion.log writer (UTF-8 + BOM)
├── Launcher/                  # → launcher.exe
│   ├── Launcher.vcxproj
│   └── launcher.cpp           # Suspended-process + DLL injection, or --debug delegation
├── DebuggerWrapper/           # → DebuggerWrapper.exe  (CPUID/RDTSC masking)
│   ├── DebuggerWrapper.vcxproj
│   ├── README.md              # Module-level deep dive (algorithm, RIP-after-INT3, limits)
│   ├── main.cpp
│   ├── config.{cpp,h}         # CLI parser
│   ├── logger.{cpp,h}         # Levelled UTF-8 logger
│   ├── debugger_core.{cpp,h}  # Debug-event loop + per-instruction handlers
│   ├── breakpoint_manager.{cpp,h}
│   ├── instruction_scanner.{cpp,h}  # PE walk + 0F A2 / 0F 31 byte scan
│   ├── cpuid_handler.{cpp,h}  # __cpuidex emulation + masking
│   └── rdtsc_handler.{cpp,h}  # Virtual TSC + jitter
├── vmcheck/                   # → vmcheck.exe  (validation target)
│   ├── vmcheck.vcxproj
│   └── vmcheck.cpp            # pafish-style HV-bit / vendor / rdtsc_diff probes
└── tools/
    └── minhook/               # Vendored MinHook (static .lib)
```

## 🧠 Future enhancements

Planned features for upcoming releases:

- [ ] Combined launcher that runs `DebuggerWrapper.exe` AND injects `hooksbox.dll` in one command.
- [ ] Extended virtualization support: VMware, Hyper-V, and QEMU masking parity with VirtualBox coverage.
- [ ] Host components: external hooking for deeper protection.
- [ ] Cross-platform compatibility: Linux sandbox-protection modules.
- [ ] Live re-scan of the target's `.text` after `VirtualProtect`/page-execute transitions so `DebuggerWrapper` covers packed/unpacked payloads.
- [ ] Coverage of `CR4.TSD` user-mode trap path (requires a driver).

## ⚠️ Disclaimer & legal

**Important**: this tool is intended for:

- Legitimate security research
- Malware analysis in controlled environments
- Educational purposes
- Improving sandbox and virtualization security

Do **not** use it to:

- Bypass security measures on systems you don't own
- Conduct illegal activities
- Distribute malware

The author assumes no liability for any misuse of this software.
