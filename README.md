# HooksBox — Advanced Anti-Detection Sandbox for Windows

**HooksBox** is a sandbox-environment protection toolkit that conceals
virtualization and debugger artifacts from malware-analysis-aware samples.
Three components ship together:

1. **`hooksbox.dll`** — user-mode API hook DLL (MinHook). Intercepts WinAPI /
   COM / Nt* calls used by `pafish`, `al-khaser`, and similar detectors and
   rewrites their results so they no longer match VirtualBox / VMware /
   Hyper-V / QEMU patterns, nor expose the debugger or the injected DLL itself.
2. **`DebuggerWrapper.exe`** — standalone user-mode debugger. Patches
   `CPUID` and `RDTSC` instructions in the target via Windows Debug API +
   INT3 soft breakpoints, then emulates them with masked results — defeats
   the CPUID-vendor / HV-bit / `RDTSC→CPUID→RDTSC` timing tests that no API
   hook can touch. `CPUID` masking is off by default (see notes below);
   `RDTSC` with virtual TSC + jitter is on.
3. **`launcher.exe`** — front-end that combines the two: interactive prompts
   ask whether to inject `hooksbox.dll` and/or attach `DebuggerWrapper`, then
   spawns the target accordingly.

## 🛡️ The problem

Modern malware uses many independent signals to decide it is running in a
sandbox or under analysis. Conceal one and three more still fire. Four
detection surfaces sit *below* a typical user-mode API hook:

- `CPUID` is a single instruction returning the hypervisor signature
  (`VBoxVBoxVBox`, `Microsoft Hv`, `VMwareVMware`, …) and the HV-present bit
  in leaf 0x1. No DLL hook intercepts it.
- `RDTSC` is a 1-cycle instruction on bare metal that costs thousands of
  cycles on a VM exit. Measuring it around a `CPUID` is a robust VM check
  that, again, no DLL hook can mask.
- Direct PEB / heap memory reads (`PEB->BeingDebugged`, `PEB->NtGlobalFlag`,
  `ProcessHeap->Flags/ForceFlags`) — read straight from segment-relative
  addresses, no API surface.
- Loader walks (`PEB->Ldr`, `EnumProcessModulesEx`, `Module32First/Next`,
  `LdrEnumerateLoadedModules`, raw memory scan with `GetMappedFileName`) —
  expose every injected DLL by file path.

`hooksbox.dll` handles the WinAPI / COM surface and patches the PEB / heap
fields directly, plus unlinks itself from the loader's module lists.
`DebuggerWrapper` handles the two instruction-level probes (currently RDTSC
by default; CPUID is opt-in).

## ✨ The solution

| Layer | What it masks | How |
|---|---|---|
| `hooksbox.dll` (registry/file) | `HKLM\HARDWARE\…`, `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, `HKLM\SYSTEM\…\Services\VBox*`, `vbox*.sys`, `\\.\VBoxMiniRdr*`, … (both W and A entry points). | MinHook trampolines on `Reg{Open,QueryValue,EnumKey}Ex{W,A}`, `GetFileAttributes{W,A}`, `CreateFile{W,A}`. |
| `hooksbox.dll` (process/window/net) | `vboxservice.exe` / `vboxtray.exe`, `VBoxTrayToolWnd*` windows, `08:00:27:*` MAC OUI, `VirtualBox Shared Folders` provider. | `Process32{First,Next}{W,A}`, `FindWindow{,Ex}{W,A}`, `GetAdapters{Info,Addresses}`, `WNetGetProviderName{W,A}`. |
| `hooksbox.dll` (firmware/WMI) | Inflated SMBIOS table count (≥45 to pass al-khaser); ACPI table filtering; `Win32_BIOS`/`Win32_VideoController`/`Win32_PnPEntity`/`Win32_ComputerSystem`/`MSAcpi_ThermalZoneTemperature`/etc. rows. | `Get/EnumSystemFirmwareTable` + IWbemServices::ExecQuery / IEnumWbemClassObject::Next / IWbemClassObject::Get vtable hooks (per-class flag + shared dispatcher). |
| `hooksbox.dll` (debugger) | `IsDebuggerPresent` → FALSE; `CheckRemoteDebuggerPresent` out-flag forced FALSE; `PEB->BeingDebugged`, `PEB->NtGlobalFlag`, `ProcessHeap->Flags/ForceFlags` zeroed in place; `NtQueryInformationProcess` (`ProcessDebugPort`/`Flags`/`ObjectHandle`) masked; `NtClose`/`CloseHandle` SEH-wrap to swallow STATUS_INVALID_HANDLE; `NtQueryObject(ObjectAllTypesInformation)` → `DebugObject.TotalNumberOfObjects = 0`. | API hooks + PEB patch. |
| `hooksbox.dll` (uptime/input) | `GetTickCount{,64}` shifted by +30 min so pafish "uptime < 12 min" reads OK; `GetLastInputInfo` returns `dwTime = GetTickCount() - 50` so al-khaser `lack_user_input` sees fresh activity. | Hook chains. |
| `hooksbox.dll` (DLL-injection hiding) | `hooksbox.dll` unlinked from `PEB->Ldr` (InLoadOrder, InMemoryOrder, InInitializationOrder, HashLinks); `LDR_DATA_TABLE_ENTRY.DllBase/SizeOfImage/Full+Base names` wiped; `GetMappedFileName{W,A}` and the underlying `NtQueryVirtualMemory(MemorySectionName)` syscall return empty for our own address range. | PEB-Ldr patch in `DllMain` + ntdll syscall hook. |
| `DebuggerWrapper.exe` | `CPUID` (clear leaf-1 ECX bit 31; zero leaves 0x40000000–0x400000FF) — **opt-in via `--cpuid`**. `RDTSC` (virtual TSC with configurable jitter) — on by default. | INT3 soft BPs in the target's `.text`, debug-event loop, full instruction emulation. |

Masking in `hooksbox.dll` is **vendor-agnostic**: it removes any hypervisor
signature regardless of which one the host actually runs. Project priority
is VirtualBox closure (`VBoxVBoxVBox`, `VEN_VBOX`, `VBoxGuest`, …) but the
same code paths cover Hyper-V, VMware, QEMU.

### Why CPUID masking in DebuggerWrapper is off by default

The naive `0F A2` byte scan for `CPUID` instructions in the target's `.text`
hits occasional false positives, and the INT3-based BP for a false-positive
hit can leak through (STATUS_BREAKPOINT 0x80000003) and crash the target.
The two anti-VM checks that motivated `CPUID` masking
(`cpuid_is_hypervisor` / `cpuid_hypervisor_vendor`) already report OK on
bare-metal hosts (HV bit = 0, vendor blank). Pass `--cpuid` to opt back in
when running inside an actual hypervisor guest where leaf 1 / leaf
0x40000000 need rewriting.

## 🔧 Key features

- **API hooking engine** — MinHook trampolines on dozens of WinAPI / COM /
  Nt* entry points, in both wide (`*W`) and ANSI (`*A`) flavours so legacy
  ANSI-only detectors (pafish is built without `UNICODE`) are covered.
- **PEB / heap in-place patching** — `BeingDebugged`, `NtGlobalFlag`,
  `ProcessHeap->Flags/ForceFlags` zeroed at DllMain so direct memory reads
  see the bare-metal snapshot.
- **WMI fake-row injection** — when a critical class returns 0 instances
  (e.g. `Win32_Fan`, `MSAcpi_ThermalZoneTemperature`), a synthetic row is
  supplied so the "empty == VM" probe fails. WMI bootstrap is deferred to a
  worker thread to avoid loader-lock deadlock.
- **SMBIOS / ACPI rewriting** — VirtualBox / VMware / etc. strings scrubbed
  in-place; SMBIOS table count inflated above the al-khaser threshold.
- **DLL-injection hiding** — single PEB-Ldr patch hides `hooksbox.dll` from
  every loader-walk-based enumerator; ntdll `NtQueryVirtualMemory` hook
  closes the file-mapping path.
- **Instruction-level masking** via `DebuggerWrapper.exe` — RDTSC + optional
  CPUID patched and emulated with vendor-agnostic rewrites.
- **Inject-race fix** — `DebuggerWrapper` suspends the target's main thread
  between `CreateRemoteThread` and the injector's `EXIT_THREAD`, so
  fast-startup binaries (pafish) can't reach anti-debug code before
  `hooksbox.dll`'s `DllMain` runs.

## 🏗️ Architecture

<img width="1314" height="713" alt="image" src="https://github.com/user-attachments/assets/46bf1f22-a8a8-4af4-9d95-4d967526f696" />

## 🚀 Getting started

### Prerequisites
- Windows 10 / 11 (64-bit)
- Visual Studio 2022 with the *Desktop development with C++* workload
- No driver / admin elevation required for the default workflow

### Build

Clone, then build the solution (three projects, three outputs):

```powershell
git clone https://github.com/x3ucher/hooxbox.git
cd hooxbox
```

In Visual Studio: open `HooksBox.sln`, choose **Debug | x64** (or
**Release | x64**), **Build → Build Solution**.

From a Developer Command Prompt:

```powershell
msbuild HooksBox.sln /p:Configuration=Debug /p:Platform=x64
```

> **Note**: build via `HooksBox.sln`, **not** via the individual `.vcxproj`.
> `HooksBox.vcxproj` references `$(SolutionDir)tools\MinHook\include`, which
> resolves to an empty directory when MSBuild is invoked on the project file
> in isolation. The solution-level build resolves it correctly.

The build produces, all in `x64\Debug\` (or `x64\Release\`):

| Artifact | Project | Purpose |
|---|---|---|
| `hooksbox.dll` | `HooksBox` | API-hook DLL, injected into the target. |
| `launcher.exe` | `Launcher` | Front-end with three modes: raw / inject / debug(+inject). Interactive prompts or CLI flags. |
| `DebuggerWrapper.exe` | `DebuggerWrapper` | User-mode RDTSC (and optional CPUID) masking debugger. Can also chain-inject `hooksbox.dll`. |

All three projects use PlatformToolset v143, target Windows SDK 10.0, x64
configurations.

## ▶️ Running

All commands below assume you are in `x64\Debug\` (or `x64\Release\`). Every
artifact looks for its peers in its own directory, so do **not** move them
apart — `launcher.exe` resolves `hooksbox.dll` and `DebuggerWrapper.exe`
next to itself.

### Launcher — interactive mode (recommended)

```
.\launcher.exe
=== HooksBox Launcher ===

Target executable path (full or relative): pafish.exe
Inject hooksbox.dll (API-hook layer)?               [Y/n]: y
Mask CPUID/RDTSC via DebuggerWrapper (instruction layer)? [y/N]: y
```

The launcher reports the chosen mode and then runs the target. Three modes
are possible depending on the answers:

| Inject? | Debug? | Mode | What happens |
|---|---|---|---|
| n | n | **raw** | `CreateProcess` the target as-is. |
| y | n | **inject** | `CreateProcess(CREATE_SUSPENDED)` + `LoadLibraryW(hooksbox.dll)` + `ResumeThread`. |
| n | y | **debug** | Spawn `DebuggerWrapper.exe --target <path>` — RDTSC (and optional `--cpuid`) masking, no DLL injection. |
| y | y | **debug+inject** | Spawn `DebuggerWrapper.exe --target <path> --inject <hooksbox.dll>` — both layers active. |

### Launcher — non-interactive (CLI)

```powershell
.\launcher.exe <target.exe>                    # interactive prompts for inject/debug
.\launcher.exe --inject <target.exe>           # mode: inject
.\launcher.exe --debug  <target.exe> [extra]   # mode: debug
.\launcher.exe --debug-inject <target.exe> [extra]   # mode: debug + inject
```

Everything after the target path in `--debug` / `--debug-inject` is
forwarded verbatim to `DebuggerWrapper.exe`. Example: turn on the (default-off)
CPUID masking and crank logging up:

```powershell
.\launcher.exe --debug-inject pafish.exe --cpuid --level DEBUG --log run.log
```

### `DebuggerWrapper.exe` — direct invocation

```
DebuggerWrapper.exe --target <path.exe> [options]
```

| Flag | Default | Meaning |
|---|---|---|
| `--target <path>` | *required* | Target executable to run under the debugger. |
| `--args <string>` | *(none)* | Command line passed to the target. |
| `--log <path>` | `debugger_wrapper.log` | Log file. UTF-8 with BOM. |
| `--level ERROR\|INFO\|DEBUG` | `INFO` | Verbosity. `DEBUG` logs every CPUID/RDTSC intercept and every BP install. |
| `--no-stdout` | off | Suppress stdout mirror of the log. |
| `--cpuid` | **off** | Enable CPUID interception. Off by default because the naive byte-pattern scan in the target's `.text` produces occasional false-positive BPs whose INT3s can leak through and crash the target. The two anti-VM checks this would mask already report OK on bare-metal hosts. Enable only inside an actual hypervisor guest. |
| `--no-cpuid` | — | Explicitly disable CPUID interception (default; kept for back-compat). |
| `--no-rdtsc` | off | Don't intercept RDTSC. |
| `--scan-dlls` | off | Also scan loaded DLLs for CPUID/RDTSC patterns. Off by default — naive byte-scan inside ntdll / ucrtbased places BPs on byte patterns that aren't real instructions. |
| `--inject <path>` | *(none)* | `LoadLibraryW` the given DLL into the target via `CreateRemoteThread` at `CREATE_PROCESS_DEBUG_EVENT`. The main thread is suspended until the injector finishes, so the DLL's `DllMain` always runs before the target's first instruction of user code. Used by `launcher.exe --debug-inject` to compose `hooksbox.dll` with the RDTSC/CPUID layer. |
| `--jitter-min <N>` | 80 | Min ticks added per virtual RDTSC. |
| `--jitter-max <N>` | 200 | Max ticks added per virtual RDTSC. |
| `--help` | — | Show usage and exit. |

End-to-end DEBUG log tail (CPUID on, in a VM):

```
[cpuid] hit @ 0x7ff...1907, leaf=0x00000001 sub=0x0 | host ecx=0x80000201 | masked ecx=0x00000201
[cpuid] hit @ 0x7ff...1a03, leaf=0x40000000 sub=0x0 | host eax=… ebx=VBoxVBox… | masked eax=0 ebx=0 ecx=0 edx=0
[rdtsc] hit @ 0x7ff...1c9f, virtTsc N -> N+160
[core]  Run summary: CPUID intercepts=11, RDTSC intercepts=20, foreign BPs=0, BPs total=12, exit=0
```

## 🔬 Testing the protection

Recommended detectors:

- [Al-Khaser](https://github.com/ayoubfaouzi/al-khaser) — broad anti-VM /
  anti-sandbox / anti-debug. Run with `launcher.exe --debug-inject`.
- [pafish](https://github.com/a0rtega/pafish) — paranoid fish; very close to
  the threat model HooksBox is tuned against. Run with
  `launcher.exe --inject` (no debugger needed) or `--debug-inject`.
- [VMDetect](https://github.com/PerryWerneck/vmdetect/) — second-opinion VM
  detector.

Example al-khaser run with `hooksbox.dll` active:

![collblack](https://github.com/user-attachments/assets/6d55dcf9-ec3a-4cb7-ab18-4c51b9b2e896)

### Known limitations

- **`Local Descriptor Table` check (al-khaser)** — uses the `sldt` CPU
  instruction, which has no API surface and doesn't trap in user mode.
  Cannot be masked from a DLL hook; would require patching the `sldt`
  opcode in the target's `.text` (same risk profile as
  `DebuggerWrapper`-style CPUID BPs). Note that the al-khaser test itself
  is broken — it compares against `0xdead0000`, a value bare-metal also
  doesn't return, so the check shows BAD even outside a VM.
- **`IsParentExplorerExe` (al-khaser)** — reports BAD because the target is
  launched by `launcher.exe → DebuggerWrapper.exe`, not by `explorer.exe`.
  Not a masking miss; just a side effect of the chosen runner.
- **CPUID masking in DebuggerWrapper** — opt-in (`--cpuid`); see rationale
  above.

## 📁 Project structure

```
hooxbox/
├── HooksBox.sln
├── HooksBox/                       # → hooksbox.dll
│   ├── HooksBox.vcxproj
│   ├── hook_dll_main.cpp           # DllMain — WMI worker bootstrap + module-hide layer
│   ├── hook_manager.{cpp,h}        # MinHook install/remove orchestration for every hook module
│   ├── config.h                    # FakeAcpiTable, masking constants, VBox name tables
│   ├── filter_engine.{cpp,h}
│   ├── filters/
│   │   └── vbox_filters.{cpp,h}    # VBox-pattern predicates (wide + ANSI)
│   ├── hooks/                      # One file per masked subsystem
│   │   ├── registry_hooks.cpp      # Reg{Open,QueryValue,EnumKey}Ex{W,A}
│   │   ├── file_hooks.cpp          # GetFileAttributes{W,A}
│   │   ├── device_hooks.cpp        # CreateFile{W,A} (VBox device paths)
│   │   ├── window_hooks.cpp        # FindWindow{,Ex}{W,A}
│   │   ├── processes_hooks.cpp     # Process32{First,Next}{W,A}
│   │   ├── network_hooks.cpp       # GetAdapters{Info,Addresses}, WNetGetProviderName{W,A}
│   │   ├── firmwaretable_hooks.cpp # Enum/GetSystemFirmwareTable, SMBIOS scrub + count inflate
│   │   ├── hypervobj_hooks.cpp     # Nt{Open,Query}DirectoryObject — Hyper-V object dir
│   │   ├── system_hooks.cpp        # SetupDiEnumDeviceInfo, GetDiskFreeSpaceExW
│   │   ├── services_hooks.cpp      # EnumServicesStatusExW (VBoxService etc.)
│   │   ├── power_hooks.cpp         # GetPwrCapabilities
│   │   ├── wmi_hooks.cpp           # IWbemServices/ClassObject/EnumClassObject vtable hooks + fake-row injection
│   │   ├── debugger_hooks.cpp      # IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB->BeingDebugged + NtGlobalFlag + ProcessHeap flags patch
│   │   ├── time_hooks.cpp          # GetTickCount{,64} (+30 min uptime offset)
│   │   ├── input_hooks.cpp         # GetLastInputInfo (sync to hooked GetTickCount)
│   │   ├── process_info_hooks.cpp  # NtQueryInformationProcess (DebugPort/Flags/ObjectHandle), NtClose+CloseHandle SEH wrap
│   │   ├── object_info_hooks.cpp   # NtQueryObject(ObjectAllTypesInformation) → DebugObject mask
│   │   └── module_hide_hooks.cpp   # PEB->Ldr unlink + GetMappedFileName{W,A} + NtQueryVirtualMemory hooks
│   └── utils/
│       └── log_utils.{cpp,h}       # sandbox_evasion.log writer (UTF-8 + BOM, CRITICAL_SECTION)
├── Launcher/                       # → launcher.exe
│   ├── Launcher.vcxproj
│   └── launcher.cpp                # Interactive prompts + CLI; dispatches to raw/inject/debug/debug-inject
├── DebuggerWrapper/                # → DebuggerWrapper.exe (RDTSC / optional CPUID masking)
│   ├── DebuggerWrapper.vcxproj
│   ├── README.md                   # Module-level deep dive (algorithm, RIP-after-INT3, limits)
│   ├── main.cpp
│   ├── config.{cpp,h}              # CLI parser (CPUID off by default)
│   ├── logger.{cpp,h}              # Levelled UTF-8 logger
│   ├── debugger_core.{cpp,h}       # Debug-event loop + per-instruction handlers + inject-race fix
│   ├── breakpoint_manager.{cpp,h}
│   ├── instruction_scanner.{cpp,h} # PE walk + 0F A2 / 0F 31 byte scan
│   ├── cpuid_handler.{cpp,h}       # __cpuidex emulation + masking
│   └── rdtsc_handler.{cpp,h}       # Virtual TSC + jitter
└── tools/
    └── MinHook/                    # Vendored MinHook (static .lib + headers)
```

## 🧠 Future enhancements

- [ ] `sldt` opcode patcher (closes the al-khaser LDT check that no hook
      can mask).
- [ ] Live re-scan of the target's `.text` after `VirtualProtect` /
      page-execute transitions so `DebuggerWrapper` covers packed /
      unpacked payloads.
- [ ] Coverage of `CR4.TSD` user-mode trap path (requires a driver).
- [ ] Cross-platform: Linux sandbox-protection modules.

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
