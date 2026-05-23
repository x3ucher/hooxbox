# HooksBox — Advanced Anti-Detection Sandbox for Windows

**HooksBox** is a sandbox-environment protection toolkit that conceals
virtualization and debugger artifacts from malware-analysis-aware samples.
Masking is layered across **host configuration** (before the VM boots) and
**in-guest runtime** (after the VM starts), with four components total:

1. **`vb-masquerade.ps1`** *(host, pre-boot)* — PowerShell script that
   reconfigures a VirtualBox VM via `VBoxManage setextradata` / `modifyvm`.
   Spoofs SMBIOS/DMI strings, ACPI OEM ID, disk model and serial,
   network MAC OUI, disables paravirt provider, and tunes TSC mode so
   `rdtsc-cpuid-rdtsc` deltas shrink. Profile-based (Dell / Lenovo / HP / Asus).
   Runs once on the host **before booting** the VM; eliminates VBox
   fingerprints at the firmware / hypervisor level, so the in-guest layers
   have less to mask. Includes backup + `-Restore` rollback.
2. **`hooksbox.dll`** *(guest, runtime)* — user-mode API hook DLL (MinHook).
   Intercepts WinAPI / COM / Nt* calls used by `pafish`, `al-khaser`, and
   similar detectors and rewrites their results so they no longer match
   VirtualBox / VMware / Hyper-V / QEMU patterns, nor expose the debugger
   or the injected DLL itself. Covers what `vb-masquerade.ps1` cannot reach
   from outside the VM: Guest Additions registry keys / files / services,
   `\Device\VBox*` kernel objects, debugger detection, DLL-injection hiding.
3. **`DebuggerWrapper.exe`** *(guest, runtime)* — standalone user-mode
   debugger. Patches `CPUID` and `RDTSC` instructions in the target via
   Windows Debug API + INT3 soft breakpoints, then emulates them with
   masked results — defeats the CPUID-vendor / HV-bit /
   `RDTSC→CPUID→RDTSC` timing tests. Needed when `vb-masquerade.ps1`
   cannot apply its TSC / HV-bit knobs because the host runs in NEM mode
   (Hyper-V / WSL2 / VBS enabled). `CPUID` masking is off by default;
   `RDTSC` with virtual TSC + jitter is on.
4. **`launcher.exe`** *(guest, orchestration)* — front-end that combines
   the runtime layers: interactive prompts ask whether to inject
   `hooksbox.dll` and/or attach `DebuggerWrapper`, then spawns the target
   accordingly.

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

The full stack is **defence-in-depth**: each layer eliminates a different
class of detection signals. When `vb-masquerade.ps1` is applied to the VM
first, the in-guest layers (`hooksbox.dll`, `DebuggerWrapper.exe`) have
substantially less work to do — many SMBIOS / ACPI / disk / MAC / CPUID
checks already pass *at the source* and never even reach API-hook code.

| Layer | Where it runs | What it masks | How |
|---|---|---|---|
| `vb-masquerade.ps1` | **Host**, before VM boot | SMBIOS/DMI (BIOS/System/Board/Chassis vendor + product + serial), ACPI OEM/Creator ID, disk model + serial (SATA + IDE), MAC OUI (replaces `08:00:27` with real Dell/Lenovo/HP/Asus OUI), hypervisor bit in CPUID(1).ECX[31] via `--paravirt-provider none`, TSC mode (`TSCTiedToExecution=1` shrinks `rdtsc-cpuid-rdtsc` delta), BIOS boot logo/menu. | `VBoxManage setextradata` (VBoxInternal/Devices/{pcbios,acpi,ahci,piix3ide}/...) + `VBoxManage modifyvm`. Backup of previous values for `-Restore`. |
| `hooksbox.dll` (registry/file) | Guest, runtime | `HKLM\HARDWARE\…`, `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, `HKLM\SYSTEM\…\Services\VBox*`, `vbox*.sys`, `\\.\VBoxMiniRdr*`, … (both W and A entry points). | MinHook trampolines on `Reg{Open,QueryValue,EnumKey}Ex{W,A}`, `GetFileAttributes{W,A}`, `CreateFile{W,A}`. |
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

- **Host-level VirtualBox masking** via `vb-masquerade.ps1` — replaces VBox
  fingerprints in SMBIOS/DMI, ACPI, disk identity, MAC OUI, CPUID HV-bit
  and TSC mode **before the VM boots**, so the guest OS itself sees a
  Dell/Lenovo/HP/Asus-branded machine. Backup + `-Restore` rollback.
  Detects NEM mode (Hyper-V/WSL2/VBS on host) and skips incompatible knobs
  with a clear warning + bcdedit instructions.
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

### Recommended workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1 — on the HOST, BEFORE booting the VM                         │
│ ─────────────────────────────────────────────                       │
│   .\vb-masquerade.ps1 -VM "MyAnalysisVM" -MaskProfile Dell          │
│                                                                     │
│ Removes VBox-specific SMBIOS / ACPI / disk / MAC / TSC / CPUID      │
│ signatures at the hypervisor level. Reboot the VM to take effect.   │
└─────────────────────────────────────────────────────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 2 — INSIDE the VM, when running a detector / sample            │
│ ────────────────────────────────────────────────────                │
│   .\launcher.exe                                                    │
│   <interactive prompts for inject + debug>                          │
│                                                                     │
│ Runs target with hooksbox.dll (API/Nt-level masking) and optionally │
│ DebuggerWrapper.exe (CPU-instruction masking).                      │
└─────────────────────────────────────────────────────────────────────┘
```

`vb-masquerade.ps1` is a **one-time per VM** action (re-run only when
switching profiles or after `-Restore`). The guest-side layers run **per
target launch** through `launcher.exe`.

## 🚀 Getting started

### Prerequisites
- Windows 10 / 11 (64-bit)
- Visual Studio 2022 with the *Desktop development with C++* workload (for
  building the C++ components)
- VirtualBox 7.x (or 6.x — `vb-masquerade.ps1` falls back to old option
  names automatically) — only needed for the host-side `vb-masquerade.ps1`
- PowerShell 5.1+ — for `vb-masquerade.ps1`
- No driver / admin elevation required for the runtime workflow.
  `vb-masquerade.ps1` needs whatever rights `VBoxManage` itself needs
  (usually none).

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

All in-VM commands below assume you are in `x64\Debug\` (or `x64\Release\`).
Every artifact looks for its peers in its own directory, so do **not** move
them apart — `launcher.exe` resolves `hooksbox.dll` and
`DebuggerWrapper.exe` next to itself.

### Step 1 — `vb-masquerade.ps1` (host, before VM boot)

Run from a PowerShell prompt on the **host** machine (where VirtualBox is
installed). The **VM must be powered off**; the script verifies this.

```powershell
# Interactive — script lists registered VMs and asks which to mask
.\vb-masquerade.ps1

# Explicit VM, default Dell profile
.\vb-masquerade.ps1 -VM "Win10-Analysis"

# Different host identity
.\vb-masquerade.ps1 -VM "Win10-Analysis" -MaskProfile Lenovo

# Preview the changes without applying them
.\vb-masquerade.ps1 -VM "Win10-Analysis" -DryRun

# Roll back to whatever the extradata was before the last apply
.\vb-masquerade.ps1 -VM "Win10-Analysis" -Restore
```

Parameters:

| Parameter | Default | Effect |
|---|---|---|
| `-VM <name\|UUID>` | (interactive picker) | Which VirtualBox VM to reconfigure. |
| `-MaskProfile Dell\|Lenovo\|HP\|Asus` | `Dell` | Which real OEM identity to impersonate. Affects every DMI string + ACPI OEM ID + MAC OUI prefix. |
| `-Restore` | off | Reapply the previously-saved extradata snapshot, undoing the masking. Snapshot is stored at `%USERPROFILE%\.vbox-mask-backups\<VM>.backup.txt`. |
| `-DryRun` | off | Print the `VBoxManage` commands without executing. |

The script touches **only the named VM**, never global VirtualBox settings,
and always snapshots the prior values before modifying them. Reboot the VM
once after running to make changes take effect.

**NEM mode (Hyper-V / WSL2 / VBS on host)**: when Windows ships with a
hypervisor active, VirtualBox cannot use its own `VBoxDrv` and falls back
to NEM (Native Execution Manager) on top of Windows Hypervisor Platform.
In NEM mode VirtualBox silently ignores some `VBoxInternal/*` keys
(specifically `TM/TSCTiedToExecution` and `CPUM/EnableHVP`). The script
detects this via `Win32_ComputerSystem.HypervisorPresent` and skips those
keys with a warning + `bcdedit` instructions for disabling Hyper-V if
full coverage is needed. Without NEM, all keys apply.

What `vb-masquerade.ps1` does **not** cover (left for `hooksbox.dll`):

- VirtualBox **Guest Additions** artefacts inside the VM (registry keys,
  files in `C:\WINDOWS\system32\drivers\VBox*.sys` and friends, services
  `VBoxService`/`VBoxTray`, processes, windows). Either don't install GA,
  or run `hooksbox.dll` to mask them.
- `\Device\VBox*` kernel object namespace.
- Anti-debug detection (PEB, `IsDebuggerPresent`, `NtQueryInformationProcess`,
  `NtClose` invalid-handle, `NtQueryObject` DebugObject, …).
- Full `rdtsc-cpuid-rdtsc` timing in NEM mode (requires `DebuggerWrapper`).

### Step 2 — Launcher — interactive mode (recommended)

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
  anti-sandbox / anti-debug. Recommended order: first apply
  `vb-masquerade.ps1` to the VM, then inside the guest run with
  `launcher.exe --debug-inject al-khaser_x64.exe`.
- [pafish](https://github.com/a0rtega/pafish) — paranoid fish; very close to
  the threat model HooksBox is tuned against. After `vb-masquerade.ps1`
  most VBox checks already pass; inside the guest
  `launcher.exe --inject pafish.exe` is usually enough (no
  `DebuggerWrapper` needed because pafish skips most CPU-instruction
  timings).
- [VMDetect](https://github.com/PerryWerneck/vmdetect/) — second-opinion VM
  detector.

Example al-khaser run with `hooksbox.dll` active:

![collblack](https://github.com/user-attachments/assets/6d55dcf9-ec3a-4cb7-ab18-4c51b9b2e896)

### Effect of `vb-masquerade.ps1` on detector output

With the script applied **before** boot, the following checks flip from
BAD to OK *without any in-guest hook firing* (the data they read is
already clean at the firmware / hypervisor level):

| Detector | Check |
|---|---|
| pafish | `Scsi port → bus → target → LUN → 0 identifier` (was VBOX) |
| pafish | `HKLM\HARDWARE\Description\System SystemBiosVersion` |
| pafish | `HKLM\HARDWARE\Description\System SystemBiosDate` |
| pafish | MAC starts with `08:00:27` |
| al-khaser | `Win32_BIOS.SerialNumber`, `Win32_BaseBoard.Product`/`Manufacturer`, `Win32_ComputerSystem.Model`/`Manufacturer`, ACPI table strings |
| al-khaser | `cpuid_is_hypervisor` (HV-bit cleared at VMM, so `--cpuid` opt-in not needed) |
| al-khaser | `cpuid_hypervisor_vendor` (vendor leaves 0x40000000 zeroed) |
| al-khaser | Various disk-model / serial WMI probes |
| al-khaser | RDTSC timing — significantly reduced delta thanks to `TSCTiedToExecution=1` (mostly removes the need for `DebuggerWrapper`'s virtual TSC, but not 100%) |

In **NEM mode** the TSC + HV-bit knobs are skipped; the remaining
hypervisor leak surfaces are then cleaned up by `DebuggerWrapper.exe` on
demand.

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
  above. Usually unnecessary if `vb-masquerade.ps1` was applied (it clears
  the HV-bit at the VMM via `--paravirt-provider none` + `EnableHVP=0`).
- **`vb-masquerade.ps1` in NEM mode** — `TSCTiedToExecution` and
  `EnableHVP` are silently skipped. Use `DebuggerWrapper.exe --rdtsc` for
  TSC and `--cpuid` for HV-bit/vendor as fallback.

## 📁 Project structure

```
hooxbox/
├── HooksBox.sln
├── vb-masquerade.ps1               # → host-side pre-boot VBox config masking
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
