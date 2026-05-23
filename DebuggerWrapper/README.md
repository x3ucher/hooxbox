# DebuggerWrapper

User-mode debugger that masks `CPUID` and `RDTSC` for a target process so that
common anti-VM checks (HV-bit in CPUID leaf 0x1, hypervisor-vendor leaves
0x40000000+, and the `RDTSC -> CPUID -> RDTSC` timing test) do not fire.

POC component of the HooksBox anti-VM research project. Standalone executable —
does not depend on `hooksbox.dll`.

## How it works

1. Launches the target via `CreateProcessW(DEBUG_ONLY_THIS_PROCESS)`.
2. On `CREATE_PROCESS_DEBUG_EVENT` (and optionally on `LOAD_DLL_DEBUG_EVENT`,
   see `--scan-dlls`) it linearly scans the executable sections of the loaded
   PE image for the 2-byte opcodes `0F A2` (CPUID) and `0F 31` (RDTSC), and
   installs INT3 (`0xCC`) breakpoints over the first byte of each.
3. On `EXCEPTION_BREAKPOINT` it looks the fault address up in the BP table:
   - **CPUID** — emulates the instruction on the host via `__cpuidex`, masks
     the result (clear HV-bit in leaf 0x1; zero leaves 0x40000000–0x400000FF),
     writes `EAX/EBX/ECX/EDX` back into the thread context, advances `RIP`,
     continues with `DBG_CONTINUE`.
   - **RDTSC** — advances a virtual TSC by a random jitter in
     `[--jitter-min, --jitter-max]`, writes the new value into `EDX:EAX`,
     advances `RIP`, continues. Crucially, virtual time does **not** advance
     while a CPUID is emulated, so `RDTSC -> CPUID -> RDTSC` looks fast.

The original instruction bytes are *not* restored after a hit — emulation
fully replaces the instruction and `RIP` is moved past it.

## Build

Open `HooksBox.sln` in Visual Studio 2022 and build the `DebuggerWrapper`
project under `Debug|x64` or `Release|x64`. Or from a Developer Command
Prompt:

```
msbuild HooksBox.sln /p:Configuration=Debug /p:Platform=x64 /t:DebuggerWrapper
```

`vmcheck` (sibling project) is the validation target — build it the same way.

## Usage

```
DebuggerWrapper.exe --target <path-to-target.exe> [options]

  --target <path>            Required. Path to the target executable.
  --args   <string>          Command line passed to the target.
  --log    <path>            Log file path (default: debugger_wrapper.log).
  --level  ERROR|INFO|DEBUG  Verbosity (default: INFO).
  --no-stdout                Suppress stdout mirror.
  --no-cpuid                 Disable CPUID interception.
  --no-rdtsc                 Disable RDTSC interception.
  --scan-dlls                Also scan loaded DLLs (off by default).
  --jitter-min <N>           Min ticks added per virtual RDTSC (default: 80).
  --jitter-max <N>           Max ticks added per virtual RDTSC (default: 200).
  --help
```

It can also be invoked from the existing `Launcher`:

```
Launcher.exe --debug C:\path\vmcheck.exe
```

The Launcher resolves `DebuggerWrapper.exe` next to itself and forwards
everything after the target path.

## Example session

Direct (no debugger):

```
> vmcheck.exe
[CHECK] rdtsc_diff             : CLEAN
[CHECK] rdtsc_diff_vmexit      : CLEAN
[CHECK] cpuid_hv_bit           : CLEAN
[CHECK] cpuid_vendor_leaf      : CLEAN    -- (zeros)
```

Under DebuggerWrapper, `--level DEBUG`:

```
> DebuggerWrapper.exe --target vmcheck.exe --level DEBUG
...
[cpuid] hit @ 0x7ff...1907, eax(leaf)=0x00000001 ... | host ecx=0x7ED8320B (HV bit clear) | masked ecx=0x7ED8320B
[cpuid] hit @ 0x7ff...1a03, eax(leaf)=0x40000000 ... | host eax=0x00000000 ... | masked eax=0x00000000 ...
[rdtsc] hit @ ..., virtTsc 18072... -> 18072... (delta=166)
...
[core]  Run summary: CPUID intercepts=11, RDTSC intercepts=20, foreign BPs=0, BPs total=12, exit=0
```

(The dev host here is bare-metal AMD — see *Host vs. target VM* below — so
masking is a no-op. Inside VirtualBox the leaf-1 ECX would have bit 31 set
and leaf 0x40000000 would read `VBoxVBoxVBox`; the same masking code wipes
both vendor-agnostically.)

## Host vs. target VM

The agent / developer machine on which DebuggerWrapper is built and unit-tested
is **not** the deployment target. The deployment target of the HooksBox
project is a **VirtualBox** guest (`cpuid leaf 0x40000000 → VBoxVBoxVBox`).
The dev host may be bare-metal, Hyper-V root partition (`Microsoft Hv`), or
anything else.

Masking is **vendor-agnostic by design**: leaf 0x1 ECX bit 31 is always
cleared, and leaves 0x40000000..0x400000FF are always zeroed, regardless of
what the host actually returned. The log records both the raw host result
and the masked result so the operator can verify the correct rewrite
happened on whatever host they ran on.

## Known limitations (intentional POC scope)

| Limitation | Notes |
|---|---|
| Doesn't see code that appears after image load | Packed / unpacked malware: code revealed at runtime is missed by the initial scan. A live re-scan on `VirtualProtect`/page-execute transitions would be needed. |
| `RDTSC` via `CR4.TSD` not covered | User-mode trap is via INT3 — no way to catch a privileged trap from user mode. Needs a driver. |
| Target can detect the debugger | `IsDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`, manual PEB read — all unhandled. PEB-mode anti-debug is out of scope. |
| Naive byte scan has false positives | `0F A2` / `0F 31` can occur inside immediates or jump tables. False BPs are logged on hit and emulation proceeds; this can destabilise the target. Default is **exe-only** (`--scan-dlls` off) to limit the blast radius — vmcheck and similar microbenchmarks only ever emit these opcodes from the main image via intrinsics. |
| Timing check passes only if both surrounding RDTSCs are intercepted | If a target inlines `__rdtsc()` calls that the scan happens to miss, the gap will show real host latency. Verify in the log that the expected RDTSC pair fired. |

## Files

| File | Role |
|---|---|
| `main.cpp` | Entry point, argv → Config, Logger init, top-level RunDebuggerLoop call. |
| `config.{h,cpp}` | Command-line parser, defaults, usage text. |
| `logger.{h,cpp}` | Levelled logger (Error/Info/Debug), UTF-8 file + optional stdout mirror, machine-greppable format. Shares the spirit of `HooksBox/utils/log_utils.cpp`. |
| `debugger_core.{h,cpp}` | The debug-event loop and the two on-hit handlers. |
| `breakpoint_manager.{h,cpp}` | Address → BpInfo map + INT3 patcher. |
| `instruction_scanner.{h,cpp}` | PE-section walk + naive `0F A2`/`0F 31` byte scan + BP install. |
| `cpuid_handler.{h,cpp}` | `__cpuidex` wrapper + masking (HV-bit, leaf 0x40000000+). |
| `rdtsc_handler.{h,cpp}` | Virtual TSC with configurable jitter. |
