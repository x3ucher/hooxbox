#ifndef DBGWRAPPER_CPUID_HANDLER_H
#define DBGWRAPPER_CPUID_HANDLER_H

#include <windows.h>
#include <cstdint>

namespace dbgwrap {

struct CpuidRegs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

// Emulate one CPUID, with masking applied so VM detection cannot tell that a
// hypervisor is present.
//
// IMPORTANT: this function is vendor-agnostic. The host's __cpuidex may
// return any vendor in leaf 0x40000000 ("Microsoft Hv" on the Hyper-V test
// host the agent runs on; "VBoxVBoxVBox" inside a VirtualBox VM, etc.). We
// strip the hypervisor footprint regardless of which vendor is observed —
// this is correct behaviour for both environments.
//
// Returned regs are written back into the target's thread context by the
// caller; the caller is also responsible for stepping Rip past the 2-byte
// CPUID encoding.
CpuidRegs EmulateAndMaskCpuid(uint32_t leaf, uint32_t subleaf,
                              CpuidRegs& hostRaw /*out: pre-mask*/);

} // namespace dbgwrap

#endif // DBGWRAPPER_CPUID_HANDLER_H
