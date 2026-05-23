#include "cpuid_handler.h"

#include <intrin.h>

namespace dbgwrap {

CpuidRegs EmulateAndMaskCpuid(uint32_t leaf, uint32_t subleaf, CpuidRegs& hostRaw) {
    int regs[4] = {0};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));

    hostRaw.eax = static_cast<uint32_t>(regs[0]);
    hostRaw.ebx = static_cast<uint32_t>(regs[1]);
    hostRaw.ecx = static_cast<uint32_t>(regs[2]);
    hostRaw.edx = static_cast<uint32_t>(regs[3]);

    CpuidRegs out = hostRaw;

    // Leaf 0x1: clear the "hypervisor present" bit (ECX bit 31). This is the
    // signal that al-khaser / pafish read for the cpuid_hv_bit check.
    if (leaf == 0x00000001u) {
        out.ecx &= ~(1u << 31);
    }

    // Leafs 0x40000000..0x400000FF: hypervisor vendor / interface leaves.
    // Zero them out so the target sees no hypervisor signature. This is the
    // signal that al-khaser / pafish read for the hypervisor-vendor check
    // ("VBoxVBoxVBox", "Microsoft Hv", "VMwareVMware", "KVMKVMKVM", etc.) —
    // we wipe them all uniformly. Vendor-agnostic by design.
    if (leaf >= 0x40000000u && leaf <= 0x400000FFu) {
        out.eax = 0;
        out.ebx = 0;
        out.ecx = 0;
        out.edx = 0;
    }

    // All other leaves: return honest host data.
    return out;
}

} // namespace dbgwrap
