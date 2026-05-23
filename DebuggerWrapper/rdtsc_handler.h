#ifndef DBGWRAPPER_RDTSC_HANDLER_H
#define DBGWRAPPER_RDTSC_HANDLER_H

#include <cstdint>

namespace dbgwrap {

// Virtual TSC: starts from __rdtsc() at debugger startup and only ever advances
// by a configurable jitter on each RDTSC interception. Crucially, the cost of
// emulating a CPUID between two RDTSCs is *zero* virtual ticks — that is what
// hides the VM-exit latency that real CPUID-on-hypervisor would otherwise
// produce.
//
// Not thread-safe: the Windows debugger event loop is single-threaded, and
// every interception ultimately runs from that loop, so a plain counter is
// sufficient.
class VirtualTsc {
public:
    void Init(uint32_t jitterMin, uint32_t jitterMax);

    // Advance by a pseudorandom amount in [jitterMin, jitterMax], then return
    // the new virtual TSC value.
    uint64_t Tick();

    uint64_t Current() const { return current_; }

private:
    uint64_t current_ = 0;
    uint32_t jitterMin_ = 80;
    uint32_t jitterMax_ = 200;
    uint64_t rngState_ = 0;
};

} // namespace dbgwrap

#endif // DBGWRAPPER_RDTSC_HANDLER_H
