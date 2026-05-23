#include "rdtsc_handler.h"

#include <intrin.h>
#include <windows.h>

namespace dbgwrap {

static uint64_t SplitMix64(uint64_t& s) {
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

void VirtualTsc::Init(uint32_t jitterMin, uint32_t jitterMax) {
    current_   = __rdtsc();
    jitterMin_ = jitterMin;
    jitterMax_ = (jitterMax < jitterMin) ? jitterMin : jitterMax;

    // Seed from a couple of cheap sources — the value doesn't need to be
    // cryptographically strong, only varied enough that the per-RDTSC jitter
    // isn't trivially predictable.
    rngState_ = current_ ^ static_cast<uint64_t>(GetTickCount64()) ^
                (static_cast<uint64_t>(GetCurrentProcessId()) << 32);
}

uint64_t VirtualTsc::Tick() {
    const uint32_t span = (jitterMax_ - jitterMin_ + 1);
    const uint64_t r = SplitMix64(rngState_);
    const uint32_t jitter = jitterMin_ + static_cast<uint32_t>(r % span);
    current_ += jitter;
    return current_;
}

} // namespace dbgwrap
