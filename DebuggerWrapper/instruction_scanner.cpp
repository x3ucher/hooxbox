#include "instruction_scanner.h"
#include "logger.h"

#include <vector>

namespace dbgwrap {

static bool ReadHeaderField(HANDLE hProcess, LPVOID base, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& nt) {
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, base, &dos, sizeof(dos), &read) || read != sizeof(dos)) {
        DBG_LOG_E(L"scanner", L"ReadProcessMemory(DOS header) failed at 0x%p: %s",
                  base, FormatWinError(GetLastError()).c_str());
        return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        DBG_LOG_D(L"scanner", L"Image at 0x%p has no MZ signature; skipping", base);
        return false;
    }

    LPVOID ntAddr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(base) + dos.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntAddr, &nt, sizeof(nt), &read) || read != sizeof(nt)) {
        DBG_LOG_E(L"scanner", L"ReadProcessMemory(NT headers) failed at 0x%p: %s",
                  ntAddr, FormatWinError(GetLastError()).c_str());
        return false;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        DBG_LOG_D(L"scanner", L"Image at 0x%p has no PE signature; skipping", base);
        return false;
    }
    return true;
}

ScanStats ScanAndInstallBreakpoints(HANDLE hProcess,
                                    LPVOID imageBase,
                                    BreakpointManager& bps,
                                    bool wantCpuid,
                                    bool wantRdtsc,
                                    const wchar_t* moduleNameForLog) {
    ScanStats stats{};
    if (!wantCpuid && !wantRdtsc) {
        return stats;
    }

    const wchar_t* modName = moduleNameForLog ? moduleNameForLog : L"<unknown>";

    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadHeaderField(hProcess, imageBase, dos, nt)) {
        return stats;
    }

    const WORD numSections = nt.FileHeader.NumberOfSections;
    const LPVOID firstSecAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(imageBase) +
        dos.e_lfanew +
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt.FileHeader.SizeOfOptionalHeader);

    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, firstSecAddr, sections.data(),
                           sizeof(IMAGE_SECTION_HEADER) * numSections, &read)) {
        DBG_LOG_E(L"scanner", L"ReadProcessMemory(section headers) failed for %s: %s",
                  modName, FormatWinError(GetLastError()).c_str());
        return stats;
    }

    for (const auto& s : sections) {
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (s.Misc.VirtualSize == 0) continue;

        const uintptr_t base = reinterpret_cast<uintptr_t>(imageBase) + s.VirtualAddress;
        const size_t size = s.Misc.VirtualSize;

        // Read the section in chunks to avoid one giant allocation. 64 KiB is
        // plenty; we overlap by 1 byte so a 2-byte pattern that straddles a
        // chunk boundary is still found.
        constexpr size_t CHUNK = 64 * 1024;
        std::vector<uint8_t> buf(CHUNK + 1);

        wchar_t secName[16] = {0};
        for (int i = 0; i < 8 && s.Name[i]; ++i) secName[i] = s.Name[i];
        DBG_LOG_D(L"scanner", L"Scanning section %s of %s, base=0x%p, size=%zu",
                  secName, modName, reinterpret_cast<void*>(base), size);

        size_t offset = 0;
        while (offset < size) {
            const size_t want = (size - offset > CHUNK) ? CHUNK + 1 : (size - offset);
            SIZE_T got = 0;
            if (!ReadProcessMemory(hProcess,
                                   reinterpret_cast<LPCVOID>(base + offset),
                                   buf.data(),
                                   want,
                                   &got)) {
                // Partial read can happen near uncommitted page tails; advance.
                DBG_LOG_D(L"scanner", L"ReadProcessMemory at 0x%p (want=%zu) failed: %s",
                          reinterpret_cast<void*>(base + offset), want,
                          FormatWinError(GetLastError()).c_str());
                break;
            }
            if (got < 2) break;

            for (size_t i = 0; i + 1 < got; ++i) {
                if (buf[i] != 0x0F) continue;
                const uint8_t b1 = buf[i + 1];
                const uintptr_t addr = base + offset + i;

                if (wantCpuid && b1 == 0xA2) {
                    stats.cpuidFound++;
                    if (bps.Install(hProcess, addr, BpKind::Cpuid, 0x0F, 0xA2)) {
                        stats.bpInstalled++;
                        DBG_LOG_D(L"scanner", L"BP installed for CPUID at 0x%p (%s)",
                                  reinterpret_cast<void*>(addr), modName);
                    }
                } else if (wantRdtsc && b1 == 0x31) {
                    stats.rdtscFound++;
                    if (bps.Install(hProcess, addr, BpKind::Rdtsc, 0x0F, 0x31)) {
                        stats.bpInstalled++;
                        DBG_LOG_D(L"scanner", L"BP installed for RDTSC at 0x%p (%s)",
                                  reinterpret_cast<void*>(addr), modName);
                    }
                }
            }

            // advance by CHUNK (keep the overlap byte for next round)
            if (got <= 1) break;
            offset += (got == CHUNK + 1) ? CHUNK : got;
        }
    }

    DBG_LOG_I(L"scanner", L"%s: CPUID patterns=%zu, RDTSC patterns=%zu, BPs installed=%zu",
              modName, stats.cpuidFound, stats.rdtscFound, stats.bpInstalled);
    return stats;
}

} // namespace dbgwrap
