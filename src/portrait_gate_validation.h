#pragma once
// Verified Ghidra control-flow bytes for ONE NBA2K26.exe build.
// This module is deliberately read-only. It does not implement a runtime patch.
#include <array>
#include <cstdint>
namespace portrait_gate {
struct BranchSite {
    std::uint32_t rva;
    std::uint8_t opcode;
    std::uint8_t rel8;
    std::uint32_t target_rva;
    const char* label;
};
inline constexpr std::array<BranchSite,4> kExpectedBranches = {{
    {0x025F6DB8u, 0x74u, 0x05u, 0x025F6DBFu, "invalid request ID #1"},
    {0x025F6DBDu, 0x74u, 0x03u, 0x025F6DC2u, "team match #1"},
    {0x025F6DE9u, 0x74u, 0x04u, 0x025F6DEFu, "invalid request ID #2"},
    {0x025F6DEDu, 0x74u, 0x03u, 0x025F6DF2u, "team match #2"}
}};
inline constexpr bool CheckBranch(const BranchSite& site,
                                  std::uint8_t opcode,
                                  std::uint8_t rel8) {
    return opcode == site.opcode && rel8 == site.rel8 &&
        (site.rva + 2u + static_cast<std::int8_t>(rel8)) == site.target_rva;
}
} // namespace portrait_gate
