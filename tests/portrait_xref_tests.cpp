#include "../tools/portrait_xref_core.hpp"
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace portrait_probe;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void w16(std::vector<std::uint8_t>& v, std::size_t at, std::uint16_t x) {
    v.at(at) = x & 255; v.at(at + 1) = (x >> 8) & 255;
}
void w32(std::vector<std::uint8_t>& v, std::size_t at, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v.at(at + i) = (x >> (i * 8)) & 255;
}
void w64(std::vector<std::uint8_t>& v, std::size_t at, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) v.at(at + i) = (x >> (i * 8)) & 255;
}
void s8(std::vector<std::uint8_t>& v, std::size_t at, const std::string& s) {
    for (std::size_t i = 0; i < s.size(); ++i) v.at(at + i) = s[i];
}
void s16(std::vector<std::uint8_t>& v, std::size_t at, const std::string& s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        v.at(at + 2*i) = s[i];
        v.at(at + 2*i + 1) = 0;
    }
}
int main() {
    try {
        std::vector<std::uint8_t> v(0x1000, 0);
        w16(v, 0, 0x5A4D); w32(v, 0x3c, 0x80);
        w32(v, 0x80, 0x4550); w16(v, 0x84, 0x8664);
        w16(v, 0x86, 2); w16(v, 0x94, 0xf0); w16(v, 0x98, 0x20b);
        w64(v, 0x98 + 24, 0x140000000ULL);
        const std::size_t sec1 = 0x188u, sec2 = sec1 + 40;
        w32(v, sec1 + 12, 0x1000); w32(v, sec1 + 16, 0x200);
        w32(v, sec1 + 20, 0x200); w32(v, sec1 + 36, 0x60000020);
        w32(v, sec2 + 12, 0x2000); w32(v, sec2 + 16, 0x400);
        w32(v, sec2 + 20, 0x400); w32(v, sec2 + 36, 0x40000040);

        const std::string label = "Photo: Force Real Photo";
        s16(v, 0x420, label);
        s8(v, 0x4a0, "PortraitTeam");
        w64(v, 0x480, 0x140002020ULL); // absolute pointer to UTF-16LE label
        v[0x210] = 0x48; v[0x211] = 0x8d; v[0x212] = 0x0d;
        w32(v, 0x213, 0x2020 - 0x1017); // LEA: direct RIP-relative label
        v[0x220] = 0x48; v[0x221] = 0x8b; v[0x222] = 0x0d;
        w32(v, 0x223, 0x2080 - 0x1027); // MOV: RIP-relative pointer slot

        const auto report = analyze(v.data(), v.size());
        require(report.valid, "Valid x64 PE rejected");
        bool string_found = false, direct_found = false, indirect_found = false;
        for (const auto& s : report.strings)
            if (s.label == label && s.encoding == "UTF-16LE" && s.file_offset == 0x420)
                string_found = true;
        for (const auto& x : report.references) {
            if (x.label != label) continue;
            if (x.instruction_file_offset == 0x210 &&
                x.reference_kind == "direct string reference") direct_found = true;
            if (x.instruction_file_offset == 0x220 &&
                x.reference_kind == "via data pointer slot") indirect_found = true;
        }
        require(string_found, "Expected UTF-16LE label was not discovered");
        require(direct_found, "Expected direct RIP-relative candidate was not discovered");
        require(indirect_found, "Expected pointer table candidate was not discovered");
        for (const auto& x : report.references) {
            if (x.label != label) continue;
            require(!x.context_bytes.empty(), "Missing context bytes");
            require(x.context_bytes.size() <= 231, "Context exceeds 64+7+160 bound");
            require(x.candidate_byte_index < x.context_bytes.size(), "Invalid byte index");
            require(x.context_bytes.at(x.candidate_byte_index) == 0x48,
                    "Context should include the candidate REX byte");
            require(x.context_file_offset + x.candidate_byte_index ==
                        x.instruction_file_offset, "Wrong context file offset");
            require(static_cast<std::uint64_t>(x.context_rva) +
                        x.candidate_byte_index == x.instruction_rva,
                    "Wrong context RVA");
        }
        const std::string formatted = format_report(report);
        require(formatted.find("NOT CONFIRMED") != std::string::npos,
                "Heuristic warning is missing");
        require(formatted.find("Static code window starts at file_offset=") !=
                    std::string::npos, "Code window is missing from report");
        require(formatted.find("48 8D 0D") != std::string::npos,
                "Expected LEA bytes missing from code window");
        const auto malformed = analyze(reinterpret_cast<const std::uint8_t*>("broken"), 6);
        require(!malformed.valid, "Malformed PE should be rejected");
        std::cout << "PASS: PE parsing, UTF-16LE detection, direct/indirect "
                     "candidates and invalid-file rejection\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
