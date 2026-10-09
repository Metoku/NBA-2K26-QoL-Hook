#include "portrait_xref_core.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace portrait_probe {
namespace {
constexpr std::uint32_t execute_flag = 0x20000000u;
constexpr std::size_t max_strings_per_term = 12;
constexpr std::size_t max_references_per_term = 48;
struct Section {
    std::uint64_t file_start{};
    std::uint64_t file_size{};
    std::uint32_t rva{};
    bool executable = false;
};
struct Target {
    std::string label;
    std::string kind;
};
struct Needle {
    std::string label;
    std::vector<std::uint8_t> bytes;
    std::string encoding;
};

bool fits(std::size_t size, std::uint64_t offset, std::uint64_t width) {
    return offset <= size && width <= size - offset;
}
std::uint16_t read16(const std::uint8_t* p) {
    return std::uint16_t(p[0]) | (std::uint16_t(p[1]) << 8);
}
std::uint32_t read32(const std::uint8_t* p) {
    return std::uint32_t(read16(p)) | (std::uint32_t(read16(p + 2)) << 16);
}
std::uint64_t read64(const std::uint8_t* p) {
    return std::uint64_t(read32(p)) | (std::uint64_t(read32(p + 4)) << 32);
}
std::vector<Needle> needles() {
    const std::array<std::string, 7> terms = {
        "Photo: Force Real Photo", "Photo: Always Render", "Photo: Use Assigned Team",
        "Style: Action Shot", "Style: Head Shot", "PortraitTeam", "ActionShotTeam"
    };
    std::vector<Needle> out;
    for (const auto& t : terms) {
        out.push_back(Needle{t, std::vector<std::uint8_t>(t.begin(), t.end()), "ASCII"});
        std::vector<std::uint8_t> wide;
        wide.reserve(t.size() * 2);
        for (char c : t) {
            wide.push_back(static_cast<std::uint8_t>(c));
            wide.push_back(0);
        }
        out.push_back(Needle{t, std::move(wide), "UTF-16LE"});
    }
    return out;
}
}

Report analyze(const std::uint8_t* file, std::size_t size) {
    Report report;
    report.file_size = size;
    if (!file || !fits(size, 0, 64) || read16(file) != 0x5a4d) {
        report.error = "Not a valid Windows PE file (DOS/MZ header missing).";
        return report;
    }
    const std::uint64_t pe = read32(file + 0x3c);
    if (!fits(size, pe, 24) || read32(file + pe) != 0x00004550) {
        report.error = "Invalid or truncated PE header.";
        return report;
    }
    const std::uint16_t machine = read16(file + pe + 4);
    const std::uint16_t section_count = read16(file + pe + 6);
    const std::uint16_t optional_size = read16(file + pe + 20);
    if (machine != 0x8664 || section_count == 0 || section_count > 96 ||
        optional_size < 32 || !fits(size, pe + 24, optional_size) ||
        read16(file + pe + 24) != 0x20b) {
        report.error = "Expected a valid 64-bit (x64) PE with a complete optional header.";
        return report;
    }
    const std::uint64_t imagebase = read64(file + pe + 24 + 24);
    const std::uint64_t sections_offset = pe + 24 + optional_size;
    if (!fits(size, sections_offset, std::uint64_t(section_count) * 40)) {
        report.error = "PE section table exceeds file size.";
        return report;
    }
    std::vector<Section> sections;
    for (std::uint32_t i = 0; i < section_count; ++i) {
        const std::uint64_t sh = sections_offset + std::uint64_t(i) * 40;
        const std::uint32_t virtual_address = read32(file + sh + 12);
        const std::uint32_t raw_size = read32(file + sh + 16);
        const std::uint32_t raw_pointer = read32(file + sh + 20);
        const std::uint32_t characteristics = read32(file + sh + 36);
        if (raw_size == 0) continue;
        if (!fits(size, raw_pointer, raw_size)) {
            report.error = "PE section raw bytes exceed file size.";
            return report;
        }
        // All converted RVAs must fit in the original 32-bit PE RVA domain.
        if (std::uint64_t(virtual_address) + raw_size > 0x100000000ull) {
            report.error = "PE section RVA range is invalid.";
            return report;
        }
        sections.push_back(Section{raw_pointer, raw_size, virtual_address,
                                   (characteristics & execute_flag) != 0});
    }
    if (sections.empty()) {
        report.error = "No readable PE sections were found.";
        return report;
    }
    report.valid = true;

    // Discover literal photo-mode strings in non-executable sections.
    // Finding a string is evidence of static data only, NOT that MyNBA uses it.
    std::map<std::uint32_t, Target> targets;
    for (const auto& needle : needles()) {
        std::size_t count = 0;
        for (const Section& sec : sections) {
            if (sec.executable || sec.file_size < needle.bytes.size()) continue;
            const auto* begin = file + sec.file_start;
            const auto* end = begin + sec.file_size;
            auto* cursor = begin;
            while (cursor < end) {
                auto* found = std::search(cursor, end,
                                          needle.bytes.begin(), needle.bytes.end());
                if (found == end) break;
                const auto delta = static_cast<std::uint64_t>(found - begin);
                const auto rva = static_cast<std::uint32_t>(std::uint64_t(sec.rva) + delta);
                report.strings.push_back(StringHit{needle.label, needle.encoding,
                                                    sec.file_start + delta, rva});
                targets.emplace(rva, Target{needle.label, "direct string reference"});
                if (++count >= max_strings_per_term) break;
                cursor = found + 1;
            }
            if (count >= max_strings_per_term) break;
        }
    }

    // Recognize possible VA pointer-table entries within data sections.
    // A code reference to a pointer slot may be indirect and needs disassembly.
    if (!targets.empty()) {
        for (const Section& sec : sections) {
            if (sec.executable || sec.file_size < 8) continue;
            const auto* p = file + sec.file_start;
            for (std::uint64_t i = 0; i + 8 <= sec.file_size; ++i) {
                const auto value = read64(p + i);
                if (value < imagebase || value - imagebase > 0xffffffffull) continue;
                const auto found = targets.find(static_cast<std::uint32_t>(value - imagebase));
                if (found != targets.end()) {
                    const auto rva = static_cast<std::uint32_t>(std::uint64_t(sec.rva) + i);
                    targets.emplace(rva, Target{found->second.label, "via data pointer slot"});
                }
            }
        }
    }

    // Identify potential REX.W + LEA/MOV RIP-relative byte patterns:
    // 4x 8D/8B ModRM disp32. This is NOT a disassembler. The resulting
    // candidate references are unverified and may include false positives.
    std::map<std::string, std::size_t> count_by_term;
    for (const Section& sec : sections) {
        if (!sec.executable || sec.file_size < 7) continue;
        const auto* p = file + sec.file_start;
        for (std::uint64_t i = 0; i + 7 <= sec.file_size; ++i) {
            if ((p[i] & 0xf8) != 0x48) continue;
            if (p[i + 1] != 0x8d && p[i + 1] != 0x8b) continue;
            if ((p[i + 2] & 0xc7) != 0x05) continue;
            const auto displacement = static_cast<std::int32_t>(read32(p + i + 3));
            const auto target = static_cast<std::int64_t>(sec.rva) +
                                static_cast<std::int64_t>(i) + 7 + displacement;
            if (target < 0 || target > 0xffffffffll) continue;
            const auto it = targets.find(static_cast<std::uint32_t>(target));
            if (it == targets.end()) continue;
            const auto& name = it->second.label;
            if (count_by_term[name]++ >= max_references_per_term) continue;
            report.references.push_back(ReferenceHit{
                name, it->second.kind, sec.file_start + i,
                static_cast<std::uint32_t>(std::uint64_t(sec.rva) + i),
                static_cast<std::uint32_t>(target)
            });
        }
    }
    return report;
}

std::string format_report(const Report& report) {
    std::ostringstream out;
    out << "NBA 2K26 Portrait Reference Probe - STATIC RESEARCH ONLY\n";
    out << "File bytes: " << report.file_size << "\n";
    out << "No running process accessed; no game file or save modified.\n";
    if (!report.valid) {
        out << "ERROR: " << report.error << "\n";
        return out.str();
    }
    out << "Literal labels found: " << report.strings.size() << "\n";
    for (const auto& s : report.strings) {
        out << "  " << s.label << " [" << s.encoding << "]"
            << " file_offset=" << s.file_offset << " RVA=0x"
            << std::hex << std::uppercase << s.rva << std::dec << "\n";
    }
    out << "Potential code references (HEURISTIC, NOT CONFIRMED): "
        << report.references.size() << "\n";
    for (const auto& x : report.references) {
        out << "  " << x.label << " (" << x.reference_kind << ")"
            << " instruction_file_offset=" << x.instruction_file_offset
            << " instruction_RVA=0x" << std::hex << std::uppercase << x.instruction_rva
            << " target_RVA=0x" << x.referenced_rva << std::dec << "\n";
    }
    out << "\nIMPORTANT: These are tentative static pattern matches, NOT proven cross references.\n";
    out << "The data might belong to in-arena presentation rather than MyNBA cards.\n";
    out << "Do not patch these addresses, inject a DLL, or assume a working hook.\n";
    out << "Zero candidates does NOT rule out the photo-mode code path.\n";
    return out.str();
}
}
