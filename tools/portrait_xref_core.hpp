#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace portrait_probe {
struct StringHit {
    std::string label;
    std::string encoding;
    std::uint64_t file_offset{};
    std::uint32_t rva{};
};
struct ReferenceHit {
    std::string label;
    std::string reference_kind;
    std::uint64_t instruction_file_offset{};
    std::uint32_t instruction_rva{};
    std::uint32_t referenced_rva{};
};
struct Report {
    bool valid = false;
    std::string error;
    std::uint64_t file_size{};
    std::vector<StringHit> strings;
    std::vector<ReferenceHit> references;
};

// Static heuristic analysis only; returned references are NOT decoded instructions
// or verified hook addresses. Call with bytes from a mapped, read-only PE file.
Report analyze(const std::uint8_t* file, std::size_t size);
std::string format_report(const Report& report);
}
