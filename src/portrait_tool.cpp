// Offline, file-only NBA 2K26 portrait gate inspector.
// It NEVER opens or enumerates game processes, reads process memory,
// attaches a debugger, or modifies the game executable.
// Run while NBA 2K26 is CLOSED and provide the original EXE's path.
#include "portrait_gate_validation.h"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
constexpr std::uint64_t kExpectedSize = 1169221400ULL;
constexpr char kExpectedSha[] =
    "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";

struct ScopedFile {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit ScopedFile(HANDLE h) : value(h) {}
    ~ScopedFile() {
        if (value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
    ScopedFile(const ScopedFile&) = delete;
    ScopedFile& operator=(const ScopedFile&) = delete;
    bool valid() const { return value != INVALID_HANDLE_VALUE; }
};

struct ScopedHash {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~ScopedHash() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
};

bool ReadAt(HANDLE file, std::uint64_t offset, void* output, DWORD count) {
    LARGE_INTEGER at = {};
    at.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, at, nullptr, FILE_BEGIN)) return false;
    DWORD read = 0;
    return ReadFile(file, output, count, &read, nullptr) && read == count;
}

bool CheckFingerprint(HANDLE file, std::uint64_t fileSize, std::string& reason) {
    if (fileSize != kExpectedSize) {
        reason = "File size differs from our verified NBA 2K26 build.";
        return false;
    }
    ScopedHash h;
    DWORD objectSize = 0, returned = 0;
    if (BCryptOpenAlgorithmProvider(&h.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(h.algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
            &returned, 0) < 0 || objectSize == 0) {
        reason = "Windows SHA-256 initialization failed.";
        return false;
    }
    std::vector<UCHAR> hashObject(objectSize);
    if (BCryptCreateHash(h.algorithm, &h.hash, hashObject.data(), objectSize,
                         nullptr, 0, 0) < 0) {
        reason = "Windows SHA-256 hash initialization failed.";
        return false;
    }
    LARGE_INTEGER zero = {};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
        reason = "Cannot seek to start of executable.";
        return false;
    }
    std::vector<UCHAR> chunk(1024 * 1024);
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file, chunk.data(), static_cast<DWORD>(chunk.size()), &count, nullptr)) {
            reason = "Executable read failed while hashing.";
            return false;
        }
        if (count == 0) break;
        if (BCryptHashData(h.hash, chunk.data(), count, 0) < 0) {
            reason = "SHA-256 hashing failed.";
            return false;
        }
    }
    std::array<UCHAR, 32> digest = {};
    if (BCryptFinishHash(h.hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        reason = "SHA-256 finalization failed.";
        return false;
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string actual;
    actual.reserve(64);
    for (const auto byte : digest) {
        actual += hex[byte >> 4];
        actual += hex[byte & 15];
    }
    if (actual != kExpectedSha) {
        reason = "SHA-256 differs from our verified NBA 2K26 build.";
        return false;
    }
    reason = "SHA-256 and size match the verified build.";
    return true;
}

bool RvaToFileOffset(
    std::uint32_t rva, std::uint32_t sizeOfHeaders,
    const std::vector<IMAGE_SECTION_HEADER>& sections,
    std::uint64_t fileSize, std::uint64_t& fileOffset)
{
    // Map PE virtual addresses back to bytes in a closed, on-disk EXE.
    // Use SizeOfRawData, not VirtualSize: uninitialized virtual bytes
    // have no file representation.
    for (const auto& section : sections) {
        if (rva < section.VirtualAddress) continue;
        const std::uint64_t delta =
            static_cast<std::uint64_t>(rva) - section.VirtualAddress;
        if (delta + 2 > section.SizeOfRawData) continue;
        const std::uint64_t offset =
            static_cast<std::uint64_t>(section.PointerToRawData) + delta;
        if (offset + 2 > fileSize) return false;
        fileOffset = offset;
        return true;
    }
    if (static_cast<std::uint64_t>(rva) + 2 <= sizeOfHeaders &&
        static_cast<std::uint64_t>(rva) + 2 <= fileSize) {
        fileOffset = rva;
        return true;
    }
    return false;
}

bool LoadSections(HANDLE file, std::uint64_t fileSize,
                  std::uint32_t& sizeOfHeaders,
                  std::vector<IMAGE_SECTION_HEADER>& sections)
{
    IMAGE_DOS_HEADER dos = {};
    if (!ReadAt(file, 0, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
        dos.e_lfanew > 1024 * 1024) return false;

    const std::uint64_t nt = static_cast<std::uint32_t>(dos.e_lfanew);
    DWORD signature = 0;
    IMAGE_FILE_HEADER coff = {};
    if (!ReadAt(file, nt, &signature, sizeof(signature)) ||
        signature != IMAGE_NT_SIGNATURE ||
        !ReadAt(file, nt + 4, &coff, sizeof(coff)) ||
        coff.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        coff.NumberOfSections == 0 || coff.NumberOfSections > 96 ||
        coff.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return false;

    IMAGE_OPTIONAL_HEADER64 optional = {};
    const std::uint64_t opt = nt + 4 + sizeof(coff);
    if (!ReadAt(file, opt, &optional, sizeof(optional)) ||
        optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    sizeOfHeaders = optional.SizeOfHeaders;

    const std::uint64_t sectionStart = opt + coff.SizeOfOptionalHeader;
    if (sectionStart + static_cast<std::uint64_t>(coff.NumberOfSections) *
                           sizeof(IMAGE_SECTION_HEADER) > fileSize) return false;
    sections.resize(coff.NumberOfSections);
    for (std::size_t i = 0; i < sections.size(); ++i) {
        if (!ReadAt(file, sectionStart + i * sizeof(IMAGE_SECTION_HEADER),
                    &sections[i], sizeof(IMAGE_SECTION_HEADER))) return false;
    }
    return true;
}

int SelfTest() {
    for (const auto& site : portrait_gate::kExpectedBranches) {
        if (!portrait_gate::CheckBranch(site, site.opcode, site.rel8) ||
             portrait_gate::CheckBranch(site, 0xEB, site.rel8)) {
            std::cerr << "FAIL: branch model for " << site.label << ".\n";
            return 1;
        }
    }
    IMAGE_SECTION_HEADER fixture = {};
    fixture.VirtualAddress = 0x1000;
    fixture.PointerToRawData = 0x400;
    fixture.SizeOfRawData = 0x1000;
    const std::vector<IMAGE_SECTION_HEADER> sections = {fixture};
    std::uint64_t offset = 0;
    if (!RvaToFileOffset(0x1100, 0x400, sections, 0x2000, offset) ||
        offset != 0x500 ||
        RvaToFileOffset(0x2000, 0x400, sections, 0x2000, offset)) {
        std::cerr << "FAIL: PE RVA-to-file offset model.\n";
        return 1;
    }
    std::cout << "PASS: branch signatures and PE address mapping (no game opened).\n";
    return 0;
}

int InspectFile(const wchar_t* path) {
    std::wcout << L"NBA 2K26 Portrait Tool — FILE-ONLY diagnostic\n";
    std::wcout << L"Read-only disk inspection. No process inspection or interaction.\n\n";
    ScopedFile file(CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) {
        std::cerr << "STOP: Cannot open specified executable file.\n";
        return 2;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0) {
        std::cerr << "STOP: Cannot determine executable size.\n";
        return 3;
    }
    std::cout << "Computing SHA-256 from the original EXE on disk (~1.1 GB)...\n";
    std::string why;
    if (!CheckFingerprint(file.value, static_cast<std::uint64_t>(size.QuadPart), why)) {
        std::cout << "STOP: " << why << "\n";
        return 4;
    }
    std::cout << "PASS: " << why << "\n";
    std::uint32_t headers = 0;
    std::vector<IMAGE_SECTION_HEADER> sections;
    if (!LoadSections(file.value, static_cast<std::uint64_t>(size.QuadPart),
                      headers, sections)) {
        std::cerr << "STOP: Cannot parse verified EXE PE headers.\n";
        return 5;
    }

    int verified = 0;
    for (const auto& branch : portrait_gate::kExpectedBranches) {
        std::uint64_t offset = 0;
        if (!RvaToFileOffset(branch.rva, headers, sections,
                             static_cast<std::uint64_t>(size.QuadPart), offset)) {
            std::cerr << "STOP: Cannot map portrait branch RVA to original EXE file.\n";
            return 6;
        }
        std::array<std::uint8_t, 2> bytes = {};
        if (!ReadAt(file.value, offset, bytes.data(), static_cast<DWORD>(bytes.size()))) {
            std::cerr << "STOP: Cannot read portrait branch from original EXE.\n";
            return 7;
        }
        const bool good = portrait_gate::CheckBranch(branch, bytes[0], bytes[1]);
        std::cout << (good ? "PASS: " : "STOP: ") << branch.label
                  << " (RVA 0x" << std::hex << branch.rva
                  << ", file offset 0x" << offset << ", bytes "
                  << std::setw(2) << std::setfill('0') << unsigned(bytes[0])
                  << " " << std::setw(2) << unsigned(bytes[1])
                  << std::dec << std::setfill(' ') << ")\n";
        if (!good) return 8;
        ++verified;
    }
    std::cout << "\nPASS: " << verified << "/4 known branch sites match.\n";
    std::cout << "File-only inspection finished. The game was NEVER accessed.\n";
    std::cout << "This is NOT an action portrait fix.\n";
    return 0;
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 2 && wcscmp(argv[1], L"--self-test") == 0) return SelfTest();
    if (argc == 2 && wcscmp(argv[1], L"--help") == 0) {
        std::cout << "Usage: NBA2K26PortraitTool.exe \"C:\\path\\to\\NBA2K26.exe\"\n";
        std::cout << "Close NBA 2K26 before running. Alternatively drag the EXE "
                     "onto this tool.\n";
        std::cout << "No OpenProcess, ReadProcessMemory, memory writes, "
                     "injection or DLL loading.\n";
        return 0;
    }
    if (argc == 2) return InspectFile(argv[1]);
    std::cout << "NBA2K26PortraitTool.exe requires the path to NBA2K26.exe.\n";
    std::cout << "Close the game and drag its EXE file onto this tool "
                 "or use --help.\n";
    return 1;
}
