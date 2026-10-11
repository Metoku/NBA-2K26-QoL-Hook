// Read-only NBA 2K26 portrait gate inspector.
// This is a separate EXE: no DLL/ASI loader, injection, writes or patches.
// Intended ONLY for the Steam built-in "without EAC (offline only)" launch.
// Our Ghidra-verified branch RVAs refer to ONE SHA-256-matched executable.
#include "portrait_gate_validation.h"
#include <windows.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
constexpr wchar_t kExeName[] = L"NBA2K26.exe";
constexpr std::uint64_t kFileSize = 1169221400ULL;
constexpr char kSha256[] =
    "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";

struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE h = nullptr) : value(h) {}
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool valid() const { return value && value != INVALID_HANDLE_VALUE; }
};

struct HashState {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~HashState() {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
};

bool FileMatchesBuild(const std::wstring& path, std::string& detail) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) {
        detail = "Cannot open game executable for read-only fingerprint.";
        return false;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file.value, &size) || size.QuadPart < 0) {
        detail = "Cannot determine game executable size.";
        return false;
    }
    if (static_cast<std::uint64_t>(size.QuadPart) != kFileSize) {
        detail = "Executable size differs from verified build; no memory inspected.";
        return false;
    }

    HashState h;
    if (BCryptOpenAlgorithmProvider(&h.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        detail = "Windows SHA-256 initialization failed.";
        return false;
    }
    DWORD objectSize = 0, bytesReturned = 0;
    if (BCryptGetProperty(h.algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
            &bytesReturned, 0) < 0 || !objectSize) {
        detail = "Cannot obtain SHA-256 hash object size.";
        return false;
    }
    std::vector<UCHAR> hashObject(objectSize);
    if (BCryptCreateHash(h.algorithm, &h.hash, hashObject.data(),
                        objectSize, nullptr, 0, 0) < 0) {
        detail = "Cannot create SHA-256 hash.";
        return false;
    }

    std::vector<UCHAR> buffer(1024 * 1024);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()),
                      &read, nullptr)) {
            detail = "Cannot read game executable during fingerprint.";
            return false;
        }
        if (read == 0) break;
        if (BCryptHashData(h.hash, buffer.data(), read, 0) < 0) {
            detail = "SHA-256 hashing failed.";
            return false;
        }
    }
    std::array<UCHAR, 32> digest{};
    if (BCryptFinishHash(h.hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        detail = "SHA-256 finish failed.";
        return false;
    }
    static constexpr char hex[] = "0123456789abcdef";
    std::string sha;
    sha.reserve(64);
    for (UCHAR b : digest) {
        sha.push_back(hex[b >> 4]);
        sha.push_back(hex[b & 0x0f]);
    }
    if (sha != kSha256) {
        detail = "SHA-256 differs from verified build; no memory inspected.";
        return false;
    }
    detail = "SHA-256 and size match the Ghidra-verified build.";
    return true;
}

bool LocateGame(DWORD& pid) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) return false;
    PROCESSENTRY32W item{};
    item.dwSize = sizeof(item);
    if (!Process32FirstW(snapshot.value, &item)) return false;
    do {
        if (_wcsicmp(item.szExeFile, kExeName) == 0) {
            pid = item.th32ProcessID;
            return true;
        }
    } while (Process32NextW(snapshot.value, &item));
    return false;
}

bool LocateImageBase(DWORD pid, std::uintptr_t& base) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot.valid()) return false;
    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    if (!Module32FirstW(snapshot.value, &module)) return false;
    do {
        if (_wcsicmp(module.szModule, kExeName) == 0) {
            base = reinterpret_cast<std::uintptr_t>(module.modBaseAddr);
            return true;
        }
    } while (Module32NextW(snapshot.value, &module));
    return false;
}

int InspectRunningGame() {
    std::cout << "NBA 2K26 Portrait Tool — read-only diagnostic\n";
    std::cout << "No hooks, injection, DLL proxies, or game-memory writes.\n\n";
    DWORD pid = 0;
    if (!LocateGame(pid)) {
        std::cout << "Game process not found. Start NBA 2K26 using Steam's OFFLINE WITHOUT EAC launch option.\n";
        return 2;
    }
    std::cout << "Found NBA2K26.exe (PID " << pid << ").\n";
    Handle game(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                            FALSE, pid));
    if (!game.valid()) {
        std::cerr << "Cannot open game for read-only inspection (error "
                  << GetLastError() << "). No changes were attempted.\n";
        return 3;
    }
    std::wstring imagePath(32768, L'\0');
    DWORD length = static_cast<DWORD>(imagePath.size());
    if (!QueryFullProcessImageNameW(game.value, 0, imagePath.data(), &length) || !length) {
        std::cerr << "Could not find the executable path. No changes were attempted.\n";
        return 4;
    }
    imagePath.resize(length);
    std::string fingerprint;
    std::cout << "Checking exact game executable fingerprint (1.1 GB; this may take a moment)...\n";
    if (!FileMatchesBuild(imagePath, fingerprint)) {
        std::cout << "STOP: " << fingerprint << "\n";
        return 5;
    }
    std::cout << "PASS: " << fingerprint << "\n";
    std::uintptr_t base = 0;
    if (!LocateImageBase(pid, base)) {
        std::cerr << "Cannot determine loaded NBA2K26.exe base address.\n";
        return 6;
    }
    std::cout << "Base address: 0x" << std::hex << base << std::dec << "\n";
    int verified = 0;
    for (const auto& site : portrait_gate::kExpectedBranches) {
        std::array<std::uint8_t, 2> bytes{};
        SIZE_T transferred = 0;
        const auto address = reinterpret_cast<LPCVOID>(
            base + static_cast<std::uintptr_t>(site.rva));
        if (!ReadProcessMemory(game.value, address, bytes.data(),
                               bytes.size(), &transferred) || transferred != bytes.size()) {
            std::cerr << "STOP: Cannot read site at RVA 0x" << std::hex
                      << site.rva << std::dec << ".\n";
            return 7;
        }
        const bool ok = portrait_gate::CheckBranch(site, bytes[0], bytes[1]);
        std::cout << (ok ? "PASS: " : "STOP: ") << site.label
                  << " at RVA 0x" << std::hex << site.rva
                  << " bytes " << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(bytes[0]) << " "
                  << std::setw(2) << static_cast<unsigned>(bytes[1])
                  << std::dec << std::setfill(' ') << "\n";
        if (!ok) {
            std::cerr << "Loaded memory does not match the verified Ghidra instructions.\n";
            return 8;
        }
        ++verified;
    }
    std::cout << "\nPASS: " << verified << "/4 branch sites match the expected build.\n";
    std::cout << "Diagnostic complete. NO portrait behavior has been changed.\n";
    return 0;
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 2 && wcscmp(argv[1], L"--help") == 0) {
        std::cout << "Usage: NBA2K26PortraitTool.exe [--help|--self-test]\n";
        std::cout << "Run with no options after launching NBA 2K26 offline WITHOUT EAC.\n";
        std::cout << "Read-only process inspection. Never run with the protected online launch.\n";
        return 0;
    }
    if (argc == 2 && wcscmp(argv[1], L"--self-test") == 0) {
        for (const auto& s : portrait_gate::kExpectedBranches) {
            if (!portrait_gate::CheckBranch(s, s.opcode, s.rel8) ||
                portrait_gate::CheckBranch(s, 0xEB, s.rel8))
                return 1;
        }
        std::cout << "PASS: static portrait branch model (no game required).\n";
        return 0;
    }
    if (argc != 1) {
        std::cerr << "Unsupported argument. Use --help.\n";
        return 1;
    }
    return InspectRunningGame();
}
