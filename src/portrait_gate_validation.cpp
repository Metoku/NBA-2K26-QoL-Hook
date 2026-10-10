#include "portrait_gate_validation.h"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <cwchar>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

namespace {
constexpr char kSha256[] =
    "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
constexpr std::uint64_t kExpectedFileSize = 1169221400ULL;

bool IsGameProcess() {
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (!length || length >= std::size(path)) return false;
    const wchar_t* leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf+1 : path;
    return _wcsicmp(leaf, L"NBA2K26.exe") == 0;
}

int VerifyFileFingerprint() {
    wchar_t path[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (!length || length >= std::size(path)) return 2;
    HANDLE file = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 2;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(file, &size) ||
        static_cast<std::uint64_t>(size.QuadPart) != kExpectedFileSize) {
        CloseHandle(file);
        return 3;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectBytes = 0, resultBytes = 0;
    std::array<UCHAR,32> digest = {};
    std::vector<UCHAR> hashObject;
    int rc = 2;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes),
            &resultBytes, 0) < 0 || objectBytes == 0)
        goto done;
    hashObject.resize(objectBytes);
    if (BCryptCreateHash(algorithm, &hash, hashObject.data(), objectBytes,
                         nullptr, 0, 0) < 0)
        goto done;
    {
        std::vector<UCHAR> buf(1024*1024);
        for (;;) {
            DWORD n = 0;
            if (!ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr))
                goto done;
            if (n == 0) break;
            if (BCryptHashData(hash, buf.data(), n, 0) < 0) goto done;
        }
    }
    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        goto done;
    {
        static constexpr char hex[] = "0123456789abcdef";
        char computed[65] = {};
        for (std::size_t i=0; i<digest.size(); ++i) {
            computed[i*2] = hex[digest[i] >> 4];
            computed[i*2+1] = hex[digest[i] & 0xf];
        }
        rc = (strcmp(computed, kSha256) == 0) ? 0 : 3;
    }
done:
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    CloseHandle(file);
    return rc;
}

int CheckLoadedBranchBytes() {
    auto* base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleW(nullptr));
    if (!base) return 4;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        dos->e_lfanew > 0x1000) return 4;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 4;
    for (const auto& site : portrait_gate::kExpectedBranches) {
        if (site.rva + 2 > nt->OptionalHeader.SizeOfImage) return 4;
        MEMORY_BASIC_INFORMATION info = {};
        if (!VirtualQuery(base+site.rva, &info, sizeof(info)) ||
            info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD) ||
            (info.Protect & PAGE_NOACCESS)) return 4;
        if (!portrait_gate::CheckBranch(site, base[site.rva], base[site.rva+1]))
            return 5;
    }
    return 0;
}
} // namespace

// Meaning: 0=matching game and four sites verified; 1=not NBA2K26.exe;
// 2=unable to fingerprint game; 3=different build; 4=unexpected PE/mapping;
// 5=in-memory code differs from verified Ghidra bytes.
// This is a diagnostic only: it does not patch the game, or prove the photo fix.
extern "C" __declspec(dllexport) int QoLInspectPortraitBranches() {
    if (!IsGameProcess()) return 1;
    const int fingerprint = VerifyFileFingerprint();
    if (fingerprint) return fingerprint;
    return CheckLoadedBranchBytes();
}
