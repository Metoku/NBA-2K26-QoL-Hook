#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commdlg.h>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include "portrait_xref_core.hpp"

namespace {
class ReadOnlyMap {
public:
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
    ~ReadOnlyMap() {
        if (data) UnmapViewOfFile(data);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
    bool open(const wchar_t* path) {
        file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER length{};
        if (!GetFileSizeEx(file, &length) || length.QuadPart <= 0 ||
            static_cast<std::uint64_t>(length.QuadPart) >
                static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
        mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!mapping) return false;
        data = static_cast<const std::uint8_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        size = static_cast<std::size_t>(length.QuadPart);
        return data != nullptr;
    }
};

void show(const wchar_t* title, const std::wstring& message, UINT type) {
    MessageBoxW(nullptr, message.c_str(), title, type | MB_OK | MB_TOPMOST);
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    // Browse and analyze only: no terminal, Python, Visual Studio, game
    // attachment, DLL injection, or modifications to the game are required.
    wchar_t selected[32768]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFile = selected;
    dialog.nMaxFile = static_cast<DWORD>(sizeof(selected) / sizeof(selected[0]));
    dialog.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
    dialog.lpstrTitle = L"Select NBA2K26.exe for read-only portrait reference analysis";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (!GetOpenFileNameW(&dialog)) return 0; // canceled, no files written
    if (_wcsicmp(std::filesystem::path(selected).filename().c_str(), L"NBA2K26.exe") != 0) {
        if (MessageBoxW(nullptr,
                L"The selected filename is not NBA2K26.exe. Continue with read-only analysis?",
                L"Check selected executable", MB_YESNO | MB_ICONWARNING) != IDYES) return 0;
    }

    ReadOnlyMap mapped;
    if (!mapped.open(selected)) {
        show(L"Cannot read executable", L"Unable to open the chosen executable read-only.", MB_ICONERROR);
        return 1;
    }
    portrait_probe::Report result = portrait_probe::analyze(mapped.data, mapped.size);
    if (!result.valid) {
        show(L"Unsupported file", L"Cannot analyze this executable: invalid or unsupported 64-bit PE layout.", MB_ICONERROR);
        return 2;
    }

    wchar_t modulePath[32768]{};
    const DWORD count = GetModuleFileNameW(nullptr, modulePath,
                                static_cast<DWORD>(sizeof(modulePath) / sizeof(modulePath[0])));
    if (count == 0 || count >= sizeof(modulePath) / sizeof(modulePath[0])) {
        show(L"Cannot find report folder", L"Unable to locate this probe's folder.", MB_ICONERROR);
        return 3;
    }
    // Write the report next to the probe, NEVER in the game directory.
    const auto reportPath = std::filesystem::path(modulePath).parent_path() /
                            L"NBA2K26-portrait-reference-report.txt";
    std::ofstream output(reportPath, std::ios::binary | std::ios::trunc);
    if (!output) {
        show(L"Cannot write report", L"Extract the EXE to a writable folder such as Desktop, then try again.", MB_ICONERROR);
        return 4;
    }
    output << portrait_probe::format_report(result);
    output.close();
    if (!output) {
        show(L"Failed writing report", L"Writing the report failed.", MB_ICONERROR);
        return 5;
    }
    show(L"Read-only analysis complete",
         L"Report saved beside the probe:\n\n" + reportPath.wstring() +
         L"\n\nThis only lists potential references, NOT confirmed working hooks."
         L"\nPlease send the text report for review.", MB_ICONINFORMATION);
    return 0;
}
