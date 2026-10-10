// NBA2K26PortraitProbe.asi
// No-op loading smoke test ONLY for NBA 2K26's built-in offline launch.
// Makes no changes to the game, its resources, EAC, memory or saves.
// The official Ultimate ASI Loader calls InitializeASI after LoadLibrary,
// outside the Windows DLL loader lock.

#include <windows.h>
#include <cwchar>
#include <cstdio>

namespace {
void ReportLoaded() {
    wchar_t exePath[32768] = {};
    const DWORD length = GetModuleFileNameW(nullptr, exePath, 32768);
    if (length == 0 || length >= 32768) return;

    const wchar_t* leaf = wcsrchr(exePath, L'\\');
    leaf = leaf ? leaf + 1 : exePath;
    if (_wcsicmp(leaf, L"NBA2K26.exe") != 0) return;

    wchar_t temp[MAX_PATH] = {};
    const DWORD n = GetTempPathW(MAX_PATH, temp);
    if (n == 0 || n >= MAX_PATH) return;

    wchar_t output[MAX_PATH + 80] = {};
    if (swprintf_s(output, sizeof(output) / sizeof(output[0]),
                   L"%lsNBA2K26PortraitProbe_%lu.txt", temp,
                   GetCurrentProcessId()) < 0)
        return;

    HANDLE file = CreateFileW(output, GENERIC_WRITE, FILE_SHARE_READ,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    static constexpr char message[] =
        "NBA2K26PortraitProbe.asi loaded inside NBA2K26.exe.\r\n"
        "PASS: the plugin initializer ran in this offline session.\r\n"
        "No portrait patches, hooks, game writes, EAC interaction or save edits.\r\n";
    DWORD written = 0;
    WriteFile(file, message, static_cast<DWORD>(sizeof(message) - 1),
              &written, nullptr);
    CloseHandle(file);
}
}

extern "C" __declspec(dllexport) const char* PortraitProbeVersion() {
    return "0.1.1-initializeasi-noop";
}

// Called by Ultimate ASI Loader outside the Windows loader lock.
// Never perform work from DLL_PROCESS_ATTACH.
extern "C" __declspec(dllexport) void InitializeASI() {
    ReportLoaded();
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(module);
    return TRUE;
}
