// NBA2K26PortraitProbe.asi
// Minimal plugin-loading smoke test for the game's BUILT-IN offline-only launch.
// NO hooks, executable patches, player edits, anti-cheat operations, or network calls.
// Creates %TEMP%\\NBA2K26PortraitProbe_<PID>.txt only when actually loaded by NBA2K26.exe.
#include <windows.h>
#include <cwchar>
#include <cstdio>

namespace {
DWORD WINAPI ReportLoaded(LPVOID) {
    wchar_t exePath[32768] = {};
    DWORD length = GetModuleFileNameW(nullptr, exePath, 32768);
    if (length == 0 || length >= 32768) return 1;

    const wchar_t* leaf = wcsrchr(exePath, L'\\');
    leaf = leaf ? leaf + 1 : exePath;
    if (_wcsicmp(leaf, L"NBA2K26.exe") != 0) return 2;

    wchar_t temp[MAX_PATH] = {};
    DWORD size = GetTempPathW(MAX_PATH, temp);
    if (size == 0 || size >= MAX_PATH) return 3;

    wchar_t output[MAX_PATH + 80] = {};
    if (swprintf_s(output, sizeof(output)/sizeof(output[0]),
        L"%lsNBA2K26PortraitProbe_%lu.txt", temp, GetCurrentProcessId()) < 0)
        return 4;

    HANDLE file = CreateFileW(output, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 5;

    static constexpr char message[] =
        "NBA2K26PortraitProbe.asi loaded inside NBA2K26.exe.\\r\\n"
        "PASS: native plugin loader worked for this session.\\r\\n"
        "No portrait patch, render hook, memory writes, EAC interaction or save edits.\\r\\n"
        "Use only the game's built-in offline-without-EAC Steam launch option.\\r\\n";
    DWORD written = 0;
    WriteFile(file, message, static_cast<DWORD>(sizeof(message) - 1), &written, nullptr);
    CloseHandle(file);
    return 0;
}
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        // Never wait for a thread while holding the loader lock.
        HANDLE thread = CreateThread(nullptr, 0, ReportLoaded, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
    }
    return TRUE;
}
