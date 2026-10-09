#include <windows.h>
#include <cstring>
#include <iostream>

using VersionFunction = const char* (*)();

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Expected DLL path argument.\n";
        return 1;
    }

    HMODULE dll = LoadLibraryA(argv[1]);
    if (!dll) {
        std::cerr << "Unable to load DLL: " << GetLastError() << "\n";
        return 2;
    }

    auto version = reinterpret_cast<VersionFunction>(
        GetProcAddress(dll, "QoLHookVersion"));
    if (!version || std::strcmp(version(), "0.1.0-skeleton") != 0) {
        std::cerr << "Version export missing or unexpected.\n";
        FreeLibrary(dll);
        return 3;
    }

    std::cout << "DLL smoke test passed: " << version() << "\n";
    FreeLibrary(dll);
    return 0;
}
