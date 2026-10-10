#include <windows.h>
#include <cstring>
#include <iostream>
using VersionFunction = const char* (*)();

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    HMODULE mod = LoadLibraryA(argv[1]);
    if (!mod) {
        std::cerr << "Cannot load ASI probe: " << GetLastError() << "\\n";
        return 2;
    }
    auto version = reinterpret_cast<VersionFunction>(
        GetProcAddress(mod, "PortraitProbeVersion"));
    int result = (!version ||
                  std::strcmp(version(), "0.1.0-noop-loader-test") != 0) ? 3 : 0;
    FreeLibrary(mod);
    if (result == 0) std::cout << "Read-only ASI probe loads in test host.\\n";
    return result;
}
