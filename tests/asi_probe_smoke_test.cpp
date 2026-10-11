#include <windows.h>
#include <cstring>
#include <iostream>

using VersionFunction = const char* (*)();
using InitializeFunction = void (*)();

int main(int argc, char** argv) {
    if (argc < 2) return 1;

    HMODULE mod = LoadLibraryA(argv[1]);
    if (!mod) {
        std::cerr << "Cannot load ASI probe: " << GetLastError() << "\n";
        return 2;
    }

    auto version = reinterpret_cast<VersionFunction>(
        GetProcAddress(mod, "PortraitProbeVersion"));
    auto initialize = reinterpret_cast<InitializeFunction>(
        GetProcAddress(mod, "InitializeASI"));

    // Test the exported entry point in a non-game process. It must return
    // without creating a game report, loading other DLLs or touching any game.
    int result = (!version || !initialize ||
                  std::strcmp(version(), "0.1.1-initializeasi-noop") != 0) ? 3 : 0;
    if (result == 0) initialize();

    FreeLibrary(mod);
    if (result == 0)
        std::cout << "ASI exports valid; InitializeASI safely ignored non-game host.\n";
    return result;
}
