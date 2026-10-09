#include <windows.h>

// Diagnostic build only: no hooks, game modifications, or injection.
extern "C" __declspec(dllexport) const char* QoLHookVersion() {
    return "0.1.0-skeleton";
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
