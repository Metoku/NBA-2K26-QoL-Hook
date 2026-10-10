#include "PortraitPolicy.h"
#include <iostream>

using namespace nba2k26qol;

static bool Check(const char* label, ActionPortraitState state,
                  PortraitDecision expected) {
    const auto result = ChooseActionPortrait(state);
    if (result != expected) {
        std::cerr << "FAILED: " << label << '\n';
        return false;
    }
    return true;
}

int main() {
    bool ok = true;
    // The caller's current team is intentionally absent from the API:
    // traded players should receive the same preference as original-team players.
    ok &= Check("assigned photo available", {true, PhotoAssetAvailability::Available},
                PortraitDecision::PreferAssignedRealActionPhoto);
    ok &= Check("assigned photo missing", {true, PhotoAssetAvailability::Missing},
                PortraitDecision::KeepGameDefault);
    ok &= Check("assigned photo unknown", {true, PhotoAssetAvailability::Unknown},
                PortraitDecision::KeepGameDefault);
    ok &= Check("no assignment, available asset", {false, PhotoAssetAvailability::Available},
                PortraitDecision::KeepGameDefault);
    ok &= Check("no assignment, missing asset", {false, PhotoAssetAvailability::Missing},
                PortraitDecision::KeepGameDefault);
    ok &= Check("no assignment, unknown asset", {false, PhotoAssetAvailability::Unknown},
                PortraitDecision::KeepGameDefault);
    if (ok) std::cout << "Portrait policy tests passed\n";
    return ok ? 0 : 1;
}
