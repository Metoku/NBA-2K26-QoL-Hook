#include "PortraitPolicy.h"

namespace nba2k26qol {

PortraitDecision ChooseActionPortrait(ActionPortraitState state) noexcept {
    if (state.hasAssignedActionPhoto &&
        state.assetAvailability == PhotoAssetAvailability::Available) {
        return PortraitDecision::PreferAssignedRealActionPhoto;
    }
    return PortraitDecision::KeepGameDefault;
}

} // namespace nba2k26qol
