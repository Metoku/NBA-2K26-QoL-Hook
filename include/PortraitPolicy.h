#pragma once

namespace nba2k26qol {

// This is an abstract policy interface. Its inputs must come from a
// *verified* NBA 2K26 image-selection function before it can be used.
enum class PhotoAssetAvailability {
    Unknown,
    Available,
    Missing
};

enum class PortraitDecision {
    // Let NBA 2K26 keep its normal action portrait/cyberface fallback.
    KeepGameDefault,
    // Prefer the game's already-assigned original real action photograph.
    PreferAssignedRealActionPhoto
};

struct ActionPortraitState {
    bool hasAssignedActionPhoto;
    PhotoAssetAvailability assetAvailability;
};

// Does not check or modify team, headshot ID, roster, memory, or assets.
// Fail closed: unknown asset availability never triggers an override.
PortraitDecision ChooseActionPortrait(ActionPortraitState state) noexcept;

} // namespace nba2k26qol
