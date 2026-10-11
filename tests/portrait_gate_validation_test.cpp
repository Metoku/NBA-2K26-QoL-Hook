#include "../src/portrait_gate_validation.h"
#include <iostream>

int main() {
    for (const auto& s : portrait_gate::kExpectedBranches) {
        if (!portrait_gate::CheckBranch(s, s.opcode, s.rel8)) {
            std::cerr << "Valid site failed: " << s.label << "\n";
            return 1;
        }
        if (portrait_gate::CheckBranch(s, 0xEBu, s.rel8) ||
            portrait_gate::CheckBranch(s, s.opcode, 0x00u)) {
            std::cerr << "Invalid site passed: " << s.label << "\n";
            return 2;
        }
    }
    std::cout << "Validated four raw control-flow branches (no patch).\n";
    return 0;
}
