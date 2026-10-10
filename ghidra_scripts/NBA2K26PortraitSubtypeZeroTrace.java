// NBA2K26PortraitSubtypeZeroTrace.java
// @category NBA2K26 Research
// Read-only listing dump for one VERIFIED NBA 2K26 portrait gate block.
// Does NOT execute the game, change bytes, create references, or patch anything.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class NBA2K26PortraitSubtypeZeroTrace extends GhidraScript {
    private static final String VERIFIED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long START = 0x1425F6D81L;
    private static final long END = 0x1425F6F3EL;
    private static final int MAX_INSTRUCTIONS = 240;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            currentProgram.getDefaultPointerSize() != 8 ||
            !currentProgram.getName().equalsIgnoreCase("NBA2K26.exe") ||
            !VERIFIED_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("Stop: expected the previously verified 64-bit NBA2K26.exe build.");
            return;
        }

        println("=== NBA2K26 SUBTYPE-ZERO PORTRAIT BRANCH TRACE ===");
        println("Function entry: 0x1425F6930");
        println("Observed upstream branch: 0x1425F6986 -> 0x1425F6D81");
        println("Observed selector test: 0x1425F69E1 TEST EBX,EBX; 0x1425F69E3 JNZ 0x1425F6F46");
        println("Goal: identify EXACT instructions that compare request +0x38 to referenced team IDs.");
        println("Field meanings not yet validated in game: do not patch from this report.");
        println("=== ALREADY-DISASSEMBLED INSTRUCTIONS (NO AUTOMATIC DISASSEMBLY) ===");

        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(toAddr(START), true);
        int number = 0, branches = 0, potentialFields = 0;
        while (instructions.hasNext() && number < MAX_INSTRUCTIONS) {
            monitor.checkCancelled();
            Instruction ins = instructions.next();
            Address at = ins.getAddress();
            if (Long.compareUnsigned(at.getOffset(), END) > 0) break;
            if (Long.compareUnsigned(at.getOffset(), START) < 0) continue;
            String asm = ins.toString();
            String lower = asm.toLowerCase();
            boolean field =
                lower.contains("0x38]") || lower.contains("0x30]") ||
                lower.contains("0x34]") || lower.contains("0xd0]") ||
                lower.contains("0xd8]") || lower.contains("0x1008]") ||
                lower.contains("0x28]") || lower.contains("0x164]");

            StringBuilder line = new StringBuilder();
            line.append(field ? "* " : "  ").append(at).append("  ").append(asm);
            if (ins.getFlowType().isConditional()) {
                branches++;
                line.append("  ; conditional ->");
                for (Address target: ins.getFlows()) line.append(" ").append(target);
            }
            if (field) potentialFields++;
            println(line.toString());
            number++;
        }
        if (number == 0)
            println("No disassembly indexed in this block. Avoid arbitrary disassembly; inspect the known function instead.");
        println("=== SUMMARY ===");
        println("Instructions shown: " + number);
        println("Conditional branches: " + branches);
        println("Potential field/flag references (*): " + potentialFields);
        println("Use raw assembly to correlate with the decompiled team-reference conditions.");
        println("No executable, save, running process, or Ghidra project modifications.");
    }
}
