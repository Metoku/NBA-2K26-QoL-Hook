// NBA2K26PortraitGateControlFlow.java
// @category NBA2K26 Research
// Read-only inspection of the VERIFIED NBA2K26.exe portrait decision window.
// This script does NOT modify the Ghidra project, game EXE, or player records.
//
// Confirmed from FUN_1425F6930 decompilation:
//   param_2[0x0E]       -> +0x38 candidate request team-id
//   param_2 + 8         -> +0x20 pointer to character/player data
//   *(data + 0xD0/D8)  -> optional team references
//   *(teamRef + 0x1008)-> compared 16-bit identifier
//   mismatch sets a selector used before PORTRAIT_CONTEXT resource creation.
// The meaning of the identifiers/selector is NOT yet validated in-game.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class NBA2K26PortraitGateControlFlow extends GhidraScript {
    private static final String SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long FN = 0x1425F6930L;
    private static final long FROM = 0x1425F6950L;
    private static final long TO = 0x1425F6A40L;
    private static final long CONTEXT_STRING = 0x145406FC0L;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null || currentProgram.getDefaultPointerSize() != 8 ||
            !currentProgram.getName().equalsIgnoreCase("NBA2K26.exe") ||
            !SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("STOP: open the previously verified NBA2K26.exe 64-bit build.");
            return;
        }
        Address fn = toAddr(FN);
        Function f = currentProgram.getFunctionManager().getFunctionAt(fn);
        println("=== NBA2K26 PORTRAIT GATE CONTROL-FLOW REPORT ===");
        println("Function: " + fn + (f == null ? " (not defined)" : " " + f.getName()));
        println("Portrait context UTF-16 string: " + toAddr(CONTEXT_STRING));
        println("Known field layout from decompilation (byte offsets):");
        println(" request kind +0x00; subtype +0x04; character pointer +0x20;");
        println(" request team ID +0x38; flag +0x30; bypass flag +0x34;");
        println(" character-team refs at +0xD0/+0xD8; IDs at teamRef +0x1008.");
        println("WARNING: these field names are hypotheses, not verified runtime types.");
        println("=== ALREADY DISASSEMBLED INSTRUCTIONS " + toAddr(FROM) + " .. " + toAddr(TO) + " ===");

        InstructionIterator it = currentProgram.getListing().getInstructions(toAddr(FROM), true);
        int count = 0;
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction ins = it.next();
            if (ins.getAddress().getOffset() > TO) break;
            StringBuilder b = new StringBuilder();
            b.append(ins.getAddress()).append("  ").append(ins.toString());
            if (ins.getFlowType().isConditional()) {
                Address[] targets = ins.getFlows();
                b.append("  ; BRANCH");
                for (Address target : targets) b.append(" -> ").append(target);
            }
            println(b.toString());
            count++;
        }
        if (count == 0)
            println("No defined instructions in this interval. In Ghidra, disassemble the actual function entry 1425F6930 (D) then rerun.");
        println("=== SUMMARY ===");
        println("Instructions printed: " + count);
        println("Do not patch a conditional jump solely on this report.");
        println("A safe hook still requires confirming image availability, request types and fallback behavior.");
        println("Read-only. Finished.");
    }
}
