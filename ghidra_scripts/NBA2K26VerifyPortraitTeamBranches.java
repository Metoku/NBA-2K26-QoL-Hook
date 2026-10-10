// NBA2K26VerifyPortraitTeamBranches.java
// @category NBA2K26 Research
// Read-only verification of candidate 2-byte short conditional branches.
// No patching, disassembly, project writes, process attachment, or injection.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class NBA2K26VerifyPortraitTeamBranches extends GhidraScript {
    private static final String SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long[] MATCH_BRANCHES = { 0x1425F6DBDL, 0x1425F6DEDL };
    private static final long[] MATCH_TARGETS = { 0x1425F6DC2L, 0x1425F6DF2L };
    private static final long[] SENTINEL_BRANCHES = { 0x1425F6DB8L, 0x1425F6DE9L };
    private static final long[] SENTINEL_TARGETS = { 0x1425F6DBFL, 0x1425F6DEFL };

    private void reportBranch(Memory mem, long va, long expectedTarget, String label) throws Exception {
        Address at = toAddr(va);
        byte[] opcodes = new byte[2];
        int count = mem.getBytes(at, opcodes);
        if (count != 2) {
            println("ERROR " + label + ": could not read 2 bytes at " + at);
            return;
        }
        int opcode = opcodes[0] & 0xff;
        int rel8 = opcodes[1];
        long rawTarget = va + 2 + rel8;
        Instruction ins = currentProgram.getListing().getInstructionAt(at);
        boolean shortJz = opcode == 0x74;
        boolean targetMatches = rawTarget == expectedTarget;
        boolean indexedMatches = ins != null && "JZ".equals(ins.getMnemonicString()) &&
                                 ins.getLength() == 2;
        println(label + " @ " + at + ":");
        println(String.format("   Raw bytes: %02X %02X", opcode, opcodes[1] & 0xff));
        println("   Already disassembled: " + (ins == null ? "(none)" : ins.toString()));
        println("   Relative branch destination: " + toAddr(rawTarget));
        println("   Expected destination:        " + toAddr(expectedTarget));
        println("   Verified short JZ, target, and listing: " +
                (shortJz && targetMatches && indexedMatches ? "YES" : "NO"));
        if (shortJz && targetMatches && indexedMatches && label.startsWith("TEAM")) {
            println("   HYPOTHETICAL one-byte JZ->JMP edit (NOT APPLIED): 74 -> EB");
            println("   Original missing/invalid team sentinel branches MUST remain unchanged.");
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null || currentProgram.getDefaultPointerSize() != 8 ||
            !currentProgram.getName().equalsIgnoreCase("NBA2K26.exe") ||
            !SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("STOP: expected the previously verified 64-bit NBA2K26.exe build.");
            return;
        }
        println("=== PORTRAIT TEAM MATCH BRANCH BYTE VERIFICATION ===");
        Memory mem = currentProgram.getMemory();
        for (int i = 0; i < MATCH_BRANCHES.length; i++) {
            monitor.checkCancelled();
            reportBranch(mem, MATCH_BRANCHES[i], MATCH_TARGETS[i], "TEAM MATCH " + (i+1));
            reportBranch(mem, SENTINEL_BRANCHES[i], SENTINEL_TARGETS[i], "INVALID-ID SENTINEL " + (i+1));
        }
        println("=== DONE: READ ONLY ===");
        println("No game, process, save, Ghidra project or executable bytes were changed.");
        println("These two edits are CANDIDATE controls, not an in-game verified fix.");
        println("Do not patch if any verification says NO.");
    }
}
