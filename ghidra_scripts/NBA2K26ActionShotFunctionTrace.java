// NBA2K26ActionShotFunctionTrace.java
// @category NBA2K26 Research
// Action-shot-only investigation using Windows x64 .pdata function boundaries.
// Makes limited Ghidra PROGRAM ANALYSIS edits (disassembly/functions only).
// Does NOT modify game files, running game memory, or MyNBA save data.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NBA2K26ActionShotFunctionTrace extends GhidraScript {

    private static final String EXPECTED_HASH =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";

    private static final long[] TARGET_RVAS = {
        0x80869BL,   // ActionShotId: likely player-data field handling
        0x8085CCL,   // PhotoId: CONTROL only; did both occur in same function?
        0x1F0147AL,  // GetActionShotId() diagnostic near validation/assertion
        0xC704C5CL   // SetActionShotId diagnostic region in farther code
    };
    private static final String[] TARGET_NAMES = {
        "ActionShotId field processing (primary)",
        "PhotoId control reference (not a headshot investigation)",
        "ActionShotId getter diagnostic",
        "ActionShotId setter diagnostic"
    };

    private static final long MAX_PDATA_BYTES = 96L * 1024 * 1024;
    private static final long MAX_FUNCTION_LENGTH = 16000L;
    private static final int MAX_DECOMPILES = 3;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 45;
    private static final int MAX_DECOMPILED_TEXT = 24000;

    private static class Region {
        long begin;
        long end;
        long unwind;
        boolean known;
        Region(long begin, long end, long unwind) {
            this.begin = begin;
            this.end = end;
            this.unwind = unwind;
            this.known = true;
        }
    }

    private Address base;
    private Memory mem;
    private PrintWriter out;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            currentProgram.getDefaultPointerSize() != 8) {
            printerr("Open the 64-bit NBA2K26.exe in CodeBrowser first.");
            return;
        }
        String hash = currentProgram.getExecutableSHA256();
        if (hash != null && !hash.isEmpty() &&
            !EXPECTED_HASH.equalsIgnoreCase(hash)) {
            printerr("Imported executable SHA-256 does not match the known NBA 2K26 build.");
            printerr("Imported: " + hash + "; expected: " + EXPECTED_HASH);
            return;
        }

        base = currentProgram.getImageBase();
        mem = currentProgram.getMemory();
        File destination = askFile("Save action-shot function trace", "Save");
        try (PrintWriter writer = new PrintWriter(
             new OutputStreamWriter(new FileOutputStream(destination),
                                    StandardCharsets.UTF_8))) {
            out = writer;
            line("NBA 2K26 - Action-Shot Function Boundary Trace");
            line("SCOPE: ActionShotId function ownership (NOT headshots or roster edits)");
            line("Executable SHA-256 metadata: " +
                 (hash == null ? "(unavailable)" : hash));
            line("Expected SHA-256: " + EXPECTED_HASH);
            line("Image base: " + hx(base));
            line("This script may CREATE DISASSEMBLY/FUNCTIONS inside your GHIDRA PROJECT.");
            line("It DOES NOT change NBA2K26.exe, patch bytes, or access any game process.");
            line("Does not run full automatic analysis.");
            line("");

            Region[] regions = findUnwindRegions();
            if (regions == null) {
                line("No usable .pdata table found. Existing indexed Ghidra functions");
                line("will still be inspected if they already contain targets.");
                regions = new Region[TARGET_RVAS.length];
            }
            line("");
            line("=== ACTION-SHOT CODE LOCATIONS ===");
            for (int i = 0; i < TARGET_RVAS.length; i++) {
                monitor.checkCancelled();
                Address addr = base.add(TARGET_RVAS[i]);
                line(TARGET_NAMES[i] + ": " + hx(addr) +
                     " (RVA " + rva(TARGET_RVAS[i]) + ")");
                if (regions[i] != null && regions[i].known) {
                    Region region = regions[i];
                    line("  PE unwind fragment: [" + hx(base.add(region.begin)) +
                         ", " + hx(base.add(region.end)) + ") length " +
                         (region.end - region.begin) + " bytes");
                    line("  Unwind metadata RVA: " + rva(region.unwind));
                    line("  NOTE: an unwind fragment is not necessarily the entire logical C++ function.");
                } else {
                    line("  No matching PE unwind fragment; do not assume an entry point.");
                }
                Function indexed = currentProgram.getFunctionManager()
                                            .getFunctionContaining(addr);
                line("  Existing Ghidra function: " +
                     (indexed == null ? "(none)" :
                      indexed.getName() + " @ " + hx(indexed.getEntryPoint())));
            }

            if (regions[0] != null && regions[1] != null &&
                regions[0].known && regions[1].known) {
                boolean same = regions[0].begin == regions[1].begin &&
                               regions[0].end == regions[1].end;
                line("");
                line("ActionShotId and PhotoId lie within the same PE unwind fragment: " + same);
                if (same) {
                    line("This suggests a shared player-data processing routine.");
                    line("It does NOT establish portrait image selection.");
                }
            }

            line("");
            line("=== FOCUSED FUNCTION DECOMPILATIONS ===");
            line("Only validated unwind-fragment entries, max 3 unique and <= 16 KiB each.");
            line("Ghidra may create local analysis functions to enable decompilation.");
            line("These are NOT safe hook points.");

            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    line("Ghidra decompiler cannot open this program.");
                } else {
                    Map<Long,Boolean> processed = new LinkedHashMap<Long,Boolean>();
                    int attempted = 0;
                    int[] priority = { 0, 2, 3, 1 };
                    for (int k : priority) {
                        monitor.checkCancelled();
                        if (attempted >= MAX_DECOMPILES) break;
                        Region region = regions[k];
                        if (region == null || !region.known) continue;
                        if (processed.containsKey(region.begin)) continue;
                        processed.put(region.begin, Boolean.TRUE);
                        if (region.end - region.begin > MAX_FUNCTION_LENGTH ||
                            region.end - region.begin < 5) {
                            line("Skipping oversized/invalid fragment at RVA " +
                                 rva(region.begin) + ", length " +
                                 (region.end - region.begin));
                            continue;
                        }
                        Address entry = base.add(region.begin);
                        if (!executable(entry)) {
                            line("Skipping region without executable start: " + hx(entry));
                            continue;
                        }
                        Function fn = currentProgram.getFunctionManager()
                                           .getFunctionContaining(base.add(TARGET_RVAS[k]));
                        if (fn == null) {
                            try {
                                // A targeted analysis operation, confined to Ghidra's
                                // local project. No EXE bytes are written to disk.
                                disassemble(entry);
                                fn = createFunction(entry, null);
                                if (fn == null) {
                                    fn = currentProgram.getFunctionManager()
                                                   .getFunctionAt(entry);
                                }
                            } catch (Exception e) {
                                line("Cannot create local analysis function at " +
                                     hx(entry) + ": " + e.getMessage());
                            }
                        }

                        if (fn == null) {
                            line("No Ghidra function found for " + hx(entry) +
                                 "; review unwind start manually.");
                            continue;
                        }
                        if (!fn.getBody().contains(base.add(TARGET_RVAS[k]))) {
                            line("WARNING: created function body does not cover target " +
                                 TARGET_NAMES[k] + "; do not draw conclusions.");
                            continue;
                        }
                        attempted++;
                        line("");
                        line("SOURCE: " + TARGET_NAMES[k]);
                        line("Function: " + fn.getName() +
                             " entry " + hx(fn.getEntryPoint()));
                        line("Decompiling for at most " + DECOMPILE_TIMEOUT_SECONDS + " seconds...");
                        DecompileResults result = decompiler.decompileFunction(
                            fn, DECOMPILE_TIMEOUT_SECONDS, monitor);
                        if (!result.decompileCompleted()) {
                            line("Incomplete: " + result.getErrorMessage());
                            continue;
                        }
                        DecompiledFunction decompiled = result.getDecompiledFunction();
                        if (decompiled == null || decompiled.getC() == null) {
                            line("Decompiler returned no C text.");
                            continue;
                        }
                        String code = decompiled.getC();
                        line("Decompiler C length: " + code.length() + " chars");
                        if (code.length() > MAX_DECOMPILED_TEXT) {
                            line("NOTE: output truncated at " + MAX_DECOMPILED_TEXT +
                                 " chars. Do not infer omitted behavior.");
                            code = code.substring(0, MAX_DECOMPILED_TEXT);
                        }
                        line("----- BEGIN GHIDRA PSEUDOCODE -----");
                        line(code);
                        line("----- END GHIDRA PSEUDOCODE -----");
                    }
                    if (attempted == 0) {
                        line("No function could be decompiled automatically.");
                        line("Report the .pdata-derived addresses rather than guessing an entry.");
                    }
                }
            } finally {
                decompiler.dispose();
            }

            line("");
            line("=== INTERPRETATION ===");
            line("Found function boundaries and output are for field processing ONLY.");
            line("Photo/action-portrait asset selection, original-team eligibility,");
            line("and render fallback have NOT been identified by this script.");
            line("If these decompilations are generic field export/assertion code,");
            line("stop following their helpers. Next phase must identify the");
            line("actual UI action-photo resource request in offline MyNBA.");
            line("Do not install or inject the skeleton QoL Hook DLL.");
            out.flush();
            if (out.checkError()) {
                printerr("Writing report failed; try saving to Desktop.");
                return;
            }
        }
        println("Action-shot function trace saved: " + destination.getAbsolutePath());
        println("Upload this text report, not the NBA2K26.exe file.");
    }

    private Region[] findUnwindRegions() throws Exception {
        MemoryBlock pdata = null;
        for (MemoryBlock b : mem.getBlocks()) {
            String name = b.getName().toLowerCase();
            if (name.equals(".pdata") || name.endsWith(".pdata")) {
                pdata = b;
                break;
            }
        }
        if (pdata == null || !pdata.isInitialized()) {
            line("WARNING: no initialized .pdata block in this import.");
            return null;
        }
        Region[] matches = new Region[TARGET_RVAS.length];
        long span = Math.min(pdata.getSize(), MAX_PDATA_BYTES);
        if (span != pdata.getSize()) {
            line("WARNING: .pdata scan capped at 96 MiB.");
        }
        line("PE .pdata start: " + hx(pdata.getStart()));
        line("PE .pdata scanned bytes: " + span);
        int accepted = 0;
        for (long offset = 0; offset + 12 <= span; offset += 12) {
            if ((offset & 0xFFFF) == 0) monitor.checkCancelled();
            Address entry = pdata.getStart().add(offset);
            long begin, end, unwind;
            try {
                begin = Integer.toUnsignedLong(mem.getInt(entry));
                end = Integer.toUnsignedLong(mem.getInt(entry.add(4)));
                unwind = Integer.toUnsignedLong(mem.getInt(entry.add(8)));
            } catch (Exception badRead) {
                line("Unreadable .pdata at " + hx(entry));
                break;
            }
            if (begin == 0 || end <= begin || unwind == 0 ||
                end - begin > 0x1000000L) continue;
            Address code = base.add(begin);
            if (!executable(code)) continue;
            accepted++;
            for (int i = 0; i < TARGET_RVAS.length; i++) {
                long target = TARGET_RVAS[i];
                if (target < begin || target >= end) continue;
                if (matches[i] == null ||
                    end - begin < matches[i].end - matches[i].begin) {
                    matches[i] = new Region(begin, end, unwind);
                }
            }
        }
        line("Plausible unwind entries encountered: " + accepted);
        return matches;
    }

    private boolean executable(Address a) {
        MemoryBlock b = mem.getBlock(a);
        return b != null && b.isInitialized() && b.isExecute();
    }

    private String hx(Address a) { return "0x" + a.toString(); }
    private String rva(long a) { return String.format("0x%X", a); }
    private void line(String s) { out.println(s); }
}
