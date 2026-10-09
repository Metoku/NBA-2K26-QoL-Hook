// NBA2K26PortraitTableInspector.java
// Read-only research of two suspected NBA 2K26 photo-label C++ vtables.
// @category NBA2K26 Research

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Ghidra GUI script for static local investigation only.
 *
 * No game launch, game-file changes, process memory access, DLL injection,
 * code patching, database modifications, network calls, or full auto-analysis.
 *
 * Built for the specifically fingerprinted July 2026 x64 NBA2K26.exe.
 * Offsets below are RVA offsets relative to the currently loaded image base.
 */
public class NBA2K26PortraitTableInspector extends GhidraScript {

    private static final String EXPECTED_SHA256 = "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long[] SLOT_RVAS = { 0x3ECCA78L, 0x3ECCB38L };
    private static final long[] FORMATTER_RVAS = { 0x7205A0L, 0x720620L };
    private static final String[] LABELS = {
        "Photo mode label formatter",
        "Photo style label formatter"
    };

    private static final int MAX_RTTI_BACK_BYTES = 16384;
    private static final int CHUNK_BYTES = 2 * 1024 * 1024;
    private static final long MAX_EXEC_SCAN_BYTES = 768L * 1024 * 1024;
    private static final int MAX_HITS_PER_TARGET = 24;

    private Memory memory;
    private Address imageBase;
    private PrintWriter report;

    private static class Table {
        String label;
        Address slot;
        Address function;
        Address probableStart;
        Address col;
        String typeName;
        int offsetToTop;
        boolean rttiVerified;

        Table(String label, Address slot, Address function) {
            this.label = label;
            this.slot = slot;
            this.function = function;
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open NBA2K26.exe in Ghidra CodeBrowser first.");
            return;
        }

        memory = currentProgram.getMemory();
        imageBase = currentProgram.getImageBase();

        if (currentProgram.getDefaultPointerSize() != 8) {
            printerr("This script expects an x64 PE: the imported program is not 64-bit.");
            return;
        }

        String importedSha = currentProgram.getExecutableSHA256();
        if (importedSha != null && !importedSha.isEmpty() &&
            !EXPECTED_SHA256.equalsIgnoreCase(importedSha)) {
            printerr("The imported program's SHA-256 does not match the studied game build.");
            printerr("Expected: " + EXPECTED_SHA256);
            printerr("Imported: " + importedSha);
            printerr("Aborting to avoid misleading analysis of the wrong version.");
            return;
        }

        // This is the only file we create: a text report selected by the user.
        File destination = askFile("Save NBA 2K26 table research report", "Save");
        try (PrintWriter writer = new PrintWriter(
                new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(destination), StandardCharsets.UTF_8)))) {
            report = writer;
            line("NBA 2K26 - Ghidra Photo Table Inspector");
            line("STATIC RESEARCH ONLY; NO PATCHES OR PROCESS ATTACHMENT");
            line("Program: " + currentProgram.getName());
            line("Loaded Ghidra image base: " + hex(imageBase));
            line("Known reference build SHA-256: " + EXPECTED_SHA256);
            line("Imported Ghidra SHA-256 metadata: " + (importedSha == null ? "(not available)" : importedSha));
            line("When Ghidra provides an imported SHA-256, this script verifies it.");
            line("Otherwise, verify your EXE build by the read-only PowerShell fingerprint tool.");
            line("");

            List<Table> tables = new ArrayList<>();
            for (int i = 0; i < SLOT_RVAS.length; i++) {
                monitor.checkCancelled();
                Table t = new Table(LABELS[i], imageBase.add(SLOT_RVAS[i]),
                                    imageBase.add(FORMATTER_RVAS[i]));
                tables.add(t);
                inspectTable(t);
            }

            line("");
            line("=== EXISTING Ghidra REFERENCES (may be empty before analysis) ===");
            for (Table t : tables) {
                dumpExistingReferences(t);
            }

            line("");
            line("=== LIMITED EXECUTABLE-BLOCK REFERENCE SEARCH ===");
            line("Pattern recognition only: 7-byte REX+LEA/MOV RIP-relative and 6-byte FF15/FF25 indirect call/jmp.");
            line("A match is NOT confirmed to begin at an instruction boundary or belong to an executed code path.");
            Map<Long, String> searchTargets = makeCandidateTargets(tables);
            line("Candidate table addresses searched: " + searchTargets.size());
            scanExecutableBlocks(searchTargets);

            // The previous user's read-only report found two particularly
            // useful references near one another. Record self-validated
            // machine-code excerpts so a reviewer can disassemble them.
            line("");
            line("=== LIKELY TABLE STARTS AND CODE CONTEXT (RESEARCH ONLY) ===");
            dumpTableStartCodeContext();

            line("");
            line("Interpretation:");
            line("- A valid MSVC RTTI name can identify a C++ class, but does NOT prove it controls MyNBA player photos.");
            line("- These tables may be arena/presentation text or display UI rather than image loading.");
            line("- No output from this script is a safe patch, callable portrait function, or working hook.");
            line("- Never modify the EXE or inject the experimental QoL Hook DLL from these results.");
            report.flush();
            if (report.checkError()) {
                printerr("Unable to finish writing the report. Try saving to Desktop.");
                return;
            }
        }

        println("Ghidra analysis report saved to: " + destination.getAbsolutePath());
        println("Upload that text report to the chat. No screenshots of raw addresses are needed.");
    }

    private void inspectTable(Table t) throws Exception {
        line("");
        line("=== " + t.label + " ===");
        line("Pointer slot: " + hex(t.slot) + " (RVA " + rva(t.slot) + ")");
        line("Expected function: " + hex(t.function));
        Long ptr = readPointer(t.slot);
        if (ptr == null) {
            line("ERROR: pointer slot isn't readable in this imported program.");
            return;
        }
        Address actual = addressFromPointer(ptr);
        line("Observed 64-bit value: " + hex64(ptr));
        line("Resolves to: " + (actual == null ? "unmapped" : hex(actual)));
        if (actual == null || !actual.equals(t.function)) {
            line("WARNING: pointer differs from the fingerprinted executable's expectation; stopping table inference.");
            return;
        }
        line("Entry targets executable memory: " + isExecutable(actual));

        // MSVC x64 vftables typically store a pointer to a Complete Object
        // Locator (COL) at vftable[-1]. Search backwards for that signature.
        MemoryBlock slotBlock = memory.getBlock(t.slot);
        if (slotBlock == null) return;
        long distance = Math.min(MAX_RTTI_BACK_BYTES,
                                 t.slot.subtract(slotBlock.getStart()));
        for (long back = 0; back <= distance; back += 8) {
            monitor.checkCancelled();
            Address candidate = t.slot.subtract(back);
            if (!isExecutablePointer(candidate)) continue;
            Address colPtrLocation = candidate.subtract(8);
            Long colValue = readPointer(colPtrLocation);
            if (colValue == null) continue;
            Address col = addressFromPointer(colValue);
            if (col == null || !isNonexecutableData(col)) continue;
            String[] metadata = parseMsvcCol(col);
            if (metadata == null) continue;

            t.probableStart = candidate;
            t.col = col;
            t.typeName = metadata[0];
            t.offsetToTop = Integer.parseInt(metadata[1]);
            t.rttiVerified = true;
            break; // nearest plausible RTTI-bearing table start
        }

        if (t.rttiVerified) {
            line("Valid-looking MSVC x64 Complete Object Locator found.");
            line("Inferred vftable start: " + hex(t.probableStart) +
                 " (RVA " + rva(t.probableStart) + ")");
            line("Pointer-to-COL at: " + hex(t.probableStart.subtract(8)));
            line("Complete Object Locator: " + hex(t.col));
            line("MSVC decorated type name: " + t.typeName);
            line("COL object offset: " + t.offsetToTop);
            line("Photo-label function's slot index: " +
                 (t.slot.subtract(t.probableStart) / 8));
            line("WARNING: RTTI establishes an apparent class/table relationship, not its use by MyNBA.");
        } else {
            line("No verifiable MSVC x64 RTTI/COL was found in the previous 16 KiB.");
            line("The table may use stripped or nonstandard RTTI, or the apparent function pointers may be another kind of registry.");
            line("Do NOT assume the pointer slot is the start of a vftable.");
        }

        line("Nearby pointer entries (only data inspection, no type edits):");
        for (int delta = -12; delta <= 12; delta++) {
            Address pos = t.slot.add((long) delta * 8);
            Long value = readPointer(pos);
            if (value == null) continue;
            Address dest = addressFromPointer(value);
            String kind = dest == null ? "unmapped" :
                          isExecutable(dest) ? "executable" :
                          isNonexecutableData(dest) ? "data" : "other";
            line(String.format("  slot %+3d | %s -> %s [%s]%s",
                 delta, hex(pos), hex64(value), kind,
                 delta == 0 ? "  <=== reported label formatter" : ""));
        }
    }

    private String[] parseMsvcCol(Address col) {
        try {
            // x64 MSVC CompleteObjectLocator:
            // signature, offset, cdOffset, typeDescRva, classHierarchyRva,
            // selfRva, all DWORDs; signature=1 and selfRva=COL RVA.
            if (!isNonexecutableData(col) ||
                !isNonexecutableData(col.add(23))) return null;
            long sig = Integer.toUnsignedLong(memory.getInt(col));
            long self = Integer.toUnsignedLong(memory.getInt(col.add(20)));
            long colRva = col.subtract(imageBase);
            if (sig != 1 || self != colRva) return null;

            long typeRva = Integer.toUnsignedLong(memory.getInt(col.add(12)));
            long hierarchyRva = Integer.toUnsignedLong(memory.getInt(col.add(16)));
            if (typeRva == 0 || hierarchyRva == 0) return null;
            Address typeDesc = imageBase.add(typeRva);
            Address hierarchy = imageBase.add(hierarchyRva);
            if (!isNonexecutableData(typeDesc) ||
                !isNonexecutableData(hierarchy)) return null;

            String name = readAscii(typeDesc.add(16), 200);
            if (!name.startsWith(".?AV") && !name.startsWith(".?AU")) return null;
            int objectOffset = memory.getInt(col.add(4));
            return new String[] { name, Integer.toString(objectOffset) };
        } catch (Exception invalid) {
            return null;
        }
    }

    private String readAscii(Address start, int maxLength) {
        StringBuilder out = new StringBuilder();
        try {
            for (int i = 0; i < maxLength; i++) {
                int c = memory.getByte(start.add(i)) & 0xFF;
                if (c == 0) break;
                if (c < 32 || c > 126) return "";
                out.append((char) c);
            }
        } catch (Exception ignored) {
            return "";
        }
        return out.toString();
    }

    private Map<Long, String> makeCandidateTargets(List<Table> tables) {
        Map<Long, String> targets = new LinkedHashMap<>();
        for (Table t : tables) {
            if (t.rttiVerified) {
                targets.put(t.probableStart.subtract(imageBase),
                            t.label + ": RTTI vftable start");
            } else {
                // No confirmed start: search a SMALL set of nearby possible
                // starts. A hit would need independent verification.
                for (int back = 0; back <= 256; back += 8) {
                    Address candidate = t.slot.subtract(back);
                    targets.put(candidate.subtract(imageBase),
                                t.label + ": unverified table address " + hex(candidate));
                }
            }
        }
        return targets;
    }

    private void dumpExistingReferences(Table t) {
        List<Address> addresses = new ArrayList<>();
        addresses.add(t.slot);
        if (t.rttiVerified && !t.probableStart.equals(t.slot)) {
            addresses.add(t.probableStart);
        }
        for (Address target : addresses) {
            ReferenceIterator iter = currentProgram.getReferenceManager().getReferencesTo(target);
            int count = 0;
            while (iter.hasNext()) {
                Reference ref = iter.next();
                if (count < 20) {
                    line("  Ref to " + hex(target) + ": from " + hex(ref.getFromAddress()) +
                         " (" + ref.getReferenceType() + ")");
                }
                count++;
            }
            line("  Indexed Ghidra references to " + hex(target) + ": " + count);
        }
        line("Note: without auto-analysis, the Ghidra reference index is incomplete.");
    }

    private void scanExecutableBlocks(Map<Long, String> targetRvas) throws Exception {
        if (targetRvas.isEmpty()) return;
        long total = 0;
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                total += block.getSize();
            }
        }
        long quota = Math.min(total, MAX_EXEC_SCAN_BYTES);
        line("Total initialized executable bytes: " + total);
        line("Scan cap (bytes): " + MAX_EXEC_SCAN_BYTES);
        if (total > MAX_EXEC_SCAN_BYTES) {
            line("WARNING: code scan is capped and may omit later executable blocks.");
        }
        monitor.initialize(quota);
        monitor.setMessage("Searching executable bytes for references to the suspected portrait tables");
        long processed = 0;
        Map<Long, Integer> hitCounts = new HashMap<>();
        int totalHits = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;
            if (processed >= MAX_EXEC_SCAN_BYTES) break;
            long length = Math.min(block.getSize(), MAX_EXEC_SCAN_BYTES - processed);
            long blockOffset = 0;
            byte[] buffer = new byte[CHUNK_BYTES + 8];

            while (blockOffset < length) {
                monitor.checkCancelled();
                int requested = (int) Math.min(buffer.length, length - blockOffset);
                if (requested < 6) break;
                int count;
                try {
                    count = memory.getBytes(block.getStart().add(blockOffset),
                                            buffer, 0, requested);
                } catch (Exception ex) {
                    line("WARNING: could not read executable block " + block.getName() +
                         " at offset " + blockOffset + "; skipping remaining part.");
                    break;
                }
                if (count < 6) break;
                for (int i = 0; i + 6 <= count; i++) {
                    int lengthOfOpcode;
                    int displacementOffset;
                    String kind;
                    int first = buffer[i] & 0xFF;
                    if (i + 7 <= count && (first & 0xF8) == 0x48 &&
                        ((buffer[i+1] & 0xFF) == 0x8D || (buffer[i+1] & 0xFF) == 0x8B) &&
                        ((buffer[i+2] & 0xC7) == 0x05)) {
                        lengthOfOpcode = 7;
                        displacementOffset = 3;
                        kind = (buffer[i+1] & 0xFF) == 0x8D ?
                               "candidate LEA [RIP+disp32]" : "candidate MOV [RIP+disp32]";
                    } else if (first == 0xFF &&
                              ((buffer[i+1] & 0xFF) == 0x15 ||
                               (buffer[i+1] & 0xFF) == 0x25)) {
                        lengthOfOpcode = 6;
                        displacementOffset = 2;
                        kind = (buffer[i+1] & 0xFF) == 0x15 ?
                               "candidate indirect CALL [RIP+disp32]" :
                               "candidate indirect JMP [RIP+disp32]";
                    } else continue;
                    int displacement = (buffer[i+displacementOffset] & 0xFF) |
                        ((buffer[i+displacementOffset+1] & 0xFF) << 8) |
                        ((buffer[i+displacementOffset+2] & 0xFF) << 16) |
                        ((buffer[i+displacementOffset+3] & 0xFF) << 24);
                    long instructionRva = block.getStart().subtract(imageBase) +
                                          blockOffset + i;
                    long target = instructionRva + lengthOfOpcode + displacement;
                    String label = targetRvas.get(target);
                    if (label == null) continue;
                    int n = hitCounts.containsKey(target) ? hitCounts.get(target) : 0;
                    if (n >= MAX_HITS_PER_TARGET) continue;
                    hitCounts.put(target, n + 1);
                    totalHits++;
                    line("  " + kind + " at " + hex(imageBase.add(instructionRva)) +
                         " (RVA " + hexRva(instructionRva) + ") -> " +
                         label + " (RVA " + hexRva(target) + ")");
                }
                // Six bytes of overlap prevents losing a 7-byte instruction
                // crossing a chunk boundary; earlier candidates won't repeat.
                int advance = (count < requested || blockOffset + count >= length)
                              ? count : count - 6;
                if (advance <= 0) break;
                blockOffset += advance;
                monitor.setProgress(Math.min(quota, processed + blockOffset));
            }
            processed += length;
        }
        line("Total tentative code-reference hits: " + totalHits);
        if (totalHits == 0) {
            line("No matches is inconclusive. Uncovered mechanisms include dynamic registration,");
            line("different instruction encodings, thunking, and virtual dispatch.");
        }
    }

    // The discovered LEA candidates target table starts, not the individual
    // label-formatter slots. Both formatter slots are exactly 0xB8 bytes
    // after the corresponding candidate table start.
    private void dumpTableStartCodeContext() throws Exception {
        dumpOneCodeContext("Photo mode candidate table start",
                           0x742A4AL, 0x3ECC9C0L, 0x3ECCA78L);
        dumpOneCodeContext("Photo style candidate table start",
                           0x7429EEL, 0x3ECCA80L, 0x3ECCB38L);
    }

    private void dumpOneCodeContext(String label, long referenceRva,
                                    long tableStartRva, long formatterSlotRva)
                                    throws Exception {
        monitor.checkCancelled();
        Address reference = imageBase.add(referenceRva);
        line("");
        line(label);
        line("Candidate code reference: " + hex(reference) +
             " (RVA " + hexRva(referenceRva) + ")");
        line("Candidate table beginning: " + hex(imageBase.add(tableStartRva)) +
             " (RVA " + hexRva(tableStartRva) + ")");
        line("Label formatter pointer: " + hex(imageBase.add(formatterSlotRva)) +
             " (index " + ((formatterSlotRva - tableStartRva) / 8) +
             " at +0x" + Long.toHexString(formatterSlotRva - tableStartRva) + ")");
        if (formatterSlotRva - tableStartRva != 0xB8) {
            line("WARNING: layout does not match expected relative offset.");
            return;
        }
        try {
            byte[] ins = new byte[7];
            if (memory.getBytes(reference, ins) != 7) {
                line("WARNING: cannot read candidate code reference.");
                return;
            }
            long disp = ((long)(ins[3] & 0xFF)) |
                        (((long)(ins[4] & 0xFF)) << 8) |
                        (((long)(ins[5] & 0xFF)) << 16) |
                        (((long)(ins[6] & 0xFF)) << 24);
            // x64 disp32 is signed, even though the intermediate is long.
            if ((disp & 0x80000000L) != 0) disp -= 0x100000000L;
            long resolvedRva = referenceRva + 7 + disp;
            boolean isLea = (ins[0] & 0xF8) == 0x48 &&
                            (ins[1] & 0xFF) == 0x8D &&
                            (ins[2] & 0xC7) == 0x05;
            line("Candidate bytes encode REX LEA RIP-relative: " + isLea);
            line("Candidate resolves to RVA: " + hexRva(resolvedRva) +
                 " (expected " + hexRva(tableStartRva) + ")");
            if (!isLea || resolvedRva != tableStartRva) {
                line("WARNING: reference did not validate; no context will be dumped.");
                return;
            }

            final int before = 192;
            final int after = 224;
            Address start = reference.subtract(before);
            byte[] bytes = new byte[before + 7 + after];
            int got = memory.getBytes(start, bytes);
            if (got <= 0) {
                line("WARNING: could not read the surrounding bytes.");
                return;
            }
            line("Raw code window starts at " + hex(start) +
                 " (RVA " + hexRva(start.subtract(imageBase)) + ")");
            line("Candidate reference begins at byte index " + before + ".");
            line("Hexadecimal bytes below are not a confirmed instruction listing.");
            for (int i = 0; i < got; i += 16) {
                int limit = Math.min(16, got - i);
                StringBuilder row = new StringBuilder();
                row.append("  ").append(hex(start.add(i))).append(": ");
                for (int j = 0; j < limit; j++) {
                    row.append(String.format("%02X ", bytes[i+j] & 0xFF));
                }
                line(row.toString());
            }
        } catch (Exception ex) {
            line("WARNING: unable to read the code window: " + ex.getMessage());
        }
    }

    private Long readPointer(Address pos) {
        try {
            MemoryBlock block = memory.getBlock(pos);
            if (block == null || !block.isInitialized() ||
                !block.contains(pos.add(7))) return null;
            return memory.getLong(pos);
        } catch (Exception invalid) {
            return null;
        }
    }

    private Address addressFromPointer(long raw) {
        try {
            Address addr = imageBase.getAddressSpace().getAddress(raw);
            return memory.contains(addr) ? addr : null;
        } catch (Exception invalid) {
            return null;
        }
    }

    private boolean isExecutablePointer(Address p) {
        Long raw = readPointer(p);
        if (raw == null) return false;
        Address dest = addressFromPointer(raw);
        return dest != null && isExecutable(dest);
    }

    private boolean isExecutable(Address address) {
        MemoryBlock block = memory.getBlock(address);
        return block != null && block.isInitialized() && block.isExecute();
    }

    private boolean isNonexecutableData(Address address) {
        MemoryBlock block = memory.getBlock(address);
        return block != null && block.isInitialized() && !block.isExecute();
    }

    private String rva(Address a) {
        return hexRva(a.subtract(imageBase));
    }

    private String hexRva(long value) {
        return String.format("0x%X", value);
    }

    private String hex(Address address) {
        return address == null ? "(none)" : "0x" + address.toString();
    }

    private String hex64(long value) {
        return String.format("0x%016X", value);
    }

    private void line(String s) {
        report.println(s);
    }
}
