// NBA2K26PlayerPhotoFieldTrace.java
// @category NBA2K26 Research
//
// Read-only investigation of player photo field strings in one exact NBA2K26.exe
// build. Does not modify program data, game files, process memory, or saves.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class NBA2K26PlayerPhotoFieldTrace extends GhidraScript {

    private static final String EXPECTED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    // Specific assertion/accessor strings are prioritized over general names.
    private static final String[] WORDS = {
        "PLAYERDATA::SetPhotoId",
        "PLAYERDATA::SetActionShotId",
        "GetPhotoId()",
        "GetActionShotId()",
        "PhotoId over/underflow",
        "ActionShotId over/underflow",
        "PortraitTeam",
        "ActionShotTeam",
        "PhotoId",
        "ActionShotId",
        "PlayerPortrait"
    };

    private static final int CHUNK = 2 * 1024 * 1024;
    private static final int OVERLAP = 128;
    private static final int MAX_MATCHES_PER_STRING = 12;
    private static final int MAX_POINTERS = 80;
    private static final int MAX_CODE_REFS = 100;
    private static final int MAX_CODE_REFS_PER_LABEL = 12;
    private static final long MAX_DATA_BYTES = 384L * 1024 * 1024;
    private static final long MAX_CODE_BYTES = 1152L * 1024 * 1024;

    private static class Needle {
        final String name;
        final String kind;
        final byte[] bytes;
        Needle(String name, String kind, byte[] bytes) {
            this.name = name;
            this.kind = kind;
            this.bytes = bytes;
        }
    }
    private static class Hit {
        final String label;
        final String kind;
        final Address address;
        Hit(String label, String kind, Address address) {
            this.label = label;
            this.kind = kind;
            this.address = address;
        }
    }
    private static class Target {
        final String label;
        final String kind;
        final Address address;
        Target(String label, String kind, Address address) {
            this.label = label;
            this.kind = kind;
            this.address = address;
        }
    }

    private Memory memory;
    private Address imageBase;
    private PrintWriter report;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null || currentProgram.getDefaultPointerSize() != 8) {
            printerr("Open the 64-bit NBA2K26.exe in CodeBrowser before running.");
            return;
        }
        String hash = currentProgram.getExecutableSHA256();
        if (hash != null && !hash.isEmpty() && !EXPECTED_SHA.equalsIgnoreCase(hash)) {
            printerr("The imported game build does not match the examined NBA2K26.exe.");
            printerr("Expected SHA256: " + EXPECTED_SHA);
            printerr("Imported SHA256: " + hash);
            return;
        }

        imageBase = currentProgram.getImageBase();
        memory = currentProgram.getMemory();
        File destination = askFile("Save player-photo field research report", "Save");
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(destination), StandardCharsets.UTF_8))) {
            report = writer;
            line("NBA 2K26 - Player Photo Field Research");
            line("READ-ONLY STATIC RESEARCH; NO GAME OR SAVE MODIFICATIONS");
            line("Executable: " + currentProgram.getName());
            line("Image base: " + hex(imageBase));
            line("Imported SHA256: " + (hash == null ? "unavailable" : hash));
            line("Exact known build: " + EXPECTED_SHA);
            line("Scope: PhotoId, ActionShotId, PortraitTeam, ActionShotTeam");
            line("No automatic disassembly or program edits performed.");
            line("");

            List<Needle> patterns = createNeedles();
            List<Hit> strings = scanDataForStrings(patterns);
            reportStringHits(strings);
            Map<Long,Target> targets = new LinkedHashMap<Long,Target>();
            for (Hit hit : strings) {
                long key = hit.address.subtract(imageBase);
                // Prefer the most specific term for a given address.
                if (!targets.containsKey(key)) {
                    targets.put(key, new Target(hit.label, "literal " + hit.kind, hit.address));
                }
            }

            Map<Long,Target> slots = scanDataForPointerSlots(targets);
            for (Map.Entry<Long,Target> e : slots.entrySet()) {
                if (!targets.containsKey(e.getKey())) targets.put(e.getKey(), e.getValue());
            }

            line("");
            line("=== INDEXED GHIDRA REFERENCES TO FIELD STRINGS ===");
            line("Unanalyzed code will usually have incomplete reference indexes.");
            int displayed = 0;
            for (Hit hit : strings) {
                if (displayed >= 35) {
                    line("Remaining hits omitted from Ghidra reference listing.");
                    break;
                }
                int references = 0;
                ReferenceIterator iter = currentProgram.getReferenceManager()
                    .getReferencesTo(hit.address);
                while (iter.hasNext()) {
                    Reference ref = iter.next();
                    if (references < 8) {
                        line("  " + hit.label + " @ " + hex(hit.address) + " <- " +
                             hex(ref.getFromAddress()) + " (" + ref.getReferenceType() + ")");
                    }
                    references++;
                }
                if (references != 0) line("  References for hit: " + references);
                displayed++;
            }

            line("");
            line("=== CANDIDATE RIP-RELATIVE REFERENCES IN EXECUTABLE SECTIONS ===");
            line("Candidates may be false positives and may only reference metadata or assertions.");
            scanCodeForTargets(targets);

            line("");
            line("=== INTERPRETATION AND LIMITATIONS ===");
            line("This is a field-name/diagnostic-string trace, NOT a player image loader trace.");
            line("A setter/assertion can be unrelated to the read path displaying portraits.");
            line("The actual real-photo asset, original-team mapping, UI loader, and fallback");
            line("decision are still unknown. Candidate code references need disassembly.");
            line("Do not patch any locations, inject the QoL DLL, or edit MyNBA saves.");
            line("If no useful code references appear, pivot to runtime investigation");
            line("in an isolated offline, non-anti-cheat context rather than inventing offsets.");
            report.flush();
            if (report.checkError()) {
                printerr("Ghidra could not finish writing the report. Try Desktop.");
                return;
            }
        }
        println("Player photo research saved: " + destination.getAbsolutePath());
        println("Upload the text report. No address-by-address screenshots are needed.");
    }

    private List<Needle> createNeedles() {
        List<Needle> out = new ArrayList<Needle>();
        for (String word : WORDS) {
            out.add(new Needle(word, "ASCII", word.getBytes(StandardCharsets.US_ASCII)));
            out.add(new Needle(word, "UTF-16LE", word.getBytes(StandardCharsets.UTF_16LE)));
        }
        return out;
    }

    private List<Hit> scanDataForStrings(List<Needle> patterns) throws Exception {
        line("=== NONEXECUTABLE SECTION STRING SCAN ===");
        line("Searches ASCII and UTF-16LE. Initial strings may be from reflection/assertion data.");
        List<Hit> hits = new ArrayList<Hit>();
        Map<String,Integer> counts = new LinkedHashMap<String,Integer>();
        long remaining = MAX_DATA_BYTES;
        long scanned = 0;
        byte[] buffer = new byte[CHUNK + OVERLAP];
        monitor.setMessage("Scanning photo field text in non-executable sections");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.isExecute() || remaining <= 0) continue;
            long length = Math.min(block.getSize(), remaining);
            long cursor = 0;
            while (cursor < length) {
                monitor.checkCancelled();
                int requested = (int)Math.min((long)buffer.length, length - cursor);
                int n;
                try {
                    n = memory.getBytes(block.getStart().add(cursor), buffer, 0, requested);
                } catch (Exception ex) {
                    line("WARNING: skipping unreadable region at " +
                         hex(block.getStart().add(cursor)));
                    break;
                }
                if (n <= 0) break;
                for (Needle needle : patterns) {
                    if (needle.bytes.length > n) continue;
                    String key = needle.name + "/" + needle.kind;
                    int count = counts.containsKey(key) ? counts.get(key) : 0;
                    if (count >= MAX_MATCHES_PER_STRING) continue;
                    byte first = needle.bytes[0];
                    for (int i = 0; i + needle.bytes.length <= n; ++i) {
                        if (buffer[i] != first) continue;
                        boolean match = true;
                        for (int j = 1; j < needle.bytes.length; j++) {
                            if (buffer[i + j] != needle.bytes[j]) {
                                match = false;
                                break;
                            }
                        }
                        if (!match) continue;
                        // Only emit when candidate starts in the non-overlap
                        // area. Any last-window bytes are handled next time.
                        boolean lastChunk = cursor + n >= length;
                        if (!lastChunk && i >= n - OVERLAP) continue;
                        hits.add(new Hit(needle.name, needle.kind,
                                         block.getStart().add(cursor + i)));
                        if (++count >= MAX_MATCHES_PER_STRING) break;
                    }
                    counts.put(key, count);
                }
                boolean done = cursor + n >= length;
                long advance = done ? n : n - OVERLAP;
                if (advance <= 0) break;
                cursor += advance;
            }
            remaining -= length;
            scanned += length;
        }
        line("Data bytes in scanned sections (approx.): " + scanned);
        if (remaining <= 0) line("WARNING: data scan cap reached; some blocks omitted.");
        line("Literal field-name hits: " + hits.size());
        if (hits.isEmpty()) line("No matching literal strings in scanned sections.");
        return hits;
    }

    private void reportStringHits(List<Hit> hits) {
        for (Hit hit : hits) {
            line("  " + hit.label + " [" + hit.kind + "] at " +
                 hex(hit.address) + " RVA " + rva(hit.address));
        }
    }

    private Map<Long,Target> scanDataForPointerSlots(Map<Long,Target> strings)
            throws Exception {
        line("");
        line("=== POSSIBLE STATIC POINTERS TO FIELD STRINGS ===");
        line("Absolute VA pointer values only; pointer slots are not verified code paths.");
        Map<Long,Target> pointerSlots = new LinkedHashMap<Long,Target>();
        if (strings.isEmpty()) return pointerSlots;
        Map<Long,Target> absolute = new LinkedHashMap<Long,Target>();
        for (Target t : strings.values()) {
            absolute.put(t.address.getOffset(), t);
        }

        long remaining = MAX_DATA_BYTES;
        byte[] buffer = new byte[CHUNK + 8];
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.isExecute() || remaining <= 0) continue;
            long length = Math.min(block.getSize(), remaining);
            long cursor = 0;
            while (cursor + 8 <= length && pointerSlots.size() < MAX_POINTERS) {
                monitor.checkCancelled();
                int requested = (int)Math.min((long)buffer.length, length - cursor);
                int n;
                try {
                    n = memory.getBytes(block.getStart().add(cursor), buffer, 0, requested);
                } catch (Exception ex) {
                    break;
                }
                if (n < 8) break;
                // x64 pointers are usually aligned; scan 8-byte-aligned RVAs.
                long blockOffset = block.getStart().getOffset();
                int align = (int)((8 - ((blockOffset + cursor) & 7)) & 7);
                for (int i = align; i + 8 <= n; i += 8) {
                    long val = 0;
                    for (int j = 0; j < 8; j++) val |=
                        ((long)(buffer[i+j] & 0xff)) << (j*8);
                    Target t = absolute.get(val);
                    if (t == null) continue;
                    Address slot = block.getStart().add(cursor + i);
                    long key = slot.subtract(imageBase);
                    if (pointerSlots.containsKey(key)) continue;
                    pointerSlots.put(key,new Target(t.label,
                                     "pointer to " + t.kind, slot));
                    line("  " + t.label + " -> pointer slot " + hex(slot) +
                         " (RVA " + rva(slot) + ")");
                    if (pointerSlots.size() >= MAX_POINTERS) break;
                }
                int advance = cursor + n >= length ? n : n - 8;
                if (advance <= 0) break;
                cursor += advance;
            }
            remaining -= length;
        }
        line("Candidate pointer slots: " + pointerSlots.size());
        return pointerSlots;
    }

    private void scanCodeForTargets(Map<Long,Target> targets) throws Exception {
        if (targets.isEmpty()) {
            line("No target strings/pointers found; reference scan skipped.");
            return;
        }
        byte[] buffer = new byte[CHUNK + 8];
        long remaining = MAX_CODE_BYTES;
        int total = 0;
        Map<String,Integer> refsPerLabel = new LinkedHashMap<String,Integer>();
        monitor.setMessage("Finding possible code references to photo-data strings");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() || remaining <= 0 ||
                total >= MAX_CODE_REFS) continue;
            long length = Math.min(block.getSize(), remaining);
            long cursor = 0;
            while (cursor < length && total < MAX_CODE_REFS) {
                monitor.checkCancelled();
                int requested = (int)Math.min((long)buffer.length, length - cursor);
                int n;
                try {
                    n = memory.getBytes(block.getStart().add(cursor), buffer, 0, requested);
                } catch (Exception ex) {
                    line("WARNING: skipped unreadable executable block at " +
                         hex(block.getStart().add(cursor)));
                    break;
                }
                if (n < 7) break;
                int scanLength = cursor + n >= length ? n : n - 8;
                for (int i = 0; i + 7 <= scanLength && total < MAX_CODE_REFS; i++) {
                    int first = buffer[i] & 0xff;
                    if ((first & 0xF8) != 0x48) continue;
                    int op = buffer[i+1] & 0xff;
                    if (op != 0x8D && op != 0x8B) continue;
                    if ((buffer[i+2] & 0xC7) != 0x05) continue;
                    long displacement = (buffer[i+3] & 0xffL) |
                        ((buffer[i+4] & 0xffL) << 8) |
                        ((buffer[i+5] & 0xffL) << 16) |
                        ((buffer[i+6] & 0xffL) << 24);
                    if ((displacement & 0x80000000L) != 0)
                        displacement -= 0x100000000L;
                    Address at = block.getStart().add(cursor + i);
                    long addressRva = at.subtract(imageBase);
                    long targetRva = addressRva + 7 + displacement;
                    Target target = targets.get(targetRva);
                    if (target == null) continue;
                    int seen = refsPerLabel.containsKey(target.label) ?
                        refsPerLabel.get(target.label) : 0;
                    if (seen >= MAX_CODE_REFS_PER_LABEL) continue;
                    refsPerLabel.put(target.label, seen + 1);
                    total++;
                    line("  " + target.label + " (" + target.kind + ") candidate " +
                         hex(at) + " -> " + hex(target.address));
                    dumpContext(at, 32, 80);
                }
                int step = cursor + n >= length ? n : n - 8;
                if (step <= 0) break;
                cursor += step;
            }
            remaining -= length;
        }
        line("Total tentative code references: " + total);
        if (total == 0) line("No candidates. This does NOT rule out a photo loading function.");
        if (total == MAX_CODE_REFS) line("WARNING: report limit reached; additional references omitted.");
        if (remaining <= 0) line("WARNING: code scan cap reached; some blocks may be omitted.");
    }

    private void dumpContext(Address at, int before, int after) {
        try {
            Address start = at.subtract(before);
            byte[] b = new byte[before + 7 + after];
            int n = memory.getBytes(start, b);
            if (n <= 0) return;
            line("    Context start: " + hex(start) +
                 ", candidate at +0x" + Integer.toHexString(before));
            for (int pos = 0; pos < n; pos += 16) {
                StringBuilder row = new StringBuilder();
                row.append("    ").append(hex(start.add(pos))).append(": ");
                int count = Math.min(16, n - pos);
                for (int j = 0; j < count; j++)
                    row.append(String.format("%02X ", b[pos+j] & 0xff));
                line(row.toString());
            }
        } catch (Exception ex) {
            line("    Context unavailable: " + ex.getMessage());
        }
    }

    private String hex(Address address) {
        return "0x" + address.toString();
    }
    private String rva(Address address) {
        return String.format("0x%X", address.subtract(imageBase));
    }
    private void line(String message) {
        report.println(message);
    }
}
