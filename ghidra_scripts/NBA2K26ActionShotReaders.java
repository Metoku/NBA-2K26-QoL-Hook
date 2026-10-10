// NBA2K26ActionShotReaders.java
// @category NBA2K26 Research
//
// Read-only Ghidra analysis of possible accesses to the player-data
// 16-bit ActionShotId field at object offset +0x3DC.
// Never edits the game, process memory, saves, or Ghidra's program database.
// Exact July 2026 x64 NBA2K26.exe build ONLY.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NBA2K26ActionShotReaders extends GhidraScript {

    private static final String EXPECTED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long EXCEPTION_RVA = 0x15C49000L;
    private static final int EXCEPTION_BYTES = 2672880;
    private static final int CHUNK = 2 * 1024 * 1024;
    private static final int OVERLAP = 24;
    private static final int MAX_STORED = 20000;
    private static final int MAX_REPORTED = 75;
    private static final long MAX_CODE_BYTES = 1200L * 1024 * 1024;
    private static final long BULK_EXPORT_BEGIN = 0x807A9FL;
    private static final long BULK_EXPORT_END = 0x80A449L;

    private static class Region {
        long begin, end;
        Region(long b, long e) { begin = b; end = e; }
    }
    private static class Candidate {
        long rva;
        int rank;
        String op;
        String encoding;
        String confidence;
        Region region;
        boolean knownBulk;
        Candidate(long rva, int rank, String op, String encoding) {
            this.rva = rva;
            this.rank = rank;
            this.op = op;
            this.encoding = encoding;
            knownBulk = rva >= BULK_EXPORT_BEGIN && rva < BULK_EXPORT_END;
        }
    }

    private Memory memory;
    private Address base;
    private PrintWriter out;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null || currentProgram.getDefaultPointerSize() != 8) {
            printerr("Open the 64-bit NBA2K26.exe program in Ghidra CodeBrowser.");
            return;
        }
        String hash = currentProgram.getExecutableSHA256();
        if (hash == null || !EXPECTED_SHA.equalsIgnoreCase(hash)) {
            printerr("This research requires Ghidra's matching SHA-256 metadata.");
            printerr("Expected: " + EXPECTED_SHA);
            printerr("Imported: " + hash);
            printerr("No file was changed. Open the known NBA2K26.exe project.");
            return;
        }

        memory = currentProgram.getMemory();
        base = currentProgram.getImageBase();
        File destination = askFile("Save ActionShotId read candidates", "Save");
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(destination), StandardCharsets.UTF_8))) {
            out = writer;
            line("NBA 2K26 - ActionShotId +0x3DC Candidate Readers");
            line("EXACT BUILD SHA-256: " + hash);
            line("Image base: " + addr(base));
            line("READ-ONLY static scan; no game files, process memory, saves, or Ghidra code edits");
            line("A matching displacement is NOT proof of a player-data field read.");
            line("");

            List<Region> regions = loadKnownUnwindTable();
            if (regions.isEmpty()) {
                line("Unable to verify known unwind table; not producing guessed readers.");
                return;
            }
            List<Candidate> matches = scanReadPatterns();
            line("");
            line("=== SCAN RESULTS ===");
            line("Stored candidates: " + matches.size());
            line("Candidate cap: " + MAX_STORED);
            int bulk = 0;
            for (Candidate c : matches) {
                c.region = regionFor(regions, c.rva);
                c.confidence = currentProgram.getListing()
                    .getInstructionAt(base.add(c.rva)) == null ? "no instruction indexed"
                    : "indexed instruction at candidate start";
                if (c.knownBulk) bulk++;
            }
            line("Candidates in previously identified bulk field processing: " + bulk);
            line("Other candidate locations: " + (matches.size() - bulk));

            // Ranking is investigative only, not a score for real photo loading.
            Collections.sort(matches, new Comparator<Candidate>() {
                @Override public int compare(Candidate a, Candidate b) {
                    if (a.knownBulk != b.knownBulk) return a.knownBulk ? 1 : -1;
                    if (a.rank != b.rank) return Integer.compare(b.rank, a.rank);
                    boolean ad = a.confidence.startsWith("indexed");
                    boolean bd = b.confidence.startsWith("indexed");
                    if (ad != bd) return ad ? -1 : 1;
                    return Long.compare(a.rva, b.rva);
                }
            });
            line("");
            line("=== CANDIDATES TO VALIDATE IN GHIDRA ===");
            line("Prefers 16-bit reads outside known export routine, up to 2 per unwind fragment.");
            line("This is NOT a list of safe hook addresses.");
            Map<Long,Integer> grouped = new HashMap<Long,Integer>();
            int shown = 0;
            for (Candidate c : matches) {
                if (shown >= MAX_REPORTED) break;
                long group = c.region == null ? c.rva : c.region.begin;
                int seen = grouped.containsKey(group) ? grouped.get(group) : 0;
                if (seen >= 2) continue;
                grouped.put(group, seen + 1);
                shown++;
                line("");
                line("#" + shown + "  " + c.op + "  @ " + addr(base.add(c.rva)) +
                     " (RVA " + hex(c.rva) + ")");
                line("  Pattern confidence: heuristic only; " + c.confidence);
                line("  x64 instruction encoding (prefix/opcode/ModRM/...): " + c.encoding);
                line("  Known bulk-field-export function: " + c.knownBulk);
                if (c.region == null) {
                    line("  No registered unwind region for this address.");
                } else {
                    line("  PE unwind fragment: [" + addr(base.add(c.region.begin)) +
                         ", " + addr(base.add(c.region.end)) + ") length " +
                         (c.region.end-c.region.begin));
                    line("  NOTE: the unwind fragment may not be a complete C++ function.");
                }
                dumpBytes(c.rva, 24, 40);
            }
            line("");
            line("Reported at most " + MAX_REPORTED + " candidate locations: " + shown);
            line("=== INTERPRETATION ===");
            line("Direct scalar x86 reads from displacement 0x3DC can belong to");
            line("MANY unrelated object types. A candidate is not necessarily");
            line("ActionShotId and does not establish any action-photo UI path.");
            line("First verify instructions, register base/object type, and");
            line("which function invokes the candidate while the MyNBA action");
            line("portrait is requested. Exclude field export/assertion code.");
            line("No dynamic hook, live address, or safe patch is identified.");
            line("Do not inject the current skeleton NBA2K26QoLHook.dll.");
            out.flush();
            if (out.checkError()) printerr("Report may be incomplete; check the destination.");
        }
        println("ActionShotId read candidate report: " + destination.getAbsolutePath());
        println("Upload the text report and we can prioritize genuine read paths.");
    }

    private List<Region> loadKnownUnwindTable() throws Exception {
        line("=== PE UNWIND / FUNCTION FRAGMENTS ===");
        Address table = base.add(EXCEPTION_RVA);
        MemoryBlock b = memory.getBlock(table);
        if (b == null || !b.isInitialized() ||
            !b.contains(table.add(EXCEPTION_BYTES - 1))) {
            line("Expected exception directory not fully mapped in Ghidra.");
            return Collections.emptyList();
        }
        byte[] bytes = new byte[EXCEPTION_BYTES];
        int read = memory.getBytes(table, bytes);
        if (read != EXCEPTION_BYTES) {
            line("Exception directory read returned only " + read + " bytes.");
            return Collections.emptyList();
        }
        List<Region> entries = new ArrayList<Region>();
        for (int i = 0; i + 12 <= bytes.length; i += 12) {
            if ((i & 0xFFFF) == 0) monitor.checkCancelled();
            long begin = word32(bytes,i);
            long end = word32(bytes,i+4);
            long unwind = word32(bytes,i+8);
            if (begin == 0 || end <= begin || end-begin > 0x1000000 ||
                unwind == 0) continue;
            MemoryBlock code = memory.getBlock(base.add(begin));
            if (code == null || !code.isInitialized() || !code.isExecute()) continue;
            entries.add(new Region(begin,end));
        }
        Collections.sort(entries, new Comparator<Region>() {
            @Override public int compare(Region a,Region b) {
                return Long.compare(a.begin,b.begin);
            }
        });
        line("Ghidra block for exception directory: " + b.getName());
        line("Plausible 64-bit unwind function fragments: " + entries.size());
        return entries;
    }

    private long word32(byte[] b, int i) {
        return ((long)b[i] & 255) |
            (((long)b[i+1] & 255)<<8) |
            (((long)b[i+2] & 255)<<16) |
            (((long)b[i+3] & 255)<<24);
    }

    private List<Candidate> scanReadPatterns() throws Exception {
        line("");
        line("=== EXECUTABLE CODE SCAN (no disassembly mutations) ===");
        line("Finds selected ModRM disp32=0x3DC forms reading [base+0x3DC].");
        line("Excluded from matches: 89 /r writes, LEA address-only operations,");
        line("and direct calls/references to static text strings.");
        List<Candidate> matches = new ArrayList<Candidate>();
        long remaining = MAX_CODE_BYTES;
        long scanned = 0;
        boolean reachedCap = false;
        byte[] buffer = new byte[CHUNK + OVERLAP];
        monitor.setMessage("Searching executable bytes for ActionShotId offset reads");
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() || remaining <= 0) continue;
            long size = Math.min(remaining,block.getSize());
            long cursor = 0;
            while (cursor < size) {
                monitor.checkCancelled();
                int requested = (int)Math.min((long)buffer.length,size-cursor);
                int n;
                try {
                    n = memory.getBytes(block.getStart().add(cursor),
                                        buffer,0,requested);
                } catch (Exception ex) {
                    line("WARNING: unable to read code near " +
                         addr(block.getStart().add(cursor)));
                    break;
                }
                if (n <= 0) break;
                boolean last = cursor + n >= size;
                int first = cursor == 0 ? 0 : 8;
                int stop = last ? n-3 : n-16;
                for (int i = first; i < stop; i++) {
                    if ((buffer[i] & 0xff) != 0xDC ||
                        (buffer[i+1] & 0xff) != 0x03 ||
                        buffer[i+2] != 0 || buffer[i+3] != 0) continue;
                    Candidate c = parseCandidate(buffer, i,
                        block.getStart().subtract(base)+cursor);
                    if (c == null) continue;
                    if (matches.size() < MAX_STORED) {
                        matches.add(c);
                    } else {
                        reachedCap = true;
                    }
                }
                long advance = last ? n : n-OVERLAP;
                if (advance <= 0) break;
                cursor += advance;
            }
            scanned += size;
            remaining -= size;
        }
        line("Executable bytes requested for scan: " + scanned);
        line("Total retained candidate encodings: " + matches.size());
        if (reachedCap) line("WARNING: candidate cap reached. Some matches omitted.");
        if (remaining <= 0) line("WARNING: executable byte scan cap reached.");
        return matches;
    }

    private Candidate parseCandidate(byte[] b, int i, long chunkRva) {
        // Decode just the very small, unambiguous family of possible
        // ModRM-memory displacement encodings; not a full instruction decoder.
        int modrmPos = i-1;
        boolean sib = false;
        if (modrmPos < 1) return null;
        int modrm = b[modrmPos] & 255;
        if ((modrm & 0xC0) != 0x80 || (modrm & 7) == 4) {
            if (i < 3) return null;
            modrmPos = i-2;
            modrm = b[modrmPos] & 255;
            if ((modrm & 0xC7) != 0x84) return null;
            sib = true;
        }
        int opPos = modrmPos-1;
        if (opPos < 0) return null;
        int opcode = b[opPos] & 255;
        int rank = 0;
        String kind;
        if (opcode == 0xB7 && opPos > 0 && (b[opPos-1] & 255) == 0x0F) {
            opPos--;
            kind = "MOVZX reg, word ptr [base+0x3DC] (16-bit read)";
            rank = 4;
        } else if (opcode == 0xBF && opPos > 0 &&
                   (b[opPos-1] & 255) == 0x0F) {
            opPos--;
            kind = "MOVSX reg, word ptr [base+0x3DC] (16-bit read)";
            rank = 4;
        } else if (opcode == 0x8B) {
            kind = "MOV reg, [base+0x3DC] (width depends on prefixes)";
            rank = 2;
        } else if (opcode == 0x3B || opcode == 0x39) {
            kind = "CMP involving memory [base+0x3DC]";
            rank = 1;
        } else if (opcode == 0x8A) {
            kind = "MOV reg8, byte ptr [base+0x3DC]";
            rank = 1;
        } else {
            return null; // no writes, LEAs, or unsupported opcodes
        }
        int prefixEnd = opPos;
        boolean wordPrefix = false;
        if (opPos > 0 && ((b[opPos-1] & 255) >= 0x40) &&
            ((b[opPos-1] & 255) <= 0x4f)) opPos--;
        if (opPos > 0 && (b[opPos-1] & 255) == 0x66) {
            wordPrefix = true;
            opPos--;
        }
        if (wordPrefix && opcode == 0x8B) {
            kind = "MOV reg16, word ptr [base+0x3DC] (16-bit read)";
            rank = 4;
        }
        if (opPos > 0 && (b[opPos-1] & 255) >= 0x40 &&
            (b[opPos-1] & 255) <= 0x4f) opPos--;
        int length = i + 4 - opPos;
        if (length > 12 || length < 6) return null;
        StringBuilder bytes = new StringBuilder();
        for (int k = opPos; k < i+4; k++) {
            bytes.append(String.format("%02X ", b[k]&255));
        }
        // The starting byte is a *candidate* start until a real
        // disassembler confirms alignment and the register meaning.
        return new Candidate(chunkRva+opPos,rank,kind,bytes.toString().trim()+
            (sib ? " (SIB addressing)" : ""));
    }

    private Region regionFor(List<Region> list,long rva) {
        int lo=0, hi=list.size()-1, best=-1;
        while (lo <= hi) {
            int mid=(lo+hi)>>>1;
            Region r=list.get(mid);
            if (r.begin <= rva) { best=mid; lo=mid+1; }
            else hi=mid-1;
        }
        if (best < 0) return null;
        // Some x64 functions use chained/overlapping unwind fragments.
        // Prefer the narrowest matching entry among recent preceding entries.
        Region result=null;
        for (int i=best; i>=0 && i>=best-6; i--) {
            Region r=list.get(i);
            if (rva < r.begin || rva >= r.end) continue;
            if (result == null || r.end-r.begin < result.end-result.begin)
                result=r;
        }
        return result;
    }

    private void dumpBytes(long rva,int before,int after) {
        try {
            Address at=base.add(rva);
            if (rva < before) return;
            Address start=at.subtract(before);
            byte[] bytes=new byte[before+after+16];
            int n=memory.getBytes(start,bytes);
            if (n <= 0) return;
            line("  Raw byte context beginning " + addr(start) +
                 " (candidate is at +0x" + Integer.toHexString(before) + "):");
            for(int i=0;i<n;i+=16) {
                StringBuilder b=new StringBuilder();
                b.append("    ").append(addr(start.add(i))).append(" : ");
                for(int j=0;j<16 && i+j<n;j++)
                    b.append(String.format("%02X ",bytes[i+j]&255));
                line(b.toString());
            }
        } catch(Exception ex) {
            line("  Context unavailable: " + ex.getMessage());
        }
    }

    private String addr(Address a) { return "0x"+a.toString(); }
    private String hex(long v) { return String.format("0x%X",v); }
    private void line(String s) { out.println(s); }
}
