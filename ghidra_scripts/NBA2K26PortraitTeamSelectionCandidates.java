// NBA2K26PortraitTeamSelectionCandidates.java
// @category NBA2K26 Research
// Read-only heuristic search for nearby accesses to NBA 2K26's
// player CURRENTTEAM (+0x60), PORTRAITTEAM1 (+0xD0), PORTRAITTEAM2 (+0xD8).
// Does not attach to NBA2K26.exe, alter saves, patch executable bytes,
// or create/disassemble code in the Ghidra project.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;

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

public class NBA2K26PortraitTeamSelectionCandidates extends GhidraScript {

    private static final String EXPECTED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long UNWIND_RVA = 0x15C49000L;
    private static final int UNWIND_BYTES = 2672880;
    private static final long MAX_SCAN = 1200L * 1024L * 1024L;
    private static final int CHUNK_SIZE = 4 * 1024 * 1024;
    private static final int OVERLAP = 16;
    private static final int MAX_GROUPS = 60000;
    private static final int MAX_ROWS = 35;

    private static final String[] FIELDS = {
        "CURRENTTEAM +0x60", "PORTRAITTEAM1 +0xD0", "PORTRAITTEAM2 +0xD8"
    };

    private static class Region {
        long start, end;
        Region(long start, long end) { this.start=start; this.end=end; }
    }

    private static class Hit {
        long rva;
        int field;
        int baseRegister;
        String operation, bytes;
        boolean indexed;
        Hit(long rva,int field,int baseRegister,String operation,
            String bytes,boolean indexed) {
            this.rva=rva;
            this.field=field;
            this.baseRegister=baseRegister;
            this.operation=operation;
            this.bytes=bytes;
            this.indexed=indexed;
        }
    }

    private static class Group {
        Region region;
        int mask=0;
        int[] count=new int[3];
        int[] baseMasks=new int[3];
        List<Hit> samples=new ArrayList<Hit>();
        int comparisonCount=0, readCount=0, indexedCount=0;
        long first=Long.MAX_VALUE,last=0;
        int score=0;
        Group(Region region) { this.region=region; }
        void add(Hit h) {
            mask|=1<<h.field;
            count[h.field]++;
            baseMasks[h.field]|=1<<h.baseRegister;
            if (h.operation.startsWith("CMP")) comparisonCount++;
            if (h.operation.startsWith("MOV")) readCount++;
            if (h.indexed) indexedCount++;
            if (first>h.rva) first=h.rva;
            if (last<h.rva) last=h.rva;
            if (samples.size()<15) samples.add(h);
        }
        int distinct() { return Integer.bitCount(mask); }
        void rank() {
            score=distinct()*10;
            if ((mask&6)==6) score+=10;
            if (distinct()==3) score+=20;
            if ((baseMasks[1]&baseMasks[2])!=0) score+=7;
            if ((baseMasks[0]&baseMasks[1]&baseMasks[2])!=0) score+=10;
            if (comparisonCount>0) score+=5;
            if (readCount>0) score+=3;
            if (indexedCount>0) score+=2;
            if (last-first<=512) score+=7;
            if (region.end-region.start>20000) score-=4;
            // Previously identified bulk player-field code:
            if ((region.start>=0x807A9FL && region.start<0x80A449L) ||
                (region.start>=0x1E3B490L && region.start<0x1E5848CL))
                score-=25;
        }
    }

    private Address base;
    private Memory mem;
    private PrintWriter out;
    private int hits=0;
    private int unmapped=0;
    private boolean capped=false;

    @Override
    protected void run() throws Exception {
        if (currentProgram==null || currentProgram.getDefaultPointerSize()!=8) {
            printerr("Open the 64-bit NBA2K26.exe in Ghidra CodeBrowser.");
            return;
        }
        String hash=currentProgram.getExecutableSHA256();
        if (hash==null || !EXPECTED_SHA.equalsIgnoreCase(hash)) {
            printerr("The imported game SHA-256 does not match the verified build.");
            printerr("Expected: "+EXPECTED_SHA);
            printerr("Observed: "+hash);
            return;
        }

        base=currentProgram.getImageBase();
        mem=currentProgram.getMemory();
        File file=askFile("Save portrait-team candidate report", "Save");
        try (PrintWriter writer=new PrintWriter(new OutputStreamWriter(
            new FileOutputStream(file),StandardCharsets.UTF_8))) {
            out=writer;
            line("NBA 2K26 - Photo-Team Selection Candidate Report");
            line("SHA-256: "+hash);
            line("Image base: "+addr(base));
            line("Method: read-only x64-memory-operand heuristic + verified PE unwind regions");
            line("This script does not change your Ghidra project or running game.");
            line("");
            line("OFFSET BASIS: public DB2K Editor player field definitions for 2K26");
            line("  CURRENTTEAM:    0x60 (64-bit reference)");
            line("  PORTRAITTEAM1: 0xD0 (64-bit reference)");
            line("  PORTRAITTEAM2: 0xD8 (64-bit reference)");
            line("Those are editor-defined structure offsets, not proven image-loader parameters.");
            line("The scan recognizes MOV, CMP, LEA x64 operands and does not fully decode every instruction.");
            line("A candidate can belong to unrelated game objects.");
            line("");

            List<Region> regions=loadUnwind();
            if (regions.isEmpty()) {
                line("No verified unwind entries. Stopping without guessed code candidates.");
                return;
            }

            Map<Long,Group> groups=search(regions);
            List<Group> ranked=new ArrayList<Group>();
            for (Group g:groups.values()) {
                if (g.distinct()<2) continue;
                g.rank();
                ranked.add(g);
            }
            Collections.sort(ranked,new Comparator<Group>() {
                @Override public int compare(Group a,Group b) {
                    int s=Integer.compare(b.score,a.score);
                    return s!=0?s:Long.compare(a.region.start,b.region.start);
                }
            });

            line("");
            line("=== SUMMARY ===");
            line("Recognized candidate operand encodings inside unwind fragments: "+hits);
            line("Potential encodings without containing unwind fragment: "+unmapped);
            line("Unique unwind fragments containing >=1 recognized access: "+groups.size());
            line("Fragments with >=2 different watched team fields: "+ranked.size());
            if (capped) line("WARNING: group cap reached; results incomplete.");
            line("Highest-ranked candidates are NOT validated MyNBA photo selectors.");
            line("");
            line("=== TOP FUNCTION FRAGMENTS (maximum "+MAX_ROWS+") ===");
            int row=0;
            for (Group g:ranked) {
                if (row>=MAX_ROWS) break;
                row++;
                Address entry=base.add(g.region.start);
                Function fn=currentProgram.getFunctionManager().getFunctionAt(entry);
                line("");
                line("#"+row+" SCORE "+g.score+"  fragment ["+addr(entry)+", "+
                     addr(base.add(g.region.end))+")");
                line("  Fragment length: "+(g.region.end-g.region.start)+" bytes");
                line("  Existing Ghidra function at start: "+
                     (fn==null?"(none)":fn.getName()));
                line("  Counts: "+FIELDS[0]+"="+g.count[0]+", "+
                     FIELDS[1]+"="+g.count[1]+", "+FIELDS[2]+"="+g.count[2]);
                line("  Compare ops: "+g.comparisonCount+
                     ", MOV reads: "+g.readCount+
                     ", already indexed instructions: "+g.indexedCount);
                line("  Operand span: "+(g.last-g.first)+" bytes");
                line("  Shared base-register ID across portrait team slots: "+
                     ((g.baseMasks[1]&g.baseMasks[2])!=0));
                line("  Shared base register ID across all 3 slots: "+
                     ((g.baseMasks[0]&g.baseMasks[1]&g.baseMasks[2])!=0));
                line("  Base register sharing within a fragment does not establish the same object.");
                line("  Sample instruction encodings (unaligned matches may be false positives):");
                Collections.sort(g.samples,new Comparator<Hit>() {
                    @Override public int compare(Hit a,Hit b) {
                        return Long.compare(a.rva,b.rva);
                    }
                });
                for (Hit h:g.samples) {
                    line("    "+addr(base.add(h.rva))+"  "+h.operation+
                         "  "+FIELDS[h.field]+"  baseReg="+h.baseRegister+
                         "  "+h.bytes+(h.indexed?" [already disassembled]":""));
                }
            }
            line("");
            if (ranked.isEmpty()) {
                line("No promising shared-team-field fragments found in these opcode families.");
                line("This is inconclusive: the game may copy fields through accessors,");
                line("compare team IDs rather than pointers, or use unsupported encodings.");
            } else {
                line("NEXT: Review top 1-3 regions in Ghidra to confirm instruction");
                line("alignment, player-object base register, data flow into a photo");
                line("selection decision and a call made from MyNBA player UI.");
            }
            line("Do not patch any of these offsets or inject the skeleton DLL.");
            out.flush();
            if (out.checkError()) printerr("Report writing failed or incomplete.");
        }
        println("Portrait-team selection candidate report saved: "+file.getAbsolutePath());
        println("Upload the text report; no screenshot or EXE needed.");
    }

    private List<Region> loadUnwind() throws Exception {
        line("=== UNWIND TABLE ===");
        Address addr=base.add(UNWIND_RVA);
        MemoryBlock block=mem.getBlock(addr);
        if (block==null || !block.isInitialized() ||
            !block.contains(addr.add(UNWIND_BYTES-1))) {
            line("Known PE exception directory is not mapped as initialized memory.");
            return Collections.emptyList();
        }
        byte[] bytes=new byte[UNWIND_BYTES];
        int n=mem.getBytes(addr,bytes);
        if (n!=UNWIND_BYTES) {
            line("Incomplete PE exception directory read: "+n);
            return Collections.emptyList();
        }
        List<Region> regions=new ArrayList<Region>();
        for (int i=0;i+12<=bytes.length;i+=12) {
            if ((i&0xFFFF)==0) monitor.checkCancelled();
            long start=u32(bytes,i),end=u32(bytes,i+4),
                 unwind=u32(bytes,i+8);
            if (start==0 || end<=start || end-start>0x1000000 ||
                unwind==0) continue;
            MemoryBlock code=mem.getBlock(base.add(start));
            if (code==null || !code.isExecute() || !code.isInitialized())
                continue;
            regions.add(new Region(start,end));
        }
        Collections.sort(regions,new Comparator<Region>() {
            @Override public int compare(Region a,Region b) {
                return Long.compare(a.start,b.start);
            }
        });
        line("Ghidra table block name: "+block.getName());
        line("Plausible unwind fragments: "+regions.size());
        return regions;
    }

    private Map<Long,Group> search(List<Region> regions) throws Exception {
        line("");
        line("=== SCAN PROGRESS ===");
        Map<Long,Group> groups=new HashMap<Long,Group>();
        byte[] bytes=new byte[CHUNK_SIZE+OVERLAP];
        long remaining=MAX_SCAN, scanned=0;
        for (MemoryBlock block:mem.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized() || remaining<=0)
                continue;
            long span=Math.min(remaining,block.getSize());
            long pos=0;
            while(pos<span) {
                monitor.checkCancelled();
                int request=(int)Math.min((long)bytes.length,span-pos);
                int n;
                try {
                    n=mem.getBytes(block.getStart().add(pos),
                                   bytes,0,request);
                } catch(Exception ex) {
                    line("WARNING: unreadable bytes near "+
                         addr(block.getStart().add(pos)));
                    break;
                }
                if (n<=0) break;
                boolean last=pos+n>=span;
                int limit=last?n-9:n-OVERLAP;
                for(int i=0;i<=limit;i++) {
                    int rex=bytes[i]&0xFF;
                    if ((rex&0xF8)!=0x48) continue; // REX.W
                    int op=bytes[i+1]&0xFF;
                    if (op!=0x8B && op!=0x39 && op!=0x3B && op!=0x8D)
                        continue;
                    int modrm=bytes[i+2]&0xFF;
                    int mod=(modrm>>6)&3;
                    if(mod!=1 && mod!=2) continue;
                    int rm=modrm&7, dispAt=i+3,reg=rm+((rex&1)!=0?8:0);
                    if(rm==4) { // ModRM SIB addressing
                        int sib=bytes[dispAt]&0xFF;
                        reg=(sib&7)+((rex&1)!=0?8:0);
                        dispAt++;
                    }
                    long disp;
                    if(mod==1) {
                        disp=bytes[dispAt]; // sign-extended disp8
                    } else {
                        disp=(int)u32(bytes,dispAt); // signed disp32
                    }
                    int field=disp==0x60?0:disp==0xD0?1:
                              disp==0xD8?2:-1;
                    if(field<0)continue;
                    long rva=block.getStart().add(pos+i).subtract(base);
                    Region region=owning(regions,rva);
                    if(region==null) { unmapped++;continue; }
                    hits++;
                    Group group=groups.get(region.start);
                    if(group==null) {
                        if(groups.size()>=MAX_GROUPS) {
                            capped=true;
                            continue;
                        }
                        group=new Group(region);
                        groups.put(region.start,group);
                    }
                    String name=op==0x8B?"MOV memory read":
                         (op==0x39 || op==0x3B)?"CMP memory read":
                         "LEA address only";
                    StringBuilder opcodeBytes=new StringBuilder();
                    int instLen=dispAt-i+(mod==1?1:4);
                    for(int x=i;x<i+instLen;x++)
                        opcodeBytes.append(String.format("%02X ",bytes[x]&255));
                    boolean indexed=currentProgram.getListing()
                         .getInstructionAt(base.add(rva))!=null;
                    group.add(new Hit(rva,field,reg,name,
                        opcodeBytes.toString().trim(),indexed));
                }
                long advance=last?n:n-OVERLAP;
                if(advance<=0)break;
                pos+=advance;
                scanned+=advance;
            }
            remaining-=span;
        }
        line("Initialized executable bytes processed: "+scanned);
        if(remaining<=0) line("WARNING: capped scan at "+MAX_SCAN+" bytes.");
        return groups;
    }

    private Region owning(List<Region> sorted,long rva) {
        int lo=0,hi=sorted.size()-1,idx=-1;
        while(lo<=hi) {
            int m=(lo+hi)>>>1;
            if(sorted.get(m).start<=rva) { idx=m;lo=m+1; }
            else hi=m-1;
        }
        if(idx<0)return null;
        Region best=null;
        for(int i=idx;i>=0 && i>=idx-6;i--) {
            Region r=sorted.get(i);
            if(rva<r.start || rva>=r.end)continue;
            if(best==null || r.end-r.start<best.end-best.start)best=r;
        }
        return best;
    }

    private long u32(byte[] b,int i) {
        return ((long)b[i]&255L) |
            (((long)b[i+1]&255L)<<8) |
            (((long)b[i+2]&255L)<<16) |
            (((long)b[i+3]&255L)<<24);
    }
    private String addr(Address a) {return "0x"+a.toString();}
    private void line(String s) {out.println(s);}
}
