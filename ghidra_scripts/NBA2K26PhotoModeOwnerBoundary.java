// NBA2K26PhotoModeOwnerBoundary.java
// @category NBA2K26 Research
// Read-only targeted owner-function lookup for known photo-mode/style
// table initialization instructions. No executable scan or modification.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class NBA2K26PhotoModeOwnerBoundary extends GhidraScript {
    private static final String SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final long EXCEPTION_RVA = 0x15C49000L;
    private static final int EXCEPTION_SIZE = 2672880;
    private static final long[] TARGETS = {0x7429EEL, 0x742A4AL};
    private static final String[] LABELS = {"Photo style object", "Photo mode object"};
    private static final int MAX_XREFS = 16;
    private static class Entry {
        long begin,end,unwind;
        Entry(long a,long b,long c) { begin=a; end=b; unwind=c; }
    }
    private long u32(byte[] b,int i) {
        return ((long)b[i]&255L) | (((long)b[i+1]&255L)<<8) |
            (((long)b[i+2]&255L)<<16) | (((long)b[i+3]&255L)<<24);
    }
    private String h(long n) {return "0x"+Long.toHexString(n).toUpperCase();}
    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            currentProgram.getDefaultPointerSize()!=8 ||
            !SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("Stop: wrong executable or SHA-256 missing/mismatched.");
            return;
        }
        Address base=currentProgram.getImageBase();
        Memory mem=currentProgram.getMemory();
        Address dir=base.add(EXCEPTION_RVA);
        MemoryBlock block=mem.getBlock(dir);
        if (block==null || !block.isInitialized() ||
            !block.contains(dir.add(EXCEPTION_SIZE-1))) {
            printerr("Known PE exception directory unavailable in Ghidra.");
            return;
        }
        byte[] entries=new byte[EXCEPTION_SIZE];
        int read=mem.getBytes(dir,entries);
        if(read!=EXCEPTION_SIZE) {
            printerr("Could not read full PE runtime-function directory.");
            return;
        }
        File destination=askFile("Save photo-mode owner boundary report","Save");
        try (PrintWriter out=new PrintWriter(new OutputStreamWriter(
             new FileOutputStream(destination),StandardCharsets.UTF_8))) {
            out.println("NBA 2K26 photo-mode object owner-function lookup");
            out.println("SHA-256: "+currentProgram.getExecutableSHA256());
            out.println("Image base: "+base);
            out.println("Unwind directory Ghidra block: "+block.getName());
            out.println("Read-only: no executable scan, patch, or project edits.");
            out.println();
            for(int t=0;t<TARGETS.length;t++) {
                monitor.checkCancelled();
                long rva=TARGETS[t];
                Address target=base.add(rva);
                Entry best=null;
                for(int i=0;i+12<=entries.length;i+=12) {
                    long a=u32(entries,i), b=u32(entries,i+4),
                         uw=u32(entries,i+8);
                    if(a==0 || b<=a || b-a>0x1000000 || uw==0 ||
                       rva<a || rva>=b) continue;
                    if(best==null || b-a<best.end-best.begin)
                        best=new Entry(a,b,uw);
                }
                out.println("=== "+LABELS[t]+" ===");
                out.println("Target VA: "+target);
                if(best==null) {
                    out.println("No containing PE unwind fragment: inconclusive.");
                    out.println();
                    continue;
                }
                Address start=base.add(best.begin);
                Address end=base.add(best.end);
                out.println("Function fragment entry: "+start);
                out.println("Function fragment end (exclusive): "+end);
                out.println("Fragment size: "+(best.end-best.begin));
                out.println("Unwind info RVA: "+h(best.unwind));
                Function fn=currentProgram.getFunctionManager().getFunctionAt(start);
                out.println("Existing function at fragment entry: "+
                    (fn==null?"(none)":fn.getName()));
                Function containing=currentProgram.getFunctionManager().getFunctionContaining(target);
                out.println("Existing function containing target: "+
                    (containing==null?"(none)":containing.getName()));
                int count=0;
                for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(start)) {
                    if(count++>=MAX_XREFS)break;
                    out.println("Existing reference to fragment start from "+
                        ref.getFromAddress()+" ("+ref.getReferenceType()+")");
                }
                if(count==0)
                    out.println("No existing references to fragment entry in this partially analyzed project.");
                out.println();
            }
            out.println("Boundary may describe a chained/unwind fragment, not the full logical C++ function.");
            out.println("Do not infer a MyNBA photo selector from constructor registration alone.");
            out.println("Next: inspect disassembly from the matching fragment entry and its real callers.");
            out.flush();
            if(out.checkError()) printerr("Report writing error.");
        }
        println("Saved targeted owner-function report: "+destination.getAbsolutePath());
    }
}
