// NBA2K26ActionShotTeamProbe.java
// @category NBA2K26 Research
// Bounded static investigation of embedded ActionShotTeam and PortraitTeam
// strings, not game changes and not a general byte scan.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class NBA2K26ActionShotTeamProbe extends GhidraScript {
    private static final String EXPECTED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";

    // Known strings from prior read-only scan of this exact game build.
    // Some are duplicates from serialization metadata, not proven UI logic.
    private static final long[] TEXT_RVAS = {
        0x3D63B8FL, 0x3D63BA5L, // PortraitTeam, ActionShotTeam
        0x4C810EBL, 0x4C81101L, // Second pair
        0x4DD5E98L,             // PortraitTeam
        0x50F5260L,             // UTF-16 "PortraitTeam"
        0x50F5303L, 0x50F531BL  // ASCII PortraitTeam pair
    };
    private static final String[] TEXT_LABELS = {
        "PortraitTeam ASCII pair 1", "ActionShotTeam ASCII pair 1",
        "PortraitTeam ASCII pair 2", "ActionShotTeam ASCII pair 2",
        "PortraitTeam ASCII pair 3",
        "PortraitTeam UTF16",
        "PortraitTeam ASCII pair 4a", "PortraitTeam ASCII pair 4b"
    };
    // Prior static scan found two tentative code references to UTF-16
    // PortraitTeam. These are NOT confirmed portrait display calls.
    private static final long[] CODE_RVAS = {0x1F397EEL, 0x2291B81L};
    private static final int CONTEXT_BEFORE = 96;
    private static final int CONTEXT_AFTER = 160;
    private static final int MAX_REFERENCES = 12;

    private Memory mem;
    private Address base;
    private PrintWriter out;

    private String hx(long n) {return "0x"+Long.toHexString(n).toUpperCase();}
    private Address va(long rva) {return base.add(rva);}

    private void dumpBytes(Address address,int count) {
        byte[] buf=new byte[count];
        int n=mem.getBytes(address,buf);
        if(n<=0) {out.println("  Memory unavailable at "+address);return;}
        for(int i=0;i<n;i+=16) {
            StringBuilder line=new StringBuilder();
            line.append("  ").append(address.add(i)).append(":");
            for(int j=i;j<Math.min(i+16,n);j++) {
                line.append(String.format(" %02X",buf[j]&0xFF));
            }
            out.println(line.toString());
        }
    }

    private void dumpReferences(Address address) {
        int count=0;
        for(Reference r:currentProgram.getReferenceManager().getReferencesTo(address)) {
            if(count++>=MAX_REFERENCES) break;
            out.println("  Indexed reference: "+r.getFromAddress()+
                " type="+r.getReferenceType());
        }
        if(count==0) out.println("  No indexed references (partial Ghidra analysis is inconclusive).");
    }

    private void dumpCode(Address around) {
        out.println();
        out.println("=== CODE CONTEXT centered at "+around+" ===");
        Address first=around.subtract(CONTEXT_BEFORE);
        out.println("Raw bytes, bounded "+(CONTEXT_BEFORE+CONTEXT_AFTER)+
            " bytes (not assumed to be instructions):");
        dumpBytes(first,CONTEXT_BEFORE+CONTEXT_AFTER);
        Function containing=currentProgram.getFunctionManager().getFunctionContaining(around);
        out.println("Existing Ghidra containing function: "+
            (containing==null?"(none)":containing.getName()+
                " @ "+containing.getEntryPoint()));
        Instruction ins=currentProgram.getListing().getInstructionContaining(around);
        out.println("Existing indexed instruction at target: "+
            (ins==null?"(none)":ins.getAddress()+" "+ins.toString()));
        out.println("Nearby indexed Listing instructions (no disassembly edits):");
        Address pos=first;
        int count=0;
        while(pos.compareTo(around.add(CONTEXT_AFTER))<0 && count<85) {
            monitorCheck();
            Instruction next=currentProgram.getListing().getInstructionAfter(pos);
            if(next==null || next.getAddress().compareTo(around.add(CONTEXT_AFTER))>=0)break;
            out.println("  "+next.getAddress()+" "+next.toString());
            pos=next.getAddress();
            count++;
        }
        if(count==0)out.println("  (None; raw byte context still supplied.)");
    }
    private void monitorCheck() {
        if(monitor.isCancelled()) throw new RuntimeException("Cancelled");
    }

    @Override
    protected void run() throws Exception {
        if(currentProgram==null || currentProgram.getDefaultPointerSize()!=8 ||
            !EXPECTED_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("Stop: wrong game executable, unknown SHA-256, or not x64.");
            return;
        }
        base=currentProgram.getImageBase();
        mem=currentProgram.getMemory();
        File dest=askFile("Save ActionShotTeam bounded probe","Save");
        try(PrintWriter writer=new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(dest),StandardCharsets.UTF_8))) {
            out=writer;
            out.println("NBA 2K26 ActionShotTeam vs PortraitTeam — static probe");
            out.println("Game SHA-256: "+currentProgram.getExecutableSHA256());
            out.println("Image base: "+base);
            out.println("Read-only; no process attach, game changes, scan or database edits.");
            out.println("Hypothesis: ActionShotTeam could control full-body photo eligibility.");
            out.println("Not verified; strings can be serializer/roster metadata.");
            out.println();
            for(int i=0;i<TEXT_RVAS.length;i++) {
                monitor.checkCancelled();
                Address a=va(TEXT_RVAS[i]);
                out.println("=== "+TEXT_LABELS[i]+" @ "+a+
                            " (RVA "+hx(TEXT_RVAS[i])+") ===");
                if(mem.getBlock(a)==null) {
                    out.println("  String location unmapped; imported layout differs.");
                    continue;
                }
                // 64 bytes each: enough to verify text plus adjacent fields.
                dumpBytes(a,64);
                dumpReferences(a);
            }
            for(long rva:CODE_RVAS) {
                monitor.checkCancelled();
                Address a=va(rva);
                if(mem.getBlock(a)==null) {
                    out.println("Unmapped code candidate "+a);
                } else dumpCode(a);
            }
            out.println();
            out.println("READING THE RESULT:");
            out.println("- String presence alone does not prove a live ActionShotTeam field.");
            out.println("- No code referencing either field means no verified selector yet.");
            out.println("- A field serializer is not a player-photo renderer.");
            out.println("- Never patch from the report. Return it for manual interpretation.");
            out.flush();
            if(out.checkError())printerr("Error while writing report.");
        }
        println("Saved static ActionShotTeam probe: "+dest.getAbsolutePath());
    }
}
