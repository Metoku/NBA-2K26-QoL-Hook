// NBA2K26ImportedDLLsReport.java
// @category NBA2K26 Research
// Static inspection of imported external library names in the verified NBA2K26.exe.
// Does not load DLLs, launch game, bypass protections, patch bytes or modify Ghidra.
import ghidra.app.script.GhidraScript;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class NBA2K26ImportedDLLsReport extends GhidraScript {
    private static final String VERIFIED_SHA =
        "efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39";
    private static final Set<String> KNOWN_PROXY_NAMES = new HashSet<>(Arrays.asList(
        "d3d9.dll", "d3d10.dll", "d3d11.dll", "d3d12.dll", "dxgi.dll",
        "dinput8.dll", "dsound.dll", "version.dll", "wininet.dll",
        "winmm.dll", "winhttp.dll", "binkw64.dll", "xinput1_3.dll",
        "xinput1_4.dll", "xinput9_1_0.dll", "xinputuap.dll"
    ));
    @Override
    protected void run() throws Exception {
        if (currentProgram == null ||
            currentProgram.getDefaultPointerSize() != 8 ||
            !VERIFIED_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            printerr("Stop: use the previously verified NBA2K26.exe x64 build.");
            return;
        }
        println("=== NBA2K26 READ-ONLY IMPORTED LIBRARY REPORT ===");
        println("Note: Ghidra external libraries may include manually added symbols.");
        String[] libraries = currentProgram.getExternalManager().getExternalLibraryNames();
        Arrays.sort(libraries, String.CASE_INSENSITIVE_ORDER);
        int matched = 0;
        for (String lib : libraries) {
            monitor.checkCancelled();
            String norm = lib.toLowerCase(Locale.ROOT);
            if (lib.equalsIgnoreCase("unknown")) continue;
            boolean candidate = KNOWN_PROXY_NAMES.contains(norm);
            if (candidate) matched++;
            println((candidate ? "[POSSIBLE ASI-PROXY NAME] " : "[EXTERNAL] ") + lib);
        }
        println("Names matching known x64 ASI proxy choices: " + matched);
        println("A library name is NOT proof of a successful load, compatibility, or safety.");
        println("NBA 2K PC uses Easy Anti-Cheat; no code-loading tests are authorized by this static report.");
        println("No files, executable instructions, protections or runtime processes were modified.");
        println("=== REPORT COMPLETE ===");
    }
}
