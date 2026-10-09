# Portrait Reference Probe (read-only Windows EXE)

This is an **investigation tool only**, not a working NBA 2K26 hook.

## Why it exists

A local analysis of the exact NBA 2K26 Steam x64 executable found text labels:

- Photo: Force Real Photo
- Photo: Always Render
- Photo: Use Assigned Team
- Style: Action Shot
- Style: Head Shot

The surrounding terms relate to arenas, marquees and team starter overlays. We
do **not** know whether those modes apply to MyNBA player portraits. The next
step is to locate code **possibly** referring to these strings, so a proper
disassembler can inspect the relevant functions.

## No Python or developer tools required

1. Open the repository's **Actions → Windows x64 Build** workflow.
2. Open a successful run for a commit containing this probe.
3. Download the **NBA2K26PortraitXrefProbe-windows-x64** artifact ZIP.
4. Extract the ZIP to a writable folder (for example, Desktop).
5. Double-click **NBA2K26PortraitXrefProbe.exe**.
6. In the file chooser, select your installed Steam **NBA2K26.exe**.
7. Wait for the completion message. The game executable is more than 1 GB and
   the scan can take time; Windows may temporarily show "Not responding."
8. Upload the generated **NBA2K26-portrait-reference-report.txt** from the
   same folder as the downloaded probe.

Only download the analyzer EXE, **not** the existing QoL Hook DLL: it does not
implement the portrait fix yet.

## What the tool actually does

- Opens the selected game executable **read-only** and uses a read-only file
  mapping. It never launches, attaches to, or modifies NBA 2K26.
- Parses the PE sections and locates selected ASCII and UTF-16LE photo-mode
  strings in data sections. Reports both *file offsets* and PE *RVAs*.
- Searches for possible absolute pointers to strings in data sections.
- Scans executable sections for a limited x64 RIP-relative instruction byte
  pattern (LEA/MOV): candidate code references to strings or pointer slots.
- Writes a **local text report**. No internet calls or automatic upload.
- Does not write to the game directory or edit saves.

## Extra code context in the report

Each tentative code reference now includes a **small, read-only hex window**
from its containing executable PE section (up to 64 bytes before and 167
bytes including/after the candidate). Every window reports its starting
FILE offset and RVA, plus the candidate's position within the window.

This means a reviewer can use a disassembler on the small excerpt to
examine nearby register, call and branch instructions without requesting
the full proprietary game executable. The window is not guaranteed to begin
at a valid x64 instruction boundary; any apparent disassembly must be
validated against actual surrounding control flow.

Use the same portable EXE workflow as above. The updated artifact will
produce an expanded text report, and the earlier report remains valid
evidence for the original candidates.

## Important limits

The scanner is **not a disassembler** and does not validate instruction
boundaries or indirect multi-level references. Candidates can be false
positives, and absence of candidates is inconclusive. It cannot prove where
or whether MyNBA portraits are selected, identify a safe hook, or fix any
portrait or Home/Away shoe behavior by itself.

All eventual in-game changes must be version-gated and tested offline using
backed-up disposable saves. No anti-cheat bypass or online modding.
