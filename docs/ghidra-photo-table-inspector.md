# One-run Ghidra Photo Table Inspector (no Python needed)

**Purpose:** identify which C++ classes own two likely function-pointer
tables in the exact Windows x64 NBA 2K26 build. This does not fix player
portraits, edit the game, load the QoL DLL, or use a debugger.

## Before starting

- Install/open Ghidra and import `NBA2K26.exe` as a 64-bit Windows PE.
- Open it in **CodeBrowser**. No full auto-analysis is necessary.
- The script is a **Java GhidraScript**; Ghidra runs and compiles it using
  the Java installation you already used to launch Ghidra.
- The script reads Ghidra's imported file SHA-256 metadata (when available)
  and refuses to proceed if it differs from the studied build:
  `efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`.

## Setup — no code editing

1. Download the file
   [NBA2K26PortraitTableInspector.java](../ghidra_scripts/NBA2K26PortraitTableInspector.java)
   from the repository: open it on GitHub and choose **Download raw file**.
   Keep the `.java` extension.
2. In Windows File Explorer, enter `%USERPROFILE%\ghidra_scripts` in the
   address bar. If the folder does not exist, create it.
3. Copy **NBA2K26PortraitTableInspector.java** into that folder.
4. In **Ghidra CodeBrowser** (with `NBA2K26.exe` open), choose
   **Window → Script Manager**.
5. Click **Refresh Script List**, search for `NBA2K26PortraitTableInspector`,
   and double-click it (or select it and click the green Run icon).
6. Choose a writable file location (e.g. Desktop) and save the report as
   `NBA2K26-ghidra-table-report.txt`.
7. Wait for the scan to finish. The report is plain text; upload it to the
   chat for interpretation.

If you cannot find the script, use Script Manager's **Script Directories /
Bundle Manager** to add the directory holding the Java file and refresh.
There is no need to paste source code into PowerShell.

## Follow-up after the first successful report

The first run successfully verified the user's SHA-256 and discovered two
plausible `LEA` references:

- `0x140742A4A` -> first candidate table start `0x143ECC9C0`
- `0x1407429EE` -> second candidate table start `0x143ECCA80`

The corresponding photo-mode and photo-style function pointers occupy the
same `+0xB8` slot relative to these candidate starts (table index 23).
This matching layout strengthens the hypothesis that these are two related
C++ dispatch tables, but the owning class and portrait behavior remain
**unknown**. No valid MSVC RTTI was found on that run.

An updated version of the **same** script now validates these specific
`LEA` targets and includes bounded raw code excerpts around the two
references. It **skips the previous 768 MiB-wide code scan** because those
reference locations have already been established.

To use it, simply download the updated Java file and **replace** the
existing copy in your `ghidra_scripts` folder. Refresh Ghidra Script
Manager, run it again, and send the new text report.

We do not need screenshots of pointer bytes, a full automatic analysis, or
the executable itself. This next pass is about **where the table starts are
used**, not about applying an unverified portrait patch.

## What the script examines

- Photo mode formatter slot at RVA `0x3ECCA78` (currently points to
  function RVA `0x7205A0`).
- Photo style formatter slot at RVA `0x3ECCB38` (points to
  function RVA `0x720620`).
- Valid-looking Microsoft C++ x64 RTTI **Complete Object Locators** in
  the preceding 16 KiB. When present, extracts the decorated C++ type name
  and likely vftable start.
- Lists neighboring pointers, distinguishing executable and data targets.
- Reports already-known Ghidra references; these can be incomplete if
  automatic analysis is disabled.
- The initial version performed a **capped read-only code scan** to find
  candidate references. The latest version skips repeating the expensive
  scan and validates the two previously observed LEA references directly,
  capturing a small code window around each.
- The byte excerpts are not disassembled or proven to be complete functions;
  they remain investigative evidence rather than patchable targets.
- Writes the report to the user-selected path **only**.

**Important:** a class owning these tables may control arena presentation
labels rather than MyNBA portrait loading. Even a perfect RTTI match is not
a working portrait hook. The script does not change symbols, decompile all
of the 1.1 GB file, inject DLLs, edit saves, or alter game files.

## Troubleshooting

- **Script not found:** make sure its extension is `.java` rather than
  `.java.txt`, and click Refresh in Script Manager.
- **Compilation error:** copy the full error text from Ghidra's Console.
  The code has not yet been executed on your own Ghidra installation,
  so version-specific API fixes may be needed.
- **Wrong SHA-256:** stop. Re-run the repository's read-only fingerprint
  tool to verify which game executable was imported.
- **No RTTI name or no code references:** inconclusive, not proof of
  unused code. A proper disassembly of the owning object constructor
  may still be required.
- **Slow scan:** the EXE is large; Ghidra may take time to read its
  executable sections. You can cancel the task using Ghidra's Cancel control.

Next research milestone: determine whether the recovered type names or
constructor references correspond to arena/presentation graphics or MyNBA
player-photo selection. Never patch the suspected formatter addresses.
