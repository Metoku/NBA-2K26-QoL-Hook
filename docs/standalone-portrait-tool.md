# NBA 2K26 Portrait Tool — file-only diagnostic

**Important safety change (2026-10-11):** The first external memory
inspector caused the user's running NBA 2K26 instance to crash. It
used OpenProcess, CreateToolhelp32Snapshot, and ReadProcessMemory,
which were read-only API calls but may still have conflicted with
the game. The exact root cause is **not established**.

**Do not run any prior build of NBA2K26PortraitTool.exe.**
The tool has been rewritten as a **FILE-ONLY inspector**: it contains
NO code for locating or opening game processes or reading process memory.
The game **must be fully CLOSED** before use.

## What it does

1. Accepts the original NBA2K26.exe path on the command line (drag-and-drop
   also supplies the path).
2. Opens only that **on-disk file** for reading, without modifying it.
3. Confirms the exact previously verified size and SHA-256.
4. Parses the file's original 64-bit PE section headers and translates
   the four known Ghidra branch RVAs to on-disk file offsets.
5. Checks the four original short-jump instruction pairs and prints results.

It **does not** attach to the game, open a running process, inspect
live game memory, inject DLLs, add hooks, change bytes, or change
portrait behavior. It cannot fix the portrait-after-trade issue yet.

The expected file SHA-256 for this one game build is:

    efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39

Any different build fails closed. It may take time to hash ~1.1 GB.

## Restoring the clean installation

Before trying *anything* else, remove only the DLL proxy and ASI plugin
files personally added during our previous tests from the game's
installation directory, leaving the original game, legitimate mods
and Windows System32 files alone.

Launch NBA 2K26 **without any diagnostic tools running**. If it still
crashes, stop and check Windows Reliability Monitor (\`perfmon /rel\`)
for the faulting module and exception code; we should resolve that
before continuing.

## Using the new offline file inspector (only if wanted)

1. **Close NBA 2K26 completely**, including any launcher attempt still
   running. Do not run the inspector simultaneously with the game.
2. Open the latest **successful** Windows x64 Build workflow from this
   PR's research branch. Download the artifact named
   \`NBA2K26PortraitTool-file-only-x64\`.
3. Extract the included \`NBA2K26PortraitTool.exe\` somewhere outside
   the game's installation folder. Only use the artifact built from
   the 2026-10-11 file-only rewrite or newer.
4. Open Steam → NBA 2K26 → Manage → Browse local files, and locate
   the installed \`NBA2K26.exe\`. Do NOT move or modify that file.
5. For a quick self-test, open PowerShell in the tool folder:

       .\NBA2K26PortraitTool.exe --self-test

6. For the file-only report, run, replacing the path as appropriate:

       .\NBA2K26PortraitTool.exe "D:\SteamLibrary\steamapps\common\NBA 2K26\NBA2K26.exe"

   Or drag the game's EXE icon onto the tool's EXE icon. The game
   should remain closed throughout the test.
7. Report the tool's Console results. The expected PASS on four
   branches means only that our original Ghidra bytes were rechecked
   from disk. It does **not** mean we have a working portrait fix.

Running with no path deliberately exits immediately with usage
instructions; it will NEVER search for a running NBA 2K26 instance.

## Crash evidence if the clean game is affected

Use Win+R → \`perfmon /rel\` → select the NBA 2K26 crash →
\`View technical details\` → note **faulting module**, **exception
code**, and **time** (no full memory dump necessary).
If the game works once all diagnostic components are removed,
the original crash probably involved the live-inspection environment,
but those details alone do not identify a specific protection.

**Don't attempt more live memory tools or DLL proxy experiments until
we have a separately validated, game-compatible approach.**
