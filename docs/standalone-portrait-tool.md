# Standalone NBA 2K26 portrait tool (read-only first milestone)

**Status:** Experimental external diagnostic, NOT a portrait fix.

This tool is a normal Windows x64 console EXE. It is not a DLL or ASI,
does not use the mods folder, does not install any proxy DLL, and does not
modify the game or its executable.

## What it does

1. Locates a running process named NBA2K26.exe (Windows Toolhelp API).
2. Opens it with only PROCESS_QUERY_LIMITED_INFORMATION and PROCESS_VM_READ.
3. Reads the game's installed executable and checks the entire file against
   our previously Ghidra-verified exact SHA-256 and size.
4. Finds the loaded executable base through a read-only module snapshot.
5. Reads **two bytes at each of four** known portrait selector branches.
6. Prints PASS or STOP for each branch, then exits.

Its known build currently has SHA-256:

    efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39

Game updates cause a fail-closed result. These addresses are offsets from the
loaded module base, not absolute addresses; they are deliberately **not**
used for patching.

The tool **does not** verify photo assets, force portraits, write any game
memory, inject code, alter saves, attach a debugger, or interact with EAC.
It cannot repair the photo-after-trade problem yet.

## How to run

1. Remove the failed ASI loader from earlier tests:
   only the added game-folder \`version.dll\` or \`dinput8.dll\`, and
   \`scripts/NBA2K26PortraitProbe.asi\`. Do not remove any Windows
   system DLLs or existing legitimate game files. The normal game
   should start without these experimental files.
2. Back up your offline MyNBA save.
3. From GitHub PR #13, use the latest **successful** "Windows x64 Build"
   action. Download its \`NBA2K26QoLHook-windows-x64\` artifact ZIP.
4. Extract **NBA2K26PortraitTool.exe** into any convenient folder,
   e.g. Downloads\\NBA2K26PortraitTool. Do not put it in the game's
   installation directory or mods folder.
5. Open NBA 2K26 via Steam's **built-in offline without EAC** launch choice.
   If that launch option is unavailable, stop here.
6. Open a PowerShell terminal in the extracted tool folder and run:

       .\NBA2K26PortraitTool.exe

7. Copy the printed output. "PASS: 4/4" only demonstrates our branch
   signature matches the running build; it does **not** mean portraits
   will work after trades.

The tool may take some time to fingerprint the >1 GB executable.
Access denied, missing game process, unknown build, and unexpected
branch bytes are handled as STOP cases without changes.

Optional quick checks **without launching the game**:

    .\NBA2K26PortraitTool.exe --self-test
    .\NBA2K26PortraitTool.exe --help

A successful read-only test will guide a separately reviewed,
opt-in implementation of a portrait override that preserves
missing-photo fallback behavior. Until then do not attempt to
convert the two team-match JZ instructions to JMP: such patches
would also bypass some null-team-reference safeguards.
