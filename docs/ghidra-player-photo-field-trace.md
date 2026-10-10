# Next investigation: NBA 2K26 player-photo field data flow

The previous Ghidra project investigated `Photo: Force Real Photo`,
`Photo: Always Render`, and `Photo: Use Assigned Team` in code that
**formats UI labels**. It found two related, likely C++ function tables, but
**no confirmed MyNBA player-photo selection function**.

This next investigation starts from the player-data fields associated with
the actual disappearance of Embiid's original player portrait after a trade.

## Run once in your existing Ghidra installation

1. Open [NBA2K26PlayerPhotoFieldTrace.java](../ghidra_scripts/NBA2K26PlayerPhotoFieldTrace.java)
   on GitHub and select **Download raw file**.
2. Put the `NBA2K26PlayerPhotoFieldTrace.java` file in the same
   `ghidra_scripts` folder where you successfully ran the previous Java
   script. Keep its `.java` extension.
3. In Ghidra, open the same `NBA2K26.exe` program inside the CodeBrowser.
4. Select **Window → Script Manager**, refresh, and run the script named
   **NBA2K26PlayerPhotoFieldTrace**.
5. Choose an output file on Desktop, for example
   `NBA2K26-player-photo-fields.txt`.
6. Wait for the read-only scan. The input EXE contains more than 1 GB
   of mapped executable data, so this can take a while. You may cancel via
   Ghidra's task monitor.
7. Upload **only the small text report** for review. No PowerShell commands,
   Python installation, or manual screenshots are required.

## What is investigated

Known player-data names and diagnostic strings:

- `PLAYERDATA::SetPhotoId`
- `PLAYERDATA::SetActionShotId`
- `GetPhotoId()` and `GetActionShotId()`
- `PhotoId` and `ActionShotId`
- `PortraitTeam` and `ActionShotTeam`
- Related ID range-error messages and `PlayerPortrait`

The script searches case-sensitive ASCII/UTF-16LE names in initialized,
non-executable data sections. It records possible statically stored pointers
to those names, checks existing Ghidra reference indexes, and makes a
bounded, heuristic search for simple RIP-relative LEA/MOV references in
executable sections. Each candidate gets a **small hex context** that can
be disassembled later.

It writes only one user-selected report file. It does **not** patch the
game executable, inject the QoL DLL, read game-process memory, edit any
roster/save, create decompiled functions, or run full auto-analysis.
The script checks Ghidra's imported SHA-256 metadata against the exact
build previously fingerprinted (when that metadata is available).

## Limitations / what will make this useful

- Matches to field names can belong to serialization, debugging,
  assertions or editor metadata. A `SetPhotoId` reference is not proof of
  where game UI selects the actual photograph.
- Even if a code reference is found, the script does not prove it is a
  valid instruction boundary or a safe hook location.
- A missing reference does not establish that the image loader is absent:
  optimized code may access fields by numeric offsets without naming them.
- Scans have caps to control the time and report size; they may miss matches.
- The important next milestone is identifying a **validated image request
  function** that uses player IDs and team context when displaying MyNBA
  player cards, followed by read-only reproduction and safe offline tests.
- If these field-name references only lead to metadata, the next step is
  real debugger-assisted offline inspection or focused Ghidra
  disassembly—not yet another unproductive string scanner.

**Do not use the current NBA2K26QoLHook.dll**: it is still a skeleton and
does not implement a working portrait fix. Backup all MyNBA saves before
any future gameplay-affecting experiment.
