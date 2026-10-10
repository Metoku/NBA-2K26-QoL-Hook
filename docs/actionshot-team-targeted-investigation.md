# Targeted ActionShotTeam investigation (read-only)

## Why this is worth **one bounded check**

The earlier SHA-matched static string report for NBA2K26.exe
(SHA-256 `efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`)
found two pairs of ASCII strings:

- `PortraitTeam` at RVA `0x3D63B8F`, followed by
  `ActionShotTeam` at RVA `0x3D63BA5`.
- `PortraitTeam` at RVA `0x4C810EB`, followed by
  `ActionShotTeam` at RVA `0x4C81101`.

`ActionShotTeam` is a plausible **full-body action-photo**
team association distinct from normal portrait team
metadata. A public 2019 NBA 2K roster-editing schema listed
`PortraitTeam TEAMDATA` and `ActionShotTeam TEAMDATA`
as separate concepts:
https://www.nba-live.com/forums/viewtopic.php?t=108089

However, the public **2K26** DB2K Editor metadata only
defines editable `PORTRAITTEAM1`/`PORTRAITTEAM2`;
it does **not** provide a verified `ActionShotTeam` offset
or confirm that the legacy name remains functional:
https://raw.githubusercontent.com/discobisco/2k26-Editor/main/2keditor/core/Offsets/offsets_players.json

**This is a hypothesis, not a discovered hook.**
The embedded names may only appear in saved/serialized
player-data metadata rather than executed MyNBA photo
selection logic. No new game patch or roster edit is
justified by string presence.

## One-click non-crashing Ghidra check

1. Download
   [`NBA2K26ActionShotTeamProbe.java`](../ghidra_scripts/NBA2K26ActionShotTeamProbe.java)
   from this branch (**Raw** → Save As or Download raw file).
2. Put the Java file in your existing
   `%USERPROFILE%\ghidra_scripts` folder.
3. Open your existing NBA2K26 Ghidra project; go to
   **Window → Script Manager → Refresh**, then run
   `NBA2K26ActionShotTeamProbe`.
4. Save the output as `actionshot-team-probe.txt` and
   upload the small text report to our conversation.
5. If Ghidra reports a Java compile error, paste the
   exact error instead of changing the executable.

The tool verifies the exact SHA-256; reads eight **known
strings** (64 bytes each); inspects existing indexed
references to those strings; and exports a bounded
256-byte context from each of the two previously found
code references to the wide `PortraitTeam` name
(`0x1401F397EE` and `0x1402291B81`).
It performs **no 1.1 GB scan**, no process attachment,
no injection, no disassembly modifications, and no
game or save changes.

## Decision rule

- **Strong field/layout evidence:** look for existing
  `ActionShotTeam` offsets and targeted consumers, not
  broad player-data accessors.
- **String serialization only:** close this lead promptly
  rather than infer a runtime portrait selector.
- **Actual UI choice function found:** only then design
  an opt-in, SHA-gated, offline-only hook with correct
  calling convention and missing-photo fallback.

Until the actual decision is verified and in-game tested,
the DLL is **not a working portrait mod**.
