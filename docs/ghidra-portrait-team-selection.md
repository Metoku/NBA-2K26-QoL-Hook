# Portrait-team selection: narrow Ghidra investigation

## Working behavior, not yet a verified branch

In offline MyNBA, players can display their assigned real-life **full-body
action photograph** on a photo-associated/original team, but display an
in-game **cyberface render** after a transfer. Regular headshots survive.

Our desired mod **prefers the existing assigned real action photograph
regardless of a later trade**, provided an eligible asset exists. If no
image is available, keep the game's normal fallback. The player should
not require manually editing their roster or swapping portrait assets.

**Important:** team-associated appearance is user-observed behavior,
not a proven implementation. The game may compare team IDs, check
portrait asset eligibility, apply presentation rules, or combine them.

## Verified information to use

Public DB2K Editor field definitions for NBA 2K26 encode:
- `CURRENTTEAM` -> player object offset `+0x60`, `uint64` team reference
- `PORTRAITTEAM1` -> offset `+0xD0`, `uint64` team reference
- `PORTRAITTEAM2` -> offset `+0xD8`, `uint64` team reference

Source: https://raw.githubusercontent.com/discobisco/2k26-Editor/main/2keditor/core/Offsets/offsets_players.json

The published file has other IDs and editor-specific fields; do
not assume its layout is authoritative for other game builds.

Previously confirmed in Ghidra, `ActionShotId` has a 16-bit field at
`+0x3DC` on a compatible player-data object. The getter, setters,
and bulk exporter were examined and are **not** action-image loaders.

Existing debug labels like `Photo: Force Real Photo`,
`Photo: Always Render`, and `Photo: Use Assigned Team` are inside a
presentation-related area alongside logos, marquee team graphics,
and player-starter selectors. Those formatting functions are **not
proven related to offline MyNBA player cards**. Do not patch them.

## What the new script does

`ghidra_scripts/NBA2K26PortraitTeamSelectionCandidates.java`:
- Verifies **exact executable SHA-256** and uses the Ghidra PE
  exception runtime-function table we already successfully parsed.
- Searches executable mapped code for select x64 memory operands
  that reference offsets `+0x60`, `+0xD0`, and `+0xD8`.
- Groups candidate accesses by registered unwind function fragment,
  prioritizing regions mentioning **multiple relevant offsets**, with
  possible memory comparisons.
- Deprioritizes previously identified bulk attribute processing.
- Saves at most 35 ranked code regions in a report; each includes
  sample assembly bytes and VAs.

**Limits:** it reads the large game's initialized executable memory,
so a run may take several minutes. It does **not** automatically
disassemble, decompile, patch EXE files, modify saves, access any
running game process, or add data definitions to your Ghidra project.
These raw-byte matches can occur inside unrelated structs or even
within encoded/non-code bytes. Same fragment / same register number
doesn't prove same object, and the PE unwind fragment can be a part
of a function. No candidate is a safe hook site yet.

## Single-run procedure

1. Download [NBA2K26PortraitTeamSelectionCandidates.java](../ghidra_scripts/NBA2K26PortraitTeamSelectionCandidates.java)
   using **Download raw file** on the GitHub page.
2. Put it inside the same existing
   `%USERPROFILE%\ghidra_scripts` folder as earlier Java scripts.
3. Open the already imported `NBA2K26.exe` in Ghidra CodeBrowser;
   no new import or full auto-analysis is needed.
4. **Window → Script Manager**, then **Refresh**.
5. Run `NBA2K26PortraitTeamSelectionCandidates`, save its report on
   Desktop as `portrait-team-selection.txt`, and upload that
   text report here.
6. If Ghidra reports a Java compile/runtime error, send the exact
   message instead. The script has not yet been tested inside the
   user's installed Ghidra version.

## Decision rule for the next engineering task

- If a convincing function reads the portrait-team and current-team
  fields, inspect **only that function** next and trace data flow.
- If none is found or candidates all belong to bulk field processing,
  stop offset scanners. Pivot to action-portrait resource selection
  through the UI/presentation path instead of guessing a patch.
- Only a verified, build-specific, offline-safe decision point
  authorizes implementing and testing an opt-in hook.
- Keep the current `NBA2K26QoLHook.dll` skeleton **uninstalled**.

This document records an investigation, **not a working fix**.
