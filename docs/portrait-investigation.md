# MyNBA portrait investigation (NBA 2K26 Steam)

**Status:** Research only; no working portrait override has been identified.

## Question

When an existing player changes teams in MyNBA and switches from an official
photo/action portrait to a 3D render, did the portrait data change, or did the
game's display-selection logic change?

These cases require different solutions. `HeadshotID` and `PortraitID` are
documented by Looyh's 2K26 Roster CLI as separate player fields, but their
exact role inside an active MyNBA save has **not** been validated for this project.

## Offline, repeatable test

1. Back up your existing MyNBA saves. Work with a disposable MyNBA save.
2. Record the game version/build displayed locally and any installed mods.
3. Pick one player who has both a visible photo portrait and an action portrait.
4. Before trading, capture both UI screenshots and note the team and exact screens.
5. If a compatible tool can **export a JSON snapshot of the active MyNBA player records**,
   save that read-only export as `before.json`. Confirm the export actually contains
   the player and the fields being investigated. An export from Roster Creator
   instead of MyNBA may not describe the same records.
6. Trade the player, open the *same screens*, and capture the resulting portraits.
7. Export `after.json` from that same active MyNBA context if supported.
8. Compare both files locally:

   ```powershell
   python tools/compare_snapshots.py before.json after.json
   python tools/compare_snapshots.py before.json after.json --all
   ```

The comparator **does not connect to the game**. It reads two JSON files and
shows changed paths. Lists with a unique player identifier are matched by that
identifier, not list position. Otherwise, lists are compared by index.

## Interpretation

- Portrait ID changes: test whether the ID itself governs the image shown.
- Same portrait ID, changed team: suggests (but **does not prove**) the display
  decision is dependent on team assignment or another value.
- No portrait field in the export: **inconclusive**. The snapshot may omit it.
- More than one field changes: isolate each candidate before concluding causality.

Record results in an issue without posting complete save files or unnecessary
personal data. Capture field names and results, not guesses at addresses.

## References

- Looyh NBA 2K26 Roster CLI (HeadshotID and PortraitID documentation):
  https://ko-fi.com/s/9c10f087e2
- DB2K Editor (open-source player snapshots, target support varies):
  https://github.com/discobisco/2k26-Editor

## Out of scope

This investigation does not patch game memory, inject a DLL, bypass anti-cheat,
or prove that any third-party editor can export those fields from MyNBA.
Do not use experimental tools in online modes. 
