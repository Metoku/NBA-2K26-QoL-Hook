# MyNBA portrait investigation (NBA 2K26 Steam)

**Status:** Research only. No working portrait override or shoe fix has been validated.

## Specific 2K26 field leads

DB2K Editor's publicly available 2K26 player metadata contains:

| Domain | Field names | Question |
| --- | --- | --- |
| Players / Vitals | `HEADSHOTID`, `PORTRAITID` | Do the actual portrait identifiers change after a trade? |
| Players / Vitals | `PORTRAITTEAM1`, `PORTRAITTEAM2` | Does the portrait's team association differ from `CURRENTTEAM`? |
| Players / Vitals | `CURRENTTEAM` | Does this change as expected in a MyNBA trade? |
| Players / Gear | `SHOEHOME`, `SHOEAWAY` | Does editing Home shoes write to the Away value? |
| Players / Gear | `SHOEHOMECOLORWAY`, `SHOEAWAYCOLORWAY` | Are colorway fields changed separately? |

These field names and layouts come from the third-party editor's *authored metadata*. They
are **not validated runtime offsets for our game build**, nor proof that changing a
field will fix the game's behavior. The player's `PORTRAITTEAM1/2` fields are
especially useful hypotheses to test, **not confirmed portrait-selection rules**.

## Read-only test with DB2K Editor

Requires a backed-up disposable MyNBA save, NBA 2K26 Steam on Windows, and
a third-party editor compatible with your game build. DB2K Editor requires
Python 3.11, PyQt6, and psutil; follow its [README](https://github.com/discobisco/2k26-Editor#requirements).

1. Launch NBA 2K26 in **offline MyNBA**, load the disposable save, and locate one
   player whose normal headshot and action photo are visible.
2. Open DB2K Editor, verify its target is **NBA 2K26** on the Dashboard, and use
   **Attach + Load All** (or Attach followed by a Players load/scan).
3. Open **Players**, locate the selected player, and note their record `index`.
4. Find **Player Roster Snapshot**, set Mode to **Selected Players**, specify
   the filename **before.json**, and click **Export Snapshot**.
   Do **not** click **Apply Snapshot**.
5. Open the exported JSON and verify that `domain` is `Players`, that the
   `records` array contains your intended player, and that its `fields` map
   contains at least some of the relevant field names from the table.
   If they are absent, a roster snapshot cannot answer that part of our question.
6. Take screenshots of the same portrait and action portrait UI screens.
7. Trade that one player in the disposable MyNBA save, then open the **same**
   screens and take screenshots again.
8. Refresh/re-attach the editor's **Players** data if required to see current
   values. Export the same player to **after.json** using **Export Snapshot**,
   not Apply. Confirm the `index` and `label` match the intended player.
9. Put `before.json` and `after.json` somewhere local (they are not needed
   on GitHub) and run:

   ```powershell
   python tools/compare_snapshots.py before.json after.json --record-index 123
   python tools/compare_snapshots.py before.json after.json --record-index 123 --all
   ```

   Replace `123` with the record's actual `index` from the JSON. The focused
   report includes **unchanged** portrait IDs and portrait-team fields as well
   as the differences, so you can distinguish missing fields from stable values.

If the editor's **Selected Players** export does not contain the intended record,
try **Full Loaded Roster** and use the same index for each export. If the editor
cannot export the active MyNBA records, stop: exporting from a different
roster mode is not equivalent.

The comparator is a local, read-only Python script. It does not access game
memory, inject a DLL, modify save files, or apply roster changes.

## How to interpret results

- `HEADSHOTID` / `PORTRAITID` **unchanged** and official photos replaced with
  3D renders: compatible with a display-selection fallback, but not proof of it.
- `PORTRAITTEAM1/2` **unchanged**, `CURRENTTEAM` changed: a team-portrait
  mismatch is a plausible cause. More testing is needed to establish causality.
- Portrait fields **changed**: investigate what changed and whether it is safe
  and sufficient to restore the intended IDs.
- Portrait fields **not exported**: inconclusive. The editor's snapshot code
  excludes some read-only or unsupported fields.
- Player `index` changed unexpectedly: verify the player's identity instead
  of relying only on the index; the comparison is inconclusive otherwise.

## Home/Away shoe regression (separate experiment)

In a backed-up disposable MyNBA save, capture `SHOEHOME`,
`SHOEAWAY`, and the colorway fields before editing. Attempt to assign a
*different* Home shoe through Edit Player. Export again and compare the same
player. If `SHOEAWAY` changes while `SHOEHOME` stays fixed, that confirms
the wrong field changes in the recorded player data, not necessarily why.

## References

- [Looyh 2K26 Roster CLI](https://ko-fi.com/s/9c10f087e2)
- [DB2K Editor source](https://github.com/discobisco/2k26-Editor)
- [DB2K 2K26 player field metadata](https://github.com/discobisco/2k26-Editor/blob/main/2keditor/core/Offsets/offsets_players.json)
- [DB2K export implementation](https://github.com/discobisco/2k26-Editor/blob/main/2keditor/models/data_model.py)

## Safety and limitations

Never test against online gameplay. Do not disable security controls as part
of this diagnostic. Make backups. These tests do not confirm any runtime hook
or fix, and data snapshots may include roster content not suitable for public upload.
Share relevant field names/values and portrait screenshots only.
