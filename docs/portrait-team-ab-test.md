# Next milestone: Is the portrait fallback gated by the photo's team?

## Why test behavior before writing a hook?

The executable scans found photo field names and likely field-serialization
routines. **None was verified as the live UI image-selection routine**.

A public NBA 2K26 user report says real photographs can be replaced by
in-game rendered faces after a team rebrand, and another discussion reports
that team changes can produce real photo/action-shot fallbacks. These are
community observations, not evidence of the game's actual implementation:
- https://www.reddit.com/r/NBA2k/comments/1u701pa/why_did_shai_turn_generated/
- https://forums.operationsports.com/forums/forum/basketball/nba-2k-basketball/26882570-players-like-kevin-durant-landry-shamet-et-al

The earlier DB2K snapshots for Joel Embiid showed:

- `HEADSHOTID`, `PORTRAITID` and `FACEID` unchanged (4090).
- `CURRENTTEAM` / `CONTRACTTEAM` changing after a trade.
- `PORTRAITTEAM1` and `PORTRAITTEAM2` remaining on his original team.

This correlation does **not** prove that one of these fields is the fallback
gate, that a photo exists for the new team, or that changing them helps.

## Experiment A — read-only in-game confirmation

Using *a disposable offline MyNBA save* with an unchanged stock team design:

1. Start from a player whose official real portrait displays normally, e.g.
   Embiid on the 76ers. Record which screen shows the real headshot and
   which shows the real action photograph (these can use different paths).
2. Trade that same player to an unmodified NBA franchise (e.g. Lakers).
   Reopen the same exact screens. Record whether headshot/action photo
   each remain real or become rendered.
3. If possible in that throwaway save, reverse the move; reopen both
   screens and record whether the original photos return.
4. Record the player, source team, destination, whether either team
   was rebranded, exact UI screen, and the result after navigating away
   and back. A screenshot pair is sufficient.

No DB2K writes, patch, mod installation, debugger, or injection is required.

## Experiment B — isolate the roster portrait-team fields (OPTIONAL)

Only if the user is comfortable with a **separate backed-up throwaway MyNBA
save** and DB2K explicitly shows the relevant fields as editable for
their NBA 2K26 version. DB2K reads/writes live game memory, and applying
one field may change game state immediately. Do not test in the primary
franchise; never assume that a field is writable merely because it appears.

1. Backup or export the **entire** throwaway save, not only a roster
   snapshot, and disconnect from online play.
2. Reproduce the post-trade rendered-photo fallback in the disposable save.
   Record a DB2K snapshot of `HEADSHOTID`, `PORTRAITID`, `PHOTOID`,
   `ACTIONSHOTID` (if exposed), `FACEID`, `CURRENTTEAM`,
   `CONTRACTTEAM`, `PORTRAITTEAM1` and `PORTRAITTEAM2`.
3. Only if there is an explicit writable control for a relevant
   `PORTRAITTEAM` field, try **one** field at a time on the throwaway
   save, using the destination team's *actual editor value* seen in
   the current team field. Do not invent numeric team IDs.
4. Reopen the same UI screen, record results, revert that single
   experiment, and reverify baseline before testing another field.
5. Avoid manipulating other player fields or using bulk snapshot-apply
   workflows; those may write unrelated values.

A restored real photo after a specific field change would be valuable
evidence that the field participates in the decision (directly or
indirectly), but still not proof of the exact code path. No change is
inconclusive: it could be ignored, need a UI reload, correspond to a
different portrait type, or refer to a photo asset absent for that
team. A crash, corrupted save, or unexpected change means **stop**,
restore backup and do not repeat.

## Next engineering step once the behavior is isolated

Identify the actual **read** path that consumes these fields during an
image-resource request for MyNBA UI. This requires real functions/data
flow, not string-adjacent setters and assertion messages. A candidate
must be verified under two controlled player/team conditions before a
strictly offline, build-specific, fail-closed, opt-in hook is considered.

**Never install the current NBA2K26QoLHook.dll:** it is a build skeleton
without a portrait hook. No patch offset is validated.
