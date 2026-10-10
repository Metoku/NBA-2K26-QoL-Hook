# Hook-only requirement and remaining portrait-selection evidence

Status 2026-10-10. **This is an investigation plan, not a functional mod.**

## User-confirmed requirement

The feature must be a runtime **DLL hook for offline MyNBA**,
not a roster editor, roster-manipulation macro, or save-file patch.

- Keep the original **full-body, real-life action photo** after a
  player's team changes, even when the photo shows the old jersey.
- Preserve the normal game-selected fallback if an action photo
  does not exist. Do not force images for created/generated players.
- Do not change `CURRENTTEAM`, `CONTRACTTEAM`,
  `PORTRAITTEAM1`, `PORTRAITTEAM2`, `ActionShotId`,
  `PORTRAITID` or `HEADSHOTID` in memory or saves.
- Do not change normal headshot behavior, unrelated broadcasts,
  clothing, roster data or game files.
- Restrict any future implementation to the exact verified Steam
  executable SHA-256 and offline operation. No anti-cheat bypass.
- The `PORTRAITTEAM1` editor control was **uneditable** for the
  user's player, so previous suggestions to edit it are not
  actionable or desired.

## Known evidence

- Embiid's action-photo ID and portrait IDs remained unchanged
  through roster moves; game UI switched the full-body real
  photograph to the generated render according to team.
- The player record can hold `ActionShotId` at object offset
  `+0x3DC`, from previous disassembly. The generic accessors
  and setters we identified are not the renderer.
- Nearby built-in photo-mode label formatters indicate the enums
  `Force Real Photo`, `Always Render`, and `Use Assigned Team`,
  and style labels `Action Shot` and `Head Shot`. Their
  configuration-table initialization and callback dispatcher
  have been traced, but **not linked to MyNBA**. Never patch
  the label formatters or generic dispatch.
- ProcMon observed I/O for one `mods/player_images/chr_r*_a1.iff`
  override, but its `ReadFile` return site is generic I/O.
  It is not evidence of the action-photo fallback branch.
- `ChooseActionPortrait` in the DLL is isolated policy logic
  with six passing tests, **not** a game hook.

## One meaningful way forward

An analyst with the game running in an **authorized offline,
debugging-permitted environment** must observe the **runtime
call path at the moment a known player action portrait is drawn**.
A hardware **read** watchpoint on that player's actual
`ActionShotId` member (if the object address can be confirmed)
is a focused approach: record the instruction pointer, call stack,
and whether the handler differs between normal photo display
and cyberface fallback. This is a **hypothesis**: the renderer may
use a cached copy or an ID retrieved elsewhere, in which case
the watchpoint won't hit. That negative result is useful and
should not prompt arbitrary writes.

Do not use a breakpoint on `ReadFile`, scan the entire
1.1 GB executable, or inject the unfinished DLL. Do not try
this in online modes or with anti-cheat enforcement present.

Before authoring a live patch, evidence must establish:
1. The exact **image-selection function or condition** with
   calling convention and a byte/signature match in the
   studied Steam executable.
2. A verified **action-photo asset availability** check at
   that decision point, so missing photos retain fallback.
3. A hook that intercepts only this choice without saving
   or mutating player/team fields, with preservation of the
   original behavior and safe opt-out.
4. In-game tests of original team, post-trade player,
   free agent/signing, unavailable image, generated player,
   unchanged headshots, and a version mismatch.

**Release gate:** Do not describe the current DLL as fixing
NBA 2K26 until an actual in-game A/B test confirms it.

## 2026-10-10: Avoid duplicate ProcMon test

The user already completed ProcMon investigation, including
a SUCCESS `ReadFile` for a loose portrait-mod IFF and a
game-side generic OS-I/O return address. That result did
not link to the MyNBA action-photo-vs-cyberface selector.

**Do not request another ProcMon capture**, another
`ReadFile` breakpoint, the x64dbg attach procedure, edits
to `PORTRAITTEAM1`, or more ungrounded neighboring setter
functions. Those avenues have already been attempted and
were either non-diagnostic or caused game crashes.

External comparison: Looyh's closed-source NBA 2K21 Hook
v0.0.5 included a real feature called "Force display photos",
documented separately from its patched file loader and
roster features:
https://www.2kspecialist.net/2020/10/nba2k21-hook-v005-by-looyh-added-force.html
This confirms historical engine precedent but supplies
**no NBA 2K26 code location, compatibility or exposed API**.
The older hook DLL has no validated or available source
in this investigation.

**Next new evidence worth seeking**: documented source,
function signature or reverse-engineering notes from an
existing photo-forcing hook, then a *specific, static*
comparison with 2K26; alternately a genuine MyNBA
consumer/eligibility branch identified independently of
generic label, setter, serializer, and I/O code. Avoid
requesting a new user-side task until we have such a lead.
