# Automatic action-portrait override: implementation state (2026-10-10)

## Feature contract

When a player has an assigned **real-life full-body action photograph**
and that resource can be loaded, the proposed offline QoL Hook should
**prefer the assigned original action photo** whether or not the player
was traded. It may show the player's earlier-team jersey.

If no assigned action portrait exists, or an asset is missing, preserve
the game's existing cyberface fallback. If asset availability cannot be
verified, leave the game's original behavior unchanged.

Do **not** modify per-player rosters or saves, action-photo IDs,
headshots, team assignments, or game assets. The behavior must
be opt-in, validated for the fingerprinted executable, and restricted
to authorized offline use.

## What is implemented in this PR

A small, **game-independent policy**, not an engine hook:

- `include/PortraitPolicy.h` defines abstract photo availability and
  decision types.
- `src/PortraitPolicy.cpp` implements a fail-closed rule:
  an assigned AND confirmed-available action photograph results in
  `PreferAssignedRealActionPhoto`. Every other case returns
  `KeepGameDefault`.
- `tests/portrait_policy_test.cpp` checks all six combinations of
  assignment presence and available/unknown/missing asset state.
- CMake adds the policy source to the existing DLL and registers the
  test in CTest alongside the DLL smoke test.

The policy intentionally has no current-team input. That means a
team transfer, by itself, cannot disable a photo **in our abstract
decision rule**. But it is **not yet connected to NBA 2K26**:
the actual game chooses how images are rendered.

The test was run locally using GCC 14.2 on Linux as a standalone
C++17 policy test. The full Windows DLL/CI build is not confirmed
by that local run; GitHub Actions must validate it.

## What external research establishes (and does not)

- Users confirm real action images disappearing on trade/rebrand:
  https://forums.operationsports.com/forums/forum/basketball/nba-2k-basketball/26882570-players-like-kevin-durant-landry-shamet-et-al
  https://www.reddit.com/r/NBA2k/comments/1u701pa/why_did_shai_turn_generated/
- An **NBA 2K26** portrait modder explicitly says their body
  portrait mod's photos can be *force-enabled through a roster tool*
  after a drafted player joins a team:
  https://ko-fi.com/s/854bca1be8
  This is good evidence that real-photo appearance can be
  influenced through roster/player data, **not** a documented
  no-roster-write MyNBA function or reusable game hook.
- A 30-team photo mod uses mod-file replacements and a supporting
  roster, not the desired automatic runtime behavior:
  https://ko-fi.com/s/0d0a1ffefa
- The public DB2K Editor 2K26 data model identifies
  `CURRENTTEAM` at player offset `+0x60`,
  `PORTRAITTEAM1` at `+0xD0`, and
  `PORTRAITTEAM2` at `+0xD8`. These are **metadata
  definitions** and do not prove a photo-selection check:
  https://raw.githubusercontent.com/discobisco/2k26-Editor/main/2keditor/core/Offsets/offsets_players.json

Previous Ghidra investigations located the `ActionShotId`
field and confirmed photo-mode label registration, but did
**not** identify the MyNBA action-photo selector. Generic
Windows I/O, roster data accessors, photo-configuration
registries and unverified team-offset candidate routines
are **not safe hook targets**.

## Release gate / remaining tasks

1. **BLOCKED:** identify and prove the game-version-specific
   MyNBA photo-versus-cyberface decision, preferably using
   a documented existing tool or authoritative modder insight.
2. **BLOCKED:** establish safe, read-only identification of
   assigned photo/asset availability at that point in code.
3. Connect verified engine inputs to `ChooseActionPortrait`
   in an optional game-integration adapter and preserve all
   non-photo UI paths.
4. Test against backed-up offline MyNBA scenarios: original
   team, traded team, free agent/new signing, no real asset,
   headshot unchanged, and new game build fails closed.
5. Release a working DLL **only** after verification on
   the exact approved game build.

**Important: this PR does not fix the game.** The existing
DLL is still an inert skeleton and should not be installed or
injected. It now contains a unit-tested policy definition
that can be reused once a legitimate, verified engine
integration point is discovered.
