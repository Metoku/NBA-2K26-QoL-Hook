# Action-shot function-boundary investigation — verified user report

## Game build

- Imported image: `NBA2K26.exe`, image base `0x140000000`.
- Ghidra-reported executable SHA-256 matched
  `efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`.
- A corrected Ghidra script parsed the Windows PE32+ exception directory
  at RVA `0x15C49000` (2,672,880 bytes), mapped inside Ghidra block
  `.tls`; this block *name* is a Ghidra import detail, not proof
  the code belongs to Thread Local Storage.
- It found 222,740 plausible runtime-function records in this region.
  Successful runtime-function parsing does not guarantee correct
  high-level decompilation of all target routines.

## Function fragments identified

| Known reference | Registered unwind fragment | Length |
| --- | --- | ---: |
| `ActionShotId` near `0x14080869B` | `0x140807A9F`–`0x14080A449` | 10,666 |
| `PhotoId` near `0x1408085CC` | same fragment as `ActionShotId` | 10,666 |
| `GetActionShotId()` diagnostic near `0x141F0147A` | `0x141F013D0`–`0x141F0149F` | 207 |
| `SetActionShotId` diagnostic near `0x14C704C5C` | `0x14C704C00`–`0x14C704CD6` | 214 |

The long function calls many generic field helpers (including
`FUN_1408F1290`, `FUN_1408F12F0`, `FUN_1408F1330`, and
`FUN_140917DD0`). Its proximity to *both* action-shot and headshot
field names and its many repeated attribute-helper calls support
interpreting it as a bulk player-data processing/export routine.
It is **not proven to be a MyNBA image loader or serializer**.

## New verifiable player-data fact: ActionShotId at +0x3DC

Both small decompiled functions write a 16-bit value:

`*(ushort *)(param_1 + 0x3dc) = uVar2;`

The subsequent branch compares the assigned value to the input and
prepares strings such as `GetActionShotId()` /
`PLAYERDATA::SetActionShotId` and the
`ActionShotId over/underflow` diagnostic. This supports that a
`ushort` field at **player-data offset `0x3DC`** is used as the
`ActionShotId` storage location in this game build.

The two short functions at `0x141F013D0` and `0x14C704C00`
share the same body apart from diagnostic string pointers.
The diagnostic name `GetActionShotId()` does not mean the
first function is an accessor/getter; the decompiled body
clearly **writes** the value.

## What is NOT known

- Which function **reads** `ActionShotId` to request a real
  action-photograph asset.
- Whether action-photo availability is gated by `ActionShotTeam`,
  `CURRENTTEAM`, separate player-data state, or resource metadata.
- Which fallback/UI function renders the player when the
  photographed action shot is considered missing/ineligible.
- Whether a player-team mismatch is the cause or merely correlates
  with the loss after a trade.

There is **no safe patch or verified hook site**. The current
`NBA2K26QoLHook.dll` is a skeleton with no action-photo fix.

## Actual next milestone

**Stop string scanning and decompiling setter/assertion helpers.**

The next useful research operation is to identify an authentic
consumer (read-path) of the 16-bit value at `+0x3DC` during a
MyNBA action-portrait request. Then trace that consumer toward
resource selection or fallback. Candidate readers need
instruction-boundary validation, real function analysis and a
controlled *offline* example, not just a byte-match to a structure
offset.

As an alternative, investigate an action-shot asset request by
profiling resource/asset name references in Ghidra. Both approaches
must keep online features and anti-cheat out of scope and avoid
modifying the EXE or production saves.

Research document only. No live game changes were made by
the Ghidra script.
