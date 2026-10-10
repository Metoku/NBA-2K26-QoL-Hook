# Photo-mode owner check — one bounded Ghidra inspection

## Why this is the next target

We should **not** continue full-executable byte scans or Windows
`ReadFile` / `CreateFile` stack tracing. Those paths yielded either
generic player-data functions or generic file I/O.

Our verified build has adjacent photo-source labels:

- `Photo: Force Real Photo`
- `Photo: Always Render`
- `Photo: Use Assigned Team`

and corresponding style labels `Style: Action Shot` and
`Style: Head Shot`.

Existing Ghidra research (PR #7/#9) found label formatters
`0x1407205A0` and `0x140720620`. They only produce strings
for a display; **do not treat them as portrait selectors**.

Two plausible constructor/table-reference instructions were
observed in the same area:

| Candidate code reference | Reported table start | Related formatter slot |
|---|---|---|
| `0x140742A4A` | `0x143ECC9C0` | `0x143ECCA78` |
| `0x1407429EE` | `0x143ECCA80` | `0x143ECCB38` |

The suspected table starts are 0xC0 apart, and their respective
label functions are at the same relative offset `+0xB8`.
This is suggestive of two sibling C++ objects/types; the owning
classes and UI screens remain unknown. The text labels appear
alongside arena graphics, marquee and logo options, so this
**may be unrelated** to MyNBA player-card portraits.

## One Ghidra screenshot to request

On the imported matching-SHA `NBA2K26.exe`, press **G**
and enter `1407429EE`. In the Listing:

1. If bytes show `??`, select the instruction candidate and
   press **D** once. Do not clear data or change the EXE.
2. Inspect about 12–20 instructions above and below; look for
   an `LEA` whose target is near `0x143ECCA80`, and
   a nearby object register or pointer store.
3. Show the **Decompiler** pane if it resolves a function.
4. Send a screenshot of both panes, including the address.
5. If disassembly conflicts or no function is available,
   show that message rather than manually creating hundreds
   of functions.

We need to identify **which object receives the table pointer**
and whether it is created by arena/scoreboard graphics or a
broader photo widget used in MyNBA. That is a question about
code ownership, not filenames or player field offsets.

## Decision rule

- **MyNBA/photo widget ownership confirmed:** trace callers to
  the actual real-action-photo-versus-render selector.
- **Arena/broadcast graphics only:** stop following this table;
  it does not justify a MyNBA hook. Reassess feasibility rather
  than repeatedly scanning unrelated addresses.
- **Ambiguous:** document exact disassembly and stop; don't
  patch table slots, label formatting values or I/O calls.

The requested mod still requires an actual, verified selection
function. Its C++ DLL remains an inert skeleton. Do not inject,
bypass game protection or edit important MyNBA saves.

## User's Ghidra screenshot — first table reference verified

The user navigated to the proposed reference in the exact imported
build. The Listing directly shows these instructions:

```asm
0x1407429E4  CALL FUN_14334ABD0
0x1407429E9  TEST RAX,RAX
0x1407429EC  JZ LAB_140742A0E
0x1407429EE  LEA RCX,[PTR_LAB_143ECCA80]
```

This confirms the earlier static report's *location of the table
reference*, but it does **not** confirm a MyNBA portrait selector.
The highlighted `LEA` loads a table-related address into RCX;
its meaning depends on subsequent instructions and caller context.
The existing Decompiler pane was stale, showing
`UndefinedFunction_156733454` from the previous generic
`ReadFile` investigation, so do not interpret its pseudocode
as belonging to this code region.

**One next bounded screenshot:** navigate to `0x140742A20`
and show Listing instructions on both sides, ideally including
the region `0x1407429EE` to `0x140742A4A`. This also covers
the second independently observed table reference. Focus on
whether the LEA address gets written into a new object, and
whether there are nearby identifying calls/strings. Do not
guess a function entry or create a patch from this reference.
