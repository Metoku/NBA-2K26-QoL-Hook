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

## Second screenshot: dispatch-table pointer is stored in object

The user provided the Listing around `0x1407429EE` through
`0x140742A3C`, with these directly visible instructions:

```asm
0x1407429E4  CALL FUN_14334ABD0
0x1407429E9  TEST RAX,RAX
0x1407429EC  JZ LAB_140742A0E
0x1407429EE  LEA RCX,[PTR_LAB_143ECCA80]
0x1407429F5  MOV qword ptr [RAX+0x8],RAX
0x1407429F9  MOV qword ptr [RAX],RCX
0x1407429FC  MOV qword ptr [RAX+0x10],RAX
0x140742A00  MOV qword ptr [RAX+0x18],RSI
0x140742A04  MOV qword ptr [RAX+0x20],RSI
0x140742A08  MOV qword ptr [RAX+0x28],RSI
0x140742A0C  JMP LAB_140742A11
0x140742A0E  MOV RAX,RSI
0x140742A11  LEA R8,[RDI+0x30]
0x140742A15  MOV RDX,RAX
0x140742A18  MOV RCX,RDI
0x140742A1B  CALL FUN_14071A8E0
```

**Interpretation:** The candidate table start
`0x143ECCA80` is indeed assigned to an object
(`[RAX]`) that is passed to a downstream helper. This is
evidence for initialization/construction of a table-backed
object rather than merely a stray label reference. The
identity of the object, whether it serves MyNBA player cards,
and whether it implements photo vs rendered cyberface choice
remain **unverified**. The neighboring `FUN_14071A8E0` is
not automatically a portrait loader.

**Next bounded inspection:** Ghidra go to
`0x140742A4A` and show several instructions above and below
to verify the corresponding photo-mode table
`0x143ECC9C0` assignment. If analogous construction is
confirmed, inspect only one owning caller to distinguish
arena/presentation settings from MyNBA player UI; do not
change any table slots or patch the executable.

## Third screenshot: both object constructions confirmed

A new Listing screenshot verifies the sibling configuration object:

```asm
0x140742A4A  LEA RCX,[DAT_143ECC9C0]
0x140742A51  MOV qword ptr [RAX+0x8],RAX
0x140742A55  MOV qword ptr [RAX],RCX
0x140742A58  MOV qword ptr [RAX+0x10],RAX
0x140742A5C  MOV qword ptr [RAX+0x18],RSI
0x140742A60  MOV qword ptr [RAX+0x20],RSI
0x140742A64  MOV qword ptr [RAX+0x28],RSI
0x140742A6D  LEA R8,[RDI+0x30]
0x140742A71  MOV RDX,RAX
0x140742A74  MOV RCX,RDI
0x140742A77  CALL FUN_14071A8E0
```

Both previously suspected related tables `0x143ECCA80`
(photo style) and `0x143ECC9C0` (photo mode) are indeed used
as the first pointer within sibling initialized objects, followed
by a common helper call `FUN_14071A8E0` that likely
registers/attaches the objects. This is **constructor/registration
evidence**, not photo render-selection evidence.

The Decompiler remained on an unrelated function in this screenshot
because the enclosing function is not properly analyzed yet.

### Next bounded step: function entry, not another scan

Use the new Ghidra Java script
[`NBA2K26PhotoModeOwnerBoundary.java`](../ghidra_scripts/NBA2K26PhotoModeOwnerBoundary.java)
to read only the known 2.67 MB PE exception unwind directory and
report the containing fragment start/end of
`0x1407429EE` and `0x140742A4A`. The script does not
disassemble, patch or create Ghidra functions. It verifies the
imported SHA-256 first.

This makes the next manual screenshot precise: we can navigate to
the **actual function fragment entry**, view the enclosing code,
and investigate the parent context for arena/presentation settings
versus a MyNBA portrait widget. If it is presentation-only,
**stop following these table objects**.

**Procedure:** download the Java file, put it in the existing
`%USERPROFILE%\ghidra_scripts` directory, refresh Ghidra
Script Manager, run
`NBA2K26PhotoModeOwnerBoundary`, save
`photo-mode-owner-boundary.txt`, and upload the resulting
text report. Script compatibility with the user's Ghidra
installation has not yet been validated; send the compile
error verbatim if encountered. This is one quick 2.67 MB
table read, not another huge executable scan.

## User's boundary report: both settings share entry `0x140742880`

The SHA-256-gated `NBA2K26PhotoModeOwnerBoundary.java` script
completed successfully. Its targeted read of the PE exception
directory (`.tls` block in this Ghidra import) established:

| Target | Unwind fragment begin | Fragment end (exclusive) |
| --- | --- | --- |
| Photo style constructor reference `0x1407429EE` | `0x140742880` | `0x140742B43` |
| Photo mode constructor reference `0x140742A4A` | `0x140742880` | `0x140742B43` |

The 707-byte region has a previously identified Ghidra
function symbol `FUN_140742880` at its start; Ghidra still
reported `(none)` as the **function containing either interior
target**, indicating the region is not yet fully disassembled
or recognized in the Ghidra function body.

The only existing reference to entry `0x140742880`
was `DATA` from `0x155C7E844`. Since the reference is
data-only and may come from PE runtime-function metadata,
**do not identify it as a C++ caller**. Need actual code
references or other evidence of ownership.

### One follow-up Ghidra inspection

1. Goto `140742880` at start of the known bounded region.
2. If undefined, press `D` at the entry once to disassemble.
   Do not clear/redefine or modify the game executable.
3. Screenshot the Listing prologue together with the
   Decompiler (if it updates). If the Decompiler still shows
   stale or unrelated code, send the Listing first.
4. Determine whether surrounding code refers to arena
   graphics / broadcast presentation or is used in MyNBA.
   If arena-only, stop chasing these objects.

**Not yet verified:** photo-eligibility check, asset
resolver, MyNBA consumer, or patchable function.
