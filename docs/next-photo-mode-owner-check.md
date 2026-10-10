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

## Latest screenshot: owner function decompiled; actual code caller now visible

The user successfully disassembled and decompiled
`FUN_140742880` at `0x140742880`. The visible prologue
copies a handful of dwords from the optional second parameter
into the first parameter's object fields around `+0x30`.
The function then initializes and registers small objects using
`FUN_14334ABD0` and `FUN_14071A8E0`, consistent with
the previously verified photo-style / photo-mode table installs.

**Crucial additional clue:** Ghidra's existing xrefs to entry
`FUN_140742880` have improved after disassembly. The Listing
now shows a **code CALL reference from `0x14071D1EA`**,
in addition to the data references `0x143ECCE28` and
`0x155C7E844`. Earlier boundary-script output showed only
the single DATA reference, so the new code xref is the
first promising path toward the actual owning subsystem.

**Next one-step inspection:** Navigate to `0x14071D1EA`
in Ghidra and capture Listing instructions ~15–20 lines
above/below the CALL, together with the containing
Decompiler if available. We need to tell whether the
caller belongs to arena/broadcast graphics versus a MyNBA
player portrait widget. If arena-only, stop this lead rather
than continuing endless constructor/table exploration.

Still **no photo-versus-cyberface selection function or
working C++ hook**. Research milestones cannot be
translated to a reliable overall completion percentage.

## Latest screenshot: actual caller is a generic function-pointer dispatcher

The user navigated to `0x14071D1EA`. Ghidra's decompiler
identifies the containing routine as `FUN_14071CAA0`,
and the Listing shows this control flow:

```asm
0x14071D1DE  LEA RAX,[FUN_140742880]
0x14071D1E5  CMP R8,RAX
0x14071D1E8  JNZ LAB_14071D1F1
0x14071D1EA  CALL FUN_140742880
0x14071D1EF  JMP LAB_14071D1F4
0x14071D1F1  CALL R8
```

In the decompiled Listing, this occurs within code that
traverses linked/list-like objects and invokes callback pointers.
The direct-call shortcut is consistent with generic dispatch,
registration or copy/restore work; it does not establish the
originating player, MyNBA screen, action-photo asset request,
team check, or cyberface fallback.

**Decision:** this is sufficient to close this bounded
photo-setting-constructor/callback-chain investigation for now.
The existence of strings `Force Real Photo`,
`Always Render`, `Use Assigned Team` is not enough to
prove that these options govern the MyNBA player-card portrait
path; several neighboring UI strings concern arena/broadcast
graphics. Do **not** follow additional generic callbacks or
patch these dispatch-table entries without a MyNBA-specific
cross-reference.

### Practical status and alternate source-led research

The game behavior is observed; player photo IDs and
photo-setting registration are partially understood; but
no verified game-specific photo selector, executable patch,
or valid runtime hook exists. The skeleton DLL should
remain uninstalled.

There is precedent in **NBA 2K16** for a trainer hotkey
that forced real photographs, but it cannot be used as
evidence of the location or implementation of an
equivalent **NBA 2K26** operation:
https://www.nba2k.org/2016/01/nba-2k16-roster-editor-trainer.html

Further work should prioritize obtaining a **game-version-specific
existing implementation or documented portrait-policy input**
to provide a stable entry point. Only then return to targeted
static code review or controlled offline testing. Generic
string, offset and file-I/O scans have reached diminishing returns.

## New bounded experiment: inspect photo-mode-specific dispatch method

A public historical reference documents Looyh's **NBA 2K21 Hook**
v0.0.5 implementing **"Force display photos"** / mandatory loading
of player photos, independent from its separately listed roster
support. **This does not prove an equivalent 2K26 hook exists.**
Source: https://www.2kspecialist.net/2020/10/nba2k21-hook-v005-by-looyh-added-force.html

Prior exact-build table report found two sibling candidate dispatch
tables used to initialize photo mode/style objects. Their adjacent
differing entries, indexed relative to the proposed table starts,
are:

| Candidate | Candidate table | Distinct index 20 (+0xA0) |
| --- | --- | --- |
| Photo mode | `0x143ECC9C0` | `0x140744910` |
| Photo style | `0x143ECCA80` | `0x1407449A0` |

**Question:** Are these unique methods merely setting/formatting
arena broadcast options, or do they expose a reusable
photo-source override path? We already know the *label
formatter* entry at table index 23 is **not** selection code.

### One screenshot only (no scanner)

With the exact SHA-matched executable open in Ghidra:

1. Press **G** and enter `140744910`.
2. Capture the Listing with ~15 instructions below and the
   Decompiler **only if it resolves the correct function**.
3. If the area is undefined, use **D** at the function's
   first instruction, but **do not manually create a random
   function or modify executable bytes**.
4. Send that screenshot. We will examine register arguments,
   fields, calls and how this method differs from the
   counterpart `0x1407449A0` *only if* the first method
   yields meaningful new behavior.

If this proves to be setting/serialization code for unrelated
presentation widgets, close the photo-mode branch. No
speculative hook or re-scanning the entire EXE.

**Project status remains blocked:** No verified 2K26
MyNBA photo-selection condition. No hook implemented.

## Ghidra screenshot: photo-mode distinct table method `0x140744910`

The user navigated to `0x140744910` and the Listing
already labels `FUN_140744910`. The Decompiler pane reads
`No Function` despite a function header in the Listing;
this is a partial-analysis/selection problem, not proof of
invalid instructions. The Listing shows (direct observations):

```asm
0x140744910  MOV qword ptr [RSP+0x8],RBX
0x140744915  MOV qword ptr [RSP+0x10],RSI
0x14074491A  PUSH RDI
0x14074491B  SUB RSP,0x20
0x14074491F  MOV RAX,qword ptr [RCX+0x30]
0x140744923  MOV RSI,RDX
0x140744926  MOV EDX,dword ptr [RDX+0x18]
0x140744929  MOV RDI,RCX
0x14074492C  MOV ECX,0xA
0x140744931  MOV EBX,dword ptr [RAX+0x1C]
0x140744934  CALL FUN_141FE3A90
0x140744939  TEST EAX,EAX
0x14074493B  JZ LAB_14074494C
0x14074493D  TEST EBX,EBX
```

The method appears to process a configuration/state object
via a helper and a selected value at `[RAX+0x1C]`.
This **does not prove** any action-photo asset loader or
MyNBA portrait-vs-render selector. The user's function
cross-reference shown is a DATA ref
(`0x155C7EA0C`), not a code caller; likely exception
metadata, not evidence of a UI caller.

### One final bounded screenshot for this method

Ghidra **G → `140744966`**. Screenshot the Listing
about `0x14074493B` through `0x1407449A0`,
especially the branches/return and final helper calls.
No need to force a Decompiler function or run another
script; don't modify binaries. If it is simply enum
validation/setting, close the photo-mode branch.

## Complete decompilation screenshot confirms option-cycling handler, not renderer

The user's latest Ghidra screenshot shows a fully updated
Decompiler for `FUN_140744910`:

```cpp
void FUN_140744910(longlong param_1,longlong param_2) {
    int iVar1;
    int iVar2;
    iVar2 = *(int *)(*(longlong *)(param_1 + 0x30) + 0x1c);
    iVar1 = FUN_141fe3a90(10, *(undefined4 *)(param_2 + 0x18));
    if (iVar1 != 0) {
        iVar1 = FUN_141fe3a90(11, *(undefined4 *)(param_2 + 0x18));
        if (iVar1 != 0) {
            if (iVar2 == 2) iVar2 = 0;
            else iVar2 = iVar2 + -1;
        }
    } else if (iVar2 == 0) {
        iVar2 = 2;
    } else {
        iVar2 = iVar2 + -1;
    }
    if (*(int *)(*(longlong *)(param_1 + 0x30) + 0x1c) != iVar2) {
        *(int *)(*(longlong *)(param_1 + 0x30) + 0x1c) = iVar2;
        FUN_1425fb230(&DAT_14770fc88,0);
    }
}
```

**Correction / interpretation**: the exact branching should be read
from the user's pseudocode, not assumed to be a strict modulo
cycle in all input cases. In all successful paths this is an
**option/state-changing handler**, not evidence of an image
resource lookup or a MyNBA team-eligibility decision.
The 0/1/2 storage corresponds plausibly to the three photo-mode
labels, and `FUN_1425fb230` is invoked *after* a configuration
change, consistent with notifying listeners; its precise effect
is not established.

**Decision:** stop looking at `FUN_140744910` as a hook
candidate. Do not patch `[*(param_1+0x30)+0x1C]` or
`FUN_1425fb230` without confirming the owner's UI context,
actual image selection, safe asset fallback and call path.
The status remains: **no working NBA 2K26 MyNBA action-photo
selection hook yet**.

If future static analysis is justified, focus on a proven
*consumer* of the photo-mode property in actual image
resolution, not another UI setter or label formatting
method. The next step must provide stronger independent
evidence; repeated screenshots of neighboring option
methods are not warranted.
