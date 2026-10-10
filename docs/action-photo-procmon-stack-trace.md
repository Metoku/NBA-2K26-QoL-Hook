# Next investigation: observe action-photo IFF resource loader call stacks

**Goal:** Obtain a real code-location lead from a confirmed NBA 2K26
action-photo override file operation instead of scanning 1.1 GB for
unrelated player-field offsets.

## Evidence already recorded

ProcMon, filtered to `NBA2K26.exe`, showed successful
`CreateFile`, metadata and `ReadFile` operations for a mod
asset path ending in `mods\\player_images\\chr_r9809_a1.iff`.
The user did not establish which player or portrait this file represents,
and it is not proven to be a normal baked-in action photo.

**What the trace proves:** the game process accesses at least one
modded action-photo-format IFF override through filesystem calls.
**What it does not prove:** which MyNBA selection path decided to
request it, whether original packed photo assets use the same loader,
or how traded players are rejected.

## One focused non-invasive step

1. Reopen the **existing** ProcMon capture if still available.
   Do **not** need to relaunch the game if the original event remains.
2. Locate the exact `chr_r9809_a1.iff` event and select the
   successful **CreateFile** record first.
3. Double-click that event, then open the **Stack** tab in Event Properties.
   Expand/maximize the window to show the `Module`,
   `Location`, and (if provided) `Address` columns.
4. Find rows with **Module = NBA2K26.exe**, preferably several
   consecutive user-mode `U` frames, and screenshot the full visible
   stack. The Stack tab's **Copy All** function can also capture
   it as text, if available.
5. If possible, repeat step 3 for the **ReadFile** event on the
   same named IFF. Both stacks might differ: one concerns opening
   the file, another the asynchronous read.
6. Only if no old capture remains, record **one short capture**
   during a known-working action-photo load with the process-name
   filter. Avoid lengthy logging; stop after the specific event.
7. If the Stack tab is empty or contains only Windows DLL/kernel
   frames, **stop**. Don't attach debuggers or bypass any game
   protection to force a stack trace.

The official Microsoft Sysinternals documentation confirms ProcMon
records event thread stacks:
https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
ProcMon Event Properties help:
https://documentation.help/Process-Monitor/Event_Properties.htm

## How to interpret, not assume

A stack for `chr_r*.iff` is an empirical *file-I/O loader* path,
not a proven **portrait eligibility/render decision**.

If a Stack row is shown as `NBA2K26.exe + 0xRVA`, the Ghidra
address for our known import image base is `0x140000000 + RVA`;
module-offset formatting must be verified before conversion.
If it instead shows a runtime absolute pointer, subtract the
exe's **runtime module load base** before adding the static
Ghidra image base; ASLR makes runtime and Ghidra VAs differ.
In either case, request the exact row or screenshot and calculate
the address carefully before navigating.

The **call site** for opening the asset likely occurs *near* (not
necessarily exactly at) the returned stack address. A file read can
occur in a worker thread with a generic code path, so a candidate
may only lead to file I/O. We should examine disassembly for
references to IFF naming, player-photo context or resource
identifier routing. Do **not** patch I/O or hook arbitrary stack
frames simply because `chr_r` was loaded.

Success milestone: at least one plausible game-module function
can be linked by a real file-operation call stack to action-photo
asset loading. Next milestone still requires identifying the
team-based real-photo vs cyberface selection behavior.

Keep the DLL skeleton **uninstalled**. No live injection, game edits,
anti-cheat interference, or important-save modification.

## User-provided initial ProcMon stack (2026-10-10)

The user shared a cropped ProcMon stack containing these **user-mode**
frames for the examined file-operation event:

```
U 12  NBA2K26.exe  ExportProductMetadata + 0xB06665  0x15673345A
U 13  <unknown>     0xD69AB                       0xD69AB
```

The numeric address `0x15673345A` is a **runtime address**, not
the static Ghidra address. `ExportProductMetadata + 0xB06665`
is how ProcMon's available symbols identified the address; the
large displacement does **not** establish that the named export
directly performs portrait loading.

Next, locate the *exact same* `ExportProductMetadata` symbol in
Ghidra's Symbol Tree, record its **static image virtual address**,
and compute `static symbol address + 0xB06665`. Verify this
lands inside a mapped executable region with real disassembly.
This can avoid needing a separate runtime module-base lookup,
**but only if both tools resolve to the same exact named export.**

Alternatively, if Process Explorer/ProcMon clearly supplies
the game's runtime image base `B_runtime`, the mapping is
`A_ghidra = 0x140000000 + (0x15673345A - B_runtime)`.
Do not assume the runtime base from an aligned-looking guess.

Call-stack entries typically indicate a return/callsite address
inside a **generic file-open or read path**, not a verified
`ActionShotId` consumer, eligibility condition or hook target.
The `<unknown>` frame is currently uninterpretable. A complete
stack and whether the recorded event was `CreateFile` or
`ReadFile` would help assess this lead.

No patch or hook is authorized by this trace.

## Correction: verified instruction bytes adjacent to the captured stack address

A user Ghidra Listing screenshot showed the following bytes in the
mapped `.data` region (which has **R/W/X** permissions in this
particular imported image):

```
0x156733454  FF 15 D6 FD 5F ED      call qword ptr [rip - 0x12A0022A]
0x15673345A  E9 01 00 00 00         jmp 0x156733460
```

The first instruction's **return address** is exactly
`0x15673345A`, the NBA2K26.exe frame shown by ProcMon on an
`NtReadFile` / `ReadFile` stack for the `chr_r9809_a1.iff`
asset. The indirect-call memory operand resolves to
`0x143D33230` **in Ghidra's displayed image address space**
(verify this with Ghidra Listing; no assertion about what the
runtime pointer targets yet). This is stronger evidence than merely
seeing a program-module frame somewhere in the stack.

This also corrects the prior premature dismissal of
`0x15673345A` just because it lies in `.data`: the specific
Ghidra Memory Map screenshot shows the section is marked executable.
The `ExportProductMetadata + 0xB06665` symbol label is an
approximation that can point at a nearby **export-name data label**,
not a reliable function-name resolution; the callsite bytes are
better evidence.

**Next one-screen Ghidra action:** go to `0x156733454`, disassemble
from that **instruction start** (press D), and screenshot the Listing
showing the decoded `CALL` and the resolved indirection. Don't
start disassembling at `0x15673345A` without checking surrounding
instruction boundaries. If Ghidra cannot safely disassemble
`0x156733454`, show the error instead.

This is evidence of a generic Windows file-read caller—not yet
proof of *who requested* the action portrait or how team-based
cyberface fallback is chosen. **Do not patch this callsite**.
