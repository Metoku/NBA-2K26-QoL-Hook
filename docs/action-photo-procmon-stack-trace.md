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
