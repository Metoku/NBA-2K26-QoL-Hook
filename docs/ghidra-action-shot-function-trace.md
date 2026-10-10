# Action-shot-only trace: finding real function boundaries in Ghidra

## Why this is different from yesterday's scans

We confirmed that NBA 2K26 keeps displaying **real headshots** after
trades, while the **full-body real action portrait** disappears and
falls back to an in-game-rendered image. Previous scans located
`ActionShotId` and some accessor/assertion field text, but did not
identify any working in-game action-photo renderer or selector.

The previous static Ghidra scan recorded:

- `0x14080869B`: direct reference to the `ActionShotId` name.
- `0x1408085CC`: nearby reference to `PhotoId` (comparison ONLY).
- `0x141F0147A`: reference to a `GetActionShotId()` diagnostic.
- `0x14C704C5C`: reference to a `SetActionShotId` diagnostic.

The new script **does not scan all strings or all executable bytes**.
It reads the **Windows x64 PE exception directory** to locate registered
function fragments for the *known* addresses. It does not require a
Ghidra memory block to be named `.pdata`.
It then attempts **targeted disassembly, function creation and
decompilation**, if the fragment is 16 KiB or smaller.

A registered unwind fragment is not guaranteed to be an entire logical
function. Where a fragment or decompilation cannot be verified, the
script says so rather than inventing a function boundary.

## Follow-up for the first reported error

The first user run successfully verified the executable SHA-256 but reported
`WARNING: no initialized .pdata block in this import`. It therefore did
**not** find any function boundaries or decompile any code.

The current version fixes that overly strict memory-block-name check:
it reads the exception-directory RVA and size directly from the loaded
PE header and reports the **actual Ghidra memory block name** containing
the runtime-function table. If PE headers are not imported at the image
base, it prints a short memory-block diagnostic rather than guessing
addresses or attempting to create unsafe functions.

**Simply replace the previous Java file with the updated version**,
refresh Script Manager, run the script, and upload the new report.
If the directory is not accessible even after this fix, we will
investigate Ghidra's import layout instead of repeatedly rerunning
the same scan.

## Run this in Ghidra (no extra software)

1. Save/back up your current Ghidra project if you want to preserve its
   current analysis state.
2. [Download the new Java script](../ghidra_scripts/NBA2K26ActionShotFunctionTrace.java)
   from the GitHub branch (select **Download raw file**).
3. Put `NBA2K26ActionShotFunctionTrace.java` in the **same existing**
   `ghidra_scripts` folder as the previous working scripts.
4. In the same `NBA2K26.exe` CodeBrowser project, open **Window →
   Script Manager** and click **Refresh**.
5. Run `NBA2K26ActionShotFunctionTrace`.
6. Save the report on your Desktop, for example
   `NBA2K26-actionshot-function-report.txt`.
7. Upload that **text report** here. If Ghidra reports a Java compile
   error, copy the error text instead.

The executable is more than 1 GB, but this step should normally
complete much faster than yesterday's byte-wide scans. It may take
longer when Ghidra builds a function or decompiles it.

## Scope and safety

- **May modify Ghidra's local analysis database:** it can add
  instructions and function definitions at metadata-derived entry
  points. It never invokes full automatic analysis.
- **Does not modify the NBA2K26.exe file**, change your roster or MyNBA
  save, attach to a running game, inject a DLL, or perform network calls.
- Checks Ghidra's imported SHA-256 against the known July 2026 build
  when Ghidra provides it.
- Limits decompilation to three unique candidate functions, with
  45 seconds maximum each. Limits source text per function to 24,000
  characters and does not claim truncated pseudocode is complete.
- The generic getter/setter diagnostic routines may turn out irrelevant.
  A field name or successful decompilation is not evidence that this
  is the in-game image selector.
- The next milestone is a verified **action-photo image request or
  team-based eligibility check**, not another field-name scan.

## Current mod status

No safe, automatic action-shot portrait hook has been identified, and
the `NBA2K26QoLHook.dll` is still a skeleton. **Do not install/inject
it** yet. Keep future validation on disposable offline MyNBA saves
and avoid interfering with game anti-cheat or online play.

Relevant outside discussion, not proof of implementation:
https://forums.operationsports.com/forums/forum/basketball/nba-2k-basketball/26882570-players-like-kevin-durant-landry-shamet-et-al
