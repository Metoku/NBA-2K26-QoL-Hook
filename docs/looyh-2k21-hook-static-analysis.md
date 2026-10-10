# Looyh NBA 2K21 Hook v0.0.5 — static photo-forcing analysis
**Status:** 2026-10-10, static-only examination of a user-supplied historical ZIP. **Not compatible with NBA 2K26 without new verification.** No uploaded DLLs were executed, loaded into NBA 2K26, or committed to this repository.

## Original package
User-supplied archive: `utf-8 NBA2K21_Hook V0.0.5.zip`.

| Archive entry | Size | SHA-256 |
|---|---:|---|
| `NBA2K21_Hook V0.0.5/NBA2K_Hook.dll` | 957,952 bytes | `beaa8ca468885836ca29f4862422734629ad0e5b99746a72a0774672b16d46f4` |
| `NBA2K21_Hook V0.0.5/dinput8.dll` | 186,368 bytes | `348a210d7b0b2d66640733f68a124b852dcac7d0ee76dbc8818a0b724d5b9884` |

Both are Windows x64 PE DLLs stamped in 2020, using UPX v3.96 packing headers. The `dinput8.dll` exports DirectInput-related symbols and serves as a loader/proxy; it is not evidence of an image-selection API. The **original DLLs must never be inserted into NBA 2K26** or committed to a public repository.

### Offline unpacking validation
We decoded the two UPX streams in memory using the documented UCL NRV2E LE32 decompression algorithm. The decompressed stream lengths and both packed/unpacked Adler-32 checksums **match** the UPX header in each file:

| DLL | UPX compression method | Unpacked stream length | Packed checksum | Unpacked checksum |
|---|---|---:|---|---|
| NBA2K_Hook.dll | NRV2E LE32 (`8`) | 2,611,750 | `0x92CF40B8` | `0x67257020` |
| dinput8.dll | NRV2E LE32 (`8`) | 687,588 | `0x461BC81A` | `0xA8697D3A` |

These are *decompressed streams* for static inspection, not reconstructed, safely loadable DLLs. The UPX instruction-filter is not fully reversed in the local disassembly, so do not trust apparent relative `CALL`/`Jcc` branch targets. Nearby opcode sequences and RIP-relative string references remain useful as contextual evidence.

## New evidence: the actual photo-forcing option and patch signatures

The unpacked game-hook stream contains the contiguous configuration names:
`global`, `debugAllFileOtp`, **`forcedisplayphotos`**, `mygmshowsettings`, `rostercustomdata` etc. The key `forcedisplayphotos` appears at *unpacked-stream* offset `0x2131A0` (candidate VA `0x1802141A0` in this historic image).

Three code references to `forcedisplayphotos` were identified at old-image locations `0x1800087FC`, `0x180008EC0`, and `0x180008F3F`.

**A specific config-true branch** at `0x180008808` tests the returned integer against zero. In that branch, it prepares two byte signatures, searches the old game module for those signatures, and attempts to write small replacements at matching addresses:

| 2021 code signature | Bytes in signature | Replacement bytes | Likely effect |
|---|---:|---|---|
| `85 DB 75 2E 48 85 C0 74` | 8 | `31 DB 90 90` | Replace `TEST EBX,EBX; JNE +0x2E` with `XOR EBX,EBX; NOP; NOP`, making that particular conditional path fall through |
| `0F 85 69 01 00 00 44 8B 45 30 48 8D` | 12 | `90 90 90 90 90 90` | Remove a near `JNE +0x169`, making that particular branch fall through |

**Grounding at historic hook code locations:**
- `0x180008820` and `0x18000882A` initialize the first signature bytes on its stack; `0x180008814` initializes the 4-byte replacement.
- `0x180008894`, `0x18000889B`, and `0x1800088A6` initialize the second 12-byte signature; `0x180008880` and `0x18000888B` initialize six `0x90` replacement bytes.
- Nearby `0x180008850` and `0x1800088C0` call an imported function with arguments consistent with `WriteProcessMemory(GetCurrentProcess(), module_base+match_offset, replacement, 4/6, NULL)`. This is **an inference** based on the x64 calling convention and the presence of `WriteProcessMemory` in the unpacked imports, not a completely recovered import-thunk mapping.
- The code starts handling a *different* setting, `mygmshowsettings`, after `0x1800088EC`. Do not confuse the following patches with the photo-force option.

This strongly suggests that the 2021 force-photo feature was implemented by **suppressing two game conditional branches**—not by editing players' `PORTRAITTEAM` roster data. However, no individual signature match was demonstrated against NBA 2K21.exe here (we did not receive that game's executable), so the **precise game-side function names and affected code paths remain unknown**.

### What this does NOT prove
- Neither signature, instruction site, nor old DLL offset is demonstrated to exist in NBA 2K26.
- We cannot yet distinguish team-eligibility enforcement from an image-existence check. **Forcing a branch indiscriminately could break fallback for players with no photo**.
- UPX unpacking only reveals the **old 2020 binary**. It supplies no reliable NBA 2K26 address, calling convention or permission to reuse old DLLs.

## Next *new* bounded static experiment on the exact 2K26 Ghidra import

Use Ghidra's built-in **Search → Memory** on the *exact SHA-matched NBA2K26.exe*, search type **Hex**, to check the **first complete eight-byte signature**:

`85 DB 75 2E 48 85 C0 74`

Do not patch anything. Record either the total count and a **single matching code address**, or **zero matches**. If a first-pattern match occurs inside actual instructions and a meaningful image-eligibility routine, inspect its enclosing function; otherwise check the second distinct 12-byte signature in a later bounded test.

**No matching bytes** is expected to be entirely plausible across NBA 2K21 → 2K26; it does not falsify the approach, only this exact old-site signature. A hit by itself is **not** a safe patch candidate: verify UI ownership and missing-photo fallback first.

This is the first prior-generation hook-based code signature evidence that is not a speculative getter/label/offset/string scan. We should **not** rerun x64dbg (it crashed), ProcMon (completed), or broad brute-force offset searches.

References for decompression format: [UPX compression constants](https://github.com/upx/upx/blob/devel/src/conf.h), [UCL NRV2E decompressor](https://sources.debian.org/src/ucl/1.03%2Brepack-5/src/n2e_d.c), and [UCL getbit macro](https://github.com/korczis/ucl/blob/master/src/getbit.h).

## User verification on NBA 2K26: exact patches do NOT match

The user ran Ghidra **Search → Memory**, Hex format, on
their fingerprinted NBA 2K26 import. Both full historic patterns
returned **zero matches**:

- `85 DB 75 2E 48 85 C0 74` — 0 results
- `0F 85 69 01 00 00 44 8B 45 30 48 8D` — 0 results

This rules out **literal byte-for-byte porting** of the
two old 2021 patch locations to this 2026 build. Neither
absence demonstrates that an equivalent higher-level
eligibility check does not exist.

### One narrowly relaxed static search

Ghidra supports hex-byte wildcards, with `??` meaning
any single byte. The most conservative relaxation is
to ignore only the conditional branch displacement in
the first signature:

```text
85 DB 75 ?? 48 85 C0 74
```

This keeps seven of the eight bytes fixed while allowing
the short `JNE` target to differ between versions.
**If a hit is reported, it is not a hook target by itself**:
the occurrence must start on genuine instruction boundaries,
live in executable code, and be proven to be the MyNBA
action-photo-vs-cyberface eligibility branch and preserve
the original missing-photo fallback.

If this single relaxed search also yields zero matches,
avoid repetitive random address exploration. A different
compilation or routine structure likely prevents
simple signature reuse; further progress will require
a structural/semantic code comparison grounded in a
known NBA 2K26 photo-resource flow.

Ghidra wildcard syntax reference:
https://scrapco.de/ghidra_docs/VERSION12/Features/Base/Search/Search_Formats.htm

## Ghidra validation: first relaxed signature produces false positives

The user searched `85 DB 75 ?? 48 85 C0 74` in
Ghidra. The screenshot returned **13 hits**, all in
unclassified code units from partially analyzed import.

A focused screenshot at `0x141E834C2` confirms
actual instructions:

```asm
0x141E834C2  TEST EBX,EBX
0x141E834C4  JNZ  LAB_141E834DA
0x141E834C6  TEST RAX,RAX
0x141E834C9  JZ   LAB_141E834ED
0x141E834CB  MOV  R8,RDI
0x141E834CE  XOR  EDX,EDX
0x141E834D0  MOV  RCX,RAX
0x141E834D3  CALL VCRUNTIME140.DLL::memset
...
0x141E834DA  TEST RAX,RAX
0x141E834DD  JZ   LAB_141E834ED
0x141E834DF  MOV  R8,RDI
0x141E834E2  MOV  RDX,RBX
0x141E834E5  MOV  RCX,RAX
0x141E834E8  CALL VCRUNTIME140.DLL::memmove
```

This is buffer-handling code, **not a demonstrated
photo-selector**. The wildcard signature is generic enough
to occur in many unrelated functions. Do not request
screenshots of all remaining 12 hits; no evidence currently
ranks one as portrait-related.

### Better next discriminating search

Use Ghidra Search Memory / Hex with the **second historic
signature** but wildcard only its near jump's four-byte
displacement:

```text
0F 85 ?? ?? ?? ?? 44 8B 45 30 48 8D
```

This preserves the `JNE` opcode and the six following
bytes, giving a different, more discriminating structural
test than the common `TEST/Jcc` pattern. No byte patch,
no runtime attachment. If zero matches, stop treating
historic signatures as directly reusable and seek a
semantic image-selection function instead.

## 2K26 wildcard hit: ONE candidate for Looyh's second patch signature

User ran Ghidra Hex Search for
`0F 85 ?? ?? ?? ?? 44 8B 45 30 48 8D`
on the exact fingerprinted NBA2K26.exe import and received
**exactly one match**:

- **VA:** `0x14347E3F7`; **RVA:** `0x347E3F7`
- **Observed bytes:** `0F 85 E2 01 00 00 44 8B 45 30 48 8D`
- Looyh NBA2K21 v0.0.5 original pattern:
  `0F 85 69 01 00 00 44 8B 45 30 48 8D`.
- The conditional branch displacement is different:
  original relative offset `0x169`; 2K26 candidate offset
  `0x1E2`. The following 6 bytes match.
- The presumed jump starts at `0x14347E3F7`,
  so its **fall-through** is `0x14347E3FD`, and
  its computed **branch target** is `0x14347E5DF`
  (`0x14347E3FD + 0x1E2`) if it is a genuine
  instruction boundary. These are static hypotheses
  until the code is disassembled in Ghidra.

This single exact-surroundings hit is a **distinctive lead**,
but its correspondence to an actual NBA2K26 MyNBA action
photo eligibility check is **not yet proven**. The
old NBA2K21 patch NOPs out this kind of conditional
branch. Do **not** patch the 2K26 match: skipping
the branch could disrupt image-existence fallback,
player cards or unrelated code.

**Next one bounded Ghidra screenshot:** double-click
result `0x14347E3F7`, or G → `14347E3F7`.
Disassemble with D only if undefined and at known
instruction boundary. Show ~15–20 Listing instructions
before and after and the correct function's Decompiler
if available. The first objective is to determine what
condition sets the ZF for the `JNZ`, what happens at
fall-through `0x14347E3FD`, and what is located at
branch target `0x14347E5DF`. Request target-region
screenshot only if the first one contains useful
photo-specific evidence.

## Ghidra disassembly of unique NBA 2K26 match

The user's screenshot validates the unique relaxed-signature hit
`0x14347E3F7` as a **genuine instruction boundary**.
The Decompiler now displays a partial function
`UndefinedFunction_14347E3B0` but no portrait-specific
symbol has been found.

Directly visible relevant Listing:

```asm
0x14347E3D0  CMP   ECX,0x504521A8
0x14347E3D6  JNZ   LAB_14347E3EC
0x14347E3D8  MOV   RCX,[RBX+0x8]
0x14347E3DC  CALL  thunk_FUN_154404530
0x14347E3E1  CMP   EAX,0xC8
0x14347E3E6  JZ    LAB_14347E5DF
0x14347E3EC  MOV   RCX,[RBX+0x8]
0x14347E3F0  CALL  thunk_FUN_15442DC90
0x14347E3F5  TEST  EAX,EAX
0x14347E3F7  JNZ   LAB_14347E5DF
0x14347E3FD  MOV   R8D,[RBP+0x30]
0x14347E401  LEA   RDX,[RSP+0x50]
0x14347E406  MOV   RCX,[RBX+0x8]
0x14347E40A  CALL  FUN_143396C30
0x14347E40F  MOV   RCX,[RBX+0x8]
0x14347E413  CMP   dword ptr [RCX+0x114],R15D
0x14347E41A  JZ    LAB_14347E5DF
0x14347E420  CMP   dword ptr [RBX+0x38],R15D
0x14347E424  JZ    LAB_14347E5DF
```

The condition whose conditional jump corresponds to the
2021 NOP-style patch is specifically the return value of
`thunk_FUN_15442DC90`. Other conditions—including a
possible return `0xC8` and integer fields at `+0x114`
and `+0x38`—can independently skip to the **same**
`0x14347E5DF` target. A naked NOP patch to
`0x14347E3F7` may have broader consequences and is
**not justified** by the signature match.

The code has not yet been linked to image rendering or
player action photos. It may process a completely unrelated
state machine, including object/error states.

### One next bounded Ghidra screenshot

**Navigate to `0x14347E5DF`** and capture the branch
destination in the Listing, with 10–20 instructions before
and after, and the matching Decompiler region if it is
practical. Focus on what the branch skips and where the
branches reconverge. Do **not** patch the EXE or inject any
DLL; the purpose is classification before proposing code.

If the destination belongs to unrelated state handling,
stop this candidate. If the destination references
player portrait assets/eligibility, trace the check helper
next, still in static Ghidra.

## Follow-up Ghidra screenshot: jump destination at `0x14347E5DF`

The user opened the branch target
`LAB_14347E5DF`, with the surrounding Listing and
partial `UndefinedFunction_14347E3B0` decompilation.

### Confirmed by screenshot

- Six separate preceding branches converge at
  `0x14347E5DF` (from addresses including
  `0x14347E3E6`, `0x14347E3F7`,
  `0x14347E41A`, `0x14347E424`,
  `0x14347E43D`, and `0x14347E453`).
- The common branch destination is **not an immediate
  return**. It continues a broader update/callback flow:
  ```asm
  0x14347E5DF MOV  RCX,RSI
  0x14347E5E2 CALL thunk_FUN_14335D7F0
  0x14347E5E7 MOV  R8,R14
  0x14347E5EA MOV  RDX,RAX
  0x14347E5ED MOV  RCX,RSI
  0x14347E5F0 CALL FUN_143449960
  0x14347E5F5 MOV  RCX,[RBX+0x8]
  0x14347E5F9 LEA  RDX,[RBP+0x30]
  0x14347E5FD MOVAPS XMM6,XMM0
  0x14347E600 CALL FUN_143396F00
  0x14347E605 MOV  RCX,[RBX+0x8]
  0x14347E609 CALL thunk_FUN_1543FF900
  ```
- The Decompiler shows later floating-point calculations,
  state blending and updates involving `[RBP+0x40]`.
  These are consistent with state/animation or another
  general update operation. **No direct action-shot asset,
  portrait ID, team eligibility or real-photo selector is
  identified yet.**
- This weakens the inference that the unique wildcard
  signature alone establishes a MyNBA photo hook.
  However, the structural match to the old Looyh patch
  remains a valid investigative lead, not yet disproven.

### Best bounded next evidence

Rather than hand the user more neighboring addresses,
request the **complete currently decompiled routine as text**
in Ghidra: click Decompiler pane, Ctrl+A, Ctrl+C, paste into
chat (or save as `.txt`). It is labeled
`UndefinedFunction_14347E3B0` and could be a partial
function body due to Ghidra's incomplete analysis.
We need to examine the check
`thunk_FUN_15442DC90`, the `0x504521A8` comparison,
the skip path, subsequent state updates and exit together,
before requesting further investigation.

**Do not remove or NOP** the branch at `0x14347E3F7`,
even though its post-`JNE` instruction bytes match
Looyh's older hook. No game patch, live debugger
or DLL injection has been validated.

## Full user-supplied decompilation resolves single relaxed second-pattern match (2026-10-10)

The user supplied all of `UndefinedFunction_14347e3b0`
at the match `0x14347E3F7` (NBA2K26.exe, fingerprinted build).
Its control flow strongly identifies a **VCHTTP network
request/state handler**, NOT a confirmed player portrait selector.
The most discriminating direct evidence is a diagnostic call:

```cpp
FUN_14335cb50(1,0,"VCHTTP","EMPTY","vchttp_request.vcc");
```

Further contextual indicators:
- `thunk_FUN_154404530(...)` returns/compares HTTP-like
  status codes `200`, `0x1F6` (502) and `0x1F7`
  (503).
- `thunk_FUN_15442DC90(unaff_RBX[1]) != 0` is the
  branch condition at `0x14347E3F7`.
- Reads/comparisons at `+0x10C` and `+0x110`
  and increment of `+0x10C` suggest buffered
  request state, lengths or retry accounting.
  Actual field meanings are **not verified**.
- A string/code sentinel `0x504521A8` is used to
  loop/terminate request state; meaning unknown.
- The shared jump target `0x14347E5DF` performs
  helper calls and returns to the requester.
- None of this decompilation names a player,
  `ActionShotId`, photo team, image resource resolver,
  or real-photo-versus-render selection.

**Important nuance:** Because the relaxed second signature
is unusually distinctive and appears inside an HTTP
request handler, it could reflect **shared engine code
across 2K21 and 2K26**, rather than a random instruction
coincidence. The 2021 hook's motivation for NOP'ing that
branch is still unknown: historical patch semantics were
inferred from its binary, without the older game executable.
We CANNOT infer that this 2K26 network branch makes the
same photo eligibility decision. It may be a networking
guard unrelated to local offline MyNBA photos. Forcing
fall-through risks destabilizing network request handling.

**Decision:** Do not NOP or hook `0x14347E3F7`.
Close this 2K26 wildcard-branch lead unless independent,
photo-specific evidence connects VCHTTP requests to MyNBA
photo eligibility. Future study, if any, must establish
what the original two NBA2K21 patch sites did within
that game's code, not assume similarity from byte patterns.
No runtime hook is currently verified. No more
neighboring screenshots required for this routine.

## Independent re-check of user-uploaded ZIP (2026-10-10)

We separately reprocessed the user's original
`NBA2K21_Hook V0.0.5/NBA2K_Hook.dll` using a **static**
UCL NRV2E LE32 decoder and independently re-verified that:

- The full compressed UPX stream starts at **file offset
  `0x400`**, has **953,116** bytes and compressed
  Adler-32 **`0x92CF40B8`**.
- Its unpacked stream has **2,611,750** bytes and uncompressed
  Adler-32 **`0x67257020`**. Both match the metadata.
- In this unpacked historical image, there is one literal
  `forcedisplayphotos` key at `0x1802141A0`.
  A RIP-relative `LEA` at `0x1800087FC`
  loads this key.
- The following branch checks a configuration result at
  `0x180008808`, then constructs **two code-signature
  searches and writes** (the first `0x180008820` through
  `0x180008870`; the second `0x180008880` through
  `0x1800088DF`) exactly as previously documented.
- The original `NBA2K_Hook.dll` was **not run** and no
  old DLL content was committed. UPX instruction filters
  make some recovered relative-call displacements
  unreliable, so the apparent pattern construction and
  imported-pointer call structure are stronger evidence
  than arbitrary downstream call-target addresses.

### Blocker for an accurate historical port

We have **only the 2021 hook DLL**, not the NBA 2K21
`NBA2K21.exe` it originally patched. A signature is
a locator, not a decompilation of the game's actual
photo-selection/asset-eligibility routine.

The only highly distinctive relaxed match for the
second 2021 signature in the user's 2K26 build is at
`0x14347E3F7`. User-provided Ghidra decompilation
reveals `VCHTTP`, `vchttp_request.vcc`, and
HTTP-style 200/502/503 statuses nearby. **We cannot
identify that 2K26 branch as the MyNBA action-photo
selection check**, and touching it risks network
state handling.

**Recommended next evidence path:** if the user owns
the historical **NBA 2K21 executable locally**, perform
a *read-only* Ghidra search for the two **original exact
signatures in that actual historical executable**,
disassemble their owning functions and determine what
the branches really test. Compare the verified function
logic to NBA2K26's corresponding subsystem. No need
to upload or distribute the copyright-protected game
binary itself.

If NBA 2K21 is unavailable, stop signature porting
as a blind alley; look for an independently evidenced
NBA2K26 MyNBA image resolver call path instead.
Do not instruct the user to download unofficial
executables, patch VCHTTP, or try x64dbg again.

## Confirmed: BOTH unmodified Looyh signatures in a legitimately downloaded Epic NBA2K21.exe (2026-10-10)

The user owns NBA 2K21 on Epic Games; Legendary's app ID is
`639977eecfd2497c941b71af949b5067`, visible release
version `1.12.135040`. They used Legendary's selective
`--prefix "NBA2K21.exe"` download (one file, size 73.15 MiB,
download 27.22 MiB, 95 others skipped), without installing
the whole game. Screenshots show Ghidra search in **NBA2K21.exe**:

1. Old Looyh signature `85 DB 75 2E 48 85 C0 74`:
   exactly **ONE match** at **VA `0x14101D107`**.
2. Old Looyh signature
   `0F 85 69 01 00 00 44 8B 45 30 48 8D`:
   exactly **ONE match** at **VA `0x140FCE5FF`**.

This confirms both literal patch target patterns survived
in the Epic NBA2K21 build, despite its 1.12 version
dating after Looyh 2020. It does **not** prove same
branch semantics, nor that the historical NOP patch is
safe or fully functional on this build. No files edited.

**Highest-value next evidence:** In Ghidra's NBA2K21.exe
(not NBA2K26.exe), navigate to **`0x140FCE5FF`**,
disassemble only if undefined, and provide 15–20 surrounding
Listing instructions with Decompiler (or the complete
pseudocode). Compare the second patch site with NBA2K26's
distinctive wildcard match `0x14347E3F7`, already
identified inside a **VCHTTP request state handler**.
This will tell us whether the old branch was in the
same networking subsystem or another function.
Only then inspect the first patch at `0x14101D107`.
Do **not** NOP either game executable.

## Ghidra NBA2K21.exe first Listing screenshot at second old signature

User navigated to **`0x140FCE5FF`** (the genuine 2K21
second patch site). The Listing has many undefined bytes
before it and Ghidra currently creates only the truncated
`UndefinedFunction_140fce5ff`; Decompiler shows
`in_ZF`, reflecting a missing predecessor rather than
actual dependency on an ambient undefined flag.

The immediately preceding raw bytes in screenshot decode to:

```asm
0x140FCE5F4  48 8B 81 C8 00 00 00  MOV RAX, qword ptr [RCX+0xC8]
0x140FCE5FB  48 39 41 60           CMP qword ptr [RCX+0x60], RAX
0x140FCE5FF  0F 85 69 01 00 00     JNZ 0x140FCE76E
0x140FCE605  44 8B 45 30           MOV R8D, dword ptr [RBP+0x30]
0x140FCE609  48 8D 45 D4           LEA RAX, [RBP-0x2C]
```

This is **different from the tested NBA2K26.exe hit**
`0x14347E3F7`, where the JNZ follows
`TEST EAX,EAX` on a function return in a VCHTTP
request handler. The wildcard signature similarity
was misleading.

The old 2K21 branch checks equality of two fields
in an unknown object at offsets `0x60` and
`0xC8`; no proof yet those fields are photos,
images, or player records. It is also not known
that the instruction at `0x140FCE5F4` belongs
to the genuine function path until disassembly.

**Immediate safe next step:** User in Ghidra NBA2K21.exe
press G → `140FCE5F4`, press D on that first
`48` byte (disassemble), and send a Listing
screenshot including the new instructions before
`0x140FCE5FF`. Do not edit instructions or try
to patch NBA2K26. If the partial function persists,
inspect raw Listing and fix function boundaries only
after observing a valid enclosing start.
