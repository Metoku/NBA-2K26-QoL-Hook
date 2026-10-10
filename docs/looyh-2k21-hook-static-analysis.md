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
