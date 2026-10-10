# ActionShotId +0x3DC read scan — first user report

**Result:** Successful read-only Ghidra scan of the exact game executable,
SHA-256 `efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`.

- Scanned approximately **1,101,781,504 initialized executable bytes**.
- Identified **183 heuristic instruction encodings** that could read
  object displacement `0x3DC`; exported 75 grouped candidates.
- One matching encoding fell inside previously recognized bulk
  player-data field processing; 182 were elsewhere. These counts
  **do not mean 182 separate real ActionShotId accessors**.
- The two-byte field layout was verified by earlier setter decompilations;
  **an instruction that reads the same offset does not establish the
  type of object in its base register**.

## First high-priority 16-bit candidates

| Candidate VA | PE unwind fragment | Code pattern | Interpretation |
| --- | --- | --- | --- |
| `0x141E3B5C3` | `0x141E3B490`–`0x141E3D81C` | `movzx edx, word ptr [rdi+0x3DC]`, then helper call | Bulk attribute read/transfer likely; not verified image loading |
| `0x141E3D966` | `0x141E3D86C`–`0x141E3E486` | Same `movzx`, helper call | Analogous attribute processing |
| `0x141E49015` | `0x141E461E0`–`0x141E4A3F7` | Reads `+0x3DC`, `+0x3DE` then calls separate helpers | Field serialization/copy or structured transfer likely |
| `0x141E5253D` | `0x141E51B44`–`0x141E541EA` | Conditional field reads controlled by object flags | Possible conditional bulk field transfer, not necessarily portrait selection |
| `0x141ED9235` | `0x141ED42B0`–`0x141EDB9F4` | Loads word at `+0x3DC`, compares it with another object's `+0x3DC`, sets flags | Plausible object/roster difference tracking |
| `0x1427CD22E` | **No unwind fragment**, possibly leaf function | `mov rax, [rdx+8]` then `movzx eax, word ptr [rax+0x3DC]`, stores an output field | Looks like typed property access / reflection getter; **not yet decompiled or proven** |
| `0x142FB4A4C` | `0x142FB3EF4`–`0x142FB57C1` | Reads word and adds to another object's matching word | Bulk accumulation/merge likely |

The byte windows at high VAs (`0x165...` through `0x187...`)
contain unusual instruction-like sequences and typically have no PE unwind
fragment. They may include obfuscation or misleading matches and
should **not** be prioritized just because a pattern resembles a word read.

Other code reads 32-bit/64-bit values at the same displacement; those
may belong to entirely unrelated object layouts, and must not
be labeled `ActionShotId` without validation.

## Narrow next experiment

**Inspect one small read-only accessor at VA `0x1427CD22E`.**
It looks like a typed property getter controlled by a field type code,
not a photo loader. A targeted Ghidra disassembly/decompilation can
confirm or reject this quickly, without another 1+ GB scan.

- Disassemble from the apparent function start, **not** the middle of
  the `movzx` at `0x1427CD22E`.
- Current raw byte window contains an apparent branch and output
  record write; confirm Ghidra function boundaries before declaring
  a getter.
- If it is a generic property getter, end the offset-based search:
  pivot to identifying **action-shot UI asset requests** and
  their team-dependent fallback condition.
- Do not implement a hook at any scanner candidate. No known UI
  selector, rendering call, or verified original-team check exists.

The target is only the **real full-body action-shot disappearing after
trades in offline MyNBA**; real player headshots remain visible.
The existing QoL Hook DLL is still a nonfunctional skeleton.
