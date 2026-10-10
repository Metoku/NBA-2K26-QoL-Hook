# First user-run findings — team-offset candidate scan

The user successfully ran `NBA2K26PortraitTeamSelectionCandidates.java`
against the known NBA 2K26 executable (SHA-256:
`efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`).

## Summary

- 1,101,781,504 initialized executable bytes processed.
- 43,923 heuristic operand matches mapped to x64 unwind fragments,
  and 37,034 unmatched potential encodings.
- 25,760 unique unwind fragments contained at least one match.
- 2,068 fragments contained two or more of the watched displacement
  values. **This is not 2,068 valid portrait-team checks.**
- Ranking output was capped at 35 regions.

## Important scoring caveat

Many high-scoring entries use **RSP** (base register ID 4), for
example regions starting `0x1433D1420`, `0x1433D1840` and the
series near `0x14006A32E`. Their apparent `+0x60`, `+0xD0`,
and `+0xD8` fields can simply be **stack-frame offsets**, not
`CURRENTTEAM` or `PORTRAITTEAM1/2`. The original numerical ranking
overweights these stack coincidences. **Do not interpret its top
scores as verified photo-eligibility routines.**

## Best first manual inspection

- Function start `0x14163A560`, unwind end `0x14163AB40`
  (about 1,504 bytes), already present in Ghidra as
  `FUN_14163A560`.
- Raw instruction encodings reference `[RBX+0x60]`,
  `[RBX+0xD0]` and `[RBX+0xD8]` from the same base
  register; a `CMP` at `0x14163A89A` references
  `[RBX+0xD8]`.
- These instruction bytes suggest **one object's fields** may
  be accessed together, unlike RSP-relative entries. But we
  **still cannot conclude** this is the player-data object, a
  photo-team eligibility comparison, or a MyNBA photo request.
- Inspect the **existing** function in Ghidra without patching:
  press G, enter `14163A560`, and view its Decompiler.
  If it isn't decompiled or Ghidra shows undefined bytes,
  request a screenshot of the Listing before doing anything else.

Lower-ranked alternatives: `0x14CF9E100` also accesses
`[RBX+0x60]`, `[RBX+0xD0]`, and `[RBX+0xD8]`;
`0x142A177D0` compares the three offsets through RAX,
but could be generic object equality.


## Follow-up user screenshot: function at `0x14163A560`

After the user manually disassembled this address in Ghidra, the
Listing showed a normal function prologue and a recurring pattern
of field tests/updates. At `0x14163A89A`, the verified Listing
instructions were:

```asm
CMP qword ptr [RBX + 0xD8], RBP
JZ  LAB_14163A8D5
MOV CL, 0x22
CALL FUN_142A099E0
```

Immediately preceding these instructions, code loads from
`[RBX + 0x70]`, conditionally performs an indirect virtual call,
and stores `RBP` into `[RBX + 0x70]`. After the comparison the
branch targets code that reads `[RBX + 0xD8]`.

**Important stronger observation:** The earlier function-prologue
screenshot shows `XOR EBP, EBP` at `0x14163A57E`, which zeroes RBP.
Unless RBP is reassigned in the intervening instructions (not yet
verified), this `CMP [RBX+0xD8], RBP` is a **null/zero test**,
not a comparison of two team IDs. This considerably weakens the
candidate as photo-team eligibility logic.

**Interpretation:** This is **consistent with a generic object
field-change notification/transfer path**, not direct evidence of
comparing `CURRENTTEAM` against `PORTRAITTEAM1/2`. Both operands in
the key CMP are **a field and the RBP register**, not the current-team
field; no image request or cyberface branch is visible in the
supplied Listing window. Without confirming the object identity and
callers, avoid assigning DB2K player-data semantics to these offsets.

**Decision:** Do not implement a hook at this CMP or assume
`FUN_142A099E0` selects a portrait. Stop broad field-offset
scanning and shift to a caller/resource-selection path with
actual UI/asset-resolution evidence.

## Engineering status

**No known image-selection function, validated eligibility branch,
image-resource request or hook address.** Identifying candidate
field accesses is preparatory analysis. Hook implementation, behavior
validation and build-gated offline testing are all still pending.
The existing DLL is only a skeleton; do not inject or install it.

The user's desired behavior: retain an existing real-life
**action portrait** after a trade, even if the image uses the former
team's jersey, while continuing the normal cyberface fallback when
no usable photo exists. Real headshots are out of scope.
