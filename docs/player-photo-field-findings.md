# Findings: photo ID and team field string trace

This report documents a successful read-only static Ghidra scan of
NBA2K26.exe (Steam x64), **SHA-256 exactly matching**:

`efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39`

## Observations

- 31 ASCII/UTF-16LE text matches, including `PhotoId`, `ActionShotId`,
  `PortraitTeam`, `ActionShotTeam`, `PLAYERDATA::SetPhotoId`,
  `PLAYERDATA::SetActionShotId`, `GetPhotoId()`, `GetActionShotId()`,
  and their over/underflow diagnostic strings.
- 0 statically stored absolute pointer slots matching those literal strings.
- 17 heuristic RIP-relative LEA/MOV code references to some matched strings.
- The reported references include `0x1408085CC` (text label `PhotoId`),
  `0x14080869B` (`ActionShotId`), `0x1412AD4E6`
  (`PLAYERDATA::SetPhotoId`), and `0x141F397EE` (`PortraitTeam`).
- The first two locations are in close proximity, with instructions
  near them reading or extracting player/object values from offsets
  including `0x3D4`, `0x3DC`, and `0x3DE`. This suggests a **player-data
  serialization/display/logging routine** could contain these fields.
  The exact owning structure and field mapping are unverified; the
  data may be packed, and the visible code does not establish the actual
  player-photo selection path.
- Several `PLAYERDATA::SetPhotoId` and `GetPhotoId()` text references
  occur next to `PhotoId over/underflow` diagnostics, consistent with
  setter/getter validation or debug error reporting, **not necessarily
  photo loading**.

## Conclusions

**No photo-selection function is verified. No dynamic player portrait
override is implemented.** For the first two code regions, the most
probable immediate role is formatting/debugging or serialization of
numeric player fields, not UI portrait retrieval. For
`PLAYERDATA::SetPhotoId`/`GetPhotoId()` messages, a string reference can
be part of an assertion or accessor and is not proof that the function
is involved in displaying a photograph.

Do not use these addresses as hook targets, write values into live
player memory, change `PhotoId` or team fields, or inject the skeleton DLL.

## Next technical milestone

Stop broad string scanners and identify an *actual image request* in
offline MyNBA:

1. Confirm the player-data field layout using **real Ghidra function
   boundaries and data flow**, not string adjacency. Inspect the
   containing functions for `0x1408085CC` and `0x14080869B`, and
   distinguish debug dumps from accessors.
2. Trace the consumers of the relevant getters/packed fields toward
   an image-resource request or UI portrait rendering call, rather than
   a setter or metadata serializer.
3. Reproduce Embiid's portrait on original 76ers versus unavailable after
   trade in a **disposable, backed-up, offline MyNBA save**. Any runtime
   validation must respect anti-cheat/game terms and avoid online play.
4. Require a real-photo asset to exist and preserve current roster/player
   data; eventual override must be opt-in, build-hash-gated, and fail closed.

This milestone requires proper Ghidra disassembly/decompilation and,
possibly, controlled offline runtime debugging. Another raw-string scan
is unlikely to confirm the actual selection function.
