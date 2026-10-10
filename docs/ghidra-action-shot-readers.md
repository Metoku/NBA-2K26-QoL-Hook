# Trace potential ActionShotId readers (field offset +0x3DC)

## Why this is the next step

The last successful Ghidra trace established that two NBA 2K26
player-data routines **write** an unsigned 16-bit field at offset
`+0x3DC`. The associated diagnostics name the field `ActionShotId`.

We already know the real **headshot survives a trade**, while the
full-body real **action portrait disappears** and the game displays
a rendered player instead. Therefore, the main goal is to find code
that **reads** `ActionShotId` while selecting the action photograph.

Important: the field offset alone does not identify the owning object
in arbitrary code. A memory read from `[some-register+0x3DC]` might
belong to an unrelated type.

## Run once in Ghidra

1. Open the [NBA2K26ActionShotReaders.java](../ghidra_scripts/NBA2K26ActionShotReaders.java)
   source file in the GitHub branch and use **Download raw file**.
2. Copy the `.java` file into your existing Windows
   `%USERPROFILE%\ghidra_scripts` folder.
3. In Ghidra CodeBrowser, open the same `NBA2K26.exe` project that worked
   previously. No full auto-analysis is needed.
4. Select **Window → Script Manager**, **Refresh**, then run
   `NBA2K26ActionShotReaders`.
5. Choose a report file on Desktop, e.g.
   `NBA2K26-actionshot-readers.txt`.
6. Wait for the executable scan and upload the **report text only**.
   This can take some minutes due to the approximately 1.1 GB of
   initialized executable data. If compilation fails, copy the
   error text instead; this script has not yet been run in your local
   Ghidra installation.

The script does **not** change game files, saves, running process memory,
or Ghidra's analysis database. It requires the exact SHA-256 previously
verified and uses the already confirmed x64 unwind-table directory at
RVA `0x15C49000` to associate candidates with function fragments.

## What it reports

- Potential reads of object member `+0x3DC` using common x64
  `MOVZX` / `MOVSX` word-read instructions (highest priority), plus
  lower-priority `MOV` / `CMP` forms.
- Candidate instruction bytes and small surrounding hex contexts.
- Whether Ghidra already has an instruction at the candidate address
  (a useful alignment clue, not proof the field is a player ID).
- Registered Windows unwind-function fragment containing each
  candidate, when available.
- Whether a candidate belongs to the previously inspected bulk
  player-data field routine at `0x140807A9F`–`0x14080A449`.
  That routine is deprioritized, **not assumed to be image loading**.

The report caps the number of candidates, and exports at most 75
places for focused review. It does not automatically create
functions, decompile the full EXE or attach to the game.

## What is still unknown

This is a *byte-pattern and unwind-fragment research step*, not an
actual trace of the running MyNBA UI. A matching 16-bit read can
belong to an unrelated type, an assertion, a serializer, or UI.
The compiled game may also access ActionShotId through bitfield
operations that these limited signatures do not capture.

**To implement a hook**, we must confirm a function that consumes
the real player's action-shot ID in the action-photo resource request,
identify its team/asset eligibility condition, and validate the
result in disposable, backed-up **offline MyNBA**. Only then consider
a build-gated, fail-closed, opt-in hook. The current DLL is still a
skeleton and should **not** be installed.
