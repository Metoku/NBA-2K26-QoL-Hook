# NBA 2K26 — offline-only ASI loader smoke test

**STATUS: NOT YET VERIFIED IN THE GAME. THIS IS NOT A PORTRAIT FIX.**

The NBA 2K26 Steam launch configuration explicitly provides
`NBA 2K26 without EAC (offline only)` as an alternative to
`Play NBA 2K26`. The game executable runs directly for this choice:
https://steamdb.info/app/3472040/config/

This probe requires **no modification** of the installed game executable,
save records, EAC files, or Windows system DLLs. It is a temporary test of
whether a general-purpose ASI plugin can be loaded in the game's
official offline launch option. Never run native mod-loading experiments
with the protected/default launch or online modes.

## Build files

Our research branch builds:
- `NBA2K26PortraitProbe.asi` — harmless plugin load check only.
- `NBA2K26QoLHook.dll` — the earlier read-only SHA and branch verifier;
  no portrait hooks and **not** needed for this smoke test.

The `.asi` creates a single log file in the Windows `%TEMP%` folder
**only after** the game process loads the plugin:
`NBA2K26PortraitProbe_<game-process-PID>.txt`.
It contains a clear statement that no portrait patch was applied.
If it was not loaded, no marker is created. This is not an assertion
that later code hooking will be compatible.

Build using the repository's Windows x64 GitHub Actions workflow or
locally with Visual Studio 2022/CMake. Before using an Actions artifact,
check that the Windows build **passed** on your chosen commit.

## General-purpose proxy candidate (not confirmed for this game)

The Ghidra external-library list for our SHA-256-verified NBA2K26.exe
included `VERSION.DLL`, `WINHTTP.DLL`, `WININET.DLL`.
ThirteenAG's Ultimate ASI Loader offers x64 proxy DLL names for all
three: https://github.com/ThirteenAG/Ultimate-ASI-Loader

**The general loader is not endorsed by 2K and is not verified to
work with this game.** If the user elects to do the offline-only
experiment despite that uncertainty, use the x64 official release
(NOT the 32-bit zip) and try only one proxy candidate at a time,
starting with `version.dll` **only if it is absent from the game
directory already**. Do not replace any existing same-name file.

1. Back up the MyNBA save, and close NBA 2K26 and Steam overlay tools.
2. Check the Steam game directory (containing `NBA2K26.exe`). Keep a
   list of any new files; never touch `C:\\Windows\\System32`.
3. In Steam select the built-in `NBA 2K26 without EAC (offline only)`
   launch. Confirm the unmodified game starts in this mode first.
4. Only after the clean offline startup works: close the game, add the
   **x64** ASI loader under one of the recognized proxy names, and put
   `NBA2K26PortraitProbe.asi` inside a `scripts` folder next to
   `NBA2K26.exe`. The existing `mods` folder is unchanged.
5. Launch only with the built-in Steam **without EAC (offline only)**
   option. Do not open competitive/online modes.
6. Press Win+R, enter `%TEMP%`, and look for
   `NBA2K26PortraitProbe_*.txt`. Its presence with a recent timestamp
   and a matching game PID is evidence that the probe loaded.
7. If the game crashes or fails to start: close it and remove ONLY
   the newly added ASI proxy and `.asi` test plugin; undo the
   temporary `scripts` folder if empty.
8. **Always remove the proxy and ASI plugin before switching back**
   to the default protected launch. Keep the original EXE and all
   Windows system DLLs unchanged.

The use of an officially available EAC-free launch does **not**
constitute authorization from 2K for any particular modification.
A native ASI loader may still be incompatible or violate game terms.
Do not use anti-cheat bypasses, manual EAC file manipulation or
evasive injection methods.

## What successful loading would prove

Only: **the plugin was loaded into an offline NBA2K26.exe process.**

It would **not** prove:
- the team-mismatch branch overrides are safe;
- portraits will survive trades;
- absent player photos will fall back correctly;
- that the original `NBA2K26QoLHook.dll` is suitable for installation.

Next stage after successful no-op probe: develop a separate, opt-in
offline-only portrait test hook, preserving the team's null references
and resource checks and recording matched game build hashes.

## Diagnostic update after failed version.dll startup

The user's NBA2K26.exe **launched again immediately after removing
only the test copy of `version.dll`**. This strongly implicates the
loader/proxy path, but does not distinguish loader incompatibility from
a failure initializing the `.asi` plugin. No proof of a native-code
loading mechanism in the game yet.

The ASI probe has been corrected to export `InitializeASI`, the
entry point documented by Ultimate ASI Loader, and **does not spawn
a thread or write files from `DllMain`**. The loader documentation:
https://github.com/ThirteenAG/Ultimate-ASI-Loader/blob/master/readme.md

For diagnosis, keep the game working with `version.dll` removed.
If continuing with a controlled test, **only use Steam's built-in
offline-without-EAC launch** and first isolate the components:
remove `NBA2K26PortraitProbe.asi` from the game `scripts` folder,
then (only if explicitly willing) try the same x64 `version.dll`
alone and record any error. Remove the temporary DLL afterward.
- Fails without an ASI: the proxy loader itself is incompatible
  or misconfigured for this installation.
- Starts without an ASI: the original test plugin or the combination
  was responsible; try ONLY a newly rebuilt probe with
  `InitializeASI` after verifying the latest CI build passed.

If an error dialog appears, capture its precise text; alternatively
view Windows Reliability Monitor for the faulting module name.
Do not attempt alternate `winhttp.dll`/`wininet.dll` proxies,
random system DLL replacement, or anti-cheat interference
without game-specific compatibility evidence.

`NBA2K26QoLHook.dll` remains read-only. The photographic portrait
hook has not been implemented or in-game tested.
