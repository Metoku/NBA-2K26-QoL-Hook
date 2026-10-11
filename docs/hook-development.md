# Automatic Portrait Hook: Build Research

**Target:** Preserve existing photo headshots and action portraits after MyNBA trades, automatically and without changing roster records.

## What is known

The three user-provided Joel Embiid snapshots showed stable headshot and portrait identifiers (4090) and stable portrait-team associations (Philadelphia 76ers). The current team changed between the Lakers, Kings, and 76ers. The user observed photos appearing on Philadelphia and not the other two teams.

This supports a team-dependent photo fallback, but it does **not** locate the rendering decision in NBA 2K26's code or prove that writing a team pointer would fix it. Manual attempts to edit portrait-team fields with DB2K Editor did not produce a working change. We are deliberately **not** building an automated roster editor.

## Required next step: identify exact game build

On the user's Windows PC, from a clone or downloaded ZIP of this repository, run in **Windows PowerShell (no Python installation needed)**:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\game_build_fingerprint.ps1" -Executable "C:\path\to\NBA2K26.exe" -Json

If Python is already installed, the original script is also available:

    python tools/game_build_fingerprint.py "C:\path\to\NBA2K26.exe" --json

Replace the quoted path with the Steam installation's actual executable path.

The tool never launches or attaches to NBA 2K26. It reads the PE header and calculates an SHA-256 checksum of the executable file. It outputs filename, CPU architecture, file size, PE timestamp, and SHA-256; it does not print the local filesystem path.

The executable should **not** be shared or committed to GitHub. Share only the printed metadata to match the local build with any later reverse-engineering findings.

**Important:** A fingerprint alone does not reveal a working hook address.

## Runtime hook investigation (still blocked)

1. Inspect the installed build in a local offline static analysis environment to identify possible image/portrait selection paths.
2. Confirm the selection behavior for **both** regular headshots and action portraits using backed-up offline MyNBA saves.
3. If a hook site can be identified, create a build-specific opt-in portrait selection override. Do **not** write CURRENTTEAM, CONTRACTTEAM, PORTRAITTEAM1, PORTRAITTEAM2, HEADSHOTID, or PORTRAITID just to force a portrait.
4. Never force unavailable images; generated players and players without photo assets should keep the normal fallback.
5. Fail closed on unknown executable versions and test save/load plus trades before any public release.

The current DLL still does **nothing** to NBA 2K26. GitHub Actions can compile and test our software, but it cannot discover the game's internal functions or validate behavior inside NBA 2K26.

## Shoe regression

Home/Away shoes are a separate editing and persistence issue and should be investigated independently once a genuine reproducible in-game trace exists.

## Safety

Local offline testing only. Back up saves. No anti-cheat bypass, no online-game modification, and no guessed production memory writes.

## 2026-10-11: External ASI loading feasibility and EAC risk

The user agreed in principle to installing a separate native DLL/ASI loader
for offline MyNBA testing. An ASI loader has **not** been installed or
validated in NBA 2K26. Asset-only `.iff` file loading from `mods` does not
imply an arbitrary native-plugin loader.

General-purpose candidate: ThirteenAG's open-source Ultimate ASI Loader,
which can use a proxy DLL named for an imported Windows library and load
`.asi` plugins in a `scripts` folder. Its advertised support is for games
that use compatible DLL imports; no NBA 2K26-specific compatibility proof
has yet been found.

**Crucial:** NBA 2K Support describes Easy Anti-Cheat for NBA 2K on PC
(https://support.nba2k.com/hc/en-us/articles/42216723600659-NBA-2K-Anti-Cheat-on-PC).
This means installing an unverified third-party native-code loader—even for
offline MyNBA—may cause launch failures or anti-cheat action. Do not install
or launch a loader as part of research without reliable game-specific
compatibility/support. We will not use instructions to disable or evade
EAC, and we will not try this in competitive modes.

To identify *candidate* native imports without loading plugins or touching
EAC, run Ghidra's read-only
`ghidra_scripts/NBA2K26ImportedDLLsReport.java` on the already imported
verified NBA2K26.exe build. It lists external library names that match
known ASI proxy DLL filenames. Even a matching name does not establish
loader compatibility or permission to run the loader in this game.

Until safe loading can be established, code changes must remain static or
execute in independent unit tests outside NBA 2K26. The portrait DLL has
no working runtime code hook.

### 2026-10-11: actual Ghidra external-library report

The user executed `NBA2K26ImportedDLLsReport.java` on the
verified NBA2K26.exe and the read-only report listed these names
as recognized x64 Ultimate ASI Loader proxy-DLL filename candidates:

| Ghidra external-library name | General loader has x64 proxy option |
|---|---|
| `VERSION.DLL` | Yes |
| `WINHTTP.DLL` | Yes |
| `WININET.DLL` | Yes |

All three appear in the verified build's Ghidra **external library
manager**. This is not yet a validated PE import descriptor report,
not proof that the loader is compatible with NBA 2K26, and not
proof that EAC will allow it. No third-party DLL has been installed.

The official Ultimate ASI Loader README documents all three names:
https://github.com/ThirteenAG/Ultimate-ASI-Loader
The official NBA 2K EAC documentation is:
https://support.nba2k.com/hc/en-us/articles/42216723600659-NBA-2K-Anti-Cheat-on-PC

**Next step:** independent game-specific confirmation that native
plugins are permitted and can load safely, or proceed with a
standalone simulation of the now-identified team-selection logic
outside the game. Do not deploy a proxy DLL on the basis of imports
alone, and do not bypass EAC.
