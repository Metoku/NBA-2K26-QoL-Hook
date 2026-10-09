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
