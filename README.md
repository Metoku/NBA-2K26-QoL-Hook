# NBA 2K26 QoL Hook

An experimental, community-made Windows x64 C++ project for investigating quality-of-life improvements for the **Steam edition of NBA 2K26**, focused on offline MyNBA.

## Goals (not yet implemented)

- Keep existing photo/headshot portraits displayed after players change teams.
- Keep existing action portraits displayed after players change teams.
- Investigate a Home/Away shoe assignment regression in Edit Player.

**Current status:** Build-system skeleton only. The DLL currently makes **no changes to the game** and does not hook, inject, or patch anything. All game-specific features require further research and local verification.

## Build

GitHub Actions uses the `windows-latest` runner and CMake with the Visual Studio 2022 x64 generator; no local C++ installation is needed to produce build artifacts.

To build locally with MSVC and CMake:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The release DLL is typically at `build/Release/NBA2K26QoLHook.dll`. A smoke test loads this DLL and verifies a version export, **without launching the game**.

On GitHub, open **Actions → Windows x64 Build → Run workflow** after the workflow is committed, or let it run on `main` pushes. Download the `NBA2K26QoLHook-windows-x64` artifact from the finished run.

## Portrait diagnosis (research-only)

The first investigation tool is a local JSON snapshot comparator (standard Python 3, no extra packages):

```powershell
python tools/compare_snapshots.py before.json after.json
python tools/compare_snapshots.py before.json after.json --all
python tools/compare_snapshots.py before.json after.json --record-index 123
```

See [the offline MyNBA portrait test protocol](docs/portrait-investigation.md) for what to capture. The comparator does not read game memory or generate exports; a separate tool must supply valid JSON snapshots from the same MyNBA context. The `--record-index` option matches DB2K Editor's exported player records and reports the relevant portrait/team/shoe fields even when unchanged. Replace `123` with the player's actual `index` from the export. No portrait override is implemented yet.

## Automatic Hook investigation (not yet implemented)

The three offline MyNBA snapshots show a team-dependent portrait fallback, but the runtime image-selection function is still unknown. We are moving toward an **automatic, portrait-only override**, not per-player roster edits.

To fingerprint your installed Steam build without launching the game or installing Python, use **Windows PowerShell** (included with Windows):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\game_build_fingerprint.ps1" -Executable "C:\path\to\NBA2K26.exe" -Json
```

Replace the quoted executable path with the actual NBA 2K26 Steam executable. Run the command from the repository's root directory. This reads the game file without launching or changing it.

Alternative (Python 3.11+ if already installed):

```powershell
python tools/game_build_fingerprint.py "C:\path\to\NBA2K26.exe" --json
```

The report contains executable metadata and a SHA-256 hash. It does **not** identify hook addresses. Read the [automatic hook development notes](docs/hook-development.md) before attempting any modifications.

## Limitations and safety

- This skeleton is not a usable NBA 2K26 mod yet. Do not place the DLL in your game directory or attempt to inject it.
- No NBA 2K26 offsets, pointer layouts, injection mechanisms, or portrait/shoe fixes have been validated.
- Test future changes only in offline MyNBA with backed-up saves. Do not bypass anti-cheat or modify online play.
- NBA 2K26 and related trademarks belong to their respective owners; this project is unofficial.

## Roadmap

1. Get a reproducible Windows x64 DLL build and successful smoke test.
2. Document reproducible portrait behavior on an offline MyNBA test save.
3. Identify the exact installed game build and investigate the portrait-selection routine.
4. Add a validated opt-in automatic portrait override (no roster writes).
5. Investigate the Home/Away shoe regression separately.
6. Release only after in-game testing on backed-up offline saves.
