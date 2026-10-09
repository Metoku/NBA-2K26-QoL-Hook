# Exact NBA 2K26 Steam Build — Portrait Research

The installed game fingerprint was provided by a local read-only Windows PowerShell
scan. It identifies **one tested installation**, not an officially published game
version, Steam build ID, hook address, or guarantee of compatibility.

| Property | Value |
| --- | --- |
| Executable | NBA2K26.exe |
| Architecture | x64 |
| File size | 1169221400 bytes |
| PE timestamp (UTC) | 2026-07-16T09:41:44+00:00 |
| SHA-256 | efbfce3d628e17a16d4cba0c28ed09767d21abef422adc49ca26752ed40a8a39 |

The PE timestamp is a compiler/linker field; it is **not** necessarily the
last official NBA 2K26 patch date. A different hash after an update means this
build may no longer match.

## Read-only portrait string probe (no Python installation)

A follow-up diagnostic scans the installed file for ASCII and UTF-16LE strings
such as 'portrait', 'headshot', and 'actionshot' and reports the relevant file
offset and context. Run from the extracted repository root:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\tools\portrait_string_probe.ps1" -Executable "C:\path\to\NBA2K26.exe" -Json

Replace the path to the executable. The scan can take some time because the
file is over 1 GB. It only reads the game executable on disk, with a maximum
of eight samples per distinct term and total counts reported per term.

The result:
- **May** provide useful static string references for later disassembly.
- **Does not** identify the portrait function, virtual memory addresses,
  safe patch bytes, or hooks by itself.
- **Does not** alter or attach to the game, inject a DLL, or change save files.
- May find no strings, because optimizations, packing, or indirection can
  prevent these exact terms from appearing in a native executable.
- Must not be used as justification for modifying random file offsets.

Share **only the JSON text report**, not copyrighted executable bytes.

## Further investigation

A game-specific runtime hook still requires *local code analysis* of this exact
build and reproduction of the Philadelphia-versus-Lakers portrait behavior.
The hook must be optional, fall back to default rendering when photos are
unavailable, and avoid player-team and portrait-ID writes. Test offline only
on backed-up MyNBA saves. No working function address has been established.

## Home/Away shoes

This is a separate issue and cannot be diagnosed from portrait strings.
