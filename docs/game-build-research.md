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


## October 9: nearby photo-mode UI strings (confirmed local evidence)

A second **read-only** PowerShell inspection decoded 2400 bytes of UTF-16LE
text beginning at file offset 65,876,000 in the exact executable above.
It produced the following neighboring labels, in order:

- `3D Logo (R)`, `Workmark`, `Style: %s`, `Pinned`, `MyPlayer`
- `Marquee Home`, `Marquee Away`, `Logo: %s`
- **`Photo: Force Real Photo`**
- **`Photo: Always Render`**
- **`Photo: Use Assigned Team`**
- **`Style: Action Shot`**
- **`Style: Head Shot`**
- `Player`, `Render Team Starter 0` through `Render Team Starter 4`,
  `Render Team Best Starter`, `Render Opponent Team Starter 0` through 4,
  `Render Best player of the game`, `Marquee Home Best Player`,
  `Marquee Away Best Player`, and `Portrait: %s`.

### Interpretation and limits

The labels **suggest** multiple photo-source policies already exist somewhere
in the executable. In particular, "Force Real Photo" sounds similar to the
desired MyNBA outcome. However, adjacency to logos, marquees, team starter
slots, and overlay canvases suggests a **presentation/arena graphics** feature,
not necessarily the MyNBA player-card portrait system.

The numeric policy values and some code/data references have since been
partially characterized below, but configuration storage, affected screens,
actual photo-selection behavior, and runtime selectability are unknown. The
string's FILE offset must never be used as a game-memory hook or patch target.

### Next research action

Identify *cross references* from executable code or data to the UTF-16LE
"Photo: Force Real Photo" string and neighboring choices, using validated
read-only local static analysis. Then determine whether that subsystem is
shared with the MyNBA player-card image-selection path. Investigate
`PortraitTeam`, `ActionShotTeam`, `PhotoId`, and `ActionShotId` as separate
leads, but do not assume all names in the executable map directly to the
DB2K Editor's current 507-field roster schema.

**Nothing in this finding establishes a callable runtime function, a safe
signature, or a working automatic override.** Keep the hook disabled until
a function and behavior have been verified on the exact build.

## October 9: executable cross-reference and pointer-table findings

Read-only executable scan results for the exact SHA-256 build listed above:

### Suspected mode-label formatting functions

| Purpose suggested by disassembly | Function entry RVA | Observation |
| --- | --- | --- |
| Photo-mode **label formatter** | `0x7205A0` | Reads an object-related value at offset `+0x1C`, selects a UTF-16 label |
| Photo-style **label formatter** | `0x720620` | Reads an object-related value at offset `+0x20`, selects a style label |

Within these functions, values apparently select textual names as follows:

- Photo mode: `0` = `Photo: Force Real Photo`, `1` = `Photo: Always Render`, `2` = `Photo: Use Assigned Team`.
- Style: `0` = `Style: Action Shot`, `1` = `Style: Head Shot`.

This mapping is confined to **the observed label-formatting code**;
it does **not** establish the same values for all photo-selection systems.

The parser also located two other code references to a UTF-16LE
`PortraitTeam` name: RVAs `0x1F397EE` and `0x2291B81`. The byte
contexts look like metadata-construction/handling logic, and neither has been
proven to control game portraits.

### Two unusually similar blocks of function pointers

The newest report found 64-bit data values referencing the two mode/style
label-formatting function entries:

| Data RVA (pointer slot) | Value in the executable | Interpretation |
| --- | --- | --- |
| `0x3ECCA78` | `0x00000001407205A0` | Points to photo-mode label formatter |
| `0x3ECCB38` | `0x0000000140720620` | Points to photo-style label formatter |

The slots differ by `0xC0` (192) bytes. Neighboring addresses at the same
relative positions in the two blocks also match (some entries differ),
consistent with **similarly laid-out C++ virtual-function tables or
function-pointer dispatch tables**.

This is **not yet a verified vtable**: the table start, RTTI metadata, and
owning C++ class are unknown. The exact image base suggested by pointer data
is `0x140000000` for this PE file. Example Ghidra VAs would be
`0x1403ECCA78` and `0x1403ECCB38` for the two pointer slots.
Do not confuse RVAs or file offsets with live ASLR-adjusted virtual addresses.

The probe found **zero** apparent direct `CALL rel32` invocations of these
formatting routines and **zero** simple code references to the individual
pointer slots. This is consistent with indirect C++ calls, where code
references a *table start* and then dispatches by method index; it is not
proof that the functions are never called.

### Practical next milestone (prefer real disassembly)

Avoid repeatedly extending narrow raw-byte scanners. Instead:

1. Open the **exact local NBA2K26.exe** in a read-only static analysis project
   in a disassembler (e.g., official
   [Ghidra](https://github.com/NationalSecurityAgency/ghidra)).
2. Inspect `0x1407205A0` / `0x140720620` to confirm the disassembled
   functions and signatures. Do **not** patch their `0/1/2` label values:
   these appear to format human-readable labels.
3. Navigate to the two data pointer slots `0x1403ECCA78` and
   `0x1403ECCB38`. Identify the beginnings of their containing tables,
   check if there is a Complete Object Locator (MSVC RTTI) and a type name,
   and inspect references to the **table address or containing object
   constructor**, not solely the individual function pointer slot.
4. Evaluate whether the owning class is arena/presentation display machinery
   or a MyNBA player portrait loader. If it is unrelated, pivot to the
   gameplay portrait request path and `PhotoId`/`ActionShotId` fields.
5. Only after locating the real photo-selection function should an **offline,
   version-gated, fail-closed** hook be developed and tested with backed-up
   MyNBA saves. A valid photo must exist to be selected.

Large game executables can require considerable analysis time and disk space.
Standard Ghidra desktop analysis requires a supported Java JDK; it does not
require installing system Python for normal GUI use. Refer to its
[official getting-started guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
for the requirements of the version installed.

**Research status:** No working automatic portrait override, no verified
portrait-selection function, and no safe patch bytes yet.

## Further investigation

A game-specific runtime hook still requires *local code analysis* of this exact
build and reproduction of the Philadelphia-versus-Lakers portrait behavior.
The hook must be optional, fall back to default rendering when photos are
unavailable, and avoid player-team and portrait-ID writes. Test offline only
on backed-up MyNBA saves. No working function address has been established.

## Home/Away shoes

This is a separate issue and cannot be diagnosed from portrait strings.
