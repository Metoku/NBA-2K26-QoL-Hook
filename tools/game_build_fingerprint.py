#!/usr/bin/env python3
r"""Identify an installed Windows game executable build without modifying it.

Usage:
    python tools/game_build_fingerprint.py "C:\path\to\NBA2K26.exe" --json
No memory scanning, game attachment, or injection is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


def inspect_pe(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError("Executable file does not exist")
    size = path.stat().st_size
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("Not a Windows PE executable (MZ header missing)")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if pe_offset < 64 or pe_offset > size - 26:
            raise ValueError("Invalid PE header offset")
        stream.seek(pe_offset)
        coff = stream.read(26)
        if len(coff) != 26 or coff[:4] != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")
        machine, _sections, timestamp, _symbols, _count, optional_size, _flags = struct.unpack_from(
            "<HHIIIHH", coff, 4
        )
        if optional_size < 2 or pe_offset + 24 + optional_size > size:
            raise ValueError("Invalid PE optional header size")
        magic = struct.unpack_from("<H", coff, 24)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError("Invalid PE optional header magic")
        digest = hashlib.sha256()
        stream.seek(0)
        while chunk := stream.read(4 * 1024 * 1024):
            digest.update(chunk)

    return {
        "filename": path.name,
        "architecture": {0x8664: "x64", 0x014C: "x86"}.get(machine, f"unknown (0x{machine:04X})"),
        "file_size_bytes": size,
        "pe_timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
        "sha256": digest.hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path, help="Local Windows game executable path")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON only")
    args = parser.parse_args(argv)
    try:
        information = inspect_pe(args.executable)
    except (OSError, ValueError, OverflowError) as exc:
        print(f"Unable to inspect executable: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(information, indent=2))
    else:
        print("Game build fingerprint (read-only):")
        for key, value in information.items():
            print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
