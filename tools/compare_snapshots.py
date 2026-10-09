#!/usr/bin/env python3
"""Compare two JSON roster snapshots without modifying them or the game.

Run: python tools/compare_snapshots.py before.json after.json
Use --all to list every changed field, not just portrait/team/shoe candidates.
"""
import argparse
import json
import sys
from pathlib import Path

CANDIDATES = ("portrait", "headshot", "photo", "face", "render", "team", "shoe")
IDENTITY_KEYS = ("UniqueID", "unique_id", "PLAYERID", "PlayerID", "player_id", "id", "ID")


def _indexed_by_key(items, key):
    if not items or not all(isinstance(item, dict) and key in item for item in items):
        return None
    # JSON keys are normalized to strings so integer identifiers compare reliably.
    identifiers = [str(item[key]) for item in items]
    if len(set(identifiers)) != len(identifiers):
        return None
    return {str(item[key]): item for item in items}


def _matched_list_maps(before, after):
    for key in IDENTITY_KEYS:
        left = _indexed_by_key(before, key)
        right = _indexed_by_key(after, key)
        if left is not None and right is not None:
            return key, left, right
    return None


def changes(before, after, path="$"):
    """Yield {path, before, after} differences, matching uniquely identified list records."""
    if type(before) is not type(after):
        yield {"path": path, "before": before, "after": after}
    elif isinstance(before, dict):
        for key in sorted(before.keys() | after.keys()):
            child = path + "." + str(key)
            if key not in before:
                yield {"path": child, "before": "<missing>", "after": after[key]}
            elif key not in after:
                yield {"path": child, "before": before[key], "after": "<missing>"}
            else:
                yield from changes(before[key], after[key], child)
    elif isinstance(before, list):
        matched = _matched_list_maps(before, after)
        if matched:
            key, left, right = matched
            for identifier in sorted(left.keys() | right.keys()):
                child = f"{path}[{key}={identifier}]"
                if identifier not in left:
                    yield {"path": child, "before": "<missing>", "after": right[identifier]}
                elif identifier not in right:
                    yield {"path": child, "before": left[identifier], "after": "<missing>"}
                else:
                    yield from changes(left[identifier], right[identifier], child)
        else:
            for index in range(max(len(before), len(after))):
                child = f"{path}[{index}]"
                if index >= len(before):
                    yield {"path": child, "before": "<missing>", "after": after[index]}
                elif index >= len(after):
                    yield {"path": child, "before": before[index], "after": "<missing>"}
                else:
                    yield from changes(before[index], after[index], child)
    elif before != after:
        yield {"path": path, "before": before, "after": after}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, help="JSON snapshot before trade/edit")
    parser.add_argument("after", type=Path, help="JSON snapshot after trade/edit")
    parser.add_argument("--all", action="store_true", help="Print all differences")
    parser.add_argument("--limit", type=int, default=60, help="Maximum printed changes (default: 60)")
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be greater than zero")

    try:
        with args.before.open(encoding="utf-8-sig") as stream:
            before = json.load(stream)
        with args.after.open(encoding="utf-8-sig") as stream:
            after = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Unable to read JSON snapshots: {exc}", file=sys.stderr)
        return 2

    differences = list(changes(before, after))
    candidates = [d for d in differences if any(word in d["path"].lower() for word in CANDIDATES)]
    selected = differences if args.all else candidates

    print(f"Total changed fields: {len(differences)}")
    print(f"Portrait/team/shoe candidate changes: {len(candidates)}")
    print(f"Showing: {'all changes' if args.all else 'candidate changes'}")
    for item in selected[:args.limit]:
        print(f"{item['path']}: {json.dumps(item['before'], ensure_ascii=False)} -> "
              f"{json.dumps(item['after'], ensure_ascii=False)}")
    if len(selected) > args.limit:
        print(f"... {len(selected) - args.limit} more (use --limit or --all)")
    if not selected and differences:
        print("No candidate fields changed. Use --all to inspect other differences.")
    if not differences:
        print("Snapshots are identical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
