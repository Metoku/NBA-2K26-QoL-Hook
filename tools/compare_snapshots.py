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
IDENTITY_KEYS = ("UniqueID", "unique_id", "PLAYERID", "PlayerID", "player_id", "id", "ID", "index")
TARGET_FIELDS = (
    "HEADSHOTID", "PORTRAITID", "PORTRAITTEAM1", "PORTRAITTEAM2",
    "CURRENTTEAM", "SHOEHOME", "SHOEAWAY", "SHOEHOMECOLORWAY",
    "SHOEAWAYCOLORWAY",
)


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



def _find_db2k_record(snapshot, record_index):
    """Return a player record from a DB2K roster export using its stable record index."""
    if not isinstance(snapshot, dict):
        return None
    rows = snapshot.get("records", [])
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and str(row.get("index")) == str(record_index):
            return row
    return None


def _target_values(snapshot, record_index):
    record = _find_db2k_record(snapshot, record_index)
    if record is None:
        return None, {}
    fields = record.get("fields", {})
    if not isinstance(fields, dict):
        return record, {}
    # DB2K stores keys as SECTION/NORMALIZED_NAME. The section is not assumed.
    values = {}
    for full_name, value in fields.items():
        if not isinstance(full_name, str):
            continue
        name = full_name.rsplit("/", 1)[-1].upper()
        if name in TARGET_FIELDS and name not in values:
            values[name] = value
    return record, values


def _format_field_value(value):
    if value is None:
        return "<not exported>"
    if isinstance(value, dict) and ("display_value" in value or "raw_value" in value):
        return f"display={value.get('display_value')!r}; raw={value.get('raw_value')!r}"
    return repr(value)


def print_target_report(before, after, record_index):
    """Show relevant DB2K fields even when values did not change after a trade."""
    before_record, old_fields = _target_values(before, record_index)
    after_record, new_fields = _target_values(after, record_index)
    if before_record is None or after_record is None:
        print(f"DB2K record index {record_index} missing in one/both snapshots.")
        print("Choose the same loaded roster/player index in both exports.")
        return False
    print(f"\nDB2K record index {record_index}")
    print(f"Label before: {before_record.get('label', '<unknown>')}")
    print(f"Label after:  {after_record.get('label', '<unknown>')}")
    available = set(old_fields) | set(new_fields)
    if not available:
        print("No target fields exported. An absence is inconclusive.")
        return True
    for name in TARGET_FIELDS:
        if name not in available:
            print(f"{name}: <not exported>")
            continue
        changed = old_fields.get(name) != new_fields.get(name)
        print(f"{name} [{'CHANGED' if changed else 'unchanged'}]")
        print(f"  before: {_format_field_value(old_fields.get(name))}")
        print(f"  after:  {_format_field_value(new_fields.get(name))}")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, help="JSON snapshot before trade/edit")
    parser.add_argument("after", type=Path, help="JSON snapshot after trade/edit")
    parser.add_argument("--all", action="store_true", help="Print all differences")
    parser.add_argument("--record-index", type=int, help="Focus on one DB2K player index and report target fields, including unchanged values")
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
    if args.record_index is not None:
        if not print_target_report(before, after, args.record_index):
            return 2
        prefix = f"$.records[index={args.record_index}]"
        selected = [item for item in selected if item["path"].startswith(prefix)]

    print(f"Total changed fields: {len(differences)}")
    print(f"Portrait/team/shoe candidate changes: {len(candidates)}")
    print(f"Showing: {'all changes' if args.all else 'candidate changes'}" +
          (f" for record index {args.record_index}" if args.record_index is not None else ""))
    for item in selected[:args.limit]:
        print(f"{item['path']}: {json.dumps(item['before'], ensure_ascii=False)} -> "
              f"{json.dumps(item['after'], ensure_ascii=False)}")
    if len(selected) > args.limit:
        print(f"... {len(selected) - args.limit} more (use --limit or --all)")
    if not selected and differences:
        print("No changes matched the current filter. Use --all to inspect other differences.")
    if not differences:
        print("Snapshots are identical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
