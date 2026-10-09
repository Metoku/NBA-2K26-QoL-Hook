import importlib.util
import io
from contextlib import redirect_stdout
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "compare_snapshots", ROOT / "tools" / "compare_snapshots.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CompareSnapshotsTests(unittest.TestCase):
    def test_player_reordering_is_not_a_change(self):
        before = {"players": [
            {"UniqueID": 10, "HeadshotID": 33, "CURRENTTEAM": 1},
            {"UniqueID": 20, "PortraitID": 44, "CURRENTTEAM": 2},
        ]}
        after = {"players": [
            {"UniqueID": 20, "PortraitID": 44, "CURRENTTEAM": 2},
            {"UniqueID": 10, "HeadshotID": 33, "CURRENTTEAM": 1},
        ]}
        self.assertEqual(list(MODULE.changes(before, after)), [])

    def test_trade_and_portrait_changes_are_detected(self):
        before = {"players": [{"UniqueID": 10, "CURRENTTEAM": 1, "PortraitID": 70}]}
        after = {"players": [{"UniqueID": 10, "CURRENTTEAM": 2, "PortraitID": 71}]}
        differences = list(MODULE.changes(before, after))
        self.assertEqual(len(differences), 2)
        self.assertEqual(
            {item["path"] for item in differences},
            {"$.players[UniqueID=10].CURRENTTEAM", "$.players[UniqueID=10].PortraitID"},
        )

    def test_missing_field(self):
        self.assertEqual(
            list(MODULE.changes({"a": 1}, {"a": 1, "b": 2})),
            [{"path": "$.b", "before": "<missing>", "after": 2}],
        )

    def test_index_fallback(self):
        self.assertEqual(
            list(MODULE.changes([1, 2], [1, 3])),
            [{"path": "$[1]", "before": 2, "after": 3}],
        )


    def test_db2k_records_match_by_index_after_reorder(self):
        before = {"domain": "Players", "records": [
            {"index": 12, "label": "Example A", "fields": {
                "Vitals/HEADSHOTID": {"display_value": 50, "raw_value": 50},
                "Vitals/CURRENTTEAM": {"display_value": "Team A", "raw_value": 100},
            }},
            {"index": 21, "label": "Example B", "fields": {
                "Vitals/PORTRAITID": {"display_value": 60, "raw_value": 60},
            }},
        ]}
        after = {"domain": "Players", "records": [
            {"index": 21, "label": "Example B", "fields": {
                "Vitals/PORTRAITID": {"display_value": 60, "raw_value": 60},
            }},
            {"index": 12, "label": "Example A", "fields": {
                "Vitals/HEADSHOTID": {"display_value": 50, "raw_value": 50},
                "Vitals/CURRENTTEAM": {"display_value": "Team B", "raw_value": 200},
            }},
        ]}
        changes = list(MODULE.changes(before, after))
        self.assertEqual(len(changes), 2)
        self.assertEqual(
            {entry["path"] for entry in changes},
            {
                "$.records[index=12].fields.Vitals/CURRENTTEAM.display_value",
                "$.records[index=12].fields.Vitals/CURRENTTEAM.raw_value",
            },
        )

    def test_focus_report_includes_unchanged_fields(self):
        before = {"records": [{"index": 9, "label": "Test Player", "fields": {
            "Vitals/HEADSHOTID": {"raw_value": 133, "display_value": 133},
            "Vitals/PORTRAITTEAM1": {"raw_value": 1, "display_value": "Team A"},
        }}]}
        after = {"records": [{"index": 9, "label": "Test Player", "fields": {
            "Vitals/HEADSHOTID": {"raw_value": 133, "display_value": 133},
            "Vitals/PORTRAITTEAM1": {"raw_value": 2, "display_value": "Team B"},
        }}]}
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(MODULE.print_target_report(before, after, 9))
        result = output.getvalue()
        self.assertIn("HEADSHOTID [unchanged]", result)
        self.assertIn("PORTRAITTEAM1 [CHANGED]", result)
        self.assertIn("SHOEHOME: <not exported>", result)

    def test_missing_db2k_record_is_reported(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertFalse(
                MODULE.print_target_report(
                    {"records": [{"index": 9, "fields": {}}]},
                    {"records": []},
                    9,
                )
            )
        self.assertIn("missing in one/both snapshots", output.getvalue())


if __name__ == "__main__":
    unittest.main()
