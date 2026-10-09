import importlib.util
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


if __name__ == "__main__":
    unittest.main()
