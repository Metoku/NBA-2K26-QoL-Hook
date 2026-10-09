import importlib.util
import io
import pathlib
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from hashlib import sha256

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "game_build_fingerprint", ROOT / "tools" / "game_build_fingerprint.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sample_pe(*, timestamp=1_700_000_000, machine=0x8664):
    image = bytearray(512)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x84, machine, 1, timestamp, 0, 0, 0xF0, 0)
    struct.pack_into("<H", image, 0x98, 0x20B)
    return bytes(image)


class GameBuildFingerprintTests(unittest.TestCase):
    def test_extracts_build_identity(self):
        content = sample_pe()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "NBA2K26.exe"
            path.write_bytes(content)
            result = MODULE.inspect_pe(path)
        self.assertEqual(result["filename"], "NBA2K26.exe")
        self.assertEqual(result["architecture"], "x64")
        self.assertEqual(result["file_size_bytes"], len(content))
        self.assertEqual(result["sha256"], sha256(content).hexdigest())
        self.assertEqual(result["pe_timestamp_utc"], "2023-11-14T22:13:20+00:00")

    def test_detects_invalid_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.exe"
            path.write_bytes(b"not-a-pe")
            with self.assertRaisesRegex(ValueError, "MZ header"):
                MODULE.inspect_pe(path)

    def test_rejects_invalid_pe_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.exe"
            image = bytearray(sample_pe())
            struct.pack_into("<I", image, 0x3C, len(image))
            path.write_bytes(image)
            with self.assertRaisesRegex(ValueError, "Invalid PE header offset"):
                MODULE.inspect_pe(path)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "NBA2K26.exe"
            path.write_bytes(sample_pe())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(MODULE.main([str(path), "--json"]), 0)
            self.assertIn('"architecture": "x64"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
