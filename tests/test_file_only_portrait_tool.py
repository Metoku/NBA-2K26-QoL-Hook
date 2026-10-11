"""Regression guard: the standalone portrait EXE must NEVER access game processes."""
from pathlib import Path
import re
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "src" / "portrait_tool.cpp").read_text(
    encoding="utf-8"
)

class FileOnlyPortraitToolTests(unittest.TestCase):
    def test_no_live_process_access_apis(self):
        forbidden = [
            "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "Module32First", "Module32Next", "QueryFullProcessImageName",
            "VirtualProtectEx", "CreateRemoteThread", "NtOpenProcess",
        ]
        for api in forbidden:
            with self.subTest(api=api):
                self.assertIsNone(re.search(r"\b" + api + r"(?:W|A)?\s*\(", SOURCE))

    def test_explicit_file_only_requirements(self):
        self.assertIn("CreateFileW(", SOURCE)
        self.assertIn("RvaToFileOffset(", SOURCE)
        self.assertIn("CheckFingerprint(", SOURCE)
        self.assertIn("if (argc == 2) return InspectFile(argv[1]);", SOURCE)
        self.assertNotIn("LocateGame(", SOURCE)

if __name__ == "__main__":
    unittest.main()
