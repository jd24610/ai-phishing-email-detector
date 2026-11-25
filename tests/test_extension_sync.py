"""
The Chrome extension carries its own copy of the detector (extension/py/).
This test fails if that copy is out of date, so the extension and the
Python tool can never quietly give different answers.

Fix a failure by running:
    python3 dev/build_extension.py
"""

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
PY = ROOT / "extension" / "py"


class TestExtensionCopy(unittest.TestCase):

    def test_extension_detector_is_up_to_date(self):
        listing = json.loads((PY / "files.json").read_text())
        listed = {f["path"] for f in listing}

        expected = {
            p.relative_to(ROOT).as_posix()
            for p in (ROOT / "detector").rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and not p.name.startswith(".")
            and p.suffix in {".py", ".json", ".dat"}
        }
        self.assertEqual(listed, expected, "Run: python3 dev/build_extension.py")

        for f in listing:
            original = hashlib.sha256((ROOT / f["path"]).read_bytes()).hexdigest()
            copy = hashlib.sha256((PY / f["path"]).read_bytes()).hexdigest()
            self.assertEqual(copy, original, f"{f['path']} is stale. Run: python3 dev/build_extension.py")

    def test_pyodide_is_bundled(self):
        for name in ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip"]:
            self.assertTrue((ROOT / "extension" / "pyodide" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
