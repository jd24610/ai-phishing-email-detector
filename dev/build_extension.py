"""
Build the extension's built-in detector.

Copies two things into extension/:
1. Our Python detector (detector/*.py + the model) -> extension/py/
2. Pyodide, which runs Python inside Chrome      -> extension/pyodide/

Run this after changing anything in detector/:
    python3 dev/build_extension.py

Pyodide comes from npm (the official package). If extension/pyodide/
already has the right version, it isn't downloaded again.
A test (tests/test_extension_sync.py) fails if extension/py/ is out of date.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTOR = ROOT / "detector"
EXT = ROOT / "extension"
PY_OUT = EXT / "py"
PYODIDE_OUT = EXT / "pyodide"

PYODIDE_VERSION = "314.0.8"
# Only the files needed to run plain Python. No extra packages.
PYODIDE_FILES = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm",
                 "python_stdlib.zip", "pyodide-lock.json", "package.json"]


def detector_files():
    """Every file the detector needs at run time: code, the model, and data files
    (like the Public Suffix List). Caches and hidden files are skipped."""
    return sorted(
        p.relative_to(ROOT).as_posix()
        for p in DETECTOR.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and not p.name.startswith(".")
        and p.suffix in {".py", ".json", ".dat"}
    )


def copy_detector():
    if PY_OUT.exists():
        shutil.rmtree(PY_OUT)
    listing = []
    for rel in detector_files():
        src = ROOT / rel
        dst = PY_OUT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        listing.append({"path": rel, "sha256": hashlib.sha256(src.read_bytes()).hexdigest()})
    (PY_OUT / "files.json").write_text(json.dumps(listing, indent=1))
    print(f"Copied {len(listing)} detector files to {PY_OUT.relative_to(ROOT)}/")


def have_pyodide():
    meta = PYODIDE_OUT / "package.json"
    return meta.is_file() and json.loads(meta.read_text()).get("version") == PYODIDE_VERSION \
        and all((PYODIDE_OUT / f).is_file() for f in PYODIDE_FILES)


def fetch_pyodide():
    if have_pyodide():
        print(f"Pyodide {PYODIDE_VERSION} already in place.")
        return
    with tempfile.TemporaryDirectory() as tmp:
        print(f"Downloading Pyodide {PYODIDE_VERSION} from npm...")
        subprocess.run(["npm", "pack", f"pyodide@{PYODIDE_VERSION}", "--silent"],
                       cwd=tmp, check=True, capture_output=True)
        tgz = next(Path(tmp).glob("pyodide-*.tgz"))
        with tarfile.open(tgz) as tar:
            tar.extractall(tmp, filter="data")   # "data" filter blocks path tricks in archives
        pkg = Path(tmp) / "package"
        if PYODIDE_OUT.exists():
            shutil.rmtree(PYODIDE_OUT)
        PYODIDE_OUT.mkdir(parents=True)
        for name in PYODIDE_FILES:
            shutil.copy2(pkg / name, PYODIDE_OUT / name)
    (PYODIDE_OUT / "NOTICE.txt").write_text(
        f"Pyodide {PYODIDE_VERSION} (https://pyodide.org), copied unchanged from the npm package.\n"
        "Licensed under the Mozilla Public License 2.0: https://www.mozilla.org/MPL/2.0/\n"
        "Includes CPython, licensed under the PSF License.\n")
    print(f"Pyodide copied to {PYODIDE_OUT.relative_to(ROOT)}/")


if __name__ == "__main__":
    copy_detector()
    if "--skip-pyodide" not in sys.argv:
        fetch_pyodide()
