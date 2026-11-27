"""
Package the extension for the Chrome Web Store.

    python3 dev/package_extension.py

Makes dist/phishing-email-detector-<version>.zip with:
- manifest.json at the root of the zip (the store requires this)
- the "key" field REMOVED from manifest.json. We use that public key during
  development to keep a fixed extension ID, but the store rejects uploads
  that contain it ("key field is not allowed in manifest").
- only the files the extension actually uses (no tests, no dev files)

It also refuses to package if the extension's copy of the detector is
stale, so you can't ship an extension that disagrees with the Python tool.
"""

import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
DIST = ROOT / "dist"

# Everything in extension/ ships, except these.
SKIP_NAMES = {".DS_Store", "Thumbs.db"}
SKIP_DIRS = {"__pycache__"}


def check_detector_copy():
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_extension_sync", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit("The extension's copy of the detector is out of date.\n"
                 "Run: python3 dev/build_extension.py, then try again.")


def main():
    check_detector_copy()
    manifest = json.loads((EXT / "manifest.json").read_text())
    manifest.pop("key", None)
    version = manifest["version"]

    DIST.mkdir(exist_ok=True)
    out = DIST / f"phishing-email-detector-{version}.zip"
    files = sorted(
        p for p in EXT.rglob("*")
        if p.is_file() and p.name not in SKIP_NAMES and not SKIP_DIRS & set(p.parts)
    )
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in files:
            rel = p.relative_to(EXT).as_posix()
            if rel == "manifest.json":
                zf.writestr(rel, json.dumps(manifest, indent=2) + "\n")
            else:
                zf.write(p, rel)

    size_mb = out.stat().st_size / 1_000_000
    print(f"Built {out.relative_to(ROOT)} ({len(files)} files, {size_mb:.1f} MB)")
    print(f"Version {version}. Each new upload needs a higher version in extension/manifest.json.")


if __name__ == "__main__":
    main()
