#!/usr/bin/env python3
"""Run the synthetic enrollment flow with the helper extracted from a bundle."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: check-packaged-tqsl-helper.py ARCHIVE TARGET")
    archive = Path(sys.argv[1]).resolve()
    target = sys.argv[2]
    suffix = ".exe" if target == "windows-amd64" else ""
    repo = Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(archive) as bundle, tempfile.TemporaryDirectory(prefix="arap-packaged-helper-") as temp:
        names = [f"arap-tqsl-sign{suffix}", "config.xml"]
        if target.startswith("darwin-"):
            names.extend(name for name in bundle.namelist() if name.endswith(".dylib"))
        if target.startswith("linux-"):
            names.append("libtqsllib.so")
        for name in names:
            extracted = Path(temp) / name
            extracted.write_bytes(bundle.read(name))
            if name.startswith("arap-tqsl-sign") or name.endswith((".so", ".dylib")):
                extracted.chmod(0o700)
        env = os.environ.copy()
        env["ARAP_TQSL_HELPER"] = str(Path(temp) / f"arap-tqsl-sign{suffix}")
        env.setdefault("TRUSTEDQSL_SOURCE_DIR", ".trustedqsl-source")
        result = subprocess.run(["bash", "scripts/enrollment-demo.sh"], cwd=repo, env=env,
                                capture_output=True, text=True, check=False, timeout=300)
        output = result.stdout + result.stderr
        if result.returncode:
            sys.stderr.write(output)
            return result.returncode
        if "Synthetic enrollment, content signing, and challenge authentication completed." not in output:
            sys.stderr.write(output)
            raise SystemExit("packaged helper demo did not reach its success marker")
    print("Extracted bundle helper and TQSLLIB passed the synthetic enrollment/signing flow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
