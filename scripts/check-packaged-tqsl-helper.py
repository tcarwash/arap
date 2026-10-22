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
    if len(sys.argv) != 2:
        raise SystemExit("usage: check-packaged-tqsl-helper.py ARCHIVE")
    archive = Path(sys.argv[1]).resolve()
    repo = Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(archive) as bundle, tempfile.TemporaryDirectory(prefix="arap-packaged-helper-") as temp:
        for name in ("arap-tqsl-sign", "libtqsllib.so", "config.xml"):
            target = Path(temp) / name
            target.write_bytes(bundle.read(name))
            target.chmod(0o700 if name == "arap-tqsl-sign" else 0o600)
        env = os.environ.copy()
        env["ARAP_TQSL_HELPER"] = str(Path(temp) / "arap-tqsl-sign")
        result = subprocess.run(["make", "enrollment-demo"], cwd=repo, env=env,
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
