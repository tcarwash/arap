#!/usr/bin/env python3
"""Exercise release assembly from a synthetic set of native CI artifacts."""
from __future__ import annotations

import csv
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "assemble-release-inventory.py"
TARGETS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="arap-release-inventory-") as temporary:
        root = Path(temporary)
        project = root / "project"
        (project / "scripts").mkdir(parents=True)
        (project / "LICENSE").write_text("synthetic project license\n", encoding="utf-8")
        script = project / "scripts" / SCRIPT.name
        script.write_bytes(SCRIPT.read_bytes())
        artifacts = root / "artifacts"
        for target in TARGETS:
            artifact_dir = artifacts / f"arap-desktop-supported-{target}"
            artifact_dir.mkdir(parents=True)
            archive = artifact_dir / "candidate.zip"
            members = {
                "BUILD-MANIFEST.txt": f"ARAP version: v0.1.0-beta.1\nTarget: {target}\n",
                "LICENSE": "synthetic project license\n",
                "TQSLLIB-LICENSE.txt": "synthetic TQSLLIB license\n",
                "GO-DEPENDENCY-NOTICES.csv": "example.org/dependency,https://example.org/LICENSE,MIT\n",
                "GO-DEPENDENCY-NOTICES/example.org/dependency/LICENSE": "synthetic dependency license\n",
            }
            if target.startswith("darwin-"):
                members["OPENSSL-LICENSE.txt"] = "synthetic OpenSSL and Expat license\n"
            if target == "windows-amd64":
                members["VCPKG-DEPENDENCY-NOTICES.txt"] = "synthetic vcpkg notices\n"
            with zipfile.ZipFile(archive, "w") as bundle:
                for name, content in members.items():
                    bundle.writestr(name, content)

        output = root / "release"
        subprocess.run([sys.executable, str(script), str(artifacts), str(output), "v0.1.0-beta.1"],
                       check=True, capture_output=True, text=True, timeout=30)
        archives = sorted(output.glob("arap-desktop-*.zip"))
        if len(archives) != len(TARGETS):
            raise SystemExit(f"expected {len(TARGETS)} versioned archives, found {len(archives)}")
        with (output / "DEPENDENCY-LICENSE-INVENTORY.csv").open(encoding="utf-8", newline="") as report:
            rows = list(csv.DictReader(report))
        if len(rows) != 18:
            raise SystemExit(f"expected 18 inventory rows, got {len(rows)}")
        print("Release assembly validated five target archives and all Go/native dependency inventory rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
