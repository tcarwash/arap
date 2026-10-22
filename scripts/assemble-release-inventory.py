#!/usr/bin/env python3
"""Copy native CI bundles into release assets and assemble their license inventory."""
from __future__ import annotations

import argparse
import csv
import io
import zipfile
from pathlib import Path

TARGETS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, help="directory created by actions/download-artifact")
    parser.add_argument("output", type=Path, help="release asset output directory")
    parser.add_argument("version", help="release tag/version string")
    args = parser.parse_args()
    if not args.version.startswith("v0.1.0-beta."):
        parser.error("version must be a v0.1.0-beta.* tag")
    args.output.mkdir(parents=True, exist_ok=False)

    inventory: list[tuple[str, str, str, str]] = []
    for target in TARGETS:
        candidates = list(args.artifacts.glob(f"arap-desktop-supported-{target}/**/*.zip"))
        if len(candidates) != 1:
            raise SystemExit(f"expected one native CI archive for {target}, found {len(candidates)}")
        archive = candidates[0]
        with zipfile.ZipFile(archive) as bundle:
            names = set(bundle.namelist())
            required = {"BUILD-MANIFEST.txt", "TQSLLIB-LICENSE.txt", "GO-DEPENDENCY-NOTICES.csv"}
            if not (Path(__file__).resolve().parents[1] / "LICENSE").is_file():
                raise SystemExit("the project LICENSE is missing")
            required.add("LICENSE")
            if not required.issubset(names):
                raise SystemExit(f"{target} archive is missing its manifest or dependency notices")
            manifest = bundle.read("BUILD-MANIFEST.txt").decode("utf-8")
            if f"Target: {target}\n" not in manifest:
                raise SystemExit(f"{target} archive has a mismatched build manifest")
            if f"ARAP version: {args.version}\n" not in manifest:
                raise SystemExit(f"{target} archive was not built for release {args.version}")
            go_report = list(csv.reader(io.StringIO(bundle.read("GO-DEPENDENCY-NOTICES.csv").decode("utf-8"))))
            if not go_report or any(len(row) < 3 or row[2].lower() == "unknown" for row in go_report):
                raise SystemExit(f"{target} Go dependency report is incomplete")
            go_notice_count = sum(
                name.startswith("GO-DEPENDENCY-NOTICES/") and not name.endswith("/") for name in names
            )
            if go_notice_count < len(go_report):
                raise SystemExit(f"{target} archive lacks Go dependency license texts")
            for module, license_url, license_name, *_ in go_report:
                inventory.append((target, module, license_name, license_url))

            native_notices = [
                name for name in ("TQSLLIB-LICENSE.txt", "OPENSSL-LICENSE.txt", "VCPKG-DEPENDENCY-NOTICES.txt")
                if name in names
            ]
            if target.startswith("darwin-") and "OPENSSL-LICENSE.txt" not in names:
                raise SystemExit(f"{target} archive lacks macOS native dependency notices")
            if target == "windows-amd64" and "VCPKG-DEPENDENCY-NOTICES.txt" not in names:
                raise SystemExit(f"{target} archive lacks Windows native dependency notices")
            for notice in native_notices:
                inventory.append((target, notice.removesuffix(".txt"), "See bundled notice", notice))

        final_archive = args.output / f"arap-desktop-{target}-{args.version}.zip"
        final_archive.write_bytes(archive.read_bytes())

    report_path = args.output / "DEPENDENCY-LICENSE-INVENTORY.csv"
    with report_path.open("w", encoding="utf-8", newline="") as report:
        writer = csv.writer(report)
        writer.writerow(("target", "component", "license", "source_or_notice"))
        writer.writerows(inventory)
    print(f"Assembled {len(TARGETS)} tested bundles and {len(inventory)} dependency inventory rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
