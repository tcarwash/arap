#!/usr/bin/env python3
"""Collect licenses for TQSL helper dependencies redistributed in native bundles."""
from __future__ import annotations

import argparse
import os
import subprocess
import tarfile
from pathlib import Path


def openssl_source_license() -> str:
    subprocess.run(
        ["brew", "fetch", "--build-from-source", "--quiet", "openssl@3"],
        check=True,
    )
    archive = Path(
        subprocess.check_output(
            ["brew", "--cache", "--build-from-source", "openssl@3"],
            text=True,
        ).strip()
    )
    with tarfile.open(archive, "r:*") as source:
        matches = [member for member in source.getmembers() if Path(member.name).name == "LICENSE.txt"]
        if len(matches) != 1:
            raise RuntimeError(f"expected one OpenSSL LICENSE.txt in {archive}, found {len(matches)}")
        content = source.extractfile(matches[0])
        if content is None:
            raise RuntimeError("OpenSSL LICENSE.txt is not a regular file")
        return content.read().decode("utf-8")


def homebrew_source_license(formula: str, candidates: tuple[str, ...]) -> str:
    subprocess.run(["brew", "fetch", "--build-from-source", "--quiet", formula], check=True)
    archive = Path(subprocess.check_output(
        ["brew", "--cache", "--build-from-source", formula], text=True
    ).strip())
    with tarfile.open(archive, "r:*") as source:
        matches = [member for member in source.getmembers() if Path(member.name).name in candidates]
        if len(matches) != 1:
            raise RuntimeError(f"expected one license file for {formula} in {archive}, found {len(matches)}")
        content = source.extractfile(matches[0])
        if content is None:
            raise RuntimeError(f"{formula} license is not a regular file")
        return content.read().decode("utf-8")


def vcpkg_notices(root: Path) -> str:
    base = root / "installed" / "x64-windows-static" / "share"
    notices: list[str] = []
    for port in ("openssl", "sqlite3", "expat", "zlib"):
        notice = base / port / "copyright"
        if not notice.is_file():
            raise RuntimeError(f"vcpkg copyright notice missing for {port}: {notice}")
        notices.append(f"===== {port} =====\n{notice.read_text(encoding='utf-8').strip()}")
    return "\n\n".join(notices) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=("darwin-amd64", "darwin-arm64", "windows-amd64"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vcpkg-root", type=Path, default=os.environ.get("VCPKG_INSTALLATION_ROOT"))
    args = parser.parse_args()
    if args.target.startswith("darwin-"):
        parts = [
            ("OpenSSL 3", openssl_source_license()),
            ("Expat", homebrew_source_license("expat", ("COPYING", "LICENSE", "LICENSE.txt"))),
        ]
        notice = "\n\n".join(f"===== {name} =====\n{content.strip()}" for name, content in parts) + "\n"
        args.output.write_text(notice, encoding="utf-8")
    else:
        if args.vcpkg_root is None:
            raise SystemExit("VCPKG_INSTALLATION_ROOT or --vcpkg-root is required for Windows notices")
        args.output.write_text(vcpkg_notices(args.vcpkg_root), encoding="utf-8")
    print(f"Wrote dependency notices to {args.output}")


if __name__ == "__main__":
    main()
