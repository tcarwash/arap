#!/usr/bin/env python3
"""Check required files and metadata in a generated ARAP platform bundle."""
from __future__ import annotations

import sys
import json
import posixpath
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path


def main() -> int:
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: check-desktop-bundle.py ARCHIVE TARGET [--enrollment]")
    archive = Path(sys.argv[1])
    target = sys.argv[2]
    enrollment = len(sys.argv) == 4 and sys.argv[3] == "--enrollment"
    if len(sys.argv) == 4 and not enrollment:
        raise SystemExit("the only supported optional argument is --enrollment")
    executable_suffix = ".exe" if target == "windows-amd64" else ""
    launcher = "arap-desktop.bat" if target == "windows-amd64" else "arap-desktop.sh"
    required = {
        f"arap{executable_suffix}",
        f"arap-keyserver{executable_suffix}",
        "arap_desktop.py",
        launcher,
        "README.md",
        "PROJECT-README.md",
        "BUILD-MANIFEST.txt",
        "FIRST-RUN.md",
        "BUG_REPORT_TEMPLATE.md",
        "docs/API-CAPABILITIES.md",
        "docs/MACHINE-INTERFACE.md",
        "docs/IDENTITY-LIFECYCLE.md",
        "docs/CHALLENGES.md",
        "docs/KEYSERVER.md",
        "spec/ARAP-machine-error-v1.schema.json",
        "interop/python/README.md",
        "interop/python/arap_interop/client.py",
        "examples/content-proof/main.go",
        "examples/mutual-auth/main.go",
        "ARAP-profile-v1.cddl",
        "ARAP-challenge-v1.cddl",
        "ARAP-challenge-response-v1.cddl",
        "ARAP-lotw-enrollment-v1.cddl",
        "ARAP-lotw-enrollment-v2.cddl",
        "ARAP-lotw-enrollment-response-v1.cddl",
        "ARAP-key-endorsement-v1.cddl",
        "ARAP-key-endorsement-chain-v1.cddl",
        "PixelQSO-card-v1.cddl",
    }
    if target == "linux-amd64" or enrollment:
        required |= {f"arap-tqsl-sign{executable_suffix}", "config.xml", "TQSLLIB-LICENSE.txt"}
        if target.startswith("linux-"):
            required.add("libtqsllib.so")
        elif enrollment and target.startswith("darwin-"):
            required.add("OPENSSL-LICENSE.txt")
        elif enrollment and target == "windows-amd64":
            required.add("VCPKG-DEPENDENCY-NOTICES.txt")
    with zipfile.ZipFile(archive) as bundle:
        bad_member = bundle.testzip()
        if bad_member:
            raise SystemExit(f"corrupt bundle member: {bad_member}")
        names = set(bundle.namelist())
        missing = sorted(required - names)
        if missing:
            raise SystemExit(f"bundle is missing required files: {', '.join(missing)}")
        broken_links: list[str] = []
        for name in names:
            if not name.endswith(".md"):
                continue
            markdown = bundle.read(name).decode("utf-8")
            for link_target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", markdown):
                link_target = link_target.split("#", 1)[0]
                if not link_target or ":" in link_target or link_target.startswith("/"):
                    continue
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), link_target))
                if resolved not in names and not any(item.startswith(resolved.rstrip("/") + "/") for item in names):
                    broken_links.append(f"{name} -> {link_target}")
        if broken_links:
            raise SystemExit("bundle has broken documentation links: " + "; ".join(broken_links))
        forbidden = sorted(name for name in names if name.endswith((".sqlite", ".sqlite3", ".pem", ".p12", ".pfx")))
        if forbidden:
            raise SystemExit(f"bundle unexpectedly contains private or local state files: {', '.join(forbidden)}")
        manifest = bundle.read("BUILD-MANIFEST.txt").decode("utf-8")
        if f"Target: {target}\n" not in manifest:
            raise SystemExit("bundle target does not match the requested target")
        if target == "linux-amd64":
            with tempfile.TemporaryDirectory(prefix="arap-bundle-check-") as temp:
                for executable, command in (("arap", ["version", "--json"]),
                                            ("arap-keyserver", ["version", "--json"])):
                    bundle.extract(executable, temp)
                    binary = Path(temp) / executable
                    binary.chmod(0o700)
                    result = subprocess.run([str(binary), *command], capture_output=True,
                                            text=True, check=False, timeout=10)
                    if result.returncode:
                        raise SystemExit(f"bundled {executable} version command failed")
                    info = json.loads(result.stdout)
                    if info.get("version") != _field(manifest, "ARAP version") or info.get("commit") != _field(manifest, "Git base commit"):
                        raise SystemExit(f"bundled {executable} version metadata does not match the manifest")
            license_text = bundle.read("TQSLLIB-LICENSE.txt").decode("utf-8")
            if "American Radio Relay League" not in license_text or "Redistribution" not in license_text:
                raise SystemExit("TQSLLIB redistribution notice is incomplete")
        if enrollment:
            with tempfile.TemporaryDirectory(prefix="arap-helper-smoke-") as temp:
                helper_name = f"arap-tqsl-sign{executable_suffix}"
                bundle.extract(helper_name, temp)
                if target.startswith("linux-"):
                    bundle.extract("libtqsllib.so", temp)
                helper = Path(temp) / helper_name
                if target != "windows-amd64":
                    helper.chmod(0o700)
                result = subprocess.run([str(helper)], capture_output=True, text=True,
                                        check=False, timeout=15)
                if result.returncode != 2 or "valid --callsign is required" not in result.stderr:
                    raise SystemExit("bundled TQSL helper failed its extracted runtime smoke check")
            license_text = bundle.read("TQSLLIB-LICENSE.txt").decode("utf-8")
            if "American Radio Relay League" not in license_text or "Redistribution" not in license_text:
                raise SystemExit("TQSLLIB redistribution notice is incomplete")
            if target.startswith("darwin-") and any(
                name not in bundle.read("OPENSSL-LICENSE.txt").decode("utf-8")
                for name in ("OpenSSL", "Expat")
            ):
                raise SystemExit("macOS dependency redistribution notices are incomplete")
            if target == "windows-amd64" and any(
                name not in bundle.read("VCPKG-DEPENDENCY-NOTICES.txt").decode("utf-8")
                for name in ("openssl", "sqlite3", "expat", "zlib")
            ):
                raise SystemExit("vcpkg dependency notices are incomplete")
    print(f"{target} bundle verified: {archive}")
    return 0


def _field(manifest: str, name: str) -> str:
    prefix = name + ": "
    for line in manifest.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise SystemExit(f"build manifest is missing {name}")


if __name__ == "__main__":
    raise SystemExit(main())
