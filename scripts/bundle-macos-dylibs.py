#!/usr/bin/env python3
"""Copy non-system dylib dependencies beside the TQSL helper and rewrite loads."""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")


def command(*args: str) -> str:
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"{args[0]} failed")
    return result.stdout


def dependencies(binary: Path) -> list[str]:
    lines = command("otool", "-L", str(binary)).splitlines()
    return [line.strip().split(" (", 1)[0] for line in lines[1:] if line[:1].isspace()]


def rpaths(binary: Path) -> list[Path]:
    lines = command("otool", "-l", str(binary)).splitlines()
    result: list[Path] = []
    for index, line in enumerate(lines):
        if line.strip() != "cmd LC_RPATH":
            continue
        for candidate in lines[index + 1 : index + 5]:
            fields = candidate.strip().split()
            if len(fields) >= 2 and fields[0] == "path":
                result.append(Path(fields[1]))
                break
    return result


def expand_loader_path(value: str, owner: Path, executable_dir: Path) -> Path:
    if value.startswith("@loader_path/"):
        return owner.parent / value.removeprefix("@loader_path/")
    if value.startswith("@executable_path/"):
        return executable_dir / value.removeprefix("@executable_path/")
    return Path(value)


def resolve(load: str, owner: Path, executable_dir: Path) -> Path | None:
    if load.startswith(SYSTEM_PREFIXES):
        return None
    direct = expand_loader_path(load, owner, executable_dir)
    if direct.is_file():
        return direct.resolve()
    if load.startswith("@rpath/"):
        suffix = load.removeprefix("@rpath/")
        for root in rpaths(owner):
            expanded = expand_loader_path(str(root), owner, executable_dir)
            candidate = expanded / suffix
            if candidate.is_file():
                return candidate.resolve()
    raise RuntimeError(f"cannot resolve non-system dylib {load!r} referenced by {owner}")


def bundle(binary: Path) -> None:
    binary = binary.resolve()
    destination = binary.parent
    queue = [binary]
    processed: set[Path] = set()
    copied: dict[Path, Path] = {}
    names: dict[str, Path] = {}
    while queue:
        owner = queue.pop()
        if owner in processed:
            continue
        processed.add(owner)
        for load in dependencies(owner):
            source = resolve(load, owner, binary.parent)
            if source is None:
                continue
            name = source.name
            bundled = destination / name
            known_source = names.get(name)
            if known_source is not None and known_source != source:
                if bundled.exists() and source == bundled.resolve():
                    source = known_source
                else:
                    raise RuntimeError(f"multiple dylibs with the same basename: {name}")
            previous = copied.get(source)
            if previous is None:
                names[name] = source
                if not bundled.exists() or source != bundled.resolve():
                    shutil.copy2(source, bundled)
                copied[source] = bundled
                queue.append(bundled.resolve())
                source_id = command("otool", "-D", str(bundled)).splitlines()
                if len(source_id) > 1 and source_id[1].strip():
                    subprocess.run(
                        ["install_name_tool", "-id", f"@loader_path/{name}", str(bundled)],
                        check=True,
                    )
            elif previous != bundled:
                raise RuntimeError(f"multiple dylibs with the same basename: {name}")
            subprocess.run(
                ["install_name_tool", "-change", load, f"@loader_path/{name}", str(owner)],
                check=True,
            )
    unresolved = [
        load
        for owner in [binary, *(destination / path.name for path in copied)]
        for load in dependencies(owner)
        if any(prefix in load for prefix in ("/opt/homebrew/", "/usr/local/opt/"))
    ]
    if unresolved:
        raise RuntimeError("Homebrew paths remain after bundling: " + ", ".join(unresolved))
    print(f"Bundled {len(copied)} non-system macOS libraries beside {binary.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("helper", type=Path)
    args = parser.parse_args()
    bundle(args.helper)


if __name__ == "__main__":
    main()
