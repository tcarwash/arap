#!/usr/bin/env python3
"""Validate the documented machine error schema against the real CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    schema_path = ROOT / "spec" / "ARAP-machine-error-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)

    with tempfile.TemporaryDirectory(prefix="arap-machine-schema-") as temp:
        temp_path = Path(temp)
        cli = temp_path / ("arap.exe" if os.name == "nt" else "arap")
        subprocess.run(["go", "build", "-o", str(cli), "./cmd/arap"],
                       cwd=ROOT, check=True, timeout=120)
        malformed = temp_path / "malformed.cose"
        malformed.write_bytes(b"not a COSE proof")

        cases = [
            (1, [str(cli), "inspect-proof", "--proof", str(malformed)]),
            (2, [str(cli), "resolve", "--server", "https://resolver.invalid",
                 "--reference", "malformed-reference", "--out", str(temp_path / "proof.cose")]),
        ]
        for expected_status, args in cases:
            env = os.environ.copy()
            env["ARAP_MACHINE"] = "1"
            result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True,
                                   timeout=10, check=False)
            if result.returncode != expected_status:
                raise AssertionError(
                    f"{args[1]} exited {result.returncode}, expected {expected_status}: "
                    f"{result.stderr.decode(errors='replace')}"
                )
            envelope = json.loads(result.stdout)
            jsonschema.validate(envelope, schema)

        sys.path.insert(0, str(ROOT / "interop" / "python"))
        from arap_interop import ArapError

        jsonschema.validate(ArapError("timeout", 124, "timed out").as_dict(), schema)

    print("Machine error schema validates live CLI errors and the Python error mapping.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
