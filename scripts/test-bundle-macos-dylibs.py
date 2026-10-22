#!/usr/bin/env python3
"""Exercise macOS dylib copying and load-path rewriting without macOS tools."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("bundle-macos-dylibs.py")
SPEC = importlib.util.spec_from_file_location("bundle_macos_dylibs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
bundler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundler)


class MacDylibBundlerTests(unittest.TestCase):
    def test_copies_transitive_dependencies_and_rewrites_load_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="arap-macos-bundler-test-") as temp:
            root = Path(temp)
            homebrew = root / "homebrew"
            bundle = root / "bundle"
            homebrew.mkdir()
            bundle.mkdir()
            helper = bundle / "arap-tqsl-sign"
            openssl = homebrew / "libcrypto.3.dylib"
            zlib = homebrew / "libz.1.dylib"
            helper.write_bytes(b"helper")
            openssl.write_bytes(b"openssl")
            zlib.write_bytes(b"zlib")

            def deps(binary: Path) -> list[str]:
                if binary.name == helper.name:
                    return [str(openssl)]
                if binary.name == openssl.name:
                    return ["@rpath/libz.1.dylib"]
                return []

            def otool_dylib_id(_program: str, _option: str, path: str) -> str:
                return f"{path}:\n{path}\n"

            with (
                patch.object(bundler, "dependencies", side_effect=deps),
                patch.object(bundler, "rpaths", return_value=[homebrew]),
                patch.object(bundler, "command", side_effect=otool_dylib_id),
                patch.object(bundler.subprocess, "run") as run,
            ):
                bundler.bundle(helper)

            self.assertEqual((bundle / openssl.name).read_bytes(), b"openssl")
            self.assertEqual((bundle / zlib.name).read_bytes(), b"zlib")
            invocations = [entry.args[0] for entry in run.call_args_list]
            self.assertIn(
                ["install_name_tool", "-change", str(openssl), f"@loader_path/{openssl.name}", str(helper.resolve())],
                invocations,
            )
            self.assertIn(
                ["install_name_tool", "-change", "@rpath/libz.1.dylib", f"@loader_path/{zlib.name}", str((bundle / openssl.name).resolve())],
                invocations,
            )
            self.assertIn(
                ["install_name_tool", "-id", f"@loader_path/{openssl.name}", str((bundle / openssl.name).resolve())],
                invocations,
            )


if __name__ == "__main__":
    unittest.main()
