#!/usr/bin/env python3
"""Exercise the installed Python package and CLI from outside the checkout."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="arap-installed-consumer-") as temp:
        work = Path(temp)
        wheels = work / "wheels"
        site = work / "site"
        wheels.mkdir()
        site.mkdir()
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheels),
             str(ROOT / "interop" / "python")],
            cwd=work, check=True, timeout=120,
        )
        wheel = next(wheels.glob("arap_interop-*.whl"))
        subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(site), str(wheel)],
                       cwd=work, check=True, timeout=120, stdout=subprocess.DEVNULL)

        cli = work / ("arap.exe" if os.name == "nt" else "arap")
        subprocess.run(["go", "build", "-o", str(cli), "./cmd/arap"],
                       cwd=ROOT, check=True, timeout=120)

        consumer = work / "consumer.py"
        consumer.write_text(textwrap.dedent("""
            import sys
            from pathlib import Path
            from arap_interop import ArapClient, ArapError

            root = Path.cwd()
            cli = Path(sys.argv[1])
            client = ArapClient(cli, timeout=30)
            password_a = "consumer key password A"
            password_b = "consumer key password B"

            def keygen(name, password):
                private, public = root / f"{name}.age", root / f"{name}.pub.pem"
                generated = client.generate_keypair(passphrase=password)
                private.write_bytes(generated["private_key"])
                private.chmod(0o600)
                public.write_bytes(generated["public_key"])
                return private, public

            private_a, public_a = keygen("a", password_a)
            private_b, public_b = keygen("b", password_b)
            trust = root / "trust.json"
            for public, call in ((public_a, "K7ABC"), (public_b, "AG7SU")):
                for purpose in ("content-signature", "challenge-response"):
                    client.add_trust(public.read_bytes(), callsign=call,
                                     purpose=purpose, store=str(trust))

            content = b"consumer installed-package contract test\\x00"
            signed = client.sign_content(content, key=str(private_a), callsign="K7ABC",
                                         media_type="application/octet-stream",
                                         context="consumer/installed/v1", passphrase=password_a)
            assert (
                client.fingerprint(public_a.read_bytes())["result"]["key_id_sha256"]
                == signed["result"]["key_id_sha256"]
            )
            verified = client.verify_content(signed["proof"], content, public_key=str(public_a),
                                             trust_store=str(trust), media_type="application/octet-stream",
                                             context="consumer/installed/v1", callsign="K7ABC")
            assert verified["result"]["overall_policy"] == "accepted"

            challenge_db = root / "challenges.sqlite"
            request = client.issue_challenge(requester="K7ABC", responder="AG7SU",
                                             store=str(challenge_db))
            response = client.respond_challenge(request["request"], key=str(private_b),
                                                callsign="AG7SU", passphrase=password_b)
            authenticated = client.verify_challenge(
                request["request"], response["response"], public_key=str(public_b),
                trust_store=str(trust), challenge_store=str(challenge_db), requester="K7ABC")
            assert authenticated["result"]["overall_policy"] == "accepted"
            try:
                client.verify_challenge(
                    request["request"], response["response"], public_key=str(public_b),
                    trust_store=str(trust), challenge_store=str(challenge_db), requester="K7ABC")
            except ArapError as error:
                assert error.code == "rejected"
            else:
                raise AssertionError("consumed challenge replay was accepted")
            print("Installed Python consumer generated keys, managed trust, signed content, authenticated a challenge and rejected replay.")
        """), encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(site)
        subprocess.run([sys.executable, str(consumer), str(cli)], cwd=work, env=env,
                       check=True, timeout=90)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
