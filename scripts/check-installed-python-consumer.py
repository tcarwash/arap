#!/usr/bin/env python3
"""Exercise the installed Python package and CLI from outside the checkout."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, help="test the CLI extracted from a desktop bundle")
    parser.add_argument("--target", choices=("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"), help="bundle target, required with --bundle")
    args = parser.parse_args()
    if args.bundle and not args.target:
        parser.error("--target is required with --bundle")
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

        executable_name = "arap.exe" if args.target == "windows-amd64" or (not args.bundle and os.name == "nt") else "arap"
        if args.bundle:
            bundled = work / "bundle"
            bundled.mkdir()
            with zipfile.ZipFile(args.bundle) as archive:
                for member in archive.infolist():
                    path = Path(member.filename)
                    if path.is_absolute() or ".." in path.parts:
                        raise SystemExit(f"unsafe bundle path: {member.filename}")
                archive.extractall(bundled)
                for member in archive.infolist():
                    mode = member.external_attr >> 16 & 0o777
                    if mode:
                        (bundled / member.filename).chmod(mode)
            cli = bundled / executable_name
            if not cli.is_file():
                raise SystemExit(f"bundle has no CLI for target {args.target}: {args.bundle}")
            keyserver = bundled / ("arap-keyserver.exe" if executable_name.endswith(".exe") else "arap-keyserver")
            if not keyserver.is_file():
                raise SystemExit(f"bundle has no keyserver for target {args.target}: {args.bundle}")
        else:
            cli = work / executable_name
            subprocess.run(["go", "build", "-o", str(cli), "./cmd/arap"],
                           cwd=ROOT, check=True, timeout=120)
            keyserver = work / ("arap-keyserver.exe" if executable_name.endswith(".exe") else "arap-keyserver")
            subprocess.run(["go", "build", "-o", str(keyserver), "./cmd/arap-keyserver"],
                           cwd=ROOT, check=True, timeout=120)

        consumer = work / "consumer.py"
        consumer.write_text(textwrap.dedent("""
            import sys
            import os
            import socket
            import subprocess
            import time
            import urllib.request
            from pathlib import Path
            from arap_interop import ArapClient, ArapError

            root = Path.cwd()
            cli = Path(sys.argv[1])
            keyserver_binary = Path(sys.argv[2])
            vector_dir = Path(sys.argv[3])
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

            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            base = f"http://127.0.0.1:{port}"
            upload_token = "external-consumer-upload-token-0123456789"
            server_env = os.environ.copy()
            server_env.update({"ARAP_LISTEN": f"127.0.0.1:{port}",
                               "ARAP_DATA_DIR": str(root / "keyserver-data"),
                               "ARAP_UPLOAD_TOKEN": upload_token})
            server = subprocess.Popen([str(keyserver_binary)], env=server_env,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.environ["ARAP_UPLOAD_TOKEN"] = upload_token
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(base + "/healthz", timeout=0.2) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        if server.poll() is not None:
                            raise AssertionError("packaged keyserver exited before becoming ready")
                        time.sleep(0.05)
                else:
                    raise AssertionError("packaged keyserver did not become ready")
                published_proof = client.publish_proof(signed["proof"], server=base)
                published_key = client.publish_key(public_a.read_bytes(), server=base)
                resolved = client.resolve_proof(published_proof["result"]["reference"], servers=[base])
                fetched = client.fetch_key(published_key["result"]["key_id_sha256"], servers=[base])
                assert resolved["proof"] == signed["proof"]
                assert fetched["public_key"] == public_a.read_bytes()
            finally:
                os.environ.pop("ARAP_UPLOAD_TOKEN", None)
                server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)

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

            mutual_store = root / "mutual.sqlite"
            binding = b"external consumer session binding"
            requests = client.issue_mutual_challenges(
                party_a="K7ABC", party_b="AG7SU", session_binding=binding,
                store=str(mutual_store))
            response_b = client.respond_challenge(
                requests["request_from_a"], key=str(private_b), callsign="AG7SU",
                passphrase=password_b)
            response_a = client.respond_challenge(
                requests["request_from_b"], key=str(private_a), callsign="K7ABC",
                passphrase=password_a)
            verify_mutual = dict(
                party_a="K7ABC", party_b="AG7SU", public_key_a=str(public_a),
                public_key_b=str(public_b), trust_store_a=str(trust), trust_store_b=str(trust),
                session_binding=binding, store=str(mutual_store))
            try:
                client.verify_mutual_challenges(
                    requests["request_from_a"], response_b["response"],
                    requests["request_from_b"], response_a["response"],
                    **{**verify_mutual, "session_binding": b"wrong session"})
            except ArapError as error:
                assert error.code == "rejected"
            else:
                raise AssertionError("mutual authentication accepted the wrong session")
            accepted_pair = client.verify_mutual_challenges(
                requests["request_from_a"], response_b["response"],
                requests["request_from_b"], response_a["response"], **verify_mutual)
            assert accepted_pair["result"]["accepted"]
            try:
                client.verify_mutual_challenges(
                    requests["request_from_a"], response_b["response"],
                    requests["request_from_b"], response_a["response"], **verify_mutual)
            except ArapError as error:
                assert error.code == "rejected"
            else:
                raise AssertionError("mutual challenge pair replay was accepted")

            endorsement = client.issue_endorsement(
                key=str(private_a), callsign="K7ABC", subject="AG7SU",
                subject_public_key=str(public_b), purposes=["content-signature"],
                max_delegation_depth=0, passphrase=password_a)
            chain = client.pack_endorsement_chain([endorsement["proof"]])
            checked_endorsement = client.verify_endorsement_chain(
                chain["chain"], root_callsign="K7ABC", root_public_key=str(public_a),
                root_purposes=["content-signature", "key-endorsement"],
                root_max_delegation_depth=1, subject="AG7SU",
                subject_public_key=str(public_b), purpose="content-signature")
            assert checked_endorsement["result"]["accepted"]

            vector = vector_dir
            card = (vector / "card.json").read_bytes()
            first_card = (vector / "first-card.json").read_bytes()
            pixel_trust = root / "pixel-trust.json"
            client.add_trust(public_a.read_bytes(), callsign="AG7SU",
                             purpose="content-signature", store=str(pixel_trust))
            pixel_proof = client.sign_pixelqso(
                card, key=str(private_a), first_card_json=first_card,
                passphrase=password_a)
            pixel_verified = client.verify_pixelqso(
                card, pixel_proof["proof"], public_key=str(public_a),
                trust_store=str(pixel_trust), first_card_json=first_card)
            assert pixel_verified["result"]["overall_policy"] == "accepted"
            print("Installed Python consumer generated keys, signed content and PixelQSO, authenticated one-way and mutual challenges, evaluated an endorsement, published and resolved proof/key references, and rejected replay and wrong-session attempts.")
        """), encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(site)
        vector_dir = ROOT / "test-vectors" / "pixelqso-card-v1"
        subprocess.run([sys.executable, str(consumer), str(cli), str(keyserver), str(vector_dir)], cwd=work, env=env,
                       check=True, timeout=90)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
