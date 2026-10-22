#!/usr/bin/env python3
"""Exercise the Compose keyserver, proxy overlay, and named-volume restart."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args: list[str], *, cwd: Path, env: dict[str, str], input_text: str | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, input=input_text)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def wait_healthy(compose: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    deadline = time.monotonic() + 75
    last_state = "unavailable"
    last_error = "no response yet"
    while time.monotonic() < deadline:
        try:
            binding = run(compose + ["port", "arap-keyserver", "8080"], cwd=cwd, env=env)
            base = f"http://127.0.0.1:{binding.rsplit(':', 1)[1]}"
            container = run(compose + ["ps", "-q", "arap-keyserver"], cwd=cwd, env=env)
            if not container:
                time.sleep(0.2)
                continue
            state = run(["docker", "inspect", "--format", "{{.State.Health.Status}}", container], cwd=cwd, env=env)
            last_state = state
            with local_http.open(base + "/healthz", timeout=1) as response:
                if state == "healthy" and response.status == 200:
                    return base
                last_error = f"health endpoint returned HTTP {response.status}"
        except Exception as exc:
            last_error = str(exc)
            time.sleep(0.2)
    raise TimeoutError(f"Compose keyserver did not become healthy (last state: {last_state}; endpoint: {last_error})")


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    cli = repo / "bin" / ("arap.exe" if os.name == "nt" else "arap")
    if not cli.is_file():
        raise SystemExit(f"build the adjacent ARAP CLI before running this check: {cli}")

    env = os.environ.copy()
    env["ARAP_UPLOAD_TOKEN"] = "compose-smoke-" + secrets.token_urlsafe(24)
    env["ARAP_PUBLISH_ADDRESS"] = "127.0.0.1"
    env["ARAP_PUBLISH_PORT"] = "0"
    project = "arap-smoke-" + secrets.token_hex(6)

    with tempfile.TemporaryDirectory(prefix="arap-compose-check-") as temporary:
        temporary_path = Path(temporary)
        compose = [
            "docker", "compose", "-p", project,
            "-f", str(repo / "compose.yaml"), "-f", str(repo / "compose.haproxy.yaml"),
        ]
        up = False
        try:
            up = True
            print("Building and starting an isolated Compose keyserver…", flush=True)
            run(compose + ["up", "-d", "--build"], cwd=repo, env=env)
            base = wait_healthy(compose, cwd=repo, env=env)

            private = temporary_path / "station.pem"
            public = temporary_path / "station.pub.pem"
            content = temporary_path / "message.txt"
            proof = temporary_path / "message.cose"
            trust = temporary_path / "trust.json"
            content.write_text("Compose-backed ARAP keyserver end-to-end check\n", encoding="utf-8")

            def arap(*args: object, input_text: str | None = None) -> str:
                return run([str(cli), *(str(arg) for arg in args)], cwd=repo, env=env, input_text=input_text)

            smoke_passphrase = "compose smoke passphrase for key"
            arap("keygen", "--private-key", private, "--public-key", public,
                 "--passphrase-stdin", input_text=f"{smoke_passphrase}\n{smoke_passphrase}\n")
            arap(
                "sign-content", "--key", private, "--callsign", "AG7SU", "--input", content,
                "--media-type", "text/plain", "--context", "compose/e2e/v1", "--out", proof,
                "--passphrase-stdin", input_text=f"{smoke_passphrase}\n",
            )
            arap("trust", "add", "--store", trust, "--public-key", public,
                 "--callsign", "AG7SU", "--purpose", "content-signature")

            proof_bytes = proof.read_bytes()
            proof_hash = hashlib.sha256(proof_bytes).hexdigest()
            request = urllib.request.Request(
                f"{base}/v1/proofs/{proof_hash}", data=proof_bytes, method="PUT"
            )
            try:
                local_http.open(request, timeout=3)
                raise AssertionError("anonymous proof upload unexpectedly succeeded")
            except urllib.error.HTTPError as exc:
                if exc.code != 401:
                    raise AssertionError(f"anonymous upload returned HTTP {exc.code}, expected 401") from exc

            arap("publish-key", "--server", base, "--public-key", public)
            published = json.loads(arap("publish", "--server", base, "--proof", proof))
            reference = published["reference"]
            fingerprint = arap("fingerprint", "--public-key", public)

            def verify_reference() -> None:
                result = json.loads(arap(
                    "verify-ref", "--server", base, "--reference", reference,
                    "--input", content, "--public-key", public, "--trust-store", trust,
                    "--expect-media-type", "text/plain", "--expect-context", "compose/e2e/v1",
                ))
                if result.get("overall_policy") != "accepted":
                    raise AssertionError(f"Compose-published proof was not accepted: {result!r}")

            verify_reference()
            fetched_key = temporary_path / "fetched.pub.pem"
            fetched_proof = temporary_path / "fetched.cose"
            arap("fetch-key", "--server", base, "--fingerprint", fingerprint, "--out", fetched_key)
            arap("resolve", "--server", base, "--reference", reference, "--out", fetched_proof)
            if fetched_key.read_bytes() != public.read_bytes():
                raise AssertionError("fetched public key bytes differ from the published key")
            if fetched_proof.read_bytes() != proof_bytes:
                raise AssertionError("fetched proof bytes differ from the published proof")

            print("Restarting the container to check named-volume persistence…", flush=True)
            run(compose + ["restart"], cwd=repo, env=env)
            base = wait_healthy(compose, cwd=repo, env=env)
            verify_reference()
            print("Compose keyserver passed: anonymous writes rejected; authenticated proof/key publish, resolve, fetch, local verification, healthcheck and named-volume restart persistence verified.")
        except Exception:
            if up:
                logs = subprocess.run(compose + ["logs", "--no-color"], cwd=repo, env=env, capture_output=True, text=True)
                if logs.stdout or logs.stderr:
                    print(logs.stdout + logs.stderr, file=sys.stderr)
            raise
        finally:
            if up:
                subprocess.run(compose + ["down", "-v", "--remove-orphans"], cwd=repo, env=env, capture_output=True, text=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
