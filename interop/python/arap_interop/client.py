"""Small, versioned Python integration layer over the ARAP CLI.

Private key files and trust/challenge databases remain application-owned. Proofs
and requests cross this boundary as bytes; they are never interpreted by the
wrapper. The CLI is launched without a shell and every call has a timeout.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Sequence

PROTOCOL_VERSION = 1


class ArapError(RuntimeError):
    """Stable wrapper error with a machine-readable code and exit status."""

    def __init__(self, code: str, exit_status: int, message: str):
        super().__init__(message)
        self.code = code
        self.exit_status = exit_status

    def as_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "ok": False,
            "error": {"code": self.code, "message": str(self)},
        }


class ArapClient:
    """Invoke ARAP's documented application operations.

    ``binary`` may be an executable path or command name. ``timeout`` is a
    per-operation wall-clock bound. Encrypted private keys can be used by
    passing ``passphrase`` to signing/responding methods; it travels on stdin,
    never in argv or the returned envelope.
    """

    def __init__(self, binary: str | os.PathLike[str] = "arap", timeout: float = 30):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.binary = os.fspath(binary)
        self.timeout = timeout

    def _call(
        self,
        args: Sequence[str],
        *,
        json_output: bool = True,
        passphrase: str | None = None,
        no_prompt: bool = False,
        stdin_lines: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        passphrase_mode = passphrase is not None or no_prompt or stdin_lines is not None
        lines = list(stdin_lines) if stdin_lines is not None else [passphrase or ""]
        input_bytes = None if not passphrase_mode else ("\n".join(lines) + "\n").encode()
        full_args = [self.binary, *map(str, args)]
        if passphrase_mode:
            full_args.append("--passphrase-stdin")
        try:
            child_env = os.environ.copy()
            child_env["ARAP_MACHINE"] = "1"
            completed = subprocess.run(
                full_args,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
                shell=False,
                env=child_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ArapError("timeout", 124, "ARAP operation exceeded its timeout") from exc
        except OSError as exc:
            raise ArapError("unavailable", 127, "ARAP executable could not be started") from exc

        code = completed.returncode
        if code:
            try:
                machine_error = json.loads(completed.stdout)
                error = machine_error.get("error", {})
                if (machine_error.get("protocol_version") == PROTOCOL_VERSION
                        and machine_error.get("ok") is False
                        and isinstance(error.get("code"), str)):
                    raise ArapError(error["code"], code,
                                    str(error.get("message") or "ARAP operation failed"))
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError, TypeError):
                pass
            names = {1: "rejected", 2: "operation_error", 3: "incomplete"}
            name = names.get(code, "operation_error")
            # CLI diagnostics are deliberately excluded from the stable message;
            # callers can log them separately only when their policy permits.
            message = {
                "rejected": "ARAP rejected the operation under the supplied policy",
                "incomplete": "ARAP could not complete all requested checks",
                "operation_error": "ARAP operation failed",
            }[name]
            raise ArapError(name, code, message)
        result: Any = None
        if json_output and completed.stdout.strip():
            try:
                result = json.loads(completed.stdout)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ArapError("invalid_response", 70, "ARAP returned invalid JSON") from exc
        return {"protocol_version": PROTOCOL_VERSION, "ok": True, "result": result}

    @staticmethod
    def _write(directory: str, name: str, data: bytes) -> str:
        path = os.path.join(directory, name)
        with open(path, "xb") as stream:
            stream.write(data)
        return path

    @staticmethod
    def _read(path: str) -> bytes:
        with open(path, "rb") as stream:
            return stream.read()

    def generate_keypair(self, *, passphrase: str) -> dict[str, Any]:
        """Generate an encrypted Ed25519 keypair and return both PEM files as bytes."""
        if not passphrase:
            raise ValueError("key passphrase must not be empty")
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            private = os.path.join(temp, "private.age")
            public = os.path.join(temp, "public.pem")
            result = self._call(["keygen", "--private-key", private,
                                 "--public-key", public],
                                stdin_lines=[passphrase, passphrase])
            result["private_key"] = self._read(private)
            result["public_key"] = self._read(public)
            return result

    def sign_content(
        self, content: bytes, *, key: str, callsign: str, media_type: str,
        context: str, canonicalization: str = "identity-v1", content_id: str = "",
        passphrase: str | None = None,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            source = self._write(temp, "content", content)
            proof = os.path.join(temp, "proof.cose")
            args = ["sign-content", "--key", key, "--callsign", callsign,
                    "--input", source, "--media-type", media_type, "--context", context,
                    "--canonicalization", canonicalization, "--out", proof]
            if content_id:
                args += ["--content-id", content_id]
            result = self._call(args, passphrase=passphrase, no_prompt=True)
            result["proof"] = self._read(proof)
            return result

    def verify_content(
        self, proof: bytes, content: bytes, *, public_key: str, trust_store: str = "",
        media_type: str, context: str, canonicalization: str = "identity-v1",
        callsign: str = "", enrollment_store: str = "",
        max_enrollment_status_age: str = "24h",
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            proof_path = self._write(temp, "proof.cose", proof)
            content_path = self._write(temp, "content", content)
            args = ["verify-content", "--proof", proof_path, "--input", content_path,
                    "--public-key", public_key,
                    "--expect-media-type", media_type, "--expect-context", context,
                    "--expect-canonicalization", canonicalization]
            if trust_store:
                args += ["--trust-store", trust_store]
            if enrollment_store:
                args += ["--enrollment-store", enrollment_store,
                         "--max-enrollment-status-age", max_enrollment_status_age]
            if not trust_store and not enrollment_store:
                raise ValueError("trust_store or enrollment_store is required")
            if callsign:
                args += ["--expect-callsign", callsign]
            return self._call(args)

    def add_trust(
        self, public_key: bytes, *, callsign: str, purpose: str, store: str,
    ) -> dict[str, Any]:
        """Authorize a public key for one explicit purpose in a local trust file."""
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = self._write(temp, "public-key.pem", public_key)
            return self._call(["trust", "add", "--store", store, "--public-key", path,
                               "--callsign", callsign, "--purpose", purpose], json_output=False)

    def list_trust(self, *, store: str) -> dict[str, Any]:
        """Return the current callsign/key/purpose bindings from a trust file."""
        return self._call(["trust", "list", "--store", store])

    def disable_trust(self, *, callsign: str, key_id: str, store: str) -> dict[str, Any]:
        """Disable every purpose granted by a local callsign/key binding."""
        return self._call(["trust", "disable", "--store", store,
                           "--callsign", callsign, "--key-id", key_id], json_output=False)

    def fingerprint(self, public_key: bytes) -> dict[str, Any]:
        """Return the canonical SHA-256 key ID for a public key or certificate."""
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = self._write(temp, "public-key.pem", public_key)
            return self._call(["fingerprint", "--public-key", path, "--json"])

    def sign_pixelqso(
        self, card_json: bytes, *, key: str, first_card_json: bytes | None = None,
        passphrase: str | None = None,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            card_path = self._write(temp, "card.json", card_json)
            proof_path = os.path.join(temp, "proof.cose")
            args = ["sign-pixelqso", "--key", key, "--card", card_path, "--out", proof_path]
            if first_card_json is not None:
                args += ["--first-card", self._write(temp, "first-card.json", first_card_json)]
            result = self._call(args, passphrase=passphrase, no_prompt=True)
            result["proof"] = self._read(proof_path)
            return result

    def verify_pixelqso(
        self, card_json: bytes, proof: bytes, *, public_key: str, trust_store: str,
        first_card_json: bytes | None = None,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            card_path = self._write(temp, "card.json", card_json)
            proof_path = self._write(temp, "proof.cose", proof)
            args = ["verify-pixelqso", "--card", card_path, "--proof", proof_path,
                    "--public-key", public_key, "--trust-store", trust_store]
            if first_card_json is not None:
                args += ["--first-card", self._write(temp, "first-card.json", first_card_json)]
            return self._call(args)

    def issue_challenge(
        self, *, requester: str, responder: str, store: str,
        purpose: str = "station-auth", session_binding: bytes = b"",
        expires_in: int = 120,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request = os.path.join(temp, "request.cbor")
            result = self._call(["challenge", "issue", "--requester", requester,
                                 "--responder", responder, "--purpose", purpose,
                                 "--session-binding-hex", session_binding.hex(),
                                 "--expires-in", str(expires_in), "--store", store,
                                 "--out", request])
            result["request"] = self._read(request)
            return result

    def cancel_challenge(self, request: bytes, *, store: str) -> dict[str, Any]:
        """Cancel a pending one-way challenge if application transport failed.

        A challenge that has already been consumed is never removed.
        """
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request_path = self._write(temp, "request.cbor", request)
            return self._call(["challenge", "cancel", "--request", request_path,
                               "--store", store])

    def respond_challenge(
        self, request: bytes, *, key: str, callsign: str,
        passphrase: str | None = None,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request_path = self._write(temp, "request.cbor", request)
            response = os.path.join(temp, "response.cose")
            result = self._call(["challenge", "respond", "--request", request_path,
                                 "--key", key, "--callsign", callsign, "--out", response],
                                passphrase=passphrase, no_prompt=True)
            result["response"] = self._read(response)
            return result

    def verify_challenge(
        self, request: bytes, response: bytes, *, public_key: str,
        challenge_store: str, requester: str, trust_store: str = "",
        enrollment_store: str = "",
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request_path = self._write(temp, "request.cbor", request)
            response_path = self._write(temp, "response.cose", response)
            args = ["challenge", "verify-response", "--request", request_path,
                    "--response", response_path, "--public-key", public_key,
                    "--store", challenge_store, "--requester", requester]
            if trust_store:
                args += ["--trust-store", trust_store]
            if enrollment_store:
                args += ["--enrollment-store", enrollment_store]
            return self._call(args)

    def issue_mutual_challenges(
        self, *, party_a: str, party_b: str, session_binding: bytes,
        store: str, purpose: str = "station-auth", expires_in: int = 120,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            from_a, from_b = os.path.join(temp, "from-a.cbor"), os.path.join(temp, "from-b.cbor")
            result = self._call(["challenge", "mutual-issue", "--party-a", party_a,
                                 "--party-b", party_b, "--purpose", purpose,
                                 "--session-binding-hex", session_binding.hex(),
                                 "--expires-in", str(expires_in), "--store", store,
                                 "--out-from-a", from_a, "--out-from-b", from_b])
            result["request_from_a"] = self._read(from_a)
            result["request_from_b"] = self._read(from_b)
            return result

    def verify_mutual_challenges(
        self, request_from_a: bytes, response_from_b: bytes,
        request_from_b: bytes, response_from_a: bytes, *,
        party_a: str, party_b: str, public_key_a: str, public_key_b: str,
        trust_store_a: str, trust_store_b: str, session_binding: bytes,
        store: str, enrollment_store_a: str = "", enrollment_store_b: str = "",
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            files = {
                "request-from-a.cbor": request_from_a,
                "response-from-b.cose": response_from_b,
                "request-from-b.cbor": request_from_b,
                "response-from-a.cose": response_from_a,
            }
            paths = {name: self._write(temp, name, data) for name, data in files.items()}
            args = ["challenge", "mutual-verify",
                    "--request-from-a", paths["request-from-a.cbor"],
                    "--response-from-b", paths["response-from-b.cose"],
                    "--request-from-b", paths["request-from-b.cbor"],
                    "--response-from-a", paths["response-from-a.cose"],
                    "--party-a", party_a, "--party-b", party_b,
                    "--party-a-public-key", public_key_a, "--party-b-public-key", public_key_b,
                    "--party-a-trust-store", trust_store_a, "--party-b-trust-store", trust_store_b,
                    "--session-binding-hex", session_binding.hex(), "--store", store]
            if enrollment_store_a:
                args += ["--party-a-enrollment-store", enrollment_store_a]
            if enrollment_store_b:
                args += ["--party-b-enrollment-store", enrollment_store_b]
            return self._call(args)

    def issue_endorsement(
        self, *, key: str, callsign: str, subject: str, subject_public_key: str,
        purposes: Sequence[str], max_delegation_depth: int = 0,
        expires_in: int = 30 * 24 * 60 * 60, passphrase: str | None = None,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            proof_path = os.path.join(temp, "endorsement.cose")
            args = ["endorsement", "issue", "--key", key, "--callsign", callsign,
                    "--subject", subject, "--subject-public-key", subject_public_key,
                    "--max-delegation-depth", str(max_delegation_depth),
                    "--expires-in", str(expires_in), "--out", proof_path]
            for purpose in purposes:
                args += ["--purpose", purpose]
            result = self._call(args, passphrase=passphrase, no_prompt=True)
            result["proof"] = self._read(proof_path)
            return result

    def pack_endorsement_chain(self, links: Sequence[bytes]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            paths = [self._write(temp, f"link-{index}.cose", link)
                     for index, link in enumerate(links)]
            chain_path = os.path.join(temp, "chain.cbor")
            args = ["endorsement", "pack"]
            for path in paths:
                args += ["--link", path]
            args += ["--out", chain_path]
            result = self._call(args)
            result["chain"] = self._read(chain_path)
            return result

    def append_endorsement(self, chain: bytes, link: bytes) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            chain_path = self._write(temp, "chain.cbor", chain)
            link_path = self._write(temp, "link.cose", link)
            output = os.path.join(temp, "extended-chain.cbor")
            result = self._call(["endorsement", "append", "--chain", chain_path,
                                 "--link", link_path, "--out", output])
            result["chain"] = self._read(output)
            return result

    def verify_endorsement_chain(
        self, chain: bytes, *, root_callsign: str, root_public_key: str,
        root_purposes: Sequence[str], root_max_delegation_depth: int,
        subject: str, subject_public_key: str, purpose: str,
        disabled_trust_store: str = "",
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            chain_path = self._write(temp, "chain.cbor", chain)
            args = ["endorsement", "verify", "--chain", chain_path,
                    "--root-callsign", root_callsign, "--root-public-key", root_public_key,
                    "--root-max-delegation-depth", str(root_max_delegation_depth),
                    "--subject", subject, "--subject-public-key", subject_public_key,
                    "--purpose", purpose]
            for root_purpose in root_purposes:
                args += ["--root-purpose", root_purpose]
            if disabled_trust_store:
                args += ["--disabled-trust-store", disabled_trust_store]
            return self._call(args)

    def issue_enrollment(
        self, *, audience: str, callsign: str, public_key: str, store: str,
        expires_in: int = 120, purposes: Sequence[str] = (),
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request = os.path.join(temp, "enrollment.cbor")
            args = ["enrollment", "issue", "--audience", audience,
                    "--callsign", callsign, "--public-key", public_key,
                    "--store", store, "--expires-in", str(expires_in), "--out", request]
            for purpose in purposes:
                args += ["--purpose", purpose]
            result = self._call(args)
            result["request"] = self._read(request)
            return result

    def respond_enrollment(
        self, request: bytes, *, private_key: str, helper: str,
        arap_passphrase: str = "", tqsl_passphrase: str = "", serial: str = "",
        tqsl_directory: str = "",
        allow_legacy_rsa_sha1: bool = True,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request_path = self._write(temp, "enrollment.cbor", request)
            response = os.path.join(temp, "enrollment-response.cbor")
            args = ["enrollment", "respond", "--request", request_path,
                    "--private-key", private_key, "--tqsl-helper", helper,
                    "--out", response]
            if serial:
                args += ["--tqsl-serial", serial]
            if tqsl_directory:
                args += ["--tqsl-directory", tqsl_directory]
            result = self._call(args, stdin_lines=[arap_passphrase, tqsl_passphrase])
            result["response"] = self._read(response)
            return result

    def list_enrollment_certificates(
        self, request: bytes, *, helper: str = "", tqsl_directory: str = "",
    ) -> dict[str, Any]:
        """List current TQSL certificate serials matching the challenge callsign.

        The operation reads only public certificate metadata and does not
        prompt for or pass a TQSL certificate password.
        """
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            request_path = self._write(temp, "enrollment.cbor", request)
            args = ["enrollment", "certificates", "--request", request_path]
            if helper:
                args += ["--tqsl-helper", helper]
            if tqsl_directory:
                args += ["--tqsl-directory", tqsl_directory]
            return self._call(args)

    def verify_enrollment(
        self, response: bytes, *, audience: str, store: str, roots: str = "",
        allow_legacy_rsa_sha1: bool = True, max_status_age: str = "24h",
        allowed_purposes: Sequence[str] = (),
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            response_path = self._write(temp, "enrollment-response.cbor", response)
            args = ["enrollment", "verify-response", "--response", response_path,
                    "--audience", audience, "--store", store,
                    "--max-status-age", max_status_age]
            if roots:
                args += ["--roots", roots]
            for purpose in allowed_purposes:
                args += ["--allow-purpose", purpose]
            return self._call(args)

    def refresh_enrollment(
        self, accepted_response: bytes, *, callsign: str, key_id: str, store: str,
        roots: str = "", max_status_age: str = "24h",
    ) -> dict[str, Any]:
        """Refresh certificate status from the retained accepted response.

        The CLI revalidates the certificate chain and matches its leaf
        fingerprint to the existing binding before asking the live status
        provider. Disabled bindings cannot be revived by this operation.
        """
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            response_path = self._write(temp, "enrollment-response.cbor", accepted_response)
            args = ["enrollment", "refresh", "--response", response_path,
                    "--callsign", callsign, "--key-id", key_id, "--store", store,
                    "--max-status-age", max_status_age]
            if roots:
                args += ["--roots", roots]
            return self._call(args)

    def list_enrollments(self, *, store: str) -> dict[str, Any]:
        return self._call(["enrollment", "list", "--store", store])

    def disable_enrollment(self, *, store: str, callsign: str, key_id: str) -> dict[str, Any]:
        return self._call(["enrollment", "disable", "--store", store,
                           "--callsign", callsign, "--key-id", key_id], json_output=False)

    def publish_proof(self, proof: bytes, *, server: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = self._write(temp, "proof.cose", proof)
            return self._call(["publish", "--server", server, "--proof", path])

    def resolve_proof(self, reference: str, *, servers: Sequence[str]) -> dict[str, Any]:
        if not servers:
            raise ValueError("at least one resolver server is required")
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = os.path.join(temp, "proof.cose")
            args = ["resolve"]
            for server in servers:
                args += ["--server", server]
            args += ["--reference", reference, "--out", path]
            result = self._call(args)
            result["proof"] = self._read(path)
            return result

    def publish_key(self, public_key: bytes, *, server: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = self._write(temp, "public-key.pem", public_key)
            return self._call(["publish-key", "--server", server,
                               "--public-key", path])

    def fetch_key(self, fingerprint: str, *, servers: Sequence[str]) -> dict[str, Any]:
        if not servers:
            raise ValueError("at least one resolver server is required")
        with tempfile.TemporaryDirectory(prefix="arap-python-") as temp:
            path = os.path.join(temp, "public-key.pem")
            args = ["fetch-key"]
            for server in servers:
                args += ["--server", server]
            args += ["--fingerprint", fingerprint, "--out", path]
            result = self._call(args)
            result["public_key"] = self._read(path)
            return result
