"""End-to-end check for the public Python wrapper against the ARAP executable."""

from __future__ import annotations

import subprocess
import socket
import os
import tempfile
import time
import urllib.request
import unittest
from pathlib import Path

from arap_interop import ArapClient, ArapError

ROOT = Path(__file__).resolve().parents[2]


class ClientIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="arap-python-test-")
        cls.directory = Path(cls.temp.name)
        cls.binary = cls.directory / "arap"
        subprocess.run(["go", "build", "-o", str(cls.binary), "./cmd/arap"],
                       cwd=ROOT, check=True, timeout=120)
        cls.keyserver_binary = cls.directory / "arap-keyserver"
        subprocess.run(["go", "build", "-o", str(cls.keyserver_binary), "./cmd/arap-keyserver"],
                       cwd=ROOT, check=True, timeout=120)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(dir=self.directory))
        self.client = ArapClient(self.binary, timeout=30)
        self.private = self.work / "private.age"
        self.public = self.work / "public.pem"
        subprocess.run([str(self.binary), "keygen", "--private-key", str(self.private),
                        "--public-key", str(self.public), "--passphrase-stdin"],
                       input=b"fixture-passphrase\nfixture-passphrase\n", check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.subject_private = self.work / "subject-private.age"
        self.subject_public = self.work / "subject-public.pem"
        subprocess.run([str(self.binary), "keygen", "--private-key", str(self.subject_private),
                        "--public-key", str(self.subject_public), "--passphrase-stdin"],
                       input=b"subject-passphrase\nsubject-passphrase\n", check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.trust = self.work / "trust.json"
        subprocess.run([str(self.binary), "trust", "add", "--store", str(self.trust),
                        "--public-key", str(self.public), "--callsign", "K7ABC",
                        "--purpose", "content-signature"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.auth_trust = self.work / "auth-trust.json"
        subprocess.run([str(self.binary), "trust", "add", "--store", str(self.auth_trust),
                        "--public-key", str(self.subject_public), "--callsign", "AG7SU",
                        "--purpose", "challenge-response"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.auth_trust_a = self.work / "auth-trust-a.json"
        subprocess.run([str(self.binary), "trust", "add", "--store", str(self.auth_trust_a),
                        "--public-key", str(self.public), "--callsign", "K7ABC",
                        "--purpose", "challenge-response"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.work)

    def test_content_sign_and_verify(self) -> None:
        content = b"python consumer bytes\x00\xff"
        signed = self.client.sign_content(content, key=str(self.private), callsign="K7ABC",
                                          media_type="application/octet-stream",
                                          context="consumer/test/v1", passphrase="fixture-passphrase")
        self.assertEqual(signed["protocol_version"], 1)
        self.assertIsInstance(signed["proof"], bytes)
        checked = self.client.verify_content(signed["proof"], content, public_key=str(self.public),
                                             trust_store=str(self.trust),
                                             media_type="application/octet-stream",
                                             context="consumer/test/v1", callsign="K7ABC")
        self.assertTrue(checked["ok"])
        self.assertEqual(checked["result"]["overall_policy"], "accepted")

    def test_trust_lifecycle_is_available_through_python_api(self) -> None:
        content = b"purpose-scoped trust lifecycle"
        signed = self.client.sign_content(
            content, key=str(self.private), callsign="K7ABC", media_type="text/plain",
            context="python/trust-lifecycle/v1", passphrase="fixture-passphrase",
        )
        store = self.work / "managed-trust.json"
        key_id = signed["result"]["key_id_sha256"]
        self.assertEqual(self.client.fingerprint(self.public.read_bytes())["result"]["key_id_sha256"], key_id)
        self.client.add_trust(self.public.read_bytes(), callsign="K7ABC",
                              purpose="content-signature", store=str(store))
        current = self.client.list_trust(store=str(store))["result"]
        self.assertEqual(current["bindings"][0]["key_id_sha256"], key_id)
        accepted = self.client.verify_content(
            signed["proof"], content, public_key=str(self.public), trust_store=str(store),
            media_type="text/plain", context="python/trust-lifecycle/v1", callsign="K7ABC",
        )
        self.assertEqual(accepted["result"]["overall_policy"], "accepted")

        self.client.disable_trust(callsign="K7ABC", key_id=key_id, store=str(store))
        disabled = self.client.list_trust(store=str(store))["result"]["bindings"][0]
        self.assertTrue(disabled["disabled"])
        self.client.add_trust(self.public.read_bytes(), callsign="K7ABC",
                              purpose="challenge-response", store=str(store))
        reauthorized = self.client.list_trust(store=str(store))["result"]["bindings"][0]
        self.assertFalse(reauthorized.get("disabled", False))
        self.assertEqual(reauthorized["purposes"], ["challenge-response"])
        with self.assertRaises(ArapError) as wrong_purpose:
            self.client.verify_content(
                signed["proof"], content, public_key=str(self.public), trust_store=str(store),
                media_type="text/plain", context="python/trust-lifecycle/v1", callsign="K7ABC",
            )
        self.assertEqual(wrong_purpose.exception.code, "incomplete")

    def test_machine_errors_preserve_stable_code(self) -> None:
        with self.assertRaises(ArapError) as caught:
            self.client.resolve_proof("bad", servers=["http://127.0.0.1:1"])
        self.assertEqual(caught.exception.code, "invalid_input")
        self.assertEqual(caught.exception.exit_status, 2)
        with tempfile.TemporaryDirectory(dir=self.work) as temp:
            malformed = Path(temp) / "malformed.cose"
            malformed.write_bytes(b"not a COSE proof")
            with self.assertRaises(ArapError) as rejected:
                self.client._call(["inspect-proof", "--proof", str(malformed)])
        self.assertEqual(rejected.exception.code, "rejected")
        self.assertEqual(rejected.exception.exit_status, 1)

    def test_python_reference_methods_round_trip_through_keyserver(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        server_env = os.environ.copy()
        server_env.update({
            "ARAP_LISTEN": f"127.0.0.1:{port}",
            "ARAP_DATA_DIR": str(self.work / "keyserver-data"),
            "ARAP_UPLOAD_TOKEN": "python-integration-token-0123456789abcdef",
        })
        process = subprocess.Popen([str(self.keyserver_binary)], env=server_env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        previous_token = os.environ.get("ARAP_UPLOAD_TOKEN")
        os.environ["ARAP_UPLOAD_TOKEN"] = server_env["ARAP_UPLOAD_TOKEN"]
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(base + "/healthz", timeout=0.2) as response:
                        if response.status == 200:
                            break
                except OSError:
                    if process.poll() is not None:
                        self.fail("ARAP keyserver exited before becoming ready")
                    time.sleep(0.05)
            else:
                self.fail("ARAP keyserver did not become ready")

            signed = self.client.sign_content(
                b"reference API round trip", key=str(self.private), callsign="K7ABC",
                media_type="text/plain", context="python/reference-test/v1",
                passphrase="fixture-passphrase",
            )
            published_proof = self.client.publish_proof(signed["proof"], server=base)
            published_key = self.client.publish_key(self.public.read_bytes(), server=base)
            resolved = self.client.resolve_proof(
                published_proof["result"]["reference"], servers=[base],
            )
            fetched = self.client.fetch_key(
                published_key["result"]["key_id_sha256"], servers=[base],
            )
            self.assertEqual(resolved["proof"], signed["proof"])
            self.assertEqual(fetched["public_key"], self.public.read_bytes())
            with self.assertRaises(ArapError) as unknown:
                self.client.resolve_proof("AR1AAAAAAAAAAAAAAAA", servers=[base])
            self.assertEqual(unknown.exception.code, "not_found")
        finally:
            if previous_token is None:
                os.environ.pop("ARAP_UPLOAD_TOKEN", None)
            else:
                os.environ["ARAP_UPLOAD_TOKEN"] = previous_token
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_challenge_authentication_consumes_once(self) -> None:
        challenge_db = self.work / "challenges.sqlite"
        request = self.client.issue_challenge(requester="K7ABC", responder="AG7SU",
                                              store=str(challenge_db))
        response = self.client.respond_challenge(request["request"], key=str(self.subject_private),
                                                 callsign="AG7SU", passphrase="subject-passphrase")
        verified = self.client.verify_challenge(request["request"], response["response"],
                                                public_key=str(self.subject_public), trust_store=str(self.auth_trust),
                                                challenge_store=str(challenge_db), requester="K7ABC")
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["result"]["overall_policy"], "accepted")
        # Cleanup after successful consumption must not turn replayable state
        # into a deletable pending request.
        self.client.cancel_challenge(request["request"], store=str(challenge_db))
        with self.assertRaises(ArapError) as caught:
            self.client.verify_challenge(request["request"], response["response"],
                                          public_key=str(self.subject_public), trust_store=str(self.auth_trust),
                                          challenge_store=str(challenge_db), requester="K7ABC")
        self.assertEqual(caught.exception.code, "rejected")

    def test_cancel_challenge_after_transport_failure(self) -> None:
        challenge_db = self.work / "cancelled-challenges.sqlite"
        request = self.client.issue_challenge(requester="K7ABC", responder="AG7SU",
                                              store=str(challenge_db))
        cancelled = self.client.cancel_challenge(request["request"], store=str(challenge_db))
        self.assertTrue(cancelled["ok"])
        response = self.client.respond_challenge(request["request"], key=str(self.subject_private),
                                                 callsign="AG7SU", passphrase="subject-passphrase")
        with self.assertRaises(ArapError) as caught:
            self.client.verify_challenge(
                request["request"], response["response"], public_key=str(self.subject_public),
                trust_store=str(self.auth_trust), challenge_store=str(challenge_db), requester="K7ABC",
            )
        self.assertEqual(caught.exception.code, "rejected")

    def test_mutual_challenge_binds_session_and_consumes_pair(self) -> None:
        store = self.work / "mutual.sqlite"
        binding = b"python app session binding"
        requests = self.client.issue_mutual_challenges(party_a="K7ABC", party_b="AG7SU",
                                                       session_binding=binding, store=str(store))
        response_b = self.client.respond_challenge(requests["request_from_a"], key=str(self.subject_private),
                                                   callsign="AG7SU", passphrase="subject-passphrase")
        response_a = self.client.respond_challenge(requests["request_from_b"], key=str(self.private),
                                                   callsign="K7ABC", passphrase="fixture-passphrase")
        with self.assertRaises(ArapError) as wrong_session:
            self.client.verify_mutual_challenges(
                requests["request_from_a"], response_b["response"], requests["request_from_b"],
                response_a["response"], party_a="K7ABC", party_b="AG7SU",
                public_key_a=str(self.public), public_key_b=str(self.subject_public),
                trust_store_a=str(self.auth_trust_a), trust_store_b=str(self.auth_trust),
                session_binding=b"different application session", store=str(store))
        self.assertEqual(wrong_session.exception.code, "rejected")
        result = self.client.verify_mutual_challenges(
            requests["request_from_a"], response_b["response"], requests["request_from_b"],
            response_a["response"], party_a="K7ABC", party_b="AG7SU",
            public_key_a=str(self.public), public_key_b=str(self.subject_public),
            trust_store_a=str(self.auth_trust_a), trust_store_b=str(self.auth_trust),
            session_binding=binding, store=str(store))
        self.assertTrue(result["ok"])
        self.assertTrue(result["result"]["accepted"])
        with self.assertRaises(ArapError) as caught:
            self.client.verify_mutual_challenges(
                requests["request_from_a"], response_b["response"], requests["request_from_b"],
                response_a["response"], party_a="K7ABC", party_b="AG7SU",
                public_key_a=str(self.public), public_key_b=str(self.subject_public),
                trust_store_a=str(self.auth_trust_a), trust_store_b=str(self.auth_trust),
                session_binding=binding, store=str(store))
        self.assertEqual(caught.exception.code, "rejected")

    def test_endorsement_issue_pack_and_verify(self) -> None:
        issued = self.client.issue_endorsement(
            key=str(self.private), callsign="K7ABC", subject="AG7SU",
            subject_public_key=str(self.subject_public), purposes=["content-signature"],
            max_delegation_depth=0, passphrase="fixture-passphrase")
        packed = self.client.pack_endorsement_chain([issued["proof"]])
        verified = self.client.verify_endorsement_chain(
            packed["chain"], root_callsign="K7ABC", root_public_key=str(self.public),
            root_purposes=["content-signature", "key-endorsement"], root_max_delegation_depth=1,
            subject="AG7SU", subject_public_key=str(self.subject_public),
            purpose="content-signature")
        self.assertTrue(verified["ok"])
        self.assertTrue(verified["result"]["accepted"])

    def test_pixelqso_frame_two_sign_and_verify(self) -> None:
        vector = ROOT / "test-vectors" / "pixelqso-card-v1"
        card = (vector / "card.json").read_bytes()
        first = (vector / "first-card.json").read_bytes()
        trust = self.work / "pixelqso-trust.json"
        subprocess.run([str(self.binary), "trust", "add", "--store", str(trust),
                        "--public-key", str(self.public), "--callsign", "AG7SU",
                        "--purpose", "content-signature"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        signed = self.client.sign_pixelqso(card, key=str(self.private),
                                           first_card_json=first,
                                           passphrase="fixture-passphrase")
        verified = self.client.verify_pixelqso(card, signed["proof"],
                                               public_key=str(self.public), trust_store=str(trust),
                                               first_card_json=first)
        self.assertEqual(verified["result"]["overall_policy"], "accepted")

    def test_lotw_enrollment_challenge_issue(self) -> None:
        result = self.client.issue_enrollment(audience="python-integration-test",
                                              callsign="K7ABC", public_key=str(self.public),
                                              store=str(self.work / "enrollment.sqlite"))
        self.assertEqual(result["protocol_version"], 1)
        self.assertIsInstance(result["request"], bytes)
        self.assertEqual(result["result"]["version"], 1)
        self.assertEqual(result["result"]["purposes"], ["challenge-response"])
        purpose_request = self.client.issue_enrollment(
            audience="python-content-test", callsign="K7ABC", public_key=str(self.public),
            purposes=["content-signature", "challenge-response"],
            store=str(self.work / "enrollment-content.sqlite"))
        self.assertEqual(purpose_request["result"]["version"], 2)
        self.assertEqual(purpose_request["result"]["purposes"],
                         ["challenge-response", "content-signature"])
        with self.assertRaises(ArapError) as caught:
            self.client.respond_enrollment(result["request"], private_key=str(self.private),
                                            helper="arap-tqsl-sign")
        self.assertNotIn("explicit opt-in", str(caught.exception))

    def test_lotw_certificate_listing_is_read_only_application_operation(self) -> None:
        issued = self.client.issue_enrollment(
            audience="python-certificate-list-test", callsign="K7ABC",
            public_key=str(self.public), store=str(self.work / "certificate-list.sqlite"),
        )
        helper = self.work / "fake-tqsl-helper"
        tqsl_directory = self.work / "custom-tqsl-data"
        helper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "assert '--list-certificates' in sys.argv\n"
            "assert '--callsign' in sys.argv and sys.argv[sys.argv.index('--callsign') + 1] == 'K7ABC'\n"
            + f"assert '--directory' in sys.argv and sys.argv[sys.argv.index('--directory') + 1] == {str(tqsl_directory)!r}\n"
            "print(json.dumps({'certificates': [{'callsign': 'K7ABC', 'serial': '12345'}]}))\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
        listed = self.client.list_enrollment_certificates(
            issued["request"], helper=str(helper), tqsl_directory=str(tqsl_directory),
        )
        self.assertEqual(listed["result"]["callsign"], "K7ABC")
        self.assertEqual(listed["result"]["certificates"],
                         [{"callsign": "K7ABC", "serial": "12345"}])

    def test_lotw_verify_and_refresh_forward_custom_tqsl_directory(self) -> None:
        calls: list[list[str]] = []
        original_call = self.client._call
        self.client._call = lambda args, **kwargs: (calls.append(list(args)) or {"ok": True})
        try:
            self.client.verify_enrollment(
                b"response", audience="python-verifier", store="enrollment.sqlite",
                tqsl_directory="custom-tqsl-data",
            )
            self.client.refresh_enrollment(
                b"response", callsign="K7ABC", key_id="a" * 64,
                store="enrollment.sqlite", tqsl_directory="custom-tqsl-data",
            )
        finally:
            self.client._call = original_call
        self.assertEqual(len(calls), 2)
        for args in calls:
            self.assertIn("--tqsl-directory", args)
            self.assertEqual(args[args.index("--tqsl-directory") + 1], "custom-tqsl-data")


if __name__ == "__main__":
    unittest.main()
