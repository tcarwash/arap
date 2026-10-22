#!/usr/bin/env python3
"""Generate ARAP's deterministic Ed25519 COSE_Sign1 interoperability vector."""
import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED = bytes(range(32))
CALLSIGN = "AG7SU"
CREATED = 1_800_000_000
CONTENT = b"ARAP deterministic interoperability vector\n"
MEDIA_TYPE = "application/octet-stream"
CONTEXT = "arap/interoperability/v1"
CONTENT_TYPE = "application/vnd.arap.proof+cbor"
MAX_FUTURE_SKEW = 300


def encode(value: object) -> bytes:
    # All profile maps use small integer labels; canonical=True yields the
    # same core deterministic order for these keys as RFC 8949 section 4.2.1.
    return cbor2.dumps(value, canonical=True)


def sign_payload(private: Ed25519PrivateKey, public, payload: dict) -> bytes:
    public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(public_der).digest()
    protected = encode({1: -19, 3: CONTENT_TYPE, 4: key_id})
    payload_bytes = encode(payload)
    sig_structure = encode(["Signature1", protected, b"", payload_bytes])
    signature = private.sign(sig_structure)
    return encode(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))


def valid_callsign(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Z0-9]+(?:/[A-Z0-9]+)*", value) is not None
        and any("A" <= char <= "Z" for char in value)
        and any("0" <= char <= "9" for char in value)
    )


def accepts_content(proof: bytes, content: bytes, public, expected: dict, now: int, trusted: bool = True) -> bool:
    try:
        if not proof or len(proof) > 64 * 1024 or not trusted:
            return False
        envelope = cbor2.loads(proof)
        if encode(envelope) != proof or not isinstance(envelope, cbor2.CBORTag) or envelope.tag != 18:
            return False
        if not isinstance(envelope.value, list) or len(envelope.value) != 4:
            return False
        protected_bytes, unprotected, payload_bytes, signature = envelope.value
        if unprotected != {} or not isinstance(protected_bytes, bytes) or not isinstance(payload_bytes, bytes):
            return False
        protected = cbor2.loads(protected_bytes)
        if encode(protected) != protected_bytes or not isinstance(protected, dict) or set(protected) != {1, 3, 4}:
            return False
        public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_id = hashlib.sha256(public_der).digest()
        if protected != {1: -19, 3: CONTENT_TYPE, 4: key_id}:
            return False
        payload = cbor2.loads(payload_bytes)
        if encode(payload) != payload_bytes or not isinstance(payload, dict):
            return False
        if set(payload) not in (set(range(1, 6)) | {7}, set(range(1, 8))):
            return False
        if (payload[1], payload[2], payload[3]) != ("ARAP", 1, "content-signature"):
            return False
        callsign, created = payload[4], payload[5]
        if not valid_callsign(callsign) or type(created) is not int or created < 0 or created > now + MAX_FUTURE_SKEW:
            return False
        if expected.get("callsign") and callsign != expected["callsign"]:
            return False
        subject = payload[7]
        if not isinstance(subject, dict) or set(subject) not in (set(range(1, 6)) | {7}, set(range(1, 8))):
            return False
        media, canonical, algorithm, digest, size, context = (subject.get(1), subject.get(2), subject.get(3), subject.get(4), subject.get(5), subject.get(7))
        content_id = subject.get(6)
        if not isinstance(media, str) or not 1 <= len(media.encode("utf-8")) <= 128:
            return False
        if canonical != "identity-v1" or algorithm != "sha-256":
            return False
        if not isinstance(digest, bytes) or len(digest) != 32 or type(size) is not int or size < 0:
            return False
        if not isinstance(context, str) or not 1 <= len(context.encode("utf-8")) <= 128:
            return False
        if 6 in subject and (not isinstance(content_id, str) or not 1 <= len(content_id.encode("utf-8")) <= 256):
            return False
        if (media, canonical, context) != (expected["media_type"], expected["canonicalization"], expected["context"]):
            return False
        public.verify(signature, encode(["Signature1", protected_bytes, b"", payload_bytes]))
        if 6 in payload:
            not_after = payload[6]
            if type(not_after) is not int or not_after <= created or now >= not_after:
                return False
        return size == len(content) and digest == hashlib.sha256(content).digest()
    except (InvalidSignature, KeyError, TypeError, ValueError, cbor2.CBORDecodeError, UnicodeError):
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public = private.public_key()
    public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    public_pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(public_der).digest()
    digest = hashlib.sha256(CONTENT).digest()

    subject = {1: MEDIA_TYPE, 2: "identity-v1", 3: "sha-256", 4: digest, 5: len(CONTENT), 7: CONTEXT}
    payload = {1: "ARAP", 2: 1, 3: "content-signature", 4: CALLSIGN, 5: CREATED, 7: subject}
    protected = encode({1: -19, 3: CONTENT_TYPE, 4: key_id})
    payload_bytes = encode(payload)
    sig_structure = encode(["Signature1", protected, b"", payload_bytes])
    signature = private.sign(sig_structure)
    proof = encode(cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]))
    proof_hash = hashlib.sha256(proof).digest()

    (args.out / "content.bin").write_bytes(CONTENT)
    (args.out / "proof.cbor").write_bytes(proof)
    (args.out / "public-key.pem").write_bytes(public_pem)
    (args.out / "test-seed.hex").write_text(SEED.hex() + "\n", encoding="ascii")
    manifest = {
        "profile": "ARAP", "version": 1, "purpose": "content-signature",
        "callsign": CALLSIGN, "created": CREATED, "media_type": MEDIA_TYPE,
        "canonicalization": "identity-v1", "context": CONTEXT,
        "content_sha256": digest.hex(), "content_size": len(CONTENT),
        "public_key_spki_sha256": key_id.hex(), "cose_algorithm": -19,
        "protected_headers_cbor_hex": protected.hex(), "payload_cbor_hex": payload_bytes.hex(),
        "signature_input_cbor_hex": sig_structure.hex(), "signature_hex": signature.hex(),
        "proof_sha256": proof_hash.hex(),
        "reference": "AR1" + base64.b32encode(proof_hash[:10]).decode("ascii").rstrip("="),
        "private_seed_is_test_only": True,
    }
    # Independently parse and verify the object just emitted.
    parsed = cbor2.loads(proof)
    assert isinstance(parsed, cbor2.CBORTag) and parsed.tag == 18
    assert parsed.value == [protected, {}, payload_bytes, signature]
    public.verify(signature, sig_structure)
    expected = {"media_type": MEDIA_TYPE, "canonicalization": "identity-v1", "context": CONTEXT, "callsign": CALLSIGN}
    if not accepts_content(proof, CONTENT, public, expected, CREATED):
        raise AssertionError("independent Python content verifier rejected valid vector")
    corrupt_proof = proof[:-1] + bytes([proof[-1] ^ 1])
    unknown_payload_proof = sign_payload(private, public, {**payload, 8: "unknown"})
    future_payload_proof = sign_payload(private, public, {**payload, 5: CREATED + MAX_FUTURE_SKEW + 1})
    expired_payload_proof = sign_payload(private, public, {**payload, 6: CREATED + 10})
    expired_items = list(cbor2.loads(expired_payload_proof).value)
    expired_payload = cbor2.loads(expired_items[2])
    expired_payload[6] = CREATED + 9
    expired_items[2] = encode(expired_payload)
    tampered_expiry_proof = encode(cbor2.CBORTag(18, expired_items))
    null_expiry_proof = sign_payload(private, public, {**payload, 6: None})
    empty_content_id_proof = sign_payload(private, public, {**payload, 7: {**subject, 6: ""}})
    wrong_public = Ed25519PrivateKey.from_private_bytes(bytes(reversed(SEED))).public_key()
    manifest["negative_checks"] = {
        "modified_content": not accepts_content(proof, CONTENT + b"x", public, expected, CREATED),
        "wrong_context": not accepts_content(proof, CONTENT, public, {**expected, "context": "other/v1"}, CREATED),
        "untrusted_key": not accepts_content(proof, CONTENT, public, expected, CREATED, trusted=False),
        "wrong_public_key": not accepts_content(proof, CONTENT, wrong_public, expected, CREATED),
        "corrupt_signature": not accepts_content(corrupt_proof, CONTENT, public, expected, CREATED),
        "unknown_signed_label": not accepts_content(unknown_payload_proof, CONTENT, public, expected, CREATED),
        "future_created": not accepts_content(future_payload_proof, CONTENT, public, expected, CREATED),
        "expired_content": not accepts_content(expired_payload_proof, CONTENT, public, expected, CREATED + 10),
        "tampered_expiry": not accepts_content(tampered_expiry_proof, CONTENT, public, expected, CREATED + 10),
        "null_expiry": not accepts_content(null_expiry_proof, CONTENT, public, expected, CREATED),
        "empty_content_id": not accepts_content(empty_content_id_proof, CONTENT, public, expected, CREATED),
    }
    if not all(manifest["negative_checks"].values()):
        raise AssertionError(f"independent content negative checks failed: {manifest['negative_checks']}")
    expired_envelope = cbor2.loads(expired_payload_proof).value
    expired_signature_input = encode(["Signature1", expired_envelope[0], b"", expired_envelope[2]])
    public.verify(expired_envelope[3], expired_signature_input)
    tampered_envelope = cbor2.loads(tampered_expiry_proof).value
    tampered_signature_input = encode(["Signature1", tampered_envelope[0], b"", tampered_envelope[2]])
    try:
        public.verify(tampered_envelope[3], tampered_signature_input)
    except InvalidSignature:
        manifest["expiry_signature_checks"] = {
            "valid_expired_signature": True,
            "tampered_expiry_signature_invalid": True,
        }
    else:
        raise AssertionError("tampered expiry unexpectedly verified")
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
