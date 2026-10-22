#!/usr/bin/env python3
"""Generate the deterministic two-link key-endorsement interoperability vector."""
import hashlib
import json
from pathlib import Path
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CREATED = 1_800_000_000
CONTENT_TYPE = "application/vnd.arap.proof+cbor"
ROOT_SEED = bytes(range(32))
DELEGATE_SEED = bytes(range(32, 64))
SUBJECT_SEED = bytes(range(64, 96))


def encode(value):
    return cbor2.dumps(value, canonical=True)


def public_der(private):
    public = private.public_key() if hasattr(private, "public_key") else private
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def pem_public(private):
    return private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def issue(signer, issuer, subject_call, subject_key, purposes, depth):
    subject_der = public_der(subject_key)
    payload = encode({
        1: "ARAP", 2: 1, 3: "key-endorsement", 4: issuer,
        5: CREATED, 6: CREATED + 86_400,
        7: {1: subject_call, 2: subject_der, 3: purposes}, 8: depth,
    })
    key_id = hashlib.sha256(public_der(signer)).digest()
    protected = encode({1: -19, 3: CONTENT_TYPE, 4: key_id})
    to_sign = encode(["Signature1", protected, b"", payload])
    signature = signer.sign(to_sign)
    return encode(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def decode_proof(proof):
    envelope = cbor2.loads(proof)
    if encode(envelope) != proof or not isinstance(envelope, cbor2.CBORTag) or envelope.tag != 18:
        raise ValueError("invalid COSE envelope")
    if not isinstance(envelope.value, list) or len(envelope.value) != 4:
        raise ValueError("invalid COSE Sign1")
    protected, unprotected, payload, signature = envelope.value
    headers = cbor2.loads(protected)
    statement = cbor2.loads(payload)
    if (encode(headers) != protected or unprotected != {} or set(headers) != {1, 3, 4}
            or headers[1] != -19 or headers[3] != CONTENT_TYPE or encode(statement) != payload
            or set(statement) != set(range(1, 9))):
        raise ValueError("invalid endorsement structure")
    return headers, statement, signature, encode(["Signature1", protected, b"", payload])


def verify_chain(encoded_chain, root_key, *, root_call="K1ROOT", root_purposes=None,
                 root_depth=2, subject_call="K3SUBJ", subject_key=None,
                 purpose="content-signature", now=CREATED + 1):
    try:
        container = cbor2.loads(encoded_chain)
        if encode(container) != encoded_chain or not isinstance(container, dict):
            return "invalid_chain_encoding"
        if (set(container) != {1, 2, 3} or container[1] != "ARAP-key-endorsement-chain"
                or container[2] != 1 or not isinstance(container[3], list)
                or not 1 <= len(container[3]) <= 8):
            return "invalid_chain_encoding"
        root_der = public_der(root_key)
        first_headers, _, _, _ = decode_proof(container[3][0])
        if first_headers[4] != hashlib.sha256(root_der).digest():
            return "untrusted_root"
        current_key = root_key.public_key()
        current_call = root_call
        allowed = set(root_purposes or ["content-signature", "key-endorsement"])
        depth = root_depth
        seen = {hashlib.sha256(root_der).digest()}
        for index, proof in enumerate(container[3]):
            if depth == 0:
                return "delegation_depth_exceeded"
            headers, statement, signature, signed = decode_proof(proof)
            if headers[4] != hashlib.sha256(public_der(current_key)).digest():
                return "issuer_key_mismatch"
            try:
                current_key.verify(signature, signed)
            except Exception:
                return "invalid_signature_or_envelope"
            if (statement[1], statement[2], statement[3], statement[4]) != ("ARAP", 1, "key-endorsement", current_call):
                return "issuer_callsign_mismatch"
            created, expires, subject, delegated_depth = statement[5], statement[6], statement[7], statement[8]
            if type(created) is not int or type(expires) is not int or now >= expires:
                return "expired"
            if expires <= created or expires - created > 365 * 24 * 60 * 60:
                return "invalid_validity"
            if not isinstance(subject, dict) or set(subject) != {1, 2, 3}:
                return "invalid_endorsement_payload"
            call, subject_der, purposes = subject[1], subject[2], subject[3]
            if not isinstance(purposes, list) or len(set(purposes)) != len(purposes) or not set(purposes) <= allowed:
                return "purpose_escalation"
            if type(delegated_depth) is not int or delegated_depth >= depth or delegated_depth > 8:
                return "delegation_depth_escalation"
            subject_id = hashlib.sha256(subject_der).digest()
            if subject_id in seen:
                return "delegation_cycle"
            seen.add(subject_id)
            parsed = serialization.load_der_public_key(subject_der)
            if not isinstance(parsed, Ed25519PublicKey):
                return "invalid_subject_key"
            if index == len(container[3]) - 1:
                if call != subject_call or subject_key is None or subject_der != public_der(subject_key):
                    return "subject_mismatch"
                if purpose not in purposes:
                    return "purpose_not_authorized"
                return "accepted"
            current_key = serialization.load_der_public_key(subject_der)
            current_call = call
            allowed = set(purposes)
            depth = delegated_depth
        return "incomplete_chain"
    except Exception:
        return "invalid_chain_encoding"


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    root = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
    delegate = Ed25519PrivateKey.from_private_bytes(DELEGATE_SEED)
    subject = Ed25519PrivateKey.from_private_bytes(SUBJECT_SEED)
    first = issue(root, "K1ROOT", "K2DELEG", delegate, ["content-signature", "key-endorsement"], 1)
    second = issue(delegate, "K2DELEG", "K3SUBJ", subject, ["content-signature"], 0)
    chain = encode({1: "ARAP-key-endorsement-chain", 2: 1, 3: [first, second]})
    accepted = verify_chain(chain, root, subject_key=subject)
    negative_checks = {
        "wrong_root_rejected": verify_chain(chain, delegate, subject_key=subject) == "untrusted_root",
        "unauthorized_challenge_purpose_rejected": verify_chain(chain, root, subject_key=subject, purpose="challenge-response") == "purpose_not_authorized",
        "wrong_subject_rejected": verify_chain(chain, root, subject_call="K4OTHER", subject_key=subject) == "subject_mismatch",
        "purpose_escalation_rejected": verify_chain(chain, root, root_purposes=["key-endorsement"]) == "purpose_escalation",
    }
    if accepted != "accepted" or not all(negative_checks.values()):
        raise AssertionError(f"independent endorsement checks failed: accepted={accepted}, negatives={negative_checks}")
    (output / "root-to-delegate.cbor").write_bytes(first)
    (output / "delegate-to-subject.cbor").write_bytes(second)
    (output / "chain.cbor").write_bytes(chain)
    (output / "root-public.pem").write_bytes(pem_public(root))
    (output / "subject-public.pem").write_bytes(pem_public(subject))
    manifest = {
        "profile": "ARAP", "version": 1, "purpose": "key-endorsement",
        "created": CREATED, "expires_at": CREATED + 86_400,
        "issuer": "K1ROOT", "delegate": "K2DELEG", "subject": "K3SUBJ",
        "delegated_purposes": ["content-signature", "key-endorsement"],
        "subject_purposes": ["content-signature"], "chain_depth": 2,
        "private_seeds_are_test_only": True,
        "independent_python_verification": "accepted",
        "negative_checks": negative_checks,
        "negative_expectations": {
            "wrong_root": "untrusted_root",
            "challenge_response_purpose": "purpose_not_authorized",
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_endorsement_vector.py OUTPUT_DIR")
    main()
