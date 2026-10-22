#!/usr/bin/env python3
"""Generate the deterministic two-link key-endorsement interoperability vector."""
import hashlib
import json
from pathlib import Path
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CREATED = 1_800_000_000
CONTENT_TYPE = "application/vnd.arap.proof+cbor"
ROOT_SEED = bytes(range(32))
DELEGATE_SEED = bytes(range(32, 64))
SUBJECT_SEED = bytes(range(64, 96))


def encode(value):
    return cbor2.dumps(value, canonical=True)


def public_der(private):
    return private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


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


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    root = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
    delegate = Ed25519PrivateKey.from_private_bytes(DELEGATE_SEED)
    subject = Ed25519PrivateKey.from_private_bytes(SUBJECT_SEED)
    first = issue(root, "K1ROOT", "K2DELEG", delegate, ["content-signature", "key-endorsement"], 1)
    second = issue(delegate, "K2DELEG", "K3SUBJ", subject, ["content-signature"], 0)
    chain = encode({1: "ARAP-key-endorsement-chain", 2: 1, 3: [first, second]})
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
