#!/usr/bin/env python3
"""Generate independently signed, deterministic mutual challenge vectors."""
import hashlib
import json
from pathlib import Path
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISSUED = 1_800_000_000
LIFETIME = 120
SESSION = b"mutual-session-42"
PURPOSE = "station-auth"
CONTENT_TYPE = "application/vnd.arap.proof+cbor"
SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))


def encode(value):
    return cbor2.dumps(value, canonical=True)


def public_der(private):
    return private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def request(requester, responder, nonce):
    return encode({1: "ARAP", 2: 1, 3: "challenge-request", 4: requester,
                   5: responder, 6: nonce, 7: ISSUED, 8: ISSUED + LIFETIME,
                   9: PURPOSE, 10: SESSION})


def response(private, request_bytes):
    req = cbor2.loads(request_bytes)
    public = public_der(private)
    key_id = hashlib.sha256(public).digest()
    protected = encode({1: -19, 3: CONTENT_TYPE, 4: key_id})
    subject = {1: hashlib.sha256(request_bytes).digest(), 2: req[6],
               3: req[4], 4: req[5], 5: req[9], 6: req[8], 7: req[10]}
    payload = encode({1: "ARAP", 2: 1, 3: "challenge-response", 4: req[5],
                      5: ISSUED + 1, 6: req[8], 7: subject})
    to_sign = encode(["Signature1", protected, b"", payload])
    signature = private.sign(to_sign)
    return encode(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def verify(private, request_bytes, proof_bytes):
    req = cbor2.loads(request_bytes)
    envelope = cbor2.loads(proof_bytes)
    protected, unprotected, payload_bytes, signature = envelope.value
    header = cbor2.loads(protected)
    public = private.public_key()
    public.verify(signature, encode(["Signature1", protected, b"", payload_bytes]))
    payload = cbor2.loads(payload_bytes)
    subject = payload[7]
    return (envelope.tag == 18 and unprotected == {} and header[1] == -19
            and payload[4] == req[5] and subject[1] == hashlib.sha256(request_bytes).digest()
            and subject[2] == req[6]
            and (subject[3], subject[4], subject[5], subject[6]) == (req[4], req[5], req[9], req[8])
            and subject[7] == req[10])


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    private_a = Ed25519PrivateKey.from_private_bytes(SEED_A)
    private_b = Ed25519PrivateKey.from_private_bytes(SEED_B)
    req_a = request("K7ABC", "AG7SU", bytes(range(16)))
    req_b = request("AG7SU", "K7ABC", bytes(range(16, 32)))
    resp_a = response(private_a, req_b)
    resp_b = response(private_b, req_a)
    if not verify(private_a, req_b, resp_a) or not verify(private_b, req_a, resp_b):
        raise AssertionError("independent mutual response verification failed")
    files = {"request-from-a.cbor": req_a, "request-from-b.cbor": req_b,
             "response-from-a.cose": resp_a, "response-from-b.cose": resp_b,
             "public-key-a.der": public_der(private_a), "public-key-b.der": public_der(private_b)}
    for name, data in files.items():
        (output / name).write_bytes(data)
    manifest = {"profile": "ARAP", "version": 1, "purpose": PURPOSE,
                "party_a": "K7ABC", "party_b": "AG7SU", "issued_at": ISSUED,
                "expires_at": ISSUED + LIFETIME, "session_binding_hex": SESSION.hex(),
                "request_a_sha256": hashlib.sha256(req_a).hexdigest(),
                "request_b_sha256": hashlib.sha256(req_b).hexdigest(),
                "private_seeds_are_test_only": True,
                "negative_expectations": {"different_session": "mutual_purpose_or_session_mismatch",
                                           "same_nonce": "requests_are_not_one_fresh_pair"}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_mutual_challenge_vector.py OUTPUT_DIR")
    main()
