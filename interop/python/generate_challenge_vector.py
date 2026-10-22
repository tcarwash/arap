#!/usr/bin/env python3
"""Generate an independent canonical ARAP challenge request/response vector."""
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
ISSUED = 1_800_000_000
REQUESTER = "K7ABC"
RESPONDER = "AG7SU"
NONCE = bytes(range(16))
SESSION = b"session-42"
CONTENT_TYPE = "application/vnd.arap.proof+cbor"
MAX_LIFETIME = 600
FUTURE_SKEW = 30

def encode(value):
    return cbor2.dumps(value, canonical=True)

def valid_callsign(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Z0-9]+(?:/[A-Z0-9]+)*", value) is not None
        and any("A" <= char <= "Z" for char in value)
        and any("0" <= char <= "9" for char in value)
    )

def accepts_response(request_bytes, proof_bytes, public, expected_requester, now):
    try:
        request = cbor2.loads(request_bytes)
        if encode(request) != request_bytes or not isinstance(request, dict):
            return False
        if set(request) not in (set(range(1, 10)), set(range(1, 11))):
            return False
        requester, responder = request[4], request[5]
        issued, expires = request[7], request[8]
        if (request[1], request[2], request[3]) != ("ARAP", 1, "challenge-request"):
            return False
        if requester != expected_requester or not valid_callsign(requester):
            return False
        if not valid_callsign(responder) or requester == responder:
            return False
        if not isinstance(request[6], bytes) or len(request[6]) != 16:
            return False
        if type(issued) is not int or type(expires) is not int or expires <= issued or expires - issued > MAX_LIFETIME:
            return False
        if not isinstance(request[9], str) or not request[9] or len(request[9].encode("utf-8")) > 64:
            return False
        if 10 in request and (not isinstance(request[10], bytes) or not 1 <= len(request[10]) <= 128):
            return False
        envelope = cbor2.loads(proof_bytes)
        if encode(envelope) != proof_bytes or not isinstance(envelope, cbor2.CBORTag) or envelope.tag != 18:
            return False
        if not isinstance(envelope.value, list) or len(envelope.value) != 4:
            return False
        protected_bytes, unprotected, payload_bytes, signature = envelope.value
        if unprotected != {} or not isinstance(protected_bytes, bytes) or not isinstance(payload_bytes, bytes):
            return False
        protected = cbor2.loads(protected_bytes)
        if encode(protected) != protected_bytes or set(protected) != {1, 3, 4}:
            return False
        public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        key_id = hashlib.sha256(public_der).digest()
        if protected != {1: -19, 3: CONTENT_TYPE, 4: key_id}:
            return False
        payload = cbor2.loads(payload_bytes)
        if encode(payload) != payload_bytes or set(payload) != set(range(1, 8)):
            return False
        public.verify(signature, encode(["Signature1", protected_bytes, b"", payload_bytes]))
        if now < issued - FUTURE_SKEW or now >= expires:
            return False
        if (payload[1], payload[2], payload[3], payload[4]) != ("ARAP", 1, "challenge-response", responder):
            return False
        created, response_expires, subject = payload[5], payload[6], payload[7]
        if type(created) is not int or created < issued - FUTURE_SKEW or created > now + FUTURE_SKEW or created >= expires:
            return False
        if response_expires != expires or now >= response_expires:
            return False
        wanted_subject_keys = set(range(1, 8)) if 10 in request else set(range(1, 7))
        if not isinstance(subject, dict) or set(subject) != wanted_subject_keys:
            return False
        if subject[1] != hashlib.sha256(request_bytes).digest() or subject[2] != request[6]:
            return False
        if (subject[3], subject[4], subject[5], subject[6]) != (requester, responder, request[9], expires):
            return False
        if 10 in request and subject[7] != request[10]:
            return False
        return True
    except (AssertionError, InvalidSignature, KeyError, TypeError, ValueError, cbor2.CBORDecodeError):
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    request = encode({1:"ARAP",2:1,3:"challenge-request",4:REQUESTER,5:RESPONDER,6:NONCE,7:ISSUED,8:ISSUED+120,9:"station-auth",10:SESSION})
    request_hash = hashlib.sha256(request).digest()
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public = private.public_key()
    public_der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    public_pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(public_der).digest()
    subject = {1:request_hash,2:NONCE,3:REQUESTER,4:RESPONDER,5:"station-auth",6:ISSUED+120,7:SESSION}
    payload = {1:"ARAP",2:1,3:"challenge-response",4:RESPONDER,5:ISSUED+1,6:ISSUED+120,7:subject}
    protected = encode({1:-19,3:CONTENT_TYPE,4:key_id})

    def sign_response(claims, protected_bytes=protected):
        payload_bytes = encode(claims)
        signature_input = encode(["Signature1",protected_bytes,b"",payload_bytes])
        signature = private.sign(signature_input)
        return encode(cbor2.CBORTag(18,[protected_bytes,{},payload_bytes,signature])), payload_bytes, signature_input, signature

    proof, payload_bytes, signature_input, signature = sign_response(payload)
    proof_hash = hashlib.sha256(proof).digest()
    (args.out/"request.cbor").write_bytes(request)
    (args.out/"response.cose").write_bytes(proof)
    (args.out/"public-key.pem").write_bytes(public_pem)
    manifest={"profile":"ARAP","version":1,"requester":REQUESTER,"responder":RESPONDER,"purpose":"station-auth","issued_at":ISSUED,"expires_at":ISSUED+120,"nonce_hex":NONCE.hex(),"session_binding_hex":SESSION.hex(),"request_sha256":request_hash.hex(),"request_cbor_hex":request.hex(),"response_payload_cbor_hex":payload_bytes.hex(),"signature_input_cbor_hex":signature_input.hex(),"proof_sha256":proof_hash.hex(),"reference":"AR1"+base64.b32encode(proof_hash[:10]).decode("ascii").rstrip("="),"key_id_sha256":key_id.hex(),"private_seed_is_test_only":True}
    parsed=cbor2.loads(request)
    assert parsed=={1:"ARAP",2:1,3:"challenge-request",4:REQUESTER,5:RESPONDER,6:NONCE,7:ISSUED,8:ISSUED+120,9:"station-auth",10:SESSION}
    parsed_proof=cbor2.loads(proof)
    assert isinstance(parsed_proof,cbor2.CBORTag) and parsed_proof.tag==18
    public.verify(signature,signature_input)
    if not accepts_response(request, proof, public, REQUESTER, ISSUED + 2):
        raise AssertionError("independent Python challenge verifier rejected valid vector")
    changed_request = encode({**parsed, 10: b"session-43"})
    corrupt_proof = proof[:-1] + bytes([proof[-1] ^ 1])
    envelope_value = cbor2.loads(proof).value
    unprotected_proof = encode(cbor2.CBORTag(18, [envelope_value[0], {99: "extra"}, envelope_value[2], envelope_value[3]]))
    untagged_proof = encode(envelope_value)
    noncanonical_proof = b"\xd2\x9f" + b"".join(encode(item) for item in envelope_value) + b"\xff"
    unknown_payload = sign_response({**payload, 8: "extension"})[0]
    missing_payload = sign_response({key: value for key, value in payload.items() if key != 7})[0]
    wrong_algorithm_protected = encode({1: -8, 3: CONTENT_TYPE, 4: key_id})
    wrong_algorithm_proof = sign_response(payload, wrong_algorithm_protected)[0]
    def signed_subject_change(label, value, *, top_level=None):
        claims = {**payload, 7: {**subject, label: value}}
        if top_level is not None:
            claims[top_level[0]] = top_level[1]
        return sign_response(claims)[0]

    negative_results = {
        "edited_request_binding": not accepts_response(changed_request, proof, public, REQUESTER, ISSUED + 2),
        "wrong_requester": not accepts_response(request, proof, public, "W1XYZ", ISSUED + 2),
        "corrupt_signature": not accepts_response(request, corrupt_proof, public, REQUESTER, ISSUED + 2),
        "expired_request": not accepts_response(request, proof, public, REQUESTER, ISSUED + 120),
        "wrong_responder": not accepts_response(request, signed_subject_change(4, "W1XYZ", top_level=(4, "W1XYZ")), public, REQUESTER, ISSUED + 2),
        "wrong_nonce": not accepts_response(request, signed_subject_change(2, bytes(reversed(NONCE))), public, REQUESTER, ISSUED + 2),
        "wrong_requested_purpose": not accepts_response(request, signed_subject_change(5, "other-purpose"), public, REQUESTER, ISSUED + 2),
        "wrong_request_expiry": not accepts_response(request, signed_subject_change(6, ISSUED + 121), public, REQUESTER, ISSUED + 2),
        "wrong_session_binding": not accepts_response(request, signed_subject_change(7, b"session-43"), public, REQUESTER, ISSUED + 2),
        "wrong_response_expiry": not accepts_response(request, sign_response({**payload, 6: ISSUED + 121})[0], public, REQUESTER, ISSUED + 2),
        "untagged_cose_sign1": not accepts_response(request, untagged_proof, public, REQUESTER, ISSUED + 2),
        "noncanonical_cose_array": not accepts_response(request, noncanonical_proof, public, REQUESTER, ISSUED + 2),
        "unprotected_header": not accepts_response(request, unprotected_proof, public, REQUESTER, ISSUED + 2),
        "unknown_response_payload_field": not accepts_response(request, unknown_payload, public, REQUESTER, ISSUED + 2),
        "missing_response_subject": not accepts_response(request, missing_payload, public, REQUESTER, ISSUED + 2),
        "unsupported_cose_algorithm": not accepts_response(request, wrong_algorithm_proof, public, REQUESTER, ISSUED + 2),
    }
    if not all(negative_results.values()):
        raise AssertionError(f"independent challenge negative checks failed: {negative_results}")
    manifest["negative_checks"] = negative_results
    (args.out/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(manifest,sort_keys=True))

if __name__=="__main__": main()
