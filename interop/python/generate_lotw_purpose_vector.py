#!/usr/bin/env python3
"""Generate the deterministic v2 LoTW enrollment-purpose challenge vector."""

import argparse
import hashlib
import json
from pathlib import Path

import cbor2


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    challenge = {
        1: "ARAP-LoTW-enrollment",
        2: 2,
        3: "bind-ed25519-key",
        4: "https://verifier.example",
        5: "N0CALL",
        6: bytes(range(1, 33)),
        7: bytes(range(33, 65)),
        8: 1_800_000_000,
        9: 1_800_000_060,
        10: ["challenge-response", "content-signature"],
    }
    encoded = cbor2.dumps(challenge, canonical=True)
    args.out.mkdir(parents=True, exist_ok=True)
    vector = args.out / "challenge.cbor"
    vector.write_bytes(encoded)
    manifest = {
        "profile": "ARAP-LoTW-enrollment",
        "version": 2,
        "purpose": "bind-ed25519-key",
        "generator": "Python cbor2 deterministic encoding",
        "challenge_sha256": hashlib.sha256(encoded).hexdigest(),
        "callsign": "N0CALL",
        "key_id_hex": bytes(range(1, 33)).hex(),
        "nonce_hex": bytes(range(33, 65)).hex(),
        "allowed_purposes": challenge[10],
        "synthetic_only": True,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
