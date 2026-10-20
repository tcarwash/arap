# Test vectors — planned, not yet generated

This directory intentionally contains **no fabricated cryptographic values**. Once the exact CBOR labels and COSE headers are frozen, add deterministic vectors including keys expressly created for testing.

Required fixtures:

- `content-ed25519-valid`: canonical PixelQSO-like content, its SHA-256, COSE proof bytes and 80-bit reference
- `content-modified`: a one-pixel altered payload that fails digest verification
- `content-wrong-purpose`: proof valid cryptographically but rejected as challenge response
- `challenge-valid`: matching outstanding 128-bit nonce, signatures and expiry
- `challenge-replayed`: second acceptance attempt rejected
- `challenge-wrong-party`: verifier identity mismatch
- `key-untrusted`: signature valid but identity not established
- `reference-collision`: multiple prefix matches; only full verification decides
- `resolver-malicious`: deliberately wrong proof contents
- `tqsl-test`: after cert policy and COSE algorithm are independently validated

All vectors should specify **byte-for-byte** inputs/outputs and expected structured verification statuses. Never commit actual station private keys or exported `.p12` files.