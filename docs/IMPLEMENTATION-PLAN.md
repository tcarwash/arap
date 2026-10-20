# Implementation plan and acceptance criteria

## M0 — Freeze the interoperable core (before claiming v1)

- Choose integer CBOR labels and exact types for all proof purposes.
- Choose mandatory protected COSE headers and algorithm allowlist.
- Define callsign syntax/normalization, purpose/domain separation, timestamp and challenge byte layout.
- Define full-hash and 80-bit reference bytes and optionally checksum/version.
- Publish valid/invalid deterministic golden vectors, independently tested in Go and Python.

**Done when:** two clean-room implementations verify identical bytes and make the same security decisions.

## M1 — Signed arbitrary content

- Native Ed25519 signing and verification.
- Detached object hashes with explicit content type and context.
- Structured trust results, without pretending unknown keys are callsign-verified.
- CLI: `keygen`, `sign-content`, `verify-content`, `inspect-proof`.

**Done when:** a saved PixelQSO-like byte blob can be signed and verified without an internet connection; single-byte changes fail verification.

## M2 — Challenges

- Secure nonce generation, requests, signed response and outstanding-challenge store.
- Expiry and replay rejection; strict requester/responder binding.
- CLI: `challenge`, `respond`, `verify-response`.

**Done when:** positive exchanges pass, stale/duplicate/wrong-party responses fail.

## M3 — Short references and proof server

- SHA-256 content addressing, standard Base32 80-bit prefix, candidate set retrieval.
- Optional object server with expiry/retention and size/abuse limits; client configured resolver list.
- CLI: `publish`, `resolve`, `verify-ref`.

**Done when:** ref mode makes exactly the same authenticity decision as full-proof mode; server cannot forge success.

## M4 — TQSL (conditional)

- Inspect current TQSL and ARRL policy; support PKCS#12 only if appropriate.
- Parse and validate chain, usages, callsign and status.
- Protect private keys; never log/export them by default.

**Done when:** a real allowed certificate can be verified with documented, reproducible trust policy, or the backend remains experimental if approval is unavailable.

## M5 — PixelQSO and optional OPV adapters

- PixelQSO stable canonical card encoding, signature attachment and verification UI.
- Optional OPV bridge using actual tested frame/control syntax, not guessed compatibility claims.

**Done when:** signed cards survive transmission and collection; direct/ref verification parity is demonstrated.

## Non-goals for initial implementation

No modem, no custom CA, no blockchain, no required account service, no automatic federation, no encrypted RF messaging, no mandatory QR code, no automated trust endorsement of strangers.