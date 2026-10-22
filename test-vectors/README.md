# Test vectors

`content-ed25519-v1/` contains an independently generated, deterministic content-signature vector. Its Python verifier records negative decisions for changed content, wrong expectations, untrusted or wrong keys, a corrupt signature, an unknown signed label, future creation, expiry, an unauthenticated expiry edit, null expiry and empty content ID. The manifest also records that an expired proof can still have a valid signature while changing its expiry claim invalidates that signature. `pixelqso-card-v1/` contains a synthetic two-frame saved-card pair, an independently generated BLAKE2s-64 frame fingerprint, and canonical CBOR content vectors. `challenge-ed25519-v1/` contains a canonical challenge request and signed response using the same test-only Ed25519 seed. Its Python verifier records sixteen negative checks across request binding, parties, signature, expiry, session and purpose values, COSE structure, algorithm selection and signed payload schema. `lotw-enrollment-v2/` contains an independently Python-generated purpose-scoped enrollment challenge with synthetic key ID and nonce. Neither signing seed may ever be used for a station or production key. Python generators in `interop/python/` use pinned dependencies and emit proofs, public keys and manifests.

Go tests regenerate the content and challenge COSE objects and check byte-for-byte equality with the Python-generated vectors; they also compare the version 2 enrollment-purpose challenge vector byte for byte. The PixelQSO adapter matches the independent Python canonical CBOR bytes. `lotw-enrollment-v1/challenge.cbor` remains the backward-compatible challenge-only fixture; its fingerprint and nonce are synthetic values. `response-shape.cbor` checks deterministic response encoding and schema bounds with deliberately fake signatures and a placeholder certificate; it is not cryptographic evidence. The Python content verifier checks proof structure, signature, trust input, content digest/size and policy expectations, then asserts rejection for eleven negative cases. The Python challenge verifier checks request/response structure, signature and bindings, then asserts rejection for sixteen negative cases, including malformed COSE envelopes, unsupported algorithms, malformed signed payload schemas, and correctly signed responses with incorrect party, nonce, purpose, expiry, or session binding. This demonstrates agreement for these tested vectors; it is not a security audit, PixelQSO RF interoperability, or TQSL interoperability evidence.

`key-endorsement-v1/` contains a two-link Ed25519 delegation chain generated and independently verified in Python, then verified by Go. Its `chain.cbor` container is also encoded byte-for-byte by Go and validated against the chain CDDL. Python asserts rejection for a wrong root, unauthorized purpose, purpose escalation and wrong expected subject. The fixture grants the final key only `content-signature`; the issuer public key is an explicit test trust anchor. The deterministic private seeds are test-only and must never be used outside these fixtures.

`mutual-challenge-ed25519-v1/` contains inverse requests and independently generated Ed25519 responses for both parties, sharing one session binding and validity window. The Python generator verifies both response signatures and request bindings; the Go test verifies the pair under explicit trust and consumes both requests atomically. Both requests and responses are checked against their CDDL schemas.

Run `make cddl` to independently compile the schemas against RFC 8610 and validate the checked-in content proof, one-way and mutual challenge requests and responses, enrollment challenge and response shape, key-endorsement chain, and both PixelQSO canonical-card vectors with the pinned `cddl` v0.10.7 tool.

More required cases:

- modified bytes and modified proof/signature
- wrong purpose, content type or context
- duplicate CBOR keys, non-deterministic encoding, extra fields and trailing items
- unknown and disabled callsign/key bindings
- expired signed content
- Real TQSL certificate identity binding; the verifier-side enrollment prototype uses only synthetic credentials
- reference candidate ambiguity and malicious keyserver responses

Never commit station private keys or exported `.p12` files.
