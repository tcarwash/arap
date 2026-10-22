# Architecture decisions — draft

## A1: One signature object, multiple purpose types

Use COSE_Sign1 for every signed proof. The CBOR payload includes signed `purpose` so that a signed PixelQSO card cannot accidentally satisfy an authentication challenge. Maintain separate verifiers for content, challenge-response, and endorsements.

The proof format uses standard COSE Sign1 and a small profile-specific CBOR payload. The implemented prototype uses Ed25519 (`-19`, RFC 9864) with independent keys; a callsign identity requires a separate enrollment. The inspected TQSL arbitrary-block API hardcodes RSA-SHA1, so it cannot sign this profile. The experimental enrollment flow uses a fresh dual-signature challenge to bind a LoTW callsign certificate to an Ed25519 key. Its optional native TQSLLIB responder never exports the TQSL private key and is accepted only for the enrollment assertion; the UI explains the algorithm before use. That signature is authentication evidence under ARAP policy, not an ARRL-approved login or endorsement, and never an ARAP content signature. The root and status policy follows TQSL's configured certificate roots and LoTW serial-status source; live-certificate validation remains incomplete. TQSL is not a general-purpose backend for hashing, randomness, keyserver transport, or proof parsing. See the [TQSL finding](TQSL-RESEARCH.md) and [LoTW binding design](LOTW-BINDING-DESIGN.md).

## A2: Content is independently hashable

Sign an application-defined canonical byte sequence identified by digest, size and context. This is necessary for detachable proofs, asynchronous delivery, local card collections, and future transports. A signature can remain mathematically valid for the **unchanged object**, while current acceptance depends on time/trust policy; it never proves current station presence or independently establishes signing time.

## A3: Direct verification is always viable

No central service or online presence is required to cryptographically verify a full signed proof and attached content if trusted key information is already present.

## A4: Proof hosts are untrusted

Proof bytes are addressed by SHA-256. Short prefix lookup only retrieves candidate proofs. Client-side crypto, challenge, signed-purpose and trust validation determines acceptance.

## A5: Identity trust is separate from signature validity

Cryptographic signature validity and callsign authorization are different results. TQSL is the preferred integration for selecting and managing ham credentials and for applying supported callsign-certificate policy; generic primitives and offline proof verification remain in ARAP. The verifier trusts the configured TQSL root bundle and checks current serial status through the LoTW endpoint used by TQSL. Its 24-hour default freshness bound is ARAP policy over the endpoint response time; it does not prove when LoTW's underlying status database changed. Live station-certificate validation remains open. The key-encoding API can export private material, so the helper never calls it; the enrollment-only adapter calls the TQSL signing lifecycle and does not export the key. ARAP labels the result as authentication evidence under ARAP policy, never as an ARRL-approved login or endorsement; the independent Ed25519 signature must not display as `ARRL-verified`.

Content verification results expose signed claims only after the COSE signature verifies. Invalid or unchecked proofs must not present attacker-supplied payload fields as authenticated; callers that need diagnostics can use `inspect-proof`, whose output explicitly labels claims untrusted.

The public `protocol.Signer` interface is still constrained by the v1 profile: signing requires an Ed25519 public key and verifies the provider's returned signature locally before emitting a proof. Algorithm labels, key types and signature bytes must agree; a signer provider cannot widen the wire algorithm allowlist by claiming `-19`. The separate TQSL adapter applies only to the experimental enrollment assertion.

## A6: Opulent Voice interoperability is opt-in

An OPV adapter maps protocol messages to ARAP objects. No waveform, codec or frame-format code belongs in the core package.

## Suggested package boundaries

These are conceptual boundaries. The implementation plan proposes packages within one Go module, introduced as needed, rather than separately released modules.

```text
arap-core          COSE/CBOR proof encoding, digest, algorithms, validators
identity/          Ed25519 keys, local trust, public-key parsing
protocol/          COSE content proofs, hashing, verification policy
lotwenroll/        TQSL enrollment evidence and certificate status policy
challenge/         nonce issuance, pending challenge, one-time/mutual verification
reference/         Base32 identifiers, content addresses, bounded HTTP client
adapters/pixelqso/ PixelQSO card canonicalization and proof integration
endorsement/       scoped key delegation and offline chain verification
cmd/arap/          content, trust, challenge, enrollment, and reference CLI
cmd/arap-keyserver optional untrusted object service
```

**Important:** No automatic trust inheritance from an arbitrary certificate chain or unrelated QSO signature.
