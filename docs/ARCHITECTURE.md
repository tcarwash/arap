# Architecture decisions — draft

## A1: One signature object, multiple purpose types

Use COSE_Sign1 for every signed proof. The CBOR payload includes signed `purpose` so that a signed PixelQSO card cannot accidentally satisfy an authentication challenge. Maintain separate verifiers for content, challenge-response, and endorsements.

## A2: Content is independently hashable

Sign an application-defined canonical byte sequence identified by digest, size and context. This is necessary for detachable proofs, asynchronous delivery, local card collections, and future transports. A signature remains valid for the **unchanged object** indefinitely, subject to time/trust policy; it never proves current station presence.

## A3: Direct verification is always viable

No central service or online presence is required to cryptographically verify a full signed proof and attached content if trusted key information is already present.

## A4: Proof hosts are untrusted

Proof bytes are addressed by SHA-256. Short prefix lookup only retrieves candidate proofs. Client-side crypto, challenge, signed-purpose and trust validation determines acceptance.

## A5: Identity trust is separate from signature validity

A valid Ed25519 signature from an unknown key must not display as `ARRL-verified`. Certificate expiry, revocation, intended use, callsign and issuer trust must be examined separately.

## A6: Opulent Voice interoperability is opt-in

An OPV adapter maps protocol messages to ARAP objects. No waveform, codec or frame-format code belongs in the core package.

## Suggested package boundaries

```text
arap-core          COSE/CBOR proof encoding, digest, algorithms, validators
arap-identity      native keys, trust policy, optional tqsl/pkcs12 adapters
arap-content       signed object / application-defined canonicalizers
arap-challenge     nonce issuance, pending challenge, one-time verification
arap-reference     Base32 identifiers, content addresses, HTTP resolver
arap-cli           sign, verify, challenge, respond, publish, resolve
arap-server        optional untrusted minimal object store
arap-adapters      later: pixelqso, opv, other applications
```

**Important:** No automatic trust inheritance from an arbitrary certificate chain or unrelated QSO signature.