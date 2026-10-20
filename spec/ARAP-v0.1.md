# Amateur Radio Authentication Profile (ARAP)

**Status:** Draft v0.1 — design proposal, not an adopted standard  
**Date:** 2026-10-20  
**Intended audience:** amateur-radio application developers, station operators, implementers of independent transports  
**License of this specification:** CC0-1.0 (proposed; see project README)

> **Design goal:** Reuse existing cryptographic formats for verifiable signed amateur-radio material, including PixelQSO cards, without requiring a particular modem, waveform, online service, or live challenge-response session.

## 1. Scope and principles

ARAP is a small application profile over established standards. It defines how an amateur-radio callsign identity, signed content, optional interactive authentication challenges, and abbreviated references to independently verifiable proofs fit together. It **does not** define new cryptography, an RF waveform, a certificate authority, or a generalized authentication framework.

The same signed envelope MUST be verifiable whether carried in a digital RF frame, downloaded from HTTPS storage, saved in a file, or transported by another medium. The envelope MUST NOT require access to its original transport.

ARAP has three independent uses:

1. **Signed content (`content-signature`)** — prove that a key signed a specified content object, e.g., a PixelQSO card, text bulletin, or file. No challenge or live counterparty is necessary.
2. **Interactive station authentication (`challenge-response`)** — respond to a fresh verifier-generated challenge, binding the responding callsign, verifier, and challenge to a signature.
3. **Key endorsement (`key-endorsement`)** — a pre-existing trusted key attests that another key is authorized for a named callsign, subject to explicit local trust policy. Endorsement MUST NOT silently inherit TQSL/LoTW authority.

These are distinct *purposes* with domain separation. A content signature MUST NOT be accepted as a challenge-response proof, and a key endorsement MUST NOT be treated as evidence of live RF participation.

### 1.1 Normative vocabulary

The terms MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express requirements for this draft. No claim of IETF or ARRL standardization is made.

### 1.2 Threat model

ARAP targets accidental modifications, impersonation without private-key possession, forged content, and replay of previously recorded challenge responses. It does not prevent deliberate RF jamming, denial of service, credential compromise, key-sharing, real-time relay attacks, or impersonation by someone who has access to a valid private key. Signing content does **not** prove where or when it was transmitted or received.

## 2. Reused standards

- **COSE_Sign1** from RFC 9052, with algorithms and identifiers from RFC 9053. Implementations MUST use standard COSE signature input construction, not directly sign their own JSON strings.
- **CBOR** per RFC 8949. Use deterministic encoding as defined there wherever the profile serializes its own CBOR maps; the exact signed bytes in the COSE payload are authoritative.
- **X.509 certificate references** following RFC 9360 when X.509 identity material is used.
- **SHA-256** for object digests and content addressing.
- **Base32** per RFC 4648, uppercase unpadded, for manually exchanged identifiers. A future human-safe alphabet MAY be separately versioned; v0.1 uses standard Base32 for simplicity.
- **HTTPS** for optional proof publication and retrieval.

**Compatibility note:** Reusing COSE does not establish interoperability with Opulent Voice (OPV). An OPV adapter must map its authentication request/response structures to this profile, and actual byte-level interoperability requires agreement with its implementers.

## 3. Data model

### 3.1 Proof envelope

An ARAP proof is one COSE_Sign1 object whose signed payload is a CBOR map. Conceptually, the decoded payload contains:

| Field | Meaning |
|---|---|
| `profile` | Literal `ARAP` |
| `version` | Integer `1` (this draft's wire-format proposal) |
| `purpose` | `content-signature`, `challenge-response`, or `key-endorsement` |
| `signer` | Normalized callsign claimed by the signing key |
| `created` | UTC Unix timestamp in seconds |
| `not_after` | Optional UTC Unix timestamp in seconds, required for challenge responses |
| `subject` | Purpose-specific structure, detailed below |

**Important:** The human-readable field names in this section define semantics, **not** frozen CBOR integer labels. Before declaring protocol version 1 interoperable, an implementation must freeze field labels, types, signing headers, and byte-level golden vectors. Do not advertise cross-implementation v1 compatibility before that is done.

CBOR and COSE format constraints:

- Use a single COSE_Sign1 signature. The protected header MUST identify the algorithm and MUST contain a profile-specific content-type or equivalent unambiguous application marker.
- The signer key identity MUST be unambiguously bound to the verified key. The `kid` header MAY be a full SHA-256 digest of the DER SubjectPublicKeyInfo; a truncated key identifier MUST NOT determine trust by itself.
- The signature covers the entire CBOR payload. The proof's signed payload, protected headers, and attached identity evidence must be interpreted according to COSE processing rules.
- Verification MUST reject unknown critical COSE headers, unsupported algorithms, mismatched profile/version/purpose, malformed values, and ambiguous encodings.
- Unrecognized noncritical payload fields MAY be ignored only if their semantics cannot change the security decision; critical extensions require a versioned rule.
- There is **no encryption** in ARAP.

### 3.2 Callsign strings

For comparisons, a callsign is converted to ASCII uppercase and surrounding whitespace removed. Internal spaces and control characters are invalid. Allowed syntactic forms and portable suffixes require a separately published grammar; v0.1 implementations SHOULD preserve the original displayed callsign and SHOULD avoid treating variations such as `AG7SU`, `AG7SU/P`, and `AG7SU/7` as interchangeable without an explicit binding rule.

A signature only establishes control of the signing key. Authorization to claim a callsign is a separate identity-validation result.

## 4. Signed content: the primary reusable operation

A `content-signature` subject binds the signature to **bytes representing the content** rather than to a current contact or timestamp.

Conceptual subject:

```yaml
kind: content-signature
media_type: application/vnd.pixelqso.card+cbor  # example; not yet registered
canonicalization: pixelqso-card-v1                # example app-defined identifier
content_digest_algorithm: sha-256
content_digest: <32 raw bytes>
content_size: <integer length in bytes>
content_id: <optional app-local object identifier>
context: <optional domain/app identifier, e.g. "pixelqso/card/v1">
```

Rules:

1. Every content type MUST define the exact bytes hashed. Prefer hashing the stored/transmitted original bytes directly; if semantic canonicalization is required, the application MUST publish a deterministic algorithm and version.
2. Compute `content_digest = SHA256(content_bytes)`; include the original byte length. Verifiers MUST recompute both against the presented content.
3. The signed subject MUST bind a type or domain (`media_type` and/or `context`) to stop one file's digest from being confused for a different kind of signed statement.
4. Signing does not require that the content itself be uploaded, that its author be online, or that the recipient be named.
5. Detached content and detached signatures are allowed. A receiver MUST NOT show a card as **verified** until it has the correct card bytes and a valid proof bound to them.
6. Publication may happen later. A receiving application MAY store a card as **signature pending** while awaiting its signature or certificate.
7. Re-signing an unchanged card makes a new proof; editing a single pixel produces a different digest and invalidates the old signature for the altered content.

### 4.1 PixelQSO profile (proposed)

PixelQSO SHOULD define one portable serialized card representation with palette, dimensions, pixel indices, and any metadata that is intended to be authenticated. Prefer a deterministic binary serialization (`pixelqso-card-v1`) rather than hashing screenshots or PNG encodings, because images can encode identical visible pixels with different file bytes.

If PixelQSO wants some mutable metadata (received-at timestamp, local deck notes, display name), it MUST explicitly keep it **outside** the signed bytes. Signature verification reports exactly what was signed, not all UI fields.

Suggested display distinctions:

- `signature-valid / callsign-trusted`
- `signature-valid / key-untrusted`
- `signature-invalid`
- `unsigned`
- `verification-incomplete` (proof, content, or certificate missing)

A key endorsement can establish a trust path, but application policy determines whether that path counts as a verified callsign.

## 5. Interactive challenge–response

Unlike content signing, `challenge-response` proves recent access to a private key in response to a specific verifier's request. It does not inherently prove physical RF presence.

A challenge is a structured request containing:

```yaml
profile: ARAP
version: 1
requester: K7ABC
responder: AG7SU
nonce: <16 cryptographically random bytes>
issued_at: <UTC seconds>
requested_purpose: station-auth
optional_session_binding: <application-specific digest or identifier>
```

The responder MUST sign the exact challenge bytes or an unambiguous digest of those bytes embedded in its signed response subject. The subject MUST include the full challenge digest and its nonce, requester and responder identities, authentication purpose, and expiry. Requesters MUST compare against a locally recorded *outstanding* challenge; mere freshness based on clocks is insufficient.

A compliant verifier MUST check signature, callsign trust policy, audience, challenge equality, expiry, and single-use acceptance. Repeated responses to the same challenge MUST NOT be accepted as a new session authentication. A nonce generated for manual CW/voice MUST still be unpredictable; the default is **128 bits**. A smaller manual challenge would require a separately analyzed profile rather than silent truncation.

Where the protocol requires mutual authentication, both sides must perform their own challenge–response exchange or use an explicitly defined mutual-handshake profile.

## 6. Key endorsements

A `key-endorsement` is a signed statement containing at least the issuer callsign/key ID, subject callsign, exact subject public-key fingerprint, issuance and expiry, and clearly restricted purpose(s) such as `content-signature` or `challenge-response`.

Clients MUST NOT interpret a self-issued endorsement as independent callsign identity proof. Clients MUST limit trust delegation by explicit policy, path depth, and accepted issuers. A LoTW/TQSL credential MAY endorse an ARAP-native key only when permitted by the credential's use policy and verified under an explicitly documented trust rule.

This purpose is **experimental** in draft v0.1; native direct signing works without endorsements.

## 7. Identity and trust

Support two independent key providers:

**Native identity.** Ed25519 using COSE algorithm `EdDSA`, with key fingerprints and a configurable trust store. An unknown native key can produce a mathematically valid signature but is not automatically a callsign-verified identity.

**TQSL-backed identity.** Reuse the station's existing TQSL/LoTW certificate and private key only if appropriate use is technically supported and consistent with applicable certificate policy. An initial prototype MAY import a user-exported PKCS#12 key; avoid unnecessary persistent copies of private keys. Key types, COSE algorithm mapping, certificate Key Usage/EKU, callsign extraction, trust anchors, and revocation/status checking MUST be explicitly validated. Do not treat an X.509 chain as trusted merely because signature verification succeeds.

TQSL-specific trust is **provisional** until technical and policy research is completed. The project MUST NOT claim that ARRL endorses this use, that TQSL allows arbitrary-message signing through its public API, or that LoTW provides a public certificate lookup/revocation service without verification.

A verifier MUST surface separate results for `cryptographic_signature`, `content_integrity`, `callsign_identity`, `challenge_freshness` (if applicable), and `overall_policy`.

## 8. Direct and reference transports

Every proof is a complete COSE_Sign1 byte string. It can be sent in full without a network dependency, or published for retrieval using a short on-air reference.

### 8.1 Full proof

Send the exact signed COSE bytes, and include the necessary certificate/key material or identify a separately retrievable trusted key. This is the authoritative offline verification form.

### 8.2 Content addressing

Let `P` be the exact serialized COSE_Sign1 bytes of a completed proof. Compute `D = SHA256(P)`.

The v0.1 *example* short token is the first **80 bits** of `D`, encoded using RFC 4648 uppercase, unpadded Base32 (16 symbols), with a human prefix `AR1` outside the token. Example presentation: `AR1 ABCD EFGH IJKL MNOP` (illustrative, not a computed value).

The token is a **locator**, not an independent verifier. An attacker may publish a colliding prefix, so the resolver MUST return a candidate set or signal ambiguity, and the client MUST hash each returned candidate, match the advertised prefix, then check the complete signature and subject against local expectations. Prefix matching alone MUST NEVER result in a verified state.

A transcription checksum is optional in this draft and MUST be explicitly versioned if added. A checksum checks typing errors, not authenticity.

### 8.3 Publication and resolution

An operator MAY upload P to any HTTPS object store or resolver. Use the full hex SHA-256 digest as the immutable storage key. Suggested minimal paths (non-normative):

```http
PUT /v1/proofs/{sha256-hex}
GET /v1/proofs/{sha256-hex}
GET /v1/lookup/{80-bit-base32-prefix}
```

The resolver is **not a trust authority**. It can be offline, censor entries, index bad records, or return candidates in any order. The client MUST verify cryptographically and must handle lookup failure as `verification-incomplete`, not `signature-invalid`.

Servers SHOULD limit record size, lookup fan-out, retention, storage abuse, and enumeration. Proofs SHOULD contain minimal personal data because publication makes them visible and potentially durable. A proof may contain callsigns and timestamps even when content is not published; hosted challenge responses reveal activity and potential contact relationships.

No central resolver, federation, transparency log, or DNS naming scheme is REQUIRED for this draft. Resolver configuration/discovery is a deployment concern, not part of the cryptographic trust model.

## 9. Human exchange

On-air tokens and challenges MAY be spoken using standard phonetics or sent in CW. Prefixes and grouping improve operator usability but are not part of the hashed data. The receiving app MUST know whether an artifact denotes a `content-signature` or a `challenge-response`; it cannot infer purpose safely from the short token itself.

Example **content** workflow:

1. AG7SU creates a PixelQSO card and computes its canonical card digest.
2. AG7SU creates and signs an ARAP `content-signature` proof for that digest.
3. The card is sent using PixelQSO; the signature is attached in-band **or** posted to HTTPS with an AR1 reference transmitted over RF.
4. K7ABC recomputes the card digest, obtains the full signed proof, verifies the signature and identity, and displays distinct status fields.

Example **challenge** workflow:

1. K7ABC issues a random nonce and records an outstanding challenge.
2. AG7SU signs a challenge-response proof and publishes or transmits the full proof.
3. AG7SU sends the optional shortened reference over RF.
4. K7ABC retrieves and verifies the full response and marks the challenge consumed.

A content proof is durable and can be replayed with the *same unchanged content*; that is often desirable. A challenge proof is short-lived and may be accepted only for its outstanding challenge. These replay semantics MUST NOT be conflated.

## 10. Verification algorithm

The following is conceptual. Detailed COSE processing follows RFC 9052:

```text
verify(proof_bytes, optional_content_bytes, optional_outstanding_challenge, trust_policy):
    parse COSE_Sign1 strictly and identify algorithm / key
    verify signature with resolved public key
    parse signed CBOR payload; check ARAP version and purpose
    validate key identity and callsign binding under trust_policy
    if purpose == content-signature:
        require content bytes
        check specified canonicalization, SHA-256, size, and context
    elif purpose == challenge-response:
        require an outstanding matching challenge
        check nonce, requester, responder, purpose, expiry, and one-time use
    elif purpose == key-endorsement:
        validate explicitly scoped endorsement and delegation policy
    else:
        reject
    return structured component statuses; never collapse unknown trust into verified
```

### 10.1 Negative tests that implementations MUST include

- Modified card, palette, dimensions, or signed metadata
- Modified signature, signed purpose, recipient, nonce, timestamp, or digest
- Valid signature from a key not trusted for the claimed callsign
- Expired/revoked certificate, expired challenge proof, wrong or reused challenge
- Mismatched content type/domain or canonicalization version
- Partial-match prefix collision and resolver returning multiple candidates
- Resolver unavailable, malicious, or serving content under a false full-hash key
- Unsupported critical COSE headers, algorithms, CBOR duplicates/noncanonical variant confusion
- An endorsement attempting unauthorized transitive trust

## 11. RF/regulatory posture

ARAP uses publicly documented message formats and digital signatures, not encryption. This is designed to preserve intelligible message semantics and avoid obscuring communications. **It is not a legal ruling.** Operators are responsible for applicable amateur-radio regulations, including station identification and control obligations. Publishing a proof on the internet does not itself perform required on-air identification. Operators SHOULD avoid placing secrets or private keys in transmitted or published artifacts.

## 12. Interoperability and versioning

ARAP v0.1 is a **draft profile**. Interoperable v1 requires:

- Freeze integer CBOR field labels and exact data types, required/optional fields, protected COSE headers, and acceptable signature algorithms.
- Publish byte-identical canonical test vectors for Ed25519 and at least one TQSL-relevant algorithm after inspection.
- Publish challenge-response and PixelQSO-style content-signing vectors, negative cases, and short-reference encodings.
- Have independent implementations (ideally Go and Python) verify the same test vectors.
- Document OPV adapter mappings as separate integration specifications; do not redefine core proof semantics to follow an RF transport.

Changes to signed byte representations, hash reference format, or security policy require an explicit version change. Profile identifiers MUST be signed as part of the proof's cryptographic context.

## 13. Open questions before v1 freeze

1. Exact CBOR key numbers, timestamp representation, payload map layout, and COSE `content-type` value.
2. Whether PixelQSO's existing serialized card format can be treated as canonical or requires a new deterministic representation.
3. How TQSL certificate subject/callsign and certificate policies are encoded and verified; accepted algorithms and trust anchor distribution.
4. Whether TQSL/LoTW operators permit or support arbitrary-purpose signing with current credentials; acceptable key-export workflow.
5. How certificate status/revocation works offline, and how to represent `status unknown` honestly.
6. Optional short-reference checksum; lookup namespace and query abuse controls.
7. Callsign suffix/portable identifier normalization and key authorization scope.
8. Resolver discovery convention without centralizing authorization.
9. Whether endorsements are needed for v1 or should remain a separate future extension.
10. Mapping to OPV's concrete messages once those are stabilized and tested.

## 14. References

- RFC 8949, *Concise Binary Object Representation (CBOR)* — https://www.rfc-editor.org/rfc/rfc8949
- RFC 9052, *CBOR Object Signing and Encryption (COSE): Structures and Process* — https://www.rfc-editor.org/rfc/rfc9052
- RFC 9053, *COSE: Initial Algorithms* — https://www.rfc-editor.org/rfc/rfc9053
- RFC 9360, *COSE X.509* — https://www.rfc-editor.org/rfc/rfc9360
- RFC 4648, *The Base16, Base32, and Base64 Data Encodings* — https://www.rfc-editor.org/rfc/rfc4648
- TrustedQSL source project — https://sourceforge.net/projects/trustedqsl/
- Open Research Institute Interlocutor / Opulent Voice — https://github.com/OpenResearchInstitute/interlocutor
- ARRL Logbook of the World — https://lotw.arrl.org/

**Disclaimer:** These are design references, not proof of endorsement or protocol-level interoperation.