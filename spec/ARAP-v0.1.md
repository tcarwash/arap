# Amateur Radio Authentication Profile (ARAP)

**Status:** Draft v0.1 — design proposal, not an adopted standard  
**Date:** 2026-10-22

**Intended audience:** amateur-radio application developers, station operators, implementers of independent transports  
**License of this specification:** CC0-1.0 (proposed; see project README)

> **Design goal:** Reuse existing cryptographic formats for verifiable signed amateur-radio material, including PixelQSO cards, without requiring a particular modem, waveform, online service, or live challenge-response session.

> **Implementation note:** This overview is conceptual and is not the wire-format authority. The implemented content-signature and challenge-response v1 schemas are [ARAP-profile-v1.cddl](ARAP-profile-v1.cddl) and [ARAP-challenge-v1.cddl](ARAP-challenge-v1.cddl). They freeze encoding details for this prototype; that does not make ARAP an adopted or independently reviewed standard.

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
- **Fully specified algorithms** from RFC 9864, which updates RFC 9053. The native Ed25519 profile uses COSE algorithm `Ed25519` (`-19`); the older polymorphic `EdDSA` (`-8`) identifier is deprecated and is not the proposed native-profile identifier.
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
| `version` | Integer `1` (implemented prototype profile) |
| `purpose` | `content-signature`; challenge responses use the separate challenge-response schema; key endorsements have their own experimental profile |
| `signer` | Normalized callsign claimed by the signing key |
| `created` | UTC Unix timestamp in seconds |
| `not_after` | Optional content expiry; challenge response expiry is a required request-bound claim in its separate schema |
| `subject` | Purpose-specific structure, detailed below |

The readable names above describe semantics. The content v1 CBOR integer labels, types, required/optional fields, and protected COSE headers are defined by `ARAP-profile-v1.cddl`; the challenge request and response have their own labels in `ARAP-challenge-v1.cddl`. The profile uses RFC 8949 core deterministic encoding, tagged COSE_Sign1, embedded payload, empty external AAD, Ed25519 (`-19`), content type `application/vnd.arap.proof+cbor`, and a full SHA-256 fingerprint of DER SubjectPublicKeyInfo in `kid`. Use the CDDL and checked-in vectors for implementation details; do not infer a frozen wire representation from the conceptual table alone.

CBOR and COSE format constraints:

- Use a single COSE_Sign1 signature. The protected header MUST identify the algorithm and MUST contain a profile-specific content-type or equivalent unambiguous application marker.
- The signer key identity MUST be unambiguously bound to the verified key. The v1 `kid` is the full SHA-256 digest of DER SubjectPublicKeyInfo; it identifies a key but does not determine trust by itself.
- The signature covers the entire CBOR payload. The proof's signed payload, protected headers, and attached identity evidence must be interpreted according to COSE processing rules.
- The implemented v1 verifier rejects headers outside its exact protected-header set, unsupported algorithms, unknown payload labels, mismatched profile/version/purpose, malformed values, and non-deterministic encodings. Extensions require an explicitly versioned profile rule.
- There is **no encryption** in ARAP.

### 3.2 Callsign strings

For comparisons, a callsign is converted to ASCII uppercase and surrounding ASCII spaces are removed. The implemented v1 grammar permits 3–20 ASCII bytes containing at least one letter and one digit, with only single internal slashes; leading, trailing or repeated slashes are invalid. Variants such as `AG7SU`, `AG7SU/P`, and `AG7SU/7` remain distinct identities unless an explicit binding rule is added.

A signature only establishes control of the signing key. Authorization to claim a callsign is a separate identity-validation result.

## 4. Signed content: the primary reusable operation

A `content-signature` subject binds the signature to **bytes representing the content** rather than to a current contact or timestamp.

Conceptual subject:

```yaml
kind: content-signature
media_type: application/vnd.pixelqso.card+cbor  # example; not yet registered
canonicalization: identity-v1                     # hash the supplied canonical CBOR bytes exactly
content_digest_algorithm: sha-256
content_digest: <32 raw bytes>
content_size: <integer length in bytes>
content_id: <optional app-local object identifier>
context: <required domain/app identifier, e.g. "pixelqso/card/v1">
```

Rules:

1. Every content type MUST define the exact bytes hashed. Prefer hashing the stored/transmitted original bytes directly; if semantic canonicalization is required, the application MUST publish a deterministic algorithm and version.
2. Compute `content_digest = SHA256(content_bytes)`; include the original byte length. Verifiers MUST recompute both against the presented content.
3. The signed subject MUST bind a type and domain (`media_type` and `context`) to stop one file's digest from being confused for a different kind of signed statement.
4. Signing does not require that the content itself be uploaded, that its author be online, or that the recipient be named.
5. Detached content and detached signatures are allowed. A receiver MUST NOT show a card as **verified** until it has the correct card bytes and a valid proof bound to them.
6. Publication may happen later. A receiving application MAY store a card as **signature pending** while awaiting its signature or certificate.
7. Re-signing an unchanged card makes a new proof; editing a single pixel produces a different digest and invalidates the old signature for the altered content.

### 4.1 PixelQSO profile

The ARAP adapter defines the portable signed representation as `PixelQSO-card-v1` deterministic CBOR over supported saved-card fields (palette, dimensions, pixel indices, card metadata and animation link), rather than screenshots or PNG encodings. The ARAP proof uses `identity-v1` because it hashes those already-canonical CBOR bytes exactly; `pixelqso-card-v1` names the content format, not the COSE payload's canonicalization method. See [PixelQSO-card-v1.cddl](PixelQSO-card-v1.cddl) and [the integration guide](../docs/PIXELQSO-INTEGRATION.md). The ARAP CLI and desktop can sign and verify it; PixelQSO's editor now attaches detached proof/reference sidecars, displays pending/verified status and publishes/resolves references without changing the radio card format.

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

The initial Go implementation and payload schema are in `endorsement/` and
`ARAP-key-endorsement-v1.cddl`. Endorsement proofs use the generic Ed25519
COSE envelope, an application-supplied root, strict purpose attenuation and a
bounded delegation depth. Go, CLI and Python interfaces support issuance,
chain assembly and explicit-root verification. The profile remains
experimental pending broader independent review.

## 7. Identity and trust

The prototype has two separate callsign-key establishment paths:

**Software-key identity.** Ed25519 using the fully specified COSE algorithm `Ed25519` (`-19`, RFC 9864), with key fingerprints and a configurable local trust store. An unknown key can produce a mathematically valid signature but is not automatically a callsign-verified identity. Verification requires the actual public key, not just its fingerprint. Local callsign/key/purpose authorization is implemented.

**TQSL Callsign Certificate evidence.** The experimental enrollment protocol uses a fresh audience-bound challenge and binds its Callsign Certificate to an ARAP Ed25519 key. Version 1 authorizes `challenge-response` only; version 2 carries verifier-selected purposes and requires each verifier to apply its own explicit purpose policy. TQSL's `tqsl_signDataBlock` API uses RSA/SHA-1, corresponding to deprecated COSE RS1; ARAP accepts that signature only for the short-lived enrollment assertion. ARAP content and challenge-response signatures remain Ed25519. The verifier builds trust from roots in the configured TQSL data directory, the platform TQSL default, or an explicit root override, then checks timestamped serial-status evidence from the LoTW endpoint used by TQSL. It fails closed for unknown, revoked, stale, or unavailable status. Live validation against a real station certificate and status response remains outstanding.

This enrollment result is authentication evidence under ARAP policy. It MUST NOT be represented as an ARRL-approved login, endorsement, or LoTW transaction. TQSL support for RSA/SHA-1 is the reason it is accepted in this narrow enrollment assertion; it does not make RSA/SHA-1 acceptable for ARAP content or challenge signatures.

A verifier MUST surface separate results for `cryptographic_signature`, `content_integrity`, `callsign_identity`, `challenge_freshness` (if applicable), and `overall_policy`.

The signed `created` value is a signer assertion, not a trusted timestamp. A verifier MUST NOT use it alone to infer that a certificate or callsign authorization was valid at signing time. Signature mathematics and current identity/expiry policy are separate decisions. Exact time and result aggregation rules remain implementation-profile freeze requirements.

## 8. Direct and reference transports

Every proof is a complete COSE_Sign1 byte string. It can be sent in full without a network dependency, or published for retrieval using a short on-air reference.

### 8.1 Full proof

Send the exact signed COSE bytes, and include the necessary certificate/key material or identify a separately retrievable trusted key. This is the authoritative offline verification form.

### 8.2 Content addressing

Let `P` be the exact serialized COSE_Sign1 bytes of a completed proof. Compute `D = SHA256(P)`.

The implemented reference token is the first **80 bits** of `D`, encoded using RFC 4648 uppercase, unpadded Base32 (16 symbols), with a human prefix `AR1` outside the token. Grouping with spaces or hyphens is presentation-only; lookup uses the exact sixteen Base32 symbols.

The token is a **locator**, not an independent verifier. An attacker may publish a colliding prefix, so the resolver MUST return a candidate set or signal ambiguity, and the client MUST hash each returned candidate, match the advertised prefix, then check the complete signature and subject against local expectations. Prefix matching alone MUST NEVER result in a verified state.

A transcription checksum is optional in this draft and MUST be explicitly versioned if added. A checksum checks typing errors, not authenticity.

### 8.3 Publication and resolution

An operator MAY upload P to any HTTPS object store or resolver. Use the full hex SHA-256 digest as the immutable storage key. The optional ARAP keyserver implements these paths:

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

The following is conceptual. Detailed COSE processing follows RFC 9052 and
the purpose-specific schemas. Content, challenge-response, and experimental
key-endorsement implementations exist; enrollment uses separate versioned
challenge and response schemas.

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

ARAP v0.1 is a **draft profile**, and the v1 schemas remain experimental. Interoperable standardization still requires:

- Independently review and maintain the integer CBOR field labels, exact data types, required/optional fields, protected COSE headers, and allowlisted signature algorithms already specified for the prototype.
- Publish byte-identical deterministic native Ed25519 test vectors. Any TQSL-backed profile requires its own inspected algorithm, trust policy and vectors; it does not gate native content-signing interoperability.
- Publish vectors and negative cases for each implemented purpose and application profile, plus short-reference encodings if supported. A native content-only implementation MUST declare that scope and reject unsupported purposes; challenge-response and real PixelQSO compatibility require their own vectors before being claimed.
- Have independent implementations (ideally Go and Python) verify the same test vectors.
- Document OPV adapter mappings as separate integration specifications; do not redefine core proof semantics to follow an RF transport.

Changes to signed byte representations, hash reference format, or security policy require an explicit version change. Profile identifiers MUST be signed as part of the proof's cryptographic context.

## 13. Open questions before standardization

1. Independent review and broader conformance vectors for the implemented COSE/CBOR profiles.
2. Live validation of the TQSL certificate chain and current status evidence using a real station certificate; keep this separate from the ARAP authentication-evidence semantics, which do not imply ARRL approval.
3. Whether an optional transcription checksum is useful and, if so, its versioned format.
4. Resolver discovery and federation conventions without centralizing authorization.
5. Independent review of the experimental endorsement profile and its delegation limits.
6. Mapping to OPV's concrete messages once those are stabilized and tested.

## 14. References

- RFC 8949, *Concise Binary Object Representation (CBOR)* — https://www.rfc-editor.org/rfc/rfc8949
- RFC 9052, *CBOR Object Signing and Encryption (COSE): Structures and Process* — https://www.rfc-editor.org/rfc/rfc9052
- RFC 9053, *COSE: Initial Algorithms* — https://www.rfc-editor.org/rfc/rfc9053
- RFC 9864, *Fully-Specified Algorithms for JOSE and COSE* — https://www.rfc-editor.org/rfc/rfc9864
- RFC 9360, *COSE X.509* — https://www.rfc-editor.org/rfc/rfc9360
- RFC 4648, *The Base16, Base32, and Base64 Data Encodings* — https://www.rfc-editor.org/rfc/rfc4648
- TrustedQSL source project — https://sourceforge.net/projects/trustedqsl/
- Open Research Institute Interlocutor / Opulent Voice — https://github.com/OpenResearchInstitute/interlocutor
- ARRL Logbook of the World — https://lotw.arrl.org/

**Disclaimer:** These are design references, not proof of endorsement or protocol-level interoperation.
