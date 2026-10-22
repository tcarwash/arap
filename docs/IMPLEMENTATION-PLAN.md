# Implementation plan

For the ordered beta scope, release gates, and packaging work, see the
[0.1.0 beta release plan](RELEASE-0.1.0.md).
The beta requires the complete application-facing signing, identity,
endorsement and challenge interfaces, including mutual authentication and
documented Go/CLI integration. Older deferrals below describe implementation
history; the release plan governs the required beta scope.

Updated 2026-10-20 after implementation began. The profile CDDL, Go Ed25519 COSE signer/verifier, CLI content flow, Tk desktop client, Python vectors, Docker Compose keyserver, and PixelQSO editor sidecar integration now exist. LoTW callsign authentication is a core product requirement, not an optional future add-on. The current prototype still uses independent Ed25519 keys and must not be presented as LoTW-authenticated. Keep Ed25519 for ARAP content; the candidate LoTW path is a separate, fresh-challenge enrollment assertion binding the ARRL-issued certificate to an Ed25519 key. TQSL must not replace ARAP's generic hashing, randomness, parsing, or transport libraries. Challenge-response and reference workflows have initial implementations; protocol hardening and production validation remain incomplete.

| Milestone | Current state | Evidence / remaining work |
| --- | --- | --- |
| M0 | Partial | [Profile CDDL](../spec/ARAP-profile-v1.cddl), deterministic Python content/challenge/enrollment-purpose vectors, byte-for-byte Go/Python tests, and independent RFC 8610 schema compilation plus CDDL validation exist (`make cddl`). Direct TQSL signing is excluded from ARAP content proofs (RSA-SHA1 / deprecated RS1). The experimental LoTW enrollment challenge/response, version 2 purpose claims, explicit verifier policy, TQSLLIB native responder helper, TQSL callsign OID parser, timestamped ARRL status client, TQSL root-bundle discovery, status refresh, and atomic SQLite binding store are implemented. ARAP certificate acceptance rules follow TQSL's configured roots and LoTW serial-status source; live certificate validation and independent review remain open. See [the LoTW binding design](LOTW-BINDING-DESIGN.md). |
| M1 | Partial | Ed25519 content signing/verification, local trust records and key generation work in the CLI. Content verification can use an explicitly purpose-scoped, fresh LoTW enrollment binding. A shared public-key parser now accepts one SPKI DER value, one public-key PEM block, or one X.509 certificate block, rejecting PEM with leading prose or extra data across CLI, keyserver and resolver paths. Non-authenticating `inspect-proof` is implemented. Native platform bundles now include the CLI and keyserver; public release licensing and broader parser review remain. The native TQSL enrollment helper and runtime resources are currently bundled only for Linux amd64; helper packaging for the other target platforms remains open. RSA-SHA1 remains incompatible with ARAP content signing; enrollment retains a per-operation acknowledgement. |
| M1a | Partial | Added `adapters/pixelqso` canonical CBOR conversion, PixelQSO-compatible BLAKE2s artwork pairing checks, `sign-pixelqso` / `verify-pixelqso` CLI commands, an ARAP desktop card workflow, and a PixelQSO editor bridge for detached sidecar proofs and references. Unit, UI and CLI checks cover semantic changes, editor-local metadata, valid frame pairs and mismatched-frame rejection, pending verification, per-frame status, stale-proof handling after edits, trust decisions, edited-card rejection, and responsive asynchronous publish/resolve. The JSON canonicalizer now has a seeded Go fuzz target run in CI. An offscreen dialog end-to-end run with the real CLI and disposable keyserver passes frame-2 sign/verify, authenticated publish, reference resolve, byte-identical proof recovery and re-verification. Real-card fixtures, native manual dialog coverage, and deployed keyserver validation remain. |
| M2 | Partial | Canonical request/response profile, Go challenge library, CLI commands and SQLite replay store are implemented. The CLI records a challenge before exclusively publishing its request file, and removes an unconsumed record if publication fails. Tests cover restart/replay, six-process single consumption, expiry, unknown/disabled trust, wrong requester/responder, storage failure, and a Python byte-identical vector. Response signature verification now precedes freshness policy so valid-expired and corrupted responses have distinct outcomes; only accepted, fresh, trusted responses consume state. Challenge verification can trust an enrolled LoTW key for `challenge-response`; content verification can use a version 2 enrollment binding only when `content-signature` was explicitly requested and allowed. Both paths require an unexpired certificate and fresh status evidence. CI fuzzes both request decoding and full response verification; Go and independent Python checks reject malformed COSE structures and invalid signed payload schemas. The Python vector also rejects party, nonce, expiry, purpose and session-binding mismatches. The Go API creates and atomically verifies inverse challenge pairs; the versioned Python wrapper now exercises one-way and mutual CLI flows, session binding, and replay/atomic pair consumption. A separately maintained consumer review remains. Desktop one-way challenge actions are wired. |
| M3 | Partial | Immutable proof/key storage, prefix lookup, Compose deployment, bounded Go resolver/publisher CLI and desktop publish/fetch exist. The desktop now also resolves and verifies an AR1 reference directly against local content and trust. SQLite-backed proof/key/byte quotas, serialized reservation, expiration cleanup and file publication, authenticated upload rate limits, optional retention, and multi-resolver reads are implemented and covered by focused tests. Stored-object reads check the index first and enforce proof/key byte limits before returning bytes, including for files corrupted after upload. `/healthz` checks SQLite connectivity plus writable proof/key directories so Compose marks unusable storage unhealthy. Both reusable server constructors and the executable require a Bearer token with at least 32 valid non-padding characters. Production service validation remains. |
| Desktop | Partial | Tk supports keys/trust add/list/disable, content signing/verification, challenge issue/respond/verify, keyserver publish/fetch, direct reference resolution with local verification, and LoTW enrollment issue/sign/verification plus record inspection/disable. Enrollment signing and verification expose RSA/SHA-1 only through default-off controls with confirmation. The TQSL helper is currently bundled only for Linux amd64; native CI now builds and packages the helper for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64, then runs extracted-helper enrollment and desktop smoke checks on each native target. Hosted runs remain pending. Live certificate flow, licensing, and broader interaction/accessibility validation also remain. Key/proof uploads and all reference verification use the CLI, with the upload token scoped to the child process environment. Long CLI/HTTP operations run off the Tk event thread, with action locking and responsive event-loop smoke coverage. Tab forms scroll vertically and were checked at the 840×620 minimum window size. |
| M4 | Partial | Initial key-endorsement issue/verify API and schema are implemented in `endorsement/`; CLI and Python wrapper issue/pack/append/verify flows now pass end-to-end checks. Independent implementation review remains. No OPV adapter. |

## First deliverable

A reusable Go library and thin `arap` CLI currently sign arbitrary saved bytes with the explicit Ed25519 COSE profile and verify detached proofs offline under explicit local trust rules. This is the implemented independent-key prototype, not the final callsign-authenticated design. For ham identity, prefer TQSL-managed credentials and certificate policy, but do not use its current SHA-1 data-block signer. Resolve the supported modern signing interface before freezing the production signature profile. Publish deterministic fixtures independently generated and checked in Go and Python. Start with exact input bytes so this work does not depend on PixelQSO canonicalization.

Use one Go module, `github.com/tcarwash/arap`, rather than separately released modules for every conceptual package. Keep file access, clocks, randomness, storage, HTTP and terminal behavior outside pure verification code. The current `origin` remote is `github.com/tcarwash/arap`, matching the module path.

Proposed layout, introduced only when behavior needs it:

```text
proof/                 payload types, strict COSE/CBOR codec, results
identity/              Ed25519 provider, local key and callsign trust
content/               streamed digest/size, content signing and verification
reference/             full digest, AR1 tokens, bounded resolver client
challenge/             request/response handling, verifier state interface
adapters/pixelqso/     card canonicalization after actual source inspection
cmd/arap/              thin local CLI
cmd/arap-keyserver/    optional untrusted object server
desktop/               local Tk interface calling the CLI
internal/cli/          argument, file and result handling
internal/store/        durable challenge and object-store implementations
interop/python/       independent vector generator/verifier and lockfile
test-vectors/          public test-only keys, bytes and expected results
deploy/                optional server Dockerfile and compose.yaml
```

Library verification must not implicitly access a network, read a user's key directory, alter trust, or consume challenges.

## M0 — Specify the proof format and validate signer compatibility (partial)

### M0a: Dependency and schema spike

1. Source inspection of TQSL finds RSA-SHA1 in its data-block signer. This rules it out as an ARAP content/COSE signer. The fresh-challenge enrollment flow and TQSLLIB responder are implemented in `lotwenroll/` and `tqsl-helper/`; the project accepts that legacy signature only for enrollment. Root/status policy is documented against TQSL's configured roots and LoTW serial-status endpoint; live certificate validation remains a gate.
2. Review the pinned `fxamacker/cbor/v2` release, license and required Go version. Go's standard library handles Ed25519 signing and verification; explicit COSE Sign1 construction avoids library algorithm-name ambiguity. Extend strict-decoding rejection tests.
3. Select and pin Python CBOR and cryptographic dependencies separately. Inspect deterministic ordering and decoder limitations; supply explicit schema/byte checks where needed. A mode named “canonical” is insufficient evidence.
4. Keep `spec/ARAP-profile-v1.cddl`, `spec/ARAP-challenge-v1.cddl`, and this conceptual draft aligned. The prototype wire schemas are implemented; any later wire changes require matching code, vectors, and explicit versioning.
   `make cddl` compiles the schemas with the pinned independent parser and validates the content, request, response-envelope and PixelQSO fixtures. The challenge-response COSE envelope has its own root schema so the response fixture is checked beyond its payload.
5. Select an explicit code license and dependency notice policy before distributing implementation. Retain the specification's proposed licensing status until owner confirmation.

### Implemented prototype wire decisions

| Topic | Proposed rule to finalize in M0 |
| --- | --- |
| Envelope | One tag-18 COSE_Sign1, embedded CBOR payload byte string, empty unprotected map. Reject untagged proofs in this profile. |
| Signature input | Standard COSE `Signature1` construction, empty external AAD; verify original protected-header and payload bytes. |
| Protected headers | Label `1` algorithm = allowlisted Ed25519 (`-19`); label `3` content-type = project-specific `application/vnd.arap.proof+cbor`; label `4` key ID = 32-byte SHA-256 of DER SubjectPublicKeyInfo. No private header allocation. |
| Payload labels | `1` profile (`"ARAP"`), `2` wire version (`1`), `3` purpose (text), `4` signer (normalized ASCII text), `5` created (integer Unix seconds), `6` optional not_after (integer), `7` subject (purpose-specific map). |
| Content subject | `1` media_type, `2` canonicalization, `3` digest algorithm (`"sha-256"`), `4` digest (32 bytes), `5` size (nonnegative integer), `6` optional content_id, `7` context. Require media_type and context. Omit conceptual `kind`: signed purpose already chooses the schema. |
| Input bytes | `canonicalization = "identity-v1"` hashes exact supplied bytes without text/newline/JSON/image conversion. Applications can add independently specified canonicalizers. |
| Encoding | RFC 8949 section 4.2.1 core deterministic encoding. Reject indefinite lengths, floats, extra tags, duplicate keys, invalid UTF-8 and trailing items. Optional fields are absent, never null. |
| Extensions | Initially reject unknown payload labels and extra headers, including critical headers that cannot be processed. Extensions require a documented version/profile rule. This narrows the conceptual draft's permissive field language. |
| Callsigns | Current profile syntax: 3–20 ASCII characters matching `[A-Z0-9]+(?:/[A-Z0-9]+)*`, with at least one letter and digit. At input, uppercase ASCII and trim outer ASCII spaces; reject controls/internal whitespace. Wire strings must already be normalized. This is a supported syntax subset, not licensing validation. |
| Trust | Bind exact callsign + full SPKI fingerprint + allowed purpose. For TQSL certificates, validate the chain/issuer and certificate dates; establish what current ARRL status evidence is available, and report status as unknown when policy requires evidence that is unavailable. An ARRL-issued certificate alone is not an eternal validity assertion. For independent Ed25519 keys, require an explicit local pin. No automatic suffix equivalence, TOFU or delegation. |
| Time | Integer seconds in `0..2^63-1`, no time tags. `created` is self-asserted. Content verification allows at most 300 seconds of future skew; this is a defensive acceptance bound, not a trusted timestamp. If supplied, require `not_after > created`, and reject as expired at `now >= not_after`. |
| References | SHA-256 of exact completed proof bytes. Full lowercase 64-character hex storage key; short token = uppercase RFC 4648 Base32 of digest bytes `[0:10]`, unpadded. `AR1` is presentation only. |
| Supported purposes | Content-signature and the separate challenge-response profile are implemented. Key endorsements have a separate experimental schema and verifier; they MUST NOT fall back to content verification. |

The challenge schema is frozen for the prototype in M2. Certificate and endorsement schemas remain separate profiles. Document supported-purpose boundaries so reserving wire version 1 does not imply every draft purpose exists.

TQSL is not a signer provider in the current profile. Software Ed25519 keys use public SPKI PEM, private PKCS#8 PEM and SHA-256 SPKI fingerprints. Never include private keys in proofs or non-test fixtures. Any future TQSL certificate binding must not imply that TQSL's current SHA-1 signing API authenticated the ARAP key.

### M0b: Golden vectors and conformance

Each valid fixture contains its test public key, SPKI bytes/fingerprint, input content, digest/size, CBOR diagnostic notation, payload, protected headers, exact signature input, signature, final tagged proof, full hash, AR1 token and structured expectations under named policies and an injected clock. Independent Go/Python generators produce identical software Ed25519 proof bytes; Python independently verifies the content profile and records eleven negative decisions, including an unauthenticated expiry edit. No TQSL signature vector is planned for the current API because its signer uses deprecated SHA-1.

Include correctly signed but invalid schemas/types/purposes as well as corrupted signatures. Otherwise parser/policy bugs can hide behind signature failures. For modified-content cases, retain the original proof and alter only the presented content.

Negative cases: duplicate/nonnumeric labels, unknown fields, booleans in integer positions, nonminimal integers, wrong ordering, null/absent confusion, nonempty AAD, tagging variants, unsupported algorithms, missing/extra headers, bad key ID, wrong key, trailing objects and bounded nested/oversized input. Discard partially decoded values after any parse error.

**Gate:** Both implementations independently generate and verify valid software Ed25519 fixtures and agree on negative decisions. Record versions/schema in a manifest. No TQSL-backed interoperability claim is made.

## M1 — Offline content library and CLI (partial: Ed25519 path implemented)

### Library operations

- Use the current Ed25519 signer over COSE's exact signature-input bytes and a public-key resolver. Do not add a TQSL signer adapter for the SHA-1 API to ARAP content proofs; the separate experimental enrollment adapter signs only the fresh challenge bytes.
- Retain Ed25519 generation with system cryptographic randomness. Fingerprint DER SPKI consistently across languages.
- Hash input streams while counting bytes, without buffering entire files. Sign typed subjects with required media type, canonicalization and context.
- Provide operations equivalent to `SignContent(signer, reader, metadata)` and `VerifyContent(proof, reader, candidateKey, expected, policy, now)`. Separate I/O errors from typed verification failures in final Go signatures.
- Require caller expectations for purpose, media type, canonicalization and context; optionally constrain signer/fingerprint. Claims inside a proof cannot authorize themselves.
- Implement explicit local trust records with callsign, full fingerprint, allowed purposes, disablement and optional validity bounds. Do not label manual trust as independently verified licensing identity.
- Enforced proof/parser limits: complete encoded proof at most 65,536 bytes, nesting 8, 32 map entries, 16 array elements, 128 UTF-8 bytes for each media type/context/canonicalization, 256 for content_id. Signers and verifiers apply the same complete-envelope limit; local streamed-file limits remain separate. Later certificate profiles may need larger proofs.

### Result contract

Components: `cryptographic_signature`, `content_integrity`, `callsign_identity`, `challenge_freshness`, `overall_policy`, plus stable reason codes. Finalize exact enums in M0: signature/integrity use `valid`, `invalid`, `unknown`, `not_checked`, `not_applicable`; identity uses `trusted`, `untrusted`, `rejected`, `not_checked`; overall uses `accepted`, `rejected`, `incomplete`. Include named policy provenance. Trust bounds are evaluated against verifier policy/time, not self-asserted signing time.

| Situation | Expected result |
| --- | --- |
| Valid signature, matching bytes, authorized exact callsign/key/purpose | Accepted under that named local policy. |
| Valid signature/content, no callsign binding | Identity untrusted; strict overall result incomplete. |
| Disabled key or wrong expected signer/context | Rejected with a policy/binding reason even if cryptography passes. |
| Valid signature, edited content | Signature valid, content invalid, overall rejected. |
| Valid signature, expired `not_after` | Signature valid, content may remain unchecked, identity/policy rejected as expired. An unauthenticated expiry claim must not bypass signature validation. |
| Missing key/content | Incomplete; unavailable checks identified. |
| Bad signature/malformed proof | Rejected; dependent checks not_checked. |
| No proof | Application reports unsigned instead of inventing a signature failure. |

CLI exits: `0` accepted; `1` verification rejected; `2` usage/I/O/internal failure; `3` incomplete. Non-verification commands use `0` for success. Parsing in `inspect-proof` never authenticates claims.

Commands `keygen`, `sign-content`, `verify-content`, `inspect-proof`, `fingerprint`, `trust`, `challenge`, `publish`, `resolve` and `verify-ref` are implemented. Verification and claim outputs are JSON. Example runnable shapes:

```sh
arap keygen --private-key station-private.age --public-key station.pub.pem
arap sign-content --key station-private.age --callsign AG7SU --input card.bin \
  --media-type application/octet-stream --context arap/example/v1 --out card.arap
arap verify-content --proof card.arap --input card.bin --public-key station.pub.pem \
  --trust-store trust.json --expect-media-type application/octet-stream \
  --expect-context arap/example/v1
```

Private key creation uses atomic exclusive files, owner-only mode where supported, refuses overwrite, and stores new encrypted keys in the standard armored age format using its scrypt recipient. New keys use work factor 15; the reader caps work at factor 18 for compatibility with age CLI defaults. The CLI prompts without echo or accepts secrets on standard input; the desktop uses a masked prompt and pipes the secret only through the child process standard input. Legacy unencrypted PKCS#8 remains readable. The discarded ARAP-only encryption envelope is not supported because no project key files used it. Review the age dependency; an OS-keychain option remains open. Reading a key must not silently copy it elsewhere.

**Gate:** A saved file verifies offline with supplied key and explicit trust; one-byte edits fail content integrity; unknown and disabled keys remain distinct. Expand unit/vector tests, cross-language checks, CLI workflows and parser fuzz coverage in CI. Add runnable setup docs once these commands exist.

## M1a — PixelQSO adapter using the Ed25519 profile

The ARAP adapter reads the saved JSON subset and emits the versioned deterministic CBOR map specified in [PixelQSO-card-v1.cddl](../spec/PixelQSO-card-v1.cddl). It binds callsign, grid, card ID, dimensions, palette order, row-major indices, and the optional frame-2 reference. It excludes only enumerated editor/local fields and rejects unknown fields. JSON layout changes do not change the canonical card bytes.

The adapter has been checked against a local PixelQSO starter card. The PixelQSO source checkout now includes an editor workflow for detached proof signing/attachment, local trust verification, reference publication/resolution, and pending/verified status without changing card JSON or modem transmission. Publish/resolve run in a worker, and a UI responsiveness test passes. The workflow was exercised through the real ARAP CLI against an unchanged and one-pixel-edited card; publish/resolve against a disposable local keyserver returned byte-identical proof data and passed trusted verification. Next add properly licensed real-card fixtures and exercise the complete GUI and hosted keyserver path. Keep receive times, deck notes and local ratings outside signed content.

Add real fixtures for supported sizes/palettes/frame combinations. Compare original and round-tripped bytes or canonical digests through the actual codec. Then freeze adapter context/media type and complete validation of the PixelQSO attachment/pending-proof UI. Signing and transmission stay explicit actions.

**Gate:** Saved cards survive serialize/load/export with identical signed content; palette/pixel/dimension/frame-link/signed-metadata edits fail. Render/UI and modem/RF verification remain separate gates. The ARAP canonicalizer, CLI, and PixelQSO proof-sidecar UI now exist; repository-owned real fixtures, full dialog and deployed resolver validation remain.

## M2 — Interactive challenges (partial implementation)

Implemented in `challenge/`, `cmd/arap` and the desktop Challenge tab, with schema in [ARAP-challenge-v1.cddl](../spec/ARAP-challenge-v1.cddl). The current implementation has a 120-second default, 600-second maximum, 128-bit nonce, 30-second future skew, exact request digest binding, and a SQLite pending-to-consumed transition.

The wire schema and request/response binding are implemented. Python independently verifies the challenge profile and rejects sixteen negative cases covering edited request binding, parties, signature, expiry, nonce, requested purpose, session binding, noncanonical or untagged COSE, unprotected headers, unsupported algorithms, and malformed signed payload schemas. Go tests also cover wrong-party checks, disabled-key handling, storage-failure handling and multi-process replay. The exact canonical request bytes are hashed; response expiry equals the recorded request expiry.

Current defaults: 120-second lifetime, 600-second maximum and 30-second future skew. Verifier-held expiry/pending state is authoritative; skew never reopens expired/consumed requests. Core verification accepts an injected clock; CLI supplies system time.

The current SQLite store has a durable pending interface and a single conditional UPDATE transition. Signature, trust, parties/purpose, exact request and time are checked before consumption; storage failures fail closed and untrusted responses do not consume the request.

Retain consumed state until expiry. Unknown requests fail after cleanup/restart too. A crash after commit can leave the first caller without success confirmation; replay must still fail. Persist issuance atomically before exposing requests. Low-level inspection/verification must not consume state or claim accepted authentication.

Commands: `challenge`, `respond`, `verify-response`.

**Gate:** A good exchange succeeds once. Test simultaneous processes, restarts, stale/unknown/reused nonce, wrong party/session, edited request, disabled key and storage failure. Independently check challenge vectors in Python.

## M3 — Short references and optional hosting (partial: store and desktop publish/fetch implemented)

Pure hash/token functions, Go client and CLI (`publish`, `resolve`, `verify-ref`, `publish-key`, `fetch-key`) now exist. The resolver accepts full SHA-256 hashes or `AR1` plus sixteen Base32 symbols, normalizes case and space/hyphen grouping, bounds formatted references at 256 bytes, and rejects extra text. Reference normalization and lookup JSON parsing now have seeded fuzz targets in CI.

The Go and desktop clients use only configured resolver URLs, reject non-HTTPS remote URLs, disable redirects, bound response sizes and time, and check hashes/prefixes. Go APIs accept contexts for cancellation. Tests cover oversized lookup/proof responses and request cancellation. CLI `verify-ref` runs the same local content verification after retrieval. Certificate URL fetching is not implemented.

Return all acceptable candidates or explicit ambiguity, never automatic first-match trust. Candidate-limit exhaustion is incomplete/truncated lookup. Distinguish retrieval failure from invalid proof and continue to other configured resolvers where appropriate. A token cannot establish completeness of a malicious server's candidate set; authenticity remains independent of availability.

An 80-bit token gives about 80-bit chosen-prefix preimage resistance and about 40-bit birthday collision search. It is never authorization. Use injected candidate sets or a test-only shorter prefix for collision fixtures, leaving production length unchanged.

Optional server: immutable full-hash PUT/GET and prefix lookup. Hash-check uploaded bodies; enforce size/quota/rate/retention and bounded index/fan-out. Return an explicit truncation indicator. Stored proof bytes remain untrusted. Default writes require an operator-configured upload credential outside RF proofs; public reads are deployment policy. Preserve downloaded full proofs with received content so later host deletion does not break local verification.

When hosting is requested, ship a non-root image, persistent volume and Docker Compose service behind the existing HAProxy HTTPS endpoint, with healthcheck/backup instructions. The optional Compose overlay publishes on loopback for a same-host proxy or a chosen private interface for a remote proxy; restrict remote access at the Docker host firewall. Library work needs no live infrastructure changes.

Commands: `publish`, `publish-key`, `fetch-key`, `resolve`, and `verify-ref`, retaining full-proof expectation/trust inputs.

**Gate:** Full and reference paths reach identical decisions. Cover multiple candidates, valid-but-unexpected signer/content, false full-hash paths, malicious/oversized/truncated response, timeout, redirects, offline behavior and server persistence.

## M4 — Conditional identities and optional transports

TQSL is the preferred ham-credential integration, but not a replacement for ARAP's general crypto and transport libraries. Keep Ed25519 for ARAP content and challenge-response signatures. The TQSL data-block signer is accepted only for the separate, short-lived enrollment assertion that binds an Ed25519 key to a callsign; it is not a COSE algorithm or QSO submission. The TQSL data-block signer hardcodes SHA-1, `tqsl_beginSigning` keeps an unencrypted private-key copy in memory, `tqsl_getKeyEncoded` can export private material, and the local certificate-status API exposes no freshness timestamp. Live certificate/status validation remains open. Never export a station private key or present cached status as current. Do not claim ARRL endorsement.

Do not create an RS1-based content-signature profile. The enrollment-only legacy signature remains experimental and needs interoperability review. Unknown revocation cannot become trusted under a policy requiring current status. Self-asserted creation time never proves historical certificate validity.

Endorsements need independently specified delegation/scope policy and negative vectors. OPV needs a mapping document against a concrete tested implementation. Neither changes native proof meaning or gates PixelQSO.

## Next implementation change

1. Exercise the PixelQSO sidecar dialog through native file dialogs and verify publish/resolve against a deployed HTTPS keyserver; the automated offscreen end-to-end path now covers frame-2 sign/verify and local keyserver round-trip.
2. Add properly licensed PixelQSO card fixtures and finish M0/M1 release hardening: broaden parser/conformance review and select the code license. User-facing key-storage documentation and key-generation disclosure are now present.
3. Add further M3 resolver cases as review identifies concrete gaps; the current suite covers candidate/token mismatch, false-hash retrieval, corrupted stored objects, oversized responses, cancellation, and durable Compose restart behavior. Document that resolver omission cannot be detected.
4. Observe hosted artifact workflows and native macOS/Windows desktop runtime behavior; CI defines those native bundle startup jobs.
5. Validate the TQSL enrollment client adapter and finish ARRL certificate/status policy using generated test certificates. The TQSLLIB helper and fail-closed responder are implemented, but the helper has not yet signed with a synthetic TQSL certificate. Do not use the station certificate for synthetic QSO signing; TQSL's `-z` test-sign option applies only to ADIF workflow checks.

The ARAP-side prototype schemas now match the conceptual overview at the field and profile-boundary level; deterministic Go/Python vectors, cross-target bundle checks, and a local container endpoint smoke check pass. CI now includes native macOS/Windows bundle startup checks, but hosted CI and platform UI behavior remain unobserved. Retain experimental status until protocol gates pass. The actual PixelQSO card schema is supported by the ARAP adapter, including frame-pair validation in the CLI. The PixelQSO editor now has detached proof/reference sidecars and pending/verified status; real-card fixtures, full manual GUI flow and deployed resolver validation remain. Milestones remain pending until their evidence exists.
