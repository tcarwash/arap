# ARAP application machine interface v1

The first cross-language interface is the Python package
[`interop/python/arap_interop`](../interop/python/arap_interop), which invokes
the `arap` executable as a child process. It is a Python API with versioned
result envelopes, not a promise that the raw CLI stdout format is stable. Go
applications should call the public Go packages directly.

## Envelope and errors

Successful methods return a Python mapping with:

```json
{"protocol_version": 1, "ok": true, "result": {}}
```

Methods that produce binary data add a top-level field such as `proof`,
`request`, `response`, or `chain`. These values are Python `bytes`; preserve
them byte for byte when transporting or storing them. They are not text or
base64 strings. The output of the verification command is retained under
`result` as its structured policy result.

Failures raise `ArapError`; applications can inspect `code` and `exit_status`.
The wrapper requests the CLI's machine error protocol internally; applications
do not need to parse stderr.
The error envelope is defined by
[`ARAP-machine-error-v1.schema.json`](../spec/ARAP-machine-error-v1.schema.json).
Its exit status is the subprocess status, not a JSON field. The Python wrapper
combines that status with the error object when raising `ArapError`.
The stable error codes are:

| Code | Status | Meaning |
| --- | ---: | --- |
| `rejected` | 1 | Verification or authorization policy rejected the operation |
| `incomplete` | 3 (verification), 2 (truncated resolver result) | Requested checks or resolver candidates were incomplete |
| `operation_error` | 2 | Invalid input, I/O, or command operation failure |
| `invalid_input` | 2 | A resolver reference is malformed |
| `not_found` | 2 | No proof or key matches the requested identifier |
| `ambiguous` | 2 | A short reference resolves to multiple proofs |
| `unavailable` | 127 (executable), 2 (resolver) | Executable could not start or configured resolver(s) could not complete the request |
| `invalid_response` | 70 (CLI JSON), 2 (resolver) | CLI or resolver data is malformed or fails content-address validation |
| `canceled` | 2 | Resolver operation was canceled or timed out |
| `timeout` | 124 | The child process exceeded the configured timeout |

Error messages are explanatory only; callers must branch on `code`. The
wrapper ignores CLI stderr; messages in the machine error envelope may vary.
Every child is launched with an argv array and `shell=False`.
Key passphrases are supplied on stdin and never on the command line. Signing
methods always select stdin mode, so they never unexpectedly prompt.

## Operations

`ArapClient` exposes these methods:

| Method | Inputs and binary output | Effect |
| --- | --- | --- |
| `generate_keypair` | Nonempty private-key passphrase; returns age-armored encrypted PKCS#8 `private_key` bytes and SPKI PEM `public_key` bytes | Creates a caller-owned Ed25519 identity without exposing passphrases in argv or output |
| `fingerprint` | Public-key or certificate bytes | Returns canonical `key_id_sha256` for trust lookup and lifecycle operations |
| `sign_content` | Exact content bytes, key/callsign, media type/context; returns `proof` bytes | Creates a detached content proof |
| `verify_content` | Proof/content bytes, public key, local trust store or enrollment DB, expected metadata and status-age limit | Applies purpose-scoped local/enrollment trust and content policy |
| `add_trust` / `list_trust` / `disable_trust` | Public-key bytes, callsign, one explicit purpose, or binding fingerprint; caller-owned trust file | Adds a purpose authorization, lists current bindings, or disables the callsign/key binding |
| `sign_pixelqso` | PixelQSO card JSON bytes, key and optional first-frame JSON; returns `proof` bytes | Canonicalizes and signs a PixelQSO card/frame |
| `verify_pixelqso` | Card/proof bytes, public key, trust store and optional first-frame JSON | Checks frame pairing, proof, integrity and local trust |
| `issue_challenge` | Requester/responder, purpose, optional session bytes, caller-owned SQLite path; returns `request` bytes | Persists a pending one-way challenge |
| `cancel_challenge` | Request bytes and issuing SQLite path | Removes the matching request only while pending; consumed records are retained |
| `respond_challenge` | Request bytes, responder key/callsign; returns `response` bytes | Signs a fresh matching challenge |
| `verify_challenge` | Request/response bytes, verifier key/trust or enrollment store and challenge DB | Verifies and consumes an accepted request once |
| `issue_mutual_challenges` | Both callsigns, nonempty session bytes, caller-owned SQLite path; returns both request byte strings | Persists the coordinated inverse pair |
| `verify_mutual_challenges` | Both requests and responses, both keys/trust stores, session bytes and challenge DB | Verifies and atomically consumes the pair |
| `issue_endorsement` | Issuer key/callsign, subject key/callsign, purpose list and depth; returns `proof` bytes | Issues one purpose-scoped delegation |
| `pack_endorsement_chain` | Ordered link bytes; returns `chain` bytes | Packages a root-to-subject chain |
| `append_endorsement` | Existing chain and next link bytes; returns `chain` bytes | Extends an encoded chain |
| `verify_endorsement_chain` | Chain bytes, explicit root authority, expected subject and purpose | Applies offline endorsement policy |
| `issue_enrollment` | Audience, callsign, Ed25519 public key, optional requested purposes and caller-owned enrollment DB; returns `request` bytes | Creates a version 1 challenge-response-only or version 2 purpose-scoped LoTW/TQSL enrollment challenge |
| `respond_enrollment` | Enrollment request bytes, ARAP private key, TQSL helper, and two secret strings; optional serial and isolated TQSL directory; returns `response` bytes | Uses the installed TQSL helper to create the TQSL-supported RSA-SHA1 enrollment response |
| `list_enrollment_certificates` | Enrollment request bytes; optional TQSL helper and data directory | Returns public serial metadata for current TQSL certificates matching the challenge callsign; it does not prompt for a password |
| `verify_enrollment` | Response bytes, audience, enrollment DB, explicit allowed-purpose set, optional roots and status-age limit | Validates certificate evidence and performs the configured live status check; version 1 defaults to challenge-response only |
| `refresh_enrollment` | Previously accepted response bytes, callsign/key fingerprint, enrollment DB and optional roots | Revalidates the matching certificate and obtains fresh status without re-enabling disabled bindings |
| `list_enrollments` / `disable_enrollment` | Caller-owned enrollment DB and, for disable, callsign/key fingerprint | Inspects or disables a locally accepted binding |
| `publish_proof` / `resolve_proof` | Proof bytes or AR1/full-hash reference and configured server list; resolve returns `proof` bytes | Publishes or fetches content-addressed proof data for local verification |
| `publish_key` / `fetch_key` | Public-key bytes or full SHA-256 fingerprint and configured server list; fetch returns `public_key` bytes | Publishes or retrieves a fingerprint-checked public key |

All calls use the `ArapClient` instance timeout. The current CLI bounds content
proof, challenge, and endorsement inputs according to their respective
protocols. Challenge databases, trust files, enrollment stores, key files,
transport, session construction, authorization after authentication, and
status-refresh scheduling remain application responsibilities. The wrapper
does not perform network access or mutate trust policy.

LoTW/TQSL enrollment remains experimental. It uses the RSA-SHA1 signature
supported by the TQSL Callsign Certificate API only for the short-lived,
audience-bound enrollment assertion; ARAP content and challenge signatures use
Ed25519. The legacy `allow_legacy_rsa_sha1` argument remains accepted for
source compatibility but is no longer required. Verification requires the
TQSL helper, configured TQSL/ARRL roots, and an available certificate status
service. Enrollment is ARAP authentication evidence, not an ARRL-approved
login or endorsement.

The CLI equivalent of `list_enrollment_certificates` is
`arap enrollment certificates --request FILE [--tqsl-helper FILE] [--tqsl-directory DIR]`.
It reads the callsign from the validated enrollment challenge and returns the
matching current certificate serials as JSON. Supply the selected serial to
`respond_enrollment` when more than one certificate matches.

Version 1 enrollment records authorize only `challenge-response`. To grant
`content-signature`, the verifier must issue a version 2 challenge with that
purpose and explicitly allow it in `verify_enrollment`. Content verification
must then use the enrollment store with an acceptable maximum status age.
Existing version 1 records do not gain content authority.

## Compatibility

`PROTOCOL_VERSION` is the wrapper compatibility identifier. Adding optional
method arguments and result fields is backward-compatible. Changing method
meaning, required arguments, stable error codes, artifact field names, or
verification policy requires a new protocol version and migration notes.
Version 1 is beta and has not yet received an independent implementation
review. Raw command flags and raw stdout JSON are implementation details behind
the wrapper.

The runnable integration checks and usage example are in
[`interop/python/README.md`](../interop/python/README.md).
