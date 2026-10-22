# TQSL signer and identity research

TQSL remains a useful callsign-certificate manager, but its current Signing API is not suitable for ARAP content or challenge signatures. In inspected upstream source commit `1916fc14a8cfc7f287742ae5a34aa986353d9df7` (2026-10-20), `tqsl_signDataBlock` calls `EVP_SignInit(ctx, EVP_sha1())` and `tqsl_verifyDataBlock` calls `EVP_VerifyInit(ctx, EVP_sha1())`. TQSL's key-generation path creates RSA keys. This is RSA PKCS#1 v1.5 with SHA-1, corresponding to COSE RS1 (`-65535`), which the IANA COSE registry marks deprecated. ARAP accepts this only for the short-lived enrollment assertion; it is not enabled as an ARAP proof algorithm.

## Before freezing a COSE algorithm or claiming support

1. Recheck the implementation when supported TQSL versions change. The currently inspected Signing API hardcodes SHA-1 and is blocked for ARAP proof signing.
2. Identify how the operation hashes/encodes its input and formats signatures. Determine whether it can sign the exact COSE `Signature1` input under a standard, fully specified COSE algorithm. Reject an adapter that requires signing some nonstandard transformation or publishing a private COSE algorithm without explicit review.
3. Determine supported Callsign Certificate public-key types, sizes, key usages, EKUs, policy OIDs, callsign fields, date ranges and issuer chain. A certificate's issuer signature algorithm is not the same as the subscriber key's message-signing algorithm.
4. Test with a purpose-built, non-station test credential if TQSL supports it. For a real station certificate, require explicit user consent and never copy its private key into fixtures, logs or exports for this research.
5. Confirm callsign certificate trust anchors and revocation/status mechanisms, how often status updates, and how offline verification represents stale or unknown status. A valid signature alone does not establish current certificate status.
6. Treat the enrollment assertion as ARAP authentication evidence only. Do not describe it as an ARRL-approved login, endorsement, or supported LoTW authentication mechanism.
7. Verify the API lifecycle and threading expectations. `tqsl_beginSigning` is documented to create an unencrypted in-memory copy of the private key and `tqsl_endSigning` zero-fills that copy. Keep it alive only for the operation, ensure cleanup on all error paths, and keep password input out of process arguments/logs.
8. Document offline trust behavior, certificate expiry/invalidations, callsign matching and portable/alternate callsign rules. Never silently equate `AG7SU`, `AG7SU/P` and `AG7SU/7`.

## Profile outcome

- Use the implemented Ed25519 COSE profile (`-19`) for ARAP content and challenge-response signatures. Keep TQSL as the preferred LoTW credential lifecycle. A separate fresh-challenge flow may use the Callsign Certificate to bind an ARAP Ed25519 key to a callsign; this is an enrollment assertion, not an ARAP content signature. The candidate flow and open gates are in [LoTW-backed ARAP key enrollment](LOTW-BINDING-DESIGN.md).
- Keep generic hashing, CSPRNG use, proof parsing/verification and transport in ARAP or its platform libraries; those operations do not become LoTW credential operations. At the identity/signing layer, require an approved provider to sign the exact COSE `Signature1` bytes and expose its public key without exporting the private key. The current Go `Signer` interface is only an interface boundary: the v1 profile still allowlists Ed25519, and the inspected TQSL API cannot implement it.
- Do not enable the current TQSL API as an ARAP content or COSE signer. The project accepts its legacy RSA-SHA1 operation only for the separately versioned, short-lived enrollment assertion, with explicit per-operation acknowledgement. ARAP content and challenge-response remain Ed25519. Freshness policy is set at 24 hours by default; live endpoint behavior remains unvalidated. This ARAP authentication evidence does not imply ARRL approval. Never label the TQSL signature as Ed25519 or use it to sign ARAP content.
- Never treat LoTW certificate status as permanently valid based solely on the certificate bytes or a signed `created` timestamp. Require fresh status evidence under ARAP policy and fail closed when it is missing. Live endpoint behavior with a real certificate remains to be validated.

## Enrollment prototype status

The challenge and dual-signature envelope are implemented in
`lotwenroll/`. TQSL's supported RSA/SHA-1 signature is accepted only for the
short-lived enrollment assertion; explicit CLI policy and desktop confirmation
remain required. ARAP content and challenge signatures remain Ed25519.
`tqsl-helper/` builds a native TQSLLIB adapter that signs
the exact challenge bytes, returns public chain certificates, and never calls
the private-key export API. The CLI can issue, respond to and verify
enrollment challenges, and `ARRLCertificateStatusClient` queries the public
status URL used by TQSL with cache-revalidation headers and response-age
accounting. The CLI can load self-signed roots from TQSL's local `certs/root`
bundle by default, keeping intermediates separate from trust anchors. The
adapter and status client have not yet been validated against a real
ARRL-issued certificate. A complete ARRL certificate policy is still missing.
TQSL's local cached status API still cannot provide its own freshness
timestamp. The profile is therefore not ready for production enrollment.

## Do not assume

- Arbitrary block signing implies compatibility with every signature format or hash algorithm.
- A certificate can be used for every purpose solely because its private key can sign data.
- A mathematically valid signature proves the key was authorized, uncompromised or physically at a radio station.
- COSE X.509 headers automatically validate callsigns, certificate policy or revocation.
- LoTW provides an unrestricted public certificate directory or a standard public revocation endpoint.

## Evidence already checked

- Local environment cross-check on 2026-10-20: the installed `/usr/local/bin/tqsl` is TQSL 2.8.7-rc5. Its CLI supports `-z` test-sign mode for synthetic ADIF and has no CLI interface for arbitrary challenge signing. The bundled `libtqsllib.so` exports `tqsl_signDataBlock` and `tqsl_verifyDataBlock`; upstream source at the inspected commit shows both call `EVP_sha1()` before OpenSSL sign/verify finalization. A safe synthetic ADIF `-z` run completed and wrote one `.tq8`; TQSL stated it had not recorded the QSO, and no upload was made. This confirms only the TQSL synthetic-log path, not LoTW or ARAP authentication.
- Rechecked upstream `master` on 2026-10-20 through the TrustedQSL SourceForge Git repository. The branch still resolves to commit `1916fc14a8cfc7f287742ae5a34aa986353d9df7`, the same commit previously inspected. In `src/openssl_cert.cpp`, `tqsl_signDataBlock` and `tqsl_verifyDataBlock` still call `EVP_SignInit` / `EVP_VerifyInit` with `EVP_sha1()`; `tqsl_new_rsa_key` still generates RSA keys. No modern direct-signing path was found in that current source snapshot, so the TQSL-to-ARAP signing blocker has not changed.
- Follow-up source check on 2026-10-20: ARRL lists TQSL 2.8.6, while SourceForge `master` is at v2.8.7-rc5. A fresh shallow checkout still has `EVP_SignInit(..., EVP_sha1())` and `EVP_VerifyInit(..., EVP_sha1())` in `src/openssl_cert.cpp`. The newer release does not change the content-signing conclusion. TQSL 2.8.3 added `-z` test-signing for ADIF logs without upload-tracking side effects; this is useful for synthetic QSO format tests, but it does not exercise the raw data-block API.
- The Signing API documentation lists arbitrary data-block sign/verify functions and documents initialization/cleanup behavior: <https://www.rickmurphy.net/lotw/doxygen/group__Sign.html>.
- The upstream implementation at the commit above hardcodes SHA-1 in both data-block signing and verification; RSA is generated for certificates. This resolves the direct API-to-COSE question against enabling that API.
- The same public API exposes `tqsl_getKeyEncoded`; its implementation serializes a `PRIVATE_KEY` field when a private key is present. Do not use this export API to build an ARAP signer. The separate experimental enrollment helper uses `tqsl_beginSigning` and `tqsl_signDataBlock` for challenge bytes, then calls `tqsl_endSigning`; it does not sign COSE content or expose the private key.
- `tqsl_getCertificateStatus(serial)` reads TQSL's locally loaded status data and maps its `Unrevoked` entry to `OK`; the function itself supplies no freshness timestamp. Treat this as cached status evidence, not proof that revocation status is current. If an ARAP policy requires current status and freshness cannot be established, the result stays unknown.
- The documented `tqsl_beginSigning` lifecycle creates an unencrypted in-memory private-key copy, and `tqsl_endSigning` zero-fills it. Even apart from the SHA-1 limitation, this API is not a hardware-backed or non-exporting signer boundary.
- The IANA [COSE Algorithms registry](https://www.iana.org/assignments/cose) marks RS1 deprecated.
- ARRL's developer guide describes TQSL as managing Callsign Certificates and signing ADIF/Cabrillo QSO logs: <https://lotw.arrl.org/lotw-help/developer-submit-qsos/>.
- ARRL describes Callsign Certificates as authenticating submitted contacts and recommends protecting private credentials: <https://lotw.arrl.org/lotw-help/certificatesecurity/>.

Live certificate-status behavior remains unvalidated. The project has accepted RSA-1024/SHA-1 for the narrow enrollment use, with per-operation acknowledgement, and treats the certificate signature as ARAP authentication evidence under ARAP policy. This is not an ARRL-approved login or endorsement. TQSL should lead ARAP's ham-credential integration, but its inspected API is not a general-purpose cryptographic provider and is not an ARAP content signer.
