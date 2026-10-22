# LoTW-backed ARAP key enrollment

Status: experimental enrollment prototype. `lotwenroll/` implements the
challenge, response, verifier and status client. `arap enrollment respond`
uses the optional native helper in `tqsl-helper/` to sign through TQSLLIB
without exporting the station private key. The project accepts TQSL's
RSA/SHA-1 data-block signature for this narrowly scoped, short-lived enrollment
assertion because that is the signing operation TQSL provides. The CLI and
desktop still require an explicit per-operation acknowledgement. This decision
does not permit RSA/SHA-1 for ARAP content or challenge signatures: those remain
Ed25519. The project treats successful enrollment as authentication evidence
under ARAP policy, not as an ARRL-approved login or endorsement. Live
real-certificate verification remains unvalidated.

## Goal

Use an ARRL-issued LoTW Callsign Certificate to authenticate control of a
callsign and bind that credential to an ARAP Ed25519 key. Keep Ed25519 for
ARAP content and challenge-response signatures. Do not create or submit a QSO
to enroll an ARAP key.

## Candidate enrollment flow

1. The ARAP client creates or selects its Ed25519 key pair locally.
2. The verifier issues a short-lived, single-use canonical challenge containing
   a domain label, verifier audience, session binding, normalized callsign,
   full Ed25519 SPKI SHA-256 fingerprint, purpose, random nonce, issue time,
   and expiry.
3. TQSL/TQSLLIB signs the exact canonical challenge bytes with the selected
   Callsign Certificate. The client also signs the challenge with the matching
   Ed25519 key. The response includes the public certificate chain and both
   signatures, never the TQSL private key.
4. The verifier consumes the nonce once, checks both signatures, validates the
   Callsign Certificate chain and callsign binding, and evaluates certificate
   dates and current status evidence under explicit policy.
5. On acceptance, the verifier records the callsign-to-Ed25519-key binding
   together with the certificate fingerprint, issuer, validation time, status
   evidence age, and allowed ARAP purposes. A later content proof is still
   signed by Ed25519.

The TQSL signature is a narrowly scoped enrollment assertion. It is not an
ARAP COSE signature, a content signature, or evidence that LoTW accepted an
ARAP assertion. The result should be worded as verification of possession of
an ARRL-issued LoTW Callsign Certificate, with certificate status reported
separately.

## Why a `.tq8` file is not the enrollment proof

ARRL documents `.tq8` signatures over normalized QSO fields. Those signatures
can establish that a Callsign Certificate signed particular QSO data, but the
signed fields do not include an arbitrary ARAP key fingerprint or challenge.
Using a fabricated QSO to carry an ARAP claim would misuse LoTW. A real QSO
signature alone also does not bind an Ed25519 key to the callsign.

## TQSL cryptographic constraint

The inspected `tqsl_signDataBlock` and `tqsl_verifyDataBlock` APIs accept
arbitrary bytes but hardcode RSA PKCS#1 v1.5 with SHA-1. The local certificate
inspected during development has a 1024-bit RSA public key. The project accepts
this legacy operation only for the fresh, audience-bound, single-use enrollment
challenge. The nonce and audience binding limit replay and cross-protocol use;
they do not strengthen RSA-1024/SHA-1. The operation must never be used for
ARAP content or challenge-response signatures, which stay on Ed25519. The
per-operation acknowledgement remains so users understand which mechanism
their station certificate applies to.

The API lifecycle must also be reviewed for key handling. `tqsl_beginSigning`
loads an unencrypted in-memory copy of the private key, and
`tqsl_endSigning` clears that copy. The helper calls cleanup on all paths,
keeps passphrases out of arguments and logs, and never calls
`tqsl_getKeyEncoded` or exports a private key.

## ARRL usage and certificate validity boundary

Reviewed against ARRL's published help on 2026-10-20. Its developer and
certificate pages describe Callsign Certificates as authenticating QSO/log
submissions: TQSL signs QSO records and sends them in a `.tq8` log file. The
public guidance reviewed here does not say that arbitrary application
challenge signatures are an approved LoTW login or authentication mechanism.
ARAP uses the certificate signature as authentication evidence by project
policy. It is not an ARRL-supported login, LoTW account authentication, or ARRL
endorsement. See [ARRL developer
information](https://lotw.arrl.org/lotw-help/developer-information/), [TQSL's
QSO signing description](https://lotw.arrl.org/lotw-help/developer-submit-qsos/),
and [Callsign Certificate management](https://lotw.arrl.org/lotw-help/managing-callsign-certificates/).

The present design runs TQSLLIB locally and returns only the challenge
signature and public certificate chain; it does not copy the LoTW private key
to an ARAP server. The ARRL [Trusted Partner requirements](https://www.arrl.org/files/file/LoTW_Developer/LoTW%20Trusted%20Partners-1_0.pdf)
address web-based services that store or process users' private keys. They do
not by themselves establish approval for this local challenge-signing use. Any
future hosted ARAP service that stores or uses LoTW private keys needs a
separate policy and security review.

ARRL states that issuing a new Callsign Certificate makes a previous
certificate for the same callsign invalid; certificate serial numbers are the
identifier used to compare local TQSL certificates with LoTW's valid list.
ARAP therefore treats the status endpoint's `Superceded` response as invalid,
requires a fresh status check under its configured age bound, and rejects an
unknown status. The [ARRL certificate validity guidance](https://lotw.arrl.org/lotw-help/certificatevalidity/)
does not make the HTTP status response a signed assertion, so the current
implementation's TLS, returned-serial, HTTP date/age and cache-revalidation
checks are freshness and transport controls, not cryptographic proof of the
status origin's internal data age.

## Certificate acceptance policy

ARAP follows TQSL's Callsign Certificate trust and current-validity evidence for
the selected supported TQSL release:

- Trust only self-signed CA roots from TQSL's configured `certs/root` bundle;
  do not silently add the operating system's general-purpose root store.
  Intermediates supplied with an enrollment response build the chain but never
  become trust anchors. An explicit `--roots` bundle is an administrator
  override and must contain self-signed CA certificates.
- Require a currently valid X.509 chain and a leaf certificate that permits
  digital signatures. Read the callsign only from the TQSL/ARRL callsign
  subject attribute (OID `1.3.6.1.4.1.12348.1.1`), require exactly one value,
  normalize it with ARAP's callsign rules, and require an exact match to the
  fresh challenge. Do not infer portable or alternate callsigns from the common
  name or silently equate suffixed calls with the base call.
- Use the certificate serial number with the LoTW status endpoint used by
  TQSL. Accept only `Unrevoked`; reject revoked, superseded, expired, bad
  serial, unknown and malformed responses. ARRL says a newly issued certificate
  invalidates the previous certificate for that callsign and describes checking
  validity by matching the serial number against LoTW's valid list
  ([certificate validity](https://lotw.arrl.org/lotw-help/certificatevalidity/),
  [managing certificates](https://lotw.arrl.org/lotw-help/managing-callsign-certificates/)).
- Require status evidence observed no more than 24 hours ago by default. Derive
  its observation time from the HTTPS response's `Date` minus `Age`, as the
  current TQSL-compatible client does. This is an ARAP freshness limit over the
  same status source TQSL uses, not proof that LoTW's underlying status database
  was updated at that time. If the endpoint is unavailable or evidence is stale,
  enrollment and status refresh fail closed; retry later rather than trusting
  cached or unknown status.

These checks establish ARAP's policy for using the Callsign Certificate
signature as authentication evidence of control of the certified key, in
combination with the matching Ed25519 signature. They do not make the exchange
an ARRL login, LoTW transaction, or ARRL endorsement. The ARRL describes
Callsign Certificates as authenticating QSO submissions
([developer PKI description](https://lotw.arrl.org/lotw-help/developer-pki/));
ARAP makes its separate use explicit.

## Required gates before implementation is trusted

- [x] Accept the legacy RSA-1024/SHA-1 signature for the narrowly scoped
  enrollment assertion, with per-operation acknowledgement. Keep it separate
  from Ed25519 proof and challenge signing.
- [x] Establish ARRL root, intermediate, key-usage, callsign extraction,
  exact-match, expiry, and status/revocation rules from TQSL's configured root
  bundle and the LoTW certificate-status source. Portable calls require their
  own certificate/callsign and are never inferred from a base call.
- [x] Require the TQSL-compatible LoTW status endpoint and reject cached,
  stale, unknown, or unavailable status under the configured freshness limit.
- [x] Define this as ARAP authentication evidence under ARAP policy, without
  representing it as an ARRL-approved login or endorsement.
- Test against generated, non-station certificates and a fake CA first. Never
  put a station private key in fixtures. Use TQSL's test-sign option only for
  synthetic ADIF workflow tests; it does not exercise raw challenge signing.
- Add replay, wrong-audience, wrong-key, wrong-callsign, expiry, revoked/status
  unknown, malformed-chain, and altered-signature negative cases.

## Synthetic native-helper demonstration

Run `make enrollment-demo` on Linux. The script generates a short-lived
synthetic root, intermediate, and `N0CALL` Callsign Certificate in a temporary
directory, builds the real helper and test-only importer against TrustedQSL
commit `1916fc14a8cfc7f287742ae5a34aa986353d9df7`, and imports only those
generated credentials into a fresh TQSL data directory. The helper receives
that directory through `--tqsl-directory`, so it does not read the normal user
TQSL credential store. Set `TRUSTEDQSL_SOURCE_DIR` to an existing checkout of
the pinned source; otherwise the script fetches that exact revision.

The prerequisites are Go 1.26.10+, Git, CMake, a C/C++ compiler, and OpenSSL,
SQLite, Expat, and zlib development files. On Ubuntu/Debian, install them with:

```sh
sudo apt-get install build-essential cmake git libssl-dev libsqlite3-dev libexpat1-dev zlib1g-dev
make enrollment-demo
```

The verifier harness injects timestamped synthetic-good status into the Go
library only. The production CLI has no synthetic-status option and the flow
does not contact LoTW or claim ARRL acceptance. It verifies and persists a
purpose-scoped enrollment, signs and verifies content, authenticates a separate
challenge with the enrolled ARAP key, and reports expected rejection cases for
replay, changed challenge, wrong audience/key/callsign, expiry, invalid chain,
revoked/unknown/stale status, and disabled binding.

`make signing-demo` runs the offline content example and signs/verifies the
repository's PixelQSO frame-pair fixture. Both demos use throwaway keys and
clean up temporary files.

Local run on 2026-10-20 passed both targets with the pinned TrustedQSL source.
The enrollment output included accepted synthetic enrollment, content and
station challenge checks plus expected rejection reports for all listed
negative cases. This does not validate a real certificate or live LoTW status.

## Prototype state

`lotwenroll/` now creates a canonical-CBOR, five-minute maximum challenge,
binds its audience, normalized callsign, random nonce, and Ed25519 SPKI
fingerprint, and defines a dual-signature response. The verifier checks the
certificate chain against caller-supplied roots, callsign through a required
issuer-specific extractor, key usage, configured status evidence, the TQSL
RSA/SHA-1 signature, the Ed25519 signature, audience, freshness, and one-time
challenge consumption. The verifier refuses enrollment by default; enabling
`EnableLegacyRSASHA1` is an explicit policy switch. Tests use a locally
generated fake CA and synthetic credentials only.

`lotwenroll.SQLiteStore` persists challenge state and accepted call/key
bindings together. Completion checks that the persisted challenge callsign
and key fingerprint match the proposed binding, then atomically consumes the
challenge and writes the certificate/status evidence. Bindings can be listed
and disabled; re-enrollment requires another fresh challenge. Version 1
enrollment authorizes only the Ed25519 key's `challenge-response` use. The
challenge's requested `station-auth` purpose remains separate from that proof
purpose. Version 2 binds an explicit verifier-selected purpose set, including
`content-signature`, into the bytes signed by both keys. The verifier must also
allow each requested purpose when accepting the response. Existing version 1
challenges and bindings remain challenge-response-only and are never upgraded
implicitly.

To authorize content, issue a version 2 challenge with the requested purpose,
then verify its response with an explicit verifier policy:

```sh
arap enrollment issue --audience verifier.example --callsign AG7SU \
  --public-key arap-ed25519.pub.pem --purpose content-signature \
  --store ~/.local/state/arap/lotw-enrollment.sqlite --out enroll-v2.cbor

arap enrollment verify-response --response enrollment-response.cbor \
  --audience verifier.example --allow-purpose content-signature \
  --store ~/.local/state/arap/lotw-enrollment.sqlite --roots arrl-roots.pem \
  --allow-legacy-rsa-sha1
```

The receiving application then verifies content with that enrollment store and
an explicit status age bound:

```sh
arap verify-content --proof message.cose --input message.bin \
  --public-key arap-ed25519.pub.pem --enrollment-store lotw-enrollment.sqlite \
  --max-enrollment-status-age 24h --expect-media-type application/octet-stream \
  --expect-context my-app/message/v1
```

The verifier can refresh status evidence for an accepted binding without
re-running dual-signature enrollment. It supplies the retained response, which
carries the public certificate chain, plus the exact callsign and Ed25519 key
fingerprint:

```sh
arap enrollment refresh --response accepted-enrollment.cbor \
  --callsign AG7SU --key-id SHA256_HEX \
  --store ~/.local/state/arap/lotw-enrollment.sqlite --roots arrl-roots.pem
```

Refresh validates the chain against configured roots at the current time,
checks the TQSL callsign attribute and exact leaf certificate fingerprint,
then requests fresh status evidence. It updates only stored status fields; it
cannot change the key, certificate, purpose, or disabled state. Expired,
revoked, unknown, stale, mismatched, or disabled bindings remain unavailable.
The application must retain the accepted response as public evidence and
choose when to schedule this network operation. Key or certificate replacement
requires a fresh enrollment challenge.

The CLI command below issues the verifier-side challenge, persists its pending
state, and writes the canonical CBOR to a new owner-only file. If output
publication fails, the pending record is cancelled. Issuing a challenge does
not contact LoTW or create an enrollment binding:

```sh
arap enrollment issue --audience verifier.example --callsign AG7SU \
  --public-key arap-ed25519.pub.pem \
  --store ~/.local/state/arap/lotw-enrollment.sqlite --out enroll.cbor
```

The response is signed separately with the enrollment responder. The ordinary
`challenge respond` command is not an enrollment response and must not be
substituted.

Status callbacks must return a source and observation timestamp, and the
verifier requires an explicit maximum evidence age. `ARRLCertificateStatusClient`
queries the same public endpoint used by TQSL at
`https://lotw.arrl.org/lotw/crl?serial=…`, checks the returned serial and
status, requests cache revalidation, and dates evidence from the HTTP `Date`
minus `Age` headers. TQSL's local cached status function cannot satisfy this
by itself because it provides no freshness time. The HTTP result is protected
by TLS and server time, not by a LoTW signature on the status response.

The CLI verifier uses this provider after validating the response certificate
chain and callsign. It accepts only the `Unrevoked` response as good; revoked,
superseded, expired, malformed, mismatched-serial, stale, and unknown results
fail closed. Its legacy TQSL RSA/SHA-1 signature policy remains disabled
unless `--allow-legacy-rsa-sha1` is explicitly passed:

```sh
arap enrollment verify-response --response signed-enrollment.cbor \
  --audience verifier.example \
  --store ~/.local/state/arap/lotw-enrollment.sqlite
```

By default, the CLI loads only self-signed roots from the local TQSL
configuration (`$TQSLDIR/certs/root`, `%APPDATA%/TrustedQSL/certs/root`, or
`~/.tqsl/certs/root`, depending on platform). Use `--roots` to override this
with another PEM bundle of self-signed roots. Intermediate certificates are
not promoted to trust anchors.

The endpoint and status handling follow the current TrustedQSL source's
certificate-status query configuration and response parser. The behavior has
not yet been exercised with a real LoTW-issued certificate; an unknown or
unrecognized status is rejected. See the [TQSL change log](https://lotw.arrl.org/lotw-help/tqslchangelog/) and [TrustedQSL source](https://sourceforge.net/p/trustedqsl/tqsl/ci/master/tree/apps/tqsl.cpp).

## Responding with TQSL

Build `arap-tqsl-sign` against the TrustedQSL source version installed on the
machine. For example, after `make build`, run
`./tqsl-helper/build.sh /path/to/TrustedQSL bin`. The helper only returns
public certificates and the signature; it does not export or persist the
station private key. The desktop discovers an adjacent `bin/arap-tqsl-sign`;
the CLI accepts `--tqsl-helper` or `ARAP_TQSL_HELPER`. Then use the
challenge file, the matching ARAP private key, and a new response output file.
When multiple current TQSL certificates exist for the callsign, supply the
decimal certificate serial. The CLI reads the ARAP key password and TQSL
certificate password from two stdin lines, or the desktop prompts for them.
Passwords are not command-line arguments.

The signer deliberately requires `--allow-legacy-rsa-sha1` (and the desktop
requires its unchecked-by-default control plus confirmation) because the
TQSL API hardcodes RSA/SHA-1. This opt-in is local user consent for that
operation; it does not mean the flow has passed security review or is endorsed
by ARRL. Do not use the QSO date-range/log-signing workflow to create an
enrollment assertion. Responding signs only the challenge bytes and does not
submit a QSO.

This remains an experimental enrollment path, not a production or ARRL-approved
workflow. The optional client adapter is built against TrustedQSL source and
does not ship inside the app bundles. The project does not ship approved ARRL
trust anchors or the complete certificate policy, and the status client still
needs integration validation. Callsigns are read only from the TQSL-specific
subject attribute; they are not guessed from a generic X.509 subject. The
challenge wire formats are defined by
[`ARAP-lotw-enrollment-v1.cddl`](../spec/ARAP-lotw-enrollment-v1.cddl) and
[`ARAP-lotw-enrollment-v2.cddl`](../spec/ARAP-lotw-enrollment-v2.cddl).

## TQSL version notes

The local installation inspected on 2026-10-20 is TQSL 2.8.7-rc5. ARRL lists
TQSL 2.8.6 as the current stable release. The 2.8.3 release added `-z`
test-signing for ADIF logs; it signs without uploading or recording the QSOs.
This is suitable for safe synthetic log tests, not for testing the data-block
signing API. The current TrustedQSL master snapshot (`v2.8.7-rc5`, commit
`1916fc14a8cfc7f287742ae5a34aa986353d9df7`) still uses `EVP_sha1()` in both
data-block signing and verification.

## Sources

- [ARRL: digitally signed `.tq8` file structure](https://lotw.arrl.org/lotw-help/developer-tq8/)
- [ARRL: LoTW developer information](https://lotw.arrl.org/lotw-help/developer-information/)
- [ARRL: TQSL 2.8.6 release notes](https://www.arrl.org/tqsl/TrustedQSL-2-8-6-release.pdf)
- [TrustedQSL current source tree](https://sourceforge.net/p/trustedqsl/tqsl/ci/master/tree/src/openssl_cert.cpp)
- [TQSLLIB signing API documentation](https://www.rickmurphy.net/lotw/doxygen/group__Sign.html)
