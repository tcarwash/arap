# Draft validation and implementation readiness

## Personal confidence demo

Run `make confidence-demo` to exercise ARAP without using a real certificate or
station key. The script builds the CLI unless `ARAP_BIN` points to an existing
one, generates two temporary encrypted Ed25519 keys, and removes its temporary
files on exit. It signs and verifies a sample file, confirms that an edited copy
is rejected, confirms that unchanged signed content from a signer missing from
the trust list is not accepted, and verifies a challenge response once before
confirming that replay is rejected. The CLI prints each result; the script exits
nonzero if an expected exit status differs.

This demonstrates local software behavior. It does not test TQSL, a real LoTW
certificate, current ARRL certificate status, deployed services, RF presence,
or independent cryptographic review.

Reviewed 2026-10-20 against the current repository implementation and primary sources linked below. This is a project validation snapshot, not an independent security review or RF validation.

## Assessment

The nine CDDL schemas are compiled against RFC 8610 by the pinned `cddl`
validator and checked against the checked-in content proof, challenge request,
challenge response COSE envelope, and PixelQSO card vectors. Run `make cddl`
locally after installing `cddl` v0.10.7 with Rust 1.88 or later; CI installs
the pinned versions. The challenge response has a separate top-level CDDL file
so validators can select and check the signed COSE envelope, not only its
embedded payload.

The prototype now has an explicit Ed25519 COSE profile, offline content verification, local trust records, a CLI, a Tk client, and a content-addressed keyserver with persistent quotas, upload throttling and optional object retention. The PixelQSO editor now has detached proof signing/attachment, local trust verification, reference publication/resolution, and pending/verified status through the ARAP CLI. The wire profile is still experimental: broader malformed-parser coverage, compatibility review, distribution licensing, and complete target-app/deployment validation remain.

The Ed25519 content-signature slice, PixelQSO card canonicalizer, and Go/Python vectors exist. Python independently checks content-proof structure, signature, trust input, digest/size and policy expectations, and rejects eleven signed or presented-input negative cases, including tampered expiry and malformed optional content ID values. Direct TQSL signing is ruled out for this profile because it uses SHA-1/RS1. Keep independent vector gates; cross-language agreement alone does not constitute an independent security review.

## Findings

| ID | Priority | Finding and consequence | Required action |
| --- | --- | --- | --- |
| V01 | Addressed in native profile | The draft previously named `EdDSA`; current profile uses explicit Ed25519 (`-19`) and has a Go/Python matching vector. | Keep rejecting `-8` and assert the numeric header in expanded vectors. |
| V02 | Partially addressed | `spec/ARAP-profile-v1.cddl` and Go encoding define tag 18, protected headers, payload labels, and empty external AAD. The conceptual draft now points to the implemented CDDL profiles and distinguishes prototype wire decisions from standardization. Broader independent conformance vectors and review remain. | Expand conformance vectors and obtain independent review before declaring the profile interoperable. |
| V03 | Addressed for local pins | CLI accepts explicit public keys and local callsign/key/purpose trust records; remote keys remain untrusted until explicitly pinned. Trust loading rejects duplicate JSON properties, duplicate callsign/key bindings and excessive nesting, and a disabled binding takes precedence over enabled duplicates. There is no certificate-chain or public identity service. | Preserve this boundary in UI wording; TQSL/certificate identity remains future work. |
| V04 | Partial, needs adversarial coverage | Decoder limits, duplicate-key rejection, deterministic re-encoding checks, exact labels, proof size, tag restrictions, malformed envelope/header/payload cases, and bounded fuzz targets are implemented for proof, challenge, public-key/certificate, PixelQSO card, and resolver parsers. Correctly signed invalid-schema cases now cover profile/version/purpose, normalized callsign, timestamps, content-size/digest and metadata bounds. External conformance review remains. | Continue signed-invalid-schema and parser-edge coverage; seek external conformance review before wire freeze. |
| V05 | Mostly implemented | Verify results separate signature, content, identity, and aggregate policy; caller purpose/media/context are required. Content verification now rejects `created` values more than 300 seconds ahead while preserving the valid cryptographic-signature result; this is clock-skew defense, not proof of signing time. Stable API compatibility still needs review. | Keep the fixed skew bound consistent across implementations and add UI/CLI regression cases; do not equate local pins with licensed identity. |
| V06 | Partial challenge implementation | Canonical requests, signed response binding, SQLite atomic consumption, expiry checks, restart/replay tests, untrusted and disabled response handling, wrong-requester non-consumption, concurrent-handle and six-process tests, wrong-responder rejection, storage-failure behavior, and a byte-identical Python vector exist. Python independently rejects sixteen semantic and malformed-envelope/schema cases. Go rejects untagged COSE, unprotected headers, noncanonical outer encoding and an unknown signed payload field. CLI issuance tests confirm that an existing output creates no pending row and a failed database insert removes the unpublished request. Construction rejects pre-epoch/sub-second bounds and invalid UTF-8 purpose; decoding rejects an explicitly empty session binding. | Continue parser and security review before claiming full profile interoperability. |
| V07 | Partially addressed | Signed `created` is a signer assertion, not a trusted timestamp. A compromised key can backdate content. Content expiry policy is now applied only after signature verification: a valid expired proof reports its signature as valid, while a tampered expiry claim is classified as an invalid signature. | Keep signature mathematics separate from current trust, disablement and expiry policy. Never infer historical credential validity from `created`; continue defining certificate status behavior. |
| V08 | Partial resolver implementation | Go resolver, CLI, and desktop merge prefix candidates across up to eight configured resolvers, fail closed on incomplete lookups, retry full-hash/key retrieval, validate object identifiers, reject redirects and bound responses. Formatted references are limited to 256 bytes. Lookup JSON rejects duplicate/missing fields, invalid field types, trailing data and candidate lists above the server's 100-entry bound; both parsers have CI fuzz targets. Tests reject candidate hashes that do not match the requested token, candidate paths serving bytes with a false hash, oversized lookup/proof responses and canceled requests; the keyserver also errors when stored proof bytes no longer match the path hash. The Compose smoke covers authenticated publication, lookup/verification, restart persistence and anonymous-write rejection. `verify-ref` then applies local content expectations and trust. | Continue malicious-resolver review: a resolver can omit candidates, and no client can prove a resolver's response is globally complete. |
| V09 | Partially addressed | The current PixelQSO saved-card schema was inspected. ARAP canonicalizes its authenticated fields to deterministic CBOR, ignores named editor-local state, rejects unknown fields, and has a synthetic Python/Go two-frame vector plus a real starter-card CLI round trip. CLI tests require the first card and reject an edited first-frame fingerprint. The PixelQSO editor now signs/attaches/verifies proof sidecars and publishes/resolves references without changing card JSON or modem payload. Publish/resolve run in a worker; tests prove scheduled UI events continue during a slow CLI operation. The adapter enforces byte, nesting-depth and value-count limits. No claim is made about transmitted raster bytes or live RF behavior. | Add properly licensed real-card fixtures and exercise paired-card GUI flows and deployed keyserver transport. |
| V10 | Resolved against direct signer use | Inspected TQSL source hardcodes SHA-1 in `tqsl_signDataBlock` / `tqsl_verifyDataBlock` and generates RSA keys. This maps to COSE RS1 (`-65535`), which is deprecated; it is not allowed by ARAP's Ed25519 profile. | Do not enable the current TQSL signer. Recheck only when an upstream supported API changes. Research certificate identity binding independently and keep Ed25519 `-19` as the signer. |
| V11 | Scope/dependency issue | The old plan conflated TQSL support with the native wire gate and ordered PixelQSO after unrelated future work. | Keep native Ed25519 vectors as their own gate. Gate PixelQSO and challenges on their own vectors; neither needs to wait for TQSL policy research. |
| V12 | Before distribution | Go module, key-file permissions, Docker Compose, setup documentation, platform bundle scripts/checker and cross-target CI artifact builds now exist. Linux amd64/arm64, macOS amd64/arm64, and Windows amd64 bundles were built and inspected locally; the Linux ZIP was extracted, launched under Tk, its adjacent CLI executed, and the desktop key-generation action created both files with owner-only private-key permissions. CLI and HTTP actions now run in background workers while Tk remains responsive; the bundle smoke checks event processing and disables action buttons during work. Native macOS/Windows runtime jobs now build a bundle for the runner architecture and launch its Tk UI and adjacent CLI. A local container smoke check covered `/healthz`, authenticated proof upload, and hash-addressed retrieval. Hosted workflow and native macOS/Windows runtime results remain unobserved. Code licensing and public release signing remain unresolved. | Select a code license and publish only after hosted and native desktop validation. |
| V13 | Partial PixelQSO integration | The ARAP library canonicalizes saved PixelQSO JSON to `PixelQSO-card-v1` CBOR; CLI and desktop can sign/verify it. Unit tests bind art, ordered palette, card metadata and animation reference while excluding known editor-local state. Python-generated bytes and the PixelQSO BLAKE2s-64 frame-link fingerprint match Go; CLI requires and validates frame 1 for frame 2. The PixelQSO editor now integrates detached proof and reference sidecars. Through the bridge and real CLI, a trusted saved card was accepted and a one-pixel edit rejected. Tests confirm status reloads per animation frame and becomes stale after edits. A disposable local keyserver publish/resolve returned byte-identical proof data and verified successfully. Hosted transport, complete modal interaction and live RF interoperability remain open. | Add properly licensed real-card fixtures; verify deployed publish/resolve and paired-card UI workflows; retain a clear split between radio FEC integrity and ARAP identity. |
| V14 | Addressed for Compose volume startup | The first live Compose test found that the distroless non-root process could not create `/data/proofs` on a fresh named volume. The image now seeds `/data` with UID/GID 65532 ownership. `scripts/check-keyserver-compose.py` runs an isolated Compose project and verifies health, anonymous upload rejection, authenticated proof/key publication, CLI reference verification, exact key/proof fetches, and proof persistence across container restart. This runtime check is part of CI. | Keep the named-volume runtime check; production HTTPS/proxy deployment and operational backup/restore remain separate validation. |

## Standards checks

- **Algorithms:** [RFC 9864, section 2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2) assigns COSE `-19` to Ed25519. Its registry updates deprecate `-8`. This is a confirmed draft correction, not a weakness in Ed25519 itself.
- **COSE:** [RFC 9052, sections 4.2–4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2) defines Sign1 and its signature input. ARAP must pin tagging and external AAD. Keep the ARAP payload embedded while application content may remain a separate file; these are different forms of detachment.
- **CBOR:** [RFC 8949, sections 4.2.1 and 5.6](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) supplies core deterministic encoding and map-key guidance. Select that exact ordering instead of loosely saying “canonical CBOR.” ARAP still needs explicit parser restrictions.
- **Certificates:** [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html) defines certificate headers and related processing. Application trust still needs explicit roots, certificate validation and callsign binding.
- **References:** [RFC 4648, sections 3.5 and 6](https://www.rfc-editor.org/rfc/rfc4648.html#section-6) supports the proposed Base32 alphabet. Ten digest bytes yield exactly sixteen unpadded symbols. Freeze presentation normalization separately from digest bytes.
- **TQSL evidence:** The API documentation exposes arbitrary-block operations. Current source commit `1916fc14a8cfc7f287742ae5a34aa986353d9df7` hardcodes SHA-1 in signing and verification, while generating RSA keys; this is deprecated COSE RS1, so direct signing is excluded. See [TQSL research](TQSL-RESEARCH.md). Certificate binding policy remains unverified.

## Dependency feasibility

The repository uses one Go module, Go standard-library Ed25519 over explicit COSE Signature1 bytes, pinned `fxamacker/cbor/v2`, and an independent Python vector generator. The TQSL API inspected is not an appropriate signer.

- `fxamacker/cbor/v2` is pinned and used with explicit deterministic encoding and decode limits. Review remaining parser edge cases in conformance work.
- Go standard-library Ed25519 signs/verifies the explicit COSE `Signature1` structure; `-19` is asserted in the profile and fixtures.
- Python independently encodes the signature input and verifies fixture bytes without invoking Go; eleven content negatives and sixteen challenge negatives are recorded in their manifests. Broader malformed-parser coverage remains open.

Validation run on 2026-10-20: `go test -race ./...`, `go vet ./...`, `git diff --check`, Python bytecode compilation, CGO-free CLI and keyserver builds, Docker image build, and Docker Compose config pass. Added proof tests cover non-ASCII callsign case mappings, negative signing time, invalid UTF-8, exact COSE envelope/header constraints, deterministic encodings, duplicate payload labels, correctly signed invalid schemas, and the 300-second future-created boundary. Challenge tests cover pre-epoch/sub-second request construction and the empty optional session edge. Trust tests cover duplicate property/binding rejection, nesting limits and disabled-binding precedence. Identity-file tests cover concurrent atomic no-overwrite creation, complete file contents, temp cleanup, private/public key consistency and pair-creation rollback. Keyserver tests cover proof/key/combined-byte quotas, concurrent distinct and idempotent same-object writes, persistence across restart, idempotent uploads, rate-window reset and HTTP 429 behavior, retention cleanup, invalid environment settings, and corrupted proof bytes at a hash-addressed path. Multi-resolver checks cover cross-server token collisions, incomplete lookup failure, candidate/token mismatch, false-hash candidate retrieval, full-hash/key retry, URL bounds/deduplication and CLI `verify-ref` against two servers. All five platform bundles build and pass ZIP content/target checks; the Linux bundle was extracted with preserved executable bits, its Tk UI started, and its adjacent CLI ran. The desktop smoke also proves scheduled Tk events run during background work and action buttons remain disabled until completion. The workflow includes Linux source/bundle UI smoke under Xvfb and defines native macOS/Windows bundle build and UI startup jobs. Proof and challenge parser fuzz sessions completed 19,151 and 57,863 executions; CI now runs each parser target for a bounded 10 seconds. Python/Go content and challenge vector equality, six-process replay, disabled/unknown trust distinction, challenge CLI issue/respond/verify/replay, and Docker keyserver build were checked. Locally this turn, the full Go race suite, vet, vector equality and `git diff --check` passed after the storage serialization change. Hosted workflow and native macOS/Windows UI runs remain unobserved. These checks do not establish independent cryptographic review, complete malicious resolver behavior, deployed service behavior, RF compatibility, or real PixelQSO interoperability.

## Acceptance boundaries

1. **M0:** The current TQSL API is excluded from the Ed25519 allowlist; this no longer blocks native development. Ed25519 schema and cross-language vectors exist. Broader parser-negative vectors and independent review remain before protocol claims mature.
2. **M1:** Current offline fixtures establish Ed25519 signing, content binding and explicit local trust. Manual key pins provide local authorization, not independent license verification.
3. **Later gates:** Real PixelQSO fixtures, durable challenge replay tests and malicious resolver tests supply separate evidence. Synthetic blobs cannot establish adapter or RF compatibility.
4. **Conditional gates:** TQSL policy permission and OPV remain separate research. No maintainers were contacted, LoTW services queried, services deployed or radio transmissions made. See the later local TQSL test note below.

## Latest local verification

On 2026-10-20, `go test ./...`, `go vet ./...`, Python/Go fixture comparison, `git diff --check`, Linux bundle inspection, Tk/Xvfb desktop smoke, and the Compose keyserver runtime smoke passed. The expanded desktop smoke exercises content signing and trusted verification, frame-2 PixelQSO signing and verification with its first card, challenge issue/respond/verify plus replay rejection, proof/key publish and fetch through the adjacent keyserver, action-button locking, and a close request while an action is running. `_run_blocking` uses a `threading.Event` while pumping Tk events on the UI thread, and the window defers close until the active action finishes; the source smoke exits cleanly. A fresh Linux bundle built from the current worktree also passed bundle inspection and the same workflow smoke. The Compose check verifies anonymous writes fail, authenticated proof/key uploads succeed, reference verification succeeds, retrieved bytes match, and objects remain available after restarting the container. It first exposed the non-root `/data` volume ownership defect; the image now seeds that mount point with UID/GID 65532 ownership. The first vector-check invocation used system Python and failed because `cbor2` was absent there. `scripts/check-vectors.sh` now honors `PYTHON`, then an active virtual environment, then the repository `.venv`, before falling back to `python3`; rerunning it with the existing `.venv` passed and all three generated fixture sets matched. This is local source/bundle/container evidence only; hosted CI, other operating-system runtime behavior, production HTTPS deployment and real RF interoperability remain unverified.

Additional resolver validation: `go test ./reference -count=1` and the full `go test ./...`, `go vet ./...`, `scripts/check-vectors.sh`, and `git diff --check` passed after adding tests that reject lookup/proof bodies one byte over their limits and confirm `Resolve` returns a context-cancellation error. The test server observes request cancellation through its request context. This closes those specific response-bounds and cancellation cases; it does not establish that a resolver's candidate list is complete.

Desktop publication now calls the CLI `publish` and `publish-key` commands, supplying the upload token only through the child process environment. This removes Python-side hashing and HTTP upload behavior. `make build` plus `xvfb-run -a python3 scripts/check-desktop-ui.py` passed through authenticated key/proof publication and exact-byte fetches against the adjacent local keyserver.

The desktop now has a direct Verify reference tab that invokes `verify-ref` across the configured resolver set. Source and extracted-bundle UI smokes accepted a published AR1 reference with its original content and trusted identity, then rejected the same reference after a content edit. `dist/arap-desktop-linux-amd64-local-verifyref.zip` passed the bundle-content checker. These checks used a disposable loopback keyserver; remote HTTPS deployment remains unverified.

The CLI's `fingerprint` and `publish-key` now accept SPKI public-key PEM or X.509 certificate PEM, matching the keyserver's existing certificate-capable API. A generated ECDSA test certificate was published and fetched byte-for-byte by its SPKI fingerprint; the same certificate is rejected by the Ed25519 proof-verification key loader. The desktop explains that certificate uploads are untrusted identity artifacts and that proof signatures use Ed25519. This enables certificate object transport only; trust-chain validation and non-Ed25519 proof signing remain unsupported.

After this change, `go test ./...`, `go vet ./...`, `scripts/check-vectors.sh`, and `git diff --check` passed. The Linux desktop bundle was rebuilt as `dist/arap-desktop-linux-amd64-local-certtransport.zip`; its content check and extracted-bundle end-to-end Tk smoke passed.

The Keys & Trust tab now exposes local binding disablement by callsign and full key fingerprint. Source and extracted Linux-bundle UI smokes disabled a previously trusted signer and then confirmed the matching hosted reference no longer returned an accepted policy result.

The follow-up `make race` and `make keyserver-smoke` also passed. The Compose run rejected anonymous writes, accepted authenticated proof/key uploads, resolved and locally verified the proof, fetched both objects, passed the healthcheck, and retained data across a container restart.

CGO-free CLI and keyserver cross-builds passed for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64 after the certificate transport changes. These are compile checks; native GUI behavior remains delegated to the platform workflow jobs.

After the local trust re-enable behavior was tightened, `go test ./...`, `go vet ./...`, and `git diff --check` passed. Re-enabling a disabled callsign/key binding now restores only the purpose explicitly selected by the user, rather than silently restoring all prior purposes. The rebuilt source UI smoke and freshly rebuilt `dist/arap-desktop-linux-amd64-local-certtransport.zip` smoke both confirmed disable → reject → re-enable for `content-signature` → accept, and confirmed the re-enabled binding contains only that selected purpose. The bundle content checker also passed. This verifies local-purpose authorization behavior; it does not establish certificate-chain or LoTW status validation.

The desktop PixelQSO smoke now also mutates frame-1 artwork while keeping the valid frame-2 card and proof, then checks that the UI surfaces the frame-pair fingerprint mismatch. Both `xvfb-run -a python3 scripts/check-desktop-ui.py` and the freshly rebuilt Linux bundle smoke passed this negative case; the bundle content checker, Python bytecode compilation and `git diff --check` passed as well. This covers the ARAP desktop's paired-card verification error path; hands-on use of the PixelQSO editor's separate sidecar dialog and live RF behavior remain unverified.

Key-storage behavior is now stated in the main and desktop READMEs and in the Keys & Trust UI: generated private keys are unencrypted PKCS#8 PEM, the app does not use an OS keychain, and users should protect the selected file and its backups. The desktop key-generation smoke asserts that its completion message explains this format and limitation. The freshly rebuilt `dist/arap-desktop-linux-amd64-local-keystorage.zip` passed bundle-content and extracted UI workflow checks; `make build`, source UI smoke, Python compilation and `git diff --check` also passed.

In the PixelQSO source checkout, three ARAP bridge UI tests were corrected to set `PIXELQSO_DATA_DIR` before creating `MainWindow`, because the app reloads its data path from that environment variable. This both fixed a fixture lookup failure and kept the tests isolated from real user data; `PYTHONPATH=. QT_QPA_PLATFORM=offscreen python3 -m pytest -q tests/test_arap_bridge.py` passed all 8 tests. An additional offscreen dialog run used the real ARAP CLI and a disposable loopback keyserver to sign and locally verify a frame-2 card, publish with bearer authentication, resolve the AR1 reference, compare the recovered proof bytes, and verify again. Native file-picker behavior and remote HTTPS deployment remain unverified.

Content verification now validates the COSE signature before applying `not_after`. The expired-proof regression confirms a correctly signed expired proof reports `cryptographic_signature=valid`, `callsign_identity=rejected`, and leaves content unchecked; changing only the signature bytes on that expired proof reports `invalid_signature`, not `expired`. `go test ./protocol ./...` passed after the change. The CDDL comment and implementation result table now state this ordering explicitly.

Challenge-response verification checks the COSE signature before applying freshness policy. Regression coverage checks valid-expired and corrupted-expired responses, then verifies the outstanding challenge still succeeds while fresh, proving neither rejected response consumed it. The independent Python verifier uses the same ordering. `go test ./challenge ./...`, `scripts/check-vectors.sh`, `go vet ./...`, and `git diff --check` passed after the change. CI now adds bounded 10-second fuzz runs for the content-proof, challenge-request, and public-key/certificate parsers; local one-second runs completed 51,094, 13,224, and 85,551 executions respectively. The challenge CDDL and operator guide document the signature/freshness result ordering.

`challenge issue` now commits the pending SQLite record before atomically publishing the request file; a failed file publication cancels the still-pending record. CLI regression cases cover pre-existing output, forced store failure, output publication failure and cancellation of pending versus consumed rows.

Public-key parsing is centralized in `identity.ParsePublicKey` for CLI, keyserver and resolver use. It accepts a single SPKI DER value, a single `PUBLIC KEY` PEM block, or a single X.509 certificate block; tests reject leading prose, multiple blocks and trailing non-whitespace while retaining valid DER and PEM inputs. `go test ./identity ./keyserver ./reference ./...` passed after consolidation.

The keyserver `/healthz` check now requires a responsive SQLite index and usable proof/key directories, including temporary-file create/remove probes. Tests cover a closed database and a missing object directory. The isolated `make keyserver-smoke` Compose run passed health checks, authenticated publishing, local reference verification, object retrieval and named-volume persistence after container restart.

The keyserver executable now rejects missing, short, malformed and misplaced-padding upload tokens before opening the service. Tests cover URL-safe and standard Base64-style token character sets plus invalid inputs. The documented `openssl rand -hex 32` credential passed the isolated Compose publication, verification and restart smoke. `go test ./cmd/arap-keyserver ./...`, `go vet ./...`, and `git diff --check` passed.

The independent Python content generator now applies the same signature-before-expiry ordering. Its regenerated manifest adds a tampered-expiry negative decision and records that a valid expired proof's signature verifies while an unauthenticated expiry edit does not. `scripts/check-vectors.sh` confirms all three Python-generated fixture sets match; the content COSE bytes remain unchanged.

`SignContent` and `SignPayload` now enforce the 65,536-byte limit on the complete encoded COSE envelope, matching `VerifyContent` and `VerifyPayload`. A regression test supplies a canonical payload within the input bound whose envelope would exceed the limit and confirms signing rejects it. `go test ./protocol ./challenge ./...` passed, and both CDDL profiles now state the encoded-envelope limit.

The exported signer abstraction now rejects providers whose algorithm is not Ed25519, whose public key is not a 32-byte Ed25519 key, or whose returned signature has the wrong length or fails local Ed25519 verification. Regression cases exercise both content and generic payload signing with incorrect providers; this keeps the extensible Go interface from producing proofs outside the v1 algorithm profile.

Upload-token strength is now enforced by the reusable `keyserver.New` / `NewWithOptions` constructors through `keyserver.ValidateUploadToken`, as well as by the executable before startup. This closes the weaker embedded-library path. Focused server tests reject empty, short, and malformed tokens; authenticated key/proof upload tests now use a 256-bit token. `go test ./keyserver ./cmd/arap-keyserver ./cmd/arap` passed after the change.

After that enforcement change, the first desktop smoke caught its disposable keyserver fixture still using a short token. The fixture now uses a valid long Bearer token. `make build`, the source Tk workflow smoke, and the extracted `dist/arap-desktop-linux-amd64-dev.zip` workflow smoke passed; both exercise signing, verification, challenge replay rejection, authenticated key/proof transfer, and reference policy changes. The Linux bundle content/target checker passed, and `make keyserver-smoke` passed anonymous-write rejection, authenticated publication, local verification, health and persistence across container restart. Full `go test ./...`, `go vet ./...`, and `git diff --check` passed.

The CBOR decoder's array-element bound now matches the documented 16-element parser limit (it previously allowed 32). A boundary test accepts 16 and rejects 17; `go test ./protocol` passed.

Trust-store loading and saving validate normalized supported callsigns, canonical 32-byte lowercase fingerprints, nonempty purpose sets for enabled bindings, and the supported `content-signature` / `challenge-response` purposes. Duplicate purposes and malformed bindings fail closed, preventing an unknown future purpose from becoming authorized by an old trust file. The challenge request purpose (`station-auth`) remains distinct from the signed response proof purpose (`challenge-response`).

The first viewport audit found that long desktop forms were clipped at the supported 840×620 minimum size. All tabs now use a shared vertical scroll container, with mouse-wheel support; the Challenge tab uses the same container instead of a separate implementation. The source smoke verifies the Keys & Trust, PixelQSO cards, Keyserver and Challenge forms can scroll fully and that wheel input moves the Keyserver form. The source smoke, Linux bundle content check, and extracted-bundle workflow smoke passed at 840×620.

The PixelQSO JSON canonicalizer now has seeded fuzz coverage in CI alongside the proof, challenge-request and public-key parsers. Its 3-second local fuzz run completed 192,487 executions without a crash; `go test ./...`, `go vet ./...`, and `git diff --check` passed. This exercises malformed card documents at the parser boundary, while real PixelQSO card fixtures and editor/native workflow validation remain open.

Challenge response verification now has its own seeded fuzz target in CI, exercising the COSE envelope, signed payload schema, request binding and in-memory single-use transition together. The 3-second local run completed 68,194 executions without a crash. Go conformance tests reject untagged COSE, unprotected headers, a noncanonical outer array and a correctly signed response with an unknown payload field. The independent Python vector records sixteen semantic and structural rejections. `scripts/check-vectors.sh`, `go test ./...`, `go vet ./...`, and `git diff --check` passed; this supplements request-decoder fuzzing and does not replace independent security review.

Keyserver GET paths now confirm the object is indexed before opening it and cap reads at the protocol proof/key limits, including when stored files are altered after upload. A regression replaces an indexed proof with a file one byte over the limit and confirms GET returns a storage error without loading the whole file. `go test ./keyserver`, `go test ./...`, `go vet ./...`, and `git diff --check` passed.

Keyserver expiration cleanup now shares the object publication lock with writes. A concurrent regression repeatedly races pruning an expired proof with publishing the same hash and confirms the replacement remains indexed and readable. `go test -race ./keyserver`, `go test ./...`, `go vet ./...`, and `git diff --check` passed.

After the bounded-read and retention-lock changes, `make keyserver-smoke` passed in an isolated Compose project: anonymous uploads were rejected; authenticated proof/key publication, lookup, local verification, fetch, health status, and named-volume persistence across container restart all succeeded. The disposable project and volume were removed by the smoke script.

The `publish-key` CLI now parses and fingerprints the same bounded byte slice that it uploads, avoiding a second file read that could observe different contents. The certificate/SPKI publish-and-fetch integration test and full Go suite passed, along with `go vet ./...` and `git diff --check`.

Resolver reference parsing now rejects input longer than 256 bytes before normalization. CI fuzzes this parser and the bounded lookup-JSON parser. Two-second local runs completed 32,574 and 24,815 executions without crashes; reference tests, the full Go suite, `go vet ./...`, and `git diff --check` passed.

After adding the resolver parser bounds and fuzz targets, `make race` passed for every Go package; `git diff --check` also passed.

The Linux desktop distribution was rebuilt after the CLI and resolver changes. Source and extracted-bundle Tk workflow smokes passed, the bundle content checker confirmed Linux amd64 metadata and executables, Python-generated vectors matched checked-in fixtures, and `git diff --check` passed.

Unix private-key loading now rejects files with group or other permission bits and reports the `chmod 600` remediation. A focused regression verifies rejection at 0644 and successful loading at 0600; Windows skips the POSIX-mode assertion. `go test ./identity`, `go test ./...`, `go vet ./...`, and `git diff --check` passed.

After the private-key loading change, both CLI and keyserver still build with CGO disabled for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64. These are cross-compilation checks; native desktop startup and target operating-system integration remain governed by the platform workflow jobs.

The initial encrypted-key implementation used an ARAP-specific scrypt/AES-GCM envelope. The CLI read secrets from a no-echo terminal prompt or standard input, and the Tk client used a masked prompt and piped secrets to the child process. Its end-to-end smoke covered content signing, PixelQSO signing, and challenge response. That writer was superseded by the age-format writer recorded below; its decoder was then removed because no project key files used that development-only format.

Rebuilt Linux amd64/arm64, macOS amd64/arm64 and Windows amd64 desktop bundles with the encrypted-key implementation; all five passed the bundle-content checker. The extracted Linux bundle passed the full Tk workflow smoke. Go 1.23.12 ran `go test ./...` and `go vet ./...` successfully, matching the then-minimum CI toolchain.

After the encrypted-key integration, `make race`, `go vet ./...`, Python/Go vector comparison, and `git diff --check` passed again.

The new-key writer now uses the standard armored age format and age's scrypt recipient (work factor 15). The loader supports age files and legacy unencrypted PKCS#8. Regression cases reject a wrong passphrase, altered armored data and trailing data. The age dependency is pinned at v1.2.1 to preserve the Go 1.23 minimum; focused tests passed under Go 1.23.12.

After switching the writer to age, `go test ./...`, `go vet ./...`, `make race`, Python/Go vectors, Python compilation, and source plus extracted-bundle desktop workflow smokes passed. Linux amd64/arm64, macOS amd64/arm64 and Windows amd64 bundles rebuilt and passed their content checks. Go 1.23.12 passed the full suite; the app now uses the standard age encryption format instead of maintaining an ARAP-specific one.

Independent file-format interoperability was checked in both directions with the age v1.2.1 command-line tool. Age decrypted a key produced by `arap keygen`, and OpenSSL parsed the recovered DER as a valid private key. Age's default work-factor-18 passphrase encryption was then loaded by ARAP and used to create a content proof. This supplements the ARAP age-library round trip with a separate CLI implementation path.

The short-lived ARAP-specific encrypted-key decoder was removed after confirming the repository contains no keys in that format; unencrypted PKCS#8 compatibility remains. Following removal, Go 1.23.12 full tests/vet, `make race`, Go/Python vectors, source and extracted Linux desktop workflow smokes, and all five rebuilt bundle-content checks passed.

The age loader accepts work factors through 18 while ARAP-generated files stay at 15. Age CLI default-factor-18 encryption was loaded by ARAP and used for content signing. After the cap change, Go 1.23.12 tests/vet, `make race`, source UI smoke, all five rebuilt bundle checks, and the extracted Linux bundle workflow smoke passed.

Keyserver Compose now keeps the plain-HTTP container port off the host by default. An optional `compose.haproxy.yaml` publishes it on loopback for a same-host TLS proxy; operators may set a private host address for a remote proxy and must restrict it with the host firewall. Both Compose configurations parse, and `make keyserver-smoke` now exercises the overlay on a dynamic loopback port along with upload authentication, local reference verification and volume persistence. The smoke also now supplies test-only passphrases through stdin for encrypted-key generation and signing. No live proxy or host firewall was changed.

The first smoke invocation after encrypted key generation exposed that its CLI fixture still expected an interactive unencrypted key; the fixture now passes a test-only passphrase through stdin to keygen and signing. The rerun passed the full isolated Compose workflow, including the HAProxy overlay's loopback publication, and cleaned its project and volume.

Fresh validation on 2026-10-20 with Go 1.23.12 passed `make test`, `make vet`, `make race`, Python/Go vector comparison, the Tk workflow smoke, and the isolated Compose keyserver smoke. The PixelQSO editor bridge suite passed all 8 tests. Additional five-second fuzz runs exercised the content-proof parser (319,050 executions) and challenge-response verifier (93,574 executions) without crashes. `git diff --check` passed. These checks validate the local prototype; native macOS/Windows GUI execution, a deployed HTTPS endpoint, independent protocol review, and ARRL/TQSL identity policy remain open.

Content verification now returns parsed claims only after the COSE signature verifies. A regression confirms valid proofs expose signed claims, corrupted signatures omit them, and proofs rejected before signature checking because caller expectations do not match also omit them. This prevents CLI/API consumers from mistaking attacker-controlled payload fields for authenticated identity metadata. `go test ./protocol ./cmd/arap`, the full Go suite, `go vet ./...`, the independent Go/Python vectors and `git diff --check` passed after the change.

Rebuilt current-worktree desktop bundles for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64; every archive passed its target/contents checker. The extracted Linux amd64 bundle passed the complete Tk workflow smoke, including content and PixelQSO signing/verification, frame-pair mismatch handling, challenge replay rejection, key/proof publication, fetch and hosted-reference verification. These are cross-target build and Linux runtime results, not native macOS or Windows GUI runtime evidence.

The keyserver's idempotent immutable-object check now bounds reads of an existing path to the incoming object's size plus one byte and rejects non-regular or differently sized paths before comparison. This avoids loading an unexpectedly large or special existing file into memory during an authenticated duplicate PUT. A counting-reader regression verifies the comparison stops at the bound; keyserver and executable tests, the full Go suite, `go test -race ./keyserver`, and `go vet ./...` passed.

After this keyserver change, all five target bundles were rebuilt and passed archive checks; the extracted Linux amd64 bundle passed the full desktop workflow smoke again. The isolated Compose keyserver smoke also passed anonymous-write rejection, authenticated proof/key publication, resolution, local verification, health checks and named-volume persistence across restart.

Dependency scanning found reachable standard-library vulnerabilities when using Go 1.26.8. The project minimum, CI compatibility job, and Docker builder now use Go 1.26.10, whose release includes the fixes for affected `net/http`, `crypto/tls`, `net/textproto`, and `os` code; CI also checks current stable Go. `golang.org/x/crypto` and `x/term` were upgraded to v0.58.0 and v0.47.0 (with `x/sys` v0.49.0). Under Go 1.26.10, the full Go suite, vet, race suite, and Python/Go vectors passed. A fresh `govulncheck` source scan found no reachable vulnerable symbols; it reports the module-level `GO-2026-5932` advisory because the required `x/crypto` module contains the unmaintained `openpgp` package, which ARAP does not import. The published Go release history records the standard-library security fixes in Go 1.26.9 and the later `crypto/x509` fix in 1.26.10.

CI now runs the same pinned `govulncheck` v1.9.0 scan under Go 1.26.10. Its current output is “No vulnerabilities found” for reachable symbols; it notes one uncalled module-level advisory for `x/crypto/openpgp`.

The current stable Go 1.27.3 also passed `make test` and `make vet`, confirming the updated dependencies and protocol/server code work on both the Go 1.26.10 minimum and current stable toolchain.

## LoTW enrollment investigation

On 2026-10-20, an initial local TQSL smoke test used the configured station credential to sign one generated synthetic ADIF contact. No `.tq8` was uploaded, but TQSL warned that it may treat the contact as already uploaded on a later submission. Do not upload that generated file. This was not ARAP or LoTW authentication evidence. Future synthetic ADIF signing must use TQSL 2.8.3 or later with `-z`, which signs without upload tracking. The separate fresh-challenge enrollment protocol has since been exercised with synthetic TQSL certificates; real station-certificate and live status validation remain deferred to final testing.

The installed TQSL 2.8.7-rc5 completed a synthetic ADIF `-z` test-sign run and explicitly reported that it had not recorded the QSO; no upload was made. The `lotwenroll` verifier passes fake-CA and synthetic TQSL certificate round trips, dual-signature verification and replay rejection using generated RSA and Ed25519 keys. Its SQLite store atomically consumes a nonce and records the binding, survives reopen, rejects a mismatched key fingerprint, and supports disablement. Version 1 enrollment remains challenge-response-only; version 2 carries explicitly allowed purposes and can authorize content when the verifier opts in. The CLI content path checks that purpose along with certificate expiry and status age. RSA/SHA-1 is accepted only for the short-lived TQSL enrollment assertion, under explicit policy acknowledgement; ARAP content/challenge signatures remain Ed25519. The pinned CDDL 0.10.7 validator compiles the version 1 and version 2 enrollment challenges plus the response schema; both challenge vectors and all existing vectors validate. Real station-certificate and live status behavior remain final validation steps.

After that validation snapshot, `arap enrollment issue` and
`arap enrollment verify-response` were added. The latter queries TQSL's public
LoTW certificate-status endpoint using TLS, cache-revalidation headers, and
the response's `Date`/`Age` for evidence time. Automated synthetic tests cover
the status client and TQSL signing adapter. The CLI discovers TQSL's local
self-signed root bundle by default. Root and status policy follows what TQSL
and ARRL accept; real certificate-chain/status validation remains a final live
test. The TQSL RSA/SHA-1 signature is accepted only for fresh enrollment
authentication evidence, never for ARAP content or challenge signatures.

The Keys & Trust tab now exposes enrollment challenge issue and response
verification, including a default-off legacy-signature checkbox and a second
confirmation before verification. The updated Go packages compile with
`go build ./...`, and the desktop script passes Python bytecode compilation;
the updated controls and TQSL-root discovery have not yet been exercised in Tk
or through a response flow.

Follow-up verification passed `go test ./...`, `go test -race ./lotwenroll`, `go vet ./...`, Python/shell syntax checks, the full Tk/Xvfb workflow smoke, `make cddl`, and the Linux amd64 package content check. The package contains the enrollment schemas; the CLI can list and disable enrollment bindings, and challenge verification can use the enrollment database subject to the 24-hour default status-evidence age. No real LoTW credentials or station-certificate signatures were used.

The TQSL responder implementation adds `arap enrollment respond`, a
`TQSLHelperSigner`, and the optional `tqsl-helper/arap-tqsl-sign` native
TQSLLIB bridge. The bridge selects one current issued certificate for the
challenge callsign (or the selected decimal serial), signs the exact challenge
bytes, returns only the signature and public certificate chain, and calls
`tqsl_endSigning` on cleanup. The CLI checks the ARAP key fingerprint before
starting TQSL and requires `--allow-legacy-rsa-sha1`; the desktop has a
default-off control and confirmation. No QSO is created or submitted.

On 2026-10-20, `go build ./...`, `go test ./...`, Python bytecode compilation,
shell syntax validation, and a native helper build against the local TrustedQSL
2.8.7-rc5 source all passed. The tests cover existing enrollment behavior but
do not exercise the new native signing operation. No TQSL signature was made
and no station private-key store was read. The helper has not been run against
a synthetic TQSL certificate store or the real certificate; ARRL chain and
status policy, certificate permissions, and live desktop workflow remain
unverified. The helper is source-built separately and is not in platform
bundles.

## Key endorsement implementation update

The `endorsement` package now issues and verifies an experimental, purpose-scoped
Ed25519 delegation chain against caller-supplied trust anchors. It rejects
untrusted or disabled roots, disabled subjects, invalid signatures/envelopes,
expiry, purpose escalation, excessive delegation depth, cycles and a mismatched
final subject. A deterministic Python-generated two-link vector is checked by
Go; the pinned CDDL validator checks both chain links. `scripts/check-vectors.sh`,
`make cddl`, and `go test ./...` passed after this addition. CLI integration,
verification by a separately implemented consumer, and broader adversarial
endorsement coverage remain open.

## Coordinated mutual challenge implementation update

The challenge package now creates inverse requests for the same application
session and exposes `VerifyMutualPair`, which checks both responses, identities,
purpose, request window, nonces and the caller's expected session binding before
consuming either request. The SQLite `ConsumePair` operation commits or rolls
back both state changes in one transaction. `go test -race ./challenge` covers
partial rollback, concurrent single-winner consumption, invalid-response
non-consumption, cross-session rejection and replay rejection. The public
[`examples/mutual-auth`](../examples/mutual-auth/main.go) flow ran successfully;
`go test ./...`, `go vet ./...`, and `git diff --check` passed. This now includes
the CLI flow: it issues both requests, produces each side's response, rejects a
wrong session without consuming either challenge, accepts the correct pair, and
rejects replay. A separate third-party application has not yet consumed the
interface.

## LoTW policy and status-client check (2026-10-20)

Reviewed ARRL's current developer, Callsign Certificate, certificate-validity,
and Trusted Partner pages. They describe the certificate's LoTW role as signing
QSO/log submissions and state that issuing a replacement certificate
invalidates the prior certificate. The reviewed public pages do not establish
that ARAP challenge signing is an approved LoTW login or authentication use, so
that policy question remains open and the feature remains explicitly
experimental. The local TQSLLIB design does not transfer the station private
key to an ARAP server; any hosted key custody would require separate review.
The findings and boundaries are recorded in
[`LOTW-BINDING-DESIGN.md`](LOTW-BINDING-DESIGN.md).

Added isolated status-client tests for serial binding, cache revalidation
headers, `Date`/`Age` observation time, revoked, superseded, expired, bad-serial,
unknown, and future-dated responses. `go test ./lotwenroll` passed. These tests
do not contact LoTW or validate a real station certificate; live certificate
status and permitted-use confirmation remain release gates.

## TQSL certificate selection and application boundary (2026-10-20)

Added a read-only `enrollment certificates` operation to the CLI, backed by
TQSLLIB's current-certificate selection for the callsign encoded in a validated
enrollment challenge. It returns matching public serial metadata and never asks
for a certificate password. The Python `ArapClient` exposes the same operation,
and the desktop enrollment screen can list matching certificates before the
user selects a serial for signing. A Python integration test validates the
request-bound callsign and wrapper result using a fake helper; the pinned native
enrollment demo validates actual discovery of its synthetic serial `424242`
before helper signing. The end-to-end demo passed and still labels its accepted
status as synthetic-only. `go test ./...`, all 11 Python consumer tests, the
installed-wheel consumer check, and the Tk desktop workflow smoke passed. The
Tk smoke also exposed and fixed unsupported `wraplength` options on two
`ttk.Checkbutton` widgets. No live LoTW status query or real certificate was
used; certificate policy, permitted use, independent application review, and
hosted CI remain release gates.

## Linux amd64 enrollment bundle (2026-10-20)

`package-desktop.sh linux-amd64` builds the native helper against pinned
TrustedQSL 2.8.7 source revision `1916fc14a8cfc7f287742ae5a34aa986353d9df7`,
places `arap-tqsl-sign`, `libtqsllib.so`, and the matching `config.xml` resource
beside the ARAP executables, and includes the TQSLLIB redistribution license.
The CLI passes the extracted resource path to TQSLLIB while the user's
certificate data directory remains separate. The helper's `$ORIGIN` runtime
search path was checked after extraction; the archive checker starts the
extracted helper without reading station certificate data. The extracted
helper then completed the native synthetic enrollment and signing demo against
the isolated generated certificate, including serial discovery, challenge
signing, verification, content signing, and authentication. The CI bundle job
now installs build prerequisites, checks out the same pinned source, validates
the archive and runs this extracted-helper demo. The Linux amd64 artifact was
built and validated locally; hosted CI has not yet run on a release commit.
The native matrix now builds Linux amd64/arm64, macOS amd64/arm64 and Windows
amd64 enrollment bundles and runs their extracted helper flows on matching
runners. Hosted results remain pending.

## Version reporting (2026-10-20)

Added shared linker-overridable build metadata. `arap version --json` and
`arap-keyserver version --json` report executable name, release version, and
source commit; normal builds report `dev`/`unknown`. Desktop About reads the
bundle manifest and displays the same release version and commit plus the
TQSL/TQSLLIB version. Packaging embeds the version and commit into both
executables and records them in `BUILD-MANIFEST.txt`. The archive checker and
Tk smoke test compare executable metadata and About text against the manifest;
the native macOS/Windows CI smoke will perform the same runtime comparison.
Local `go test ./...`, both version commands, package archive checks, packaged
helper demo, Tk workflow smoke, and Python bytecode checks passed. Hosted native
macOS/Windows results remain pending.

## Tester diagnostics and bundled developer guides (2026-10-20)

The desktop now has a non-modal Setup diagnostics window with copy support. It
reports Python/Tk, ARAP CLI version, helper execution and adjacent TQSLLIB
resources, TQSL command version, and the standard TQSL user data directory.
Linux/macOS and Windows launchers now explain missing Python/Tk, and enrollment
errors give recovery hints for a missing helper or likely wrong TQSL password,
serial, or certificate state. The diagnostic report can contain personal file
paths; the bug template tells testers to redact them before sharing. On this
machine, diagnostics found TQSL 2.8.7-rc5; only that TQSL CLI with pinned
TQSLLIB 2.8.7 has been checked, so other versions remain unqualified.

Added `FIRST-RUN.md` and `BUG_REPORT_TEMPLATE.md` to desktop archives. Archives
now include the application capability map, machine API documentation, identity
lifecycle guide, versioned schema files at their documented paths, Python
wrapper and guide, and public Go content/mutual-auth examples. Packaging now
recurses through these subdirectories. The archive checker verifies required
API artifacts and every relative Markdown link. Local Go tests, Python
bytecode checks, Tk desktop smoke, Linux bundle check, extracted packaged TQSL
synthetic enrollment demo, and `git diff --check` passed.

## Desktop workflow navigation (2026-10-20)

Added a first-position “Start here” page with direct navigation to identity and
trust setup, content signing, content verification, peer challenge
authentication, and PixelQSO card signing. It explains that ARAP content proofs
and peer authentication are separate, and that applications own transport and
trust decisions. The challenge form now labels requester/verifier issuance and
single-use verification separately from responder signing. The enrollment note
calls out audience, selected ARAP key fingerprint, and certificate serial
selection. The Tk smoke asserts that the workflow page is first, its buttons
navigate to the right tabs, and both peer roles appear in the challenge form.

## Enrollment status lifecycle controls (2026-10-20)

The desktop enrollment list now summarizes purpose, key fingerprint, leaf
certificate fingerprint/issuer/expiry, status value/source, status observation
time and computed age, plus disablement. Added an explicit refresh form that
uses the retained accepted response and the existing optional roots and
maximum-age settings; it confirms before contacting LoTW and invokes the
supported `enrollment refresh` CLI operation. The operation revalidates the
same chain and key and cannot re-enable a disabled binding. The UI smoke tests
expiry formatting, evidence age, disablement display, and refresh argument
routing with a stubbed CLI, without making a network request. Live refresh with
a real certificate remains open.

## Multi-platform native TQSL helper packaging (2026-10-22)

The packaging path now accepts a helper built on the target OS, bundles
TQSLLIB's configuration and redistribution notice, and includes native runtime
libraries. The macOS path copies non-system dylibs and rewrites their load paths
to use the extracted bundle directory. Windows and macOS CI use static TQSLLIB;
Windows uses vcpkg static dependencies, while macOS bundles Homebrew OpenSSL
dylibs. The native CI matrix now covers Linux amd64/arm64, macOS Intel/arm64,
and Windows amd64. Each target archive is checked after extraction, the
synthetic enrollment flow uses the extracted helper, and the desktop UI/CLI is
launched on the native runner.

Local evidence on Linux amd64: make test, make vectors, make cddl, make vet,
and make enrollment-demo passed. A package assembled using the new
external-helper path passed bundle checking, extracted-helper synthetic
enrollment/signing/authentication, and the Xvfb desktop workflow smoke. A
static-TQSLLIB/dynamic-OpenSSL helper also built and started successfully.
The macOS dylib-copy/load-path test passes with mocked `otool` and
`install_name_tool` calls.
Static OpenSSL linking on this Debian host failed because its static libcrypto
requires libjitterentropy.a, which is not installed; the macOS job therefore
bundles OpenSSL's dynamic libraries. Workflow YAML, Python syntax, Bash syntax,
and git diff --check passed. Native macOS, Windows, Linux arm64 builds and
hosted CI have not run yet.
