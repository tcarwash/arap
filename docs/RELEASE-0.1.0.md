# ARAP 0.1.0 beta release plan

Planning baseline: 2026-10-20. This plan records proposed release work; unchecked
items are not completed validation. First public prerelease: `v0.1.0-beta.1`.
Use later beta tags for feedback fixes and reserve `v0.1.0` for graduation.

## Beta scope

Deliver the complete signing, identity and challenge feature set as a reusable
Go library with a documented machine interface for other languages. The CLI,
desktop and example applications must use those public interfaces. A desktop
demo alone does not meet the beta gate. File exchange and application-owned
transports must both work; an ARAP-hosted authentication service is not required.

The beta is not feature-complete while any application-facing signing,
authentication, or challenge item below is unchecked. In particular, a consumer
must be able to provide its own transport, durable challenge store, identity
trust policy, and key lifecycle without depending on desktop code, private
database edits, or parsing human-readable CLI output. The reference Go API and
versioned Python machine wrapper are the supported integration boundaries.

Include the existing offline content and PixelQSO proof workflows, local trust,
and optional Compose keyserver. Enrollment currently authorizes only
`challenge-response`; completing explicit purpose-scoped identity policy for
content verification is part of this release. Describe enrollment as
proof of control of a Callsign Certificate with separately evaluated certificate
status. Do not imply that LoTW accepted an ARAP login or assertion.

Multi-platform enrollment is a primary beta goal. The target matrix is the
existing desktop bundle matrix: Linux amd64/arm64, macOS amd64/arm64, and
Windows amd64. Package the native TQSL helper and its runtime resources for
each target and validate the enrollment workflow on that platform before
calling its bundle supported. A target without enrollment remains a clearly
labeled preview, not a supported multi-platform release.

Key endorsements, identity lifecycle operations and application integration are
required beta features. Defer the OPV-specific adapter, OS keychain integration,
a public identity directory and new RF transports. Applications must be able to
carry ARAP messages over their own transport without needing those additions.

## 0. Complete the application-facing feature contract

This milestone precedes release packaging. Existing implementations should be
reused, with gaps filled and public interfaces documented before claiming API
completeness.

- [x] Publish an initial capability matrix mapping every operation to its Go API, CLI
  command, request/response schema, example and conformance checks.
- [x] Complete content signing and verification for arbitrary bytes and the
  PixelQSO adapter, with detached proofs, expiry, context and purpose checks,
  and separate signature, integrity and identity results. Exported PixelQSO
  `SignJSON` and `VerifyJSON` compose schema validation, frame-link checking,
  canonicalization and core proof operations; the CLI uses these same adapter
  methods. Independent consumer validation remains a release check.
- [x] Complete the versioned identity-enrollment API and purpose-scoped
  authorization. Define how
  an accepted certificate binding authorizes content as well as authentication;
  require explicit verifier policy and version any changed enrollment claims.
  Never silently widen existing challenge-only records or infer historical
  certificate validity from a content proof's asserted signing time. Version 1
  remains challenge-response-only; version 2 binds selected purposes and requires
  explicit verification policy. Live certificate policy review remains a gate.
- [x] Implement an initial key-endorsement purpose: Go issuance, verification,
  canonical schema and proof-byte import/export with explicit issuer trust. Enforce expiry,
  allowed purposes, delegation depth, cycle rejection and disablement. Endorsement
  must not silently convey LoTW authority or confer trust on an unknown issuer.
  CLI issue, chain pack/append and explicit-root verify commands are implemented
  with purpose/depth checks and optional local disablement. Portable identity
  lifecycle and external implementation verification remain release requirements.
- [x] Complete one-way and mutual challenge authentication, binding each exchange
  to its audience, application purpose, session and intended peer. The Go API
  now creates inverse challenges and verifies both responses with atomic pair
  consumption and an expected session binding. Mutual CLI support is implemented;
  checks from an independent consumer remain. Never treat two unrelated responses
  as a session.
- [x] Expose challenge issue/respond/verify, cancellation, expiry and atomic
  consumption through caller-owned storage interfaces, with the SQLite adapter
  retained. `challenge.LifecycleStore`, `IssueRequest`, and `CancelRequest` now
  define persist-before-publish, cleanup and publish-failure behavior;
  `challenge.Store` retains atomic consumption and expiry checks. Concurrency,
  restart and failure behavior still require independent consumer validation.
- [x] Expose enrollment status refresh, expiry and disablement through Go, CLI and
  Python interfaces. Refresh revalidates the original certificate chain and must
  not revive disabled or expired bindings. Keep network access application-controlled.
- [x] Define and document key replacement/migration using a new fresh enrollment;
  do not allow status refresh to change the key or certificate binding.
- [x] Define portable identity evidence and endorsement import/export so another
  application can independently evaluate evidence under its own trust policy.
  Importing a previous verifier's local acceptance must not itself establish
  trust; specify freshness and audience restrictions and when re-enrollment is
  required. Export public evidence only. The binding migration procedure and
  audience/freshness rules are in [`IDENTITY-LIFECYCLE.md`](IDENTITY-LIFECYCLE.md);
  enrollment response bytes carry public evidence, while local acceptance is
  intentionally not exported.
- [x] Finish proof/key publication and resolution interfaces, preserving local
  verification and explicit unknown, ambiguous and unavailable outcomes.
- [x] Stabilize the initial CLI machine error protocol and Python resolver
  methods: versioned error envelopes, stable resolver codes, binary file
  framing, bounded inputs and wrapper timeouts. Passphrases stay out of
  arguments, logs and normal result output.
- [x] Supply a Python wrapper and machine-interface specification for content,
  PixelQSO, challenge and endorsement operations, alongside runnable Go samples.
  Do not require a C ABI or background service for this beta; add either only
  when a concrete consumer requires it.
- [x] Document application responsibilities: identity trust, session ownership,
  authorization after authentication, storage, status freshness and transport.
  Core proof verification must not implicitly fetch network data or mutate trust.
- [x] Expose experimental LoTW enrollment challenge/response, verification and
  local list/disable operations through the Python wrapper. Existing enrollment
  TQSL-supported RSA/SHA-1 enrollment signatures are accepted only for the
  short-lived enrollment assertion; ARAP content and challenge signatures
  remain Ed25519.
- [ ] Exercise those wrapper operations with a real station certificate and
  live certificate-status check at the final live-validation stage; verify
  refresh/expiry and disablement from an independently maintained consumer.

Acceptance: two independent sample applications can exchange signed content,
enroll or evaluate identity evidence, perform one-way and mutual authentication,
evaluate an endorsement and handle refresh/expiry/disablement through supported
interfaces. The examples must not import private internals, edit ARAP databases
directly or scrape human-readable output. Provide runnable examples and negative
vectors for every feature, including cross-purpose and cross-session rejection.

## Current evidence

The current-state API map is in [API-CAPABILITIES.md](API-CAPABILITIES.md).
The Go packages and versioned Python wrapper expose signing, identity,
enrollment, one-way and mutual challenge, endorsement, and reference
operations. Local integration checks exercise these boundaries. Release
acceptance still requires independent application validation and the live
certificate/policy gates below.

- CLI, desktop, content proofs, challenge-response, local trust, keyserver,
  PixelQSO integration, schema checks, and protocol vectors exist.
- A generated certificate chain in an isolated TQSL store passed CLI enrollment
  issuance and native helper signing, followed by library verification with
  synthetic good-status evidence. This exposed and led to a fix for certificate
  chain retrieval occurring before helper signing.
- Enrollment version 2 now carries a verifier-selected purpose list. Version 1
  and previously stored version 1 bindings remain challenge-response-only.
  Verifier acceptance checks its explicit allowed-purpose set; content
  verification can use only a matching fresh, unexpired enrolled binding.
  Python-generated challenge vectors, CDDL validation and Go/CLI tests cover
  version compatibility and cross-purpose rejection.
- An initial public `endorsement` Go package now issues and verifies offline,
  purpose-scoped Ed25519 delegation chains against caller-supplied roots. It
  limits validity and depth, rejects purpose/depth escalation and key cycles,
  supports caller-supplied disablement, and has a deterministic Python-generated
  two-link vector. Chains have a bounded canonical-CBOR transport container,
  independently generated and checked against a separate schema. The CLI and
  Python wrapper now cover issue, assembly and explicit-root verification; review
  by an independent implementation remains.
- The Go challenge API can create inverse requests for one session and verify
  both trusted responses with an atomic SQLite pair-consumption operation. A
  runnable public-package example, `mutual-issue`/`mutual-verify` CLI commands,
  and race-tested replay/rollback behavior exist. The Python wrapper now exercises
  one-way and mutual flows, including cancellation of pending requests, retention
  after consumption, replay and atomic pair consumption, against the built CLI;
  a separately maintained consumer review remains.
- A versioned Python wrapper API now covers content, PixelQSO, one-way and mutual
  challenge, endorsement, and experimental LoTW enrollment operations. Its
  integration tests build the local CLI and verify byte proof exchange, policy
  acceptance, session binding and replay rejection. Live TQSL signing and current
  certificate-status verification remain untested through the wrapper.
- PixelQSO now has exported Go `SignJSON` and `VerifyJSON` operations that own
  card validation, frame linking, canonicalization, proof handling and trust
  result plumbing. The CLI calls these adapter methods. One-way challenge
  issuance now goes through `IssueRequest`, and Go, CLI and Python surfaces
  expose cancellation for pending requests after transport publication fails.
- `IDENTITY-LIFECYCLE.md` defines fresh-enrollment key replacement, explicit
  disablement, portable public evidence, and the audience/freshness constraints
  that prevent importing another application's local acceptance decision.
- A repository `make enrollment-demo` now generates a fake CA and callsign
  certificate, imports them into a temporary TQSL directory, invokes the native
  helper, injects synthetic status only in a demo verifier, and covers
  enrollment, content signing, challenge authentication, replay, and disabled
  binding flows. The full target passed locally on 2026-10-20 against the pinned
  TrustedQSL source and reported each expected rejection. The hosted Linux CI
  run remains pending.
- The native demo enumerates matching TQSL certificates from its isolated
  fixture store before signing. The CLI and Python `ArapClient` expose this
  read-only operation, and the desktop offers “List matching certificates” to
  help select a serial when several certificates match.
- `make signing-demo` combines the offline arbitrary-content walkthrough with a
  PixelQSO frame-pair proof generated from the repository fixture; both paths
  passed locally on 2026-10-20.
- Existing CI defines platform builds, native desktop jobs, protocol checks,
  vulnerability scanning, and container smoke checks. Successful hosted runs for
  the eventual release commit still need to be observed.
- Native enrollment-bundle CI now targets Linux amd64/arm64, macOS Intel/arm64,
  and Windows amd64. Each target builds the pinned TQSL helper natively, packages
  its runtime dependencies, checks the extracted helper, runs the synthetic
  enrollment flow using the extracted helper, and launches the desktop bundle.
  Hosted results remain unobserved.
- Local validation on 2026-10-22 passed `go test -race ./...`, all seven CI
  parser fuzz targets, `make vectors`, `make cddl`, the 11 Python client
  integration tests, and the installed-wheel consumer against the extracted
  Linux amd64 bundle. The consumer covered content, PixelQSO, one-way/mutual
  challenges, endorsements, reference publication and replay/session rejection.
  The Compose smoke passed authenticated publication/resolution, anonymous
  write rejection and named-volume restart persistence. `govulncheck` found no
  reachable vulnerabilities and reported one advisory only in an unreachable
  required module. These are local Linux results; hosted native targets and
  live LoTW/certificate evidence remain open.
- Desktop archives require Python/Tk. The native enrollment matrix builds the
  pinned TQSL helper and runtime resources for Linux amd64/arm64, macOS
  amd64/arm64 and Windows amd64. Extracted-helper synthetic enrollment and
  native desktop checks are part of each hosted job; their results remain
  pending until those jobs run.
  Packaging still has no tag-triggered release workflow, and
  this worktree's implementation files must be reviewed and committed before a
  candidate can be built from an exact source revision.

## 1. Make the complete authentication demo reproducible

- [x] Add a documented `make enrollment-demo` entry point that generates a fake
  root/intermediate/callsign certificate, imports only generated credentials into
  a temporary TQSL store, and invokes the actual native helper. The helper now
  accepts an explicit TQSL directory; the test importer is built only with the
  fixture option and cannot target the user's normal TQSL directory.
- [x] Exercise enrollment issuance, signing, verification, and persistence, then
  issue and answer a separate authentication challenge using the enrolled key.
- [x] Keep issuer/verifier state and responder state separate. Inject a local
  synthetic status provider through a test harness; do not add an acceptance
  bypass to the production CLI.
- [x] Report acceptance and expected rejections for replay, changed challenge,
  wrong audience/key/callsign, expired challenge/certificate, invalid chain,
  revoked/unknown/stale status, and disabled binding. Extend existing coverage
  where missing rather than duplicating it.
- [x] Add a focused regression for helper signing before chain retrieval.
- [ ] Observe the native synthetic flow passing in Linux CI using the pinned
  TrustedQSL source revision.
- [x] Provide a small offline content/PixelQSO demo using repository fixtures.
  `make signing-demo` runs both paths; the CI run remains part of validation.

Acceptance: a fresh checkout with documented prerequisites can run both demos
without station credentials or LoTW access. Failure returns a nonzero exit code;
the authentication demo prints the accepted callsign and later replay rejection.

## 2. Finish the enrollment policy and lifecycle

- [x] Record supported root provenance, intermediate validation, certificate key
  usage, callsign normalization and matching, certificate selection, expiry,
  supersession, and revocation rules against TQSL's configured roots and
  certificate-status source. See [the enrollment policy](LOTW-BINDING-DESIGN.md#certificate-acceptance-policy).
- [x] Review the legacy RSA/SHA-1 enrollment threat model and document the beta
  decision. The project accepts TQSL's supported signature only for the
  fresh-challenge enrollment assertion; the interface explains its use before
  signing;
  ARAP content and challenge signatures remain Ed25519. Enrollment is ARAP
  authentication evidence and is not represented as an ARRL login or endorsement.
- [x] Define status freshness and outage policy using the TQSL-compatible LoTW
  endpoint: require HTTPS response time evidence no older than 24 hours by
  default, fail closed when unavailable or stale, and document that this does
  not prove the origin's database update time. Verify behavior with live status
  testing at the end of platform integration.
- [x] Present certificate expiry, status observation time/age, status source,
  purposes, issuer, and disabled state in the desktop binding view. Add an
  explicit refresh action using the retained accepted response, configured
  roots (or TQSL defaults), and selected maximum age. Refresh cannot re-enable
  disabled bindings; live service behavior remains unvalidated with a real cert.
- [x] Document encrypted ARAP key backup, restore, key replacement and disabling
  a lost key. Preserve the distinction between a verifier's local binding and
  a binding recognized by other verifiers.
- [ ] After platform integration, conduct a user-operated real certificate
  enrollment and subsequent authentication challenge, including the live status
  path. Record versions, public certificate metadata and outcomes; keep private
  material out of evidence.

Acceptance: a real supported certificate works through the packaged flow;
unsupported, stale, revoked and unknown cases fail with actionable messages.
No synthetic status result is counted as evidence for live LoTW status behavior.
Unresolved platform integration and live status behavior block
the promised enrollment beta rather than being silently removed from its scope.

## 3. Package a complete tester experience

- [x] Bundle the native helper, TQSLLIB and TrustedQSL `config.xml` resources
  for Linux amd64, pin TrustedQSL
  2.8.7 to its source revision, and discover the adjacent helper/library after
  extraction. The packaged synthetic enrollment flow passes outside the build
  tree; standard shared Linux runtime libraries remain host prerequisites.
- [ ] Complete the redistribution notice inventory for every bundled
  dependency and have the project owner select the project license. The native
  packaging now includes the TQSLLIB notice, collects versioned Go module
  notices, and gathers OpenSSL/Expat or vcpkg notices for macOS and Windows.
  The archive checker verifies the Go report and license files. Confirm each
  platform notice set against hosted artifacts and add the selected project
  license before publication.
- [x] Add version/commit reporting to both executables and the desktop About
  view. Linux amd64 archive checks compare CLI/keyserver JSON version reports
  against the build manifest; native desktop smoke repeats this on macOS and
  Windows.
- [x] Add startup diagnostics for Python/Tk, CLI/version, helper/runtime
  resources, TQSL command version, and standard user certificate data path.
  Launchers explain missing Python/Tk; enrollment errors explain missing helper
  and likely TQSL password/serial/certificate causes. The checked integration
  versions are TQSL 2.8.7-rc5 and TQSLLIB 2.8.7; other releases are not yet
  qualified.
- [x] Make identity/trust → sign → verify → authenticate discoverable from the
  first desktop tab. The challenge form names requester/verifier and responder
  roles; enrollment describes the key fingerprint, verifier audience, and TQSL
  certificate serial selection.
- [x] Add the bundled first-run guide, demo instructions, beta limitations and
  bug report template requesting versions and sanitized errors.
- [x] Ship API documentation, versioned machine-interface schemas, Go/Python
  integration examples, and compatibility/migration notes alongside the bundle.
  Archive validation checks every local Markdown link and the required targets.

Acceptance: a tester follows the included guide from an extracted archive on a
clean supported machine without compiling the helper or editing source paths.
Python/Tk may remain explicit beta prerequisites if the launcher diagnoses them.

## 4. Validate the release candidate

- [ ] Inventory and review the working tree; include intended implementation and
  fixtures in source control while excluding credentials, generated stores,
  tokens and temporary artifacts. Build candidates from an exact committed tree.
- [ ] Run existing unit/race/vet, vectors, schemas, parser fuzz checks and
  dependency scan against that commit. Add enrollment parser/native-helper
  coverage where the existing pipeline does not exercise it.
- [ ] Run consumer integration checks from outside the ARAP source tree against
  the candidate module and packaged CLI, covering every milestone 0 capability.
  Include independent vectors for endorsement and mutual authentication and
  regression checks for API/result-schema compatibility.
- [ ] Run the packaged synthetic demo and desktop workflow on Linux amd64,
  including cancellation, multiple certificates, incorrect password, missing
  helper and restart persistence. Observe hosted CI results for the same commit.
- [ ] Exercise the documented Compose deployment through HTTPS and verify
  publication, resolution, anonymous-write rejection and backup/restore. Use a
  disposable deployment; a public hosted keyserver is not required for beta.
- [ ] Verify the advertised PixelQSO workflow with a redistributable saved-card
  fixture, including paired frames, an edited card and an unavailable resolver.
- [x] Fix stale implementation/validation documentation, including the completed
  synthetic helper run. Record remaining limits against the release commit.
  Current local Linux packaged-helper evidence is in [`VALIDATION.md`](VALIDATION.md);
  hosted/native platform results remain pending.

Acceptance: advertised workflows pass from the distributed artifacts, with no
known blocker involving private-key exposure, incorrect identity acceptance,
replay acceptance, data loss or a broken supported installation path.

## 5. Publish and collect beta feedback

- [x] Add a release workflow for `v0.1.0-beta.*` that builds the tested source,
  produces versioned archives and SHA-256 checksums, includes notices and
  dependency inventory, and assembles a draft prerelease with concise notes.
  The workflow waits for successful native CI on the exact tag and verifies
  each archive's target and version; hosted execution awaits an owner-selected
  project license and a beta tag.
- [ ] Decide artifact signing for the supported platforms and disclose any
  unsigned beta downloads. Checksums alone do not authenticate a release.
- [ ] Review the exact candidate artifacts, CI evidence and known issues before
  publishing. This planning task does not publish or tag a release.
- [ ] Recruit a small tester group for fresh installation, existing TQSL
  certificates, enrollment, authentication, restart/re-enrollment, and the
  optional content/keyserver workflows. Track defects by impact and reproduce
  them with sanitized fixtures where possible.
- [ ] Produce beta.2 and later tags as needed. Graduate to `v0.1.0` when advertised
  flows have repeatable tester evidence and release blockers are resolved;
  document API/wire compatibility and any necessary migration before graduation.

## Work order and decisions

Start by defining the milestone 0 public contracts and implementing milestone 1's
reproducible baseline. Finish identity policy/lifecycle, endorsements, mutual
authentication and consumer integrations before feature freeze. Packaging work
can proceed while certificate-policy evidence is collected. Milestone 4 runs
against the assembled candidate; milestone 5 uses those exact artifacts or
rebuilds and rechecks a new candidate. All signing/authentication/challenge
capabilities are release requirements, not post-beta follow-ups.

Owner decisions still needed before publication: project license and artifact
signing. The enrollment signature policy and multi-platform target matrix are
set. The existing desktop target matrix is Linux amd64/arm64, macOS
amd64/arm64, and Windows amd64; enrollment should be included on each supported
target. Estimate calendar dates after the native TQSL packaging spike reveals
the remaining integration work.
