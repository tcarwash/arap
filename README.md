# ARAP — Amateur Radio Authentication Profile

**Status: early implementation.** The Ed25519 content-signature profile, challenge request/response, Go CLI, local Tk desktop client and content-addressed proof/key server are implemented. ARAP can canonicalize, sign and verify saved PixelQSO cards; the PixelQSO editor now attaches detached proofs, displays verification status, and publishes or resolves short references through the ARAP CLI. Broader conformance and full interoperability review remain in progress.

This project defines a transport-independent way to sign amateur-radio content and station-authentication exchanges using existing standards. It is intended to support signed PixelQSO cards, arbitrary messages, and short voice/CW references to complete hosted proofs.

The [KISSChat integration profile](docs/KISSCHAT-INTEGRATION.md) and
`adapters/kisschat` provide an application-specific canonical message schema;
KISSChat itself remains responsible for optional asynchronous delivery and UI.

Start with [the draft overview](spec/ARAP-v0.1.md). The content and challenge wire formats are described by [content CDDL](spec/ARAP-profile-v1.cddl) and [challenge CDDL](spec/ARAP-challenge-v1.cddl). The [PixelQSO card content profile](spec/PixelQSO-card-v1.cddl) and [integration guide](docs/PIXELQSO-INTEGRATION.md) describe signing saved cards. The [validation review](docs/VALIDATION.md) records remaining blockers, the [implementation plan](docs/IMPLEMENTATION-PLAN.md) tracks progress, and [keyserver operations](docs/KEYSERVER.md) documents the service.

## Build and run

```sh
make test
make build
```

Building from source requires Go 1.26.10 or later. This minimum keeps the Go standard library at a security-fixed release; CI also checks the current stable Go release.

The current executable uses independent Ed25519 (`-19`) keys and a pure-Go SQLite driver for durable challenge replay protection; enrollment is experimental and has not been validated against a live LoTW certificate. The enrollment flow includes a fresh challenge, dual signatures, certificate/status checks, atomic binding storage, and an optional native TQSL helper. TQSL's RSA-SHA1 data-block API is excluded from ARAP content proofs. Signing and verification of enrollment assertions both stay disabled unless the user explicitly accepts that legacy signature for the operation. See the [LoTW binding design](docs/LOTW-BINDING-DESIGN.md) and [TQSL research](docs/TQSL-RESEARCH.md).

The verifier can issue and persist a bounded enrollment challenge with `arap enrollment issue`, while the client can sign it with `arap enrollment respond` using the optional helper built against TrustedQSL source. Verification uses TQSL's local ARRL root bundle by default and queries the LoTW certificate-status endpoint. Signing and verification require per-operation acknowledgement of TQSL's legacy RSA/SHA-1 signature, which the project accepts only for this enrollment assertion; ARAP content and challenge signatures use Ed25519. This experimental flow does not create or submit a QSO and is not an ARRL-endorsed process. See the [enrollment design](docs/LOTW-BINDING-DESIGN.md) for helper build and use instructions.

`make enrollment-demo` exercises native signing with generated certificates in an isolated TQSL directory and a demo-only synthetic status provider. It does not use station credentials or query LoTW. `make signing-demo` demonstrates offline content and PixelQSO proof flows. See the [release plan](docs/RELEASE-0.1.0.md) for validation status and beta limitations.

The Tk desktop client needs Python 3 with Tk 8.6 and a built CLI; run `make desktop` or see [desktop setup](desktop/README.md). `make package` creates a platform bundle with the CLI, keyserver and all nine CDDL schemas; use `make package TARGET=windows-amd64` to cross-build. CI makes seven-day review bundles for Linux and macOS amd64/arm64 and Windows amd64. Challenge CLI flows are documented in [CHALLENGES.md](docs/CHALLENGES.md). `make race`, `make vet`, `make vectors`, and `make cddl` run additional checks; GitHub Actions tests Go on Linux, macOS and Windows, validates the Python vectors and CDDL schemas, and scans for reachable Go vulnerabilities. Run the keyserver with Docker Compose after setting `ARAP_UPLOAD_TOKEN` to a random value with at least 32 characters (for example, `openssl rand -hex 32`). The base Compose service stays inside its Docker network; use the optional loopback port overlay for a host-local HTTPS proxy. See [keyserver operations](docs/KEYSERVER.md) for remote-proxy firewall guidance. The server stores objects and does not decide identity trust.

## Local key storage

`arap keygen` creates a passphrase-encrypted Ed25519 key in the standard armored age file format and an SPKI public-key PEM. Use an `.age` suffix for the private key. New keys use age's scrypt recipient with work factor 15 and require at least 12 UTF-8 bytes; ARAP accepts age scrypt work factors up to 18 when loading a key. Key files are created with owner-only permissions where supported and are never overwritten. The CLI prompts without echo. For automation, `--passphrase-stdin` reads secrets from standard input instead of command arguments. Legacy unencrypted PKCS#8 keys remain readable; on Unix ARAP refuses private-key files readable by group or other users. ARAP does not use an operating-system keychain. Trust stores are separate local JSON files; keyservers receive public keys and signed proofs, never private keys.

## Architectural choices

- COSE_Sign1 / CBOR, not homemade signature primitives
- Signing arbitrary content as a core operation
- Challenge-response as a separate purpose with single-use verifier nonces
- LoTW callsign authentication as a core target; experimental enrollment responder and verifier exist, while ARRL policy and real-certificate validation remain incomplete; Ed25519 signs ARAP content
- Short on-air artifacts locate complete proofs and never replace cryptographic verification
- HTTPS proof hosting is optional; direct offline verification must work
- Opulent Voice is an optional adapter, not a required transport

## Layout

```text
spec/       draft and implemented profile schemas
docs/       validation, architecture, integration and research notes
protocol/   COSE/CBOR proof encoding and verification
adapters/   canonical application content adapters, including PixelQSO cards and KISSChat messages
identity/   local keys and trust records
challenge/ request/response encoding and durable single-use verification
cmd/        arap CLI and keyserver
reference/ bounded resolver and proof/key publishing client
keyserver/  immutable proof and public-key object service
desktop/    Tk client for signing, verification, challenges and keyserver tasks
interop/    independent Python vector generator
test-vectors/ generated public test-only interoperability fixtures
```

## License

The specification text is proposed under CC0-1.0, subject to project-owner confirmation. Application-code licensing has not yet been selected.
