# Application API and capability map

This page describes the public integration surface in the current source tree.
It distinguishes operations applications can call today from beta requirements
that still need an API or wire profile. Package exports are the current source of
truth; this map is a release checklist, not a compatibility promise yet.

| Capability | Go package/API | CLI or schema | State for beta |
| --- | --- | --- | --- |
| Key generation and encrypted key files | `identity.GenerateEncryptedKeyPair`, `identity.LoadPrivateWithPassphrase`, `identity.LoadPublicKey`, `identity.WriteExclusive`; Python `generate_keypair`, `fingerprint` | `arap keygen`, `arap fingerprint --json`; age-encrypted PKCS#8 and SPKI PEM | Implemented; Python returns encrypted identity files as bytes and calculates key IDs for lifecycle operations; consuming application retains custody and handles backup/rotation |
| Sign arbitrary content | `protocol.SignContent` with `protocol.Signer` | `arap sign`; `ARAP-profile-v1.cddl` | Implemented; Go API is available and Python wrapper is versioned; independent consumer review remains |
| Verify content proof | `protocol.VerifyContentWithTrust`, `protocol.VerifyPayload` | `arap verify`, `arap inspect-proof` | Integrated with local purpose-scoped trust and accepted enrollment evidence; independent consumer review remains |
| PixelQSO card signing | `adapters/pixelqso.SignJSON`, `VerifyJSON`, `CanonicalizeJSON`, animation helpers | `arap sign-pixelqso`, `arap verify-pixelqso`; `PixelQSO-card-v1.cddl` | Library-level card validation, frame linking, canonicalization, signing, verification and caller trust policy are implemented; external consumer validation remains |
| Local callsign/key trust | `identity.LoadTrust`, `TrustStore.Add`, `TrustStore.Disable`, `TrustStore.Status`; Python `add_trust`, `list_trust`, `disable_trust` | trust CLI commands; caller-owned JSON trust file | Go callbacks and Python operations support explicit purpose-scoped add/list/disable; integration checks confirm disable and purpose-narrow reauthorization |
| Issue a challenge | `challenge.IssueRequest`, `CancelRequest`, `NewRequest`, `EncodeRequest`, `LifecycleStore` | `arap challenge issue|cancel`; `ARAP-challenge-v1.cddl` | Implemented; persist-before-publish, cancellation, pruning and atomic consumption contract; Python exposes issue and cancel |
| Respond to a challenge | `challenge.Respond` | `arap challenge respond` | Implemented |
| Verify and consume responses | `challenge.VerifyResponseWithTrust`, `challenge.VerifyMutualPair`, `challenge.PairStore` | `arap challenge verify-response`, `mutual-verify`; challenge request/response CDDL | One-way and coordinated inverse-pair verification are available through Go and CLI; an independent consuming application remains |
| LoTW/TQSL enrollment | `lotwenroll.NewWithPurposes`, `Respond`, `Verify`, `RefreshStatus`, `SQLiteStore.TrustStatus` | `arap enrollment`; `verify-content --enrollment-store`; Python wrapper; enrollment CDDL v1/v2 | Version 1 remains challenge-response-only. Version 2 binds verifier-selected challenge/content purposes and requires them again at response verification; content trust also checks certificate expiry and status age. The CLI and Python wrapper can enumerate matching current TQSL certificate serials before signing. RSA/SHA-1 policy and live TQSL/status validation remain experimental |
| Key endorsement | `endorsement.Issue`, `EncodeChain`, `DecodeChain`, `Verify`, `VerifyEncoded` | `arap endorsement issue|pack|append|verify`; Python wrapper; endorsement proof and chain CDDL schemas | Go API, CLI and versioned Python wrapper support signed delegation, portable chain assembly, and offline verification against explicit roots with purpose/depth attenuation and optional local disablement; independent consumer review remains |
| Enrollment record refresh/disable/replace | `lotwenroll.RefreshStatus`, `SQLiteStore.RefreshStatus`, list/disable methods | `arap enrollment refresh|list|disable`; Python wrapper | Refresh revalidates a supplied certificate chain against roots and updates fresh good status only for the exact existing key/certificate; disabled or expired bindings remain unavailable. Key replacement requires a fresh enrollment |
| Publish and resolve proof references | `reference.Client`; `PublishProof`, `Resolve`, `PublishKey`, `FetchKey` | `arap publish|resolve|publish-key|fetch-key`; Python `publish_proof`, `resolve_proof`, `publish_key`, `fetch_key` | Implemented with stable proof-resolution codes and local verification responsibility; live multi-resolver interoperability remains |
| Machine integration | Go packages; Python `ArapClient` envelope v1 | `interop/python/arap_interop`; `docs/MACHINE-INTERFACE.md` | Signing, content, PixelQSO, one way/mutual challenge, endorsement, enrollment and reference operations have a timed subprocess wrapper, binary-safe inputs/outputs and stable errors; independent consumer validation remains |
| Foreign-language integration | Public Go packages plus Python wrapper | `interop/python/README.md`; `scripts/check-installed-python-consumer.py` | Installed-wheel consumer runs outside the checkout and tests an extracted bundle CLI/keyserver across content, PixelQSO, one-way/mutual challenges, endorsements, replay/session rejection and reference publication. Source integration tests additionally cover trust lifecycle and enrollment challenge/certificate listing. Live TQSL enrollment response/status and an independently maintained implementation remain |

## Integration rules

- Applications pass content through `io.Reader`; ARAP hashes exact bytes. If an
  application needs canonicalization, it must name and implement that format
  before calling the signer.
- Applications choose the callsign/key trust decision. A valid signature proves
  possession of the signing key, while a trust callback determines authorization.
- Challenge storage belongs behind `challenge.Store`. Applications may provide
  their own durable backend; `challenge.SQLiteStore` is the reference adapter.
  Issuers should implement `challenge.LifecycleStore` and use `IssueRequest` so
  each request is durably recorded before transport publication. If publication
  fails, call `CancelRequest`; implement atomic `Consume` so concurrent replay
  attempts have one winner. Expiry is checked during consumption, while
  `PruneExpired` is cleanup and never an authentication decision.
- Application transports carry opaque encoded request, response and proof bytes.
  They must retain audience/session bindings and must not infer authentication
  from transport encryption alone.
- No current export turns a local enrollment acceptance into portable trust.
  Import must validate public evidence independently under the receiving
  application's roots and freshness policy.

The complete two-party challenge exchange is also demonstrated in
[`examples/mutual-auth`](../examples/mutual-auth/main.go).

Key generation, authorization, replacement enrollment, status refresh, and
portable evidence boundaries are documented in
[`IDENTITY-LIFECYCLE.md`](IDENTITY-LIFECYCLE.md).

Key endorsement chains can be issued, packed, appended, and verified with the
`arap endorsement` commands. Verification requires the caller to supply the
root key, root purposes and delegation limit, and the expected subject key and
purpose. Chain bytes carry signed public statements only; they do not carry a
trust decision.

## Runnable consumer example

The [content proof example](../examples/content-proof/main.go) imports only
public ARAP packages. Run it with:

```sh
go run ./examples/content-proof
```

It creates an in-memory key for demonstration, signs sample bytes, and verifies
the proof with an explicit trust decision. It does not persist the ephemeral
private key or exercise LoTW enrollment.
