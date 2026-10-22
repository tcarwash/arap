# PixelQSO signed cards — integration guide

## Desired user experience

- Cards can be authored, saved, and signed while offline.
- A sender can transmit the card and its full signature over any modem, or transmit a short reference to a hosted proof.
- A received card remains viewable even when proof resolution is unavailable; its verification badge must accurately describe the missing proof.
- Decks can filter by unsigned, cryptographically valid, trusted callsign identity, failed verification, or incomplete verification.
- Local annotations, rating, collection/deck grouping, and receipt times remain unsigned metadata unless intentionally included in the canonical card.

## Canonical card content

The ARAP adapter canonicalizes saved PixelQSO card JSON to the deterministic CBOR map in [PixelQSO-card-v1.cddl](../spec/PixelQSO-card-v1.cddl). It authenticates the normalized callsign, grid, card ID, dimensions, ordered RGB444 palette, row-major palette indices, and optional frame-2 reference. It ignores only editor-local `base_pixels` and `stamp_layers`, plus local `archive_reason`, `copied_from`, and `reception_report`; unknown fields are rejected until deliberately added to a versioned profile. JSON whitespace and key order do not affect the signed bytes.

Input JSON is limited to 1 MiB, 16 nested containers, and 250,000 values. The value cap accommodates a maximum 255×255 card plus a second full raster in `base_pixels`, while bounding parsing of editor-only state that is ignored after validation.

Frame timing is normalized to 500 ms when omitted, matching PixelQSO's current default; the canonical map always contains the effective duration. For a frame-2 card, `first_digest` is PixelQSO's BLAKE2s-64 fingerprint over the first card's callsign, ID, dimensions, and RGB444 artwork quantized to its shared palette. ARAP signing and verification require the first card and validate this fingerprint, callsign, ID, and dimensions. The content media type is `application/vnd.pixelqso.card+cbor` and context is `pixelqso/card-v1`. This adapter profile is versioned independently from the COSE envelope.

Do not hash GUI screenshots or nondeterministically compressed PNG representations.

## Attachment example (conceptual)

```yaml
card_format: pixelqso-card-v1
card_bytes: <opaque binary canonical card>
proof_transport:
  inline: <COSE_Sign1 bytes>
  # OR (reference mode)
  reference: AR1-ABCDEFGHIJKLMNOP
```

Both forms MUST resolve to identical verification semantics. The example token is a placeholder and not a valid calculated digest.

## Required verification checks

1. Recompute the content SHA-256 from canonical card bytes and verify length.
2. Validate the COSE signature.
3. Confirm content type/context `application/vnd.pixelqso.card+cbor` / `pixelqso/card-v1` and purpose `content-signature`.
4. Resolve key and independently determine callsign trust level.
5. Display the outcome separately from receive CRC/FEC integrity.

**Security distinction:** a valid card signature means the key signed that card, not that a particular contact actually occurred. Do not mislabel signed content as a live authenticated QSO.

## Go application API

Applications can use the public adapter directly; it validates the card and an
optional frame-2 link, canonicalizes the authenticated fields, then calls the
shared content proof implementation. The card and proof remain separate
transport values.

```go
signer, err := protocol.GenerateEd25519(card.Callsign)
if err != nil { return err }
proof, claims, err := pixelqso.SignJSON(signer, cardJSON, firstCardJSON, time.Now())
if err != nil { return err }

verifier, err := protocol.NewEd25519Verifier(signer.PublicKey().(ed25519.PublicKey))
if err != nil { return err }
result, err := pixelqso.VerifyJSON(proof, cardJSON, firstCardJSON, verifier,
    trustStore.Status, time.Now())
if err != nil { return err } // invalid card or frame link
if result.OverallPolicy != "accepted" { return errors.New(result.Reason) }
_ = claims // authenticated metadata returned by signing
```

Pass `nil` for `firstCardJSON` for ordinary cards; frame-2 cards require the
frame-1 JSON. `VerifyJSON` returns an error for malformed or incorrectly paired
cards and a structured policy result for proof, content, or trust rejection.
The result keeps signature, content-integrity, callsign-identity and overall
policy outcomes separate. The caller supplies the trust callback and decides
what `trusted`, `untrusted`, or `disabled` means in its application.

The Go API imports are `github.com/tcarwash/arap/adapters/pixelqso` and
`github.com/tcarwash/arap/protocol`.

## Suggested transport API

```text
sign_content(identity, content_bytes, content_type, context) -> proof_bytes
verify_content(proof_bytes, content_bytes, trust_policy) -> structured_result
short_reference(proof_bytes) -> printable_reference
resolve(reference, resolver_urls) -> candidate_proof_bytes[]
```

## CLI

```sh
arap sign-pixelqso --key station.pem --card card.json --out card.cose
arap verify-pixelqso --card card.json --proof card.cose \
  --public-key station.pub.pem --trust-store trust.json
```

For a frame-2 card, include `--first-card frame-1.json` on both commands. The signer callsign comes from the card and the local trust store must authorize the exact callsign/key/purpose. A proof is a separate file; these commands do not modify or transmit a card.

```sh
arap sign-pixelqso --key station.pem --card frame-2.json \
  --first-card frame-1.json --out frame-2.cose
arap verify-pixelqso --card frame-2.json --first-card frame-1.json \
  --proof frame-2.cose --public-key station.pub.pem --trust-store trust.json
```

## Validation boundary

Adapter tests and a Python-generated two-frame vector cover JSON layout independence, editor-layer exclusion, semantic pixel/palette/grid/ID changes, the BLAKE2s frame fingerprint and pair checks, duplicate/unknown fields, and invalid dimensions/palette indices. The PixelQSO source checkout now has an editor workflow backed by the ARAP CLI: saved-card signing, detached `.arap.cose` attachment, local-key/trust verification, keyserver reference publication and resolution, and pending/verified status. It leaves PixelQSO JSON and modem transmission unchanged. The real CLI accepted a trusted saved-card proof and rejected a one-pixel edit through the bridge. Signing/verification are local; publish/resolve run in a worker. Publish/resolve against a disposable local keyserver returned identical proof bytes and passed local trust verification. The focused editor bridge suite passes 8 tests with an isolated data directory. An offscreen end-to-end dialog run with automated file/prompt responses and the real CLI/keyserver passed frame-2 signing, trusted verification, authenticated publication, reference resolution, byte-identical proof recovery and re-verification. Native manual dialog behavior, hosted keyserver operation, and real-card/RF interoperability remain unverified.
