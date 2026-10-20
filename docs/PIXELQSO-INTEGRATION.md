# PixelQSO signed cards — integration guide

## Desired user experience

- Cards can be authored, saved, and signed while offline.
- A sender can transmit the card and its full signature over any modem, or transmit a short reference to a hosted proof.
- A received card remains viewable even when proof resolution is unavailable; its verification badge must accurately describe the missing proof.
- Decks can filter by unsigned, cryptographically valid, trusted callsign identity, failed verification, or incomplete verification.
- Local annotations, rating, collection/deck grouping, and receipt times remain unsigned metadata unless intentionally included in the canonical card.

## Canonical card content

The PixelQSO adapter MUST define an exact byte sequence. Choose either:

**Option A (simplest):** hash the existing final card payload bytes, as transmitted or saved, if identical bytes can be reproduced by recipients. Changes in serialization produce new content IDs even for visually identical cards.

**Option B (better cross-version durability):** deterministic CBOR card object with explicit schema version, width/height, palette entries, pixel indices, and agreed signed metadata. Hash exactly those bytes. Legacy payloads can map to this format via versioned conversion.

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
2. Validate COSE signature.
3. Confirm content type/context `pixelqso/card/v1` and purpose `content-signature`.
4. Resolve key and independently determine callsign trust level.
5. Display the outcome separately from receive CRC/FEC integrity.

**Security distinction:** a valid card signature means the key signed that card, not that a particular contact actually occurred. Do not mislabel signed content as a live authenticated QSO.

## Suggested API

```text
sign_content(identity, content_bytes, content_type, context) -> proof_bytes
verify_content(proof_bytes, content_bytes, trust_policy) -> structured_result
short_reference(proof_bytes) -> printable_reference
resolve(reference, resolver_urls) -> candidate_proof_bytes[]
```

## Initial test fixtures

16x16, 32x32, 64x64 cards; different palettes; transparency if supported; modified pixel; reordered palette; unchanged art with different encoding; card with and without attached signature; reference lookup offline/online.