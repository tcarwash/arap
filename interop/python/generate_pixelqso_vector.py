#!/usr/bin/env python3
"""Independently generate the canonical PixelQSO-card-v1 CBOR vector."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import cbor2


SHARED_PALETTES = (
    ((0, 0, 0), (15, 15, 15), (0, 0, 15), (0, 15, 15), (0, 15, 0), (15, 15, 0), (15, 0, 0), (15, 0, 15)),
    tuple((r, g, b) for r in (0, 5, 10, 15) for g in (0, 15) for b in (0, 15)),
    tuple((r, g, b) for r in (0, 5, 10, 15) for g in (0, 5, 10, 15) for b in (0, 15)),
)


def artwork_digest(card: dict) -> bytes:
    palette = card["palette"]
    target = SHARED_PALETTES[{8: 0, 16: 1, 32: 2}[len(palette)]]
    colors = [palette[pixel] for pixel in card["pixels"]]
    quantized = bytes(min(range(len(target)), key=lambda i: sum(
        (int(colors[n][k]) - target[i][k]) ** 2 for k in range(3))) for n in range(len(colors)))
    identity = json.dumps([card["callsign"].upper(), card["card_id"], card["width"],
                           card["height"], len(target)], separators=(",", ":")).encode()
    return hashlib.blake2s(identity + quantized, digest_size=8).digest()


def canonical_value(card: dict) -> dict:
    value = {1: 1, 2: card["callsign"], 3: card["grid"], 4: card["card_id"],
             5: card["width"], 6: card["height"], 7: card["palette"], 8: card["pixels"]}
    animation = card.get("animation")
    if animation is not None:
        value[9] = {1: animation["first_card_id"],
                    2: bytes.fromhex(animation["first_digest"]),
                    3: animation.get("frame_ms", 500)}
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2] / "test-vectors" / "pixelqso-card-v1" / "card.json"
    card = json.loads(source.read_text(encoding="utf-8"))
    first_source = source.with_name("first-card.json")
    first = json.loads(first_source.read_text(encoding="utf-8"))
    digest = artwork_digest(first)
    assert card["animation"]["first_card_id"] == first["card_id"]
    assert bytes.fromhex(card["animation"]["first_digest"]) == digest
    first_encoded = cbor2.dumps(canonical_value(first), canonical=True)
    encoded = cbor2.dumps(canonical_value(card), canonical=True)
    assert cbor2.loads(first_encoded) == canonical_value(first)
    assert cbor2.loads(encoded) == canonical_value(card)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "first.cbor").write_bytes(first_encoded)
    (args.out / "canonical.cbor").write_bytes(encoded)
    manifest = {
        "profile": "PixelQSO-card-v1",
        "media_type": "application/vnd.pixelqso.card+cbor",
        "context": "pixelqso/card-v1",
        "first_artwork_digest": digest.hex(),
        "first_canonical_size": len(first_encoded),
        "first_canonical_sha256": hashlib.sha256(first_encoded).hexdigest(),
        "canonical_size": len(encoded),
        "canonical_sha256": hashlib.sha256(encoded).hexdigest(),
        "canonical_cbor_hex": encoded.hex(),
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
