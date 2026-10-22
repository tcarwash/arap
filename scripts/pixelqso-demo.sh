#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/arap-pixelqso-demo.XXXXXXXX")
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT INT TERM

go build -trimpath -o "$tmp_dir/arap" ./cmd/arap
passphrase=synthetic-demo-only
printf '%s\n%s\n' "$passphrase" "$passphrase" | "$tmp_dir/arap" keygen \
  --private-key "$tmp_dir/private.pem" --public-key "$tmp_dir/public.pem" \
  --passphrase-stdin >/dev/null
"$tmp_dir/arap" trust add --store "$tmp_dir/trust.json" \
  --public-key "$tmp_dir/public.pem" --callsign AG7SU \
  --purpose content-signature >/dev/null
fixture=test-vectors/pixelqso-card-v1
printf '%s\n' "$passphrase" | "$tmp_dir/arap" sign-pixelqso \
  --key "$tmp_dir/private.pem" --card "$fixture/card.json" \
  --first-card "$fixture/first-card.json" --out "$tmp_dir/card.cose" \
  --passphrase-stdin >/dev/null
"$tmp_dir/arap" verify-pixelqso --card "$fixture/card.json" \
  --first-card "$fixture/first-card.json" --proof "$tmp_dir/card.cose" \
  --public-key "$tmp_dir/public.pem" --trust-store "$tmp_dir/trust.json"
echo "Synthetic PixelQSO frame-pair proof accepted. No station key or transport used."
