#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cddl_command="${CDDL:-cddl}"

if ! command -v "$cddl_command" >/dev/null 2>&1; then
  printf '%s\n' "cddl v0.10.7 is required (https://github.com/anweiss/cddl)." >&2
  exit 1
fi
version="$("$cddl_command" --version)"
if [[ "$version" != "cddl 0.10.7" ]]; then
  printf 'expected cddl 0.10.7, got %s\n' "$version" >&2
  exit 1
fi

schemas=(
  spec/ARAP-profile-v1.cddl
  spec/ARAP-challenge-v1.cddl
  spec/ARAP-challenge-response-v1.cddl
  spec/ARAP-lotw-enrollment-v1.cddl
  spec/ARAP-lotw-enrollment-v2.cddl
  spec/ARAP-lotw-enrollment-response-v1.cddl
  spec/ARAP-key-endorsement-v1.cddl
  spec/ARAP-key-endorsement-chain-v1.cddl
  spec/PixelQSO-card-v1.cddl
)
for schema in "${schemas[@]}"; do
  "$cddl_command" --ci compile-cddl --cddl "$repo_root/$schema"
done

"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-profile-v1.cddl" \
  --cbor "$repo_root/test-vectors/content-ed25519-v1/proof.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-challenge-v1.cddl" \
  --cbor "$repo_root/test-vectors/challenge-ed25519-v1/request.cbor" \
  --cbor "$repo_root/test-vectors/mutual-challenge-ed25519-v1/request-from-a.cbor" \
  --cbor "$repo_root/test-vectors/mutual-challenge-ed25519-v1/request-from-b.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-challenge-response-v1.cddl" \
  --cbor "$repo_root/test-vectors/challenge-ed25519-v1/response.cose" \
  --cbor "$repo_root/test-vectors/mutual-challenge-ed25519-v1/response-from-a.cose" \
  --cbor "$repo_root/test-vectors/mutual-challenge-ed25519-v1/response-from-b.cose"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-lotw-enrollment-v1.cddl" \
  --cbor "$repo_root/test-vectors/lotw-enrollment-v1/challenge.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-lotw-enrollment-v2.cddl" \
  --cbor "$repo_root/test-vectors/lotw-enrollment-v2/challenge.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-lotw-enrollment-response-v1.cddl" \
  --cbor "$repo_root/test-vectors/lotw-enrollment-v1/response-shape.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-key-endorsement-v1.cddl" \
  --cbor "$repo_root/test-vectors/key-endorsement-v1/root-to-delegate.cbor" \
  --cbor "$repo_root/test-vectors/key-endorsement-v1/delegate-to-subject.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/ARAP-key-endorsement-chain-v1.cddl" \
  --cbor "$repo_root/test-vectors/key-endorsement-v1/chain.cbor"
"$cddl_command" --ci validate --cddl "$repo_root/spec/PixelQSO-card-v1.cddl" \
  --cbor "$repo_root/test-vectors/pixelqso-card-v1/canonical.cbor" \
  --cbor "$repo_root/test-vectors/pixelqso-card-v1/first.cbor"

printf '%s\n' 'All CDDL schemas compile and all protocol/card vectors validate.'
