#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/arap-confidence.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

arap_bin="${ARAP_BIN:-$work_dir/arap}"
if [[ -z "${ARAP_BIN:-}" ]]; then
  (cd "$repo_root" && go build -trimpath -o "$arap_bin" ./cmd/arap)
fi

passphrase='arap-demo-only-passphrase'
make_key() {
  local name="$1"
  printf '%s\n%s\n' "$passphrase" "$passphrase" |
    "$arap_bin" keygen --private-key "$work_dir/$name-private.pem" \
      --public-key "$work_dir/$name-public.pem" --passphrase-stdin
}

expect_exit() {
  local expected="$1"
  shift
  local actual=0
  "$@" || actual=$?
  if [[ "$actual" -ne "$expected" ]]; then
    printf 'FAIL: expected exit %s, got %s: %s\n' "$expected" "$actual" "$*" >&2
    return 1
  fi
}

printf '%s\n' 'ARAP confidence demo: using generated keys and temporary files only.'
make_key trusted
make_key stranger
printf '%s\n' 'A sample radio message for the ARAP confidence demo.' > "$work_dir/message.txt"

"$arap_bin" trust add --store "$work_dir/trust.json" \
  --public-key "$work_dir/trusted-public.pem" --callsign K7ABC --purpose content-signature
"$arap_bin" trust add --store "$work_dir/other-trust.json" \
  --public-key "$work_dir/stranger-public.pem" --callsign AG7SU --purpose content-signature
printf '%s\n' '1/5 Signing a sample file with a temporary key...'
printf '%s\n' "$passphrase" | "$arap_bin" sign-content \
  --key "$work_dir/trusted-private.pem" --passphrase-stdin --callsign K7ABC \
  --input "$work_dir/message.txt" --media-type text/plain \
  --context arap/confidence-demo/v1 --out "$work_dir/message.cose"

printf '%s\n' '2/5 The unchanged file and trusted signer should be accepted...'
"$arap_bin" verify-content --proof "$work_dir/message.cose" \
  --input "$work_dir/message.txt" --public-key "$work_dir/trusted-public.pem" \
  --trust-store "$work_dir/trust.json" --expect-media-type text/plain \
  --expect-context arap/confidence-demo/v1 --expect-callsign K7ABC

printf '%s\n' '3/5 Editing one byte should be rejected...'
cp "$work_dir/message.txt" "$work_dir/edited.txt"
printf '%s\n' 'Edited.' >> "$work_dir/edited.txt"
expect_exit 1 "$arap_bin" verify-content --proof "$work_dir/message.cose" \
  --input "$work_dir/edited.txt" --public-key "$work_dir/trusted-public.pem" \
  --trust-store "$work_dir/trust.json" --expect-media-type text/plain \
  --expect-context arap/confidence-demo/v1 --expect-callsign K7ABC
printf '%s\n' 'PASS: edited content was rejected.'
printf '%s\n' '4/5 A valid signature without a trust record should not be accepted...'
expect_exit 3 "$arap_bin" verify-content --proof "$work_dir/message.cose" \
  --input "$work_dir/message.txt" --public-key "$work_dir/trusted-public.pem" \
  --trust-store "$work_dir/other-trust.json" --expect-media-type text/plain \
  --expect-context arap/confidence-demo/v1 --expect-callsign K7ABC
printf '%s\n' 'PASS: the signer was not authorized by the other trust record.'

"$arap_bin" trust add --store "$work_dir/challenge-trust.json" \
  --public-key "$work_dir/stranger-public.pem" --callsign AG7SU --purpose challenge-response
printf '%s\n' '5/5 A challenge should verify once; replay should be rejected...'
"$arap_bin" challenge issue --requester K7ABC --responder AG7SU \
  --store "$work_dir/challenges.sqlite" --out "$work_dir/request.cbor"
printf '%s\n' "$passphrase" | "$arap_bin" challenge respond \
  --request "$work_dir/request.cbor" --key "$work_dir/stranger-private.pem" \
  --passphrase-stdin --callsign AG7SU --out "$work_dir/response.cose"
"$arap_bin" challenge verify-response --request "$work_dir/request.cbor" \
  --response "$work_dir/response.cose" --public-key "$work_dir/stranger-public.pem" \
  --trust-store "$work_dir/challenge-trust.json" --store "$work_dir/challenges.sqlite" \
  --requester K7ABC
expect_exit 1 "$arap_bin" challenge verify-response --request "$work_dir/request.cbor" \
  --response "$work_dir/response.cose" --public-key "$work_dir/stranger-public.pem" \
  --trust-store "$work_dir/challenge-trust.json" --store "$work_dir/challenges.sqlite" \
  --requester K7ABC
printf '%s\n' 'PASS: the challenge response could not be replayed.'
printf '%s\n' 'All confidence demo checks passed. Temporary keys and files were removed.'
