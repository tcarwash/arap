#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
trustedqsl_revision=1916fc14a8cfc7f287742ae5a34aa986353d9df7
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/arap-enrollment-demo.XXXXXXXX")
cleanup() { rm -rf -- "$tmp_dir"; }
trap cleanup EXIT INT TERM

source_dir=${TRUSTEDQSL_SOURCE_DIR:-}
if [[ -z "$source_dir" && -f /tmp/arap-tqsl-source/src/tqsllib.h ]]; then
  source_dir=/tmp/arap-tqsl-source
fi
if [[ -z "$source_dir" ]]; then
  source_dir="$tmp_dir/trustedqsl"
  git clone --filter=blob:none --no-checkout https://git.code.sf.net/p/trustedqsl/tqsl "$source_dir"
  git -C "$source_dir" fetch --depth 1 origin "$trustedqsl_revision"
  git -C "$source_dir" checkout --detach "$trustedqsl_revision"
fi
if [[ ! -f "$source_dir/src/tqsllib.h" || ! -f "$source_dir/apps/tqslversion.ver" ]]; then
  echo "Set TRUSTEDQSL_SOURCE_DIR to a TrustedQSL checkout at $trustedqsl_revision" >&2
  exit 2
fi
actual_revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)
if [[ "$actual_revision" != "$trustedqsl_revision" ]]; then
  echo "TrustedQSL source revision mismatch: expected $trustedqsl_revision, got ${actual_revision:-unknown}" >&2
  exit 2
fi
source_version=$(tr -d '\r\n' < "$source_dir/apps/tqslversion.ver")
if [[ "$source_version" != "2.8.7" ]]; then
  echo "TrustedQSL revision has an unexpected version file" >&2
  exit 2
fi

responder_dir="$tmp_dir/responder"
verifier_dir="$tmp_dir/verifier"
fixture_dir="$tmp_dir/fixture"
build_dir="$tmp_dir/tqsl-build"
exe_suffix=
if [[ "$(go env GOOS)" == windows ]]; then exe_suffix=.exe; fi
mkdir -m 700 -p "$responder_dir" "$verifier_dir" "$fixture_dir" "$tmp_dir/tqsl-data"

"$repo_dir/tqsl-helper/build.sh" "$source_dir" "$build_dir" --fixture-importer
go build -trimpath -o "$tmp_dir/arap" "$repo_dir/cmd/arap"
go run "$repo_dir/examples/enrollment-demo" generate --out "$fixture_dir"
"$build_dir/arap-tqsl-fixture-import$exe_suffix" "$tmp_dir/tqsl-data" \
  "$fixture_dir/root.pem" "$fixture_dir/intermediate.pem" \
  "$fixture_dir/keybuf.b64" "$fixture_dir/leaf.pem"
tqsl_helper=${ARAP_TQSL_HELPER:-$build_dir/arap-tqsl-sign$exe_suffix}

arap="$tmp_dir/arap$exe_suffix"
key_passphrase=synthetic-demo-only
"$arap" keygen --private-key "$responder_dir/arap-private.pem" \
  --public-key "$responder_dir/arap-public.pem" --passphrase-stdin \
  < <(printf '%s\n%s\n' "$key_passphrase" "$key_passphrase")

audience=arap-enrollment-demo-v1
"$arap" enrollment issue --audience "$audience" --callsign N0CALL \
  --public-key "$responder_dir/arap-public.pem" \
  --store "$verifier_dir/enrollment.sqlite" --out "$verifier_dir/enrollment.cbor" \
  --purpose challenge-response --purpose content-signature
certificate_list=$("$arap" enrollment certificates --request "$verifier_dir/enrollment.cbor" \
  --tqsl-helper "$tqsl_helper" --tqsl-directory "$tmp_dir/tqsl-data")
case "$certificate_list" in *'"serial":"424242"'*) ;; *) echo "synthetic TQSL certificate was not discoverable" >&2; exit 1 ;; esac
ARAP_DEMO_PASSPHRASE="$key_passphrase" PYTHONPATH="$repo_dir/interop/python" \
  python3 - "$arap" "$verifier_dir/enrollment.cbor" \
  "$responder_dir/arap-private.pem" "$tqsl_helper" "$tmp_dir/tqsl-data" \
  "$responder_dir/enrollment-response.cbor" <<'PY'
import os
import sys
from pathlib import Path

from arap_interop import ArapClient

binary, request_path, private_key, helper, tqsl_directory, response_path = sys.argv[1:]
request = Path(request_path).read_bytes()
client = ArapClient(binary, timeout=30)
listed = client.list_enrollment_certificates(
    request, helper=helper, tqsl_directory=tqsl_directory,
)
certificates = listed["result"].get("certificates", [])
if not any(item.get("serial") == "424242" for item in certificates):
    raise SystemExit("Python wrapper did not discover synthetic TQSL certificate serial 424242")
result = client.respond_enrollment(
    request, private_key=private_key, helper=helper, serial="424242",
    tqsl_directory=tqsl_directory,
    arap_passphrase=os.environ["ARAP_DEMO_PASSPHRASE"],
)
Path(response_path).write_bytes(result["response"])
print("Python enrollment wrapper listed and signed with synthetic TQSL certificate 424242.")
PY
go run "$repo_dir/examples/enrollment-demo" verify \
  --response "$responder_dir/enrollment-response.cbor" \
  --root "$fixture_dir/root.pem" --store "$verifier_dir/enrollment.sqlite" \
  --audience "$audience"
go run "$repo_dir/examples/enrollment-demo" negatives \
  --response "$responder_dir/enrollment-response.cbor" \
  --root "$fixture_dir/root.pem" --expired-leaf "$fixture_dir/leaf-expired.pem" \
  --audience "$audience"

printf '%s\n' 'synthetic signed application content' > "$responder_dir/content.txt"
printf '%s\n' "$key_passphrase" | "$arap" sign-content \
  --key "$responder_dir/arap-private.pem" --callsign N0CALL \
  --input "$responder_dir/content.txt" --media-type text/plain \
  --context arap/enrollment-demo/content-v1 --out "$responder_dir/content.cose" \
  --passphrase-stdin >/dev/null
"$arap" verify-content --proof "$responder_dir/content.cose" \
  --input "$responder_dir/content.txt" --public-key "$responder_dir/arap-public.pem" \
  --enrollment-store "$verifier_dir/enrollment.sqlite" \
  --expect-media-type text/plain --expect-context arap/enrollment-demo/content-v1 \
  --expect-callsign N0CALL

# A separate verifier challenge proves the enrolled key can authenticate. The
# responder receives only request bytes and its own keys/TQSL data directory.
"$arap" challenge issue --requester K7DEMO --responder N0CALL \
  --store "$verifier_dir/authentication.sqlite" --out "$verifier_dir/auth.cbor"
printf '%s\n' "$key_passphrase" | "$arap" challenge respond \
  --request "$verifier_dir/auth.cbor" --callsign N0CALL \
  --key "$responder_dir/arap-private.pem" --passphrase-stdin \
  --out "$responder_dir/auth-response.cose"
"$arap" challenge verify-response --request "$verifier_dir/auth.cbor" \
  --response "$responder_dir/auth-response.cose" \
  --public-key "$responder_dir/arap-public.pem" \
  --enrollment-store "$verifier_dir/enrollment.sqlite" \
  --store "$verifier_dir/authentication.sqlite" --requester K7DEMO

if "$arap" challenge verify-response --request "$verifier_dir/auth.cbor" \
  --response "$responder_dir/auth-response.cose" \
  --public-key "$responder_dir/arap-public.pem" \
  --enrollment-store "$verifier_dir/enrollment.sqlite" \
  --store "$verifier_dir/authentication.sqlite" --requester K7DEMO \
  >/dev/null 2>&1; then
  echo "challenge replay unexpectedly succeeded" >&2
  exit 1
fi
echo "EXPECTED_REJECTION challenge-replay"
key_id=$("$arap" fingerprint --public-key "$responder_dir/arap-public.pem")
"$arap" enrollment disable --store "$verifier_dir/enrollment.sqlite" \
  --callsign N0CALL --key-id "$key_id"
"$arap" challenge issue --requester K7DEMO --responder N0CALL \
  --store "$verifier_dir/disabled-authentication.sqlite" \
  --out "$verifier_dir/disabled-auth.cbor"
printf '%s\n' "$key_passphrase" | "$arap" challenge respond \
  --request "$verifier_dir/disabled-auth.cbor" --callsign N0CALL \
  --key "$responder_dir/arap-private.pem" --passphrase-stdin \
  --out "$responder_dir/disabled-auth-response.cose"
if "$arap" challenge verify-response --request "$verifier_dir/disabled-auth.cbor" \
  --response "$responder_dir/disabled-auth-response.cose" \
  --public-key "$responder_dir/arap-public.pem" \
  --enrollment-store "$verifier_dir/enrollment.sqlite" \
  --store "$verifier_dir/disabled-authentication.sqlite" --requester K7DEMO \
  >/dev/null 2>&1; then
  echo "disabled enrollment binding unexpectedly authenticated" >&2
  exit 1
fi
echo "EXPECTED_REJECTION disabled-binding"
echo "Synthetic enrollment, content signing, and challenge authentication completed. No live LoTW status was queried."
