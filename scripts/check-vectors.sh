#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

python_command="${PYTHON:-}"
if [[ -z "$python_command" && -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  python_command="$VIRTUAL_ENV/bin/python"
fi
if [[ -z "$python_command" && -x "$repo_root/.venv/bin/python" ]]; then
  python_command="$repo_root/.venv/bin/python"
fi
if [[ -z "$python_command" ]]; then
  python_command="python3"
fi

"$python_command" "$repo_root/interop/python/generate_vector.py" --out "$temp_dir/content" >/dev/null
for file in content.bin proof.cbor public-key.pem test-seed.hex manifest.json; do
  cmp "$repo_root/test-vectors/content-ed25519-v1/$file" "$temp_dir/content/$file"
done

"$python_command" "$repo_root/interop/python/generate_pixelqso_vector.py" --out "$temp_dir/pixelqso" >/dev/null
for file in first.cbor canonical.cbor manifest.json; do
  cmp "$repo_root/test-vectors/pixelqso-card-v1/$file" "$temp_dir/pixelqso/$file"
done

"$python_command" "$repo_root/interop/python/generate_challenge_vector.py" --out "$temp_dir/challenge" >/dev/null
for file in request.cbor response.cose public-key.pem manifest.json; do
  cmp "$repo_root/test-vectors/challenge-ed25519-v1/$file" "$temp_dir/challenge/$file"
done

"$python_command" "$repo_root/interop/python/generate_mutual_challenge_vector.py" "$temp_dir/mutual-challenge"
for file in request-from-a.cbor request-from-b.cbor response-from-a.cose response-from-b.cose public-key-a.der public-key-b.der manifest.json; do
  cmp "$repo_root/test-vectors/mutual-challenge-ed25519-v1/$file" "$temp_dir/mutual-challenge/$file"
done

"$python_command" "$repo_root/interop/python/generate_endorsement_vector.py" "$temp_dir/endorsement"
for file in root-to-delegate.cbor delegate-to-subject.cbor chain.cbor root-public.pem subject-public.pem manifest.json; do
  cmp "$repo_root/test-vectors/key-endorsement-v1/$file" "$temp_dir/endorsement/$file"
done

"$python_command" "$repo_root/interop/python/generate_lotw_purpose_vector.py" --out "$temp_dir/lotw-enrollment-v2" >/dev/null
for file in challenge.cbor manifest.json; do
  cmp "$repo_root/test-vectors/lotw-enrollment-v2/$file" "$temp_dir/lotw-enrollment-v2/$file"
done

printf '%s\n' 'Python-generated content, PixelQSO-card, one-way and mutual challenge, endorsement and enrollment-purpose vectors match the checked-in fixtures.'
