#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
target="${1:-$(go env GOOS)-$(go env GOARCH)}"
version="${ARAP_VERSION:-dev}"
if [[ ! "$version" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  printf '%s\n' 'ARAP_VERSION may contain only letters, digits, dot, underscore, plus, and hyphen.' >&2
  exit 2
fi

case "$target" in
  linux-amd64) goos=linux; goarch=amd64; suffix= ; launcher=launch.sh ;;
  linux-arm64) goos=linux; goarch=arm64; suffix= ; launcher=launch.sh ;;
  darwin-amd64) goos=darwin; goarch=amd64; suffix= ; launcher=launch.sh ;;
  darwin-arm64) goos=darwin; goarch=arm64; suffix= ; launcher=launch.sh ;;
  windows-amd64) goos=windows; goarch=amd64; suffix=.exe; launcher=launch.bat ;;
  *)
    printf 'Unsupported bundle target: %s\n' "$target" >&2
    exit 2
    ;;
esac

commit="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)"
tqsl_version=not-included
tqsl_revision=not-included
output_dir="$repo_root/dist"
mkdir -p "$output_dir"
stage="$(mktemp -d "$output_dir/.arap-bundle-${target}.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

ldflags="-s -w -X github.com/tcarwash/arap/internal/buildinfo.Version=$version -X github.com/tcarwash/arap/internal/buildinfo.Commit=$commit"
CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "$stage/arap$suffix" ./cmd/arap
CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -buildvcs=false -ldflags="$ldflags" -o "$stage/arap-keyserver$suffix" ./cmd/arap-keyserver
cp "$repo_root/desktop/arap_desktop.py" "$stage/"
cp "$repo_root/desktop/$launcher" "$stage/"
cp "$repo_root/desktop/BUNDLE-README.md" "$stage/README.md"
cp "$repo_root/docs/FIRST-RUN.md" "$repo_root/docs/BUG_REPORT_TEMPLATE.md" "$stage/"
mkdir -p "$stage/docs" "$stage/spec" "$stage/examples/content-proof" \
  "$stage/examples/mutual-auth" "$stage/interop/python/arap_interop"
cp "$repo_root/docs/API-CAPABILITIES.md" "$repo_root/docs/MACHINE-INTERFACE.md" \
  "$repo_root/docs/IDENTITY-LIFECYCLE.md" "$repo_root/docs/CHALLENGES.md" \
  "$repo_root/docs/KEYSERVER.md" "$stage/docs/"
cp "$repo_root/interop/python/README.md" "$stage/interop/python/README.md"
cp "$repo_root/interop/python/arap_interop/"*.py "$stage/interop/python/arap_interop/"
cp "$repo_root/examples/content-proof/main.go" "$stage/examples/content-proof/"
cp "$repo_root/examples/mutual-auth/main.go" "$stage/examples/mutual-auth/"
cat >"$stage/PROJECT-README.md" <<'EOF'
# ARAP application integration

ARAP provides reusable signing, identity, enrollment and challenge operations
for applications that own their transport, storage and authorization policy.

- [Capability map](docs/API-CAPABILITIES.md)
- [Machine interface and Python wrapper](docs/MACHINE-INTERFACE.md)
- [Python consumer guide](interop/python/README.md)
- [Identity lifecycle](docs/IDENTITY-LIFECYCLE.md)
- [Content signing example](examples/content-proof/main.go)
- [Mutual authentication example](examples/mutual-auth/main.go)
- [Wire schemas](spec/)
- [Challenge operations](docs/CHALLENGES.md)
- [Keyserver operations](docs/KEYSERVER.md)

The first-run guide and beta limitations are in `FIRST-RUN.md`. Experimental
TQSL enrollment is supported only by the Linux amd64 bundle and is not an
ARRL-approved login or LoTW transaction.
EOF
cp \
  "$repo_root/spec/ARAP-profile-v1.cddl" \
  "$repo_root/spec/ARAP-challenge-v1.cddl" \
  "$repo_root/spec/ARAP-challenge-response-v1.cddl" \
  "$repo_root/spec/ARAP-lotw-enrollment-v1.cddl" \
  "$repo_root/spec/ARAP-lotw-enrollment-v2.cddl" \
  "$repo_root/spec/ARAP-lotw-enrollment-response-v1.cddl" \
  "$repo_root/spec/ARAP-key-endorsement-v1.cddl" \
  "$repo_root/spec/ARAP-key-endorsement-chain-v1.cddl" \
  "$repo_root/spec/ARAP-machine-error-v1.schema.json" \
  "$repo_root/spec/PixelQSO-card-v1.cddl" \
  "$stage/"
cp "$repo_root/spec/"*.cddl "$repo_root/spec/ARAP-machine-error-v1.schema.json" "$stage/spec/"

if [[ -n "${ARAP_TQSL_HELPER_DIR:-}" ]]; then
  helper_dir="$ARAP_TQSL_HELPER_DIR"
  helper_name="arap-tqsl-sign$suffix"
  if [[ ! -f "$helper_dir/$helper_name" ]]; then
    printf 'Native TQSL helper is missing: %s\n' "$helper_dir/$helper_name" >&2
    exit 2
  fi
  if [[ "$goos" != windows && ! -x "$helper_dir/$helper_name" ]]; then
    printf 'Native TQSL helper is not executable: %s\n' "$helper_dir/$helper_name" >&2
    exit 2
  fi
  [[ -f "$helper_dir/config.xml" ]] || { printf '%s\n' 'Native TQSL helper config.xml is missing.' >&2; exit 2; }
  [[ -f "$helper_dir/TQSLLIB-LICENSE.txt" ]] || { printf '%s\n' 'Native TQSL helper license notice is missing.' >&2; exit 2; }
  cp "$helper_dir/$helper_name" "$stage/"
  cp "$helper_dir/config.xml" "$stage/"
  cp "$helper_dir/TQSLLIB-LICENSE.txt" "$stage/"
  if [[ -d "$helper_dir/GO-DEPENDENCY-NOTICES" ]]; then
    cp -R "$helper_dir/GO-DEPENDENCY-NOTICES" "$stage/"
  fi
  if [[ -f "$helper_dir/GO-DEPENDENCY-NOTICES.csv" ]]; then
    cp "$helper_dir/GO-DEPENDENCY-NOTICES.csv" "$stage/"
  fi
  if [[ -f "$helper_dir/OPENSSL-LICENSE.txt" ]]; then cp "$helper_dir/OPENSSL-LICENSE.txt" "$stage/"; fi
  if [[ -f "$helper_dir/VCPKG-DEPENDENCY-NOTICES.txt" ]]; then cp "$helper_dir/VCPKG-DEPENDENCY-NOTICES.txt" "$stage/"; fi
  if [[ -f "$helper_dir/libtqsllib.so" ]]; then cp "$helper_dir/libtqsllib.so" "$stage/"; fi
  if [[ -f "$helper_dir/libtqsllib.dylib" ]]; then cp "$helper_dir/libtqsllib.dylib" "$stage/"; fi
  if [[ "$goos" == darwin ]]; then
    for dylib in "$helper_dir"/*.dylib; do
      if [[ -f "$dylib" ]]; then cp "$dylib" "$stage/"; fi
    done
  fi
  tqsl_version=${TQSL_VERSION:-unknown}
  tqsl_revision=${TQSL_REVISION:-unknown}
elif [[ "$target" == linux-amd64 ]]; then
  trustedqsl_revision=1916fc14a8cfc7f287742ae5a34aa986353d9df7
  trustedqsl_source=${TRUSTEDQSL_SOURCE_DIR:-}
  if [[ -z "$trustedqsl_source" && -f /tmp/arap-tqsl-source/src/tqsllib.h ]]; then
    trustedqsl_source=/tmp/arap-tqsl-source
  fi
  if [[ -z "$trustedqsl_source" ]]; then
    trustedqsl_source="$stage/.trustedqsl-source"
    git clone --filter=blob:none --no-checkout https://git.code.sf.net/p/trustedqsl/tqsl "$trustedqsl_source"
    git -C "$trustedqsl_source" fetch --depth 1 origin "$trustedqsl_revision"
    git -C "$trustedqsl_source" checkout --detach "$trustedqsl_revision"
  fi
  actual_revision=$(git -C "$trustedqsl_source" rev-parse HEAD 2>/dev/null || true)
  if [[ "$actual_revision" != "$trustedqsl_revision" ]]; then
    printf 'TrustedQSL source revision mismatch: expected %s, got %s\n' "$trustedqsl_revision" "${actual_revision:-unknown}" >&2
    exit 2
  fi
  tqsl_version=$(tr -d '\r\n' < "$trustedqsl_source/apps/tqslversion.ver")
  if [[ "$tqsl_version" != "2.8.7" ]]; then
    printf '%s\n' 'TrustedQSL source has an unexpected version file.' >&2
    exit 2
  fi
  tqsl_revision=$actual_revision
  tqsl_build="$stage/.trustedqsl-build"
  "$repo_root/tqsl-helper/build.sh" "$trustedqsl_source" "$tqsl_build"
  cp "$tqsl_build/arap-tqsl-sign" "$stage/"
  cp "$tqsl_build/tqsllib/libtqsllib.so" "$stage/"
  cp "$tqsl_build/config.xml" "$stage/"
  cp "$tqsl_build/TQSLLIB-LICENSE.txt" "$stage/"
  rm -rf -- "$tqsl_build" "$stage/.trustedqsl-source"
fi

if [[ "$launcher" == launch.sh ]]; then
  chmod +x "$stage/arap" "$stage/arap-keyserver"
  chmod +x "$stage/launch.sh"
  mv "$stage/launch.sh" "$stage/arap-desktop.sh"
else
  mv "$stage/launch.bat" "$stage/arap-desktop.bat"
fi

cat >"$stage/BUILD-MANIFEST.txt" <<EOF
ARAP version: $version
Target: $target
Git base commit: $commit
Go toolchain: $(go version)
TQSL/TQSLLIB version: $tqsl_version
TrustedQSL source commit: $tqsl_revision
Source files: checkout contents at packaging time
Worktree may contain uncommitted changes.
EOF

archive="$output_dir/arap-desktop-${target}-${version}.zip"
python_command=python3
if ! command -v "$python_command" >/dev/null 2>&1; then
  python_command=python
fi
"$python_command" - "$stage" "$archive" <<'PY'
import pathlib
import stat
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for item in sorted(source.rglob("*")):
        if not item.is_file():
            continue
        info = zipfile.ZipInfo(item.relative_to(source).as_posix())
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = item.stat().st_mode
        info.external_attr = (stat.S_IFREG | stat.S_IMODE(mode)) << 16
        bundle.writestr(info, item.read_bytes())
print(destination)
PY
