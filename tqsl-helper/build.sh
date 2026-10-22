#!/usr/bin/env bash
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 TRUSTEDQSL_SOURCE_DIR BUILD_DIR [--fixture-importer]" >&2
  exit 2
fi
source_dir=$(cd "$1" && pwd)
build_dir=$2
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${3:-}" = "--fixture-importer" ]; then
  fixture_option=ON
elif [ "$#" -eq 3 ]; then
  echo "unknown option: $3" >&2
  exit 2
else
  fixture_option=OFF
fi
static_option=${ARAP_TQSL_STATIC:-OFF}
openssl_static_option=${ARAP_OPENSSL_STATIC:-OFF}
cmake_path() {
  case "${OSTYPE:-}" in
    msys*|cygwin*) cygpath -m "$1" ;;
    *) printf '%s\n' "$1" ;;
  esac
}
cmake_args=()
if [ -n "${CMAKE_TOOLCHAIN_FILE:-}" ]; then
  cmake_args+=("-DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE")
fi
if [ -n "${CMAKE_PREFIX_PATH:-}" ]; then
  cmake_args+=("-DCMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH")
fi
if [ -n "${VCPKG_TARGET_TRIPLET:-}" ]; then
  cmake_args+=("-DVCPKG_TARGET_TRIPLET=$VCPKG_TARGET_TRIPLET")
fi
cmake -S "$(cmake_path "$repo_dir/tqsl-helper")" -B "$(cmake_path "$build_dir")" \
  -DTQSL_SOURCE_DIR="$(cmake_path "$source_dir")" \
  -DCMAKE_BUILD_TYPE=Release \
  -DARAP_BUILD_FIXTURE_IMPORTER="$fixture_option" \
  -DTQSLLIB_STATIC="$static_option" \
  -DOPENSSL_USE_STATIC_LIBS="$openssl_static_option" \
  "${cmake_args[@]}"
cmake --build "$build_dir" --config Release --target arap-tqsl-sign --parallel
if [ -f "$build_dir/Release/arap-tqsl-sign.exe" ]; then
  cp "$build_dir/Release/arap-tqsl-sign.exe" "$build_dir/arap-tqsl-sign.exe"
fi
for runtime_library in libtqsllib.so libtqsllib.dylib; do
  if [ -f "$build_dir/tqsllib/$runtime_library" ]; then
    cp "$build_dir/tqsllib/$runtime_library" "$build_dir/$runtime_library"
  fi
done
cp "$source_dir/src/config.xml" "$build_dir/config.xml"
cp "$source_dir/src/LICENSE" "$build_dir/TQSLLIB-LICENSE.txt"
if [ "$fixture_option" = ON ]; then
  cmake --build "$build_dir" --config Release --target arap-tqsl-fixture-import --parallel
  if [ -f "$build_dir/Release/arap-tqsl-fixture-import.exe" ]; then
    cp "$build_dir/Release/arap-tqsl-fixture-import.exe" "$build_dir/arap-tqsl-fixture-import.exe"
  fi
fi
