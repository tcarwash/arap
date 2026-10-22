#!/bin/sh
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
cmake -S "$repo_dir/tqsl-helper" -B "$build_dir" -DTQSL_SOURCE_DIR="$source_dir" -DCMAKE_BUILD_TYPE=Release -DARAP_BUILD_FIXTURE_IMPORTER="$fixture_option"
cmake --build "$build_dir" --target arap-tqsl-sign --parallel
cp "$source_dir/src/config.xml" "$build_dir/config.xml"
if [ "$fixture_option" = ON ]; then
  cmake --build "$build_dir" --target arap-tqsl-fixture-import --parallel
fi
