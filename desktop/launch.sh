#!/bin/sh
set -eu
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
  echo "ARAP desktop needs Python 3. Install Python 3, then run this launcher again." >&2
  exit 1
fi
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "ARAP desktop needs Tk 8.6. Install the Python Tk package for your Python 3 installation." >&2
  exit 1
fi
exec python3 "$bundle_dir/arap_desktop.py" "$@"
