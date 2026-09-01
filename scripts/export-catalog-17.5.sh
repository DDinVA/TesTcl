#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 OUTPUT_DIR [catalog-export options...]" >&2
  exit 2
fi
if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi
if ! "$python_bin" -c 'import tkinter; tkinter.Tcl()' >/dev/null 2>&1; then
  echo "TesTcl requires Tcl/Tk support in $python_bin" >&2
  exit 2
fi

output_dir=$1
shift
exec "$python_bin" "$repo_root/tools/catalog-export.py" \
  --output-dir "$output_dir" "$@"
