#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 CATALOG_DIR OUTPUT_DIR [catalog-capture-batch options...]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="$repo_root/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  echo "missing repo uv environment: $python_bin" >&2
  echo "create it with: uv venv --python 3.13 \"$repo_root/.venv\"" >&2
  exit 1
fi
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "repo uv environment must use Python 3.13 or newer" >&2
  exit 1
fi

catalog_dir="$1"
output_dir="$2"
shift 2
exec "$python_bin" "$repo_root/tools/catalog-capture-batch.py" \
  --catalog-dir "$catalog_dir" \
  --output-dir "$output_dir" \
  "$@"
