#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 [campaign-assemble options...]" >&2
  exit 2
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  echo "missing repo uv environment: $python_bin" >&2
  echo "create it with: uv sync --python 3.13" >&2
  exit 2
fi
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "repo uv environment must use Python 3.13 or newer" >&2
  exit 2
fi

exec "$python_bin" "$repo_root/tools/tmos17-capture-assemble-campaign.py" "$@"
