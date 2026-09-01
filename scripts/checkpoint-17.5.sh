#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"
tcl_lsp_root=${TCL_LSP_ROOT:-}
report_file=$(mktemp -t testcl-17.5-checkpoint.XXXXXX)

cleanup() {
  rm -f "$report_file"
}
trap cleanup EXIT

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi

if [[ -z "$tcl_lsp_root" ]]; then
  echo "Set TCL_LSP_ROOT to the pinned tcl-lsp checkout (for example /tmp/tcl-lsp)" >&2
  exit 2
fi

echo "== TMOS 17.5 local contracts =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/evaluate-local.sh" \
  --tcl-lsp-root "$tcl_lsp_root" >"$report_file"
"$python_bin" - "$report_file" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps({
    "status": report.get("status"),
    "profile": report.get("profile"),
    "summary": report.get("summary"),
}, indent=2, sort_keys=True))
PY

echo
echo "== TMOS 17.5 real-client smoke tests =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/live-all-observation-smoke.sh"

echo
echo "TMOS 17.5 checkpoint passed."
