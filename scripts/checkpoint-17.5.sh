#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"
tcl_lsp_root=${TCL_LSP_ROOT:-}
report_file=$(mktemp -t testcl-17.5-checkpoint.XXXXXX)
coverage_file=$(mktemp -t testcl-17.5-coverage.XXXXXX)

cleanup() {
  rm -f "$report_file"
  rm -f "$coverage_file"
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
echo "== TMOS 17.5 behavior-input coverage =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/emulate-irule.sh" \
  --behavior-coverage >"$coverage_file"
"$python_bin" - "$coverage_file" <<'PY'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
summary = report.get("summary", {})
if report.get("status") != "ok":
    raise SystemExit("behavior coverage report did not complete successfully")
target = summary.get("target_f5_command_count")
covered = summary.get("covered_command_count")
if not isinstance(target, int) or not isinstance(covered, int) or covered != target:
    raise SystemExit(
        f"behavior-input coverage is incomplete: {covered!r}/{target!r} commands"
    )
print(json.dumps({
    "target_f5_command_count": target,
    "covered_command_count": covered,
    "coverage_percent": summary.get("coverage_percent"),
    "behavior_pack_count": summary.get("behavior_pack_count"),
    "case_count": summary.get("case_count"),
    "runtime_status_counts": summary.get("runtime_status_counts"),
}, indent=2, sort_keys=True))
PY

echo
echo "== TMOS 17.5 real-client smoke tests =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/live-all-observation-smoke.sh"

echo
echo "TMOS 17.5 checkpoint passed."
