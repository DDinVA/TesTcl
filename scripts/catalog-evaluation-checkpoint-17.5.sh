#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"
tcl_lsp_root=${TCL_LSP_ROOT:-$repo_root/.cache/tcl-lsp-17.5}
work_dir=$(mktemp -d -t testcl-catalog-checkpoint.XXXXXX)

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi

if [[ ! -d "$tcl_lsp_root" ]]; then
  echo "Pinned tcl-lsp checkout not found: $tcl_lsp_root" >&2
  echo "Run ./scripts/setup-17.5.sh or set TCL_LSP_ROOT explicitly" >&2
  exit 2
fi

catalog_dir="$work_dir/catalog"
batch_dir="$work_dir/batch"
report_dir="$work_dir/reports"
mkdir -p "$report_dir"

echo "== Export target catalog =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/export-catalog-17.5.sh" \
  "$catalog_dir" \
  --chunk-size 250 \
  --target-status available-in-tmos-17.5

echo "== Evaluate every exported chunk locally =="
chunks=("$catalog_dir"/chunks/chunk-*.json)
if [[ ! -e "${chunks[0]}" ]]; then
  echo "catalog export produced no chunk files" >&2
  exit 1
fi
for chunk in "${chunks[@]}"; do
  chunk_name=${chunk##*/}
  report_name=${chunk_name%.json}.report.json
  TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/catalog-worker-17.5.sh" \
    "$chunk" \
    --mode both \
    --variants 1 \
    --output "$report_dir/$report_name" >/dev/null
done

echo "== Build external capture batch =="
TCL_LSP_ROOT="$tcl_lsp_root" "$repo_root/scripts/catalog-capture-batch-17.5.sh" \
  "$catalog_dir" "$batch_dir" \
  --variants 1 \
  --capture-id catalog-checkpoint >/dev/null

"$python_bin" - "$catalog_dir" "$batch_dir" "$report_dir" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

catalog_dir, batch_dir, report_dir = map(Path, sys.argv[1:])
catalog = json.loads((catalog_dir / "manifest.json").read_text(encoding="utf-8"))
batch = json.loads((batch_dir / "manifest.json").read_text(encoding="utf-8"))
reports = [
    json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(report_dir.glob("chunk-*.report.json"))
]
if not reports:
    raise SystemExit("catalog evaluation produced no worker reports")

local_statuses = Counter()
generation_statuses = Counter()
for report in reports:
    summary = report["summary"]
    local_statuses.update(summary["local_status_counts"])
    generation_statuses.update(summary["generation_status_counts"])

target_command_count = sum(
    report["summary"]["target_command_count"] for report in reports
)
if generation_statuses.get("ready", 0) != target_command_count:
    raise SystemExit(
        "worker did not generate every target F5 command: "
        f"{generation_statuses.get('ready', 0)!r}/{target_command_count!r}"
    )
if local_statuses != Counter({"ok": target_command_count}):
    raise SystemExit(
        "local catalog evaluation was not entirely successful: "
        f"{dict(sorted(local_statuses.items()))!r}"
    )

catalog_summary = catalog["summary"]
batch_summary = batch["summary"]
if batch_summary["source_catalog_command_count"] != catalog_summary["filtered_command_count"]:
    raise SystemExit("capture batch does not cover the exported catalog")
if batch_summary["target_command_count"] != target_command_count:
    raise SystemExit("capture batch target count does not match worker evaluation")
if (
    batch_summary["capturable_command_count"]
    + batch_summary["collector_blocked_command_count"]
    != target_command_count
):
    raise SystemExit("capture batch target commands are not fully accounted for")
if batch_summary["observation_count"] != batch_summary["capturable_command_count"]:
    raise SystemExit("capture batch observation count does not match capturable commands")
if batch_summary["bundled_driver_preflight_failures"]:
    raise SystemExit("capture batch contains bundled driver preflight failures")

print(json.dumps({
    "status": "passed",
    "profile": "tmos-17.5",
    "catalog": catalog["summary"],
    "worker": {
        "chunk_count": len(reports),
        "target_command_count": target_command_count,
        "local_status_counts": dict(sorted(local_statuses.items())),
        "generation_status_counts": dict(sorted(generation_statuses.items())),
    },
    "capture_batch": batch["summary"],
    "interpretation": (
        "Local results are emulator diagnostics. The capture batch is a "
        "reference-free plan until an authorized TMOS 17.5 collector returns records."
    ),
}, indent=2, sort_keys=True))
PY
