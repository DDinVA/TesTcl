#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIR" >&2
  exit 2
fi

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi
if [[ -z "${TCL_LSP_ROOT:-}" ]]; then
  echo "Set TCL_LSP_ROOT to the pinned tcl-lsp checkout" >&2
  exit 2
fi

output_root=$1
if [[ -e "$output_root" || -L "$output_root" ]]; then
  echo "output directory already exists: $output_root" >&2
  exit 2
fi
mkdir -p "$output_root"

catalog_dir="$output_root/catalog"
report_dir="$output_root/local-reports"
batch_dir="$output_root/capture-batch"
scheduled_dir="$output_root/scheduled-batches"
campaign_report="$output_root/campaign-plan.json"
mkdir -p "$report_dir"

echo "== Export TMOS 17.5 catalog =="
TCL_LSP_ROOT="$TCL_LSP_ROOT" "$repo_root/scripts/export-catalog-17.5.sh" \
  "$catalog_dir" \
  --chunk-size 250 \
  --target-status available-in-tmos-17.5

echo "== Evaluate every catalog chunk locally =="
chunks=("$catalog_dir"/chunks/chunk-*.json)
if [[ ! -e "${chunks[0]}" ]]; then
  echo "catalog export produced no chunks" >&2
  exit 1
fi
for chunk in "${chunks[@]}"; do
  chunk_name=${chunk##*/}
  report_name=${chunk_name%.json}.report.json
  TCL_LSP_ROOT="$TCL_LSP_ROOT" "$repo_root/scripts/catalog-worker-17.5.sh" \
    "$chunk" \
    --mode both \
    --variants 1 \
    --output "$report_dir/$report_name"
done

echo "== Build capture batch =="
TCL_LSP_ROOT="$TCL_LSP_ROOT" "$repo_root/scripts/catalog-capture-batch-17.5.sh" \
  "$catalog_dir" "$batch_dir" \
  --variants 1 \
  --capture-id local-checkpoint

echo "== Split by protocol and event stimulus =="
TCL_LSP_ROOT="$TCL_LSP_ROOT" "$python_bin" \
  "$repo_root/tools/tmos17-capture-split.py" \
  --manifest "$batch_dir/manifest.json" \
  --output-dir "$scheduled_dir"

echo "== Plan external campaign without device access =="
TCL_LSP_ROOT="$TCL_LSP_ROOT" "$repo_root/scripts/tmos17-capture-campaign-17.5.sh" \
  --schedule "$scheduled_dir/schedule.json" \
  > "$campaign_report"

"$python_bin" - "$output_root" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
catalog = json.loads((root / "catalog" / "manifest.json").read_text(encoding="utf-8"))
batch = json.loads((root / "capture-batch" / "manifest.json").read_text(encoding="utf-8"))
campaign = json.loads((root / "campaign-plan.json").read_text(encoding="utf-8"))
reports = sorted((root / "local-reports").glob("chunk-*.report.json"))
if not reports:
    raise SystemExit("local evaluation produced no reports")
local_ok = 0
local_total = 0
target_total = 0
for report_path in reports:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    counts = report["summary"]["local_status_counts"]
    local_ok += counts.get("ok", 0)
    local_total += sum(counts.values())
    target_total += report["summary"]["target_command_count"]

batch_summary = batch["summary"]
campaign_summary = campaign["summary"]
if local_total != target_total:
    raise SystemExit("local reports do not cover their target command counts")
if local_ok != target_total:
    raise SystemExit("one or more catalog commands failed local evaluation")
if batch_summary["target_command_count"] != target_total:
    raise SystemExit("capture batch target count does not match local evaluation")
if batch_summary["observation_count"] != batch_summary["capturable_command_count"]:
    raise SystemExit("capture batch observation count does not match capturable commands")
if campaign_summary["observation_count"] != batch_summary["observation_count"]:
    raise SystemExit("campaign plan does not cover the capture batch")
if campaign_summary["planned_group_count"] != campaign_summary["group_count"]:
    raise SystemExit("campaign plan did not plan every scheduled group")

summary = {
    "status": "passed",
    "profile": "tmos-17.5",
    "output_dir": str(root.resolve()),
    "catalog": {
        "chunk_count": catalog["chunking"]["chunk_count"],
        "filtered_command_count": catalog["summary"]["filtered_command_count"],
    },
    "local_evaluation": {
        "chunk_count": len(reports),
        "ok_count": local_ok,
        "evaluated_count": local_total,
    },
    "capture_batch": batch_summary,
    "campaign": campaign_summary,
    "interpretation": (
        "Local results are emulator diagnostics. Capture plans remain reference-free "
        "until an authorized TMOS 17.5 or vLab run returns observations."
    ),
}
print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
PY
