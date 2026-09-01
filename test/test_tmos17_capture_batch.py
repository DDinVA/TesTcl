from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BATCH_PATH = ROOT / "tools" / "tmos17-capture-batch.py"
SPEC = importlib.util.spec_from_file_location("tmos17_capture_batch", BATCH_PATH)
assert SPEC is not None and SPEC.loader is not None
batch = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = batch
SPEC.loader.exec_module(batch)


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def test_batch_materializes_complete_tmos_catalog_with_collector_preflight(tmp_path: Path) -> None:
    output_dir = tmp_path / "capture-batch"
    manifest = batch.build_batch(
        tcl_lsp_root=TCL_LSP_ROOT,
        output_dir=output_dir,
        variants=1,
    )

    assert manifest["status"] == "ready-with-collector-blocks"
    assert manifest["summary"]["command_count"] == 989
    assert manifest["summary"]["capturable_command_count"] == 986
    assert manifest["summary"]["collector_blocked_command_count"] == 3
    assert manifest["summary"]["observation_count"] == 986
    assert manifest["summary"]["plan_count"] == 4
    assert manifest["summary"]["requires_trigger_count"] > 0
    assert sum(manifest["summary"]["event_counts"].values()) == 986

    on_disk = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert on_disk == manifest
    blocked = json.loads(
        (output_dir / "blocked-catalog.json").read_text(encoding="utf-8")
    )
    assert len(blocked["commands"]) == 3
    assert {item["name"] for item in blocked["commands"]} == {"after", "close", "proc"}
    for plan_info in manifest["plans"]:
        plan = json.loads(
            (output_dir / plan_info["file"]).read_text(encoding="utf-8")
        )
        validated = batch.COLLECTOR.validate_plan(plan)
        assert len(validated["observations"]) == plan_info["observation_count"]


def test_batch_variants_choose_collector_safe_chunk_size(tmp_path: Path) -> None:
    output_dir = tmp_path / "capture-batch-v2"
    manifest = batch.build_batch(
        tcl_lsp_root=TCL_LSP_ROOT,
        output_dir=output_dir,
        namespace="TCP",
        variants=2,
    )
    assert manifest["selection"]["chunk_size"] == 128
    assert all(
        plan["observation_count"] <= batch.EMULATOR.CAPTURE_MAX_RECORDS
        for plan in manifest["plans"]
    )
    first_plan = json.loads(
        (output_dir / manifest["plans"][0]["file"]).read_text(encoding="utf-8")
    )
    assert first_plan["provenance"]["variants"] == 2


def test_batch_rejects_existing_output_and_oversized_variant_chunk(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(batch.BatchError, match="already exists"):
        batch.build_batch(tcl_lsp_root=TCL_LSP_ROOT, output_dir=existing)

    with pytest.raises(batch.BatchError, match="between 1 and 32"):
        batch.build_batch(
            tcl_lsp_root=TCL_LSP_ROOT,
            output_dir=tmp_path / "invalid",
            variants=8,
            chunk_size=33,
        )
