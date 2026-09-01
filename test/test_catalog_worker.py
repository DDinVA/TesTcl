from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "tools" / "catalog-worker.py"
SPEC = importlib.util.spec_from_file_location("testcl_catalog_worker", WORKER_PATH)
assert SPEC is not None and SPEC.loader is not None
worker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = worker
SPEC.loader.exec_module(worker)


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def _export_chunk(tmp_path: Path, size: int = 2, namespace: str | None = "HTTP") -> Path:
    exporter_path = ROOT / "tools" / "catalog-export.py"
    spec = importlib.util.spec_from_file_location("testcl_catalog_export_for_worker", exporter_path)
    assert spec is not None and spec.loader is not None
    exporter = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = exporter
    spec.loader.exec_module(exporter)
    output = tmp_path / "catalog"
    exporter.export_catalog(
        output_dir=output,
        tcl_lsp_root=TCL_LSP_ROOT,
        chunk_size=size,
        namespace=namespace,
        target_status="available-in-tmos-17.5",
    )
    return output / "chunks" / "chunk-0000.json"


def test_worker_consumes_chunk_and_emits_local_results_and_external_plan(tmp_path: Path) -> None:
    chunk_path = _export_chunk(tmp_path)
    chunk = worker._read_chunk(chunk_path)
    report = worker._build_report(
        chunk, tcl_lsp_root=TCL_LSP_ROOT, variants=1, mode="both"
    )

    assert report["profile"] == "tmos-17.5"
    assert report["summary"]["input_command_count"] == 2
    assert report["summary"]["generated_command_count"] == 2
    assert report["summary"]["capture_observation_count"] == 2
    assert report["summary"]["local_status_counts"] == {"ok": 2}
    assert report["capture_plan"]["observations"]
    for row in report["commands"]:
        assert row["variants"][0]["local_status"] == "ok"
        assert "state" not in row["variants"][0]["capture_input"]
        assert "scenario" not in row["variants"][0]["capture_input"]


def test_worker_keeps_command_ids_stable_and_can_skip_excluded_commands(
    tmp_path: Path,
) -> None:
    chunk_path = _export_chunk(tmp_path)
    chunk = worker._read_chunk(chunk_path)
    report = worker._build_report(
        chunk,
        tcl_lsp_root=TCL_LSP_ROOT,
        variants=1,
        mode="plan",
        exclude_commands={"HTTP::class"},
    )

    skipped = next(row for row in report["commands"] if row["command"] == "HTTP::class")
    assert skipped["id"] == "catalog:HTTP::class"
    assert skipped["generation_status"] == "skipped-collector-safety"
    assert all(
        observation["id"] != "catalog:HTTP::class:variant:1"
        for observation in report["capture_plan"]["observations"]
    )


def test_worker_rejects_variant_plan_over_collector_bound(tmp_path: Path) -> None:
    chunk_path = _export_chunk(tmp_path, size=33, namespace=None)
    chunk = worker._read_chunk(chunk_path)
    with pytest.raises(worker.CatalogWorkerError, match="more than 256"):
        worker._build_report(
            chunk, tcl_lsp_root=TCL_LSP_ROOT, variants=8, mode="plan"
        )


def test_worker_rejects_duplicate_command_names(tmp_path: Path) -> None:
    chunk_path = _export_chunk(tmp_path)
    chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
    chunk["commands"][1]["name"] = chunk["commands"][0]["name"]
    chunk_path.write_text(json.dumps(chunk), encoding="utf-8")
    with pytest.raises(worker.CatalogWorkerError, match="duplicate name"):
        worker._read_chunk(chunk_path)


def test_worker_consumes_non_f5_catalog_entries_as_non_runnable_rows(tmp_path: Path) -> None:
    chunk_path = _export_chunk(tmp_path)
    chunk = json.loads(chunk_path.read_text(encoding="utf-8"))
    chunk["commands"][0]["catalog_kind"] = "tcl-core"
    chunk_path.write_text(json.dumps(chunk), encoding="utf-8")

    report = worker._build_report(
        worker._read_chunk(chunk_path),
        tcl_lsp_root=TCL_LSP_ROOT,
        variants=1,
        mode="plan",
    )
    assert report["summary"]["input_command_count"] == 2
    assert report["summary"]["target_command_count"] == 1
    assert report["summary"]["non_f5_command_count"] == 1
    skipped = next(row for row in report["commands"] if row["catalog_kind"] == "tcl-core")
    assert skipped["generation_status"] == "skipped-non-f5-catalog"
