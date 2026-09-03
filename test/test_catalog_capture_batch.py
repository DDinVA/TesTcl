from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPORT_PATH = ROOT / "tools" / "catalog-export.py"
BATCH_PATH = ROOT / "tools" / "catalog-capture-batch.py"
RUNNER_PATH = ROOT / "tools" / "tmos17-capture-runner.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


exporter = _load(EXPORT_PATH, "testcl_catalog_export_for_capture_batch")
batch = _load(BATCH_PATH, "testcl_catalog_capture_batch")
runner = _load(RUNNER_PATH, "testcl_catalog_capture_runner_for_catalog_batch")
TCL_LSP_ROOT = "/tmp/tcl-lsp"


def _catalog(tmp_path: Path) -> Path:
    output = tmp_path / "catalog"
    exporter.export_catalog(
        output_dir=output,
        tcl_lsp_root=TCL_LSP_ROOT,
        chunk_size=3,
        namespace="HTTP",
        target_status="available-in-tmos-17.5",
    )
    return output


def test_build_batch_uses_verified_exported_chunks(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    output = tmp_path / "capture-batch"

    manifest = batch.build_batch_from_catalog(
        catalog_dir=catalog,
        output_dir=output,
        tcl_lsp_root=TCL_LSP_ROOT,
        variants=1,
        capture_id="http-exported",
    )

    assert manifest["status"] == "ready-for-external-capture"
    assert manifest["source_catalog"]["chunk_count"] == 11
    assert manifest["summary"]["target_command_count"] == 32
    assert manifest["summary"]["capturable_command_count"] == 32
    assert manifest["summary"]["collector_blocked_command_count"] == 0
    assert manifest["summary"]["observation_count"] == 32
    loaded, entries, _ = runner._load_batch(output / "manifest.json")
    assert loaded["source_catalog"]["manifest_sha256"] == manifest["source_catalog"]["manifest_sha256"]
    assert len(entries) == manifest["summary"]["plan_count"]
    assert all(entry.observation_count <= 256 for entry in entries)
    blocked = json.loads((output / "blocked-catalog.json").read_text(encoding="utf-8"))
    assert blocked["commands"] == []


def test_build_batch_rejects_a_tampered_exported_chunk(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    chunk = catalog / "chunks" / "chunk-0000.json"
    chunk.write_text(chunk.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(batch.CatalogBatchError, match="hash mismatch"):
        batch.build_batch_from_catalog(
            catalog_dir=catalog,
            output_dir=tmp_path / "capture-batch",
            tcl_lsp_root=TCL_LSP_ROOT,
        )


def test_build_batch_refuses_existing_output(tmp_path: Path) -> None:
    catalog = _catalog(tmp_path)
    output = tmp_path / "capture-batch"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(batch.CatalogBatchError, match="already exists"):
        batch.build_batch_from_catalog(
            catalog_dir=catalog,
            output_dir=output,
            tcl_lsp_root=TCL_LSP_ROOT,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep"
