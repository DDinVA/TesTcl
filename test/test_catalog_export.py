from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXPORT_PATH = ROOT / "tools" / "catalog-export.py"
SPEC = importlib.util.spec_from_file_location("testcl_catalog_export", EXPORT_PATH)
assert SPEC is not None and SPEC.loader is not None
exporter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = exporter
SPEC.loader.exec_module(exporter)


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def test_export_materializes_hashed_complete_catalog_chunks(tmp_path: Path) -> None:
    output = tmp_path / "catalog"
    result = exporter.export_catalog(
        output_dir=output,
        tcl_lsp_root=TCL_LSP_ROOT,
        chunk_size=37,
        target_status="available-in-tmos-17.5",
    )

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert result["status"] == "ok"
    assert manifest["profile"] == "tmos-17.5"
    assert manifest["summary"]["filtered_command_count"] == 1477
    assert manifest["chunking"]["command_count"] == 1477
    assert len(manifest["files"]["chunks"]) == 40

    names: list[str] = []
    for info in manifest["files"]["chunks"]:
        chunk_path = output / info["file"]
        raw = chunk_path.read_bytes()
        assert exporter.hashlib.sha256(raw).hexdigest() == info["sha256"]
        chunk = json.loads(raw.decode("utf-8"))
        assert chunk["chunk"]["count"] == len(chunk["commands"])
        names.extend(command["name"] for command in chunk["commands"])
    assert len(names) == len(set(names)) == 1477


def test_export_refuses_existing_output_without_touching_it(tmp_path: Path) -> None:
    output = tmp_path / "catalog"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(exporter.CatalogExportError, match="already exists"):
        exporter.export_catalog(
            output_dir=output,
            tcl_lsp_root=TCL_LSP_ROOT,
            chunk_size=64,
        )
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_export_refuses_a_broken_output_symlink(tmp_path: Path) -> None:
    output = tmp_path / "catalog-link"
    output.symlink_to(tmp_path / "missing-target", target_is_directory=True)
    with pytest.raises(exporter.CatalogExportError, match="must not be a symlink"):
        exporter.export_catalog(
            output_dir=output,
            tcl_lsp_root=TCL_LSP_ROOT,
            chunk_size=64,
        )
