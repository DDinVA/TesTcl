from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLE_PATH = ROOT / "tools" / "tmos17-capture-assemble.py"
SPEC = importlib.util.spec_from_file_location("tmos17_capture_assemble", ASSEMBLE_PATH)
assert SPEC is not None and SPEC.loader is not None
assemble = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assemble
SPEC.loader.exec_module(assemble)


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def _plan(*ids: str) -> dict:
    return {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": "assemble-test",
        "source": "test-tmos-17.5",
        "provenance": {
            "collector": "test",
            "tmos_build": "17.5",
            "capture_id": "assemble-test",
        },
        "observations": [
            {
                "id": case_id,
                "operation": "command_probe",
                "input": {
                    "command": "HTTP::host",
                    "args": [],
                    "event": "HTTP_REQUEST",
                    "profiles": ["TCP", "HTTP"],
                    "request": {
                        "method": "GET",
                        "uri": "/health",
                        "host": "example.test",
                    },
                },
                "comparisons": [
                    {
                        "label": "status",
                        "actual_path": ["execution", "status"],
                        "reference_path": ["status"],
                    }
                ],
            }
            for case_id in ids
        ],
    }


def _write_batch(
    directory: Path, plan_ids: tuple[tuple[str, ...], ...] = (("case-0",),)
) -> tuple[Path, Path]:
    plans: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    for index, ids in enumerate(plan_ids):
        plan_path = directory / f"plan-{index:04d}.json"
        plan_path.write_text(json.dumps(_plan(*ids)), encoding="utf-8")
        plans.append({"file": plan_path.name, "command_count": len(ids)})
        records.extend(
            {
                "id": case_id,
                "output": {
                    "status": "ok",
                    "tcl_return_code": 0,
                    "value_base64": "",
                    "value_bytes": 0,
                },
            }
            for case_id in ids
        )
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile": "tmos-17.5",
                "status": "ready-for-external-capture",
                "plans": plans,
            }
        ),
        encoding="utf-8",
    )
    records_path = directory / "records.ndjson"
    records_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    return manifest_path, records_path


def test_batch_assembly_writes_one_pack_per_plan_and_verifies(
    tmp_path: Path,
) -> None:
    manifest, records = _write_batch(tmp_path, (("case-0",), ("case-1",)))
    output = tmp_path / "assembled"

    result = assemble.assemble_batch(
        manifest,
        records,
        output,
        tcl_lsp_root=TCL_LSP_ROOT,
        verify=True,
    )

    assert result["status"] == "assembled"
    assert result["plan_count"] == 2
    assert result["vector_count"] == 2
    output_manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert output_manifest["summary"]["verification_passed"] == 2
    assert [pack["file"] for pack in output_manifest["packs"]] == [
        "pack-0000.json",
        "pack-0001.json",
    ]
    for pack in output_manifest["packs"]:
        assert json.loads((output / pack["file"]).read_text(encoding="utf-8"))["vectors"]
        report = output / pack["verification"]["report"]
        assert json.loads(report.read_text(encoding="utf-8"))["status"] == "passed"


def test_batch_assembly_rejects_incomplete_records_before_writing(
    tmp_path: Path,
) -> None:
    manifest, records = _write_batch(tmp_path, (("case-0", "case-1"),))
    records.write_text(
        '{"id":"case-0","output":{"status":"ok","tcl_return_code":0,"value_base64":"","value_bytes":0}}\n',
        encoding="utf-8",
    )
    output = tmp_path / "assembled"

    with pytest.raises(assemble.AssembleError, match="missing records"):
        assemble.assemble_batch(manifest, records, output, tcl_lsp_root=TCL_LSP_ROOT)
    assert not output.exists()


def test_batch_assembly_refuses_existing_output_directory(tmp_path: Path) -> None:
    manifest, records = _write_batch(tmp_path)
    output = tmp_path / "assembled"
    output.mkdir()
    sentinel = output / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(assemble.AssembleError, match="already exists"):
        assemble.assemble_batch(manifest, records, output, tcl_lsp_root=TCL_LSP_ROOT)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_batch_assembly_preserves_failed_differential_report(tmp_path: Path) -> None:
    manifest, records = _write_batch(tmp_path)
    records.write_text(
        '{"id":"case-0","output":{"status":"error","tcl_return_code":1,"value_base64":null,"value_bytes":0}}\n',
        encoding="utf-8",
    )
    output = tmp_path / "assembled"

    result = assemble.assemble_batch(
        manifest,
        records,
        output,
        tcl_lsp_root=TCL_LSP_ROOT,
        verify=True,
    )

    assert result["status"] == "assembled-with-verification-failures"
    report = json.loads(
        (output / "reports" / "pack-0000-verification.json").read_text(encoding="utf-8")
    )
    assert report["status"] == "failed"
    assert report["analysis"]["comparison_failed"] == 1
