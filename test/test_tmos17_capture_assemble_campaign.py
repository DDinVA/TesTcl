from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLE_CAMPAIGN_PATH = ROOT / "tools" / "tmos17-capture-assemble-campaign.py"
SPEC = importlib.util.spec_from_file_location(
    "tmos17_capture_assemble_campaign", ASSEMBLE_CAMPAIGN_PATH
)
assert SPEC is not None and SPEC.loader is not None
assemble_campaign = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assemble_campaign
SPEC.loader.exec_module(assemble_campaign)


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def _plan(case_id: str) -> dict:
    return {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": f"plan-{case_id}",
        "source": "campaign-assemble-test",
        "provenance": {
            "collector": "test",
            "tmos_build": "17.5",
            "capture_id": case_id,
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
        ],
    }


def _write_group(
    schedule_root: Path,
    records_root: Path,
    *,
    group_id: str,
    mode: str,
    case_id: str,
) -> dict:
    group_dir = schedule_root / f"group-{case_id}"
    group_dir.mkdir()
    plan_path = group_dir / "plan-0000.json"
    plan_path.write_text(json.dumps(_plan(case_id)), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "status": "ready",
        "selection": {
            "source_manifest": "source.json",
            "source_manifest_sha256": "a" * 64,
            "group_id": group_id,
            "mode": mode,
            "events": ["HTTP_REQUEST"],
        },
        "provenance": {"capture_id": case_id},
        "summary": {
            "plan_count": 1,
            "command_count": 1,
            "observation_count": 1,
            "directly_triggerable_count": 1,
            "requires_trigger_count": 0,
        },
        "plans": [
            {
                "file": "plan-0000.json",
                "command_count": 1,
                "observation_count": 1,
                "directly_triggerable_count": 1,
                "requires_trigger_count": 0,
            }
        ],
    }
    (group_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    records_dir = records_root / assemble_campaign.CAMPAIGN._group_output_name(group_id)
    records_dir.mkdir(parents=True)
    (records_dir / "records.ndjson").write_text(
        json.dumps(
            {
                "id": case_id,
                "output": {
                    "status": "ok",
                    "tcl_return_code": 0,
                    "value_base64": "",
                    "value_bytes": 0,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "id": group_id,
        "mode": mode,
        "events": ["HTTP_REQUEST"],
        "observation_ids": [case_id],
        "observation_count": 1,
        "requires_trigger": False,
        "endpoint_schemes": ["tcp"],
        "manifest": f"{group_dir.name}/manifest.json",
    }


def _write_schedule(tmp_path: Path, *, complete: bool = True) -> tuple[Path, Path]:
    schedule_root = tmp_path / "schedule-root"
    schedule_root.mkdir()
    records_root = tmp_path / "records"
    records_root.mkdir()
    groups = [
        _write_group(
            schedule_root,
            records_root,
            group_id="http1",
            mode="http1",
            case_id="case-1",
        )
    ]
    if complete:
        groups.append(
            _write_group(
                schedule_root,
                records_root,
                group_id="http2",
                mode="http2",
                case_id="case-2",
            )
        )
    schedule = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "status": "ready",
        "source": {"manifest": "source.json", "manifest_sha256": "b" * 64},
        "summary": {
            "group_count": len(groups),
            "observation_count": len(groups),
        },
        "groups": groups,
    }
    schedule_path = schedule_root / "schedule.json"
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    return schedule_path, records_root


def test_campaign_assembly_indexes_all_group_packs(tmp_path: Path) -> None:
    schedule, records_root = _write_schedule(tmp_path)
    output = tmp_path / "campaign-packs"

    result = assemble_campaign.assemble_campaign(
        schedule,
        records_root,
        output,
        tcl_lsp_root=TCL_LSP_ROOT,
        verify=True,
    )

    assert result["status"] == "assembled"
    assert result["group_count"] == 2
    assert result["plan_count"] == 2
    assert result["vector_count"] == 2
    assert result["verification_passed"] == 2
    assert result["verification_failed"] == 0
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["record_count"] == 2
    assert len(manifest["groups"]) == 2
    for group in manifest["groups"]:
        group_manifest = output / group["manifest"]
        assert group_manifest.is_file()
        group_data = json.loads(group_manifest.read_text(encoding="utf-8"))
        assert group_data["packs"]
        report = (
            output
            / "groups"
            / assemble_campaign.CAMPAIGN._group_output_name(group["id"])
            / "reports"
            / "pack-0000-verification.json"
        )
        assert json.loads(report.read_text(encoding="utf-8"))["status"] == "passed"


def test_campaign_assembly_rejects_missing_group_records(tmp_path: Path) -> None:
    schedule, records_root = _write_schedule(tmp_path, complete=False)
    schedule_data = json.loads(schedule.read_text(encoding="utf-8"))
    missing = _write_group(
        schedule.parent,
        records_root,
        group_id="http2",
        mode="http2",
        case_id="case-missing",
    )
    missing["observation_ids"] = ["case-missing"]
    missing["observation_count"] = 1
    schedule_data["groups"].append(missing)
    schedule_data["summary"] = {"group_count": 2, "observation_count": 2}
    missing_records = records_root / assemble_campaign.CAMPAIGN._group_output_name("http2")
    (missing_records / "records.ndjson").unlink()
    schedule.write_text(json.dumps(schedule_data), encoding="utf-8")
    output = tmp_path / "campaign-packs"

    with pytest.raises(assemble_campaign.CampaignAssembleError, match="records are missing"):
        assemble_campaign.assemble_campaign(
            schedule,
            records_root,
            output,
            tcl_lsp_root=TCL_LSP_ROOT,
        )
    assert not output.exists()
