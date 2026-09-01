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


def test_driver_preflight_does_not_require_network_for_rule_init() -> None:
    result = batch._driver_preflight(
        {"id": "command_probe:test", "input": {"event": "RULE_INIT"}}
    )
    assert result == {
        "id": "command_probe:test",
        "event": "RULE_INIT",
        "mode": "none",
        "status": "not-required",
        "event_supported": False,
    }


def test_profile_driven_events_get_http_capture_fixtures() -> None:
    assert batch.EMULATOR._capture_plan_request_template(
        "ACCESS_POLICY_AGENT_EVENT", ["TCP", "HTTP", "ACCESS"]
    ) == {
        "method": "GET",
        "uri": "/testcl/command",
    }
    assert batch.EMULATOR._capture_plan_request_template(
        "CLIENT_ACCEPTED", ["TCP"]
    ) == {"payload": "testcl"}


def test_stimulus_schedule_treats_rule_init_as_control_not_trigger() -> None:
    groups: dict[str, dict[str, object]] = {}
    batch._record_stimulus_group(
        groups,
        {
            "id": "command_probe:init",
            "event": "RULE_INIT",
            "mode": "none",
            "status": "not-required",
            "event_supported": False,
        },
        plan_filename="plan-0000.json",
    )
    group = batch._finalise_stimulus_schedule(groups)[0]
    assert group["id"] == "control"
    assert group["requires_trigger"] is False
    assert "RULE_INIT" in str(group["operator_guidance"])


def test_stimulus_schedule_describes_mixed_direct_and_trigger_events() -> None:
    groups: dict[str, dict[str, object]] = {}
    for result in (
        {
            "id": "command_probe:http",
            "event": "HTTP_REQUEST",
            "mode": "http1",
            "status": "buildable",
            "event_supported": True,
            "endpoint_scheme": "tcp",
        },
        {
            "id": "command_probe:access",
            "event": "ACCESS_POLICY_AGENT_EVENT",
            "mode": "http1",
            "status": "buildable",
            "event_supported": False,
            "endpoint_scheme": "tcp",
        },
    ):
        batch._record_stimulus_group(groups, result, plan_filename="plan-0000.json")
    group = batch._finalise_stimulus_schedule(groups)[0]
    assert group["observation_count"] == 2
    assert group["direct_event_count"] == 1
    assert group["requires_trigger"] is True
    assert "direct path" in str(group["operator_guidance"])


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
    assert manifest["protocol_driver"]["driver"] == "tmos17-protocol-driver"
    assert manifest["summary"]["bundled_driver_preflight_status_counts"]["buildable"] > 0
    assert "raw" in manifest["summary"]["bundled_driver_mode_counts"]
    schedule = manifest["stimulus_schedule"]
    assert schedule["schema_version"] == 1
    groups = {group["id"]: group for group in schedule["groups"]}
    assert "http1" in groups
    assert "raw:CLIENT_ACCEPTED" in groups
    assert sum(group["observation_count"] for group in groups.values()) == 986
    observation_ids = [
        observation_id
        for group in groups.values()
        for observation_id in group["observation_ids"]
    ]
    assert len(observation_ids) == len(set(observation_ids)) == 986
    assert all(group["plan_files"] for group in groups.values())
    assert all(group["driver_status_counts"] for group in groups.values())

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
        if any(
            item["input"]["event"] == "CLIENT_ACCEPTED"
            for item in plan["observations"]
        ):
            raw_fallback = next(
                item
                for item in plan["observations"]
                if item["input"]["event"] == "CLIENT_ACCEPTED"
            )
            assert raw_fallback["input"]["request"] == {"payload": "testcl"}


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
