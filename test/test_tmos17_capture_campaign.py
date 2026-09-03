from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_PATH = ROOT / "tools" / "tmos17-capture-campaign.py"
SPEC = importlib.util.spec_from_file_location("tmos17_capture_campaign", CAMPAIGN_PATH)
assert SPEC is not None and SPEC.loader is not None
campaign = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = campaign
SPEC.loader.exec_module(campaign)


def _plan(observation_id: str) -> dict:
    return {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": f"plan-{observation_id}",
        "source": "bigip-test",
        "provenance": {
            "collector": "test",
            "tmos_build": "17.5.4",
            "capture_id": observation_id,
        },
        "observations": [
            {
                "id": observation_id,
                "operation": "command_probe",
                "input": {
                    "command": "HTTP::host",
                    "args": [],
                    "event": "HTTP_REQUEST",
                    "profiles": ["TCP", "HTTP"],
                    "request": {"host": "example.test", "uri": "/"},
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


def _write_schedule(tmp_path: Path, *, mode: str = "http1") -> Path:
    group_dir = tmp_path / "http1-group"
    group_dir.mkdir()
    (group_dir / "plan-0000.json").write_text(
        json.dumps(_plan("probe-1")), encoding="utf-8"
    )
    group_manifest = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "status": "ready",
        "selection": {
            "source_manifest": "manifest.json",
            "source_manifest_sha256": "a" * 64,
            "group_id": "http1",
            "mode": mode,
            "events": ["HTTP_REQUEST"],
        },
        "provenance": {"capture_id": "campaign-test"},
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
    (group_dir / "manifest.json").write_text(
        json.dumps(group_manifest), encoding="utf-8"
    )
    schedule = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "status": "ready",
        "source": {"manifest": "manifest.json", "manifest_sha256": "b" * 64},
        "summary": {"group_count": 1, "observation_count": 1},
        "groups": [
            {
                "id": "http1",
                "mode": mode,
                "events": ["HTTP_REQUEST"],
                "observation_ids": ["probe-1"],
                "observation_count": 1,
                "requires_trigger": False,
                "endpoint_schemes": ["tcp"],
                "manifest": "http1-group/manifest.json",
            }
        ],
    }
    schedule_path = tmp_path / "schedule.json"
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    return schedule_path


def test_campaign_plan_routes_http_group_to_http_endpoint(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    result = campaign.build_campaign(
        schedule_path,
        http_traffic_url="https://vip.example.test/",
    )
    assert result["status"] == "planned"
    assert result["summary"] == {
        "group_count": 1,
        "planned_group_count": 1,
        "completed_group_count": 0,
        "failed_group_count": 0,
        "observation_count": 1,
    }
    row = result["groups"][0]
    assert row["traffic_url"] == "https://vip.example.test/"
    assert "--preflight" not in row["command"]
    assert "--execute" not in row["command"]


def test_campaign_plan_routes_http2_group_to_tcp_endpoint(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path, mode="http2")
    result = campaign.build_campaign(
        schedule_path,
        tcp_traffic_url="tcp://vip.example.test:443",
    )
    assert result["groups"][0]["traffic_url"] == "tcp://vip.example.test:443"


def test_campaign_accepts_driver_http2_endpoint_marker(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path, mode="http2")
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    schedule["groups"][0]["endpoint_schemes"] = ["h2c"]
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    result = campaign.build_campaign(
        schedule_path,
        tcp_traffic_url="tcp://vip.example.test:443",
    )
    assert result["groups"][0]["traffic_url"] == "tcp://vip.example.test:443"


def test_campaign_group_output_names_are_distinct_and_safe() -> None:
    first = campaign._group_output_name("raw:CLIENT_DATA")
    second = campaign._group_output_name("raw/CLIENT_DATA")
    assert first != second
    assert "/" not in first
    assert "/" not in second


def test_campaign_rejects_wrong_transport_for_http_group(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    with pytest.raises(campaign.CampaignError, match="requires http, https traffic"):
        campaign.build_campaign(schedule_path, traffic_url="tcp://vip.example.test:80")


def test_campaign_execute_requires_second_write_acknowledgement(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    with pytest.raises(campaign.CampaignError, match="allow-device-write"):
        campaign.build_campaign(
            schedule_path,
            mode="execute",
            bigip_url="https://bigip.example.test",
            virtual="/Common/test-vs",
            http_traffic_url="https://vip.example.test/",
        )


def test_campaign_cli_declares_and_enforces_write_acknowledgement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    schedule_path = _write_schedule(tmp_path)
    result = campaign.main(
        [
            "--schedule",
            str(schedule_path),
            "--execute",
            "--bigip-url",
            "https://bigip.example.test",
            "--virtual",
            "/Common/test-vs",
            "--http-traffic-url",
            "https://vip.example.test/",
        ]
    )
    assert result == 1
    assert "allow-device-write" in capsys.readouterr().out


def test_campaign_rejects_schedule_manifest_symlink(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    group_manifest = tmp_path / "http1-group" / "manifest.json"
    target = tmp_path / "real-manifest.json"
    target.write_bytes(group_manifest.read_bytes())
    group_manifest.unlink()
    group_manifest.symlink_to(target)
    with pytest.raises(campaign.CampaignError, match="symlink"):
        campaign.load_schedule(schedule_path)


def test_campaign_rejects_top_level_schedule_symlink(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    alias = tmp_path / "schedule-alias.json"
    alias.symlink_to(schedule_path)
    with pytest.raises(campaign.CampaignError, match="schedule must not be a symlink"):
        campaign.load_schedule(alias)


def test_campaign_rejects_mixed_transport_group_before_building_commands(
    tmp_path: Path,
) -> None:
    schedule_path = _write_schedule(tmp_path)
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    schedule["groups"][0]["endpoint_schemes"] = ["tcp", "udp"]
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    with pytest.raises(campaign.CampaignError, match="mixes endpoint schemes"):
        campaign.load_schedule(schedule_path)


def test_campaign_rejects_incompatible_mode_transport(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path, mode="http2")
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    schedule["groups"][0]["endpoint_schemes"] = ["udp"]
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    with pytest.raises(campaign.CampaignError, match="HTTP mode requires"):
        campaign.load_schedule(schedule_path)


def test_campaign_binds_manifest_mode_to_schedule_mode(tmp_path: Path) -> None:
    schedule_path = _write_schedule(tmp_path)
    manifest_path = tmp_path / "http1-group" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["selection"]["mode"] = "websocket"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(campaign.CampaignError, match="bound to its schedule"):
        campaign.load_schedule(schedule_path)
