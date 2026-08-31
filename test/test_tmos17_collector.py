from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "tools" / "tmos17-collector.py"
SPEC = importlib.util.spec_from_file_location("tmos17_collector", COLLECTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)


def _plan(*events: str) -> dict:
    return {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": "collector-test",
        "source": "bigip-test",
        "provenance": {
            "collector": "test",
            "tmos_build": "17.5.4",
            "capture_id": "test-001",
        },
        "observations": [
            {
                "id": f"case-{index}",
                "operation": "command_probe",
                "input": {
                    "command": "HTTP::host",
                    "event": event,
                    "profiles": ["TCP", "HTTP"],
                    "args": [],
                },
                "comparisons": [
                    {
                        "label": "status",
                        "actual_path": ["execution", "status"],
                        "reference_path": ["status"],
                    }
                ],
            }
            for index, event in enumerate(events)
        ],
    }


def test_validate_plan_rejects_unknown_input_fields() -> None:
    plan = _plan("HTTP_REQUEST")
    plan["observations"][0]["input"]["scenario"] = {}
    with pytest.raises(collector.CollectorError, match="unsupported field"):
        collector.validate_plan(plan)


def test_validate_plan_rejects_device_shell_command() -> None:
    plan = _plan("HTTP_REQUEST")
    plan["observations"][0]["input"]["command"] = "exec"
    with pytest.raises(collector.CollectorError, match="safety policy"):
        collector.validate_plan(plan)


def test_render_probe_irule_quotes_command_arguments_without_substitution() -> None:
    case = collector.validate_plan(_plan("HTTP_REQUEST"))["observations"][0]
    case["input"]["command"] = "HTTP::header"
    case["input"]["args"] = ["replace", "X-Test", "$(not-[a]-shell-command)"]
    source = collector.render_probe_irule(case, "testcl_capture_123")
    assert "when HTTP_REQUEST" in source
    assert "\\$" in source
    assert "\\[" in source
    assert "TESTCL_CAPTURE_V1|$testcl_capture_id" in source


def test_parse_capture_line_decodes_observed_value_and_error() -> None:
    value = base64.b64encode("observed value".encode()).decode()
    error = base64.b64encode("no error".encode()).decode()
    line = f"Aug 30 20:00:00 bigip notice: TESTCL_CAPTURE_V1|case-0|ok|0|{value}|{error}"
    assert collector.parse_capture_line(line, "case-0") == {
        "status": "ok",
        "tcl_return_code": 0,
        "value": "observed value",
        "error": "no error",
    }
    assert collector.parse_capture_line(line, "other") is None


class _FakeRest:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object | None]] = []

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path, None))
        return {"rules": ["/Tenant/existing-rule"]}

    def post(self, path: str, body: dict) -> dict:
        self.calls.append(("POST", path, body))
        return {}

    def patch(self, path: str, body: dict) -> dict:
        self.calls.append(("PATCH", path, body))
        return {}

    def delete(self, path: str) -> dict:
        self.calls.append(("DELETE", path, None))
        return {}


def test_collect_case_restores_virtual_and_returns_only_observed_record() -> None:
    fake = _FakeRest()
    plan_case = collector.validate_plan(_plan("HTTP_REQUEST"))["observations"][0]
    runner = collector.PlanCollector(
        fake,
        "/Tenant/test-vs",
        "http://127.0.0.1:8080/",
        log_timeout=0,
        settle_seconds=0,
    )
    with patch.object(runner, "_send_http"), patch.object(
        runner,
        "_find_log_result",
        return_value={"status": "ok", "tcl_return_code": 0, "value": "device"},
    ):
        result = runner.collect_case(plan_case)
    assert result == {
        "id": "case-0",
        "output": {"status": "ok", "tcl_return_code": 0, "value": "device"},
    }
    assert [method for method, _, _ in fake.calls] == [
        "GET", "POST", "PATCH", "PATCH", "DELETE"
    ]
    attach_body = fake.calls[2][2]
    restore_body = fake.calls[3][2]
    assert isinstance(attach_body, dict)
    assert isinstance(restore_body, dict)
    assert attach_body["rules"][-1].startswith("/Tenant/testcl_capture_")
    assert restore_body == {"rules": ["/Tenant/existing-rule"]}
    assert fake.calls[1][2]["partition"] == "Tenant"
    assert "~Tenant~testcl_capture_" in fake.calls[4][1]


def test_collect_refuses_unsupported_event_before_device_mutation() -> None:
    fake = _FakeRest()
    runner = collector.PlanCollector(
        fake,
        "/Common/test-vs",
        "http://127.0.0.1:8080/",
        settle_seconds=0,
    )
    with pytest.raises(collector.CollectorError, match="cannot drive"):
        runner.collect(_plan("MQTT_CLIENT_DATA"))
    assert fake.calls == []


def test_cli_dry_run_reports_supported_and_unsupported_cases(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(_plan("HTTP_REQUEST", "MQTT_CLIENT_DATA")), encoding="utf-8"
    )
    completed = subprocess.run(
        [sys.executable, str(COLLECTOR_PATH), "--plan", str(plan_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "dry-run"
    assert report["case_count"] == 2
    assert report["executable_count"] == 1
    assert report["device_mutation"] is False
