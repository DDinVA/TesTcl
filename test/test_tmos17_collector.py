from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
from types import SimpleNamespace
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


def test_render_probe_irule_primes_rtsp_data_collection() -> None:
    case = collector.validate_plan(_plan("RTSP_REQUEST_DATA"))["observations"][0]
    source = collector.render_probe_irule(case, "testcl_capture_123")
    assert source.startswith("when RTSP_REQUEST { RTSP::collect }\nwhen RTSP_REQUEST_DATA {")


def test_parse_capture_line_decodes_observed_value_and_error() -> None:
    value = base64.b64encode("observed value".encode()).decode()
    error = base64.b64encode("no error".encode()).decode()
    line = f"Aug 30 20:00:00 bigip notice: TESTCL_CAPTURE_V1|case-0|ok|0|{value}|{error}"
    assert collector.parse_capture_line(line, "case-0") == {
        "status": "ok",
        "tcl_return_code": 0,
        "value_base64": value,
        "value_bytes": len("observed value"),
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
        "output": {
            "status": "ok",
            "tcl_return_code": 0,
            "value": "device",
            "event_trace": [
                {
                    "sequence": 0,
                    "event": "HTTP_REQUEST",
                    "fired": True,
                    "reason": "structured-log",
                    "source": "bigip-log",
                    "state_observed": False,
                    "command_status": "ok",
                    "tcl_return_code": 0,
                }
            ],
        },
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


def test_send_http_preserves_declared_host_header() -> None:
    runner = collector.PlanCollector(
        _FakeRest(),
        "/Common/test-vs",
        "https://traffic.example.test/",
        settle_seconds=0,
    )
    response = SimpleNamespace(read=lambda _limit: b"")
    with patch.object(collector, "urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value = response
        runner._send_http(
            {
                "method": "GET",
                "uri": "/testcl/command",
                "host": "example.test",
            }
        )
    sent_request = urlopen.call_args.args[0]
    assert sent_request.get_header("Host") == "example.test"


def test_send_http_rejects_unsafe_declared_host() -> None:
    runner = collector.PlanCollector(
        _FakeRest(),
        "/Common/test-vs",
        "https://traffic.example.test/",
        settle_seconds=0,
    )
    with pytest.raises(collector.CollectorError, match="host"):
        runner._send_http({"uri": "/testcl/command", "host": "bad\r\nHost: injected"})
    with pytest.raises(collector.CollectorError, match="valid UTF-8"):
        runner._send_http({"uri": "/testcl/command", "host": "bad\ud800"})


def test_http2_plan_requires_a_trigger_driver_instead_of_http11_fallback() -> None:
    plan = _plan("HTTP_REQUEST")
    plan["observations"][0]["input"]["request"] = {
        "method": "GET",
        "uri": "/testcl/command",
        "host": "h2.example.test",
        "http2": {"active": True, "version": 2, "stream_id": 3},
    }
    validated = collector.validate_plan(plan)
    assert validated["observations"][0]["event_supported"] is False

    fake = _FakeRest()
    runner = collector.PlanCollector(
        fake,
        "/Common/test-vs",
        "https://traffic.example.test/",
        trigger_command="/opt/drivers/http2-driver",
        settle_seconds=0,
    )
    with patch.object(runner, "_send_http") as send_http, patch.object(
        runner, "_run_trigger"
    ) as run_trigger, patch.object(
        runner,
        "_find_log_result",
        return_value={"status": "ok", "tcl_return_code": 0},
    ):
        result = runner.collect_case(validated["observations"][0])
    assert result["output"]["status"] == "ok"
    send_http.assert_not_called()
    run_trigger.assert_called_once_with(validated["observations"][0])

    no_driver = collector.PlanCollector(
        _FakeRest(),
        "/Common/test-vs",
        "https://traffic.example.test/",
        settle_seconds=0,
    )
    with pytest.raises(collector.CollectorError, match="cannot drive"):
        no_driver.collect(plan)


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


def test_protocol_driver_receives_json_without_shell_execution() -> None:
    fake = _FakeRest()
    plan_case = collector.validate_plan(_plan("MQTT_CLIENT_DATA"))["observations"][0]
    runner = collector.PlanCollector(
        fake,
        "/Common/test-vs",
        "https://traffic.example.test/",
        trigger_command="/opt/drivers/mqtt-driver",
        trigger_timeout=12.5,
        settle_seconds=0,
    )
    plan_case["input"]["request"] = {"payload": "fixture"}
    with patch.dict(
        collector.os.environ,
        {"BIGIP_USERNAME": "secret-user", "BIGIP_PASSWORD": "secret-pass"},
        clear=False,
    ), patch.object(
        collector.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0),
    ) as run:
        runner._run_trigger(plan_case)

    positional, kwargs = run.call_args
    command = positional[0]
    assert command == ["/opt/drivers/mqtt-driver"]
    assert kwargs["shell"] is False
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert kwargs["timeout"] == 12.5
    assert "BIGIP_USERNAME" not in kwargs["env"]
    assert "BIGIP_PASSWORD" not in kwargs["env"]
    payload = json.loads(kwargs["input"].decode("utf-8"))
    assert payload == {
        "profile": "tmos-17.5",
        "case": "case-0",
        "event": "MQTT_CLIENT_DATA",
        "command": "HTTP::host",
        "args": [],
        "profiles": ["TCP", "HTTP"],
        "traffic_url": "https://traffic.example.test/",
        "virtual": "/Common/test-vs",
        "request": {"payload": "fixture"},
    }


def test_protocol_driver_drives_unsupported_event_and_returns_observation() -> None:
    fake = _FakeRest()
    plan_case = collector.validate_plan(_plan("MQTT_CLIENT_DATA"))["observations"][0]
    runner = collector.PlanCollector(
        fake,
        "/Common/test-vs",
        "http://127.0.0.1:8080/",
        trigger_command="/opt/drivers/mqtt-driver",
        settle_seconds=0,
    )
    with patch.object(runner, "_run_trigger") as trigger, patch.object(
        runner,
        "_find_log_result",
        return_value={"status": "ok", "tcl_return_code": 0, "value": "mqtt"},
    ):
        result = runner.collect_case(plan_case)
    trigger.assert_called_once_with(plan_case)
    assert result["id"] == "case-0"
    assert result["output"]["value"] == "mqtt"
    assert result["output"]["event_trace"][0]["event"] == "MQTT_CLIENT_DATA"
    assert result["output"]["event_trace"][0]["state_observed"] is False
    assert [method for method, _, _ in fake.calls] == [
        "GET", "POST", "PATCH", "PATCH", "DELETE"
    ]


def test_protocol_driver_failure_still_restores_virtual_and_deletes_rule() -> None:
    fake = _FakeRest()
    plan_case = collector.validate_plan(_plan("MQTT_CLIENT_DATA"))["observations"][0]
    runner = collector.PlanCollector(
        fake,
        "/Common/test-vs",
        "http://127.0.0.1:8080/",
        trigger_command="/opt/drivers/mqtt-driver",
        settle_seconds=0,
    )
    with patch.object(
        runner,
        "_run_trigger",
        side_effect=collector.CollectorError("driver failed"),
    ), pytest.raises(collector.CollectorError, match="driver failed"):
        runner.collect_case(plan_case)
    assert [method for method, _, _ in fake.calls] == [
        "GET", "POST", "PATCH", "PATCH", "DELETE"
    ]


def test_protocol_driver_timeout_must_be_bounded() -> None:
    with pytest.raises(collector.CollectorError, match="trigger-timeout"):
        collector.PlanCollector(
            _FakeRest(),
            "/Common/test-vs",
            "http://127.0.0.1:8080/",
            trigger_command="/opt/drivers/mqtt-driver",
            trigger_timeout=0,
        )


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


def test_cli_dry_run_counts_protocol_driver_cases_and_validates_timeout(
    tmp_path: Path,
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(_plan("MQTT_CLIENT_DATA")), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR_PATH),
            "--plan",
            str(plan_path),
            "--trigger-command",
            "/opt/drivers/mqtt-driver",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["executable_count"] == 1
    assert report["protocol_driver"] is True

    invalid = subprocess.run(
        [
            sys.executable,
            str(COLLECTOR_PATH),
            "--plan",
            str(plan_path),
            "--trigger-timeout",
            "0",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode == 2
    assert "trigger-timeout" in invalid.stderr
