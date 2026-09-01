from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tools" / "tmos17-capture-runner.py"
SPEC = importlib.util.spec_from_file_location("tmos17_capture_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def _plan(*ids: str) -> dict:
    return {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": "runner-test",
        "source": "test",
        "provenance": {"collector": "test", "tmos_build": "17.5"},
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


def _write_batch(directory: Path, ids: tuple[str, ...] = ("case-0",)) -> Path:
    plan_path = directory / "plan-0000.json"
    plan_path.write_text(json.dumps(_plan(*ids)), encoding="utf-8")
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile": "tmos-17.5",
                "status": "ready-for-external-capture",
                "plans": [
                    {
                        "file": plan_path.name,
                        "command_count": len(ids),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def _execute_args(
    manifest: Path,
    records: Path,
    state: Path,
    *,
    allow_partial: bool = False,
) -> list[str]:
    args = [
        "--manifest",
        str(manifest),
        "--collector-script",
        str(runner.COLLECTOR_PATH),
        "--execute",
        "--allow-device-write",
        "--records",
        str(records),
        "--state",
        str(state),
        "--bigip-url",
        "https://bigip.example.test",
        "--virtual",
        "/Common/test-vs",
        "--traffic-url",
        "http://vip.example.test/health",
    ]
    if allow_partial:
        args.append("--allow-partial")
    return args


def test_runner_dry_run_revalidates_plans_without_device_mutation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _write_batch(tmp_path)
    assert runner.main(["--manifest", str(manifest)]) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["status"] == "dry-run"
    assert response["observation_count"] == 1
    assert response["device_mutation"] is False


def test_runner_preflight_is_read_only_and_reports_device_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _write_batch(tmp_path)

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        assert "--preflight" in command
        assert "--execute" not in command
        return subprocess.CompletedProcess(
            command,
            0,
            b'{"status":"preflight-ok","profile":"tmos-17.5","tmos_version":"17.5.4","device_mutation":false}\n',
            b"",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner.main(
        [
            "--manifest",
            str(manifest),
            "--preflight",
            "--bigip-url",
            "https://bigip.example.test",
            "--virtual",
            "/Common/test-vs",
            "--traffic-url",
            "http://vip.example.test/health",
        ]
    ) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["status"] == "preflight-ok"
    assert response["tmos_version"] == "17.5.4"
    assert response["batch_observation_count"] == 1


def test_runner_checkpoints_and_resumes_collected_plans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write_batch(tmp_path)
    records = tmp_path / "records.ndjson"
    state = tmp_path / "state.json"
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            b'{"id":"case-0","output":{"status":"ok"}}\n',
            b"",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    args = _execute_args(manifest, records, state)
    assert runner.main(args) == 0
    assert runner.main(args) == 0
    assert len(calls) == 1
    saved_state = json.loads(state.read_text(encoding="utf-8"))
    assert saved_state["status"] == "complete"
    assert saved_state["plans"]["plan-0000.json"]["status"] == "collected"
    assert records.read_text(encoding="utf-8") == (
        '{"id":"case-0","output":{"status":"ok"}}\n'
    )


def test_runner_keeps_partial_plan_retryable_without_allow_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write_batch(tmp_path, ("case-0", "case-1"))
    records = tmp_path / "records.ndjson"
    state = tmp_path / "state.json"
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            b'{"id":"case-0","output":{"status":"ok"}}\n',
            b"",
        )

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    partial_args = _execute_args(manifest, records, state, allow_partial=True)
    assert runner.main(partial_args) == 0
    saved_state = json.loads(state.read_text(encoding="utf-8"))
    assert saved_state["plans"]["plan-0000.json"]["status"] == "collected-partial"
    assert runner.main(partial_args) == 0
    assert len(calls) == 1

    assert runner.main(_execute_args(manifest, records, state)) == 1
    assert len(calls) == 2


def test_runner_rejects_plan_changes_and_orphaned_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write_batch(tmp_path)
    records = tmp_path / "records.ndjson"
    state = tmp_path / "state.json"
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, b'{"id":"case-0","output":{}}\n', b""
        ),
    )
    args = _execute_args(manifest, records, state)
    assert runner.main(args) == 0
    plan_path = tmp_path / "plan-0000.json"
    plan_path.write_text(json.dumps(_plan("changed")), encoding="utf-8")
    assert runner.main(args) == 1

    orphan_records = tmp_path / "orphan.ndjson"
    orphan_records.write_text('{"id":"case-0","output":{}}\n', encoding="utf-8")
    assert runner.main(
        _execute_args(manifest, orphan_records, tmp_path / "orphan-state.json")
    ) == 1
