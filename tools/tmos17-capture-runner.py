#!/usr/bin/env python3
"""Run a TMOS 17.5 capture batch with dry-run and resumable execution modes.

The batch builder creates immutable plan files; this runner is the operational
boundary that validates them again, optionally invokes the external collector,
and checkpoints one completed plan at a time. It is dry-run by default. Actual
BIG-IP mutation requires ``--execute`` and ``--allow-device-write`` and keeps
credentials in the inherited environment rather than command-line arguments.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "tools" / "tmos17-collector.py"
TMOS_PROFILE = "tmos-17.5"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_RECORDS_BYTES = 32 * 1024 * 1024
MAX_BATCH_PLANS = 256


class RunnerError(RuntimeError):
    """Raised when a batch cannot be safely validated or resumed."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RunnerError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


COLLECTOR = _load_module(COLLECTOR_PATH, "testcl_tmos17_collector_for_runner")


@dataclass(frozen=True)
class PlanEntry:
    filename: str
    path: Path
    sha256: str
    command_count: int
    observation_count: int
    event_supported_count: int
    event_driver_count: int
    record_ids: frozenset[str]


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_json(path: Path, max_bytes: int) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"could not read {path}: {exc}") from exc
    if len(raw) > max_bytes:
        raise RunnerError(f"{path.name} exceeds the {max_bytes} byte limit")
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant), raw
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RunnerError(f"{path} is not valid UTF-8 JSON: {exc}") from exc


def _write_json_atomic(path: Path, payload: Any) -> None:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RunnerError(f"could not serialize {path.name}: {exc}") from exc
    if len(encoded) > MAX_STATE_BYTES:
        raise RunnerError(f"{path.name} exceeds the {MAX_STATE_BYTES} byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        raise RunnerError(f"could not write {path}: {exc}") from exc


def _safe_plan_path(base: Path, filename: Any) -> tuple[str, Path]:
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        raise RunnerError("manifest plan files must be simple filenames")
    if filename in {".", ".."} or not filename.endswith(".json"):
        raise RunnerError(f"manifest plan filename is invalid: {filename!r}")
    path = (base / filename).resolve()
    if path.parent != base.resolve():
        raise RunnerError(f"manifest plan escapes its directory: {filename!r}")
    if not path.is_file():
        raise RunnerError(f"manifest plan does not exist: {filename!r}")
    return filename, path


def _load_batch(manifest_path: Path) -> tuple[dict[str, Any], list[PlanEntry], str]:
    manifest, raw_manifest = _read_json(manifest_path, MAX_MANIFEST_BYTES)
    if not isinstance(manifest, dict):
        raise RunnerError("capture manifest must be a JSON object")
    if manifest.get("profile") != TMOS_PROFILE:
        raise RunnerError("capture manifest profile must be tmos-17.5")
    plans = manifest.get("plans")
    if not isinstance(plans, list) or not plans:
        raise RunnerError("capture manifest must contain a non-empty plans array")
    if len(plans) > MAX_BATCH_PLANS:
        raise RunnerError(f"capture manifest accepts at most {MAX_BATCH_PLANS} plans")

    base = manifest_path.parent.resolve()
    entries: list[PlanEntry] = []
    seen: set[str] = set()
    seen_record_ids: set[str] = set()
    for index, item in enumerate(plans):
        if not isinstance(item, dict):
            raise RunnerError(f"manifest plan {index} must be an object")
        filename, path = _safe_plan_path(base, item.get("file"))
        if filename in seen:
            raise RunnerError(f"manifest contains duplicate plan {filename!r}")
        seen.add(filename)
        plan, raw_plan = _read_json(path, MAX_PLAN_BYTES)
        try:
            validated = COLLECTOR.validate_plan(plan)
        except COLLECTOR.CollectorError as exc:
            raise RunnerError(f"plan {filename!r} fails collector validation: {exc}") from exc
        observations = validated["observations"]
        record_ids = frozenset(item["id"] for item in observations)
        command_count = item.get("command_count")
        if (
            isinstance(command_count, bool)
            or not isinstance(command_count, int)
            or command_count < 0
        ):
            raise RunnerError(f"manifest plan {filename!r} has an invalid command_count")
        entries.append(
            PlanEntry(
                filename=filename,
                path=path,
                sha256=hashlib.sha256(raw_plan).hexdigest(),
                command_count=command_count,
                observation_count=len(observations),
                event_supported_count=sum(
                    1 for observation in observations if observation["event_supported"]
                ),
                event_driver_count=sum(
                    1 for observation in observations if not observation["event_supported"]
                ),
                record_ids=record_ids,
            )
        )
        duplicate_record_ids = seen_record_ids & record_ids
        if duplicate_record_ids:
            raise RunnerError(
                "capture manifest repeats observation id(s): "
                + ", ".join(sorted(duplicate_record_ids)[:8])
            )
        seen_record_ids.update(record_ids)
    return manifest, entries, hashlib.sha256(raw_manifest).hexdigest()


def _record_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"could not read records file {path}: {exc}") from exc
    if len(raw) > MAX_RECORDS_BYTES:
        raise RunnerError(f"records file exceeds the {MAX_RECORDS_BYTES} byte limit")
    ids: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            raise RunnerError(f"records file contains a blank line at {line_number}")
        try:
            record = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RunnerError(f"records line {line_number} is not valid JSON: {exc}") from exc
        if (
            not isinstance(record, dict)
            or set(record) != {"id", "output"}
            or not isinstance(record["id"], str)
            or not record["id"]
            or not isinstance(record["output"], dict)
        ):
            raise RunnerError(f"records line {line_number} is not a collector record")
        if record["id"] in ids:
            raise RunnerError(f"records file contains duplicate id {record['id']!r}")
        ids.add(record["id"])
    return ids


def _validate_new_records(
    stdout: bytes, entry: PlanEntry, existing_ids: set[str]
) -> list[bytes]:
    if len(stdout) > MAX_RECORDS_BYTES:
        raise RunnerError(f"collector output for {entry.filename!r} exceeds the records limit")
    lines = stdout.splitlines()
    new_lines: list[bytes] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise RunnerError(f"collector output for {entry.filename!r} has a blank line")
        try:
            record = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RunnerError(
                f"collector output for {entry.filename!r} line {line_number} is invalid JSON: {exc}"
            ) from exc
        if (
            not isinstance(record, dict)
            or set(record) != {"id", "output"}
            or not isinstance(record["id"], str)
            or not isinstance(record["output"], dict)
        ):
            raise RunnerError(f"collector output for {entry.filename!r} contains an invalid record")
        record_id = record["id"]
        if record_id not in entry.record_ids:
            raise RunnerError(
                f"collector output for {entry.filename!r} contains unknown id {record_id!r}"
            )
        if record_id in seen or record_id in existing_ids:
            raise RunnerError(f"collector output contains duplicate id {record_id!r}")
        seen.add(record_id)
        new_lines.append(line)
    return new_lines


def _new_state(manifest_sha256: str, records_path: Path) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "profile": TMOS_PROFILE,
        "status": "pending",
        "manifest_sha256": manifest_sha256,
        "records_path": str(records_path.resolve()),
        "plans": {},
    }


def _load_state(
    state_path: Path, manifest_sha256: str, records_path: Path
) -> dict[str, Any]:
    if not state_path.exists():
        return _new_state(manifest_sha256, records_path)
    state, _ = _read_json(state_path, MAX_STATE_BYTES)
    if not isinstance(state, dict):
        raise RunnerError("capture state must be a JSON object")
    if state.get("profile") != TMOS_PROFILE or state.get("schema_version") != 1:
        raise RunnerError("capture state has an unsupported profile or schema")
    if state.get("manifest_sha256") != manifest_sha256:
        raise RunnerError("capture state belongs to a different manifest")
    if state.get("records_path") != str(records_path.resolve()):
        raise RunnerError("capture state belongs to a different records path")
    if not isinstance(state.get("plans"), dict):
        raise RunnerError("capture state plans must be an object")
    return state


def _append_records(path: Path, lines: list[bytes]) -> None:
    if not lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_size = path.stat().st_size if path.exists() else 0
    except OSError as exc:
        raise RunnerError(f"could not inspect records file {path}: {exc}") from exc
    additional_size = sum(len(line.rstrip(b"\r\n")) + 1 for line in lines)
    if existing_size + additional_size > MAX_RECORDS_BYTES:
        raise RunnerError(f"records file exceeds the {MAX_RECORDS_BYTES} byte limit")
    try:
        with path.open("ab") as stream:
            for line in lines:
                stream.write(line.rstrip(b"\r\n") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise RunnerError(f"could not append records to {path}: {exc}") from exc


def _collector_command(args: argparse.Namespace, entry: PlanEntry) -> list[str]:
    command = [
        sys.executable,
        str(Path(args.collector_script).resolve()),
        "--plan",
        str(entry.path),
        "--execute",
        "--allow-device-write",
        "--bigip-url",
        args.bigip_url,
        "--virtual",
        args.virtual,
        "--traffic-url",
        args.traffic_url,
        "--log-lines",
        str(args.log_lines),
        "--log-timeout",
        str(args.log_timeout),
        "--settle-seconds",
        str(args.settle_seconds),
        "--trigger-timeout",
        str(args.trigger_timeout),
    ]
    if args.capture_wire:
        command.append("--capture-wire")
    if args.allow_partial:
        command.append("--allow-partial")
    if args.trigger_command:
        command.extend(("--trigger-command", args.trigger_command))
    if args.insecure:
        command.append("--insecure")
    return command


def _preflight_command(args: argparse.Namespace, entry: PlanEntry) -> list[str]:
    if not args.bigip_url or not args.virtual or not args.traffic_url:
        raise RunnerError(
            "--preflight requires --bigip-url, --virtual, and --traffic-url"
        )
    command = [
        sys.executable,
        str(Path(args.collector_script).resolve()),
        "--plan",
        str(entry.path),
        "--preflight",
        "--bigip-url",
        args.bigip_url,
        "--virtual",
        args.virtual,
        "--traffic-url",
        args.traffic_url,
    ]
    if args.insecure:
        command.append("--insecure")
    return command


def _run_preflight(args: argparse.Namespace, entry: PlanEntry) -> dict[str, Any]:
    if not Path(args.collector_script).is_file():
        raise RunnerError(f"collector script does not exist: {args.collector_script}")
    try:
        completed = subprocess.run(
            _preflight_command(args, entry),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            env=os.environ.copy(),
        )
    except OSError as exc:
        raise RunnerError(f"device preflight could not start: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-2048:]
        raise RunnerError(f"device preflight failed: {detail}")
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("device preflight returned invalid JSON") from exc
    if (
        not isinstance(result, dict)
        or result.get("status") != "preflight-ok"
        or result.get("profile") != TMOS_PROFILE
        or result.get("device_mutation") is not False
        or not isinstance(result.get("tmos_version"), str)
        or not result["tmos_version"].startswith("17.5")
        or not isinstance(result.get("virtual_path"), str)
        or not isinstance(result.get("virtual"), str)
    ):
        raise RunnerError("device preflight returned an invalid result")
    return result


def _preflight_identity(result: dict[str, Any]) -> tuple[str, str, str]:
    """Return the stable device identity used to bind a resumable capture."""
    return (
        result["tmos_version"],
        result["virtual_path"],
        result["virtual"],
    )


def _dry_run(manifest: dict[str, Any], entries: list[PlanEntry]) -> dict[str, Any]:
    return {
        "status": "dry-run",
        "profile": TMOS_PROFILE,
        "manifest_status": manifest.get("status"),
        "plan_count": len(entries),
        "command_count": sum(entry.command_count for entry in entries),
        "observation_count": sum(entry.observation_count for entry in entries),
        "directly_triggerable_count": sum(
            entry.event_supported_count for entry in entries
        ),
        "requires_trigger_count": sum(entry.event_driver_count for entry in entries),
        "plans": [
            {
                "file": entry.filename,
                "sha256": entry.sha256,
                "command_count": entry.command_count,
                "observation_count": entry.observation_count,
                "directly_triggerable_count": entry.event_supported_count,
                "requires_trigger_count": entry.event_driver_count,
            }
            for entry in entries
        ],
        "device_mutation": False,
    }


def _execute_batch(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    entries: list[PlanEntry],
    manifest_sha256: str,
) -> dict[str, Any]:
    if not args.allow_device_write:
        raise RunnerError("--execute requires --allow-device-write")
    if not args.bigip_url or not args.virtual or not args.traffic_url:
        raise RunnerError("--execute requires --bigip-url, --virtual, and --traffic-url")
    if not args.records:
        raise RunnerError("--execute requires --records")
    records_path = Path(args.records).expanduser().resolve()
    state_path = Path(args.state or (Path(args.manifest).resolve().parent / "capture-state.json"))
    state_path = state_path.expanduser().resolve()
    input_paths = {Path(args.manifest).resolve(), *(entry.path for entry in entries)}
    if records_path in input_paths or state_path in input_paths:
        raise RunnerError("records/state paths must not overwrite the manifest or a plan")
    if state_path == records_path:
        raise RunnerError("records and state paths must be different")
    if not Path(args.collector_script).is_file():
        raise RunnerError(f"collector script does not exist: {args.collector_script}")

    state_was_present = state_path.exists()
    state = _load_state(state_path, manifest_sha256, records_path)
    preflight = _run_preflight(args, entries[0])
    stored_preflight = state.get("preflight")
    if stored_preflight is not None:
        if not isinstance(stored_preflight, dict):
            raise RunnerError("capture state preflight must be an object")
        try:
            stored_identity = _preflight_identity(stored_preflight)
        except (KeyError, TypeError) as exc:
            raise RunnerError("capture state preflight is missing device identity") from exc
        if stored_identity != _preflight_identity(preflight):
            raise RunnerError("device preflight identity changed since capture started")
    state["preflight"] = preflight
    existing_ids = _record_ids(records_path)
    if not state_was_present and existing_ids:
        raise RunnerError("records file is non-empty but capture state is missing")
    completed = {
        filename: value
        for filename, value in state["plans"].items()
        if (
            isinstance(value, dict)
            and value.get("status") == "collected"
        ) or (
            isinstance(value, dict)
            and value.get("status") == "collected-partial"
            and args.allow_partial
        )
    }
    known_plan_files = {entry.filename for entry in entries}
    unknown_state_plans = set(state["plans"]) - known_plan_files
    if unknown_state_plans:
        raise RunnerError(
            "capture state contains unknown plan(s): "
            + ", ".join(sorted(unknown_state_plans)[:8])
        )
    entries_by_filename = {entry.filename: entry for entry in entries}
    for filename, value in state["plans"].items():
        if filename not in entries_by_filename:
            continue
        if not isinstance(value, dict):
            raise RunnerError(f"capture state entry for {filename!r} must be an object")
        if value.get("status") not in {"collected", "collected-partial"}:
            raise RunnerError(f"capture state entry for {filename!r} has an invalid status")
        if value.get("sha256") != entries_by_filename[filename].sha256:
            raise RunnerError(f"state checksum does not match plan {filename!r}")
    all_plan_ids = set().union(*(set(entry.record_ids) for entry in entries))
    if not existing_ids <= all_plan_ids:
        raise RunnerError("records file contains ids not present in this manifest")
    for entry in entries:
        if entry.filename in completed:
            recorded_ids = completed[entry.filename].get("record_ids", [])
            if (
                not isinstance(recorded_ids, list)
                or any(not isinstance(record_id, str) for record_id in recorded_ids)
                or not set(recorded_ids) <= existing_ids
            ):
                raise RunnerError(
                    f"state marks {entry.filename!r} complete but its records are missing"
                )

    state["status"] = "running"
    state.pop("error", None)
    _write_json_atomic(state_path, state)
    for entry in entries:
        if entry.filename in completed:
            continue
        state["current_plan"] = entry.filename
        _write_json_atomic(state_path, state)
        try:
            completed_process = subprocess.run(
                _collector_command(args, entry),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                shell=False,
                env=os.environ.copy(),
            )
        except OSError as exc:
            state["status"] = "failed"
            state["error"] = str(exc)
            _write_json_atomic(state_path, state)
            raise RunnerError(f"collector could not start for {entry.filename!r}: {exc}") from exc
        if completed_process.returncode != 0:
            state["status"] = "failed"
            state["error"] = (
                f"collector failed for {entry.filename!r} with exit code "
                f"{completed_process.returncode}: "
                f"{completed_process.stderr.decode('utf-8', errors='replace')[-2048:]}"
            )
            _write_json_atomic(state_path, state)
            raise RunnerError(state["error"])
        try:
            new_lines = _validate_new_records(completed_process.stdout, entry, existing_ids)
        except RunnerError as exc:
            state["status"] = "failed"
            state["error"] = str(exc)
            _write_json_atomic(state_path, state)
            raise
        _append_records(records_path, new_lines)
        new_ids = [
            json.loads(line.decode("utf-8"))["id"] for line in new_lines
        ]
        existing_ids.update(new_ids)
        state["plans"][entry.filename] = {
            "status": (
                "collected-partial"
                if len(new_ids) < entry.observation_count
                else "collected"
            ),
            "sha256": entry.sha256,
            "record_ids": new_ids,
            "record_count": len(new_ids),
        }
        state.pop("error", None)
        state.pop("current_plan", None)
        _write_json_atomic(state_path, state)
    state["status"] = "complete"
    state.pop("current_plan", None)
    _write_json_atomic(state_path, state)
    return {
        "status": "collected",
        "profile": TMOS_PROFILE,
        "plan_count": len(entries),
        "record_count": len(existing_ids),
        "state": str(state_path),
        "records": str(records_path),
        "preflight": state["preflight"],
        "device_mutation": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Dry-run or execute a resumable TMOS 17.5 capture batch"
    )
    parser.add_argument("--manifest", required=True, help="batch manifest JSON path")
    parser.add_argument("--collector-script", default=str(COLLECTOR_PATH))
    parser.add_argument("--execute", action="store_true", help="run the external collector")
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="run one read-only TMOS 17.5/device/virtual check for the batch",
    )
    parser.add_argument("--allow-device-write", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--records", help="NDJSON output path; required with --execute")
    parser.add_argument("--state", help="checkpoint JSON path; defaults beside the manifest")
    parser.add_argument("--bigip-url")
    parser.add_argument("--virtual")
    parser.add_argument("--traffic-url")
    parser.add_argument("--trigger-command")
    parser.add_argument("--trigger-timeout", type=float, default=60.0)
    parser.add_argument(
        "--capture-wire",
        action="store_true",
        help="ask the protocol driver to retain bounded server responses",
    )
    parser.add_argument("--log-lines", type=int, default=500)
    parser.add_argument("--log-timeout", type=float, default=5.0)
    parser.add_argument("--settle-seconds", type=float, default=0.2)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.execute and args.preflight:
            raise RunnerError("--execute and --preflight are mutually exclusive")
        manifest_path = Path(args.manifest).expanduser().resolve()
        manifest, entries, manifest_sha256 = _load_batch(manifest_path)
        if args.preflight:
            result = _run_preflight(args, entries[0])
            result["batch_plan_count"] = len(entries)
            result["batch_observation_count"] = sum(
                entry.observation_count for entry in entries
            )
        elif args.execute:
            result = _execute_batch(args, manifest, entries, manifest_sha256)
        else:
            result = _dry_run(manifest, entries)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (RunnerError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
