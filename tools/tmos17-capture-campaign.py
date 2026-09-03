#!/usr/bin/env python3
"""Plan or run a scheduled TMOS 17.5 capture campaign.

The catalog batch is intentionally split by stimulus family before it reaches
this tool.  This command consumes the resulting ``schedule.json`` and turns
each group into a safe, resumable capture-runner invocation.  It is dry-run by
default; ``--preflight`` performs read-only device checks and ``--execute``
requires the runner's explicit device-write acknowledgement.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tools" / "tmos17-capture-runner.py"
DRIVER_PATH = ROOT / "scripts" / "tmos17-protocol-driver.sh"
TMOS_PROFILE = "tmos-17.5"
MAX_SCHEDULE_BYTES = 8 * 1024 * 1024
MAX_GROUPS = 256
MAX_ERROR_BYTES = 4096


class CampaignError(RuntimeError):
    """Raised when a scheduled capture campaign is not safe to run."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CampaignError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = _load_module(RUNNER_PATH, "testcl_tmos17_capture_runner_for_campaign")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_json(path: Path) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CampaignError(f"could not read schedule {path}: {exc}") from exc
    if len(raw) > MAX_SCHEDULE_BYTES:
        raise CampaignError("schedule exceeds the 8 MiB limit")
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CampaignError(f"schedule is not valid UTF-8 JSON: {exc}") from exc
    return value, raw


def _safe_relative_file(base: Path, value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CampaignError(f"{field} must be a non-empty relative path")
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise CampaignError(f"{field} must be a safe relative path")
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CampaignError(f"{field} must not traverse a symlink")
    path = (base / relative).resolve()
    if base.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise CampaignError(f"{field} is not a regular file inside the schedule")
    return path


def _normalise_group(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CampaignError(f"schedule group {index} must be an object")
    group_id = raw.get("id")
    if not isinstance(group_id, str) or not group_id or "\x00" in group_id:
        raise CampaignError(f"schedule group {index} has an invalid id")
    mode = raw.get("mode")
    if not isinstance(mode, str) or not mode or "\x00" in mode:
        raise CampaignError(f"schedule group {group_id!r} has an invalid mode")
    schemes = raw.get("endpoint_schemes", [])
    if not isinstance(schemes, list) or any(
        scheme not in {"tcp", "udp"} for scheme in schemes
    ):
        raise CampaignError(
            f"schedule group {group_id!r} endpoint_schemes must contain tcp or udp"
        )
    if len(set(schemes)) != len(schemes):
        raise CampaignError(f"schedule group {group_id!r} repeats an endpoint scheme")
    if len(schemes) > 1:
        raise CampaignError(
            f"schedule group {group_id!r} mixes endpoint schemes; split it first"
        )
    if mode in {"http1", "http2", "websocket"} and schemes and schemes != ["tcp"]:
        raise CampaignError(
            f"schedule group {group_id!r} HTTP mode requires a tcp endpoint scheme"
        )
    if mode in {"dns", "pcp", "radius", "sip"} and schemes and schemes != ["udp"]:
        raise CampaignError(
            f"schedule group {group_id!r} datagram mode requires a udp endpoint scheme"
        )
    if mode not in {"none", "http1", "http2", "websocket", "dns", "pcp", "radius", "sip"} and not schemes:
        raise CampaignError(
            f"schedule group {group_id!r} needs an endpoint scheme for mode {mode!r}"
        )
    observation_count = raw.get("observation_count")
    if (
        isinstance(observation_count, bool)
        or not isinstance(observation_count, int)
        or observation_count <= 0
    ):
        raise CampaignError(
            f"schedule group {group_id!r} has an invalid observation_count"
        )
    observation_ids = raw.get("observation_ids")
    if not isinstance(observation_ids, list) or len(observation_ids) != observation_count:
        raise CampaignError(
            f"schedule group {group_id!r} observation_ids do not match observation_count"
        )
    if any(not isinstance(item, str) or not item for item in observation_ids):
        raise CampaignError(f"schedule group {group_id!r} has invalid observation_ids")
    if len(set(observation_ids)) != len(observation_ids):
        raise CampaignError(f"schedule group {group_id!r} repeats an observation id")
    return dict(raw)


def load_schedule(schedule_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    """Validate the split schedule and every group runner manifest."""
    schedule_path = schedule_path.expanduser()
    if schedule_path.is_symlink():
        raise CampaignError(f"schedule must not be a symlink: {schedule_path}")
    schedule_path = schedule_path.resolve()
    if not schedule_path.is_file():
        raise CampaignError(f"schedule does not exist as a regular file: {schedule_path}")
    schedule, raw = _read_json(schedule_path)
    if not isinstance(schedule, dict):
        raise CampaignError("schedule must be a JSON object")
    if schedule.get("schema_version") != 1 or schedule.get("profile") != TMOS_PROFILE:
        raise CampaignError("schedule must use schema 1 and profile tmos-17.5")
    groups = schedule.get("groups")
    if not isinstance(groups, list) or not groups or len(groups) > MAX_GROUPS:
        raise CampaignError(f"schedule must contain 1 to {MAX_GROUPS} groups")
    summary = schedule.get("summary")
    if not isinstance(summary, dict):
        raise CampaignError("schedule summary must be an object")

    normalised: list[dict[str, Any]] = []
    seen_group_ids: set[str] = set()
    seen_observation_ids: set[str] = set()
    total_observations = 0
    for index, raw_group in enumerate(groups):
        group = _normalise_group(raw_group, index)
        group_id = group["id"]
        if group_id in seen_group_ids:
            raise CampaignError(f"schedule repeats group {group_id!r}")
        seen_group_ids.add(group_id)
        manifest_path = _safe_relative_file(
            schedule_path.parent, group.get("manifest"), f"group {group_id!r} manifest"
        )
        try:
            group_manifest, entries, _ = RUNNER._load_batch(manifest_path)
        except (RUNNER.RunnerError, OSError) as exc:
            raise CampaignError(
                f"group {group_id!r} manifest fails runner validation: {exc}"
            ) from exc
        selection = group_manifest.get("selection")
        if (
            not isinstance(selection, dict)
            or selection.get("group_id") != group_id
            or selection.get("mode") != group["mode"]
        ):
            raise CampaignError(
                f"group {group_id!r} manifest is not bound to its schedule group and mode"
            )
        manifest_count = group_manifest.get("summary", {}).get("observation_count")
        if manifest_count != group["observation_count"]:
            raise CampaignError(
                f"group {group_id!r} manifest count does not match schedule"
            )
        manifest_ids = set().union(*(set(entry.record_ids) for entry in entries))
        schedule_ids = set(group["observation_ids"])
        if manifest_ids != schedule_ids:
            raise CampaignError(
                f"group {group_id!r} manifest observation ids do not match schedule"
            )
        overlap = seen_observation_ids & schedule_ids
        if overlap:
            raise CampaignError(
                "schedule assigns an observation more than once: "
                + ", ".join(sorted(overlap)[:8])
            )
        seen_observation_ids.update(schedule_ids)
        total_observations += group["observation_count"]
        group["manifest_path"] = manifest_path
        normalised.append(group)

    if summary.get("group_count") != len(normalised):
        raise CampaignError("schedule summary group_count does not match groups")
    if summary.get("observation_count") != total_observations:
        raise CampaignError("schedule summary observation_count does not match groups")
    return schedule, normalised, hashlib.sha256(raw).hexdigest()


def _expected_schemes(group: dict[str, Any]) -> set[str] | None:
    mode = group["mode"]
    if mode in {"http1", "http2", "websocket"}:
        return {"http", "https"} if mode == "http1" else {"http", "https", "tcp"}
    if mode in {"dns", "pcp", "radius", "sip"}:
        return {"udp"}
    schemes = set(group.get("endpoint_schemes", []))
    return schemes or None


def _group_output_name(group_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", group_id).strip("-._") or "group"
    token = hashlib.sha256(group_id.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:64]}-{token}"


def _select_traffic_url(
    group: dict[str, Any],
    *,
    common: str | None,
    http: str | None,
    tcp: str | None,
    udp: str | None,
) -> str | None:
    mode = group["mode"]
    if mode == "none":
        selected = common or http or tcp or udp
    elif mode in {"http1", "http2", "websocket"}:
        selected = http or tcp or common
    elif mode in {"dns", "pcp", "radius", "sip"}:
        selected = udp or common
    else:
        schemes = set(group.get("endpoint_schemes", []))
        if schemes == {"tcp"}:
            selected = tcp or common
        elif schemes == {"udp"}:
            selected = udp or common
        else:
            selected = common
    if selected is None:
        return None
    parsed = RUNNER.COLLECTOR._validate_traffic_url(selected)
    expected = _expected_schemes(group)
    if expected is not None and parsed.scheme not in expected:
        expected_label = ", ".join(sorted(expected))
        raise CampaignError(
            f"group {group['id']!r} requires {expected_label} traffic, got {parsed.scheme}"
        )
    return selected


def _runner_command(
    group: dict[str, Any],
    *,
    runner_script: Path,
    traffic_url: str | None,
    bigip_url: str | None,
    virtual: str | None,
    trigger_command: str | None,
    mode: str,
    records_root: Path,
    capture_wire: bool,
    allow_partial: bool,
    allow_scenario_rule: bool,
    insecure: bool,
) -> list[str]:
    if mode in {"preflight", "execute"} and (
        not bigip_url or not virtual or not traffic_url
    ):
        raise CampaignError(
            f"group {group['id']!r} requires --bigip-url, --virtual, and a matching traffic URL"
        )
    command = [
        sys.executable,
        str(runner_script.resolve()),
        "--manifest",
        str(group["manifest_path"]),
        "--bigip-url",
        bigip_url or "<BIGIP_URL>",
        "--virtual",
        virtual or "<VIRTUAL>",
        "--traffic-url",
        traffic_url or "<TRAFFIC_URL>",
    ]
    if mode == "preflight":
        command.append("--preflight")
    elif mode == "execute":
        command.extend(
            [
                "--execute",
                "--allow-device-write",
                "--records",
                str((records_root / "records.ndjson").resolve()),
                "--state",
                str((records_root / "capture-state.json").resolve()),
            ]
        )
    if trigger_command and group.get("requires_trigger"):
        command.extend(("--trigger-command", trigger_command))
    if capture_wire:
        command.append("--capture-wire")
    if allow_partial:
        command.append("--allow-partial")
    if allow_scenario_rule:
        command.append("--allow-scenario-rule")
    if insecure:
        command.append("--insecure")
    return command


def build_campaign(
    schedule_path: Path,
    *,
    bigip_url: str | None = None,
    virtual: str | None = None,
    traffic_url: str | None = None,
    http_traffic_url: str | None = None,
    tcp_traffic_url: str | None = None,
    udp_traffic_url: str | None = None,
    trigger_command: str | None = None,
    mode: str = "plan",
    runner_script: Path = RUNNER_PATH,
    records_root: Path | None = None,
    capture_wire: bool = False,
    allow_partial: bool = False,
    allow_scenario_rule: bool = False,
    allow_device_write: bool = False,
    insecure: bool = False,
) -> dict[str, Any]:
    if mode not in {"plan", "preflight", "execute"}:
        raise CampaignError("mode must be plan, preflight, or execute")
    if mode == "execute" and not allow_device_write:
        raise CampaignError("--execute requires --allow-device-write")
    schedule, groups, schedule_sha256 = load_schedule(schedule_path)
    schedule_root = Path(schedule_path).expanduser().resolve().parent
    output_root = (records_root or schedule_root).expanduser().resolve()
    if trigger_command is None and any(group.get("requires_trigger") for group in groups):
        trigger_command = str(DRIVER_PATH.resolve())
    rows: list[dict[str, Any]] = []
    for group in groups:
        selected_url = _select_traffic_url(
            group,
            common=traffic_url,
            http=http_traffic_url,
            tcp=tcp_traffic_url,
            udp=udp_traffic_url,
        )
        command = _runner_command(
            group,
            runner_script=runner_script,
            traffic_url=selected_url,
            bigip_url=bigip_url,
            virtual=virtual,
            trigger_command=trigger_command,
            mode=mode,
            records_root=(output_root / _group_output_name(group["id"])),
            capture_wire=capture_wire,
            allow_partial=allow_partial,
            allow_scenario_rule=allow_scenario_rule,
            insecure=insecure,
        )
        row: dict[str, Any] = {
            "id": group["id"],
            "mode": group["mode"],
            "manifest": str(group["manifest_path"]),
            "observation_count": group["observation_count"],
            "requires_trigger": bool(group.get("requires_trigger")),
            "traffic_url": selected_url,
            "command": command,
            "status": "planned",
        }
        if mode != "plan":
            try:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    shell=False,
                    env=os.environ.copy(),
                )
            except OSError as exc:
                row.update({"status": "failed", "error": str(exc)[:MAX_ERROR_BYTES]})
                rows.append(row)
                break
            stdout = completed.stdout.decode("utf-8", errors="replace").strip()
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            row["exit_code"] = completed.returncode
            if completed.returncode != 0:
                row.update(
                    {
                        "status": "failed",
                        "error": (stderr or stdout or "runner failed")[-MAX_ERROR_BYTES:],
                    }
                )
                rows.append(row)
                break
            try:
                row["result"] = json.loads(stdout)
            except (json.JSONDecodeError, ValueError):
                row.update(
                    {
                        "status": "failed",
                        "error": "runner returned non-JSON output",
                    }
                )
                rows.append(row)
                break
            row["status"] = "completed"
        rows.append(row)
        if row["status"] == "failed":
            break
    completed_count = sum(1 for row in rows if row["status"] == "completed")
    failed_count = sum(1 for row in rows if row["status"] == "failed")
    return {
        "status": "failed" if failed_count else ("completed" if mode != "plan" else "planned"),
        "schema_version": 1,
        "profile": TMOS_PROFILE,
        "mode": mode,
        "schedule": str(Path(schedule_path).expanduser().resolve()),
        "schedule_sha256": schedule_sha256,
        "summary": {
            "group_count": len(groups),
            "planned_group_count": len(rows),
            "completed_group_count": completed_count,
            "failed_group_count": failed_count,
            "observation_count": sum(row["observation_count"] for row in rows),
        },
        "groups": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Plan or run a scheduled TMOS 17.5 capture campaign"
    )
    parser.add_argument("--schedule", required=True, help="split schedule.json path")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="run read-only device preflight")
    mode.add_argument("--execute", action="store_true", help="run resumable external capture")
    parser.add_argument(
        "--allow-device-write",
        action="store_true",
        help="acknowledge temporary device mutation (required with --execute)",
    )
    parser.add_argument("--bigip-url")
    parser.add_argument("--virtual")
    parser.add_argument("--traffic-url", help="common endpoint fallback")
    parser.add_argument("--http-traffic-url")
    parser.add_argument("--tcp-traffic-url")
    parser.add_argument("--udp-traffic-url")
    parser.add_argument("--trigger-command")
    parser.add_argument("--runner-script", default=str(RUNNER_PATH))
    parser.add_argument("--records-root", help="root for per-group records/state files")
    parser.add_argument("--capture-wire", action="store_true")
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--allow-scenario-rule", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args(argv)
    selected_mode = "execute" if args.execute else ("preflight" if args.preflight else "plan")
    try:
        result = build_campaign(
            Path(args.schedule),
            bigip_url=args.bigip_url,
            virtual=args.virtual,
            traffic_url=args.traffic_url,
            http_traffic_url=args.http_traffic_url,
            tcp_traffic_url=args.tcp_traffic_url,
            udp_traffic_url=args.udp_traffic_url,
            trigger_command=args.trigger_command,
            mode=selected_mode,
            runner_script=Path(args.runner_script),
            records_root=Path(args.records_root) if args.records_root else None,
            capture_wire=args.capture_wire,
            allow_partial=args.allow_partial,
            allow_scenario_rule=args.allow_scenario_rule,
            allow_device_write=args.allow_device_write,
            insecure=args.insecure,
        )
    except (CampaignError, RUNNER.RunnerError, OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
