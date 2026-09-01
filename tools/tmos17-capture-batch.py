#!/usr/bin/env python3
"""Build a complete, collector-validated TMOS 17.5 capture batch.

The emulator owns catalog selection and plan generation; the companion
collector owns the external safety contract. This tool joins those two
boundaries so an operator can materialize every selected catalog command as a
set of bounded JSON plans without manually tracking offsets. It never talks
to a BIG-IP and never mutates an existing output directory.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"
COLLECTOR_PATH = ROOT / "tools" / "tmos17-collector.py"
PROTOCOL_DRIVER_PATH = ROOT / "tools" / "tmos17-protocol-driver.py"


class BatchError(RuntimeError):
    """Raised when a complete capture batch cannot be built safely."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BatchError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EMULATOR = _load_module(EMULATOR_PATH, "testcl_irule_emulator_for_batch")
COLLECTOR = _load_module(COLLECTOR_PATH, "testcl_tmos17_collector_for_batch")
PROTOCOL_DRIVER = _load_module(
    PROTOCOL_DRIVER_PATH, "testcl_tmos17_protocol_driver_for_batch"
)
MAX_METADATA_BYTES = 8 * 1024 * 1024


def _write_json(path: Path, payload: Any, *, max_bytes: int | None = None) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    if max_bytes is not None and len(encoded) > max_bytes:
        raise BatchError(
            f"generated file {path.name!r} exceeds the collector's "
            f"{max_bytes} byte limit"
        )
    path.write_bytes(encoded + b"\n")


def _event_counts(observations: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for observation in observations:
        event = observation["input"]["event"]
        counts[event] = counts.get(event, 0) + 1
    return dict(sorted(counts.items()))


def _stimulus_group_id(result: dict[str, Any]) -> str:
    """Return a stable live-capture grouping key for one driver fixture.

    Specialized protocol modes can share a driver invocation contract. Raw
    fixtures cannot: the event name is the only reliable indication of which
    iRule lifecycle hook must be stimulated. Keeping raw events separate also
    prevents an operator from accidentally treating a mixed-event plan as one
    protocol transaction.
    """
    mode = result["mode"]
    if mode == "none":
        return "control"
    if mode in {"raw", "unknown"}:
        return f"{mode}:{result['event']}"
    return mode


def _stimulus_group_template(group_id: str, result: dict[str, Any]) -> dict[str, Any]:
    mode = result["mode"]
    event = result["event"]
    return {
        "id": group_id,
        "mode": mode,
        "events": [],
        "observation_ids": [],
        "observation_count": 0,
        "plan_files": [],
        "requires_trigger": False,
        "direct_event_count": 0,
        "driver_status_counts": {},
        "endpoint_schemes": [],
        "operator_guidance": (
            "install the plan's temporary probe rule and use the collector's "
            "direct HTTP/RULE_INIT path"
            if event in {"HTTP_REQUEST", "RULE_INIT"}
            else "install the plan's temporary probe rule and invoke the "
            "matching tmos17-protocol-driver trigger"
        ),
    }


def _record_stimulus_group(
    groups: dict[str, dict[str, Any]],
    result: dict[str, Any],
    *,
    plan_filename: str,
) -> None:
    group_id = _stimulus_group_id(result)
    group = groups.setdefault(group_id, _stimulus_group_template(group_id, result))
    event = result["event"]
    if event not in group["events"]:
        group["events"].append(event)
    group["observation_ids"].append(result["id"])
    if plan_filename not in group["plan_files"]:
        group["plan_files"].append(plan_filename)
    group["observation_count"] += 1
    if result.get("event_supported"):
        group["direct_event_count"] += 1
    elif event != "RULE_INIT":
        group["requires_trigger"] = True
    status = result["status"]
    status_counts = group["driver_status_counts"]
    status_counts[status] = status_counts.get(status, 0) + 1
    scheme = result.get("endpoint_scheme")
    if isinstance(scheme, str) and scheme not in group["endpoint_schemes"]:
        group["endpoint_schemes"].append(scheme)


def _finalise_stimulus_schedule(
    groups: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    finalised: list[dict[str, Any]] = []
    for group_id in sorted(groups):
        group = dict(groups[group_id])
        group["events"] = sorted(group["events"])
        group["observation_ids"] = sorted(group["observation_ids"])
        group["plan_files"] = sorted(group["plan_files"])
        group["endpoint_schemes"] = sorted(group["endpoint_schemes"])
        group["driver_status_counts"] = dict(sorted(group["driver_status_counts"].items()))
        if group["mode"] == "none":
            group["operator_guidance"] = (
                "install the plan's temporary probe rule and observe the "
                "RULE_INIT result during rule installation"
            )
        elif group["requires_trigger"] and group["direct_event_count"]:
            group["operator_guidance"] = (
                "use the collector's direct path for directly supported events "
                "and invoke the matching tmos17-protocol-driver trigger for "
                "the remaining events"
            )
        elif group["requires_trigger"]:
            group["operator_guidance"] = (
                "install the plan's temporary probe rule and invoke the "
                "matching tmos17-protocol-driver trigger"
            )
        else:
            group["operator_guidance"] = (
                "install the plan's temporary probe rule and use the collector's "
                "direct HTTP/RULE_INIT path"
            )
        finalised.append(group)
    return finalised


def _driver_preflight(observation: dict[str, Any]) -> dict[str, Any]:
    """Validate one generated driver fixture without opening a network socket."""
    event = observation["input"]["event"]
    event_supported = observation.get("event_supported", False)
    if not isinstance(event_supported, bool):
        raise BatchError("collector event_supported must be a boolean")
    if event == "RULE_INIT":
        return {
            "id": observation["id"],
            "event": event,
            "mode": "none",
            "status": "not-required",
            "event_supported": event_supported,
        }
    request = observation["input"].get("request", {})
    trigger = {
        "event": event,
        "request": request,
        "profiles": observation["input"].get("profiles", []),
        "traffic_url": "tcp://192.0.2.10:1024",
    }
    mode = "unknown"
    try:
        mode = PROTOCOL_DRIVER.payload_mode(trigger)
        endpoint, payload, _ = PROTOCOL_DRIVER.build_payload(trigger)
    except PROTOCOL_DRIVER.DriverError as exc:
        return {
            "id": observation["id"],
            "event": event,
            "mode": mode,
            "status": "fixture-error",
            "error": str(exc)[:2048],
            "event_supported": event_supported,
        }
    return {
        "id": observation["id"],
        "event": event,
        "mode": mode,
        "status": "raw-fallback" if mode == "raw" else "buildable",
        "endpoint_scheme": endpoint.scheme,
        "payload_bytes": len(payload),
        "event_supported": event_supported,
    }


def _normalise_optional_string(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not value or "\x00" in value:
        raise BatchError(f"{field} must be a non-empty NUL-free string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BatchError(f"{field} must be valid UTF-8") from exc
    return value


def build_batch(
    *,
    tcl_lsp_root: str | None,
    output_dir: Path,
    namespace: str | None = None,
    runtime_status: str | None = None,
    target_status: str | None = "available-in-tmos-17.5",
    variants: int = 1,
    chunk_size: int | None = None,
    source: str = "external-bigip-or-vlab",
    collector: str = "external-collector",
    tmos_build: str = "17.5",
    capture_id: str = "tmos-17.5-catalog",
) -> dict[str, Any]:
    """Write all selected plans and return the machine-readable manifest."""
    if isinstance(variants, bool) or not isinstance(variants, int):
        raise BatchError("variants must be an integer")
    if not 1 <= variants <= EMULATOR.BEHAVIOR_CANDIDATE_MAX_VARIANTS:
        raise BatchError(
            "variants must be between 1 and "
            f"{EMULATOR.BEHAVIOR_CANDIDATE_MAX_VARIANTS}"
        )
    max_chunk_size = EMULATOR.CAPTURE_MAX_RECORDS // variants
    if chunk_size is None:
        chunk_size = max_chunk_size
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise BatchError("chunk-size must be an integer")
    if not 1 <= chunk_size <= max_chunk_size:
        raise BatchError(
            f"chunk-size must be between 1 and {max_chunk_size} for "
            f"{variants} variant(s)"
        )
    namespace = _normalise_optional_string(namespace, "namespace")
    runtime_status = _normalise_optional_string(runtime_status, "runtime-status")
    target_status = _normalise_optional_string(target_status, "target-status")
    source = _normalise_optional_string(source, "source") or "external-bigip-or-vlab"
    collector = _normalise_optional_string(collector, "collector") or "external-collector"
    tmos_build = _normalise_optional_string(tmos_build, "tmos-build") or "17.5"
    capture_id = _normalise_optional_string(capture_id, "capture-id") or "tmos-17.5-catalog"
    if output_dir.exists():
        raise BatchError(
            f"output directory already exists: {output_dir}; choose a new directory"
        )
    output_dir = output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)

    root = EMULATOR._find_tcl_lsp_root(tcl_lsp_root)
    filters = {
        field: value
        for field, value in (
            ("namespace", namespace),
            ("runtime_status", runtime_status),
            ("target_status", target_status),
        )
        if value is not None
    }
    all_cases: list[dict[str, Any]] = []
    catalog_offset = 0
    while True:
        catalog_campaign = EMULATOR._build_capture_campaign(
            root, catalog_offset, 1000, **filters
        )
        catalog_data = catalog_campaign["campaign"]
        catalog_cases = catalog_data["cases"]
        all_cases.extend(catalog_cases)
        if not catalog_data["chunk"]["has_more"]:
            break
        selected_count = catalog_data["chunk"]["count"]
        if not isinstance(selected_count, int) or selected_count <= 0:
            raise BatchError("catalog campaign pagination made no progress")
        catalog_offset += selected_count
    if not all_cases:
        raise BatchError("the selected TMOS 17.5 catalog range is empty")
    blocked_cases = [
        {
            **case,
            "collector_block_reason": (
                "the collector safety policy blocks direct command-name injection; "
                "use a reviewed command-specific driver if this command must be captured"
            ),
        }
        for case in all_cases
        if case["name"] in COLLECTOR.DANGEROUS_TCL_COMMANDS
    ]
    blocked_names = frozenset(case["name"] for case in blocked_cases)
    plan_payloads: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    offset = 0
    command_count = 0
    observation_count = 0
    directly_triggerable_count = 0
    requires_trigger_count = 0
    aggregate_events: dict[str, int] = {}
    aggregate_driver_modes: dict[str, int] = {}
    aggregate_driver_statuses: dict[str, int] = {}
    aggregate_driver_failures: list[dict[str, Any]] = []
    stimulus_groups: dict[str, dict[str, Any]] = {}

    while True:
        campaign = EMULATOR._build_capture_campaign(
            root,
            offset,
            chunk_size,
            **filters,
            exclude_commands=blocked_names,
        )
        campaign_data = campaign["campaign"]
        cases = campaign_data["cases"]
        if not cases:
            break
        selected_count = campaign_data["chunk"]["count"]
        if not isinstance(selected_count, int) or selected_count != len(cases):
            raise BatchError("catalog campaign returned an inconsistent chunk count")
        plan_index = len(plan_payloads)
        plan = EMULATOR._build_capture_plan_template(
            root,
            offset,
            selected_count,
            **filters,
            source=source,
            collector=collector,
            tmos_build=tmos_build,
            capture_id=f"{capture_id}-chunk-{plan_index:04d}",
            name=f"{capture_id}-chunk-{plan_index:04d}",
            variants=variants,
            exclude_commands=blocked_names,
        )
        validated = COLLECTOR.validate_plan(plan)
        observations = validated["observations"]
        supported = sum(1 for item in observations if item["event_supported"])
        unsupported = len(observations) - supported
        events = _event_counts(observations)
        driver_results = [_driver_preflight(item) for item in observations]
        driver_modes: dict[str, int] = {}
        driver_statuses: dict[str, int] = {}
        driver_failures: list[dict[str, Any]] = []
        for result in driver_results:
            mode = result["mode"]
            status = result["status"]
            driver_modes[mode] = driver_modes.get(mode, 0) + 1
            driver_statuses[status] = driver_statuses.get(status, 0) + 1
            aggregate_driver_modes[mode] = aggregate_driver_modes.get(mode, 0) + 1
            aggregate_driver_statuses[status] = aggregate_driver_statuses.get(status, 0) + 1
            if status == "fixture-error":
                failure = {
                    "id": result["id"],
                    "event": result["event"],
                    "mode": mode,
                    "error": result["error"],
                }
                driver_failures.append(failure)
                if len(aggregate_driver_failures) < 32:
                    aggregate_driver_failures.append(failure)
        for event, count in events.items():
            aggregate_events[event] = aggregate_events.get(event, 0) + count
        plan_filename = f"plan-{plan_index:04d}.json"
        for result in driver_results:
            _record_stimulus_group(
                stimulus_groups,
                result,
                plan_filename=plan_filename,
            )
        plan_info = {
            "file": plan_filename,
            "offset": offset,
            "command_count": selected_count,
            "observation_count": len(observations),
            "directly_triggerable_count": supported,
            "requires_trigger_count": unsupported,
            "event_counts": events,
            "driver_mode_counts": dict(sorted(driver_modes.items())),
            "driver_preflight_status_counts": dict(sorted(driver_statuses.items())),
            "driver_preflight_failures": driver_failures[:32],
            "commands": [case["name"] for case in cases],
        }
        plan_payloads.append((plan_filename, plan, plan_info))
        command_count += selected_count
        observation_count += len(observations)
        directly_triggerable_count += supported
        requires_trigger_count += unsupported
        offset += selected_count

    manifest = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "status": (
            "ready-with-collector-blocks"
            if blocked_cases
            else "ready-for-external-capture"
        ),
        "generator": "tmos-17.5-capture-batch-v1",
        "selection": {
            "namespace": namespace,
            "runtime_status": runtime_status,
            "target_status": target_status,
            "variants": variants,
            "chunk_size": chunk_size,
            "collector_blocked_commands": len(blocked_cases),
        },
        "provenance": {
            "source": source,
            "collector": collector,
            "tmos_build": tmos_build,
            "capture_id": capture_id,
            "tcl_lsp_commit": os.environ.get("TCL_LSP_COMMIT"),
        },
        "summary": {
            "plan_count": len(plan_payloads),
            "command_count": len(all_cases),
            "capturable_command_count": command_count,
            "collector_blocked_command_count": len(blocked_cases),
            "observation_count": observation_count,
            "directly_triggerable_count": directly_triggerable_count,
            "requires_trigger_count": requires_trigger_count,
            "event_counts": dict(sorted(aggregate_events.items())),
            "bundled_driver_mode_counts": dict(sorted(aggregate_driver_modes.items())),
            "bundled_driver_preflight_status_counts": dict(
                sorted(aggregate_driver_statuses.items())
            ),
            "bundled_driver_preflight_failures": aggregate_driver_failures,
        },
        "blocked_catalog_file": "blocked-catalog.json",
        "protocol_driver": PROTOCOL_DRIVER.capability_report(),
        "stimulus_schedule": {
            "schema_version": 1,
            "groups": _finalise_stimulus_schedule(stimulus_groups),
            "interpretation": (
                "Plans are lossless command chunks; use this schedule to run "
                "protocol/event-compatible external stimuli. A live target "
                "may require separate virtual servers or traffic URLs per "
                "group, while observation IDs remain stable across captures."
            ),
        },
        "plans": [plan_info for _, _, plan_info in plan_payloads],
    }

    staging_dir = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        _write_json(
            staging_dir / "blocked-catalog.json",
            {
                "schema_version": 1,
                "profile": "tmos-17.5",
                "status": "collector-blocked",
                "commands": blocked_cases,
            },
            max_bytes=MAX_METADATA_BYTES,
        )
        for filename, plan, _ in plan_payloads:
            _write_json(
                staging_dir / filename,
                plan,
                max_bytes=COLLECTOR.MAX_PLAN_BYTES,
            )
        _write_json(
            staging_dir / "manifest.json",
            manifest,
            max_bytes=MAX_METADATA_BYTES,
        )
        os.replace(staging_dir, output_dir)
    except Exception:
        # The staging directory is private and removed on failure; no existing
        # user directory is removed or overwritten.
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build collector-validated TMOS 17.5 capture plans for a catalog range"
    )
    parser.add_argument("--output-dir", required=True, help="new directory for plans and manifest")
    parser.add_argument("--tcl-lsp-root", help="pinned tcl-lsp checkout (defaults to TCL_LSP_ROOT)")
    parser.add_argument("--namespace", help="limit to one exact command namespace")
    parser.add_argument("--runtime-status", help="limit by local runtime status")
    parser.add_argument(
        "--target-status",
        default="available-in-tmos-17.5",
        help="target catalog status (only available-in-tmos-17.5 is capturable)",
    )
    parser.add_argument("--variants", type=int, default=1, help="argument hypotheses per command (1-8)")
    parser.add_argument(
        "--chunk-size",
        type=int,
        help="commands per plan; defaults to the largest collector-safe chunk for --variants",
    )
    parser.add_argument("--source", default="external-bigip-or-vlab")
    parser.add_argument("--collector", default="external-collector")
    parser.add_argument("--tmos-build", default="17.5")
    parser.add_argument("--capture-id", default="tmos-17.5-catalog")
    args = parser.parse_args(argv)
    try:
        manifest = build_batch(
            tcl_lsp_root=args.tcl_lsp_root,
            output_dir=Path(args.output_dir),
            namespace=args.namespace,
            runtime_status=args.runtime_status,
            target_status=args.target_status,
            variants=args.variants,
            chunk_size=args.chunk_size,
            source=args.source,
            collector=args.collector,
            tmos_build=args.tmos_build,
            capture_id=args.capture_id,
        )
    except (BatchError, EMULATOR.EmulatorInputError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "manifest": str(Path(args.output_dir).resolve()),
                "summary": manifest["summary"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
