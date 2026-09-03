#!/usr/bin/env python3
"""Split a TMOS 17.5 capture batch into protocol/event-ready sub-batches.

The catalog batch is intentionally lossless and may mix several stimulus
families in one collector-safe plan. This tool consumes its manifest schedule
and materializes one independently resumable runner batch per schedule group.
Observation IDs and comparisons are preserved byte-for-byte; only plan
provenance and the surrounding manifest identify the split.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "tools" / "tmos17-capture-runner.py"
MAX_METADATA_BYTES = 8 * 1024 * 1024


class SplitError(RuntimeError):
    """Raised when a capture schedule cannot be safely materialized."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SplitError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = _load_module(RUNNER_PATH, "testcl_tmos17_capture_runner_for_split")
MAX_NAME_BYTES = 256
MAX_PROVENANCE_VALUE_BYTES = 256


def _with_suffix(prefix: str, suffix: str, *, field: str) -> str:
    """Append an ASCII suffix while respecting the UTF-8 field limit."""
    suffix_bytes = suffix.encode("utf-8")
    if len(suffix_bytes) >= MAX_PROVENANCE_VALUE_BYTES:
        raise SplitError(f"{field} suffix exceeds the {MAX_PROVENANCE_VALUE_BYTES} byte limit")
    available = MAX_PROVENANCE_VALUE_BYTES - len(suffix_bytes)
    prefix_bytes = prefix.encode("utf-8")[:available]
    safe_prefix = prefix_bytes.decode("utf-8", errors="ignore")
    value = safe_prefix + suffix
    if not value or len(value.encode("utf-8")) > MAX_PROVENANCE_VALUE_BYTES:
        raise SplitError(f"{field} cannot be bounded to the required UTF-8 limit")
    return value


def _write_json(path: Path, payload: Any, max_bytes: int) -> None:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SplitError(f"could not serialize {path.name}: {exc}") from exc
    if len(encoded) > max_bytes:
        raise SplitError(f"{path.name} exceeds the {max_bytes} byte limit")
    try:
        path.write_bytes(encoded + b"\n")
    except OSError as exc:
        raise SplitError(f"could not write {path}: {exc}") from exc


def _slug(group_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", group_id).strip("-._")
    if not safe:
        safe = "group"
    token = hashlib.sha256(group_id.encode("utf-8")).hexdigest()[:12]
    return f"{safe[:64]}-{token}"


def _new_staging(output_dir: Path) -> tuple[Path, Path]:
    expanded = output_dir.expanduser()
    if expanded.is_symlink():
        raise SplitError(f"output directory must not be a symlink: {expanded}")
    resolved = expanded.resolve()
    if resolved.name in {"", ".", ".."}:
        raise SplitError("output directory must have a concrete name")
    if resolved.exists() or resolved.is_symlink():
        raise SplitError(f"output directory already exists: {resolved}")
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{resolved.name}-", dir=resolved.parent))
    except OSError as exc:
        raise SplitError(f"could not create output staging directory: {exc}") from exc
    return resolved, staging


def _load_schedule(
    manifest_path: Path,
    selected_group: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, dict[str, Any]], str]:
    try:
        manifest, entries, manifest_sha256 = RUNNER._load_batch(manifest_path)
    except (RUNNER.RunnerError, OSError) as exc:
        raise SplitError(f"invalid capture batch: {exc}") from exc
    schedule = manifest.get("stimulus_schedule")
    if not isinstance(schedule, dict) or schedule.get("schema_version") != 1:
        raise SplitError("capture manifest has no supported stimulus_schedule")
    groups = schedule.get("groups")
    if not isinstance(groups, list) or not groups:
        raise SplitError("stimulus_schedule.groups must be a non-empty array")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict) or not isinstance(provenance.get("capture_id"), str):
        raise SplitError("capture manifest provenance.capture_id must be a string")

    source_observations: dict[str, dict[str, Any]] = {}
    source_plans: dict[str, dict[str, Any]] = {}
    try:
        for entry in entries:
            plan, _ = RUNNER._read_json(entry.path, RUNNER.MAX_PLAN_BYTES)
            validated = RUNNER.COLLECTOR.validate_plan(plan)
            source_plans[entry.filename] = plan
            for observation in validated["observations"]:
                if observation["id"] in source_observations:
                    raise SplitError(
                        f"capture batch contains duplicate observation id {observation['id']!r}"
                    )
                source_observations[observation["id"]] = observation
    except (RUNNER.RunnerError, RUNNER.COLLECTOR.CollectorError, OSError) as exc:
        raise SplitError(f"could not load capture plans: {exc}") from exc

    normalised_groups: list[dict[str, Any]] = []
    group_ids: dict[str, dict[str, Any]] = {}
    assigned: set[str] = set()
    for index, raw_group in enumerate(groups):
        if not isinstance(raw_group, dict):
            raise SplitError(f"stimulus schedule group {index} must be an object")
        group_id = raw_group.get("id")
        observation_ids = raw_group.get("observation_ids")
        if not isinstance(group_id, str) or not group_id:
            raise SplitError(f"stimulus schedule group {index} has an invalid id")
        if group_id in group_ids:
            raise SplitError(f"stimulus schedule repeats group {group_id!r}")
        if not isinstance(observation_ids, list) or not observation_ids:
            raise SplitError(f"stimulus schedule group {group_id!r} has no observation_ids")
        if any(not isinstance(item, str) or not item for item in observation_ids):
            raise SplitError(f"stimulus schedule group {group_id!r} has an invalid observation id")
        ids = set(observation_ids)
        if len(ids) != len(observation_ids):
            raise SplitError(f"stimulus schedule group {group_id!r} repeats an observation id")
        missing = sorted(ids - set(source_observations))
        if missing:
            raise SplitError(
                f"stimulus schedule group {group_id!r} references unknown observation(s): "
                + ", ".join(missing[:8])
            )
        overlap = assigned & ids
        if overlap:
            raise SplitError(
                "stimulus schedule assigns observation more than once: "
                + ", ".join(sorted(overlap)[:8])
            )
        assigned.update(ids)
        group = dict(raw_group)
        group["observation_ids"] = sorted(observation_ids)
        group_ids[group_id] = group
        normalised_groups.append(group)

    expected = set(source_observations)
    if assigned != expected:
        missing = sorted(expected - assigned)
        extra = sorted(assigned - expected)
        detail: list[str] = []
        if missing:
            detail.append("unassigned: " + ", ".join(missing[:8]))
        if extra:
            detail.append("unexpected: " + ", ".join(extra[:8]))
        raise SplitError("stimulus schedule does not cover the batch (" + "; ".join(detail) + ")")
    if selected_group is not None:
        if selected_group not in group_ids:
            raise SplitError(f"unknown stimulus schedule group {selected_group!r}")
        normalised_groups = [group_ids[selected_group]]
    return manifest, normalised_groups, source_plans, manifest_sha256


def _group_plan(
    source_plan: dict[str, Any],
    observations: list[dict[str, Any]],
    *,
    group_id: str,
    group_slug: str,
) -> dict[str, Any]:
    provenance = dict(source_plan["provenance"])
    group_token = f"group-{group_slug}"
    provenance["capture_id"] = _with_suffix(
        provenance["capture_id"], f"-{group_token}", field="capture_id"
    )
    filtered = dict(source_plan)
    filtered["name"] = _with_suffix(
        source_plan["name"], f"-{group_token}", field="plan name"
    )
    filtered["provenance"] = provenance
    filtered["observations"] = observations
    try:
        RUNNER.COLLECTOR.validate_plan(filtered)
    except RUNNER.COLLECTOR.CollectorError as exc:
        raise SplitError(
            f"split plan for group {group_id!r} fails collector validation: {exc}"
        ) from exc
    return filtered


def split_batch(
    manifest_path: Path,
    output_dir: Path,
    *,
    group: str | None = None,
) -> dict[str, Any]:
    manifest_path = manifest_path.expanduser().resolve()
    if not manifest_path.is_file():
        raise SplitError(f"capture manifest does not exist: {manifest_path}")
    manifest, groups, source_plans, manifest_sha256 = _load_schedule(manifest_path, group)
    final_dir, staging = _new_staging(output_dir)
    schedule_rows: list[dict[str, Any]] = []
    total_observations = 0
    try:
        for group_data in groups:
            group_id = group_data["id"]
            group_slug = _slug(group_id)
            group_dir = staging / group_slug
            group_dir.mkdir()
            wanted = set(group_data["observation_ids"])
            plan_rows: list[dict[str, Any]] = []
            group_observation_count = 0
            for plan_index, (source_filename, source_plan) in enumerate(source_plans.items()):
                observations = [
                    observation
                    for observation in source_plan["observations"]
                    if observation["id"] in wanted
                ]
                if not observations:
                    continue
                filtered = _group_plan(
                    source_plan,
                    observations,
                    group_id=group_id,
                    group_slug=group_slug,
                )
                filename = f"plan-{plan_index:04d}.json"
                _write_json(group_dir / filename, filtered, RUNNER.MAX_PLAN_BYTES)
                command_names = {
                    item["input"]["command"]
                    for item in observations
                    if isinstance(item.get("input"), dict)
                    and isinstance(item["input"].get("command"), str)
                }
                plan_rows.append(
                    {
                        "file": filename,
                        "source_file": source_filename,
                        "command_count": len(command_names),
                        "observation_count": len(observations),
                        "directly_triggerable_count": sum(
                            1
                            for item in observations
                            if item["input"]["event"] in {"HTTP_REQUEST", "RULE_INIT"}
                            and not (
                                item["input"]["event"] == "HTTP_REQUEST"
                                and isinstance(item["input"].get("request"), dict)
                                and isinstance(item["input"]["request"].get("http2"), dict)
                            )
                        ),
                        "requires_trigger_count": sum(
                            1
                            for item in observations
                            if item["input"]["event"] not in {"HTTP_REQUEST", "RULE_INIT"}
                            or (
                                item["input"]["event"] == "HTTP_REQUEST"
                                and isinstance(item["input"].get("request"), dict)
                                and isinstance(item["input"]["request"].get("http2"), dict)
                            )
                        ),
                    }
                )
                group_observation_count += len(observations)

            group_manifest = {
                "schema_version": 1,
                "profile": "tmos-17.5",
                "status": manifest.get("status"),
                "generator": "tmos17-capture-schedule-v1",
                "selection": {
                    "source_manifest": manifest_path.name,
                    "source_manifest_sha256": manifest_sha256,
                    "group_id": group_id,
                    "mode": group_data.get("mode"),
                    "events": group_data.get("events", []),
                },
                "provenance": {
                    **dict(manifest.get("provenance", {})),
                    "capture_id": _with_suffix(
                        manifest["provenance"]["capture_id"],
                        f"-group-{group_slug}",
                        field="capture_id",
                    ),
                },
                "summary": {
                    "plan_count": len(plan_rows),
                    "command_count": sum(row["command_count"] for row in plan_rows),
                    "observation_count": group_observation_count,
                    "directly_triggerable_count": sum(
                        row["directly_triggerable_count"] for row in plan_rows
                    ),
                    "requires_trigger_count": sum(
                        row["requires_trigger_count"] for row in plan_rows
                    ),
                },
                "plans": plan_rows,
            }
            _write_json(group_dir / "manifest.json", group_manifest, MAX_METADATA_BYTES)
            schedule_rows.append(
                {
                    **group_data,
                    "directory": group_slug,
                    "manifest": f"{group_slug}/manifest.json",
                }
            )
            total_observations += group_observation_count

        output_schedule = {
            "schema_version": 1,
            "profile": "tmos-17.5",
            "status": "ready",
            "source": {
                "manifest": manifest_path.name,
                "manifest_sha256": manifest_sha256,
            },
            "splitter": "tmos17-capture-split-v1",
            "summary": {
                "group_count": len(schedule_rows),
                "observation_count": total_observations,
            },
            "groups": schedule_rows,
        }
        _write_json(staging / "schedule.json", output_schedule, MAX_METADATA_BYTES)
        if final_dir.exists() or final_dir.is_symlink():
            raise SplitError(f"output directory appeared during split: {final_dir}")
        try:
            staging.rename(final_dir)
        except OSError as exc:
            raise SplitError(f"could not publish split schedule: {exc}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "status": "ready",
        "profile": "tmos-17.5",
        "output_dir": str(final_dir),
        "group_count": len(schedule_rows),
        "observation_count": total_observations,
        "schedule": str(final_dir / "schedule.json"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Split a TMOS 17.5 capture batch into scheduled runner sub-batches"
    )
    parser.add_argument("--manifest", required=True, help="source capture batch manifest")
    parser.add_argument("--output-dir", required=True, help="new directory for split batches")
    parser.add_argument("--group", help="split only this stimulus schedule group")
    args = parser.parse_args(argv)
    try:
        result = split_batch(Path(args.manifest), Path(args.output_dir), group=args.group)
    except (SplitError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
