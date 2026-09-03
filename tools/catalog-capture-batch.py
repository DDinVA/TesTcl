#!/usr/bin/env python3
"""Build a resumable TMOS 17.5 capture batch from an exported catalog.

Unlike the registry-driven batch builder, this tool treats the hashed catalog
bundle as the source of truth. Every source chunk is verified, converted into
one or more collector-safe plans, and recorded in a runner-compatible
manifest. It never contacts or mutates a BIG-IP.
"""

from __future__ import annotations

import argparse
import hashlib
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
WORKER_PATH = ROOT / "tools" / "catalog-worker.py"
BATCH_PATH = ROOT / "tools" / "tmos17-capture-batch.py"
MAX_METADATA_BYTES = 8 * 1024 * 1024
MAX_CHUNKS = 256
TMOS_PROFILE = "tmos-17.5"


class CatalogBatchError(RuntimeError):
    """Raised when an exported catalog cannot become a safe batch."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CatalogBatchError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


WORKER = _load_module(WORKER_PATH, "testcl_catalog_worker_for_batch")
BATCH = _load_module(BATCH_PATH, "testcl_capture_batch_helpers")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_json(path: Path, max_bytes: int) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CatalogBatchError(f"could not read {path}: {exc}") from exc
    if len(raw) > max_bytes:
        raise CatalogBatchError(f"{path.name} exceeds the {max_bytes} byte limit")
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant), raw
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CatalogBatchError(f"{path} is not valid UTF-8 JSON: {exc}") from exc


def _safe_catalog_file(base: Path, filename: Any) -> Path:
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise CatalogBatchError("catalog manifest file must be a non-empty string")
    relative = Path(filename)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise CatalogBatchError(f"catalog manifest file is not a safe relative path: {filename!r}")
    candidate = base / relative
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CatalogBatchError(f"catalog manifest file must not be a symlink: {filename!r}")
    path = candidate.resolve()
    if base.resolve() not in path.parents:
        raise CatalogBatchError(f"catalog manifest file escapes the bundle: {filename!r}")
    if path.is_symlink() or not path.is_file():
        raise CatalogBatchError(f"catalog manifest file is not a regular file: {filename!r}")
    return path


def _load_catalog(catalog_dir: Path) -> tuple[dict[str, Any], list[tuple[Path, dict[str, Any], str]], str]:
    catalog_dir = catalog_dir.expanduser()
    if catalog_dir.is_symlink() or not catalog_dir.is_dir():
        raise CatalogBatchError(f"catalog directory is not a real directory: {catalog_dir}")
    manifest_path = _safe_catalog_file(catalog_dir, "manifest.json")
    manifest, raw_manifest = _read_json(manifest_path, MAX_METADATA_BYTES)
    if not isinstance(manifest, dict):
        raise CatalogBatchError("catalog manifest must be a JSON object")
    if manifest.get("schema_version") != 1 or manifest.get("profile") != TMOS_PROFILE:
        raise CatalogBatchError("catalog manifest must use schema 1 and profile tmos-17.5")
    files = manifest.get("files")
    chunks = files.get("chunks") if isinstance(files, dict) else None
    if not isinstance(chunks, list) or not chunks or len(chunks) > MAX_CHUNKS:
        raise CatalogBatchError(f"catalog manifest must contain 1 to {MAX_CHUNKS} chunks")

    loaded: list[tuple[Path, dict[str, Any], str]] = []
    expected_offset = 0
    seen_names: set[str] = set()
    for index, info in enumerate(chunks):
        if not isinstance(info, dict):
            raise CatalogBatchError(f"catalog manifest chunk {index} must be an object")
        path = _safe_catalog_file(catalog_dir, info.get("file"))
        digest = info.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise CatalogBatchError(f"catalog manifest chunk {index} has an invalid SHA-256")
        try:
            if path.stat().st_size > MAX_METADATA_BYTES:
                raise CatalogBatchError(
                    f"catalog chunk {path.name} exceeds the {MAX_METADATA_BYTES} byte limit"
                )
            raw = path.read_bytes()
        except OSError as exc:
            raise CatalogBatchError(f"could not read catalog chunk {path}: {exc}") from exc
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest != digest:
            raise CatalogBatchError(f"catalog chunk hash mismatch: {path.name}")
        chunk = WORKER._read_chunk(path)
        metadata = chunk["chunk"]
        if metadata["offset"] != expected_offset:
            raise CatalogBatchError("catalog chunks are not contiguous in manifest order")
        names = {item["name"] for item in chunk["commands"]}
        duplicate_names = seen_names & names
        if duplicate_names:
            raise CatalogBatchError(
                "catalog bundle repeats command name(s): " + ", ".join(sorted(duplicate_names)[:8])
            )
        seen_names.update(names)
        expected_offset += metadata["count"]
        loaded.append((path, chunk, digest))

    manifest_summary = manifest.get("chunking")
    if not isinstance(manifest_summary, dict):
        raise CatalogBatchError("catalog manifest chunking metadata must be an object")
    if manifest_summary.get("command_count") != expected_offset:
        raise CatalogBatchError("catalog manifest command_count does not match chunks")
    if loaded[-1][1]["chunk"]["has_more"]:
        raise CatalogBatchError("catalog bundle ends before its final chunk")
    return manifest, loaded, hashlib.sha256(raw_manifest).hexdigest()


def _write_json(path: Path, payload: Any, max_bytes: int) -> None:
    try:
        encoded = json.dumps(
            payload, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CatalogBatchError(f"could not serialize {path.name}: {exc}") from exc
    if len(encoded) > max_bytes:
        raise CatalogBatchError(f"generated file {path.name} exceeds {max_bytes} bytes")
    try:
        path.write_bytes(encoded)
    except OSError as exc:
        raise CatalogBatchError(f"could not write {path}: {exc}") from exc


def _new_output(output_dir: Path) -> tuple[Path, Path]:
    output_dir = output_dir.expanduser()
    if output_dir.is_symlink() or output_dir.exists():
        raise CatalogBatchError(f"output directory already exists or is a symlink: {output_dir}")
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    except OSError as exc:
        raise CatalogBatchError(f"could not create batch staging directory: {exc}") from exc
    return output_dir.resolve(), staging


def build_batch_from_catalog(
    *,
    catalog_dir: Path,
    output_dir: Path,
    tcl_lsp_root: str | None = None,
    variants: int = 1,
    source: str = "external-bigip-or-vlab",
    collector: str = "catalog-capture-batch",
    tmos_build: str = "17.5",
    capture_id: str = "tmos-17.5-catalog",
) -> dict[str, Any]:
    if isinstance(variants, bool) or not isinstance(variants, int) or not 1 <= variants <= 8:
        raise CatalogBatchError("variants must be an integer between 1 and 8")
    manifest, chunks, manifest_sha256 = _load_catalog(catalog_dir)
    output_path, staging = _new_output(output_dir)
    root = WORKER.EMULATOR._find_tcl_lsp_root(tcl_lsp_root)
    blocked_names = frozenset(BATCH.COLLECTOR.DANGEROUS_TCL_COMMANDS)
    plan_payloads: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    blocked_cases: list[dict[str, Any]] = []
    schedule_groups: dict[str, dict[str, Any]] = {}
    aggregate_events: dict[str, int] = {}
    aggregate_modes: dict[str, int] = {}
    aggregate_statuses: dict[str, int] = {}
    aggregate_failures: list[dict[str, Any]] = []
    command_count = 0
    capturable_command_count = 0
    observation_count = 0
    directly_triggerable_count = 0
    requires_trigger_count = 0

    try:
        for chunk_path, chunk, chunk_sha256 in chunks:
            for command in chunk["commands"]:
                if (
                    command.get("catalog_kind") == "f5-irule"
                    and command.get("target_status") == "available-in-tmos-17.5"
                    and command["name"] in blocked_names
                ):
                    blocked_cases.append(
                        {
                            **command,
                            "collector_block_reason": (
                                "collector safety policy blocks direct command-name injection"
                            ),
                        }
                    )
            report = WORKER._build_report(
                chunk,
                tcl_lsp_root=str(root),
                variants=variants,
                mode="plan",
                exclude_commands=blocked_names,
            )
            plan = report.get("capture_plan")
            command_count += report["summary"]["target_command_count"]
            capturable_command_count += report["summary"]["generated_command_count"]
            if plan is None:
                continue
            plan_index = len(plan_payloads)
            plan["name"] = f"{capture_id}-chunk-{plan_index:04d}"
            plan["source"] = source
            plan["provenance"].update(
                {
                    "collector": collector,
                    "tmos_build": tmos_build,
                    "capture_id": f"{capture_id}-chunk-{plan_index:04d}",
                    "generator": "tmos-17.5-catalog-capture-batch-v1",
                    "catalog_manifest_sha256": manifest_sha256,
                    "catalog_chunk": chunk_path.name,
                    "catalog_chunk_sha256": chunk_sha256,
                }
            )
            plan = WORKER.EMULATOR._normalise_capture_plan(root, plan)
            validated = BATCH.COLLECTOR.validate_plan(plan)
            observations = validated["observations"]
            driver_results = [BATCH._driver_preflight(item) for item in observations]
            plan_filename = f"plan-{plan_index:04d}.json"
            event_counts = BATCH._event_counts(observations)
            driver_modes: dict[str, int] = {}
            driver_statuses: dict[str, int] = {}
            driver_failures: list[dict[str, Any]] = []
            for event, count in event_counts.items():
                aggregate_events[event] = aggregate_events.get(event, 0) + count
            for result in driver_results:
                mode = result["mode"]
                status = result["status"]
                driver_modes[mode] = driver_modes.get(mode, 0) + 1
                driver_statuses[status] = driver_statuses.get(status, 0) + 1
                aggregate_modes[mode] = aggregate_modes.get(mode, 0) + 1
                aggregate_statuses[status] = aggregate_statuses.get(status, 0) + 1
                if status == "fixture-error":
                    failure = {key: result[key] for key in ("id", "event", "mode", "error")}
                    driver_failures.append(failure)
                    if len(aggregate_failures) < 32:
                        aggregate_failures.append(failure)
                BATCH._record_stimulus_group(schedule_groups, result, plan_filename=plan_filename)
            supported = sum(1 for item in observations if item["event_supported"])
            plan_payloads.append(
                (
                    plan_filename,
                    plan,
                    {
                        "file": plan_filename,
                        "source_chunk": chunk_path.name,
                        "source_chunk_sha256": chunk_sha256,
                        "command_count": report["summary"]["generated_command_count"],
                        "observation_count": len(observations),
                        "directly_triggerable_count": supported,
                        "requires_trigger_count": len(observations) - supported,
                        "event_counts": event_counts,
                        "driver_mode_counts": dict(sorted(driver_modes.items())),
                        "driver_preflight_status_counts": dict(sorted(driver_statuses.items())),
                        "driver_preflight_failures": driver_failures[:32],
                        "commands": [item["input"]["command"] for item in observations],
                    },
                )
            )
            observation_count += len(observations)
            directly_triggerable_count += supported
            requires_trigger_count += len(observations) - supported

        if not plan_payloads:
            raise CatalogBatchError("exported catalog contains no capturable TMOS 17.5 commands")
        output_manifest = {
            "schema_version": 1,
            "profile": TMOS_PROFILE,
            "status": "ready-with-collector-blocks" if blocked_cases else "ready-for-external-capture",
            "generator": "tmos-17.5-catalog-capture-batch-v1",
            "source_catalog": {
                "directory": str(catalog_dir.expanduser().resolve()),
                "manifest": "manifest.json",
                "manifest_sha256": manifest_sha256,
                "source": manifest.get("source"),
                "filter": manifest.get("filter"),
                "chunk_count": len(chunks),
            },
            "provenance": {
                "source": source,
                "collector": collector,
                "tmos_build": tmos_build,
                "capture_id": capture_id,
                "tcl_lsp_commit": os.environ.get("TCL_LSP_COMMIT"),
            },
            "selection": {
                "variants": variants,
                "collector_blocked_commands": len(blocked_cases),
            },
            "summary": {
                "source_catalog_command_count": manifest["chunking"]["command_count"],
                "target_command_count": command_count,
                "capturable_command_count": capturable_command_count,
                "collector_blocked_command_count": len(blocked_cases),
                "plan_count": len(plan_payloads),
                "observation_count": observation_count,
                "directly_triggerable_count": directly_triggerable_count,
                "requires_trigger_count": requires_trigger_count,
                "event_counts": dict(sorted(aggregate_events.items())),
                "bundled_driver_mode_counts": dict(sorted(aggregate_modes.items())),
                "bundled_driver_preflight_status_counts": dict(sorted(aggregate_statuses.items())),
                "bundled_driver_preflight_failures": aggregate_failures,
            },
            "blocked_catalog_file": "blocked-catalog.json",
            "protocol_driver": BATCH.PROTOCOL_DRIVER.capability_report(),
            "stimulus_schedule": {
                "schema_version": 1,
                "groups": BATCH._finalise_stimulus_schedule(schedule_groups),
                "interpretation": (
                    "Plans were generated from verified exported chunks. Use this schedule "
                    "to supply protocol/event-compatible external stimuli."
                ),
            },
            "plans": [info for _, _, info in plan_payloads],
        }
        _write_json(
            staging / "blocked-catalog.json",
            {
                "schema_version": 1,
                "profile": TMOS_PROFILE,
                "status": "collector-blocked",
                "commands": blocked_cases,
            },
            MAX_METADATA_BYTES,
        )
        for filename, plan, _ in plan_payloads:
            _write_json(staging / filename, plan, BATCH.COLLECTOR.MAX_PLAN_BYTES)
        _write_json(staging / "manifest.json", output_manifest, MAX_METADATA_BYTES)
        if output_path.exists() or output_path.is_symlink():
            raise CatalogBatchError(f"output directory appeared during batch build: {output_path}")
        staging.rename(output_path)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--tcl-lsp-root")
    parser.add_argument("--variants", type=int, default=1)
    parser.add_argument("--source", default="external-bigip-or-vlab")
    parser.add_argument("--collector", default="catalog-capture-batch")
    parser.add_argument("--tmos-build", default="17.5")
    parser.add_argument("--capture-id", default="tmos-17.5-catalog")
    args = parser.parse_args(argv)
    try:
        manifest = build_batch_from_catalog(
            catalog_dir=Path(args.catalog_dir),
            output_dir=Path(args.output_dir),
            tcl_lsp_root=args.tcl_lsp_root,
            variants=args.variants,
            source=args.source,
            collector=args.collector,
            tmos_build=args.tmos_build,
            capture_id=args.capture_id,
        )
    except (CatalogBatchError, WORKER.CatalogWorkerError, WORKER.EMULATOR.EmulatorInputError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps({"status": "ok", "manifest": str(Path(args.output_dir).expanduser().resolve()), "summary": manifest["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
