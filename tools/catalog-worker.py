#!/usr/bin/env python3
"""Evaluate one exported TMOS 17.5 catalog chunk.

The worker consumes an immutable ``catalog-export.py`` chunk, generates the
same bounded event/profile/argument candidates used by the API, optionally
executes them in the local emulator, and emits an assembly-ready external
capture plan. Local results are emulator diagnostics; the plan has no
reference output until a BIG-IP 17.5 system or vLab produces observations.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"
MAX_CHUNK_BYTES = 8 * 1024 * 1024
MAX_COMMANDS = 256
MAX_VARIANTS = 8
MAX_PLAN_OBSERVATIONS = 256
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
TMOS_PROFILE = "tmos-17.5"


class CatalogWorkerError(RuntimeError):
    """Raised when a chunk cannot be safely evaluated."""


def _load_emulator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "testcl_irule_emulator_for_catalog_worker", EMULATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise CatalogWorkerError(f"could not load emulator module {EMULATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EMULATOR = _load_emulator()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_chunk(path: Path) -> dict[str, Any]:
    if path == Path("-"):
        raw = sys.stdin.buffer.read(MAX_CHUNK_BYTES + 1)
    else:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise CatalogWorkerError(f"could not read catalog chunk {path}: {exc}") from exc
    if len(raw) > MAX_CHUNK_BYTES:
        raise CatalogWorkerError(
            f"catalog chunk exceeds the {MAX_CHUNK_BYTES // (1024 * 1024)} MiB limit"
        )
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CatalogWorkerError(f"catalog chunk is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CatalogWorkerError("catalog chunk must be a JSON object")
    if value.get("schema_version") != 1 or value.get("profile") != TMOS_PROFILE:
        raise CatalogWorkerError("catalog chunk must use schema 1 and profile tmos-17.5")
    if value.get("tmos_version") != "17.5":
        raise CatalogWorkerError("catalog chunk tmos_version must be 17.5")
    chunk = value.get("chunk")
    commands = value.get("commands")
    if not isinstance(chunk, dict) or not isinstance(commands, list):
        raise CatalogWorkerError("catalog chunk must contain chunk and commands")
    if len(commands) > MAX_COMMANDS:
        raise CatalogWorkerError(f"catalog worker accepts at most {MAX_COMMANDS} commands")
    if chunk.get("count") != len(commands):
        raise CatalogWorkerError("catalog chunk count does not match commands")
    for field in ("offset", "limit", "count", "total"):
        field_value = chunk.get(field)
        if isinstance(field_value, bool) or not isinstance(field_value, int) or field_value < 0:
            raise CatalogWorkerError(f"catalog chunk field {field!r} must be a non-negative integer")
    if chunk["limit"] == 0 or chunk["count"] > chunk["limit"]:
        raise CatalogWorkerError("catalog chunk has an invalid limit/count relationship")
    if not isinstance(chunk.get("has_more"), bool):
        raise CatalogWorkerError("catalog chunk has_more must be a boolean")
    if chunk["count"] == 0 and chunk["has_more"]:
        raise CatalogWorkerError("catalog chunk pagination made no progress")
    if chunk["offset"] + chunk["count"] > chunk["total"]:
        raise CatalogWorkerError("catalog chunk exceeds its declared total")
    if chunk["has_more"] != (chunk["offset"] + chunk["count"] < chunk["total"]):
        raise CatalogWorkerError("catalog chunk has inconsistent pagination metadata")
    names: set[str] = set()
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            raise CatalogWorkerError(f"catalog command {index} must be an object")
        name = command.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise CatalogWorkerError(f"catalog command {index} has a missing or duplicate name")
        names.add(name)
        catalog_kind = command.get("catalog_kind")
        if not isinstance(catalog_kind, str) or not catalog_kind or "\x00" in catalog_kind:
            raise CatalogWorkerError(f"catalog command {name!r} has an invalid catalog kind")
    return value


def _copy_state(state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(state, dict) or any(not isinstance(values, dict) for values in state.values()):
        raise CatalogWorkerError("catalog fixture state must be a JSON object of object layers")
    return {layer: dict(values) for layer, values in state.items()}


def _build_inputs(
    root: Path,
    command: dict[str, Any],
    event_inventory: list[tuple[str, Any]],
    registry: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    name = command["name"]
    template = EMULATOR._command_probe_template(root, name, event_inventory)
    spec = EMULATOR._f5_catalog_spec(registry, name)
    if spec is None:
        raise EMULATOR.EmulatorInputError(f"catalog command has no specification: {name}")
    argument_candidates = EMULATOR._command_argument_candidates(name, spec)
    base_input: dict[str, Any] = {
        "command": name,
        "args": list(argument_candidates[0]["args"]),
        "event": template["event"],
        "profiles": list(template["profiles"]),
    }
    state_hint = EMULATOR._CANDIDATE_STATE_HINTS.get(name)
    if state_hint is not None:
        if name.startswith("HTTP2::") and template["event"] in {"HTTP_REQUEST", "HTTP_RESPONSE"}:
            base_input["request"] = EMULATOR._http2_candidate_request()
        else:
            base_input["state"] = _copy_state(state_hint)
    else:
        request = EMULATOR._protocol_request_template(template["event"])
        if request is not None:
            base_input["request"] = request
    scenario = EMULATOR._candidate_fixture_scenario(name)
    if scenario is not None:
        base_input["scenario"] = scenario
    # Validate the generated local input before any execution. This keeps a
    # bad registry entry isolated to one row and prevents malformed plans.
    EMULATOR._normalise_command_probe_request(
        root, base_input, allow_external_protocol_request=True
    )
    return base_input, argument_candidates, template


def _plan_input(root: Path, probe_input: dict[str, Any], event: str, profiles: list[str]) -> dict[str, Any]:
    capture_input = EMULATOR._capture_plan_probe_input(probe_input)
    if "request" not in capture_input:
        request = EMULATOR._capture_plan_request_template(event, profiles)
        if request is not None:
            capture_input["request"] = request
    # This is an additional boundary check: local-only state/scenario must not
    # leak into the external collector input.
    if set(capture_input) - {"command", "args", "event", "profiles", "request"}:
        raise CatalogWorkerError("external capture input contains local-only fields")
    return capture_input


def _build_report(
    chunk: dict[str, Any],
    *,
    tcl_lsp_root: str | None,
    variants: int,
    mode: str,
    exclude_commands: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if mode not in {"local", "plan", "both"}:
        raise CatalogWorkerError("mode must be local, plan, or both")
    if isinstance(variants, bool) or not isinstance(variants, int) or not 1 <= variants <= MAX_VARIANTS:
        raise CatalogWorkerError(f"variants must be between 1 and {MAX_VARIANTS}")
    commands = chunk["commands"]
    target_commands = [
        item for item in commands
        if item.get("catalog_kind") == "f5-irule"
        if item.get("target_status") == "available-in-tmos-17.5"
    ]
    candidate_commands = [
        item for item in target_commands if item.get("name") not in exclude_commands
    ]
    if len(candidate_commands) * variants > MAX_PLAN_OBSERVATIONS:
        raise CatalogWorkerError(
            f"chunk would create more than {MAX_PLAN_OBSERVATIONS} capture observations; "
            "use a smaller exported chunk or fewer variants"
        )
    root = EMULATOR._find_tcl_lsp_root(tcl_lsp_root)
    event_inventory = EMULATOR._probe_event_inventory(root)
    registry, _ = EMULATOR._runtime_status_map(root)
    rows: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    local_status_counts: dict[str, int] = {}
    generation_status_counts: dict[str, int] = {}

    for catalog in commands:
        name = catalog["name"]
        row: dict[str, Any] = {
            # IDs are command-stable so changing export chunk size does not
            # invalidate resumable capture state or previously imported vectors.
            "id": f"catalog:{name}",
            "command": name,
            "namespace": catalog.get("namespace"),
            "runtime_status": catalog.get("runtime_status"),
            "target_status": catalog.get("target_status"),
            "catalog_kind": catalog.get("catalog_kind"),
            "pure": catalog.get("pure"),
            "unsafe": catalog.get("unsafe"),
            "generation_status": "skipped-not-available-in-tmos-17.5",
            "variants": [],
        }
        if catalog.get("catalog_kind") != "f5-irule":
            row["generation_status"] = "skipped-non-f5-catalog"
            generation_status_counts[row["generation_status"]] = generation_status_counts.get(row["generation_status"], 0) + 1
            rows.append(row)
            continue
        if catalog.get("target_status") != "available-in-tmos-17.5":
            row["generation_status"] = "skipped-not-available-in-tmos-17.5"
            generation_status_counts[row["generation_status"]] = generation_status_counts.get(row["generation_status"], 0) + 1
            rows.append(row)
            continue
        if name in exclude_commands:
            row["generation_status"] = "skipped-collector-safety"
            generation_status_counts[row["generation_status"]] = generation_status_counts.get(row["generation_status"], 0) + 1
            rows.append(row)
            continue
        try:
            base_input, argument_candidates, template = _build_inputs(
                root, catalog, event_inventory, registry
            )
            row.update(
                {
                    "generation_status": "ready",
                    "event": template["event"],
                    "profiles": list(template["profiles"]),
                    "argument_candidates": argument_candidates[:variants],
                }
            )
            for variant_index, candidate in enumerate(argument_candidates[:variants]):
                variant_input = dict(base_input)
                variant_input["args"] = list(candidate["args"])
                observation_id = f"{row['id']}:variant:{variant_index + 1}"
                variant_row: dict[str, Any] = {
                    "id": observation_id,
                    "args": list(candidate["args"]),
                    "argument_source": candidate.get("source"),
                    "capture_input": _plan_input(
                        root, variant_input, template["event"], list(template["profiles"])
                    ),
                }
                if mode in {"local", "both"}:
                    try:
                        local_result = EMULATOR.run_command_probe(
                            variant_input,
                            tcl_lsp_root=str(root),
                            allow_external_protocol_request=True,
                        )
                        variant_row["local_status"] = "ok"
                        variant_row["local_execution"] = local_result["execution"]
                    except EMULATOR.EmulatorInputError as exc:
                        variant_row["local_status"] = "error"
                        variant_row["local_error"] = str(exc)
                    status = variant_row["local_status"]
                    local_status_counts[status] = local_status_counts.get(status, 0) + 1
                row["variants"].append(variant_row)
                if mode in {"plan", "both"}:
                    observations.append(
                        {
                            "id": observation_id,
                            "operation": "command_probe",
                            "input": variant_row["capture_input"],
                            "comparisons": EMULATOR._capture_plan_command_comparisons(),
                        }
                    )
            row["capture_observation_count"] = len(row["variants"])
        except EMULATOR.EmulatorInputError as exc:
            row["generation_status"] = "error"
            row["generation_error"] = str(exc)
        generation_status_counts[row["generation_status"]] = generation_status_counts.get(row["generation_status"], 0) + 1
        rows.append(row)

    plan = None
    if observations:
        plan = EMULATOR._normalise_capture_plan(
            root,
            {
                "schema_version": 1,
                "profile": TMOS_PROFILE,
                "name": f"tmos-17.5-catalog-chunk-{chunk['chunk']['offset']:06d}",
                "source": "external-bigip-or-vlab",
                "provenance": {
                    "collector": "catalog-worker",
                    "tmos_build": "17.5",
                    "capture_id": f"catalog-chunk-{chunk['chunk']['offset']:06d}",
                    "generator": "tmos-17.5-catalog-worker-v1",
                    "variants": variants,
                },
                "observations": observations,
            },
        )
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": TMOS_PROFILE,
        "tmos_version": "17.5",
        "source": "catalog-worker",
        "chunk": chunk["chunk"],
        "summary": {
            "input_command_count": len(commands),
            "target_command_count": len(target_commands),
            "non_f5_command_count": sum(
                1 for item in commands if item.get("catalog_kind") != "f5-irule"
            ),
            "generated_command_count": sum(1 for row in rows if row["generation_status"] == "ready"),
            "capture_observation_count": len(observations),
            "generation_status_counts": dict(sorted(generation_status_counts.items())),
            "local_status_counts": dict(sorted(local_status_counts.items())),
        },
        "interpretation": (
            "Local results show current emulator behavior only. The capture_plan is "
            "a reference-free hypothesis set; it becomes TMOS 17.5 evidence only "
            "after an authorized BIG-IP or vLab collector returns observations."
        ),
        "commands": rows,
        "capture_plan": plan,
    }


def _write_output(path: Path, report: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise CatalogWorkerError(f"output already exists: {path}; choose a new file")
    try:
        encoded = json.dumps(
            report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CatalogWorkerError(f"could not serialize report: {exc}") from exc
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise CatalogWorkerError(f"worker report exceeds {MAX_OUTPUT_BYTES // (1024 * 1024)} MiB")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() or path.is_symlink():
            raise CatalogWorkerError(f"output appeared during report write: {path}")
        temporary.rename(path)
    except OSError as exc:
        raise CatalogWorkerError(f"could not write report {path}: {exc}") from exc
    finally:
        if temporary is not None and temporary.exists():
            try:
                temporary.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chunk", required=True, help="exported chunk JSON, or - for stdin")
    parser.add_argument("--tcl-lsp-root")
    parser.add_argument("--variants", type=int, default=1)
    parser.add_argument("--mode", choices=("local", "plan", "both"), default="both")
    parser.add_argument(
        "--exclude-command",
        action="append",
        default=[],
        help="skip a command from external plan generation (repeatable)",
    )
    parser.add_argument("--output", help="new report path; stdout is used when omitted")
    args = parser.parse_args(argv)
    try:
        chunk = _read_chunk(Path(args.chunk))
        report = _build_report(
            chunk,
            tcl_lsp_root=args.tcl_lsp_root,
            variants=args.variants,
            mode=args.mode,
            exclude_commands=frozenset(args.exclude_command),
        )
        encoded = json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2).encode("utf-8") + b"\n"
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise CatalogWorkerError(f"worker report exceeds {MAX_OUTPUT_BYTES // (1024 * 1024)} MiB")
        if args.output:
            _write_output(Path(args.output).expanduser(), report)
            print(json.dumps({"status": "ok", "output": str(Path(args.output).expanduser()), "summary": report["summary"]}, allow_nan=False))
        else:
            sys.stdout.buffer.write(encoded)
    except (CatalogWorkerError, EMULATOR.EmulatorInputError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
