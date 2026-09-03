#!/usr/bin/env python3
"""Promote a completed TMOS 17.5 capture batch into golden-vector packs.

The capture runner deliberately stores raw collector records as NDJSON so a
batch can be resumed.  This tool is the next boundary: it validates the batch
and record set, assembles one immutable golden-vector pack per plan, and can
optionally replay every pack through the local emulator for a differential
report.  It never contacts a BIG-IP and refuses to overwrite an output
directory.
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
RUNNER_PATH = ROOT / "tools" / "tmos17-capture-runner.py"
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"
MAX_RECORDS_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 32 * 1024 * 1024


class AssembleError(RuntimeError):
    """Raised when a capture batch cannot be promoted safely."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssembleError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = _load_module(RUNNER_PATH, "testcl_tmos17_capture_runner_for_assemble")
EMULATOR = _load_module(EMULATOR_PATH, "testcl_irule_emulator_for_assemble")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_records(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AssembleError(f"could not read records file {path}: {exc}") from exc
    if len(raw) > MAX_RECORDS_BYTES:
        raise AssembleError(
            f"records file exceeds the {MAX_RECORDS_BYTES} byte limit"
        )
    if not raw:
        raise AssembleError("records file is empty")

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            raise AssembleError(f"records file contains a blank line at {line_number}")
        try:
            record = json.loads(
                line.decode("utf-8"), parse_constant=_reject_constant
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise AssembleError(
                f"records line {line_number} is not valid JSON: {exc}"
            ) from exc
        if (
            not isinstance(record, dict)
            or set(record) != {"id", "output"}
            or not isinstance(record["id"], str)
            or not record["id"]
            or not isinstance(record["output"], dict)
        ):
            raise AssembleError(
                f"records line {line_number} must contain only string id and object output"
            )
        record_id = record["id"]
        if record_id in seen:
            raise AssembleError(f"records file contains duplicate id {record_id!r}")
        seen.add(record_id)
        records.append(record)
    return records, raw


def _write_json(path: Path, payload: Any, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AssembleError(f"could not serialize {path.name}: {exc}") from exc
    if len(encoded) > max_bytes:
        raise AssembleError(f"{path.name} exceeds the {max_bytes} byte limit")
    try:
        with path.open("wb") as stream:
            stream.write(encoded)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise AssembleError(f"could not write {path}: {exc}") from exc
    return encoded + b"\n"


def _new_output_dir(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise AssembleError(f"output directory must not be a symlink: {path}")
    path = path.resolve()
    if path.name in {"", ".", ".."}:
        raise AssembleError("output directory must have a concrete name")
    if path.exists() or path.is_symlink():
        raise AssembleError(f"output directory already exists: {path}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{path.name}.", dir=path.parent)
        )
    except OSError as exc:
        raise AssembleError(f"could not create output staging directory: {exc}") from exc
    return staging


def _record_map(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["id"]: record for record in records}


def assemble_batch(
    manifest_path: Path,
    records_path: Path,
    output_dir: Path,
    *,
    tcl_lsp_root: str | None = None,
    verify: bool = False,
) -> dict[str, Any]:
    """Assemble and optionally verify every completed plan in a batch."""
    manifest_path = manifest_path.expanduser().resolve()
    records_path = records_path.expanduser().resolve()
    if manifest_path == records_path:
        raise AssembleError("manifest and records paths must be different")
    if not manifest_path.is_file():
        raise AssembleError(f"manifest does not exist: {manifest_path}")
    if not records_path.is_file():
        raise AssembleError(f"records file does not exist: {records_path}")

    try:
        manifest, entries, manifest_sha256 = RUNNER._load_batch(manifest_path)
    except (RUNNER.RunnerError, OSError) as exc:
        raise AssembleError(f"invalid capture batch: {exc}") from exc
    records, records_raw = _read_records(records_path)
    by_id = _record_map(records)
    expected_ids = set().union(*(set(entry.record_ids) for entry in entries))
    record_ids = set(by_id)
    missing = sorted(expected_ids - record_ids)
    unexpected = sorted(record_ids - expected_ids)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append("missing records: " + ", ".join(missing[:8]))
        if unexpected:
            details.append("unexpected records: " + ", ".join(unexpected[:8]))
        raise AssembleError("record set does not match batch (" + "; ".join(details) + ")")

    staging = _new_output_dir(output_dir)
    packs: list[dict[str, Any]] = []
    verification_failures = 0
    try:
        reports_dir = staging / "reports"
        if verify:
            reports_dir.mkdir()

        for index, entry in enumerate(entries):
            try:
                plan, _ = RUNNER._read_json(entry.path, RUNNER.MAX_PLAN_BYTES)
                plan_records = [by_id[record_id] for record_id in entry.record_ids]
                assembled = EMULATOR.run_capture_assemble(
                    plan, plan_records, tcl_lsp_root=tcl_lsp_root
                )
            except (
                RUNNER.RunnerError,
                EMULATOR.EmulatorInputError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
                KeyError,
            ) as exc:
                raise AssembleError(
                    f"could not assemble plan {entry.filename!r}: {exc}"
                ) from exc

            pack = assembled["pack"]
            pack_filename = f"pack-{index:04d}.json"
            pack_bytes = _write_json(
                staging / pack_filename,
                pack,
                EMULATOR.GOLDEN_VECTOR_MAX_BYTES,
            )
            pack_info: dict[str, Any] = {
                "file": pack_filename,
                "plan": entry.filename,
                "vector_count": assembled["summary"]["observation_count"],
                "record_count": assembled["summary"]["record_count"],
                "pack_sha256": hashlib.sha256(pack_bytes).hexdigest(),
                "records_sha256": assembled["summary"]["records_sha256"],
            }
            if verify:
                try:
                    verification = EMULATOR.run_golden_vectors(
                        pack, tcl_lsp_root=tcl_lsp_root
                    )
                except (
                    EMULATOR.EmulatorInputError,
                    OSError,
                    RuntimeError,
                    TypeError,
                    ValueError,
                    KeyError,
                ) as exc:
                    raise AssembleError(
                        f"could not verify pack {pack_filename!r}: {exc}"
                    ) from exc
                report_filename = f"{pack_filename[:-5]}-verification.json"
                _write_json(
                    reports_dir / report_filename,
                    verification,
                    MAX_REPORT_BYTES,
                )
                pack_info["verification"] = {
                    "status": verification.get("status"),
                    "summary": verification.get("summary"),
                    "analysis": verification.get("analysis"),
                    "report": f"reports/{report_filename}",
                }
                if verification.get("status") != "passed":
                    verification_failures += 1
            packs.append(pack_info)

        output_manifest: dict[str, Any] = {
            "schema_version": 1,
            "profile": "tmos-17.5",
            "status": (
                "assembled-with-verification-failures"
                if verification_failures
                else "assembled"
            ),
            "source": {
                "manifest": manifest_path.name,
                "records": records_path.name,
                "manifest_sha256": manifest_sha256,
                "records_file_sha256": hashlib.sha256(records_raw).hexdigest(),
                "batch_status": manifest.get("status"),
            },
            "assembly": "tmos17-batch-assemble-v1",
            "packs": packs,
            "summary": {
                "plan_count": len(packs),
                "vector_count": sum(pack["vector_count"] for pack in packs),
                "record_count": len(records),
                "verification_requested": verify,
                "verification_passed": (
                    len(packs) - verification_failures if verify else None
                ),
                "verification_failed": verification_failures if verify else None,
            },
        }
        _write_json(
            staging / "manifest.json", output_manifest, EMULATOR.GOLDEN_VECTOR_MAX_BYTES
        )

        final_dir = output_dir.expanduser().resolve()
        if final_dir.exists() or final_dir.is_symlink():
            raise AssembleError(f"output directory appeared during assembly: {final_dir}")
        try:
            staging.rename(final_dir)
        except OSError as exc:
            raise AssembleError(f"could not publish assembled batch: {exc}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {
        "status": output_manifest["status"],
        "profile": "tmos-17.5",
        "output_dir": str(final_dir),
        "plan_count": output_manifest["summary"]["plan_count"],
        "vector_count": output_manifest["summary"]["vector_count"],
        "record_count": output_manifest["summary"]["record_count"],
        "verification_requested": verify,
        "verification_failed": verification_failures if verify else None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Promote a completed TMOS 17.5 capture batch into golden-vector packs"
    )
    parser.add_argument("--manifest", required=True, help="capture-runner batch manifest")
    parser.add_argument("--records", required=True, help="capture-runner NDJSON records")
    parser.add_argument("--output-dir", required=True, help="new output directory")
    parser.add_argument("--tcl-lsp-root", default=None)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="replay every assembled pack and write differential reports",
    )
    args = parser.parse_args(argv)
    try:
        result = assemble_batch(
            Path(args.manifest),
            Path(args.records),
            Path(args.output_dir),
            tcl_lsp_root=args.tcl_lsp_root,
            verify=args.verify,
        )
    except (AssembleError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 1 if result["status"] == "assembled-with-verification-failures" else 0


if __name__ == "__main__":
    raise SystemExit(main())
