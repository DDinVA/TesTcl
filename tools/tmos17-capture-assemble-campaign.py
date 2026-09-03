#!/usr/bin/env python3
"""Assemble a completed TMOS 17.5 capture campaign into golden-vector packs.

Campaign groups are deliberately kept as bounded pack sets because the local
golden-vector contract caps each pack at 256 vectors.  This tool validates the
split schedule, consumes the per-group resumable ``records.ndjson`` files
produced by the campaign runner, and writes one indexed campaign directory.
It never contacts a BIG-IP and refuses to overwrite existing output.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLE_PATH = ROOT / "tools" / "tmos17-capture-assemble.py"
CAMPAIGN_PATH = ROOT / "tools" / "tmos17-capture-campaign.py"
TMOS_PROFILE = "tmos-17.5"


class CampaignAssembleError(RuntimeError):
    """Raised when a campaign cannot be promoted safely."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CampaignAssembleError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ASSEMBLE = _load_module(ASSEMBLE_PATH, "testcl_tmos17_capture_assemble_for_campaign")
CAMPAIGN = _load_module(CAMPAIGN_PATH, "testcl_tmos17_capture_campaign_for_assemble")


def _new_output_dir(path: Path) -> tuple[Path, Path]:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CampaignAssembleError(f"output directory must not be a symlink: {expanded}")
    resolved = expanded.resolve()
    if resolved.name in {"", ".", ".."}:
        raise CampaignAssembleError("output directory must have a concrete name")
    if resolved.exists() or resolved.is_symlink():
        raise CampaignAssembleError(f"output directory already exists: {resolved}")
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{resolved.name}.", dir=resolved.parent)
        )
    except OSError as exc:
        raise CampaignAssembleError(f"could not create output staging directory: {exc}") from exc
    return resolved, staging


def _records_root(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CampaignAssembleError(f"records root must not be a symlink: {expanded}")
    resolved = expanded.resolve()
    if not resolved.is_dir():
        raise CampaignAssembleError(f"records root does not exist as a directory: {resolved}")
    return resolved


def _records_path(records_root: Path, group_id: str) -> Path:
    group_dir = records_root / CAMPAIGN._group_output_name(group_id)
    if group_dir.is_symlink():
        raise CampaignAssembleError(f"records group directory must not be a symlink: {group_dir}")
    records = group_dir / "records.ndjson"
    if records.is_symlink() or not records.is_file():
        raise CampaignAssembleError(
            f"records are missing for campaign group {group_id!r}: {records}"
        )
    return records.resolve()


def assemble_campaign(
    schedule_path: Path,
    records_root: Path,
    output_dir: Path,
    *,
    tcl_lsp_root: str | None = None,
    verify: bool = False,
) -> dict[str, Any]:
    """Promote every completed schedule group into bounded golden-vector packs."""
    schedule_path = schedule_path.expanduser()
    if schedule_path.is_symlink():
        raise CampaignAssembleError(f"schedule must not be a symlink: {schedule_path}")
    schedule_path = schedule_path.resolve()
    if not schedule_path.is_file():
        raise CampaignAssembleError(f"schedule does not exist as a regular file: {schedule_path}")
    records_root = _records_root(records_root)
    try:
        schedule, groups, schedule_sha256 = CAMPAIGN.load_schedule(schedule_path)
    except (CAMPAIGN.CampaignError, OSError, TypeError, ValueError) as exc:
        raise CampaignAssembleError(f"invalid campaign schedule: {exc}") from exc

    final_dir, staging = _new_output_dir(output_dir)
    group_infos: list[dict[str, Any]] = []
    verification_failed = 0
    try:
        group_root = staging / "groups"
        group_root.mkdir()
        seen_output_names: set[str] = set()
        for group in groups:
            group_id = group["id"]
            output_name = CAMPAIGN._group_output_name(group_id)
            if output_name in seen_output_names:
                raise CampaignAssembleError(
                    f"campaign output name collision for group {group_id!r}"
                )
            seen_output_names.add(output_name)
            records_path = _records_path(records_root, group_id)
            group_output = group_root / output_name
            try:
                result = ASSEMBLE.assemble_batch(
                    Path(group["manifest_path"]),
                    records_path,
                    group_output,
                    tcl_lsp_root=tcl_lsp_root,
                    verify=verify,
                )
            except (ASSEMBLE.AssembleError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
                raise CampaignAssembleError(
                    f"could not assemble campaign group {group_id!r}: {exc}"
                ) from exc
            group_manifest_path = group_output / "manifest.json"
            try:
                group_manifest = json.loads(group_manifest_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CampaignAssembleError(
                    f"assembled group {group_id!r} has an invalid manifest: {exc}"
                ) from exc
            group_summary = group_manifest.get("summary")
            if not isinstance(group_summary, dict):
                raise CampaignAssembleError(
                    f"assembled group {group_id!r} has no summary"
                )
            failed = group_summary.get("verification_failed", 0) or 0
            verification_failed += failed
            group_infos.append(
                {
                    "id": group_id,
                    "mode": group["mode"],
                    "manifest": f"groups/{output_name}/manifest.json",
                    "records": str(records_path),
                    "plan_count": result["plan_count"],
                    "vector_count": result["vector_count"],
                    "record_count": result["record_count"],
                    "status": result["status"],
                }
            )

        total_plan_count = sum(item["plan_count"] for item in group_infos)
        total_vector_count = sum(item["vector_count"] for item in group_infos)
        total_record_count = sum(item["record_count"] for item in group_infos)
        output_manifest = {
            "schema_version": 1,
            "profile": TMOS_PROFILE,
            "status": (
                "assembled-with-verification-failures"
                if verification_failed
                else "assembled"
            ),
            "assembly": "tmos17-campaign-assemble-v1",
            "source": {
                "schedule": str(schedule_path),
                "schedule_sha256": schedule_sha256,
                "records_root": str(records_root),
                "group_count": len(groups),
                "schedule_status": schedule.get("status"),
            },
            "groups": group_infos,
            "summary": {
                "group_count": len(group_infos),
                "plan_count": total_plan_count,
                "vector_count": total_vector_count,
                "record_count": total_record_count,
                "verification_requested": verify,
                "verification_passed": (
                    total_plan_count - verification_failed if verify else None
                ),
                "verification_failed": verification_failed if verify else None,
            },
        }
        try:
            encoded = json.dumps(
                output_manifest,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise CampaignAssembleError(f"could not serialize campaign manifest: {exc}") from exc
        if len(encoded) > ASSEMBLE.EMULATOR.GOLDEN_VECTOR_MAX_BYTES:
            raise CampaignAssembleError("campaign manifest exceeds the golden-vector size limit")
        (staging / "manifest.json").write_bytes(encoded + b"\n")
        if final_dir.exists() or final_dir.is_symlink():
            raise CampaignAssembleError(f"output directory appeared during assembly: {final_dir}")
        try:
            staging.rename(final_dir)
        except OSError as exc:
            raise CampaignAssembleError(f"could not publish campaign assembly: {exc}") from exc
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return {
        "status": output_manifest["status"],
        "profile": TMOS_PROFILE,
        "output_dir": str(final_dir),
        **output_manifest["summary"],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Promote a complete TMOS 17.5 capture campaign into golden-vector packs"
    )
    parser.add_argument("--schedule", required=True, help="split campaign schedule.json")
    parser.add_argument(
        "--records-root",
        required=True,
        help="campaign records root used by tmos17-capture-campaign.py",
    )
    parser.add_argument("--output-dir", required=True, help="new campaign output directory")
    parser.add_argument("--tcl-lsp-root", default=None)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="replay every assembled pack through the local emulator",
    )
    args = parser.parse_args(argv)
    try:
        result = assemble_campaign(
            Path(args.schedule),
            Path(args.records_root),
            Path(args.output_dir),
            tcl_lsp_root=args.tcl_lsp_root,
            verify=args.verify,
        )
    except (CampaignAssembleError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 1 if result["status"] == "assembled-with-verification-failures" else 0


if __name__ == "__main__":
    raise SystemExit(main())
