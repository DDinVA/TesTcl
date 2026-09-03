#!/usr/bin/env python3
"""Re-verify an assembled TMOS 17.5 campaign without contacting a device.

The campaign assembler writes an indexed directory containing one bounded
golden-vector pack per capture group.  This tool validates the index and pack
hashes, then replays every pack through the local emulator.  It is intended
for a later audit or artifact-transfer check; it does not reassemble records
and it never performs BIG-IP I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"
TMOS_PROFILE = "tmos-17.5"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_PACK_BYTES = 32 * 1024 * 1024


class CampaignVerifyError(RuntimeError):
    """Raised when an assembled campaign is not safe to replay."""


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CampaignVerifyError(f"could not load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EMULATOR = _load_module(EMULATOR_PATH, "testcl_irule_emulator_for_campaign_verify")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _read_json(path: Path, max_bytes: int) -> Any:
    if path.is_symlink() or not path.is_file():
        raise CampaignVerifyError(f"campaign file is not a regular file: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CampaignVerifyError(f"could not read campaign file {path}: {exc}") from exc
    if len(raw) > max_bytes:
        raise CampaignVerifyError(f"campaign file exceeds the {max_bytes} byte limit: {path}")
    try:
        return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CampaignVerifyError(f"invalid JSON in {path}: {exc}") from exc


def _relative_file(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CampaignVerifyError(f"{label} must be a non-empty relative path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CampaignVerifyError(f"{label} must stay within the campaign directory")
    current = root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise CampaignVerifyError(f"{label} must not traverse a symlink")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise CampaignVerifyError(f"{label} escapes the campaign directory") from exc
    return resolved


def _validate_manifest(manifest: Any, campaign_dir: Path) -> list[tuple[str, Path]]:
    if not isinstance(manifest, dict):
        raise CampaignVerifyError("campaign manifest must be a JSON object")
    if manifest.get("schema_version") != 1:
        raise CampaignVerifyError("unsupported campaign manifest schema")
    if manifest.get("profile") != TMOS_PROFILE:
        raise CampaignVerifyError("campaign manifest is not for TMOS 17.5")
    if manifest.get("assembly") != "tmos17-campaign-assemble-v1":
        raise CampaignVerifyError("input is not an assembled TMOS 17.5 campaign")
    groups = manifest.get("groups")
    if not isinstance(groups, list) or not groups:
        raise CampaignVerifyError("campaign manifest must contain at least one group")
    seen: set[str] = set()
    seen_pack_paths: set[Path] = set()
    pack_files: list[tuple[str, Path]] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("id"), str):
            raise CampaignVerifyError("campaign group must contain a string id")
        group_id = group["id"]
        if group_id in seen:
            raise CampaignVerifyError(f"duplicate campaign group {group_id!r}")
        seen.add(group_id)
        group_manifest_path = _relative_file(
            campaign_dir, group.get("manifest"), f"group {group_id!r} manifest"
        )
        group_manifest = _read_json(group_manifest_path, MAX_MANIFEST_BYTES)
        if not isinstance(group_manifest, dict):
            raise CampaignVerifyError(f"group {group_id!r} manifest must be an object")
        if group_manifest.get("profile") != TMOS_PROFILE:
            raise CampaignVerifyError(f"group {group_id!r} is not for TMOS 17.5")
        packs = group_manifest.get("packs")
        if not isinstance(packs, list) or not packs:
            raise CampaignVerifyError(f"group {group_id!r} has no packs")
        group_root = group_manifest_path.parent
        for pack in packs:
            if not isinstance(pack, dict):
                raise CampaignVerifyError(f"group {group_id!r} contains an invalid pack entry")
            pack_path = _relative_file(group_root, pack.get("file"), f"group {group_id!r} pack")
            if pack_path in seen_pack_paths:
                raise CampaignVerifyError(f"pack is referenced more than once: {pack_path}")
            if pack_path.is_symlink() or not pack_path.is_file():
                raise CampaignVerifyError(f"campaign pack is not a regular file: {pack_path}")
            seen_pack_paths.add(pack_path)
            expected_hash = pack.get("pack_sha256")
            if not isinstance(expected_hash, str) or len(expected_hash) != 64:
                raise CampaignVerifyError(f"group {group_id!r} pack has an invalid SHA-256")
            actual_hash = hashlib.sha256(pack_path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise CampaignVerifyError(
                    f"group {group_id!r} pack hash mismatch for {pack_path.name}"
                )
            pack_files.append((group_id, pack_path))
    return pack_files


def _counter(report: dict[str, Any], container: str, field: str) -> int:
    value = report.get(container)
    if not isinstance(value, dict):
        return 0
    count = value.get(field, 0) or 0
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise CampaignVerifyError(f"replay report has an invalid {container}.{field}")
    return count


def verify_campaign(
    campaign_dir: Path, *, tcl_lsp_root: str | None = None
) -> dict[str, Any]:
    """Validate and replay every pack in an assembled campaign."""
    campaign_dir = campaign_dir.expanduser()
    if campaign_dir.is_symlink() or not campaign_dir.is_dir():
        raise CampaignVerifyError(f"campaign directory is not a regular directory: {campaign_dir}")
    campaign_dir = campaign_dir.resolve()
    manifest = _read_json(campaign_dir / "manifest.json", MAX_MANIFEST_BYTES)
    packs = _validate_manifest(manifest, campaign_dir)
    manifest_summary = manifest.get("summary")
    if isinstance(manifest_summary, dict):
        declared_groups = manifest_summary.get("group_count")
        if declared_groups is not None and declared_groups != len(manifest["groups"]):
            raise CampaignVerifyError("campaign summary group_count does not match the index")
    reports: list[dict[str, Any]] = []
    failed = 0
    vector_count = 0
    comparison_count = 0
    for group_id, pack_path in packs:
        pack = _read_json(pack_path, MAX_PACK_BYTES)
        if not isinstance(pack, dict):
            raise CampaignVerifyError(f"pack must be a JSON object: {pack_path}")
        try:
            report = EMULATOR.run_golden_vectors(pack, tcl_lsp_root=tcl_lsp_root)
        except (EMULATOR.EmulatorInputError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
            raise CampaignVerifyError(f"could not replay {pack_path}: {exc}") from exc
        status = report.get("status")
        if status != "passed":
            failed += 1
        summary = report.get("summary")
        analysis = report.get("analysis")
        vector_count += _counter(report, "summary", "vector_count")
        comparison_count += _counter(report, "analysis", "comparison_count")
        reports.append(
            {
                "group": group_id,
                "pack": str(pack_path.relative_to(campaign_dir)),
                "status": status,
                "summary": summary,
                "analysis": analysis,
            }
        )
    return {
        "status": "passed" if failed == 0 else "failed",
        "profile": TMOS_PROFILE,
        "campaign_dir": str(campaign_dir),
        "summary": {
            "group_count": len(manifest["groups"]),
            "pack_count": len(packs),
            "vector_count": vector_count,
            "comparison_count": comparison_count,
            "passed": len(packs) - failed,
            "failed": failed,
        },
        "packs": reports,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Re-verify an assembled TMOS 17.5 campaign locally"
    )
    parser.add_argument("--campaign-dir", required=True, help="assembled campaign directory")
    parser.add_argument("--tcl-lsp-root", default=None)
    args = parser.parse_args(argv)
    try:
        result = verify_campaign(Path(args.campaign_dir), tcl_lsp_root=args.tcl_lsp_root)
    except (CampaignVerifyError, OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
