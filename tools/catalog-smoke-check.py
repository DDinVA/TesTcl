#!/usr/bin/env python3
"""Validate the small exported-catalog smoke fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"JSON document is not an object: {path}")
    return value


def _integer(summary: dict[str, Any], field: str, source: str) -> int:
    value = summary.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"{source}.summary.{field} must be a non-negative integer")
    return value


def validate(
    catalog: dict[str, Any], worker: dict[str, Any], batch: dict[str, Any]
) -> dict[str, int]:
    if worker.get("status") != "ok":
        raise SystemExit("catalog worker report did not complete successfully")
    if batch.get("status") != "ok":
        raise SystemExit("catalog capture-batch report did not complete successfully")
    catalog_summary = catalog.get("summary")
    worker_summary = worker.get("summary")
    batch_summary = batch.get("summary")
    if not isinstance(catalog_summary, dict):
        raise SystemExit("catalog, worker, and batch documents must contain summary objects")
    if not isinstance(worker_summary, dict):
        raise SystemExit("catalog, worker, and batch documents must contain summary objects")
    if not isinstance(batch_summary, dict):
        raise SystemExit("catalog, worker, and batch documents must contain summary objects")

    expected = _integer(catalog_summary, "filtered_command_count", "catalog")
    generated = _integer(worker_summary, "generated_command_count", "worker")
    worker_observations = _integer(worker_summary, "capture_observation_count", "worker")
    observations = _integer(batch_summary, "observation_count", "batch")
    target = _integer(batch_summary, "target_command_count", "batch")

    if generated != 3:
        raise SystemExit(f"catalog worker did not evaluate all three commands: {generated}")
    if worker_observations != 3:
        raise SystemExit(
            "catalog worker did not emit all three observations: "
            f"{worker_observations}"
        )
    if observations != expected:
        raise SystemExit(
            "capture batch observation count does not match the exported catalog: "
            f"{observations} != {expected}"
        )
    if target != expected:
        raise SystemExit(
            "capture batch target count does not match the exported catalog: "
            f"{target} != {expected}"
        )
    return {
        "catalog_command_count": expected,
        "capture_observation_count": observations,
        "target_command_count": target,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-manifest", type=Path, required=True)
    parser.add_argument("--worker-report", type=Path, required=True)
    parser.add_argument("--batch-report", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            validate(
                _load_object(args.catalog_manifest),
                _load_object(args.worker_report),
                _load_object(args.batch_report),
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
