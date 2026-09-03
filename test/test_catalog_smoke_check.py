from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "tools" / "catalog-smoke-check.py"
SPEC = importlib.util.spec_from_file_location("catalog_smoke_check", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
catalog_smoke_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog_smoke_check)


def test_validate_uses_exported_catalog_count() -> None:
    catalog = {"summary": {"filtered_command_count": 4}}
    worker = {
        "status": "ok",
        "summary": {"generated_command_count": 3, "capture_observation_count": 3},
    }
    batch = {
        "status": "ok",
        "summary": {"observation_count": 4, "target_command_count": 4},
    }

    assert catalog_smoke_check.validate(catalog, worker, batch) == {
        "catalog_command_count": 4,
        "capture_observation_count": 4,
        "target_command_count": 4,
    }


def test_validate_rejects_mismatched_batch() -> None:
    with pytest.raises(SystemExit, match="observation count"):
        catalog_smoke_check.validate(
            {"summary": {"filtered_command_count": 4}},
            {
                "status": "ok",
                "summary": {"generated_command_count": 3, "capture_observation_count": 3},
            },
            {
                "status": "ok",
                "summary": {"observation_count": 3, "target_command_count": 4},
            },
        )


def test_validate_rejects_unsuccessful_report() -> None:
    with pytest.raises(SystemExit, match="did not complete successfully"):
        catalog_smoke_check.validate(
            {"summary": {"filtered_command_count": 4}},
            {"status": "error", "summary": {}},
            {"status": "ok", "summary": {}},
        )
