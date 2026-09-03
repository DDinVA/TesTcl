from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BATCH_PATH = ROOT / "tools" / "tmos17-capture-batch.py"
SPLIT_PATH = ROOT / "tools" / "tmos17-capture-split.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


batch = _load(BATCH_PATH, "tmos17_capture_batch_for_split_test")
split = _load(SPLIT_PATH, "tmos17_capture_split")


TCL_LSP_ROOT = "/tmp/tcl-lsp"


def test_split_materializes_all_schedule_groups_without_losing_observations(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "capture-batch"
    source = batch.build_batch(
        tcl_lsp_root=TCL_LSP_ROOT,
        output_dir=source_dir,
        variants=1,
    )
    output_dir = tmp_path / "scheduled-batches"
    result = split.split_batch(source_dir / "manifest.json", output_dir)

    assert result["status"] == "ready"
    assert result["group_count"] == len(source["stimulus_schedule"]["groups"])
    assert result["observation_count"] == source["summary"]["observation_count"] == 986
    schedule = json.loads((output_dir / "schedule.json").read_text(encoding="utf-8"))
    assert schedule["summary"] == {"group_count": 35, "observation_count": 986}

    split_ids: list[str] = []
    for group in schedule["groups"]:
        group_manifest_path = output_dir / group["manifest"]
        group_manifest, entries, _ = split.RUNNER._load_batch(group_manifest_path)
        assert group_manifest["selection"]["group_id"] == group["id"]
        assert group_manifest["summary"]["observation_count"] == group["observation_count"]
        for entry in entries:
            plan, _ = split.RUNNER._read_json(entry.path, split.RUNNER.MAX_PLAN_BYTES)
            split_ids.extend(item["id"] for item in plan["observations"])
    expected_ids = [
        observation_id
        for group in source["stimulus_schedule"]["groups"]
        for observation_id in group["observation_ids"]
    ]
    assert sorted(split_ids) == sorted(expected_ids)
    assert len(split_ids) == len(set(split_ids)) == 986


def test_split_can_materialize_one_group_and_refuses_existing_output(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "capture-batch"
    batch.build_batch(
        tcl_lsp_root=TCL_LSP_ROOT,
        output_dir=source_dir,
        namespace="HTTP",
        variants=1,
    )
    output_dir = tmp_path / "one-group"
    result = split.split_batch(
        source_dir / "manifest.json",
        output_dir,
        group="http1",
    )
    assert result["group_count"] == 1
    schedule = json.loads((output_dir / "schedule.json").read_text(encoding="utf-8"))
    assert [group["id"] for group in schedule["groups"]] == ["http1"]
    with pytest.raises(split.SplitError, match="already exists"):
        split.split_batch(source_dir / "manifest.json", output_dir, group="http1")


def test_split_rejects_unknown_group(tmp_path: Path) -> None:
    source_dir = tmp_path / "capture-batch"
    batch.build_batch(
        tcl_lsp_root=TCL_LSP_ROOT,
        output_dir=source_dir,
        namespace="HTTP",
        variants=1,
    )
    with pytest.raises(split.SplitError, match="unknown stimulus schedule group"):
        split.split_batch(
            source_dir / "manifest.json",
            tmp_path / "unknown-group",
            group="does-not-exist",
        )


def test_split_rejects_dangling_symlink_output(tmp_path: Path) -> None:
    dangling = tmp_path / "dangling-output"
    dangling.symlink_to(tmp_path / "missing-target", target_is_directory=True)
    with pytest.raises(split.SplitError, match="must not be a symlink"):
        split._new_staging(dangling)
