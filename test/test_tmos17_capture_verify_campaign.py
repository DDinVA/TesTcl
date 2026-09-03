from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
VERIFY_PATH = ROOT / "tools" / "tmos17-capture-verify-campaign.py"
SPEC = importlib.util.spec_from_file_location("tmos17_capture_verify_campaign", VERIFY_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_campaign = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_campaign
SPEC.loader.exec_module(verify_campaign)


def _make_campaign(tmp_path: Path) -> Path:
    campaign = tmp_path / "campaign"
    group = campaign / "groups" / "http1"
    group.mkdir(parents=True)
    pack = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "name": "test-pack",
        "source": "test",
        "vectors": [],
    }
    pack_path = group / "pack-0000.json"
    pack_bytes = (json.dumps(pack, sort_keys=True, indent=2) + "\n").encode()
    pack_path.write_bytes(pack_bytes)
    group_manifest = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "packs": [{"file": "pack-0000.json", "pack_sha256": hashlib.sha256(pack_bytes).hexdigest()}],
    }
    (group / "manifest.json").write_text(json.dumps(group_manifest), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "profile": "tmos-17.5",
        "assembly": "tmos17-campaign-assemble-v1",
        "groups": [{"id": "http1", "manifest": "groups/http1/manifest.json"}],
    }
    (campaign / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return campaign


def test_verify_campaign_replays_every_pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    campaign = _make_campaign(tmp_path)
    monkeypatch.setattr(
        verify_campaign.EMULATOR,
        "run_golden_vectors",
        lambda pack, tcl_lsp_root=None: {
            "status": "passed",
            "summary": {"vector_count": len(pack["vectors"])},
            "analysis": {"comparison_count": 0},
        },
    )
    result = verify_campaign.verify_campaign(campaign)
    assert result["status"] == "passed"
    assert result["summary"] == {
        "group_count": 1,
        "pack_count": 1,
        "vector_count": 0,
        "comparison_count": 0,
        "passed": 1,
        "failed": 0,
    }


def test_verify_campaign_rejects_tampered_pack(tmp_path: Path) -> None:
    campaign = _make_campaign(tmp_path)
    pack_path = campaign / "groups" / "http1" / "pack-0000.json"
    pack_path.write_text("{}", encoding="utf-8")
    with pytest.raises(verify_campaign.CampaignVerifyError, match="hash mismatch"):
        verify_campaign.verify_campaign(campaign)


def test_verify_campaign_rejects_pack_path_escape(tmp_path: Path) -> None:
    campaign = _make_campaign(tmp_path)
    group_manifest_path = campaign / "groups" / "http1" / "manifest.json"
    group_manifest = json.loads(group_manifest_path.read_text(encoding="utf-8"))
    group_manifest["packs"][0]["file"] = "../../manifest.json"
    group_manifest_path.write_text(json.dumps(group_manifest), encoding="utf-8")
    with pytest.raises(verify_campaign.CampaignVerifyError, match="stay within"):
        verify_campaign.verify_campaign(campaign)


def test_verify_campaign_rejects_duplicate_pack_reference(tmp_path: Path) -> None:
    campaign = _make_campaign(tmp_path)
    group = campaign / "groups" / "http1"
    group_manifest_path = group / "manifest.json"
    group_manifest = json.loads(group_manifest_path.read_text(encoding="utf-8"))
    group_manifest["packs"].append(dict(group_manifest["packs"][0]))
    group_manifest_path.write_text(json.dumps(group_manifest), encoding="utf-8")
    with pytest.raises(verify_campaign.CampaignVerifyError, match="more than once"):
        verify_campaign.verify_campaign(campaign)


def test_verify_campaign_rejects_malformed_replay_counter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    campaign = _make_campaign(tmp_path)
    monkeypatch.setattr(
        verify_campaign.EMULATOR,
        "run_golden_vectors",
        lambda pack, tcl_lsp_root=None: {
            "status": "passed",
            "summary": {"vector_count": "one"},
            "analysis": {"comparison_count": 0},
        },
    )
    with pytest.raises(verify_campaign.CampaignVerifyError, match="invalid summary.vector_count"):
        verify_campaign.verify_campaign(campaign)
