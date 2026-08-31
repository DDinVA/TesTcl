#!/usr/bin/env python3
"""Run the checked-in TMOS 17.5 emulator contracts as a local smoke report."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"


def _load_emulator() -> Any:
    spec = importlib.util.spec_from_file_location("testcl_irule_emulator", EMULATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load emulator from {EMULATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_check(name: str, callback: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = callback()
    except Exception as exc:  # Keep the report useful when one contract fails.
        return {"name": name, "status": "error", "error": str(exc)}
    if not isinstance(result, dict):
        return {
            "name": name,
            "status": "error",
            "error": f"check returned {type(result).__name__}, expected an object",
        }
    row = {"name": name, "status": result.get("status", "unknown")}
    for field in ("summary", "analysis", "execution"):
        if field in result:
            row[field] = result[field]
    return row


def _check_passed(row: dict[str, Any]) -> bool:
    return row.get("status") in {"ok", "passed"}


def _probe_requests(emulator: Any) -> list[dict[str, Any]]:
    templates = emulator._protocol_request_template
    return [
        {
            "name": "HTTP::host",
            "request": {
                "command": "HTTP::host",
                "event": "HTTP_REQUEST",
                "profiles": ["TCP", "HTTP"],
                "request": templates("HTTP_REQUEST"),
            },
        },
        {
            "name": "DNS::len",
            "request": {
                "command": "DNS::len",
                "event": "DNS_REQUEST",
                "profiles": ["UDP", "DNS"],
                "request": templates("DNS_REQUEST"),
            },
        },
        {
            "name": "MQTT::topic",
            "request": {
                "command": "MQTT::topic",
                "event": "MQTT_CLIENT_DATA",
                "profiles": ["TCP", "MQTT"],
                "request": templates("MQTT_CLIENT_DATA"),
            },
        },
        {
            "name": "SIP::method",
            "request": {
                "command": "SIP::method",
                "event": "SIP_REQUEST",
                "profiles": ["UDP", "SIP"],
                "request": templates("SIP_REQUEST"),
            },
        },
        {
            "name": "PCP::request",
            "request": {
                "command": "PCP::request",
                "args": ["opcode"],
                "event": "PCP_REQUEST",
                "profiles": ["UDP", "PCP"],
                "request": templates("PCP_REQUEST"),
            },
        },
        {
            "name": "RADIUS::code",
            "request": {
                "command": "RADIUS::code",
                "event": "RADIUS_AAA_AUTH_REQUEST",
                "profiles": ["UDP", "RADIUS"],
                "request": templates("RADIUS_AAA_AUTH_REQUEST"),
            },
        },
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run local TMOS 17.5 emulator contracts and representative protocol probes"
    )
    parser.add_argument(
        "--tcl-lsp-root",
        default=os.environ.get("TCL_LSP_ROOT"),
        help="pinned tcl-lsp checkout (defaults to TCL_LSP_ROOT)",
    )
    args = parser.parse_args(argv)
    if not args.tcl_lsp_root:
        parser.error("--tcl-lsp-root or TCL_LSP_ROOT is required")

    emulator = _load_emulator()
    root = emulator._find_tcl_lsp_root(args.tcl_lsp_root)
    report: dict[str, Any] = {
        "status": "passed",
        "profile": "tmos-17.5",
        "evidence": "local-emulator-contracts",
        "warning": "This report is not independent TMOS/vLab observation evidence.",
        "conformance": _run_check(
            "catalog-conformance", lambda: emulator._build_conformance(root)
        ),
        "behavior_packs": [],
        "golden_vectors": [],
        "protocol_probes": [],
    }

    for path in sorted((ROOT / "examples" / "behavior-packs").glob("*.json")):
        report["behavior_packs"].append(
            _run_check(
                path.name,
                lambda path=path: emulator.run_behavior_pack(
                    json.loads(path.read_text(encoding="utf-8")),
                    tcl_lsp_root=str(root),
                ),
            )
        )
    for path in sorted((ROOT / "examples" / "golden-vectors").glob("*.json")):
        report["golden_vectors"].append(
            _run_check(
                path.name,
                lambda path=path: emulator.run_golden_vectors(
                    json.loads(path.read_text(encoding="utf-8")),
                    tcl_lsp_root=str(root),
                ),
            )
        )

    for probe in _probe_requests(emulator):
        result = _run_check(
            probe["name"],
            lambda probe=probe: emulator.run_command_probe(
                probe["request"],
                tcl_lsp_root=str(root),
                allow_external_protocol_request=True,
            ),
        )
        if "error" not in result:
            execution = result.pop("execution", None)
            if isinstance(execution, dict):
                result["value"] = execution.get("value")
                result["event_fired"] = execution.get("event", {}).get("fired")
        report["protocol_probes"].append(result)

    groups = [report["conformance"], *report["behavior_packs"], *report["golden_vectors"], *report["protocol_probes"]]
    failed = [row for row in groups if not _check_passed(row)]
    report["summary"] = {
        "checks": len(groups),
        "passed": len(groups) - len(failed),
        "failed": len(failed),
        "behavior_pack_count": len(report["behavior_packs"]),
        "golden_vector_count": len(report["golden_vectors"]),
        "protocol_probe_count": len(report["protocol_probes"]),
    }
    report["status"] = "passed" if not failed else "failed"
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
