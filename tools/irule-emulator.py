#!/usr/bin/env python3
"""Run a BIG-IP 17.5 iRule scenario through the tcl-lsp emulator.

TesTcl remains a Tcl-only library.  This adapter is deliberately a thin
runtime boundary: tcl-lsp is discovered outside this repository and imported
only when the emulator is invoked.  That keeps the legacy package usable on
its own while giving container and automation callers a stable JSON API.

Input is one JSON scenario object.  See docs/emulator.md for the schema.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


TMOS_VERSION = "17.5"
DEFAULT_PROFILES = ["TCP", "HTTP"]


class EmulatorInputError(ValueError):
    """Raised when a scenario cannot be safely or unambiguously executed."""


def _find_tcl_lsp_root(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_root = os.environ.get("TCL_LSP_ROOT")
    if env_root:
        candidates.append(Path(env_root))
    here = Path(__file__).resolve()
    candidates.extend((here.parent.parent / "tcl-lsp", here.parent / "tcl-lsp"))

    for candidate in candidates:
        root = candidate.expanduser().resolve()
        if (root / "tooling" / "irule_test" / "bridge.py").is_file():
            return root

    searched = ", ".join(str(path.expanduser()) for path in candidates)
    raise EmulatorInputError(
        "tcl-lsp was not found; set TCL_LSP_ROOT or pass --tcl-lsp-root "
        f"(searched: {searched})"
    )


def _load_session_class(root: Path) -> Any:
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        from tooling.irule_test.bridge import IruleTestSessionSync
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp iRule framework: {exc}") from exc
    return IruleTestSessionSync


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise EmulatorInputError(f"{field} must be a string")
    return value


def _normalise_pools(raw: Any) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("pools must be an object mapping names to member arrays")
    pools: dict[str, list[str]] = {}
    for name, members in raw.items():
        _require_string(name, "pool name")
        if isinstance(members, dict):
            members = members.get("members")
        if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
            raise EmulatorInputError(f"pool {name!r} members must be an array of strings")
        pools[name] = members
    return pools


def _normalise_datagroups(raw: Any) -> list[tuple[str, dict[str, str], str]]:
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise EmulatorInputError("datagroups must be an object")
    groups: list[tuple[str, dict[str, str], str]] = []
    for name, definition in raw.items():
        if not isinstance(definition, dict):
            raise EmulatorInputError(f"datagroup {name!r} must be an object")
        records = definition.get("records", {})
        dg_type = definition.get("type", "string")
        if not isinstance(records, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in records.items()
        ):
            raise EmulatorInputError(f"datagroup {name!r} records must be a string object")
        if not isinstance(dg_type, str):
            raise EmulatorInputError(f"datagroup {name!r} type must be a string")
        groups.append((name, records, dg_type))
    return groups


def _normalise_requests(scenario: dict[str, Any]) -> list[dict[str, Any]]:
    requests = scenario.get("requests")
    if requests is None:
        requests = [scenario.get("request", {})]
    if not isinstance(requests, list) or not requests:
        raise EmulatorInputError("requests must be a non-empty array")
    if not all(isinstance(request, dict) for request in requests):
        raise EmulatorInputError("each request must be an object")
    return requests


def _request_kwargs(request: dict[str, Any]) -> dict[str, Any]:
    allowed = {"method", "uri", "host", "headers", "sni", "response_status"}
    unknown = sorted(set(request) - allowed - {"close_before", "close_after", "new_connection"})
    if unknown:
        raise EmulatorInputError(f"unsupported request field(s): {', '.join(unknown)}")

    kwargs: dict[str, Any] = {}
    for field in ("method", "uri", "host", "sni"):
        if field in request:
            kwargs[field] = _require_string(request[field], field)
    headers = request.get("headers")
    if headers is not None:
        if not isinstance(headers, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in headers.items()
        ):
            raise EmulatorInputError("request headers must be an object of strings")
        kwargs["headers"] = headers
    if "response_status" in request:
        status = request["response_status"]
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 999:
            raise EmulatorInputError("response_status must be an integer between 100 and 999")
        kwargs["response_status"] = status
    return kwargs


def _result_json(result: Any) -> dict[str, Any]:
    def event_json(event: Any) -> dict[str, Any]:
        return {
            "event": event.event,
            "fired": bool(event.fired),
            "handlers": event.handlers,
            "reason": event.reason,
        }

    def entry_json(entry: Any) -> Any:
        if isinstance(entry, (list, tuple)):
            return list(entry)
        return entry

    return {
        "pool": result.pool_selected,
        "node": result.node_selected,
        "response_committed": bool(result.http_response_committed),
        "connection_state": result.connection_state,
        "events_fired": [event_json(event) for event in result.events_fired],
        "decisions": [entry_json(decision) for decision in result.decisions],
        "logs": [entry_json(log_entry) for log_entry in result.logs],
    }


def run_scenario(
    scenario: Any,
    *,
    tcl_lsp_root: str | None = None,
    backend: str = "inprocess",
) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")
    allowed_fields = {
        "tmos_version",
        "irule",
        "irule_file",
        "profiles",
        "pools",
        "datagroups",
        "request",
        "requests",
    }
    unknown_fields = sorted(set(scenario) - allowed_fields)
    if unknown_fields:
        raise EmulatorInputError(f"unsupported scenario field(s): {', '.join(unknown_fields)}")
    if scenario.get("tmos_version", TMOS_VERSION) != TMOS_VERSION:
        raise EmulatorInputError("only the tmos-17.5 emulator profile is supported")
    if backend != "inprocess":
        raise EmulatorInputError(
            "the tmos-17.5 adapter currently requires the in-process Tcl backend"
        )

    source = scenario.get("irule")
    if source is not None and scenario.get("irule_file") is not None:
        raise EmulatorInputError("provide only one of irule and irule_file")
    if source is None and scenario.get("irule_file") is not None:
        rule_path = Path(_require_string(scenario["irule_file"], "irule_file")).expanduser()
        try:
            source = rule_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise EmulatorInputError(f"could not read irule_file {rule_path}: {exc}") from exc
    if not isinstance(source, str) or not source.strip():
        raise EmulatorInputError("scenario requires a non-empty irule or irule_file")

    profiles = scenario.get("profiles", DEFAULT_PROFILES)
    if not isinstance(profiles, list) or not profiles or not all(
        isinstance(profile, str) and profile for profile in profiles
    ):
        raise EmulatorInputError("profiles must be a non-empty array of strings")
    if "HTTP" not in profiles:
        raise EmulatorInputError("the first emulator slice requires the HTTP profile")

    session_class = _load_session_class(_find_tcl_lsp_root(tcl_lsp_root))
    pools = _normalise_pools(scenario.get("pools"))
    datagroups = _normalise_datagroups(scenario.get("datagroups"))
    requests = _normalise_requests(scenario)

    try:
        with session_class(profiles=profiles, tmos_version=TMOS_VERSION, backend=backend) as session:
            registered_events = session.load_irule(source)
            for name, members in pools.items():
                session.add_pool(name, members)
            for name, records, dg_type in datagroups:
                session.add_datagroup(name, records, dg_type)

            results: list[dict[str, Any]] = []
            connection_open = False
            for request in requests:
                for flag in ("close_before", "close_after", "new_connection"):
                    if flag in request and not isinstance(request[flag], bool):
                        raise EmulatorInputError(f"request field {flag} must be a boolean")
                if request.get("close_before") or request.get("new_connection"):
                    if connection_open:
                        session.close_connection()
                    connection_open = False
                kwargs = _request_kwargs(request)
                if connection_open and not request.get("new_connection"):
                    result = session.run_next_request(**kwargs)
                else:
                    result = session.run_http_request(**kwargs)
                results.append(_result_json(result))
                connection_open = True
                if request.get("close_after"):
                    session.close_connection()
                    connection_open = False
    except EmulatorInputError:
        raise
    except Exception as exc:
        raise EmulatorInputError(f"emulator execution failed: {exc}") from exc

    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "registered_events": registered_events,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a BIG-IP 17.5 iRule emulator scenario")
    parser.add_argument("--scenario", default="-", help="JSON scenario path, or - for stdin")
    parser.add_argument("--tcl-lsp-root", help="path to a tcl-lsp checkout")
    parser.add_argument(
        "--backend",
        choices=("inprocess",),
        default="inprocess",
        help="tcl-lsp bridge backend (inprocess is currently required)",
    )
    args = parser.parse_args(argv)

    try:
        if args.scenario == "-":
            scenario = json.load(sys.stdin)
        else:
            scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
        response = run_scenario(scenario, tcl_lsp_root=args.tcl_lsp_root, backend=args.backend)
    except (OSError, json.JSONDecodeError, EmulatorInputError) as exc:
        response = {"status": "error", "error": str(exc)}
        print(json.dumps(response, separators=(",", ":")))
        return 1

    print(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
