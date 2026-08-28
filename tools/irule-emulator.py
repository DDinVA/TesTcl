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
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


TMOS_VERSION = "17.5"
DEFAULT_PROFILES = ["TCP", "HTTP"]
HTTP_REASON_PHRASES = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    409: "Conflict",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


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


def _proc_names(path: Path) -> set[str]:
    """Read Tcl proc names without executing upstream source code."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    return set(re.findall(r"^\s*proc\s+([A-Za-z0-9_.-]+)\s+", source, re.MULTILINE))


def _mock_proc_name(command: str) -> str:
    if "::" in command:
        namespace, subcommand = command.split("::", 1)
        return "{}_{}".format(
            namespace.lower().replace("-", "_").replace(".", "_"),
            subcommand.replace("-", "_").replace(".", "_"),
        )
    return "cmd_{}".format(command.replace("-", "_").replace(".", "_"))


def _capability_status(proc_name: str, handwritten: set[str], generated: set[str]) -> str:
    if proc_name in handwritten:
        return "handwritten-mock"
    if proc_name in generated:
        return "generated-stub"
    return "no-runtime-handler"


def _build_capabilities(root: Path, offset: int, limit: int) -> dict[str, Any]:
    """Build a chunked, machine-readable view of the tcl-lsp F5 registry."""
    if offset < 0:
        raise EmulatorInputError("capability offset must be non-negative")
    if not 1 <= limit <= 1000:
        raise EmulatorInputError("capability limit must be between 1 and 1000")

    _load_session_class(root)
    try:
        from compiler.registry import REGISTRY
        from compiler.registry.namespace_data import PROFILE_SPECS
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp capability registry: {exc}") from exc

    command_names = list(REGISTRY.command_names(dialect="f5-irules"))
    command_names.sort()
    tcl_dir = root / "tooling" / "irule_test" / "tcl"
    handwritten = _proc_names(tcl_dir / "command_mocks.tcl")
    generated = _proc_names(tcl_dir / "_mock_stubs.tcl")

    commands: list[dict[str, Any]] = []
    status_counts = {"handwritten-mock": 0, "generated-stub": 0, "no-runtime-handler": 0}
    for name in command_names:
        spec = REGISTRY.get_any(name)
        if spec is None:  # pragma: no cover - registry contract guard
            continue
        proc_name = _mock_proc_name(name)
        runtime_status = _capability_status(proc_name, handwritten, generated)
        status_counts[runtime_status] += 1
        requirement = spec.event_requires
        commands.append(
            {
                "name": name,
                "namespace": name.split("::", 1)[0] if "::" in name else "",
                "subcommands": sorted(spec.subcommands),
                "pure": bool(spec.pure),
                "unsafe": bool(spec.unsafe),
                "runtime_status": runtime_status,
                "event_requirements": {
                    "profiles": sorted(requirement.profiles) if requirement else [],
                    "also_in": sorted(requirement.also_in) if requirement else [],
                    "transport": requirement.transport if requirement else None,
                    "capability": requirement.capability if requirement else None,
                    "client_side": bool(requirement.client_side) if requirement else False,
                    "server_side": bool(requirement.server_side) if requirement else False,
                    "flow": bool(requirement.flow) if requirement else False,
                    "init_only": bool(requirement.init_only) if requirement else False,
                },
            }
        )

    events: list[dict[str, Any]] = []
    for name in sorted(NAMESPACE_REGISTRY.all_event_names()):
        props = NAMESPACE_REGISTRY.get_props(name)
        if props is None:  # pragma: no cover - registry contract guard
            continue
        transport = props.transport
        events.append(
            {
                "name": name,
                "multiplicity": NAMESPACE_REGISTRY.event_multiplicity(name),
                "client_side": bool(props.client_side),
                "server_side": bool(props.server_side),
                "transport": list(transport) if isinstance(transport, tuple) else transport,
                "implied_profiles": sorted(props.implied_profiles),
                "flow": bool(props.flow),
                "deprecated": bool(props.deprecated),
                "common": bool(props.common),
            }
        )

    profiles = [
        {
            "name": name,
            "layer": spec.layer,
            "side": spec.side,
            "requires": sorted(spec.requires),
            "conflicts": sorted(spec.conflicts),
            "capabilities": sorted(spec.capabilities),
        }
        for name, spec in sorted(PROFILE_SPECS.items())
    ]

    start = min(offset, len(commands))
    end = min(start + limit, len(commands))
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "source": {
            "name": "tcl-lsp f5-irules registry",
            "commit": os.environ.get("TCL_LSP_COMMIT", "unknown"),
        },
        "summary": {
            "command_count": len(commands),
            "event_count": len(events),
            "profile_count": len(profiles),
            "runtime_status_counts": status_counts,
        },
        "chunk": {
            "offset": offset,
            "limit": limit,
            "count": end - start,
            "total": len(commands),
            "has_more": end < len(commands),
        },
        "commands": commands[start:end],
        "events": events,
        "profiles": profiles,
    }


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise EmulatorInputError(f"{field} must be a string")
    return value


def _tcl_quote(value: str) -> str:
    """Quote a string for one Tcl word without enabling substitutions."""
    if "\x00" in value:
        raise EmulatorInputError("Tcl strings cannot contain NUL bytes")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _tcl_list(values: list[str]) -> str:
    return "{" + " ".join(_tcl_quote(value) for value in values) + "}"


def _split_tcl_list(value: Any) -> list[str]:
    """Parse a Tcl list returned by the bridge using a temporary interpreter."""
    try:
        import tkinter

        return list(tkinter.Tcl().splitlist(str(value)))
    except Exception:
        return []


def _header_dict(raw: Any) -> dict[str, Any]:
    parts = _split_tcl_list(raw)
    if len(parts) % 2:
        return {"_raw": str(raw)}
    headers: dict[str, Any] = {}
    for name, values in zip(parts[::2], parts[1::2]):
        parsed_values = _split_tcl_list(values)
        headers[name] = parsed_values[0] if len(parsed_values) == 1 else parsed_values
    return headers


def _install_runtime_shims(session: Any) -> None:
    """Correct small upstream mock gaps at the adapter boundary.

    These wrappers delegate to the upstream implementation. They only add
    response-context selection and capture the body supplied to
    ``HTTP::respond ... content ...``.
    """
    session.eval_tcl(
        r"""
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_http_payload_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::http_payload ::itest::cmd::_testcl_http_payload_orig
            proc ::itest::cmd::http_payload {args} {
                if {$::itest::current_event ne "HTTP_RESPONSE"} {
                    return [eval [linsert $args 0 ::itest::cmd::_testcl_http_payload_orig]]
                }
                set previous_event $::itest::current_event
                set ::itest::current_event HTTP_RESPONSE_DATA
                set rc [catch {
                    eval [linsert $args 0 ::itest::cmd::_testcl_http_payload_orig]
                } result options]
                set ::itest::current_event $previous_event
                if {$rc} {
                    return -options $options $result
                }
                return $result
            }
        }
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_http_respond_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::http_respond ::itest::cmd::_testcl_http_respond_orig
            proc ::itest::cmd::http_respond {args} {
                set rc [catch {
                    eval [linsert $args 0 ::itest::cmd::_testcl_http_respond_orig]
                } result options]
                if {$rc} {
                    return -options $options $result
                }
                set status [lindex $args 0]
                if {[string is integer -strict $status]} {
                    set ::state::http::response::status $status
                }
                set content_index [lsearch -exact $args content]
                if {$content_index >= 0 && $content_index + 1 < [llength $args]} {
                    set ::state::http::response::payload [lindex $args [expr {$content_index + 1}]]
                }
                return $result
            }
        }
        """
    )


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
    allowed = {
        "method",
        "uri",
        "host",
        "headers",
        "body",
        "sni",
        "response_status",
        "response_headers",
        "response_body",
    }
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
    for field in ("body", "response_body"):
        if field in request:
            kwargs[field] = _require_string(request[field], field)
    if "response_status" in request:
        status = request["response_status"]
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 999:
            raise EmulatorInputError("response_status must be an integer between 100 and 999")
        kwargs["response_status"] = status
    for field in ("response_headers",):
        headers_value = request.get(field)
        if headers_value is not None:
            if not isinstance(headers_value, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in headers_value.items()
            ):
                raise EmulatorInputError(f"{field} must be an object of strings")
            kwargs[field] = headers_value
    return kwargs


def _run_request_with_state(session: Any, proc_name: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Run an orchestrator request and return enriched HTTP state."""
    args: list[str] = []
    for field, option in (
        ("method", "-method"),
        ("uri", "-uri"),
        ("host", "-host"),
        ("sni", "-sni"),
    ):
        if field in kwargs:
            args.extend([option, _tcl_quote(kwargs[field])])
    if "headers" in kwargs:
        header_values: list[str] = []
        for name, value in kwargs["headers"].items():
            header_values.extend([name, value])
        args.extend(["-headers", _tcl_list(header_values)])
    if "response_status" in kwargs:
        args.extend(["-response_status", str(kwargs["response_status"])])
    if "response_headers" in kwargs:
        header_values = []
        for name, value in kwargs["response_headers"].items():
            header_values.extend([name, value])
        args.extend(["-response_headers", _tcl_list(header_values)])
    if "response_body" in kwargs:
        args.extend(["-response_payload", _tcl_quote(kwargs["response_body"])])

    command = "::orch::{} {}".format(proc_name, " ".join(args))
    body = kwargs.get("body")
    if body is None:
        session.eval_tcl(command)
    else:
        body_value = _tcl_quote(body)
        script = f"""
            set ::orch::_testcl_request_payload {body_value}
            proc ::orch::_testcl_request_payload_trace {{name1 name2 op}} {{
                set ::state::http::request::payload $::orch::_testcl_request_payload
            }}
            ::trace add variable ::state::http::request::payload write ::orch::_testcl_request_payload_trace
            set ::orch::_testcl_request_rc [catch {{set ::orch::_testcl_request_result [{command}]}} ::orch::_testcl_request_error ::orch::_testcl_request_options]
            catch {{::trace remove variable ::state::http::request::payload write ::orch::_testcl_request_payload_trace}}
            ::tmm::_orig_rename ::orch::_testcl_request_payload_trace {{}}
            if {{$::orch::_testcl_request_rc}} {{
                return -options $::orch::_testcl_request_options $::orch::_testcl_request_error
            }}
            set ::orch::_testcl_request_result
        """
        session.eval_tcl(script)

    request_state = session.get_state("http_request")
    response_state = session.get_state("http_response")
    committed = session.eval_tcl("set ::state::http::response_committed")
    fired_events = _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
    decisions = session.get_decisions()
    logs = session.get_logs()
    lb_state = session.get_state("lb")
    connection_state = session.get_state("connection")
    response_status = int(response_state.get("status", "200"))
    response_reason = HTTP_REASON_PHRASES.get(
        response_status, response_state.get("reason", "")
    )
    return {
        "pool": lb_state.get("pool", ""),
        "node": lb_state.get("node_addr", ""),
        "response_committed": str(committed) == "1",
        "connection_state": connection_state.get("state", ""),
        "events_fired": fired_events,
        "decisions": [entry if not isinstance(entry, tuple) else list(entry) for entry in decisions],
        "logs": [entry if not isinstance(entry, tuple) else list(entry) for entry in logs],
        "request": {
            "method": request_state.get("method", ""),
            "uri": request_state.get("uri", ""),
            "path": request_state.get("path", ""),
            "query": request_state.get("query", ""),
            "host": request_state.get("host", ""),
            "headers": _header_dict(request_state.get("headers", "")),
            "body": session.eval_tcl("set ::state::http::request::payload"),
        },
        "response": {
            "status": response_status,
            "reason": response_reason,
            "headers": _header_dict(response_state.get("headers", "")),
            "body": session.eval_tcl("set ::state::http::response::payload"),
        },
    }


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
            _install_runtime_shims(session)
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
                fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
                if connection_open and not request.get("new_connection"):
                    result = _run_request_with_state(session, "run_next_request", kwargs)
                else:
                    result = _run_request_with_state(session, "run_http_request", kwargs)
                result["events_fired"] = result["events_fired"][fired_before:]
                results.append(result)
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


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _http_handler(root: Path) -> type[BaseHTTPRequestHandler]:
    class EmulatorHandler(BaseHTTPRequestHandler):
        server_version = "testcl-irule-emulator/1"

        def log_message(self, format: str, *args: Any) -> None:
            print(f"{self.address_string()} - {format % args}", file=sys.stderr)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                _json_response(self, 200, {"status": "ok", "profile": "tmos-17.5"})
                return
            if parsed.path == "/v1/capabilities":
                query = parse_qs(parsed.query, strict_parsing=False)
                try:
                    offset = int(query.get("offset", ["0"])[0])
                    limit = int(query.get("limit", ["100"])[0])
                    payload = _build_capabilities(root, offset, limit)
                except (TypeError, ValueError, EmulatorInputError) as exc:
                    _json_response(self, 400, {"status": "error", "error": str(exc)})
                    return
                _json_response(self, 200, payload)
                return
            _json_response(self, 404, {"status": "error", "error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path != "/v1/simulations":
                _json_response(self, 404, {"status": "error", "error": "not found"})
                return
            length_header = self.headers.get("Content-Length")
            try:
                length = int(length_header) if length_header is not None else -1
            except ValueError:
                length = -1
            if length < 0 or length > 2 * 1024 * 1024:
                _json_response(self, 413, {"status": "error", "error": "request body too large or missing"})
                return
            try:
                scenario = json.loads(self.rfile.read(length))
                if isinstance(scenario, dict) and "irule_file" in scenario:
                    raise EmulatorInputError(
                        "HTTP API accepts inline irule only; use the CLI for irule_file"
                    )
                payload = run_scenario(scenario, tcl_lsp_root=str(root))
            except (json.JSONDecodeError, EmulatorInputError, OSError) as exc:
                _json_response(self, 400, {"status": "error", "error": str(exc)})
                return
            _json_response(self, 200, payload)

    return EmulatorHandler


def serve(root: Path, host: str, port: int) -> None:
    if not 1 <= port <= 65535:
        raise EmulatorInputError("port must be between 1 and 65535")
    server = ThreadingHTTPServer((host, port), _http_handler(root))
    print(f"testcl emulator listening on http://{host}:{port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a BIG-IP 17.5 iRule emulator scenario")
    parser.add_argument("--scenario", default="-", help="JSON scenario path, or - for stdin")
    parser.add_argument("--tcl-lsp-root", help="path to a tcl-lsp checkout")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--capabilities",
        action="store_true",
        help="emit a chunk of the complete tcl-lsp iRule capability catalog",
    )
    mode.add_argument("--serve", action="store_true", help="serve the HTTP API instead of reading stdin")
    parser.add_argument("--offset", type=int, default=0, help="capability chunk start")
    parser.add_argument("--limit", type=int, default=100, help="capability chunk size")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP API bind address")
    parser.add_argument("--port", type=int, default=8080, help="HTTP API bind port")
    parser.add_argument(
        "--backend",
        choices=("inprocess",),
        default="inprocess",
        help="tcl-lsp bridge backend (inprocess is currently required)",
    )
    args = parser.parse_args(argv)

    try:
        root = _find_tcl_lsp_root(args.tcl_lsp_root)
        if args.serve:
            serve(root, args.host, args.port)
            return 0
        if args.capabilities:
            response = _build_capabilities(root, args.offset, args.limit)
        else:
            if args.scenario == "-":
                scenario = json.load(sys.stdin)
            else:
                scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
            response = run_scenario(scenario, tcl_lsp_root=str(root), backend=args.backend)
    except (OSError, json.JSONDecodeError, EmulatorInputError) as exc:
        response = {"status": "error", "error": str(exc)}
        print(json.dumps(response, separators=(",", ":")))
        return 1

    print(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
