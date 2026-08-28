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
import queue
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


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
DEFAULT_MAX_SESSIONS = 32
DEFAULT_SESSION_IDLE_SECONDS = 1800
EVENT_STATE_FIELDS = {
    "connection": {
        "client_addr",
        "client_port",
        "server_addr",
        "server_port",
        "local_addr",
        "local_port",
        "remote_addr",
        "remote_port",
        "vip_addr",
        "vip_port",
        "protocol",
        "transport",
        "mss",
        "ttl",
        "tos",
        "bandwidth",
        "rtt",
        "idle_timeout",
        "client_payload",
        "server_payload",
        "state",
    },
    "tls_client": {
        "sni",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_count",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
    },
    "tls_server": {
        "sni",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_count",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
    },
    "dns": {
        "qname",
        "qtype",
        "qclass",
        "rcode",
        "opcode",
        "id",
        "aa",
        "tc",
        "rd",
        "ra",
        "cd",
        "ad",
        "answers",
        "authority",
        "additional",
        "response_sent",
    },
}
EVENT_STATE_NAMESPACES = {
    "connection": "::state::connection",
    "tls_client": "::state::tls::client",
    "tls_server": "::state::tls::server",
    "dns": "::state::dns",
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
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")
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


def _validate_request_flags(request: dict[str, Any]) -> None:
    for flag in ("close_before", "close_after", "new_connection"):
        if flag in request and not isinstance(request[flag], bool):
            raise EmulatorInputError(f"request field {flag} must be a boolean")


def _normalise_scenario_config(
    scenario: Any,
    *,
    allow_irule_file: bool,
    allow_requests: bool,
    require_http: bool,
) -> tuple[str, list[str], dict[str, list[str]], list[tuple[str, dict[str, str], str]]]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")

    allowed_fields = {"tmos_version", "irule", "irule_file", "profiles", "pools", "datagroups"}
    if allow_requests:
        allowed_fields.update(("request", "requests"))
    unknown_fields = sorted(set(scenario) - allowed_fields)
    if unknown_fields:
        raise EmulatorInputError(f"unsupported scenario field(s): {', '.join(unknown_fields)}")
    if scenario.get("tmos_version", TMOS_VERSION) != TMOS_VERSION:
        raise EmulatorInputError("only the tmos-17.5 emulator profile is supported")

    source = scenario.get("irule")
    irule_file = scenario.get("irule_file")
    if source is not None and irule_file is not None:
        raise EmulatorInputError("provide only one of irule and irule_file")
    if irule_file is not None:
        if not allow_irule_file:
            raise EmulatorInputError("this API accepts inline irule only")
        rule_path = Path(_require_string(irule_file, "irule_file")).expanduser()
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
    if require_http and "HTTP" not in profiles:
        raise EmulatorInputError("the first emulator slice requires the HTTP profile")

    return source, profiles, _normalise_pools(scenario.get("pools")), _normalise_datagroups(
        scenario.get("datagroups")
    )


def _load_event_profiles(root: Path) -> dict[str, set[str]]:
    _load_session_class(root)
    try:
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp event registry: {exc}") from exc
    event_profiles: dict[str, set[str]] = {}
    for name in NAMESPACE_REGISTRY.all_event_names():
        props = NAMESPACE_REGISTRY.get_props(name)
        event_profiles[name] = set(props.implied_profiles) if props is not None else set()
    return event_profiles


def _normalise_event(event: Any, state: Any) -> tuple[str, dict[str, dict[str, str]]]:
    event_name = _require_string(event, "event")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", event_name):
        raise EmulatorInputError("event must be an uppercase iRule event name")
    if state is None:
        return event_name, {}
    if not isinstance(state, dict):
        raise EmulatorInputError("event state must be an object mapping layers to fields")
    normalised: dict[str, dict[str, str]] = {}
    for layer, values in state.items():
        if layer not in EVENT_STATE_FIELDS:
            raise EmulatorInputError(f"unsupported event state layer: {layer}")
        if not isinstance(values, dict):
            raise EmulatorInputError(f"event state layer {layer!r} must be an object")
        layer_values: dict[str, str] = {}
        for field, value in values.items():
            if field not in EVENT_STATE_FIELDS[layer]:
                raise EmulatorInputError(f"unsupported {layer} state field: {field}")
            if isinstance(value, bool):
                layer_values[field] = "1" if value else "0"
            elif isinstance(value, (str, int, float)):
                layer_values[field] = str(value)
            else:
                raise EmulatorInputError(
                    f"event state value {layer}.{field} must be a string or number"
                )
        normalised[layer] = layer_values
    return event_name, normalised


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


class EmulatorSession:
    """Own one Tcl interpreter on a dedicated thread.

    tkinter Tcl interpreters are thread-affine. A worker thread keeps a
    persistent session safe when successive HTTP requests are handled by
    different ``ThreadingHTTPServer`` workers.
    """

    def __init__(
        self,
        root: Path,
        scenario: dict[str, Any],
        *,
        allow_irule_file: bool,
        allow_requests: bool,
    ) -> None:
        source, profiles, pools, datagroups = _normalise_scenario_config(
            scenario,
            allow_irule_file=allow_irule_file,
            allow_requests=allow_requests,
            require_http=False,
        )
        self._root = root
        self._source = source
        self._profiles = profiles
        self._pools = pools
        self._datagroups = datagroups
        self._event_profiles = _load_event_profiles(root)
        self._tasks: queue.Queue[Any] = queue.Queue()
        self._started = threading.Event()
        self._startup_error: BaseException | None = None
        self._call_lock = threading.RLock()
        self._closed = False
        self._thread = threading.Thread(
            target=self._worker_main,
            name="testcl-irule-session",
            daemon=True,
        )
        self._registered_events: list[str] = []
        self._request_count = 0
        self._connection_open = False
        self._thread.start()
        self._started.wait()
        if self._startup_error is not None:
            error = self._startup_error
            self.close()
            raise EmulatorInputError(f"could not start emulator session: {error}") from error

    @property
    def registered_events(self) -> list[str]:
        return list(self._registered_events)

    def _worker_main(self) -> None:
        session_class: Any = None
        try:
            session_class = _load_session_class(self._root)
            backend_session = session_class(
                profiles=self._profiles,
                tmos_version=TMOS_VERSION,
                backend="inprocess",
            )
            with backend_session as session:
                _install_runtime_shims(session)
                self._registered_events = session.load_irule(self._source)
                for name, members in self._pools.items():
                    session.add_pool(name, members)
                for name, records, dg_type in self._datagroups:
                    session.add_datagroup(name, records, dg_type)
                self._started.set()
                while True:
                    task = self._tasks.get()
                    if task is None:
                        break
                    function, completed, result = task
                    try:
                        result["value"] = function(session)
                    except BaseException as exc:  # propagate Tcl errors to the caller
                        result["error"] = exc
                    finally:
                        completed.set()
        except BaseException as exc:
            self._startup_error = exc
            self._started.set()

    def _call(self, function: Any) -> Any:
        with self._call_lock:
            if self._closed:
                raise EmulatorInputError("emulator session is closed")
            if not self._thread.is_alive():
                raise EmulatorInputError("emulator session worker stopped")
            completed = threading.Event()
            result: dict[str, Any] = {}
            self._tasks.put((function, completed, result))
            completed.wait()
            if "error" in result:
                error = result["error"]
                raise error
            return result.get("value")

    def _run_request_on_worker(self, session: Any, request: dict[str, Any]) -> dict[str, Any]:
        _validate_request_flags(request)
        if request.get("close_before") or request.get("new_connection"):
            if self._connection_open:
                session.close_connection()
            self._connection_open = False
        kwargs = _request_kwargs(request)
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        if self._connection_open and not request.get("new_connection"):
            result = _run_request_with_state(session, "run_next_request", kwargs)
        else:
            result = _run_request_with_state(session, "run_http_request", kwargs)
        result["events_fired"] = result["events_fired"][fired_before:]
        self._connection_open = True
        self._request_count += 1
        if request.get("close_after"):
            session.close_connection()
            self._connection_open = False
        return result

    def run_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._call(lambda session: self._run_request_on_worker(session, request))

    def _fire_event_on_worker(
        self,
        session: Any,
        event_name: str,
        state: dict[str, dict[str, str]],
    ) -> dict[str, Any]:
        required_profiles = self._event_profiles.get(event_name, set())
        attached_profiles = {profile.upper() for profile in self._profiles}
        if required_profiles and not required_profiles.intersection(attached_profiles):
            return {
                "event": event_name,
                "fired": False,
                "reason": "profile_gate",
                "events_fired": [],
                "state": {},
                "decisions": [],
                "logs": [],
            }
        for layer, values in state.items():
            namespace = EVENT_STATE_NAMESPACES[layer]
            for field, value in values.items():
                session.eval_tcl(f"set {namespace}::{field} {_tcl_quote(value)}")
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        event_result = session.fire_event(event_name)
        fired_events = _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
        return {
            "event": event_name,
            "fired": bool(event_result.fired),
            "reason": event_result.reason,
            "events_fired": fired_events[fired_before:],
            "state": {
                layer: {
                    field: session.eval_tcl(f"set {EVENT_STATE_NAMESPACES[layer]}::{field}")
                    for field in EVENT_STATE_FIELDS[layer]
                }
                for layer in state
            },
            "decisions": [
                entry if not isinstance(entry, tuple) else list(entry)
                for entry in session.get_decisions()
            ],
            "logs": [
                entry if not isinstance(entry, tuple) else list(entry)
                for entry in session.get_logs()
            ],
        }

    def fire_event(self, event: Any, state: Any = None) -> dict[str, Any]:
        event_name, normalised_state = _normalise_event(event, state)
        if event_name not in self._event_profiles:
            raise EmulatorInputError(f"unknown iRule event: {event_name}")
        return self._call(
            lambda session: self._fire_event_on_worker(session, event_name, normalised_state)
        )

    def metadata(self, session_id: str) -> dict[str, Any]:
        def read_metadata(session: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "schema_version": 1,
                "profile": "tmos-17.5",
                "tmos_version": TMOS_VERSION,
                "session_id": session_id,
                "registered_events": self.registered_events,
                "request_count": self._request_count,
                "connection_open": self._connection_open,
            }

        return self._call(read_metadata)

    def close(self) -> None:
        with self._call_lock:
            if self._closed:
                return
            self._closed = True
            if self._thread.is_alive():
                self._tasks.put(None)
        self._thread.join(timeout=5)


class EmulatorNotFoundError(KeyError):
    """Raised when a persistent session ID is unknown or expired."""


class EmulatorResourceError(RuntimeError):
    """Raised when the service has reached its session capacity."""


class _SessionRecord:
    def __init__(self, session: EmulatorSession, last_used: float) -> None:
        self.session = session
        self.last_used = last_used
        self.active_operations = 0


class SessionManager:
    """Bounded, idle-expiring registry of persistent emulator sessions."""

    def __init__(
        self,
        root: Path,
        *,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        idle_timeout: float = DEFAULT_SESSION_IDLE_SECONDS,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        self._root = root
        self._max_sessions = max_sessions
        self._idle_timeout = idle_timeout
        self._sessions: dict[str, _SessionRecord] = {}
        self._lock = threading.RLock()

    def _reap(self) -> None:
        expired: list[EmulatorSession] = []
        now = time.monotonic()
        with self._lock:
            for session_id, record in list(self._sessions.items()):
                if record.active_operations == 0 and now - record.last_used > self._idle_timeout:
                    del self._sessions[session_id]
                    expired.append(record.session)
        for session in expired:
            session.close()

    def create(self, scenario: dict[str, Any]) -> str:
        self._reap()
        with self._lock:
            if len(self._sessions) >= self._max_sessions:
                raise EmulatorResourceError("maximum emulator session count reached")
            session = EmulatorSession(
                self._root,
                scenario,
                allow_irule_file=False,
                allow_requests=False,
            )
            session_id = "ses_" + secrets.token_urlsafe(18)
            while session_id in self._sessions:
                session_id = "ses_" + secrets.token_urlsafe(18)
            self._sessions[session_id] = _SessionRecord(session, time.monotonic())
            return session_id

    def execute(self, session_id: str, function: Any) -> Any:
        self._reap()
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise EmulatorNotFoundError(f"unknown or expired session {session_id}")
            record.active_operations += 1
            record.last_used = time.monotonic()
        try:
            return function(record.session)
        finally:
            with self._lock:
                current = self._sessions.get(session_id)
                if current is record:
                    current.active_operations -= 1
                    current.last_used = time.monotonic()

    def metadata(self, session_id: str) -> dict[str, Any]:
        return self.execute(session_id, lambda session: session.metadata(session_id))

    def close(self, session_id: str) -> None:
        with self._lock:
            entry = self._sessions.pop(session_id, None)
        if entry is None:
            raise EmulatorNotFoundError(f"unknown or expired session {session_id}")
        entry.session.close()

    def close_all(self) -> None:
        with self._lock:
            sessions = [record.session for record in self._sessions.values()]
            self._sessions.clear()
        for session in sessions:
            session.close()


def run_scenario(
    scenario: Any,
    *,
    tcl_lsp_root: str | None = None,
    backend: str = "inprocess",
) -> dict[str, Any]:
    if backend != "inprocess":
        raise EmulatorInputError(
            "the tmos-17.5 adapter currently requires the in-process Tcl backend"
        )
    root = _find_tcl_lsp_root(tcl_lsp_root)
    requests = _normalise_requests(scenario)
    _normalise_scenario_config(
        scenario,
        allow_irule_file=True,
        allow_requests=True,
        require_http=True,
    )

    session = EmulatorSession(
        root,
        scenario,
        allow_irule_file=True,
        allow_requests=True,
    )
    try:
        results = [session.run_request(request) for request in requests]
    except EmulatorInputError:
        raise
    except Exception as exc:
        raise EmulatorInputError(f"emulator execution failed: {exc}") from exc
    finally:
        registered_events = session.registered_events
        session.close()

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


def _api_error_status(error: Exception) -> int:
    if isinstance(error, EmulatorNotFoundError):
        return 404
    if isinstance(error, EmulatorResourceError):
        return 429
    return 400


def _http_handler(root: Path, manager: SessionManager | None = None) -> type[BaseHTTPRequestHandler]:
    session_manager = manager if manager is not None else SessionManager(root)

    class EmulatorHandler(BaseHTTPRequestHandler):
        server_version = "testcl-irule-emulator/1"

        def log_message(self, format: str, *args: Any) -> None:
            print(f"{self.address_string()} - {format % args}", file=sys.stderr)

        def _read_json(self) -> Any:
            length_header = self.headers.get("Content-Length")
            try:
                length = int(length_header) if length_header is not None else -1
            except ValueError:
                length = -1
            if length < 0:
                raise EmulatorInputError("request requires a valid Content-Length")
            if length > 2 * 1024 * 1024:
                raise EmulatorResourceError("request body exceeds the 2 MiB limit")
            return json.loads(self.rfile.read(length))

        def _error(self, error: Exception) -> None:
            _json_response(self, _api_error_status(error), {"status": "error", "error": str(error)})

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
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            if len(parts) == 3 and parts[:2] == ["v1", "sessions"]:
                try:
                    payload = session_manager.metadata(parts[2])
                except (EmulatorNotFoundError, EmulatorInputError) as exc:
                    self._error(exc)
                    return
                _json_response(self, 200, payload)
                return
            _json_response(self, 404, {"status": "error", "error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path != "/v1/simulations":
                parts = [unquote(part) for part in parsed.path.split("/") if part]
                if len(parts) == 2 and parts == ["v1", "sessions"]:
                    session_id: str | None = None
                    try:
                        scenario = self._read_json()
                        session_id = session_manager.create(scenario)
                        payload = session_manager.metadata(session_id)
                    except (json.JSONDecodeError, EmulatorInputError, EmulatorResourceError, OSError) as exc:
                        if session_id is not None:
                            try:
                                session_manager.close(session_id)
                            except EmulatorNotFoundError:
                                pass
                        self._error(exc)
                        return
                    _json_response(self, 201, payload)
                    return
                if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "events":
                    try:
                        event_request = self._read_json()
                        if not isinstance(event_request, dict):
                            raise EmulatorInputError("session event must be a JSON object")
                        if "event" not in event_request:
                            raise EmulatorInputError("session event requires an event field")
                        unknown = sorted(set(event_request) - {"event", "state"})
                        if unknown:
                            raise EmulatorInputError(
                                f"unsupported session event field(s): {', '.join(unknown)}"
                            )
                        result = session_manager.execute(
                            parts[2],
                            lambda session: session.fire_event(
                                event_request["event"], event_request.get("state")
                            ),
                        )
                        payload = {
                            "status": "ok",
                            "schema_version": 1,
                            "profile": "tmos-17.5",
                            "tmos_version": TMOS_VERSION,
                            "session_id": parts[2],
                            "result": result,
                        }
                    except (
                        json.JSONDecodeError,
                        EmulatorInputError,
                        EmulatorNotFoundError,
                        EmulatorResourceError,
                        OSError,
                    ) as exc:
                        self._error(exc)
                        return
                    _json_response(self, 200, payload)
                    return
                if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "requests":
                    try:
                        request = self._read_json()
                        if not isinstance(request, dict):
                            raise EmulatorInputError("session request must be a JSON object")
                        result = session_manager.execute(
                            parts[2], lambda session: session.run_request(request)
                        )
                        metadata = session_manager.metadata(parts[2])
                        payload = {
                            "status": "ok",
                            "schema_version": 1,
                            "profile": "tmos-17.5",
                            "tmos_version": TMOS_VERSION,
                            "session_id": parts[2],
                            "request_number": metadata["request_count"],
                            "result": result,
                        }
                    except (
                        json.JSONDecodeError,
                        EmulatorInputError,
                        EmulatorNotFoundError,
                        EmulatorResourceError,
                        OSError,
                    ) as exc:
                        self._error(exc)
                        return
                    _json_response(self, 200, payload)
                    return
                if parsed.path != "/v1/simulations":
                    _json_response(self, 404, {"status": "error", "error": "not found"})
                    return
            try:
                scenario = self._read_json()
                if isinstance(scenario, dict) and "irule_file" in scenario:
                    raise EmulatorInputError(
                        "HTTP API accepts inline irule only; use the CLI for irule_file"
                    )
                payload = run_scenario(scenario, tcl_lsp_root=str(root))
            except (json.JSONDecodeError, EmulatorInputError, EmulatorResourceError, OSError) as exc:
                self._error(exc)
                return
            _json_response(self, 200, payload)

        def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            if len(parts) != 3 or parts[:2] != ["v1", "sessions"]:
                _json_response(self, 404, {"status": "error", "error": "not found"})
                return
            try:
                session_manager.close(parts[2])
            except EmulatorNotFoundError as exc:
                self._error(exc)
                return
            _json_response(
                self,
                200,
                {
                    "status": "ok",
                    "schema_version": 1,
                    "profile": "tmos-17.5",
                    "tmos_version": TMOS_VERSION,
                    "session_id": parts[2],
                    "closed": True,
                },
            )

    return EmulatorHandler


def serve(root: Path, host: str, port: int) -> None:
    if not 1 <= port <= 65535:
        raise EmulatorInputError("port must be between 1 and 65535")
    session_manager = SessionManager(root)
    server = ThreadingHTTPServer((host, port), _http_handler(root, session_manager))
    print(f"testcl emulator listening on http://{host}:{port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        session_manager.close_all()


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
