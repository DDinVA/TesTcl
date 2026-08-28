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
import base64
import binascii
import hashlib
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


TMOS_VERSION = "17.5"
DEFAULT_PROFILES = ["TCP", "HTTP"]
LB_FAILURE_CAUSES = frozenset(
    {"no_member", "unreachable", "queue_limit", "connection_timeout"}
)
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
MAX_HTTP_RETRIES = 8
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


SEMANTIC_MOCK_COMMANDS = {
    "HSL::open",
    "HSL::send",
    "DNS::origin",
    "DNS::question",
    "event",
    "HTTP::passthrough_reason",
    "HTTP::password",
    "HTTP::reject_reason",
    "HTTP::response",
    "HTTP::close",
    "HTTP::retry",
    "HTTP::is_keepalive",
    "HTTP::is_redirect",
    "HTTP::request_num",
    "HTTP::cookie",
    "HTTP::username",
    "IP::addr",
    "IP::version",
    "LB::down",
    "LB::persist",
    "LB::reselect",
    "LB::status",
    "LB::up",
    "class",
    "PROFILE::clientssl",
    "PROFILE::exists",
    "PROFILE::fastL4",
    "PROFILE::fasthttp",
    "PROFILE::http",
    "PROFILE::list",
    "PROFILE::serverssl",
    "PROFILE::tcp",
    "PROFILE::udp",
    "persist",
    "STATS::get",
    "STATS::incr",
    "STATS::set",
    "STATS::setmax",
    "STATS::setmin",
    "table",
    "TCP::collect",
    "TCP::close",
    "TCP::offset",
    "TCP::payload",
    "TCP::release",
    "TCP::respond",
    "active_members",
    "active_nodes",
    "b64decode",
    "b64encode",
    "client_addr",
    "client_port",
    "crc32",
    "decode_uri",
    "domain",
    "findclass",
    "findstr",
    "getfield",
    "llookup",
    "matchclass",
    "md5",
    "members",
    "nodes",
    "peer",
    "clientside",
    "serverside",
    "local_addr",
    "local_port",
    "remote_addr",
    "remote_port",
    "server_addr",
    "server_port",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "substr",
    "URI::basename",
    "URI::compare",
    "URI::decode",
    "URI::encode",
    "URI::encode_component",
    "URI::escape",
    "URI::host",
    "URI::path",
    "URI::port",
    "URI::protocol",
    "URI::query",
}
SEMANTIC_MOCK_PROC_NAMES = {_mock_proc_name(name) for name in SEMANTIC_MOCK_COMMANDS}


def _capability_status(proc_name: str, handwritten: set[str], generated: set[str]) -> str:
    if proc_name in SEMANTIC_MOCK_PROC_NAMES:
        return "semantic-mock"
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
    status_counts = {
        "handwritten-mock": 0,
        "semantic-mock": 0,
        "generated-stub": 0,
        "no-runtime-handler": 0,
    }
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


def _build_conformance(root: Path) -> dict[str, Any]:
    """Report static catalog coverage without pretending stubs are semantics."""
    registry, status_map = _runtime_status_map(root)
    try:
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp event registry: {exc}") from exc

    command_counts = {
        "handwritten-mock": 0,
        "semantic-mock": 0,
        "generated-stub": 0,
        "no-runtime-handler": 0,
    }
    for status in status_map.values():
        command_counts[status] = command_counts.get(status, 0) + 1
    event_names = sorted(NAMESPACE_REGISTRY.all_event_names())
    supported_events = [name for name in event_names if name in PACKET_EVENT_ADAPTERS]
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "source": {
            "name": "tcl-lsp f5-irules registry",
            "commit": os.environ.get("TCL_LSP_COMMIT", "unknown"),
        },
        "commands": {
            "catalog_count": len(status_map),
            "runtime_status_counts": command_counts,
            "runtime_status_meaning": {
                "handwritten-mock": "implemented behavioral mock in the loaded Tcl framework",
                "semantic-mock": "implemented behavioral mock in the TesTcl adapter overlay",
                "generated-stub": "recognized command with generated placeholder behavior",
                "no-runtime-handler": "catalogued command without a matching runtime proc",
            },
        },
        "events": {
            "catalog_count": len(event_names),
            "packet_adapter_count": len(supported_events),
            "packet_adapter_events": [
                {"name": name, "adapter": PACKET_EVENT_ADAPTERS[name]}
                for name in supported_events
            ],
            "unmapped_events": [name for name in event_names if name not in PACKET_EVENT_ADAPTERS],
        },
        "interpretation": (
            "This is static catalog-to-runtime coverage. It is not a claim that "
            "generated stubs reproduce BIG-IP TMM semantics."
        ),
    }


def _runtime_status_map(root: Path) -> tuple[Any, dict[str, str]]:
    """Return the tcl-lsp registry and runtime status for each command."""
    _load_session_class(root)
    try:
        from compiler.registry import REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp command registry: {exc}") from exc
    tcl_dir = root / "tooling" / "irule_test" / "tcl"
    handwritten = _proc_names(tcl_dir / "command_mocks.tcl")
    generated = _proc_names(tcl_dir / "_mock_stubs.tcl")
    status_map: dict[str, str] = {}
    for name in REGISTRY.command_names(dialect="f5-irules"):
        status_map[name] = _capability_status(_mock_proc_name(name), handwritten, generated)
    return REGISTRY, status_map


def _is_f5_runtime_command(name: str, spec: Any) -> bool:
    """Avoid warning on ordinary Tcl control commands in a rule."""
    return "::" in name or bool(getattr(spec, "event_requires", None))


def _analyze_rule_capabilities(
    root: Path,
    source: str,
    profiles: list[str],
) -> dict[str, Any]:
    """Statically map used commands/events to catalog runtime support."""
    try:
        _load_session_class(root)
        from compiler.irules_flow import _find_when_bodies
        from compiler.parsing.command_segmenter import segment_commands
        from compiler.parsing.token_scanning import scan_command_substitutions
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
        from compiler.registry.runtime import body_arg_indices
        from shared.tokens import TokenType

        registry, status_map = _runtime_status_map(root)
        usage: dict[str, dict[str, Any]] = {}
        event_names: set[str] = set()
        visited_scripts: set[tuple[str, str]] = set()

        def visit(script: str, event_name: str) -> None:
            visit_key = (event_name, script)
            if visit_key in visited_scripts:
                return
            visited_scripts.add(visit_key)
            commands = segment_commands(
                script,
                registry_snapshot=registry,
                recovery=False,
            )
            for command in commands:
                name = command.name
                if not name:
                    continue
                entry = usage.setdefault(
                    name,
                    {"name": name, "occurrences": 0, "events": set()},
                )
                entry["occurrences"] += 1
                entry["events"].add(event_name)

                body_indices = body_arg_indices(name, command.args)
                if name == "when" and command.texts:
                    body_indices = [len(command.args) - 1]
                for index in body_indices:
                    text_index = index + 1
                    if 0 <= text_index < len(command.texts):
                        visit(command.texts[text_index], event_name)
                for token in command.all_tokens:
                    if token.type is TokenType.CMD:
                        visit(token.text, event_name)
                    elif token.type is TokenType.STR:
                        for nested in scan_command_substitutions(token.text):
                            visit(nested.text, event_name)

        for event_name, _priority, body, _body_token, _event_token in _find_when_bodies(source):
            event_names.add(event_name)
            visit(body, event_name)

        warnings: list[dict[str, Any]] = []
        command_rows: list[dict[str, Any]] = []
        for name in sorted(usage):
            spec = registry.get_any(name)
            status = status_map.get(name)
            if status is None:
                status = "unknown-command" if spec is None else "no-runtime-handler"
            row = {
                "name": name,
                "occurrences": usage[name]["occurrences"],
                "events": sorted(usage[name]["events"]),
                "runtime_status": status,
            }
            command_rows.append(row)
            if status in {"generated-stub", "no-runtime-handler"} and spec is not None:
                if _is_f5_runtime_command(name, spec):
                    warnings.append(
                        {
                            "code": "runtime-fidelity",
                            "severity": "warning",
                            "command": name,
                            "runtime_status": status,
                            "message": (
                                f"{name} is recognized by the 17.5 catalog but uses a "
                                f"{status.replace('-', ' ')} at runtime"
                            ),
                        }
                    )
            elif status == "unknown-command":
                warnings.append(
                    {
                        "code": "unknown-command",
                        "severity": "warning",
                        "command": name,
                        "message": f"{name} is not present in the pinned 17.5 catalog",
                    }
                )

        attached_profiles = {profile.upper() for profile in profiles}
        for event_name in sorted(event_names):
            props = NAMESPACE_REGISTRY.get_props(event_name)
            required = set(props.implied_profiles) if props is not None else set()
            if required and not required.intersection(attached_profiles):
                warnings.append(
                    {
                        "code": "profile-gated-event",
                        "severity": "warning",
                        "event": event_name,
                        "required_profiles": sorted(required),
                        "message": (
                            f"{event_name} is registered but the attached profiles do not "
                            "include a profile that enables it"
                        ),
                    }
                )
        return {
            "analysis": "static-tcl-lsp",
            "commands": command_rows,
            "events": sorted(event_names),
            "warnings": warnings,
        }
    except Exception as exc:  # pragma: no cover - parser version compatibility guard
        return {
            "analysis": "unavailable",
            "commands": [],
            "events": [],
            "warnings": [
                {
                    "code": "analysis-unavailable",
                    "severity": "warning",
                    "message": f"could not statically analyze rule usage: {exc}",
                }
            ],
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


def _semantic_snapshot(session: Any) -> dict[str, Any]:
    stats_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::stats_snapshot"))
    stats = {
        name: value
        for name, value in zip(stats_parts[::2], stats_parts[1::2])
    }
    hsl_messages: list[dict[str, str]] = []
    for raw_message in _split_tcl_list(session.eval_tcl("::itest::semantic::hsl_snapshot")):
        parts = _split_tcl_list(raw_message)
        if len(parts) >= 2:
            hsl_messages.append({"handle": parts[0], "message": parts[1]})
    lb_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::lb_snapshot"))
    lb_status = {
        target: status
        for target, status in zip(lb_parts[::2], lb_parts[1::2])
    }
    table_entries: list[dict[str, str]] = []
    for raw_entry in _split_tcl_list(session.eval_tcl("::itest::semantic::table_snapshot")):
        parts = _split_tcl_list(raw_entry)
        if len(parts) >= 10:
            table_entries.append(
                {
                    parts[index]: parts[index + 1]
                    for index in range(0, len(parts) - 1, 2)
                }
            )
    return {
        "stats": stats,
        "hsl_messages": hsl_messages,
        "lb_status": lb_status,
        "table": table_entries,
    }


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
    _install_python_digest_helper(session)
    semantic_path = Path(__file__).with_name("semantic-mocks.tcl")
    if not semantic_path.exists():
        raise EmulatorInputError(f"missing adapter semantic mock file: {semantic_path}")
    session.eval_tcl(f"::tmm::_orig_source {_tcl_quote(str(semantic_path))}")


def _install_python_digest_helper(session: Any) -> None:
    """Expose stdlib hashlib to semantic Tcl commands as base64 bytes.

    The pinned tcl-lsp bridge uses an in-process tkinter Tcl interpreter for
    this emulator. Returning base64 avoids embedded-NUL issues while allowing
    the Tcl wrapper to restore the raw digest bytes expected by iRules.
    """
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("binary digest support requires the in-process Tcl backend")

    algorithms = {"md5", "sha1", "sha256", "sha384", "sha512"}

    def digest_callback(*args: str) -> str:
        if len(args) != 2 or args[0] not in algorithms:
            raise ValueError("digest helper requires a supported algorithm and one value")
        raw_value = base64.b64decode(args[1].encode("ascii"), validate=True)
        digest = hashlib.new(args[0], raw_value).digest()
        return base64.b64encode(digest).decode("ascii")

    interpreter.createcommand("::itest::semantic::py_digest", digest_callback)
    # Keep a strong reference on the session for bridge implementations that
    # do not retain Python callbacks independently of tkinter's command table.
    setattr(session, "_testcl_digest_callback", digest_callback)


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
        "lb_failure",
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
    if "lb_failure" in request:
        failure = request["lb_failure"]
        if not isinstance(failure, str) or failure not in LB_FAILURE_CAUSES:
            causes = ", ".join(sorted(LB_FAILURE_CAUSES))
            raise EmulatorInputError(f"lb_failure must be one of: {causes}")
        kwargs["lb_failure"] = failure
    return kwargs


def _lb_failure_snapshot(session: Any) -> dict[str, str]:
    parts = _split_tcl_list(session.eval_tcl("::itest::semantic::lb_failure_snapshot"))
    if len(parts) % 2:
        raise EmulatorInputError("invalid load-balancer failure state")
    snapshot = dict(zip(parts[::2], parts[1::2]))
    if set(snapshot) - {"cause", "fired", "selected"}:
        raise EmulatorInputError("invalid load-balancer failure fields")
    return snapshot


def _http_retry_snapshot(session: Any) -> dict[str, str]:
    parts = _split_tcl_list(session.eval_tcl("::itest::semantic::http_retry_snapshot"))
    if len(parts) % 2:
        raise EmulatorInputError("invalid HTTP retry state")
    snapshot = dict(zip(parts[::2], parts[1::2]))
    if set(snapshot) - {"requested", "request", "reset"}:
        raise EmulatorInputError("invalid HTTP retry fields")
    return snapshot


def _parse_http_retry_request(raw_request: str) -> dict[str, Any]:
    """Parse the bounded HTTP request form accepted by HTTP::retry."""
    if not raw_request:
        return {}
    if raw_request.startswith("/"):
        return {"uri": raw_request}
    lines = raw_request.split("\r\n")
    if len(lines) == 1:
        lines = raw_request.splitlines()
    if not lines:
        raise EmulatorInputError("HTTP::retry request is empty")
    request_line = lines[0].split()
    if len(request_line) < 2:
        raise EmulatorInputError("HTTP::retry request needs a method and URI")
    retry_request: dict[str, Any] = {
        "method": request_line[0],
        "uri": request_line[1],
    }
    header_end = len(lines)
    for index, line in enumerate(lines[1:], start=1):
        if line == "":
            header_end = index
            break
    headers: dict[str, str] = {}
    for line in lines[1:header_end]:
        name, separator, value = line.partition(":")
        if not separator or not name.strip():
            raise EmulatorInputError("HTTP::retry request contains a malformed header")
        headers[name.strip()] = value.lstrip()
    if headers:
        retry_request["headers"] = headers
        for name, value in headers.items():
            if name.lower() == "host":
                retry_request["host"] = value
                break
    if header_end < len(lines) - 1:
        retry_request["body"] = "\r\n".join(lines[header_end + 1:])
    return retry_request


def _validate_request_flags(request: dict[str, Any]) -> None:
    for flag in ("close_before", "close_after", "new_connection"):
        if flag in request and not isinstance(request[flag], bool):
            raise EmulatorInputError(f"request field {flag} must be a boolean")


def _normalise_scenario_config(
    scenario: Any,
    *,
    allow_irule_file: bool,
    allow_requests: bool,
    allow_packets: bool = False,
    require_http: bool,
) -> tuple[str, list[str], dict[str, list[str]], list[tuple[str, dict[str, str], str]]]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")

    allowed_fields = {"tmos_version", "irule", "irule_file", "profiles", "pools", "datagroups"}
    if allow_requests:
        allowed_fields.update(("request", "requests"))
    if allow_packets:
        allowed_fields.add("packets")
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


PACKET_MAX_COUNT = 1000
STREAM_MAX_BYTES = 2 * 1024 * 1024
MAX_PACKET_STREAMS = 128
TCP_SEQUENCE_MODULUS = 2**32
TCP_SEQUENCE_HALF_RANGE = 2**31
PCAP_MAX_BYTES = 16 * 1024 * 1024
PCAP_MAX_PACKET_BYTES = 2 * 1024 * 1024
PACKET_PROTOCOLS = {"tcp", "udp", "tls", "http", "dns", "wire"}
PACKET_DIRECTIONS = {"client_to_server", "server_to_client"}
PACKET_COMMON_FIELDS = {
    "protocol",
    "direction",
    "flags",
    "payload",
    "source",
    "destination",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "timestamp",
    "seq",
    "ack",
}
PACKET_PROTOCOL_FIELDS = {
    "tcp": set(),
    "udp": set(),
    "tls": {
        "type",
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
        "session_id",
    },
    "http": {
        "method",
        "uri",
        "host",
        "headers",
        "body",
        "status",
        "response_headers",
        "response_body",
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
PACKET_EVENT_ADAPTERS = {
    "RULE_INIT": "trace initialization",
    "CLIENT_ACCEPTED": "tcp SYN/connection start",
    "CLIENT_CLOSED": "tcp FIN/RST from client",
    "SERVER_CLOSED": "tcp FIN/RST from server",
    "CLIENT_DATA": "tcp client payload",
    "SERVER_DATA": "tcp server payload",
    "CLIENTSSL_CLIENTHELLO": "TLS client hello",
    "CLIENTSSL_CLIENTCERT": "TLS client certificate",
    "CLIENTSSL_HANDSHAKE": "TLS client handshake",
    "CLIENTSSL_DATA": "TLS client data",
    "SERVERSSL_SERVERHELLO": "TLS server hello",
    "SERVERSSL_SERVERCERT": "TLS server certificate",
    "SERVERSSL_HANDSHAKE": "TLS server handshake",
    "SERVERSSL_DATA": "TLS server data",
    "HTTP_REQUEST": "HTTP request transaction",
    "HTTP_RESPONSE": "HTTP response transaction",
    "DNS_REQUEST": "DNS request packet",
    "DNS_RESPONSE": "DNS response packet",
}


class _TcpStream:
    """Bounded per-direction TCP state using unwrapped sequence coordinates."""

    def __init__(self) -> None:
        self.expected_seq: int | None = None
        self.segments: dict[int, bytes] = {}
        self.buffer = b""

    @property
    def buffered_bytes(self) -> int:
        return len(self.buffer) + sum(len(segment) for segment in self.segments.values())


def _packet_direction(value: Any) -> str:
    direction = _require_string(value, "packet direction").lower()
    aliases = {
        "client": "client_to_server",
        "c2s": "client_to_server",
        "server": "server_to_client",
        "s2c": "server_to_client",
    }
    direction = aliases.get(direction, direction)
    if direction not in PACKET_DIRECTIONS:
        raise EmulatorInputError(
            "packet direction must be client_to_server or server_to_client"
        )
    return direction


def _decode_wire_text(payload: bytes) -> str:
    # Tcl strings cannot contain embedded NUL bytes. Preserve human-readable
    # captures while replacing binary NULs at the wire-to-Tcl boundary.
    return payload.decode("utf-8", errors="replace").replace("\x00", "\ufffd")


def _decode_http_payload(payload: bytes, direction: str) -> dict[str, Any] | None:
    text = payload.decode("iso-8859-1", errors="replace").replace("\x00", "\ufffd")
    separator = text.find("\r\n\r\n")
    separator_length = 4
    if separator < 0:
        separator = text.find("\n\n")
        separator_length = 2
    if separator < 0:
        return None
    header_text = text[:separator]
    body = text[separator + separator_length :]
    lines = header_text.splitlines()
    if not lines:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    if direction == "client_to_server":
        match = re.match(r"^([A-Za-z]+)\s+(\S+)\s+HTTP/", lines[0])
        if match is None:
            return None
        return {
            "protocol": "http",
            "direction": direction,
            "method": match.group(1),
            "uri": match.group(2),
            "headers": headers,
            "body": body,
        }
    match = re.match(r"^HTTP/\S+\s+(\d{3})(?:\s+.*)?$", lines[0])
    if match is None:
        return None
    return {
        "protocol": "http",
        "direction": direction,
        "status": int(match.group(1)),
        "response_headers": headers,
        "response_body": body,
    }


def _decode_tls_payload(payload: bytes, direction: str) -> dict[str, Any] | None:
    if len(payload) < 5 or payload[0] not in {20, 21, 22, 23}:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + record_length:
        return None
    record = payload[5 : 5 + record_length]
    if payload[0] == 23:
        packet_type = "client_data" if direction == "client_to_server" else "server_data"
        return {"protocol": "tls", "direction": direction, "type": packet_type}
    if payload[0] != 22 or len(record) < 4:
        return None
    handshake_type = record[0]
    packet_types = {
        ("client_to_server", 1): "client_hello",
        ("server_to_client", 2): "server_hello",
        ("client_to_server", 11): "client_cert",
        ("server_to_client", 11): "server_cert",
    }
    packet_type = packet_types.get((direction, handshake_type))
    if packet_type is None:
        if handshake_type == 20:
            packet_type = "handshake" if direction == "client_to_server" else "server_handshake"
        else:
            return None
    result: dict[str, Any] = {
        "protocol": "tls",
        "direction": direction,
        "type": packet_type,
    }
    if handshake_type == 1 and len(record) >= 4 + 2 + 32 + 1:
        body = record[4:]
        cursor = 2 + 32
        session_length = body[cursor]
        cursor += 1 + session_length
        if cursor + 2 <= len(body):
            cipher_length = int.from_bytes(body[cursor : cursor + 2], "big")
            cursor += 2 + cipher_length
        if cursor < len(body):
            compression_length = body[cursor]
            cursor += 1 + compression_length
        if cursor + 2 <= len(body):
            extensions_length = int.from_bytes(body[cursor : cursor + 2], "big")
            cursor += 2
            extensions_end = min(cursor + extensions_length, len(body))
            while cursor + 4 <= extensions_end:
                extension_type = int.from_bytes(body[cursor : cursor + 2], "big")
                extension_length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
                cursor += 4
                extension = body[cursor : cursor + extension_length]
                cursor += extension_length
                if extension_type == 0 and len(extension) >= 5:
                    name_length = int.from_bytes(extension[3:5], "big")
                    result["sni"] = _decode_wire_text(extension[5 : 5 + name_length])
                    break
    return result


def _decode_dns_payload(payload: bytes, direction: str, index: int) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    flags = int.from_bytes(payload[2:4], "big")
    qdcount = int.from_bytes(payload[4:6], "big")
    if qdcount < 1:
        return None
    cursor = 12
    labels: list[str] = []
    while cursor < len(payload):
        length = payload[cursor]
        cursor += 1
        if length == 0:
            break
        if length & 0xC0 or cursor + length > len(payload):
            raise EmulatorInputError(f"wire packet {index} has an invalid DNS name")
        labels.append(_decode_wire_text(payload[cursor : cursor + length]))
        cursor += length
    if cursor + 4 > len(payload):
        raise EmulatorInputError(f"wire packet {index} has an incomplete DNS question")
    qtype = int.from_bytes(payload[cursor : cursor + 2], "big")
    qclass = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
    result: dict[str, Any] = {
        "protocol": "dns",
        "direction": "server_to_client" if flags & 0x8000 else direction,
        "qname": ".".join(labels),
        "qtype": {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX"}.get(qtype, str(qtype)),
        "qclass": {1: "IN"}.get(qclass, str(qclass)),
        "id": int.from_bytes(payload[0:2], "big"),
        "rcode": flags & 0x000F,
        "opcode": (flags >> 11) & 0x000F,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080),
        "cd": bool(flags & 0x0010),
        "ad": bool(flags & 0x0020),
    }
    return result


def _decode_wire_packet(raw_packet: dict[str, Any], index: int, direction: str) -> dict[str, Any]:
    unknown = sorted(
        set(raw_packet) - {"protocol", "direction", "raw_hex", "network", "timestamp"}
    )
    if unknown:
        raise EmulatorInputError(
            f"unsupported wire packet {index} field(s): {', '.join(unknown)}"
        )
    network = _require_string(raw_packet.get("network", "ipv4"), f"wire packet {index} network").lower()
    if network != "ipv4":
        raise EmulatorInputError("only raw IPv4 wire packets are currently supported")
    raw_hex = _require_string(raw_packet.get("raw_hex"), f"wire packet {index} raw_hex")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise EmulatorInputError(f"wire packet {index} raw_hex is not valid hexadecimal") from exc
    if len(raw) < 20 or raw[0] >> 4 != 4:
        raise EmulatorInputError(f"wire packet {index} must contain an IPv4 packet")
    header_length = (raw[0] & 0x0F) * 4
    if header_length < 20 or len(raw) < header_length:
        raise EmulatorInputError(f"wire packet {index} has an invalid IPv4 header length")
    total_length = int.from_bytes(raw[2:4], "big")
    if total_length < header_length or total_length > len(raw):
        raise EmulatorInputError(f"wire packet {index} has an invalid IPv4 total length")
    fragment_field = int.from_bytes(raw[6:8], "big")
    if fragment_field & 0x3FFF:
        raise EmulatorInputError(
            f"wire packet {index} is fragmented; IPv4 fragment reassembly is not supported"
        )
    source_address = str(ipaddress.ip_address(raw[12:16]))
    destination_address = str(ipaddress.ip_address(raw[16:20]))
    ip_protocol = raw[9]
    payload = raw[header_length:total_length]
    if ip_protocol == 6:
        if len(payload) < 20:
            raise EmulatorInputError(f"wire packet {index} has an incomplete TCP header")
        tcp_header_length = (payload[12] >> 4) * 4
        if tcp_header_length < 20 or len(payload) < tcp_header_length:
            raise EmulatorInputError(f"wire packet {index} has an invalid TCP header length")
        flags_value = payload[13]
        flag_names = [
            name
            for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"))
            if flags_value & bit
        ]
        tcp_payload = payload[tcp_header_length:]
        packet: dict[str, Any] = {
            "protocol": "tcp",
            "direction": direction,
            "flags": flag_names,
            "seq": int.from_bytes(payload[4:8], "big"),
            "ack": int.from_bytes(payload[8:12], "big"),
            "source": {"address": source_address, "port": int.from_bytes(payload[0:2], "big")},
            "destination": {"address": destination_address, "port": int.from_bytes(payload[2:4], "big")},
        }
        if "timestamp" in raw_packet:
            packet["timestamp"] = raw_packet["timestamp"]
        if tcp_payload:
            packet["payload"] = _decode_wire_text(tcp_payload)
            packet["_wire_payload"] = tcp_payload
        return packet
    if ip_protocol == 17:
        if len(payload) < 8:
            raise EmulatorInputError(f"wire packet {index} has an incomplete UDP header")
        udp_payload = payload[8:]
        packet = {
            "protocol": "udp",
            "direction": direction,
            "source": {"address": source_address, "port": int.from_bytes(payload[0:2], "big")},
            "destination": {"address": destination_address, "port": int.from_bytes(payload[2:4], "big")},
        }
        if "timestamp" in raw_packet:
            packet["timestamp"] = raw_packet["timestamp"]
        if udp_payload:
            packet["payload"] = _decode_wire_text(udp_payload)
            packet["_wire_payload"] = udp_payload
        return packet
    raise EmulatorInputError(
        f"wire packet {index} uses unsupported IPv4 protocol number {ip_protocol}"
    )


def _wire_ipv4_endpoints(raw: bytes, index: int) -> tuple[str, str]:
    if len(raw) < 20 or raw[0] >> 4 != 4:
        raise EmulatorInputError(f"pcap IPv4 packet {index} is incomplete")
    header_length = (raw[0] & 0x0F) * 4
    if header_length < 20 or len(raw) < header_length:
        raise EmulatorInputError(f"pcap IPv4 packet {index} has an invalid header length")
    return str(ipaddress.ip_address(raw[12:16])), str(ipaddress.ip_address(raw[16:20]))


def _extract_pcap_ipv4(frame: bytes, linktype: int, index: int) -> bytes | None:
    if linktype == 101:  # LINKTYPE_RAW
        return frame if len(frame) >= 1 and frame[0] >> 4 == 4 else None
    if linktype != 1:  # LINKTYPE_ETHERNET
        raise EmulatorInputError(
            f"unsupported pcap link-layer type {linktype}; only Ethernet and raw IPv4 are supported"
        )
    if len(frame) < 14:
        return None
    cursor = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < cursor + 4:
            return None
        ether_type = int.from_bytes(frame[cursor + 2 : cursor + 4], "big")
        cursor += 4
    if ether_type != 0x0800:
        return None
    if len(frame) <= cursor or frame[cursor] >> 4 != 4:
        return None
    return frame[cursor:]


def _pcap_format(data: bytes) -> tuple[str, float]:
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    try:
        return formats[magic]
    except KeyError as exc:
        raise EmulatorInputError(
            "unsupported capture format; classic PCAP (not pcapng) is required"
        ) from exc


def _pcap_packets(
    data: bytes,
    *,
    direction: str,
    client_addr: str | None,
    server_addr: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(data, bytes):
        raise EmulatorInputError("pcap data must be bytes")
    if len(data) > PCAP_MAX_BYTES:
        raise EmulatorInputError(f"pcap data exceeds the {PCAP_MAX_BYTES // (1024 * 1024)} MiB limit")
    if len(data) < 24:
        raise EmulatorInputError("pcap global header is incomplete")
    endian, timestamp_scale = _pcap_format(data)
    _magic, major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
        endian + "IHHIIII", data[:24]
    )
    if major != 2 or minor not in {3, 4}:
        raise EmulatorInputError(f"unsupported classic PCAP version {major}.{minor}")
    if snaplen < 1 or snaplen > PCAP_MAX_PACKET_BYTES:
        raise EmulatorInputError("pcap snaplen is outside the supported packet-size limit")
    for field, value in (("pcap client_addr", client_addr), ("pcap server_addr", server_addr)):
        if value is None:
            continue
        address = _require_string(value, field)
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise EmulatorInputError(f"{field} must be an IPv4 address") from exc
        if parsed_address.version != 4:
            raise EmulatorInputError(f"{field} must be an IPv4 address")
        if field.endswith("client_addr"):
            client_addr = str(parsed_address)
        else:
            server_addr = str(parsed_address)
    if direction == "auto":
        if not client_addr or not server_addr:
            raise EmulatorInputError(
                "pcap direction auto requires both client_addr and server_addr"
            )
    else:
        direction = _packet_direction(direction)

    packets: list[dict[str, Any]] = []
    offset = 24
    record_count = 0
    skipped_non_ipv4 = 0
    skipped_unmatched = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise EmulatorInputError(f"pcap record {record_count} header is incomplete")
        ts_sec, ts_fraction, included_length, original_length = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        record_count += 1
        if record_count > PACKET_MAX_COUNT:
            raise EmulatorInputError(f"pcap cannot contain more than {PACKET_MAX_COUNT} records")
        if included_length > snaplen or included_length > PCAP_MAX_PACKET_BYTES:
            raise EmulatorInputError(f"pcap record {record_count - 1} exceeds the packet-size limit")
        if original_length < included_length:
            raise EmulatorInputError(f"pcap record {record_count - 1} has invalid captured length")
        if len(data) - offset < included_length:
            raise EmulatorInputError(f"pcap record {record_count - 1} payload is incomplete")
        frame = data[offset : offset + included_length]
        offset += included_length
        ipv4 = _extract_pcap_ipv4(frame, linktype, record_count - 1)
        if ipv4 is None:
            skipped_non_ipv4 += 1
            continue
        source, destination = _wire_ipv4_endpoints(ipv4, record_count - 1)
        packet_direction = direction
        if direction == "auto":
            if source == client_addr and destination == server_addr:
                packet_direction = "client_to_server"
            elif source == server_addr and destination == client_addr:
                packet_direction = "server_to_client"
            else:
                skipped_unmatched += 1
                continue
        packets.append(
            {
                "protocol": "wire",
                "direction": packet_direction,
                "network": "ipv4",
                "raw_hex": ipv4.hex(),
                "timestamp": ts_sec + ts_fraction / timestamp_scale,
            }
        )
    if not packets:
        raise EmulatorInputError("pcap contained no usable IPv4 packets")
    return packets, {
        "format": "pcap",
        "version": f"{major}.{minor}",
        "linktype": linktype,
        "timestamp_resolution": "nanoseconds" if timestamp_scale == 1_000_000_000.0 else "microseconds",
        "record_count": record_count,
        "ipv4_packet_count": len(packets),
        "skipped_non_ipv4": skipped_non_ipv4,
        "skipped_unmatched": skipped_unmatched,
        "direction": direction,
    }


def _decode_pcap_base64(value: Any) -> bytes:
    encoded = _require_string(value, "pcap_base64")
    maximum_encoded_length = ((PCAP_MAX_BYTES + 2) // 3) * 4
    if len(encoded) > maximum_encoded_length:
        raise EmulatorInputError(
            f"pcap_base64 exceeds the {PCAP_MAX_BYTES // (1024 * 1024)} MiB decoded limit"
        )
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EmulatorInputError("pcap_base64 is not valid base64") from exc
    if len(data) > PCAP_MAX_BYTES:
        raise EmulatorInputError(f"pcap data exceeds the {PCAP_MAX_BYTES // (1024 * 1024)} MiB limit")
    return data


def _packet_endpoint(raw: Any, prefix: str, packet_index: int) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"packet {packet_index} {prefix} must be an object")
    unknown = sorted(set(raw) - {"address", "port"})
    if unknown:
        raise EmulatorInputError(
            f"unsupported packet {prefix} field(s): {', '.join(unknown)}"
        )
    result: dict[str, Any] = {}
    if "address" in raw:
        result["address"] = _require_string(raw["address"], f"packet {prefix} address")
    if "port" in raw:
        port = raw["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise EmulatorInputError(f"packet {prefix} port must be an integer from 0 to 65535")
        result["port"] = port
    return result


def _packet_scalar(value: Any, field: str) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, (list, dict)):
        try:
            return json.dumps(value, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise EmulatorInputError(f"packet field {field} must be JSON-serialisable") from exc
    raise EmulatorInputError(f"packet field {field} must be a scalar or JSON value")


def _normalise_packets(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise EmulatorInputError("packets must be a non-empty array")
    if len(raw) > PACKET_MAX_COUNT:
        raise EmulatorInputError(f"packets cannot contain more than {PACKET_MAX_COUNT} entries")

    packets: list[dict[str, Any]] = []
    for index, packet in enumerate(raw):
        if not isinstance(packet, dict):
            raise EmulatorInputError(f"packet {index} must be an object")
        protocol = _require_string(packet.get("protocol"), f"packet {index} protocol").lower()
        if protocol not in PACKET_PROTOCOLS:
            raise EmulatorInputError(
                f"packet {index} protocol must be one of: {', '.join(sorted(PACKET_PROTOCOLS))}"
            )
        direction = _packet_direction(packet.get("direction", "client_to_server"))
        wire_payload: bytes | None = None
        if protocol == "wire":
            packet = _decode_wire_packet(packet, index, direction)
            protocol = packet["protocol"]
            direction = packet["direction"]
            wire_payload = packet.pop("_wire_payload", None)
        allowed = PACKET_COMMON_FIELDS | PACKET_PROTOCOL_FIELDS[protocol]
        unknown = sorted(set(packet) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"unsupported packet {index} field(s): {', '.join(unknown)}"
            )

        normalised: dict[str, Any] = {
            "protocol": protocol,
            "direction": direction,
            "source": _packet_endpoint(packet.get("source"), "source", index),
            "destination": _packet_endpoint(packet.get("destination"), "destination", index),
        }
        if "timestamp" in packet:
            timestamp = packet["timestamp"]
            if (
                isinstance(timestamp, bool)
                or not isinstance(timestamp, (int, float))
                or not math.isfinite(float(timestamp))
                or timestamp < 0
            ):
                raise EmulatorInputError(
                    f"packet {index} timestamp must be a finite non-negative number"
                )
            normalised["timestamp"] = float(timestamp)
        for field, endpoint_key in (
            ("src_addr", "address"),
            ("src_port", "port"),
            ("dst_addr", "address"),
            ("dst_port", "port"),
        ):
            if field not in packet:
                continue
            if field.endswith("_addr"):
                value = _require_string(packet[field], f"packet {index} {field}")
            else:
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                    raise EmulatorInputError(
                        f"packet {index} {field} must be an integer from 0 to 65535"
                    )
            endpoint = "source" if field.startswith("src_") else "destination"
            if endpoint_key in normalised[endpoint]:
                raise EmulatorInputError(
                    f"packet {index} specifies both {endpoint}.{endpoint_key} and {field}"
                )
            normalised[endpoint][endpoint_key] = value

        if "flags" in packet:
            flags = packet["flags"]
            if not isinstance(flags, list) or not all(isinstance(flag, str) and flag for flag in flags):
                raise EmulatorInputError(f"packet {index} flags must be an array of strings")
            normalised["flags"] = [flag.upper() for flag in flags]
        if "payload" in packet:
            normalised["payload"] = _require_string(packet["payload"], f"packet {index} payload")
        for field in ("seq", "ack"):
            if field not in packet:
                continue
            value = packet[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < TCP_SEQUENCE_MODULUS:
                raise EmulatorInputError(
                    f"packet {index} {field} must be an integer from 0 to {TCP_SEQUENCE_MODULUS - 1}"
                )
            normalised[field] = value

        for field in PACKET_PROTOCOL_FIELDS[protocol]:
            if field not in packet:
                continue
            if field in {"headers", "response_headers"}:
                value = packet[field]
                if not isinstance(value, dict) or not all(
                    isinstance(key, str) and isinstance(item, str) for key, item in value.items()
                ):
                    raise EmulatorInputError(f"packet {index} {field} must be an object of strings")
                normalised[field] = value
            elif field in {"body", "response_body", "method", "uri", "host"}:
                normalised[field] = _require_string(packet[field], f"packet {index} {field}")
            elif field == "type":
                packet_type = _require_string(packet[field], f"packet {index} type").lower()
                if packet_type not in {
                    "client_hello",
                    "client_cert",
                    "handshake",
                    "client_data",
                    "server_hello",
                    "server_cert",
                    "server_handshake",
                    "server_data",
                }:
                    raise EmulatorInputError(f"unsupported TLS packet type: {packet_type}")
                normalised[field] = packet_type
            else:
                normalised[field] = _packet_scalar(packet[field], f"packet {index} {field}")

        if wire_payload is not None:
            normalised["_wire_payload"] = wire_payload

        if protocol == "tls" and "type" not in normalised:
            raise EmulatorInputError(f"packet {index} TLS packets require type")
        if protocol == "tls":
            client_types = {"client_hello", "client_cert", "handshake", "client_data"}
            server_types = {"server_hello", "server_cert", "server_handshake", "server_data"}
            valid_types = client_types if direction == "client_to_server" else server_types
            if normalised["type"] not in valid_types:
                side = "client" if direction == "client_to_server" else "server"
                raise EmulatorInputError(
                    f"packet {index} TLS {side} direction cannot carry {normalised['type']}"
                )
        if protocol == "http" and direction == "client_to_server" and "status" in normalised:
            raise EmulatorInputError(f"packet {index} HTTP requests cannot specify status")
        if protocol == "http" and direction == "server_to_client" and "method" in normalised:
            raise EmulatorInputError(f"packet {index} HTTP responses cannot specify method")
        if protocol == "http" and direction == "server_to_client" and "status" in normalised:
            try:
                status = int(normalised["status"])
            except (TypeError, ValueError) as exc:
                raise EmulatorInputError(f"packet {index} HTTP status must be an integer") from exc
            if not 100 <= status <= 999:
                raise EmulatorInputError(f"packet {index} HTTP status must be between 100 and 999")
        packets.append(normalised)
    return packets


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
    semantic = _semantic_snapshot(session)
    lb_failure = _lb_failure_snapshot(session)
    http_retry = _http_retry_snapshot(session)
    http_close_requested = session.eval_tcl(
        "set ::itest::semantic::http_close_requested"
    )
    lb_state = session.get_state("lb")
    connection_state = session.get_state("connection")
    response_status = int(response_state.get("status", "200"))
    response_reason = HTTP_REASON_PHRASES.get(
        response_status, response_state.get("reason", "")
    )
    result = {
        "pool": lb_state.get("pool", ""),
        "node": lb_state.get("node_addr", ""),
        "response_committed": str(committed) == "1",
        "connection_state": connection_state.get("state", ""),
        "events_fired": fired_events,
        "decisions": [entry if not isinstance(entry, tuple) else list(entry) for entry in decisions],
        "logs": [entry if not isinstance(entry, tuple) else list(entry) for entry in logs],
        "semantic": semantic,
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
    if lb_failure.get("cause", ""):
        result["lb_failure"] = {
            "cause": lb_failure["cause"],
            "fired": lb_failure.get("fired", "0") == "1",
            "selected": lb_failure.get("selected", "0") == "1",
        }
    if http_retry.get("requested", "0") == "1":
        result["http_retry"] = {
            "request": http_retry.get("request", ""),
            "reset": http_retry.get("reset", "0") == "1",
        }
    if str(http_close_requested) == "1":
        result["http_close"] = True
    return result


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
        allow_packets: bool = False,
        backend: str = "inprocess",
    ) -> None:
        source, profiles, pools, datagroups = _normalise_scenario_config(
            scenario,
            allow_irule_file=allow_irule_file,
            allow_requests=allow_requests,
            allow_packets=allow_packets,
            require_http=False,
        )
        self._root = root
        self._backend = backend
        self._source = source
        self._profiles = profiles
        self._pools = pools
        self._datagroups = datagroups
        self._fidelity = _analyze_rule_capabilities(root, source, profiles)
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
        self._connection_request_number = 0
        self._connection_open = False
        self._server_connection_open = False
        self._tcp_buffers = {"client": "", "server": ""}
        self._packet_streams: dict[tuple[Any, ...], _TcpStream] = {}
        self._thread.start()
        self._started.wait()
        if self._startup_error is not None:
            error = self._startup_error
            self.close()
            raise EmulatorInputError(f"could not start emulator session: {error}") from error

    @property
    def registered_events(self) -> list[str]:
        return list(self._registered_events)

    @property
    def fidelity(self) -> dict[str, Any]:
        return self._fidelity

    def _worker_main(self) -> None:
        session_class: Any = None
        try:
            session_class = _load_session_class(self._root)
            backend_session = session_class(
                profiles=self._profiles,
                tmos_version=TMOS_VERSION,
                backend=self._backend,
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
            self._connection_request_number = 0
        if not self._connection_open:
            self._connection_request_number = 0
        request_number = self._connection_request_number + 1
        session.eval_tcl(
            f"set ::itest::semantic::http_request_number {request_number}"
        )
        kwargs = _request_kwargs(request)
        lb_failure = kwargs.pop("lb_failure", "")
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        original_kwargs = dict(kwargs)
        retry_count = 0
        retry_exhausted = False
        http_close_requested = False
        decision_history: list[Any] = []
        log_history: list[Any] = []
        result: dict[str, Any]
        try:
            while True:
                attempt_failure = lb_failure if retry_count == 0 else ""
                session.eval_tcl(
                    f"::itest::semantic::prepare_lb_failure {_tcl_quote(attempt_failure)}"
                )
                session.eval_tcl("::itest::semantic::prepare_http_retry")
                session.eval_tcl("::itest::semantic::prepare_http_close")
                session.eval_tcl("set ::itest::semantic::automatic_http_flow 1")
                try:
                    use_existing_connection = self._connection_open and (
                        retry_count > 0 or not request.get("new_connection")
                    )
                    if use_existing_connection:
                        result = _run_request_with_state(
                            session, "run_next_request", kwargs
                        )
                    else:
                        result = _run_request_with_state(
                            session, "run_http_request", kwargs
                        )
                finally:
                    session.eval_tcl(
                        "unset -nocomplain ::itest::semantic::automatic_http_flow"
                    )

                decision_history.extend(result.get("decisions", []))
                log_history.extend(result.get("logs", []))
                retry = result.pop("http_retry", None)
                http_close = bool(result.pop("http_close", False))
                self._connection_open = True
                if not retry:
                    http_close_requested = http_close
                    break
                if retry_count >= MAX_HTTP_RETRIES:
                    retry_exhausted = True
                    break
                retry_count += 1
                retry_kwargs = _parse_http_retry_request(retry["request"])
                for field in (
                    "response_status",
                    "response_headers",
                    "response_body",
                ):
                    if field in original_kwargs:
                        retry_kwargs.setdefault(field, original_kwargs[field])
                kwargs = retry_kwargs
        finally:
            session.eval_tcl(
                "unset -nocomplain ::itest::semantic::automatic_http_flow"
            )
            session.eval_tcl("::itest::semantic::clear_lb_failure")
            session.eval_tcl("::itest::semantic::prepare_http_retry")
            session.eval_tcl("::itest::semantic::prepare_http_close")
        if http_close_requested:
            events_before_close = _split_tcl_list(
                session.eval_tcl("::itest::get_fired_events")
            )
            decisions_before_close = len(session.get_decisions())
            logs_before_close = len(session.get_logs())
            connection_active = session.eval_tcl("set ::orch::_connection_active")
            if str(connection_active) == "1":
                session.fire_event("CLIENT_CLOSED")
            events_after_close = _split_tcl_list(
                session.eval_tcl("::itest::get_fired_events")
            )
            result["events_fired"].extend(events_after_close[len(events_before_close):])
            decision_history.extend(session.get_decisions()[decisions_before_close:])
            log_history.extend(session.get_logs()[logs_before_close:])
            session.eval_tcl("set ::orch::_connection_active 0")
            session.eval_tcl("::state::reset_connection_state")
            self._connection_open = False
            self._connection_request_number = 0
        result["decisions"] = decision_history
        result["logs"] = log_history
        result["events_fired"] = result["events_fired"][fired_before:]
        self._request_count += 1
        self._connection_request_number = request_number
        if retry_count:
            result["retry"] = {
                "attempts": retry_count,
                "exhausted": retry_exhausted,
            }
        if request.get("close_after"):
            session.close_connection()
            self._connection_open = False
            self._connection_request_number = 0
        return result

    def run_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._call(lambda session: self._run_request_on_worker(session, request))

    def _fire_event_on_worker(
        self,
        session: Any,
        event_name: str,
        state: dict[str, dict[str, str]],
    ) -> dict[str, Any]:
        session.eval_tcl("::itest::semantic::tcp_clear_event_state")
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
        result = {
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
        emissions = self._tcp_emissions(session)
        if emissions:
            result["emissions"] = emissions
        return result

    def fire_event(self, event: Any, state: Any = None) -> dict[str, Any]:
        event_name, normalised_state = _normalise_event(event, state)
        if event_name not in self._event_profiles:
            raise EmulatorInputError(f"unknown iRule event: {event_name}")
        return self._call(
            lambda session: self._fire_event_on_worker(session, event_name, normalised_state)
        )

    @staticmethod
    def _packet_connection_state(packet: dict[str, Any]) -> dict[str, str]:
        connection: dict[str, str] = {}
        source = packet["source"]
        destination = packet["destination"]
        direction = packet["direction"]
        if direction == "client_to_server":
            source_prefix, destination_prefix = "client", "local"
        else:
            source_prefix, destination_prefix = "server", "remote"
        if "address" in source:
            connection[f"{source_prefix}_addr"] = str(source["address"])
        if "port" in source:
            connection[f"{source_prefix}_port"] = str(source["port"])
        if "address" in destination:
            connection[f"{destination_prefix}_addr"] = str(destination["address"])
        if "port" in destination:
            connection[f"{destination_prefix}_port"] = str(destination["port"])
        protocol = packet["protocol"]
        if protocol in {"tcp", "tls", "http"}:
            connection.update({"protocol": "6", "transport": "tcp"})
        elif protocol in {"udp", "dns"}:
            connection.update({"protocol": "17", "transport": "udp"})
        if "payload" in packet:
            payload_key = "client_payload" if direction == "client_to_server" else "server_payload"
            connection[payload_key] = packet["payload"]
        return connection

    @staticmethod
    def _packet_event_state(packet: dict[str, Any]) -> dict[str, dict[str, str]]:
        state: dict[str, dict[str, str]] = {}
        connection = EmulatorSession._packet_connection_state(packet)
        if connection:
            state["connection"] = connection
        protocol = packet["protocol"]
        direction = packet["direction"]
        if protocol == "tls":
            layer = "tls_client" if direction == "client_to_server" else "tls_server"
            tls_state: dict[str, str] = {}
            for field in (
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
                "session_id",
            ):
                if field in packet:
                    tls_state[field] = packet[field]
            if packet.get("type") in {"handshake", "server_handshake"}:
                tls_state["handshake_done"] = "1"
            if tls_state:
                state[layer] = tls_state
        elif protocol == "dns":
            dns_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["dns"]:
                if field in packet:
                    dns_state[field] = _packet_scalar(packet[field], field)
            if dns_state:
                state["dns"] = dns_state
        return state

    @staticmethod
    def _packet_tls_event(packet: dict[str, Any]) -> str:
        client_events = {
            "client_hello": "CLIENTSSL_CLIENTHELLO",
            "client_cert": "CLIENTSSL_CLIENTCERT",
            "handshake": "CLIENTSSL_HANDSHAKE",
            "client_data": "CLIENTSSL_DATA",
        }
        server_events = {
            "server_hello": "SERVERSSL_SERVERHELLO",
            "server_cert": "SERVERSSL_SERVERCERT",
            "server_handshake": "SERVERSSL_HANDSHAKE",
            "server_data": "SERVERSSL_DATA",
        }
        events = client_events if packet["direction"] == "client_to_server" else server_events
        return events[packet["type"]]

    @staticmethod
    def _tcp_emissions(session: Any) -> list[dict[str, Any]]:
        emissions: list[dict[str, Any]] = []
        raw_emissions = _split_tcl_list(
            session.eval_tcl("::itest::semantic::tcp_emission_snapshot")
        )
        for raw_emission in raw_emissions:
            parts = _split_tcl_list(raw_emission)
            if len(parts) not in {4, 8}:
                raise EmulatorInputError("invalid TCP emission state")
            values = {
                parts[index]: parts[index + 1]
                for index in range(0, len(parts), 2)
            }
            side = values.get("side")
            if side not in {"client", "server"}:
                raise EmulatorInputError("invalid TCP emission side")
            direction = "server_to_client" if side == "client" else "client_to_server"
            if values.get("kind") == "fin":
                emissions.append(
                    {
                        "protocol": "tcp",
                        "side": side,
                        "direction": direction,
                        "control": "FIN",
                    }
                )
                continue
            if values.get("kind") != "data":
                raise EmulatorInputError("invalid TCP emission kind")
            try:
                byte_length = int(values["byte_length"])
            except (KeyError, TypeError, ValueError):
                raise EmulatorInputError("invalid TCP response byte length") from None
            emissions.append({
                "protocol": "tcp",
                "side": side,
                "direction": direction,
                "payload": values.get("payload", ""),
                "byte_length": byte_length,
            })
        return emissions

    def _configure_packet_connection(self, session: Any, packet: dict[str, Any]) -> None:
        """Make packet endpoints visible to the upstream HTTP orchestrator."""
        if packet["protocol"] not in {"tcp", "tls", "http"}:
            return
        source = packet["source"]
        destination = packet["destination"]
        values: dict[str, Any] = {}
        if packet["direction"] == "client_to_server":
            if "address" in source:
                values["client_addr"] = source["address"]
            if "port" in source:
                values["client_port"] = source["port"]
            if "address" in destination:
                values["local_addr"] = destination["address"]
            if "port" in destination:
                values["local_port"] = destination["port"]
        for key, value in values.items():
            session.eval_tcl(f"set ::orch::config({key}) {_tcl_quote(str(value))}")

    def _activate_packet_connection(
        self, session: Any, packet: dict[str, Any], events: list[dict[str, Any]]
    ) -> None:
        if self._connection_open or packet["protocol"] not in {"tcp", "tls", "http"}:
            return
        self._configure_packet_connection(session, packet)
        events.append(self._fire_event_on_worker(session, "RULE_INIT", {}))
        events.append(
            self._fire_event_on_worker(
                session, "CLIENT_ACCEPTED", {"connection": self._packet_connection_state(packet)}
            )
        )
        # Direct packet events bypass ::orch::run_http_request, so mark the
        # orchestrator connection active before a later HTTP packet arrives.
        session.eval_tcl("set ::orch::_connection_active 1")
        session.eval_tcl("set ::orch::_init_done 1")
        self._connection_open = True

    def _close_packet_connection(self, session: Any) -> None:
        session.eval_tcl("set ::orch::_connection_active 0")
        session.eval_tcl("::state::reset_connection_state")
        self._packet_streams.clear()
        self._tcp_buffers = {"client": "", "server": ""}
        self._connection_open = False
        self._server_connection_open = False

    @staticmethod
    def _packet_stream_key(packet: dict[str, Any]) -> tuple[Any, ...]:
        source = packet["source"]
        destination = packet["destination"]
        return (
            packet["direction"],
            source.get("address", ""),
            source.get("port", 0),
            destination.get("address", ""),
            destination.get("port", 0),
        )

    @staticmethod
    def _unwrap_tcp_sequence(sequence: int, reference: int) -> int:
        """Map a 32-bit wire sequence number near an unwrapped reference."""
        delta = (sequence - (reference % TCP_SEQUENCE_MODULUS)) % TCP_SEQUENCE_MODULUS
        if delta >= TCP_SEQUENCE_HALF_RANGE:
            delta -= TCP_SEQUENCE_MODULUS
        return reference + delta

    def _tcp_stream(self, key: tuple[Any, ...]) -> _TcpStream:
        stream = self._packet_streams.get(key)
        if stream is not None:
            return stream
        if len(self._packet_streams) >= MAX_PACKET_STREAMS:
            raise EmulatorInputError(
                f"packet stream table exceeds the {MAX_PACKET_STREAMS} stream limit"
            )
        stream = _TcpStream()
        self._packet_streams[key] = stream
        return stream

    @staticmethod
    def _tcp_add_segment(stream: _TcpStream, start: int, payload: bytes) -> int:
        """Add only previously unseen bytes, preserving the first copy received."""
        if not payload:
            return 0
        end = start + len(payload)
        uncovered: list[tuple[int, int]] = []
        cursor = start
        for existing_start, existing_payload in sorted(stream.segments.items()):
            existing_end = existing_start + len(existing_payload)
            if existing_end <= cursor:
                continue
            if existing_start >= end:
                break
            if existing_start > cursor:
                uncovered.append((cursor, min(existing_start, end)))
            cursor = max(cursor, existing_end)
            if cursor >= end:
                break
        if cursor < end:
            uncovered.append((cursor, end))
        added = 0
        for piece_start, piece_end in uncovered:
            offset = piece_start - start
            piece = payload[offset : offset + piece_end - piece_start]
            stream.segments[piece_start] = piece
            added += len(piece)
        return added

    @staticmethod
    def _tcp_drain(stream: _TcpStream) -> bytes:
        """Move every segment contiguous with expected_seq into the message buffer."""
        if stream.expected_seq is None:
            return stream.buffer
        while stream.segments:
            candidate: tuple[int, bytes] | None = None
            for start, payload in sorted(stream.segments.items()):
                if start <= stream.expected_seq < start + len(payload):
                    candidate = (start, payload)
                    break
                if start > stream.expected_seq:
                    break
            if candidate is None:
                break
            start, payload = candidate
            del stream.segments[start]
            offset = stream.expected_seq - start
            stream.buffer += payload[offset:]
            stream.expected_seq += len(payload) - offset
        return stream.buffer

    @staticmethod
    def _looks_like_http_prefix(payload: bytes) -> bool:
        if payload.startswith(b"HTTP/"):
            return True
        methods = (b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE")
        return any(method.startswith(payload) or payload.startswith(method + b" ") for method in methods)

    def _reassemble_packet(
        self, packet: dict[str, Any], packet_index: int
    ) -> tuple[dict[str, Any] | None, int]:
        """Join application payloads until a complete HTTP/TLS message is visible.

        Raw TCP packets carry sequence numbers, so gaps are held, overlaps are
        de-duplicated, and retransmissions do not fire application events twice.
        Structured packets without sequence numbers retain the original append-
        in-arrival-order behavior.
        """
        if packet["protocol"] == "udp" and packet.get("_wire_payload"):
            decoded_dns = _decode_dns_payload(
                packet["_wire_payload"], packet["direction"], packet_index
            )
            if decoded_dns is not None:
                merged = dict(packet)
                merged.update(decoded_dns)
                merged.pop("_wire_payload", None)
                return merged, 0
            return packet, 0
        if packet["protocol"] != "tcp":
            return packet, 0
        raw_payload = packet.get("_wire_payload")
        if raw_payload is None and "payload" in packet:
            raw_payload = packet["payload"].encode("utf-8")
        sequence = packet.get("seq")
        flags = set(packet.get("flags", []))
        key = self._packet_stream_key(packet)
        if sequence is not None and "SYN" in flags:
            stream = self._tcp_stream(key)
            stream.expected_seq = sequence + 1
            stream.segments.clear()
            stream.buffer = b""
        if not raw_payload:
            return packet, 0

        stream = self._tcp_stream(key)
        if sequence is None:
            stream.buffer += raw_payload
            combined = stream.buffer
            has_gap = False
        else:
            if stream.expected_seq is None:
                stream.expected_seq = sequence
            payload_sequence = sequence + 1 if "SYN" in flags else sequence
            absolute_sequence = self._unwrap_tcp_sequence(
                payload_sequence, stream.expected_seq
            )
            if absolute_sequence < stream.expected_seq:
                trim = stream.expected_seq - absolute_sequence
                if trim >= len(raw_payload):
                    retransmission = dict(packet)
                    retransmission["_retransmission"] = True
                    return retransmission, 0
                raw_payload = raw_payload[trim:]
                absolute_sequence = stream.expected_seq
            added = self._tcp_add_segment(stream, absolute_sequence, raw_payload)
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            if added == 0:
                retransmission = dict(packet)
                retransmission["_retransmission"] = True
                return retransmission, 0
            combined = self._tcp_drain(stream)
            has_gap = bool(stream.segments)

        if not combined and has_gap:
            return None, stream.buffered_bytes
        looks_like_tls = bool(combined) and combined[0] in {20, 21, 22, 23}
        looks_like_http = self._looks_like_http_prefix(combined)
        if looks_like_tls:
            decoded = _decode_tls_payload(combined, packet["direction"])
            if decoded is not None:
                stream.buffer = b""
                stream.segments.clear()
                merged = dict(packet)
                merged.update(decoded)
                merged.pop("_wire_payload", None)
                return merged, len(combined)
        elif looks_like_http:
            decoded = _decode_http_payload(combined, packet["direction"])
            if decoded is not None:
                stream.buffer = b""
                stream.segments.clear()
                merged = dict(packet)
                merged.update(decoded)
                merged.pop("_wire_payload", None)
                return merged, len(combined)
        if looks_like_tls or looks_like_http or has_gap:
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            return None, stream.buffered_bytes
        stream.buffer = b""
        stream.segments.clear()
        return packet, len(combined)

    def _run_packet_trace_on_worker(
        self, session: Any, packets: list[dict[str, Any]]
    ) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []
        http_results: list[dict[str, Any]] = []
        pending_http: tuple[dict[str, Any], int] | None = None

        def finish_http(response: dict[str, Any] | None = None, at_index: int | None = None) -> None:
            nonlocal pending_http
            if pending_http is None:
                return
            request, trace_index = pending_http
            if response:
                request.update(response)
            result = self._run_request_on_worker(session, request)
            trace[trace_index]["http_result"] = result
            trace[trace_index]["pending"] = False
            if at_index is not None:
                trace[trace_index]["completed_at"] = at_index
            http_results.append(result)
            pending_http = None

        for index, packet in enumerate(packets):
            original_packet = packet
            packet, buffered_bytes = self._reassemble_packet(packet, index)
            if packet is None:
                buffered_entry: dict[str, Any] = {
                    "index": index,
                    "protocol": original_packet["protocol"],
                    "direction": original_packet["direction"],
                    "events": [],
                    "buffered": True,
                    "buffered_bytes": buffered_bytes,
                }
                for field in (
                    "source",
                    "destination",
                    "flags",
                    "timestamp",
                ):
                    if field in original_packet:
                        buffered_entry[field] = original_packet[field]
                trace.append(buffered_entry)
                continue
            entry: dict[str, Any] = {
                "index": index,
                "protocol": packet["protocol"],
                "direction": packet["direction"],
                "events": [],
            }
            for field in (
                "source",
                "destination",
                "flags",
                "type",
                "method",
                "uri",
                "status",
                "sni",
                "qname",
                "qtype",
                "timestamp",
                "seq",
                "ack",
            ):
                if field in packet:
                    entry[field] = packet[field]
            trace.append(entry)
            retransmission = bool(packet.pop("_retransmission", False))
            if retransmission:
                entry["ignored"] = "tcp retransmission"
                packet.pop("payload", None)
                packet.pop("_wire_payload", None)
            protocol = packet["protocol"]
            direction = packet["direction"]
            if protocol == "http":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "client_to_server":
                    finish_http()
                    request: dict[str, Any] = {
                        "method": packet.get("method", "GET"),
                        "uri": packet.get("uri", "/"),
                    }
                    for field in ("host", "headers", "body"):
                        if field in packet:
                            request[field] = packet[field]
                    if "payload" in packet and "body" not in request:
                        request["body"] = packet["payload"]
                    pending_http = (request, index)
                    entry["pending"] = True
                else:
                    if pending_http is None:
                        entry["ignored"] = "HTTP response has no pending HTTP request"
                    else:
                        response_headers = packet.get("response_headers", packet.get("headers", {}))
                        response_body = packet.get("response_body", packet.get("payload", ""))
                        finish_http(
                            {
                                "response_status": int(packet.get("status", 200)),
                                "response_headers": response_headers,
                                "response_body": response_body,
                            },
                            index,
                        )
                continue

            if protocol in {"tcp", "tls"}:
                if protocol == "tcp":
                    flags = set(packet.get("flags", []))
                    if "SYN" in flags and "ACK" not in flags and self._connection_open:
                        finish_http(at_index=index)
                        entry["events"].append(
                            self._fire_event_on_worker(
                                session,
                                "CLIENT_CLOSED",
                                {"connection": self._packet_connection_state(packet)},
                            )
                        )
                        self._close_packet_connection(session)
                self._activate_packet_connection(session, packet, entry["events"])
                if (
                    direction == "server_to_client"
                    and self._connection_open
                    and not self._server_connection_open
                ):
                    self._configure_packet_connection(session, packet)
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "SERVER_CONNECTED",
                            {"connection": self._packet_connection_state(packet)},
                        )
                    )
                    self._server_connection_open = True
            elif protocol == "dns":
                event_name = "DNS_REQUEST" if direction == "client_to_server" else "DNS_RESPONSE"
                entry["events"].append(
                    self._fire_event_on_worker(session, event_name, self._packet_event_state(packet))
                )
                continue
            else:  # Generic UDP has no single catalogued iRule data event.
                entry["ignored"] = "generic UDP packet has no protocol-specific event adapter"
                continue

            if protocol == "tls":
                entry["events"].append(
                    self._fire_event_on_worker(
                        session, self._packet_tls_event(packet), self._packet_event_state(packet)
                    )
                )
            else:  # TCP
                flags = set(packet.get("flags", []))
                if packet.get("payload"):
                    side = "client" if direction == "client_to_server" else "server"
                    collection = _split_tcl_list(
                        session.eval_tcl(f"::itest::semantic::tcp_collection_request {side}")
                    )
                    if len(collection) != 6:
                        entry["ignored"] = "tcp payload not collected"
                    else:
                        try:
                            collection_values = {
                                collection[index]: int(collection[index + 1])
                                for index in range(0, len(collection), 2)
                            }
                        except (TypeError, ValueError):
                            raise EmulatorInputError("invalid TCP collection state") from None
                        self._tcp_buffers[side] += packet["payload"]
                        skip = collection_values.get("skip", 0)
                        length = collection_values.get("length", 0)
                        every_packet = collection_values.get("every_packet", 0) == 1
                        required = skip + length
                        if len(self._tcp_buffers[side]) < required:
                            entry["buffered"] = True
                            entry["buffered_bytes"] = len(self._tcp_buffers[side])
                        else:
                            event_start = skip
                            # The no-argument form has no fixed length: the
                            # current packet buffer is the complete event
                            # payload and is consumed before the next packet.
                            event_end = event_start + length if length else len(self._tcp_buffers[side])
                            event_payload = self._tcp_buffers[side][event_start:event_end]
                            remainder = self._tcp_buffers[side][event_end:]
                            event_packet = dict(packet)
                            event_packet["payload"] = event_payload
                            event_name = (
                                "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                            )
                            # F5 collection is consumed when the data event is
                            # released. Clear it before dispatch so a rule can
                            # explicitly re-arm TCP::collect from the event.
                            if not every_packet:
                                session.eval_tcl(
                                    f"::itest::semantic::tcp_clear_collection {side}"
                                )
                            event_result = self._fire_event_on_worker(
                                session, event_name, self._packet_event_state(event_packet)
                            )
                            entry["events"].append(event_result)
                            connection_state = event_result.get("state", {}).get("connection", {})
                            released = session.eval_tcl(
                                "::itest::semantic::tcp_event_released"
                            ) == "1"
                            retained = (
                                connection_state.get(f"{side}_payload", "")
                                if released
                                else ""
                            )
                            self._tcp_buffers[side] = retained + remainder
                if flags.intersection({"FIN", "RST"}):
                    finish_http(at_index=index)
                    event_name = "CLIENT_CLOSED" if direction == "client_to_server" else "SERVER_CLOSED"
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session, event_name, self._packet_event_state(packet)
                        )
                    )
                    self._close_packet_connection(session)

        finish_http()
        emitted = []
        for packet_entry in trace:
            for event in packet_entry.get("events", []):
                for emission in event.get("emissions", []):
                    emitted.append(
                        {
                            **emission,
                            "packet_index": packet_entry["index"],
                            "event": event["event"],
                        }
                    )
        return {
            "status": "ok",
            "schema_version": 1,
            "profile": "tmos-17.5",
            "tmos_version": TMOS_VERSION,
            "packets_processed": len(packets),
            "trace": trace,
            "emitted": emitted,
            "results": http_results,
        }

    def run_packet_trace(self, packets: Any) -> dict[str, Any]:
        normalised = _normalise_packets(packets)
        return self._call(lambda session: self._run_packet_trace_on_worker(session, normalised))

    def metadata(self, session_id: str) -> dict[str, Any]:
        def read_metadata(session: Any) -> dict[str, Any]:
            return {
                "status": "ok",
                "schema_version": 1,
                "profile": "tmos-17.5",
                "tmos_version": TMOS_VERSION,
                "session_id": session_id,
                "registered_events": self.registered_events,
                "fidelity": self.fidelity,
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
        backend: str = "inprocess",
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        self._root = root
        self._backend = backend
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
                backend=self._backend,
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


MCP_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MCP_MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MCP_SERVER_INFO = {
    "name": "testcl-irule-emulator",
    "title": "BIG-IP 17.5 iRule emulator",
    "version": "0.1",
}


class McpProtocolError(ValueError):
    """A JSON-RPC/MCP request error that must not become a tool result."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


def _mcp_object_schema(
    properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


class McpProtocolServer:
    """Small stdio MCP adapter over the emulator's existing service contract."""

    def __init__(self, root: Path, manager: SessionManager | None = None) -> None:
        self._root = root
        self._manager = manager if manager is not None else SessionManager(root)
        self._owns_manager = manager is None
        self._initialized = False
        self._ready = False
        self._protocol_version: str | None = None

    @property
    def tools(self) -> list[dict[str, Any]]:
        scenario_schema = {
            "type": "object",
            "description": "An inline tmos-17.5 scenario accepted by the emulator.",
        }
        return [
            {
                "name": "irule_simulate",
                "title": "Simulate an iRule",
                "description": "Run one bounded BIG-IP 17.5 iRule scenario and return protocol state, decisions, logs, and fidelity warnings.",
                "inputSchema": _mcp_object_schema(
                    {"scenario": scenario_schema}, ["scenario"]
                ),
            },
            {
                "name": "irule_pcap_replay",
                "title": "Replay a PCAP capture",
                "description": "Replay a bounded classic PCAP capture through the BIG-IP 17.5 packet and Tcl event adapters.",
                "inputSchema": _mcp_object_schema(
                    {
                        "scenario": scenario_schema,
                        "pcap_base64": {"type": "string", "minLength": 1},
                        "direction": {
                            "type": "string",
                            "enum": ["client_to_server", "server_to_client", "auto"],
                            "default": "client_to_server",
                        },
                        "client_addr": {"type": "string"},
                        "server_addr": {"type": "string"},
                    },
                    ["scenario", "pcap_base64"],
                ),
            },
            {
                "name": "irule_capabilities",
                "title": "List iRule capabilities",
                "description": "Return a bounded chunk of the complete pinned BIG-IP 17.5 command, event, and profile catalog.",
                "inputSchema": _mcp_object_schema(
                    {
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    }
                ),
            },
            {
                "name": "irule_conformance",
                "title": "Report catalog conformance",
                "description": "Report static 17.5 catalog coverage for runtime command handlers and packet-to-event adapters.",
                "inputSchema": _mcp_object_schema({}),
            },
            {
                "name": "irule_session_create",
                "title": "Create an iRule session",
                "description": "Create a persistent connection-aware emulator session for repeated requests or protocol events.",
                "inputSchema": _mcp_object_schema(
                    {"scenario": scenario_schema}, ["scenario"]
                ),
            },
            {
                "name": "irule_session_inspect",
                "title": "Inspect an iRule session",
                "description": "Return session lifecycle metadata, registered events, and static fidelity analysis.",
                "inputSchema": _mcp_object_schema(
                    {"session_id": {"type": "string", "minLength": 1}}, ["session_id"]
                ),
            },
            {
                "name": "irule_session_request",
                "title": "Send a session request",
                "description": "Run one HTTP request on a persistent emulator session while preserving connection state.",
                "inputSchema": _mcp_object_schema(
                    {
                        "session_id": {"type": "string", "minLength": 1},
                        "request": {"type": "object"},
                    },
                    ["session_id", "request"],
                ),
            },
            {
                "name": "irule_session_trace",
                "title": "Replay a packet trace",
                "description": "Replay a bounded structured TCP, TLS, HTTP, UDP, or DNS packet trace on a persistent emulator session.",
                "inputSchema": _mcp_object_schema(
                    {
                        "session_id": {"type": "string", "minLength": 1},
                        "packets": {"type": "array", "minItems": 1, "maxItems": PACKET_MAX_COUNT},
                    },
                    ["session_id", "packets"],
                ),
            },
            {
                "name": "irule_session_event",
                "title": "Fire an iRule event",
                "description": "Inject a catalogued BIG-IP 17.5 event with structured connection, TLS, or DNS state.",
                "inputSchema": _mcp_object_schema(
                    {
                        "session_id": {"type": "string", "minLength": 1},
                        "event": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
                        "state": {"type": "object"},
                    },
                    ["session_id", "event"],
                ),
            },
            {
                "name": "irule_session_close",
                "title": "Close an iRule session",
                "description": "Close a persistent emulator session and release its Tcl interpreter.",
                "inputSchema": _mcp_object_schema(
                    {"session_id": {"type": "string", "minLength": 1}}, ["session_id"]
                ),
            },
        ]

    @staticmethod
    def _error_response(request_id: Any, error: McpProtocolError) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": error.code, "message": str(error)},
        }
        if error.data is not None:
            payload["error"]["data"] = error.data
        return payload

    @staticmethod
    def _require_args(params: Any) -> dict[str, Any]:
        if params is None:
            return {}
        if not isinstance(params, dict):
            raise McpProtocolError(-32602, "request params must be an object")
        return params

    @staticmethod
    def _tool_error(error: Exception) -> dict[str, Any]:
        payload = {"status": "error", "error": str(error)}
        return {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "structuredContent": payload,
            "isError": True,
        }

    @staticmethod
    def _tool_success(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "structuredContent": payload,
            "isError": False,
        }

    def _call_tool(self, name: Any, arguments: Any) -> dict[str, Any]:
        if not isinstance(name, str) or not name:
            raise McpProtocolError(-32602, "tools/call requires a tool name")
        known_tools = {tool["name"] for tool in self.tools}
        if name not in known_tools:
            raise McpProtocolError(-32602, f"unknown tool: {name}")
        args = self._require_args(arguments)

        if name == "irule_simulate":
            if set(args) != {"scenario"}:
                raise McpProtocolError(-32602, "irule_simulate requires only scenario")
            return self._tool_success(run_scenario(args["scenario"], tcl_lsp_root=str(self._root)))

        if name == "irule_pcap_replay":
            unknown = sorted(
                set(args)
                - {"scenario", "pcap_base64", "direction", "client_addr", "server_addr"}
            )
            if unknown or "scenario" not in args or "pcap_base64" not in args:
                fields = f": {', '.join(unknown)}" if unknown else ""
                raise McpProtocolError(
                    -32602,
                    f"irule_pcap_replay requires scenario and pcap_base64{fields}",
                )
            scenario = args["scenario"]
            if not isinstance(scenario, dict) or "irule_file" in scenario:
                raise McpProtocolError(-32602, "irule_pcap_replay accepts an inline irule scenario only")
            options = {
                field: args[field]
                for field in ("direction", "client_addr", "server_addr")
                if field in args
            }
            return self._tool_success(
                run_pcap_scenario(
                    scenario,
                    _decode_pcap_base64(args["pcap_base64"]),
                    tcl_lsp_root=str(self._root),
                    **options,
                )
            )

        if name == "irule_capabilities":
            unknown = sorted(set(args) - {"offset", "limit"})
            if unknown:
                raise McpProtocolError(-32602, f"unsupported irule_capabilities field(s): {', '.join(unknown)}")
            offset = args.get("offset", 0)
            limit = args.get("limit", 100)
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise McpProtocolError(-32602, "capability offset must be an integer")
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise McpProtocolError(-32602, "capability limit must be an integer")
            return self._tool_success(_build_capabilities(self._root, offset, limit))

        if name == "irule_conformance":
            if args:
                raise McpProtocolError(-32602, "irule_conformance accepts no arguments")
            return self._tool_success(_build_conformance(self._root))

        if name == "irule_session_create":
            if set(args) != {"scenario"}:
                raise McpProtocolError(-32602, "irule_session_create requires only scenario")
            session_id: str | None = None
            try:
                session_id = self._manager.create(args["scenario"])
                return self._tool_success(self._manager.metadata(session_id))
            except Exception:
                if session_id is not None:
                    try:
                        self._manager.close(session_id)
                    except EmulatorNotFoundError:
                        pass
                raise

        session_id = args.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise McpProtocolError(-32602, f"{name} requires a non-empty session_id")

        if name == "irule_session_inspect":
            if set(args) != {"session_id"}:
                raise McpProtocolError(-32602, "irule_session_inspect accepts only session_id")
            return self._tool_success(self._manager.metadata(session_id))

        if name == "irule_session_request":
            if set(args) != {"session_id", "request"} or not isinstance(args["request"], dict):
                raise McpProtocolError(-32602, "irule_session_request requires session_id and request object")
            result = self._manager.execute(session_id, lambda session: session.run_request(args["request"]))
            metadata = self._manager.metadata(session_id)
            return self._tool_success(
                {
                    "status": "ok",
                    "schema_version": 1,
                    "profile": "tmos-17.5",
                    "tmos_version": TMOS_VERSION,
                    "session_id": session_id,
                    "fidelity": metadata["fidelity"],
                    "request_number": metadata["request_count"],
                    "result": result,
                }
            )

        if name == "irule_session_trace":
            if set(args) != {"session_id", "packets"} or not isinstance(args["packets"], list):
                raise McpProtocolError(-32602, "irule_session_trace requires session_id and packets array")
            result = self._manager.execute(
                session_id, lambda session: session.run_packet_trace(args["packets"])
            )
            metadata = self._manager.metadata(session_id)
            return self._tool_success(
                {
                    "status": "ok",
                    "schema_version": 1,
                    "profile": "tmos-17.5",
                    "tmos_version": TMOS_VERSION,
                    "session_id": session_id,
                    "fidelity": metadata["fidelity"],
                    "request_count": metadata["request_count"],
                    "result": result,
                }
            )

        if name == "irule_session_event":
            if set(args) - {"session_id", "event", "state"} or "event" not in args:
                raise McpProtocolError(-32602, "irule_session_event requires session_id and event")
            result = self._manager.execute(
                session_id,
                lambda session: session.fire_event(args["event"], args.get("state")),
            )
            metadata = self._manager.metadata(session_id)
            return self._tool_success(
                {
                    "status": "ok",
                    "schema_version": 1,
                    "profile": "tmos-17.5",
                    "tmos_version": TMOS_VERSION,
                    "session_id": session_id,
                    "fidelity": metadata["fidelity"],
                    "result": result,
                }
            )

        if name == "irule_session_close":
            if set(args) != {"session_id"}:
                raise McpProtocolError(-32602, "irule_session_close accepts only session_id")
            self._manager.close(session_id)
            return self._tool_success(
                {
                    "status": "ok",
                    "schema_version": 1,
                    "profile": "tmos-17.5",
                    "tmos_version": TMOS_VERSION,
                    "session_id": session_id,
                    "closed": True,
                }
            )

        raise McpProtocolError(-32601, f"method not implemented: {name}")

    def _dispatch(self, method: str, params: Any) -> dict[str, Any] | None:
        if method == "notifications/initialized":
            self._ready = True
            return None
        if method == "ping":
            self._require_args(params)
            return {}
        if method == "initialize":
            if self._initialized:
                raise McpProtocolError(-32600, "initialize may only be called once")
            request = self._require_args(params)
            protocol_version = request.get("protocolVersion")
            if not isinstance(protocol_version, str):
                raise McpProtocolError(-32602, "initialize requires protocolVersion")
            if protocol_version not in MCP_PROTOCOL_VERSIONS:
                raise McpProtocolError(
                    -32602,
                    f"unsupported MCP protocol version: {protocol_version}",
                    {"supported": list(MCP_PROTOCOL_VERSIONS)},
                )
            self._protocol_version = protocol_version
            self._initialized = True
            return {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {}},
                "serverInfo": MCP_SERVER_INFO,
                "instructions": "Use the irule_* tools for bounded BIG-IP 17.5 emulation; no arbitrary Tcl evaluation is exposed.",
            }
        if not self._initialized:
            raise McpProtocolError(-32002, "server is not initialized")
        if method == "tools/list":
            request = self._require_args(params)
            if request.get("cursor") not in (None, ""):
                raise McpProtocolError(-32602, "tools/list pagination is not supported")
            return {"tools": self.tools}
        if method == "tools/call":
            request = self._require_args(params)
            unknown = sorted(set(request) - {"name", "arguments"})
            if unknown:
                raise McpProtocolError(
                    -32602, f"unsupported tools/call field(s): {', '.join(unknown)}"
                )
            if "name" not in request:
                raise McpProtocolError(-32602, "tools/call requires name")
            try:
                return self._call_tool(request["name"], request.get("arguments"))
            except McpProtocolError:
                raise
            except (EmulatorInputError, EmulatorNotFoundError, EmulatorResourceError, OSError) as exc:
                return self._tool_error(exc)
            except Exception as exc:  # keep a bad rule from taking down the stdio server
                return self._tool_error(EmulatorInputError(f"tool execution failed: {exc}"))
        raise McpProtocolError(-32601, f"method not found: {method}")

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise McpProtocolError(-32600, "message must be a JSON-RPC 2.0 object")
        method = message.get("method")
        if not isinstance(method, str) or not method:
            raise McpProtocolError(-32600, "message requires a method")
        has_id = "id" in message
        request_id = message.get("id")
        if has_id and (
            isinstance(request_id, bool)
            or not isinstance(request_id, (str, int, float, type(None)))
            or (isinstance(request_id, float) and not math.isfinite(request_id))
        ):
            raise McpProtocolError(-32600, "request id must be a string, number, or null")
        try:
            result = self._dispatch(method, message.get("params"))
        except McpProtocolError as exc:
            if not has_id:
                return None
            return self._error_response(request_id, exc)
        if not has_id:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def close(self) -> None:
        if self._owns_manager:
            self._manager.close_all()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def serve_mcp(root: Path, input_stream: Any = None, output_stream: Any = None) -> None:
    """Serve newline-delimited JSON-RPC over stdio with stdout kept protocol-pure."""
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    server = McpProtocolServer(root)
    try:
        for line in input_stream:
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > MCP_MAX_MESSAGE_BYTES:
                response = McpProtocolServer._error_response(
                    None,
                    McpProtocolError(-32600, "MCP message exceeds the 2 MiB limit"),
                )
                output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
                output_stream.flush()
                continue
            request_id = None
            try:
                message = json.loads(line, parse_constant=_reject_json_constant)
                if isinstance(message, dict) and "id" in message:
                    request_id = message["id"]
                response = server.handle_message(message)
            except json.JSONDecodeError as exc:
                response = McpProtocolServer._error_response(
                    None, McpProtocolError(-32700, f"parse error: {exc.msg}")
                )
            except McpProtocolError as exc:
                response = McpProtocolServer._error_response(None, exc)
            except ValueError as exc:
                response = McpProtocolServer._error_response(
                    None, McpProtocolError(-32700, f"parse error: {exc}")
                )
            except Exception as exc:  # keep transport alive across unexpected request failures
                print(f"MCP request failed: {exc}", file=sys.stderr)
                response = McpProtocolServer._error_response(
                    request_id, McpProtocolError(-32603, "internal MCP server error")
                )
            if response is not None:
                output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
                output_stream.flush()
    finally:
        server.close()


def run_scenario(
    scenario: Any,
    *,
    tcl_lsp_root: str | None = None,
    backend: str = "inprocess",
) -> dict[str, Any]:
    if backend != "inprocess":
        raise EmulatorInputError(
            "the tmos-17.5 adapter requires the in-process Tcl backend; "
            "use the repo uv environment with Tcl/Tk support"
        )
    root = _find_tcl_lsp_root(tcl_lsp_root)
    if isinstance(scenario, dict) and "packets" in scenario:
        if "request" in scenario or "requests" in scenario:
            raise EmulatorInputError("provide packets instead of request or requests")
        _normalise_scenario_config(
            scenario,
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=True,
            require_http=False,
        )
        session = EmulatorSession(
            root,
            scenario,
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=True,
            backend=backend,
        )
        try:
            packet_result = session.run_packet_trace(scenario["packets"])
        except EmulatorInputError:
            raise
        except Exception as exc:
            raise EmulatorInputError(f"emulator packet trace failed: {exc}") from exc
        finally:
            registered_events = session.registered_events
            session.close()
        packet_result["registered_events"] = registered_events
        packet_result["fidelity"] = session.fidelity
        return packet_result

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
        backend=backend,
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
        "fidelity": session.fidelity,
        "results": results,
    }


def run_pcap_scenario(
    scenario: Any,
    pcap_data: bytes,
    *,
    tcl_lsp_root: str | None = None,
    backend: str = "inprocess",
    direction: str = "client_to_server",
    client_addr: str | None = None,
    server_addr: str | None = None,
) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("pcap scenario must be a JSON object")
    if any(field in scenario for field in ("request", "requests", "packets")):
        raise EmulatorInputError("pcap replay scenario cannot also contain request, requests, or packets")
    packets, capture = _pcap_packets(
        pcap_data,
        direction=direction,
        client_addr=client_addr,
        server_addr=server_addr,
    )
    replay_scenario = dict(scenario)
    replay_scenario["packets"] = packets
    result = run_scenario(
        replay_scenario,
        tcl_lsp_root=tcl_lsp_root,
        backend=backend,
    )
    result["capture"] = capture
    return result


def run_pcap_file(
    scenario: Any,
    path: str,
    *,
    tcl_lsp_root: str | None = None,
    backend: str = "inprocess",
    direction: str = "client_to_server",
    client_addr: str | None = None,
    server_addr: str | None = None,
) -> dict[str, Any]:
    capture_path = Path(_require_string(path, "pcap path")).expanduser()
    try:
        with capture_path.open("rb") as capture_stream:
            data = capture_stream.read(PCAP_MAX_BYTES + 1)
    except OSError as exc:
        raise EmulatorInputError(f"could not read pcap file {capture_path}: {exc}") from exc
    return run_pcap_scenario(
        scenario,
        data,
        tcl_lsp_root=tcl_lsp_root,
        backend=backend,
        direction=direction,
        client_addr=client_addr,
        server_addr=server_addr,
    )


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
            try:
                return json.loads(self.rfile.read(length))
            except UnicodeDecodeError as exc:
                raise EmulatorInputError("request body must be valid UTF-8 JSON") from exc

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
            if parsed.path == "/v1/conformance":
                try:
                    payload = _build_conformance(root)
                except (EmulatorInputError, OSError) as exc:
                    self._error(exc)
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
            if parsed.path == "/v1/simulations/pcap":
                try:
                    request = self._read_json()
                    if not isinstance(request, dict):
                        raise EmulatorInputError("pcap replay request must be a JSON object")
                    allowed = {
                        "scenario",
                        "pcap_base64",
                        "direction",
                        "client_addr",
                        "server_addr",
                    }
                    unknown = sorted(set(request) - allowed)
                    if unknown:
                        raise EmulatorInputError(
                            f"unsupported pcap replay field(s): {', '.join(unknown)}"
                        )
                    if "scenario" not in request or "pcap_base64" not in request:
                        raise EmulatorInputError(
                            "pcap replay request requires scenario and pcap_base64"
                        )
                    scenario = request["scenario"]
                    if not isinstance(scenario, dict) or "irule_file" in scenario:
                        raise EmulatorInputError(
                            "HTTP pcap replay accepts an inline irule scenario only"
                        )
                    options = {
                        field: request[field]
                        for field in ("direction", "client_addr", "server_addr")
                        if field in request
                    }
                    payload = run_pcap_scenario(
                        scenario,
                        _decode_pcap_base64(request["pcap_base64"]),
                        tcl_lsp_root=str(root),
                        **options,
                    )
                except (json.JSONDecodeError, EmulatorInputError, EmulatorResourceError, OSError) as exc:
                    self._error(exc)
                    return
                _json_response(self, 200, payload)
                return
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
                            "fidelity": session_manager.execute(
                                parts[2], lambda session: session.fidelity
                            ),
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
                if len(parts) == 4 and parts[:2] == ["v1", "sessions"] and parts[3] == "packets":
                    try:
                        packet_request = self._read_json()
                        if not isinstance(packet_request, dict) or set(packet_request) != {"packets"}:
                            raise EmulatorInputError("session packets request requires only a packets array")
                        if not isinstance(packet_request["packets"], list):
                            raise EmulatorInputError("session packets field must be an array")
                        result = session_manager.execute(
                            parts[2], lambda session: session.run_packet_trace(packet_request["packets"])
                        )
                        metadata = session_manager.metadata(parts[2])
                        payload = {
                            "status": "ok",
                            "schema_version": 1,
                            "profile": "tmos-17.5",
                            "tmos_version": TMOS_VERSION,
                            "session_id": parts[2],
                            "fidelity": metadata["fidelity"],
                            "request_count": metadata["request_count"],
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
                            "fidelity": session_manager.execute(
                                parts[2], lambda session: session.fidelity
                            ),
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
    parser.add_argument("--pcap", help="classic PCAP file to replay for the scenario")
    parser.add_argument(
        "--pcap-direction",
        choices=("client_to_server", "server_to_client", "auto"),
        default="client_to_server",
        help="direction assigned to PCAP packets; auto uses client/server addresses",
    )
    parser.add_argument("--client-addr", help="client IPv4 address for --pcap-direction auto")
    parser.add_argument("--server-addr", help="server IPv4 address for --pcap-direction auto")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--capabilities",
        action="store_true",
        help="emit a chunk of the complete tcl-lsp iRule capability catalog",
    )
    mode.add_argument(
        "--conformance",
        action="store_true",
        help="report static catalog-to-runtime and packet-event adapter coverage",
    )
    mode.add_argument("--serve", action="store_true", help="serve the HTTP API instead of reading stdin")
    mode.add_argument(
        "--mcp",
        action="store_true",
        help="serve the emulator tools over newline-delimited MCP JSON-RPC on stdin/stdout",
    )
    parser.add_argument("--offset", type=int, default=0, help="capability chunk start")
    parser.add_argument("--limit", type=int, default=100, help="capability chunk size")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP API bind address")
    parser.add_argument("--port", type=int, default=8080, help="HTTP API bind port")
    parser.add_argument(
        "--backend",
        choices=("inprocess",),
        default="inprocess",
        help="tcl-lsp bridge backend (in-process Tcl/Tk is required)",
    )
    args = parser.parse_args(argv)

    try:
        root = _find_tcl_lsp_root(args.tcl_lsp_root)
        if args.pcap and (args.serve or args.mcp or args.capabilities or args.conformance):
            raise EmulatorInputError(
                "--pcap can only be used with one-shot scenario execution"
            )
        if args.serve:
            serve(root, args.host, args.port)
            return 0
        if args.mcp:
            serve_mcp(root)
            return 0
        if args.capabilities:
            response = _build_capabilities(root, args.offset, args.limit)
        elif args.conformance:
            response = _build_conformance(root)
        else:
            if args.scenario == "-":
                scenario = json.load(sys.stdin)
            else:
                scenario = json.loads(Path(args.scenario).read_text(encoding="utf-8"))
            if args.pcap:
                response = run_pcap_file(
                    scenario,
                    args.pcap,
                    tcl_lsp_root=str(root),
                    backend=args.backend,
                    direction=args.pcap_direction,
                    client_addr=args.client_addr,
                    server_addr=args.server_addr,
                )
            else:
                response = run_scenario(scenario, tcl_lsp_root=str(root), backend=args.backend)
    except (OSError, json.JSONDecodeError, EmulatorInputError) as exc:
        response = {"status": "error", "error": str(exc)}
        print(json.dumps(response, separators=(",", ":")))
        return 1

    print(json.dumps(response, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
