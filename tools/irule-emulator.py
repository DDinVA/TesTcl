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
import importlib.util
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


try:
    from http2_wire import HTTP2_CLIENT_PREFACE, Http2ConnectionDecoder, Http2DecodeError
except ModuleNotFoundError:  # test modules load this script by absolute path
    _http2_spec = importlib.util.spec_from_file_location(
        "testcl_http2_wire", Path(__file__).with_name("http2_wire.py")
    )
    if _http2_spec is None or _http2_spec.loader is None:  # pragma: no cover
        raise ImportError("could not load HTTP/2 wire decoder")
    _http2_module = importlib.util.module_from_spec(_http2_spec)
    sys.modules[_http2_spec.name] = _http2_module
    _http2_spec.loader.exec_module(_http2_module)
    Http2ConnectionDecoder = _http2_module.Http2ConnectionDecoder
    Http2DecodeError = _http2_module.Http2DecodeError
    HTTP2_CLIENT_PREFACE = _http2_module.HTTP2_CLIENT_PREFACE


TMOS_VERSION = "17.5"
# The pinned tcl-lsp registry is intentionally broader than one BIG-IP
# release. These entries are documented by F5 as introduced in 21.0, so they
# remain visible in the complete catalog but must not be presented as 17.5
# runtime capabilities.
TMOS_17_5_POST_TARGET_COMMANDS = frozenset(
    {
        "JSON::array",
        "JSON::create",
        "JSON::get",
        "JSON::object",
        "JSON::parse",
        "JSON::render",
        "JSON::root",
        "JSON::set",
        "JSON::type",
        "SSE::field",
    }
)
TMOS_17_5_POST_TARGET_EVENTS = frozenset(
    {
        "JSON_REQUEST",
        "JSON_REQUEST_ERROR",
        "JSON_REQUEST_MISSING",
        "JSON_RESPONSE",
        "JSON_RESPONSE_ERROR",
        "JSON_RESPONSE_MISSING",
        "SSE_RESPONSE",
    }
)
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
        "sni_required",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cipher_clientlist",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_count",
        "cert_mode",
        "verify_result",
        "disabled",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
    },
    "tls_server": {
        "sni",
        "sni_required",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cipher_clientlist",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_count",
        "cert_mode",
        "verify_result",
        "disabled",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
    },
    "http2": {
        "active",
        "version",
        "stream_id",
        "stream_priority",
        "concurrency",
        "requests",
        "enabled",
        "clientside_enabled",
        "serverside_enabled",
        "disconnected",
        "discarded",
        "pseudo_headers",
    },
    "dns": {
        "qname",
        "qtype",
        "qclass",
        "qr",
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
        "qdcount",
        "ancount",
        "nscount",
        "arcount",
        "ptype",
        "message_length",
        "message_hex",
        "disabled",
        "dropped",
        "last_act",
        "edns0",
        "rpz_policy",
        "wideips",
        "response_sent",
    },
    "websocket": {
        "request_headers",
        "response_headers",
        "method",
        "uri",
        "host",
        "status",
        "frame_type",
        "eom",
        "orig_masked",
        "mask",
        "payload",
        "payload_length",
    },
    "mqtt": {
        "type",
        "protocol_name",
        "protocol_version",
        "client_id",
        "clean_session",
        "keep_alive",
        "username",
        "password",
        "will_topic",
        "will_message",
        "will_qos",
        "will_retain",
        "packet_id",
        "qos",
        "dup",
        "retain",
        "topic",
        "payload",
        "payload_length",
        "message",
        "message_length",
        "return_code",
        "return_code_list",
        "session_present",
        "topic_list",
    },
    "sip": {
        "type",
        "transport",
        "method",
        "uri",
        "version",
        "status",
        "phrase",
        "headers",
        "payload",
        "payload_length",
        "message",
        "message_length",
        "call_id",
        "from",
        "to",
        "route_status",
        "persist_key",
        "record_route",
        "route",
        "via",
    },
    "diameter": {
        "type",
        "version",
        "rflag",
        "pflag",
        "eflag",
        "tflag",
        "command_code",
        "application_id",
        "hop_by_hop_id",
        "end_to_end_id",
        "avps",
        "payload",
        "payload_length",
        "message",
        "message_length",
        "message_hex",
        "payload_hex",
        "route_status",
        "persist_key",
    },
    "radius": {
        "code",
        "id",
        "authenticator",
        "attributes",
        "payload",
        "payload_length",
        "message",
        "message_length",
        "message_hex",
        "payload_hex",
        "rtdom",
        "subscriber",
    },
    "message": {
        "proto",
        "type",
        "fields",
    },
    "mr": {
        "payload",
        "payload_length",
        "peer",
        "route_status",
        "route",
        "route_target",
        "collect_length",
        "available_for_routing",
        "always_match_port",
        "ignore_peer_port",
        "connect_back_port",
        "connection_instance",
        "connection_mode",
        "equivalent_transport",
        "flow_id",
        "instance",
        "max_retries",
        "transport",
        "retry_count",
        "stored",
        "streamed",
        "dropped",
        "released",
        "response",
    },
    "gtp": {
        "version",
        "type",
        "teid",
        "sequence",
        "npdu",
        "length",
        "ies",
        "payload",
        "payload_length",
        "message",
        "message_length",
        "message_hex",
        "payload_hex",
        "discarded",
        "responded",
    },
}
EVENT_STATE_NAMESPACES = {
    "connection": "::state::connection",
    "tls_client": "::state::tls::client",
    "tls_server": "::state::tls::server",
    "http2": "::state::http2",
    "dns": "::state::dns",
    "websocket": "::state::websocket",
    "mqtt": "::state::mqtt",
    "sip": "::state::sip",
    "diameter": "::state::diameter",
    "radius": "::state::radius",
    "message": "::state::message",
    "mr": "::state::mr",
    "gtp": "::state::gtp",
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


def _target_status(name: str, post_target_names: frozenset[str]) -> str:
    if name in post_target_names:
        return "introduced-after-tmos-17.5"
    return "available-in-tmos-17.5"


SEMANTIC_MOCK_COMMANDS = {
    "HSL::open",
    "HSL::send",
    "DNS::additional",
    "DNS::answer",
    "DNS::authority",
    "DNS::class",
    "DNS::disable",
    "DNS::drop",
    "DNS::edns0",
    "DNS::enable",
    "DNS::header",
    "DNS::is_wideip",
    "DNS::last_act",
    "DNS::len",
    "DNS::log",
    "DNS::name",
    "DNS::origin",
    "DNS::ptype",
    "DNS::query",
    "DNS::question",
    "DNS::rdata",
    "DNS::return",
    "DNS::rpz_policy",
    "DNS::rr",
    "DNS::scrape",
    "DNS::ttl",
    "DNS::type",
    "DNSMSG::header",
    "DNSMSG::record",
    "DNSMSG::section",
    "RESOLVER::name_lookup",
    "RESOLVER::summarize",
    "SSL::cert",
    "SSL::cipher",
    "SSL::disable",
    "SSL::enable",
    "SSL::sessionid",
    "SSL::sni",
    "SSL::verify_result",
    "X509::issuer",
    "X509::subject",
    "HTTP2::active",
    "HTTP2::concurrency",
    "HTTP2::disable",
    "HTTP2::disconnect",
    "HTTP2::enable",
    "HTTP2::header",
    "HTTP2::requests",
    "HTTP2::stream",
    "HTTP2::version",
    "event",
    "HTTP::passthrough_reason",
    "HTTP::password",
    "HTTP::reject_reason",
    "HTTP::response",
    "HTTP::request",
    "HTTP::redirect",
    "HTTP::has_responded",
    "HTTP::release",
    "HTTP::collect",
    "HTTP::payload",
    "HTTP::close",
    "HTTP::retry",
    "HTTP::is_keepalive",
    "HTTP::is_redirect",
    "HTTP::request_num",
    "HTTP::cookie",
    "WS::collect",
    "WS::disconnect",
    "WS::enabled",
    "WS::frame",
    "WS::masking",
    "WS::message",
    "WS::payload",
    "WS::release",
    "WS::request",
    "WS::response",
    "HTTP::username",
    "IP::addr",
    "IP::version",
    "LB::down",
    "LB::persist",
    "LB::reselect",
    "LB::server",
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
    "MQTT::clean_session",
    "MQTT::client_id",
    "MQTT::collect",
    "MQTT::disable",
    "MQTT::disconnect",
    "MQTT::drop",
    "MQTT::dup",
    "MQTT::enable",
    "MQTT::keep_alive",
    "MQTT::length",
    "MQTT::message",
    "MQTT::packet_id",
    "MQTT::password",
    "MQTT::payload",
    "MQTT::protocol_name",
    "MQTT::protocol_version",
    "MQTT::qos",
    "MQTT::release",
    "MQTT::retain",
    "MQTT::return_code",
    "MQTT::return_code_list",
    "MQTT::session_present",
    "MQTT::topic",
    "MQTT::type",
    "MQTT::username",
    "SIP::call_id",
    "SIP::discard",
    "SIP::from",
    "SIP::header",
    "SIP::message",
    "SIP::method",
    "SIP::payload",
    "SIP::persist",
    "SIP::record-route",
    "SIP::respond",
    "SIP::response",
    "SIP::route",
    "SIP::route_status",
    "SIP::to",
    "SIP::uri",
    "SIP::via",
    "DIAMETER::avp",
    "DIAMETER::command",
    "DIAMETER::disconnect",
    "DIAMETER::drop",
    "DIAMETER::dynamic_route_insertion",
    "DIAMETER::dynamic_route_lookup",
    "DIAMETER::header",
    "DIAMETER::host",
    "DIAMETER::is_request",
    "DIAMETER::is_response",
    "DIAMETER::is_retransmission",
    "DIAMETER::length",
    "DIAMETER::message",
    "DIAMETER::payload",
    "DIAMETER::persist",
    "DIAMETER::realm",
    "DIAMETER::respond",
    "DIAMETER::result",
    "DIAMETER::retransmission",
    "DIAMETER::retransmission_default",
    "DIAMETER::retransmission_reason",
    "DIAMETER::retransmit",
    "DIAMETER::retry",
    "DIAMETER::route_status",
    "DIAMETER::session",
    "DIAMETER::skip_capabilities_exchange",
    "DIAMETER::state",
    "RADIUS::avp",
    "RADIUS::code",
    "RADIUS::id",
    "RADIUS::rtdom",
    "RADIUS::subscriber",
    "radius_authenticate",
    "MESSAGE::field",
    "MESSAGE::proto",
    "MESSAGE::type",
    "GENERICMESSAGE::message",
    "GENERICMESSAGE::peer",
    "GENERICMESSAGE::route",
    "MR::always_match_port",
    "MR::available_for_routing",
    "MR::collect",
    "MR::connect_back_port",
    "MR::connection_instance",
    "MR::connection_mode",
    "MR::equivalent_transport",
    "MR::flow_id",
    "MR::ignore_peer_port",
    "MR::instance",
    "MR::max_retries",
    "MR::message",
    "MR::payload",
    "MR::peer",
    "MR::prime",
    "MR::protocol",
    "MR::release",
    "MR::restore",
    "MR::retry",
    "MR::return",
    "MR::store",
    "MR::stream",
    "MR::transport",
    "GTP::clone",
    "GTP::discard",
    "GTP::forward",
    "GTP::header",
    "GTP::ie",
    "GTP::length",
    "GTP::message",
    "GTP::new",
    "GTP::parse",
    "GTP::payload",
    "GTP::respond",
    "GTP::tunnel",
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
    target_status_counts = {
        "available-in-tmos-17.5": 0,
        "introduced-after-tmos-17.5": 0,
    }
    for name in command_names:
        spec = REGISTRY.get_any(name)
        if spec is None:  # pragma: no cover - registry contract guard
            continue
        proc_name = _mock_proc_name(name)
        runtime_status = _capability_status(proc_name, handwritten, generated)
        status_counts[runtime_status] += 1
        target_status = _target_status(name, TMOS_17_5_POST_TARGET_COMMANDS)
        target_status_counts[target_status] += 1
        requirement = spec.event_requires
        commands.append(
            {
                "name": name,
                "namespace": name.split("::", 1)[0] if "::" in name else "",
                "subcommands": sorted(spec.subcommands),
                "pure": bool(spec.pure),
                "unsafe": bool(spec.unsafe),
                "runtime_status": runtime_status,
                "target_status": target_status,
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
                "target_status": _target_status(name, TMOS_17_5_POST_TARGET_EVENTS),
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
            "target_status_counts": target_status_counts,
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
    post_target_commands = sorted(
        name for name in status_map if name in TMOS_17_5_POST_TARGET_COMMANDS
    )
    post_target_events = sorted(
        name for name in event_names if name in TMOS_17_5_POST_TARGET_EVENTS
    )
    supported_events = [
        name
        for name in event_names
        if name in PACKET_EVENT_ADAPTERS and name not in TMOS_17_5_POST_TARGET_EVENTS
    ]
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
            "target_catalog_count": len(status_map) - len(post_target_commands),
            "post_target_count": len(post_target_commands),
            "post_target_commands": post_target_commands,
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
            "target_catalog_count": len(event_names) - len(post_target_events),
            "post_target_count": len(post_target_events),
            "post_target_events": post_target_events,
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
            target_status = _target_status(name, TMOS_17_5_POST_TARGET_COMMANDS)
            row = {
                "name": name,
                "occurrences": usage[name]["occurrences"],
                "events": sorted(usage[name]["events"]),
                "runtime_status": status,
                "target_status": target_status,
            }
            command_rows.append(row)
            if target_status == "introduced-after-tmos-17.5":
                warnings.append(
                    {
                        "code": "version-incompatible",
                        "severity": "error",
                        "command": name,
                        "target_status": target_status,
                        "message": f"{name} was introduced after TMOS 17.5",
                    }
                )
            elif status in {"generated-stub", "no-runtime-handler"} and spec is not None:
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
            if event_name in TMOS_17_5_POST_TARGET_EVENTS:
                warnings.append(
                    {
                        "code": "version-incompatible",
                        "severity": "error",
                        "event": event_name,
                        "target_status": "introduced-after-tmos-17.5",
                        "message": f"{event_name} was introduced after TMOS 17.5",
                    }
                )
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


def _normalise_resolvers(raw: Any) -> dict[str, list[dict[str, Any]]]:
    """Normalize deterministic DNS records used by RESOLVER::name_lookup."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError(
            "resolvers must be an object mapping resolver names to record arrays"
        )
    resolvers: dict[str, list[dict[str, Any]]] = {}
    for name, records in raw.items():
        resolver_name = _require_string(name, "resolver name")
        if not resolver_name or "\x00" in resolver_name:
            raise EmulatorInputError("resolver name cannot be empty or contain NUL")
        resolvers[resolver_name] = _dns_normalise_records(
            records, f"resolver {resolver_name}"
        )
    return resolvers


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
        "http2",
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
    if "http2" in request:
        kwargs["http2"] = _normalise_http2_state(request["http2"], "http2")
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


def _normalise_http2_state(raw: Any, field: str) -> dict[str, Any]:
    """Validate structured HTTP/2 metadata without parsing wire frames."""
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"{field} must be an object")
    allowed = {
        "active", "version", "stream_id", "stream_priority", "concurrency",
        "requests", "enabled", "clientside_enabled", "serverside_enabled",
        "disconnected", "discarded", "pseudo_headers",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(f"{field} unsupported field(s): {', '.join(unknown)}")

    result: dict[str, Any] = {}
    for name in (
        "active", "enabled", "clientside_enabled", "serverside_enabled",
        "disconnected", "discarded",
    ):
        if name not in raw:
            continue
        value = raw[name]
        if not isinstance(value, bool):
            raise EmulatorInputError(f"{field}.{name} must be a boolean")
        result[name] = value

    limits = {
        "version": 3,
        "stream_id": 0x7FFF_FFFF,
        "stream_priority": 255,
        "concurrency": 0xFFFF_FFFF,
        "requests": 0xFFFF_FFFF,
    }
    for name, maximum in limits.items():
        if name not in raw:
            continue
        value = raw[name]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise EmulatorInputError(
                f"{field}.{name} must be an integer from 0 to {maximum}"
            )
        result[name] = value

    if "version" in result and result["version"] not in {0, 2}:
        raise EmulatorInputError(f"{field}.version must be 0 or 2")

    if "pseudo_headers" in raw:
        headers = raw["pseudo_headers"]
        if not isinstance(headers, dict) or not all(
            isinstance(name, str)
            and re.fullmatch(r":[a-z0-9-]+", name) is not None
            and isinstance(value, str)
            for name, value in headers.items()
        ):
            raise EmulatorInputError(
                f"{field}.pseudo_headers must map lowercase :pseudo-names to strings"
            )
        result["pseudo_headers"] = dict(headers)
    return result


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


def _http_release_snapshot(session: Any) -> dict[str, str]:
    parts = _split_tcl_list(session.eval_tcl("::itest::semantic::http_release_snapshot"))
    if len(parts) % 2:
        raise EmulatorInputError("invalid HTTP release state")
    snapshot = dict(zip(parts[::2], parts[1::2]))
    if set(snapshot) - {"requested"}:
        raise EmulatorInputError("invalid HTTP release fields")
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
) -> tuple[
    str,
    list[str],
    dict[str, list[str]],
    dict[str, list[dict[str, Any]]],
    list[tuple[str, dict[str, str], str]],
]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")

    allowed_fields = {
        "tmos_version",
        "irule",
        "irule_file",
        "profiles",
        "pools",
        "resolvers",
        "datagroups",
    }
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

    return (
        source,
        profiles,
        _normalise_pools(scenario.get("pools")),
        _normalise_resolvers(scenario.get("resolvers")),
        _normalise_datagroups(scenario.get("datagroups")),
    )


def _load_event_profiles(root: Path) -> dict[str, set[str]]:
    _load_session_class(root)
    try:
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp event registry: {exc}") from exc
    event_profiles: dict[str, set[str]] = {}
    for name in NAMESPACE_REGISTRY.all_event_names():
        if name in TMOS_17_5_POST_TARGET_EVENTS:
            continue
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
WEBSOCKET_MAX_FRAME_BYTES = STREAM_MAX_BYTES
MQTT_MAX_MESSAGE_BYTES = STREAM_MAX_BYTES
SIP_MAX_MESSAGE_BYTES = STREAM_MAX_BYTES
DIAMETER_MAX_MESSAGE_BYTES = STREAM_MAX_BYTES
RADIUS_MAX_MESSAGE_BYTES = 4096
RADIUS_AUTHENTICATOR_BYTES = 16
RADIUS_HEADER_LENGTH = 20
RADIUS_ATTRIBUTE_HEADER_LENGTH = 2
RADIUS_VENDOR_SPECIFIC = 26
RADIUS_AUTH_REQUEST = 1
RADIUS_ACCOUNTING_REQUEST = 4
RADIUS_ACCOUNTING_RESPONSE = 5
RADIUS_AUTH_RESPONSE_CODES = frozenset({2, 3, 11})
RADIUS_AUTH_ATTRIBUTE_CODES = {
    "user-name": 1,
    "user-password": 2,
    "nas-ip-address": 4,
    "nas-port": 5,
    "service-type": 6,
    "framed-ip-address": 8,
    "reply-message": 18,
    "state": 24,
    "class": 25,
    "vendor-specific": 26,
    "session-timeout": 27,
    "called-station-id": 30,
    "calling-station-id": 31,
    "nas-identifier": 32,
    "acct-status-type": 40,
    "acct-input-octets": 42,
    "acct-output-octets": 43,
    "acct-session-id": 44,
    "event-timestamp": 55,
    "nas-port-type": 61,
    "connect-info": 77,
}
GTP_MAX_MESSAGE_BYTES = 2 * 1024 * 1024
GTP_MAX_WIRE_MESSAGE_BYTES = 65543
GTP_HEADER_MIN_BYTES = 8
GTP_SIGNALING_PORT = 2123
GTP_USER_PLANE_PORT = 2152
GTP_PRIME_PORT = 3386
GTP_VERSION_1 = 1
GTP_VERSION_2 = 2
GTP_GPDU_TYPE = 255
GTP_IE_HEADER_BYTES = 4
DNS_RECORD_MAX_BYTES = 64 * 1024
DNS_RR_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    64: "SVCB",
    65: "HTTPS",
}
DNS_RR_CLASSES = {1: "IN", 3: "CH", 4: "HS"}
DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}
DNS_OPCODE_NAMES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
MAX_PACKET_STREAMS = 128
TCP_SEQUENCE_MODULUS = 2**32
TCP_SEQUENCE_HALF_RANGE = 2**31
PCAP_MAX_BYTES = 16 * 1024 * 1024
PCAP_MAX_PACKET_BYTES = 2 * 1024 * 1024
PACKET_PROTOCOLS = {"tcp", "udp", "tls", "http", "http2", "dns", "websocket", "mqtt", "sip", "diameter", "radius", "mr", "gtp", "wire"}
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
    "tcp": {
        "payload_hex",
    },
    "udp": set(),
    "tls": {
        "type",
        "sni",
        "sni_required",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cipher_clientlist",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_count",
        "cert_mode",
        "verify_result",
        "disabled",
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
        "http2",
    },
    "http2": {
        "payload_hex",
    },
    "dns": {
        "qname",
        "qtype",
        "qclass",
        "qr",
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
        "qdcount",
        "ancount",
        "nscount",
        "arcount",
        "ptype",
        "message_length",
        "message_hex",
        "disabled",
        "dropped",
        "last_act",
        "edns0",
        "rpz_policy",
        "wideips",
        "response_sent",
    },
    "websocket": {
        "type",
        "method",
        "uri",
        "host",
        "headers",
        "status",
        "response_headers",
        "frame_type",
        "fin",
        "masked",
        "mask",
    },
    "mqtt": {
        "type",
        "protocol_name",
        "protocol_version",
        "client_id",
        "clean_session",
        "keep_alive",
        "username",
        "password",
        "will_topic",
        "will_message",
        "will_qos",
        "will_retain",
        "packet_id",
        "qos",
        "dup",
        "retain",
        "topic",
        "payload",
        "return_code",
        "return_code_list",
        "session_present",
        "topic_list",
    },
    "sip": {
        "type",
        "transport",
        "method",
        "uri",
        "version",
        "status",
        "phrase",
        "headers",
        "body",
        "payload",
        "message",
        "call_id",
        "from",
        "to",
        "route_status",
        "persist_key",
        "record_route",
        "route",
        "via",
    },
    "diameter": {
        "type",
        "version",
        "rflag",
        "pflag",
        "eflag",
        "tflag",
        "command_code",
        "application_id",
        "hop_by_hop_id",
        "end_to_end_id",
        "avps",
        "message_hex",
        "payload_hex",
        "route_status",
        "persist_key",
    },
    "radius": {
        "code",
        "id",
        "authenticator_hex",
        "avps",
        "message_hex",
        "payload_hex",
        "rtdom",
        "subscriber",
    },
    "mr": {
        "proto",
        "type",
        "fields",
        "payload",
        "payload_hex",
        "peer",
        "route_status",
        "route",
    },
    "gtp": {
        "version",
        "type",
        "message_type",
        "teid",
        "sequence",
        "npdu",
        "ies",
        "payload",
        "payload_hex",
        "message_hex",
        "transport",
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
    "HTTP_REQUEST_RELEASE": "HTTP request transaction release phase",
    "HTTP_RESPONSE": "HTTP response transaction",
    "HTTP_RESPONSE_CONTINUE": "raw HTTP 100 Continue response",
    "HTTP_RESPONSE_RELEASE": "HTTP response transaction release phase",
    "DNS_REQUEST": "DNS request packet",
    "DNS_RESPONSE": "DNS response packet",
    "WS_REQUEST": "WebSocket upgrade request",
    "WS_RESPONSE": "WebSocket upgrade response",
    "WS_CLIENT_FRAME": "WebSocket client frame start",
    "WS_SERVER_FRAME": "WebSocket server frame start",
    "WS_CLIENT_FRAME_DONE": "WebSocket client frame end",
    "WS_SERVER_FRAME_DONE": "WebSocket server frame end",
    "WS_CLIENT_DATA": "collected WebSocket client frame data",
    "WS_SERVER_DATA": "collected WebSocket server frame data",
    "MQTT_CLIENT_INGRESS": "MQTT message received from client",
    "MQTT_CLIENT_DATA": "collected MQTT client PUBLISH payload",
    "MQTT_SERVER_INGRESS": "MQTT message received from server",
    "MQTT_SERVER_DATA": "collected MQTT server PUBLISH payload",
    "MQTT_CLIENT_SHUTDOWN": "MQTT client TCP shutdown",
    "SIP_REQUEST": "SIP client request ingress",
    "SIP_REQUEST_DONE": "SIP request routing completion",
    "SIP_REQUEST_SEND": "SIP request server-side send",
    "SIP_RESPONSE": "SIP server response ingress",
    "SIP_RESPONSE_DONE": "SIP response routing completion",
    "SIP_RESPONSE_SEND": "SIP response client-side send",
    "DIAMETER_INGRESS": "Diameter client-side message ingress",
    "DIAMETER_EGRESS": "Diameter message egress",
    "DIAMETER_RETRANSMISSION": "Diameter request retransmission",
    "RADIUS_AAA_AUTH_REQUEST": "RADIUS authentication request",
    "RADIUS_AAA_AUTH_RESPONSE": "RADIUS authentication response",
    "RADIUS_AAA_ACCT_REQUEST": "RADIUS accounting request",
    "RADIUS_AAA_ACCT_RESPONSE": "RADIUS accounting response",
    "MR_INGRESS": "Message Routing Framework ingress",
    "MR_EGRESS": "Message Routing Framework egress",
    "MR_FAILED": "Message Routing Framework route failure",
    "MR_DATA": "Message Routing Framework collected payload",
    "GENERICMESSAGE_INGRESS": "generic message ingress",
    "GENERICMESSAGE_EGRESS": "generic message egress",
    "GTP_GPDU_INGRESS": "GTP user-plane ingress",
    "GTP_GPDU_EGRESS": "GTP user-plane egress",
    "GTP_PRIME_INGRESS": "GTP-prime ingress",
    "GTP_PRIME_EGRESS": "GTP-prime egress",
    "GTP_SIGNALLING_INGRESS": "GTP signalling ingress",
    "GTP_SIGNALLING_EGRESS": "GTP signalling egress",
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


def _http_header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == wanted:
            return value
    return ""


def _decode_chunked_body(payload: bytes, body_start: int) -> tuple[bytes, int] | None:
    """Decode one bounded HTTP/1.x chunked body and return bytes consumed."""
    position = body_start
    body = bytearray()
    while True:
        line_end = payload.find(b"\r\n", position)
        line_width = 2
        if line_end < 0:
            line_end = payload.find(b"\n", position)
            line_width = 1
        if line_end < 0:
            return None
        size_text = payload[position:line_end].split(b";", 1)[0].strip()
        if not size_text:
            return None
        try:
            chunk_size = int(size_text, 16)
        except ValueError:
            return None
        if chunk_size < 0:
            return None
        position = line_end + line_width
        if chunk_size == 0:
            # The zero chunk is followed by optional trailer fields and a
            # final empty line. Do not expose trailers as response payload.
            while True:
                trailer_end = payload.find(b"\r\n", position)
                trailer_width = 2
                if trailer_end < 0:
                    trailer_end = payload.find(b"\n", position)
                    trailer_width = 1
                if trailer_end < 0:
                    return None
                if trailer_end == position:
                    return bytes(body), trailer_end + trailer_width
                if b":" not in payload[position:trailer_end]:
                    return None
                position = trailer_end + trailer_width
        if len(payload) < position + chunk_size:
            return None
        body.extend(payload[position : position + chunk_size])
        position += chunk_size
        if payload[position : position + 2] == b"\r\n":
            position += 2
        elif payload[position : position + 1] == b"\n":
            position += 1
        else:
            return None


def _decode_http_payload(
    payload: bytes, direction: str
) -> tuple[dict[str, Any], int] | None:
    separator = payload.find(b"\r\n\r\n")
    separator_length = 4
    if separator < 0:
        separator = payload.find(b"\n\n")
        separator_length = 2
    if separator < 0:
        return None
    header_text = payload[:separator].decode("iso-8859-1", errors="replace")
    lines = header_text.splitlines()
    if not lines:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    body_start = separator + separator_length
    response_status: int | None = None
    if direction == "server_to_client":
        response_match = re.match(r"^HTTP/\S+\s+(\d{3})(?:\s+.*)?$", lines[0])
        if response_match is None:
            return None
        response_status = int(response_match.group(1))
        if response_status < 200 or response_status in {204, 304}:
            return {
                "protocol": "http",
                "direction": direction,
                "status": response_status,
                "response_headers": headers,
                "response_body": "",
            }, body_start
    body_bytes = payload[body_start:]
    consumed = len(payload)
    transfer_encoding = _http_header_value(headers, "transfer-encoding").lower()
    content_length = _http_header_value(headers, "content-length")
    if "chunked" in [token.strip() for token in transfer_encoding.split(",")]:
        decoded_body = _decode_chunked_body(payload, body_start)
        if decoded_body is None:
            return None
        body_bytes, consumed = decoded_body
    elif content_length:
        if not content_length.isdigit():
            return None
        body_length = int(content_length, 10)
        consumed = body_start + body_length
        if len(payload) < consumed:
            return None
        body_bytes = payload[body_start:consumed]

    body = body_bytes.decode("iso-8859-1", errors="replace").replace("\x00", "\ufffd")
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
        }, consumed
    assert response_status is not None
    return {
        "protocol": "http",
        "direction": direction,
        "status": response_status,
        "response_headers": headers,
        "response_body": body,
    }, consumed


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


def _dns_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise EmulatorInputError(f"DNS {field} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value, 10)
    else:
        raise EmulatorInputError(f"DNS {field} must be an integer")
    if not 0 <= parsed <= maximum:
        raise EmulatorInputError(f"DNS {field} must be between 0 and {maximum}")
    return parsed


def _dns_normalise_record(value: Any, field: str, index: int) -> dict[str, Any]:
    if isinstance(value, str):
        parts = value.split()
        if len(parts) < 5:
            raise EmulatorInputError(
                f"{field} record {index} must contain name, ttl, class, type, and rdata"
            )
        name, ttl, rr_class, rr_type = parts[:4]
        rdata = " ".join(parts[4:])
    elif isinstance(value, dict):
        unknown = sorted(set(value) - {"name", "type", "class", "ttl", "rdata"})
        if unknown:
            raise EmulatorInputError(
                f"unsupported {field} record {index} field(s): {', '.join(unknown)}"
            )
        name = value.get("name", "")
        rr_type = value.get("type", "A")
        rr_class = value.get("class", "IN")
        ttl = value.get("ttl", 0)
        rdata = value.get("rdata", "")
    elif isinstance(value, list) and len(value) == 5:
        name, rr_type, rr_class, ttl, rdata = value
    else:
        raise EmulatorInputError(f"{field} record {index} must be a string, object, or five-item array")
    name = _require_string(name, f"{field} record {index} name")
    rr_type = _require_string(rr_type, f"{field} record {index} type").upper()
    rr_class = _require_string(rr_class, f"{field} record {index} class").upper()
    rdata = _require_string(rdata, f"{field} record {index} rdata")
    if not name or "\x00" in name or "\x00" in rr_type or "\x00" in rr_class or "\x00" in rdata:
        raise EmulatorInputError(f"{field} record {index} contains an empty or NUL value")
    ttl = _dns_uint(ttl, f"{field} record {index} ttl", 0xFFFF_FFFF)
    try:
        encoded_size = sum(
            len(part.encode("utf-8")) for part in (name, rr_type, rr_class, rdata)
        )
    except UnicodeEncodeError as exc:
        raise EmulatorInputError(f"{field} record {index} must contain valid UTF-8") from exc
    if encoded_size > DNS_RECORD_MAX_BYTES:
        raise EmulatorInputError(f"{field} record {index} exceeds the {DNS_RECORD_MAX_BYTES}-byte limit")
    return {"name": name, "type": rr_type, "class": rr_class, "ttl": ttl, "rdata": rdata}


def _dns_normalise_records(raw: Any, field: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EmulatorInputError(f"DNS {field} must be an array")
    if len(raw) > PACKET_MAX_COUNT:
        raise EmulatorInputError(f"DNS {field} cannot contain more than {PACKET_MAX_COUNT} records")
    return [_dns_normalise_record(value, field, index) for index, value in enumerate(raw)]


def _dns_normalise_edns0(raw: Any, field: str) -> dict[str, Any] | str:
    if raw in (None, ""):
        return ""
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"{field} must be an object")
    allowed = {
        "exists",
        "do",
        "sz",
        "nsid",
        "subnet_address",
        "subnet_source",
        "subnet_scope",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(f"unsupported {field} field(s): {', '.join(unknown)}")
    return {
        "exists": _packet_bool(raw.get("exists", False), f"{field} exists"),
        "do": _packet_bool(raw.get("do", False), f"{field} do"),
        "sz": _dns_uint(raw.get("sz", 512), f"{field} sz", 65535),
        "nsid": _require_string(raw.get("nsid", ""), f"{field} nsid"),
        "subnet_address": _require_string(
            raw.get("subnet_address", ""), f"{field} subnet_address"
        ),
        "subnet_source": _dns_uint(
            raw.get("subnet_source", 0), f"{field} subnet_source", 255
        ),
        "subnet_scope": _dns_uint(
            raw.get("subnet_scope", 0), f"{field} subnet_scope", 255
        ),
    }


def _dns_edns0_tcl(value: dict[str, Any] | str) -> str:
    if value == "":
        return ""
    values: list[str] = []
    for key in (
        "exists",
        "do",
        "sz",
        "nsid",
        "subnet_address",
        "subnet_source",
        "subnet_scope",
    ):
        values.extend((key, str(value[key])))
    return " ".join(_tcl_quote(item) for item in values)


def _dns_records_tcl(records: list[dict[str, Any]]) -> str:
    return " ".join(
        "{" + " ".join(
            _tcl_quote(str(record[key]))
            for key in ("name", "type", "class", "ttl", "rdata")
        ) + "}"
        for record in records
    )


def _dns_read_name(payload: bytes, offset: int, index: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(payload):
        raise EmulatorInputError(f"wire packet {index} has a DNS name outside the message")
    labels: list[str] = []
    cursor = offset
    next_offset: int | None = None
    visited: set[int] = set()
    while True:
        if cursor >= len(payload):
            raise EmulatorInputError(f"wire packet {index} has a truncated DNS name")
        length = payload[cursor]
        if length == 0:
            cursor += 1
            if next_offset is None:
                next_offset = cursor
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                raise EmulatorInputError(f"wire packet {index} has a truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
            if pointer in visited or pointer >= len(payload):
                raise EmulatorInputError(f"wire packet {index} has an invalid DNS compression pointer")
            visited.add(pointer)
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise EmulatorInputError(f"wire packet {index} has an invalid DNS label length")
        cursor += 1
        if length > 63 or cursor + length > len(payload):
            raise EmulatorInputError(f"wire packet {index} has an invalid DNS label")
        labels.append(_decode_wire_text(payload[cursor : cursor + length]))
        cursor += length
    return ".".join(labels), next_offset if next_offset is not None else cursor


def _dns_rdata_text(payload: bytes, start: int, end: int, rr_type: int, index: int) -> str:
    data = payload[start:end]
    if rr_type == 1 and len(data) == 4:
        return str(ipaddress.ip_address(data))
    if rr_type == 28 and len(data) == 16:
        return str(ipaddress.ip_address(data))
    if rr_type in {2, 5, 12, 39}:
        name, consumed = _dns_read_name(payload, start, index)
        if consumed > end:
            raise EmulatorInputError(f"wire packet {index} has a DNS RDATA name outside its record")
        return name
    if rr_type == 15 and len(data) >= 3:
        name, consumed = _dns_read_name(payload, start + 2, index)
        if consumed > end:
            raise EmulatorInputError(f"wire packet {index} has an invalid MX record")
        return f"{int.from_bytes(data[:2], 'big')} {name}"
    if rr_type == 33 and len(data) >= 7:
        name, consumed = _dns_read_name(payload, start + 6, index)
        if consumed > end:
            raise EmulatorInputError(f"wire packet {index} has an invalid SRV record")
        return "{} {} {} {}".format(
            int.from_bytes(data[:2], "big"),
            int.from_bytes(data[2:4], "big"),
            int.from_bytes(data[4:6], "big"),
            name,
        )
    if rr_type == 16:
        parts: list[str] = []
        cursor = 0
        while cursor < len(data):
            length = data[cursor]
            cursor += 1
            if cursor + length > len(data):
                raise EmulatorInputError(f"wire packet {index} has an invalid TXT record")
            parts.append(_decode_wire_text(data[cursor : cursor + length]))
            cursor += length
        return " ".join(parts)
    return _decode_wire_text(data)


def _dns_parse_rr(payload: bytes, offset: int, index: int) -> tuple[dict[str, Any], int]:
    name, cursor = _dns_read_name(payload, offset, index)
    if cursor + 10 > len(payload):
        raise EmulatorInputError(f"wire packet {index} has an incomplete DNS resource record")
    rr_type = int.from_bytes(payload[cursor : cursor + 2], "big")
    rr_class = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
    ttl = int.from_bytes(payload[cursor + 4 : cursor + 8], "big")
    rdlength = int.from_bytes(payload[cursor + 8 : cursor + 10], "big")
    data_start = cursor + 10
    data_end = data_start + rdlength
    if data_end > len(payload):
        raise EmulatorInputError(f"wire packet {index} has an incomplete DNS resource record payload")
    record = {
        "name": name,
        "type": DNS_RR_TYPES.get(rr_type, str(rr_type)),
        "class": DNS_RR_CLASSES.get(rr_class, str(rr_class)),
        "ttl": ttl,
        "rdata": _dns_rdata_text(payload, data_start, data_end, rr_type, index),
    }
    return record, data_end


def _dns_packet_type(qr: bool, rcode: int, answers: list[dict[str, Any]], authority: list[dict[str, Any]]) -> str:
    if not qr:
        return "QUESTION"
    if rcode == 3:
        return "NXDOMAIN"
    if answers:
        return "ANSWER"
    if authority:
        return "REFERRAL"
    return "NODATA"


def _dns_wire_name(name: str, field: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    labels = name.split(".")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise EmulatorInputError(f"DNS {field} contains an invalid label")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    if len(encoded) > 255:
        raise EmulatorInputError(f"DNS {field} exceeds the 255-byte wire name limit")
    return bytes(encoded)


def _dns_wire_code(value: Any, field: str, names: dict[int, str], maximum: int) -> int:
    if isinstance(value, str):
        upper = value.upper()
        for code, name in names.items():
            if name == upper:
                return code
    return _dns_uint(value, field, maximum)


def _dns_rdata_wire(record: dict[str, Any], index: int) -> bytes:
    rr_type = str(record["type"]).upper()
    rdata = str(record["rdata"])
    if rr_type == "A":
        try:
            value = ipaddress.ip_address(rdata)
        except ValueError as exc:
            raise EmulatorInputError(f"DNS record {index} has invalid A RDATA") from exc
        if value.version != 4:
            raise EmulatorInputError(f"DNS record {index} A RDATA must be IPv4")
        return value.packed
    if rr_type == "AAAA":
        try:
            value = ipaddress.ip_address(rdata)
        except ValueError as exc:
            raise EmulatorInputError(f"DNS record {index} has invalid AAAA RDATA") from exc
        if value.version != 6:
            raise EmulatorInputError(f"DNS record {index} AAAA RDATA must be IPv6")
        return value.packed
    if rr_type in {"CNAME", "DNAME", "NS", "PTR"}:
        return _dns_wire_name(rdata, f"record {index} RDATA")
    parts = rdata.split()
    if rr_type == "MX" and len(parts) == 2:
        return _dns_uint(parts[0], f"DNS record {index} MX preference", 65535).to_bytes(2, "big") + _dns_wire_name(parts[1], f"record {index} MX target")
    if rr_type == "SRV" and len(parts) == 4:
        return b"".join(
            _dns_uint(parts[offset], f"DNS record {index} SRV field", 65535).to_bytes(2, "big")
            for offset in range(3)
        ) + _dns_wire_name(parts[3], f"record {index} SRV target")
    if rr_type == "TXT":
        chunks = rdata.split(" ") if rdata else [""]
        encoded = bytearray()
        for chunk in chunks:
            raw = chunk.encode("utf-8")
            if len(raw) > 255:
                raise EmulatorInputError(f"DNS record {index} TXT chunk exceeds 255 bytes")
            encoded.append(len(raw))
            encoded.extend(raw)
        return bytes(encoded)
    return rdata.encode("utf-8")


def _dns_records_from_tcl(value: Any, field: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(_split_tcl_list(value)):
        parts = _split_tcl_list(raw_record)
        if len(parts) != 5:
            raise EmulatorInputError(f"DNS {field} snapshot record {index} is malformed")
        records.append(
            _dns_normalise_record(
                {
                    "name": parts[0],
                    "type": parts[1],
                    "class": parts[2],
                    "ttl": parts[3],
                    "rdata": parts[4],
                },
                field,
                index,
            )
        )
    return records


def _dns_encode_message(state: dict[str, Any]) -> bytes:
    answers = _dns_records_from_tcl(state.get("answers", ""), "answers")
    authority = _dns_records_from_tcl(state.get("authority", ""), "authority")
    additional = _dns_records_from_tcl(state.get("additional", ""), "additional")
    qname = _dns_wire_name(str(state.get("qname", "")), "question name")
    qtype = _dns_wire_code(state.get("qtype", "A"), "question type", DNS_RR_TYPES, 65535)
    qclass = _dns_wire_code(state.get("qclass", "IN"), "question class", DNS_RR_CLASSES, 65535)
    def flag(name: str) -> int:
        return 1 if str(state.get(name, "0")).lower() in {"1", "true"} else 0
    rcode = _dns_wire_code(state.get("rcode", "0"), "rcode", DNS_RCODE_NAMES, 15)
    opcode = _dns_wire_code(state.get("opcode", "0"), "opcode", DNS_OPCODE_NAMES, 15)
    flags = (
        (flag("qr") << 15)
        | (opcode << 11)
        | (flag("aa") << 10)
        | (flag("tc") << 9)
        | (flag("rd") << 8)
        | (flag("ra") << 7)
        | (flag("ad") << 5)
        | (flag("cd") << 4)
        | rcode
    )
    question_count = _dns_uint(state.get("qdcount", "1"), "qdcount", 65535)
    message = bytearray(struct.pack(
        "!HHHHHH",
        _dns_uint(state.get("id", "0"), "id", 65535),
        flags,
        question_count,
        len(answers),
        len(authority),
        len(additional),
    ))
    for _ in range(question_count):
        message.extend(qname)
        message.extend(struct.pack("!HH", qtype, qclass))
    for record in answers + authority + additional:
        name = _dns_wire_name(record["name"], "record name")
        rr_type = _dns_wire_code(record["type"], "record type", DNS_RR_TYPES, 65535)
        rr_class = _dns_wire_code(record["class"], "record class", DNS_RR_CLASSES, 65535)
        rdata = _dns_rdata_wire(record, len(message))
        if len(rdata) > 65535:
            raise EmulatorInputError("DNS RDATA exceeds the 65535-byte wire limit")
        message.extend(name)
        message.extend(struct.pack("!HHIH", rr_type, rr_class, record["ttl"], len(rdata)))
        message.extend(rdata)
    if len(message) > 65535:
        raise EmulatorInputError("DNS message exceeds the 65535-byte wire limit")
    return bytes(message)


def _decode_dns_payload(payload: bytes, direction: str, index: int) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    flags = int.from_bytes(payload[2:4], "big")
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    nscount = int.from_bytes(payload[8:10], "big")
    arcount = int.from_bytes(payload[10:12], "big")
    if qdcount < 1:
        return None
    cursor = 12
    qname, cursor = _dns_read_name(payload, cursor, index)
    if cursor + 4 > len(payload):
        raise EmulatorInputError(f"wire packet {index} has an incomplete DNS question")
    qtype = int.from_bytes(payload[cursor : cursor + 2], "big")
    qclass = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
    cursor += 4
    for _ in range(qdcount - 1):
        _, cursor = _dns_read_name(payload, cursor, index)
        if cursor + 4 > len(payload):
            raise EmulatorInputError(f"wire packet {index} has an incomplete DNS question")
        cursor += 4
    sections: dict[str, list[dict[str, Any]]] = {}
    for section, count in (("answers", ancount), ("authority", nscount), ("additional", arcount)):
        records: list[dict[str, Any]] = []
        for _ in range(count):
            record, cursor = _dns_parse_rr(payload, cursor, index)
            records.append(record)
        sections[section] = records
    qr = bool(flags & 0x8000)
    rcode = flags & 0x000F
    result: dict[str, Any] = {
        "protocol": "dns",
        "direction": "server_to_client" if qr else direction,
        "qname": qname,
        "qtype": DNS_RR_TYPES.get(qtype, str(qtype)),
        "qclass": DNS_RR_CLASSES.get(qclass, str(qclass)),
        "qr": qr,
        "id": int.from_bytes(payload[0:2], "big"),
        "rcode": rcode,
        "opcode": (flags >> 11) & 0x000F,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080),
        "cd": bool(flags & 0x0010),
        "ad": bool(flags & 0x0020),
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "ptype": _dns_packet_type(qr, rcode, sections["answers"], sections["authority"]),
        "message_length": len(payload),
    }
    result.update(sections)
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


def _packet_bool(value: Any, field: str) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int) and value in {0, 1}:
        return str(value)
    if isinstance(value, str) and value.lower() in {"0", "1", "false", "true"}:
        return "1" if value.lower() in {"1", "true"} else "0"
    raise EmulatorInputError(f"{field} must be a boolean or 0/1")


WEBSOCKET_FRAME_TYPES = frozenset(
    {"continuation", "text", "binary", "close", "ping", "pong"}
)


def _websocket_header_value(headers: Any, name: str) -> str:
    if not isinstance(headers, dict):
        return ""
    wanted = name.lower()
    for header_name, header_value in headers.items():
        if header_name.lower() == wanted:
            return header_value
    return ""


def _websocket_header_has_token(headers: Any, name: str, token: str) -> bool:
    value = _websocket_header_value(headers, name)
    return any(part.strip().lower() == token.lower() for part in value.split(","))


def _websocket_request_is_upgrade(packet: dict[str, Any]) -> bool:
    headers = packet.get("headers", {})
    return (
        _websocket_header_has_token(headers, "upgrade", "websocket")
        and _websocket_header_has_token(headers, "connection", "upgrade")
        and bool(_websocket_header_value(headers, "sec-websocket-key"))
    )


def _websocket_response_is_upgrade(packet: dict[str, Any]) -> bool:
    headers = packet.get("response_headers", {})
    return (
        _websocket_header_has_token(headers, "upgrade", "websocket")
        and _websocket_header_has_token(headers, "connection", "upgrade")
        and bool(_websocket_header_value(headers, "sec-websocket-accept"))
    )


WEBSOCKET_OPCODE_NAMES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


def _decode_websocket_frame(
    payload: bytes, direction: str
) -> tuple[dict[str, Any], int] | None:
    """Decode one RFC 6455 frame, preserving the unmasked wire payload."""
    if len(payload) < 2:
        return None
    first, second = payload[0], payload[1]
    opcode = first & 0x0F
    frame_type = WEBSOCKET_OPCODE_NAMES.get(opcode)
    if frame_type is None:
        raise EmulatorInputError(f"unsupported WebSocket opcode 0x{opcode:x}")
    if first & 0x70:
        raise EmulatorInputError("WebSocket RSV bits require an unsupported extension")

    masked = bool(second & 0x80)
    length_code = second & 0x7F
    position = 2
    if length_code < 126:
        payload_length = length_code
    elif length_code == 126:
        if len(payload) < position + 2:
            return None
        payload_length = int.from_bytes(payload[position : position + 2], "big")
        position += 2
    else:
        if len(payload) < position + 8:
            return None
        payload_length = int.from_bytes(payload[position : position + 8], "big")
        position += 8
        if payload_length > 0x7FFF_FFFF_FFFF_FFFF:
            raise EmulatorInputError("WebSocket payload length has its reserved high bit set")
    if payload_length > WEBSOCKET_MAX_FRAME_BYTES:
        raise EmulatorInputError(
            f"WebSocket frame exceeds the {WEBSOCKET_MAX_FRAME_BYTES // (1024 * 1024)} MiB limit"
        )

    mask = b""
    if masked:
        if len(payload) < position + 4:
            return None
        mask = payload[position : position + 4]
        position += 4
    frame_end = position + payload_length
    if len(payload) < frame_end:
        return None
    frame_payload = payload[position:frame_end]
    if masked:
        frame_payload = bytes(
            value ^ mask[index % 4] for index, value in enumerate(frame_payload)
        )
    return (
        {
            "protocol": "websocket",
            "type": "frame",
            "direction": direction,
            "frame_type": frame_type,
            "fin": "1" if first & 0x80 else "0",
            "masked": "1" if masked else "0",
            "mask": mask.hex(),
            "payload": _decode_wire_text(frame_payload),
            "_wire_payload": frame_payload,
        },
        frame_end,
    )


def _decode_websocket_frames(
    payload: bytes, direction: str
) -> tuple[list[dict[str, Any]], bytes]:
    frames: list[dict[str, Any]] = []
    position = 0
    while position < len(payload):
        decoded = _decode_websocket_frame(payload[position:], direction)
        if decoded is None:
            break
        frame, consumed = decoded
        if consumed <= 0:
            raise EmulatorInputError("WebSocket decoder returned an invalid frame length")
        frames.append(frame)
        if len(frames) > PACKET_MAX_COUNT:
            raise EmulatorInputError(
                f"a TCP segment cannot contain more than {PACKET_MAX_COUNT} WebSocket frames"
            )
        position += consumed
    return frames, payload[position:]


MQTT_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
}
MQTT_FIXED_FLAGS = {
    1: 0,
    2: 0,
    4: 0,
    5: 2,
    6: 2,
    7: 0,
    8: 2,
    9: 0,
    10: 2,
    11: 0,
    12: 0,
    13: 0,
    14: 0,
}
MQTT_CLIENT_PACKET_TYPES = frozenset(
    {
        "CONNECT",
        "PUBLISH",
        "PUBACK",
        "PUBREC",
        "PUBREL",
        "PUBCOMP",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "PINGREQ",
        "DISCONNECT",
    }
)
MQTT_SERVER_PACKET_TYPES = frozenset(
    {
        "CONNACK",
        "PUBLISH",
        "PUBACK",
        "PUBREC",
        "PUBREL",
        "PUBCOMP",
        "SUBACK",
        "UNSUBACK",
        "PINGRESP",
    }
)


def _mqtt_read_utf8(payload: bytes, position: int) -> tuple[str, int]:
    if position + 2 > len(payload):
        raise EmulatorInputError("MQTT UTF-8 field is truncated")
    length = int.from_bytes(payload[position : position + 2], "big")
    position += 2
    end = position + length
    if end > len(payload):
        raise EmulatorInputError("MQTT UTF-8 field exceeds the message")
    try:
        value = payload[position:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EmulatorInputError("MQTT UTF-8 field is invalid") from exc
    if "\x00" in value:
        raise EmulatorInputError("MQTT UTF-8 fields cannot contain NUL")
    return value, end


def _mqtt_remaining_length(payload: bytes) -> tuple[int, int] | None:
    value = 0
    multiplier = 1
    for offset in range(4):
        position = 1 + offset
        if position >= len(payload):
            return None
        digit = payload[position]
        value += (digit & 0x7F) * multiplier
        if digit & 0x80 == 0:
            return value, position + 1
        multiplier *= 128
    raise EmulatorInputError("MQTT remaining length uses more than four bytes")


def _decode_mqtt_message(
    payload: bytes, direction: str
) -> tuple[dict[str, Any], int] | None:
    if not payload:
        return None
    packet_type_number = payload[0] >> 4
    packet_type = MQTT_PACKET_TYPES.get(packet_type_number)
    if packet_type is None:
        raise EmulatorInputError(f"unsupported MQTT packet type {packet_type_number}")
    allowed_types = (
        MQTT_CLIENT_PACKET_TYPES
        if direction == "client_to_server"
        else MQTT_SERVER_PACKET_TYPES
    )
    if packet_type not in allowed_types:
        side = "client" if direction == "client_to_server" else "server"
        raise EmulatorInputError(
            f"MQTT {side} direction cannot carry {packet_type}"
        )
    flags = payload[0] & 0x0F
    expected_flags = MQTT_FIXED_FLAGS.get(packet_type_number)
    if expected_flags is not None and flags != expected_flags:
        raise EmulatorInputError(
            f"invalid MQTT flags 0x{flags:x} for {packet_type}"
        )
    if packet_type_number == 3 and (flags >> 1) & 0x03 == 3:
        raise EmulatorInputError("MQTT PUBLISH uses reserved QoS 3")
    remaining = _mqtt_remaining_length(payload)
    if remaining is None:
        return None
    remaining_length, body_start = remaining
    total_length = body_start + remaining_length
    if remaining_length > MQTT_MAX_MESSAGE_BYTES or total_length > MQTT_MAX_MESSAGE_BYTES:
        raise EmulatorInputError(
            f"MQTT message exceeds the {MQTT_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
        )
    if len(payload) < total_length:
        return None
    body = payload[body_start:total_length]
    result: dict[str, Any] = {
        "protocol": "mqtt",
        "direction": direction,
        "type": packet_type,
        "message_length": total_length,
        "_wire_payload": bytes(payload[:total_length]),
    }
    cursor = 0
    if packet_type == "CONNECT":
        protocol_name, cursor = _mqtt_read_utf8(body, cursor)
        if cursor + 4 > len(body):
            raise EmulatorInputError("MQTT CONNECT variable header is truncated")
        protocol_version = body[cursor]
        connect_flags = body[cursor + 1]
        keep_alive = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        if protocol_name != "MQTT" or protocol_version != 4:
            raise EmulatorInputError(
                "only MQTT 3.1.1 CONNECT packets are supported"
            )
        if connect_flags & 0x01:
            raise EmulatorInputError("MQTT CONNECT reserved flag is set")
        if connect_flags & 0x40 and not connect_flags & 0x80:
            raise EmulatorInputError("MQTT CONNECT password requires a username")
        will_flag = bool(connect_flags & 0x04)
        will_qos = (connect_flags >> 3) & 0x03
        if not will_flag and will_qos:
            raise EmulatorInputError("MQTT CONNECT will QoS is set without a will")
        if will_qos == 3:
            raise EmulatorInputError("MQTT CONNECT uses reserved will QoS 3")
        client_id, cursor = _mqtt_read_utf8(body, cursor)
        result.update(
            {
                "protocol_name": protocol_name,
                "protocol_version": protocol_version,
                "client_id": client_id,
                "clean_session": bool(connect_flags & 0x02),
                "keep_alive": keep_alive,
            }
        )
        if will_flag:
            result["will_qos"] = will_qos
            result["will_retain"] = bool(connect_flags & 0x20)
            result["will_topic"], cursor = _mqtt_read_utf8(body, cursor)
            result["will_message"], cursor = _mqtt_read_utf8(body, cursor)
        if connect_flags & 0x80:
            result["username"], cursor = _mqtt_read_utf8(body, cursor)
        if connect_flags & 0x40:
            result["password"], cursor = _mqtt_read_utf8(body, cursor)
        if cursor != len(body):
            raise EmulatorInputError("MQTT CONNECT contains trailing bytes")
    elif packet_type == "CONNACK":
        if len(body) != 2:
            raise EmulatorInputError("MQTT CONNACK must contain two bytes")
        result["session_present"] = bool(body[0] & 0x01)
        result["return_code"] = body[1]
        if body[1] not in {0, 1, 2, 3, 4, 5, 0x80}:
            raise EmulatorInputError("MQTT CONNACK has an invalid return code")
        if body[0] & 0xFE or (body[1] != 0 and body[0] & 0x01):
            raise EmulatorInputError("MQTT CONNACK has invalid session state")
    elif packet_type == "PUBLISH":
        result["dup"] = bool(flags & 0x08)
        result["qos"] = (flags >> 1) & 0x03
        result["retain"] = bool(flags & 0x01)
        result["topic"], cursor = _mqtt_read_utf8(body, cursor)
        if not result["topic"]:
            raise EmulatorInputError("MQTT PUBLISH topic must not be empty")
        if result["qos"]:
            if cursor + 2 > len(body):
                raise EmulatorInputError("MQTT PUBLISH packet id is truncated")
            result["packet_id"] = int.from_bytes(body[cursor : cursor + 2], "big")
            cursor += 2
            if result["packet_id"] == 0:
                raise EmulatorInputError("MQTT PUBLISH packet id must be nonzero")
        message_payload = body[cursor:]
        result["payload"] = _decode_wire_text(message_payload)
        result["_mqtt_payload"] = message_payload
    elif packet_type in {"PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "UNSUBACK"}:
        if len(body) != 2:
            raise EmulatorInputError(f"MQTT {packet_type} must contain a packet id")
        result["packet_id"] = int.from_bytes(body, "big")
        if result["packet_id"] == 0:
            raise EmulatorInputError(f"MQTT {packet_type} packet id must be nonzero")
    elif packet_type in {"SUBSCRIBE", "UNSUBSCRIBE"}:
        if len(body) < 2:
            raise EmulatorInputError(f"MQTT {packet_type} is missing a packet id")
        result["packet_id"] = int.from_bytes(body[:2], "big")
        if result["packet_id"] == 0:
            raise EmulatorInputError(f"MQTT {packet_type} packet id must be nonzero")
        cursor = 2
        topics: list[list[Any]] = []
        while cursor < len(body):
            topic, cursor = _mqtt_read_utf8(body, cursor)
            if packet_type == "SUBSCRIBE":
                if cursor >= len(body):
                    raise EmulatorInputError("MQTT SUBSCRIBE topic QoS is truncated")
                requested_qos = body[cursor]
                cursor += 1
                if requested_qos > 2:
                    raise EmulatorInputError("MQTT SUBSCRIBE uses invalid QoS")
                topics.append([topic, requested_qos])
            else:
                topics.append([topic])
        result["topic_list"] = json.dumps(topics, separators=(",", ":"))
    elif packet_type == "SUBACK":
        if len(body) < 3:
            raise EmulatorInputError("MQTT SUBACK is missing a packet id")
        result["packet_id"] = int.from_bytes(body[:2], "big")
        if result["packet_id"] == 0:
            raise EmulatorInputError("MQTT SUBACK packet id must be nonzero")
        if any(code not in {0, 1, 2, 0x80} for code in body[2:]):
            raise EmulatorInputError("MQTT SUBACK contains an invalid return code")
        result["return_code_list"] = json.dumps(list(body[2:]), separators=(",", ":"))
    elif body:
        raise EmulatorInputError(f"MQTT {packet_type} must not contain a payload")
    return result, total_length


def _decode_mqtt_messages(
    payload: bytes, direction: str
) -> tuple[list[dict[str, Any]], bytes]:
    messages: list[dict[str, Any]] = []
    position = 0
    while position < len(payload):
        decoded = _decode_mqtt_message(payload[position:], direction)
        if decoded is None:
            break
        message, consumed = decoded
        if consumed <= 0:
            raise EmulatorInputError("MQTT decoder returned an invalid message length")
        messages.append(message)
        if len(messages) > PACKET_MAX_COUNT:
            raise EmulatorInputError(
                f"a TCP segment cannot contain more than {PACKET_MAX_COUNT} MQTT messages"
            )
        position += consumed
    return messages, payload[position:]


def _mqtt_encode_utf8(value: Any, field: str) -> bytes:
    text = str(value)
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EmulatorInputError(f"MQTT {field} must be valid UTF-8") from exc
    if len(encoded) > 65535:
        raise EmulatorInputError(f"MQTT {field} exceeds the two-byte length limit")
    return len(encoded).to_bytes(2, "big") + encoded


def _mqtt_encode_remaining_length(length: int) -> bytes:
    if length < 0 or length > 268_435_455:
        raise EmulatorInputError("MQTT remaining length is out of range")
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        encoded.append(digit)
        if not length:
            return bytes(encoded)


def _mqtt_int(packet: dict[str, Any], field: str, default: int = 0) -> int:
    value = packet.get(field, default)
    if isinstance(value, bool):
        raise EmulatorInputError(f"MQTT {field} must be an integer")
    try:
        integer = int(value)
    except (TypeError, ValueError):
        raise EmulatorInputError(f"MQTT {field} must be an integer") from None
    if not 0 <= integer <= 65535:
        raise EmulatorInputError(f"MQTT {field} must be between 0 and 65535")
    return integer


def _mqtt_byte(packet: dict[str, Any], field: str, default: int = 0) -> int:
    value = _mqtt_int(packet, field, default)
    if value > 255:
        raise EmulatorInputError(f"MQTT {field} must be between 0 and 255")
    return value


def _mqtt_flag(packet: dict[str, Any], field: str, default: bool = False) -> bool:
    value = packet.get(field, default)
    return str(value).lower() in {"1", "true"}


def _mqtt_topic_list(packet: dict[str, Any]) -> list[list[Any]]:
    raw = packet.get("topic_list", "[]")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EmulatorInputError("MQTT topic_list must be JSON") from exc
    if not isinstance(raw, list):
        raise EmulatorInputError("MQTT topic_list must be an array")
    result: list[list[Any]] = []
    for item in raw:
        if not isinstance(item, list) or not item or not isinstance(item[0], str):
            raise EmulatorInputError("MQTT topic_list entries must contain a topic")
        result.append(item)
    return result


def _encode_mqtt_message(packet: dict[str, Any]) -> bytes:
    packet_type = str(packet.get("type", "")).upper()
    numbers = {
        "CONNECT": 1,
        "CONNACK": 2,
        "PUBLISH": 3,
        "PUBACK": 4,
        "PUBREC": 5,
        "PUBREL": 6,
        "PUBCOMP": 7,
        "SUBSCRIBE": 8,
        "SUBACK": 9,
        "UNSUBSCRIBE": 10,
        "UNSUBACK": 11,
        "PINGREQ": 12,
        "PINGRESP": 13,
        "DISCONNECT": 14,
    }
    if packet_type not in numbers:
        raise EmulatorInputError(f"unsupported MQTT packet type: {packet_type}")
    flags = MQTT_FIXED_FLAGS.get(numbers[packet_type], 0)
    body = bytearray()
    if packet_type == "CONNECT":
        body += _mqtt_encode_utf8(packet.get("protocol_name", "MQTT"), "protocol_name")
        protocol_version = _mqtt_int(packet, "protocol_version", 4)
        if packet.get("protocol_name", "MQTT") != "MQTT" or protocol_version != 4:
            raise EmulatorInputError("only MQTT 3.1.1 CONNECT packets are supported")
        body.append(protocol_version)
        will_topic = packet.get("will_topic", "")
        will_message = packet.get("will_message", "")
        has_will = "will_topic" in packet or "will_message" in packet
        will_qos = _mqtt_int(packet, "will_qos", 0)
        if will_qos > 2:
            raise EmulatorInputError("MQTT will_qos must be 0, 1, or 2")
        connect_flags = (_mqtt_flag(packet, "clean_session", True) << 1)
        if has_will:
            connect_flags |= 0x04 | (will_qos << 3) | (_mqtt_flag(packet, "will_retain") << 5)
        if "password" in packet:
            connect_flags |= 0x40
        if "username" in packet:
            connect_flags |= 0x80
        body.append(connect_flags)
        body += _mqtt_int(packet, "keep_alive", 60).to_bytes(2, "big")
        body += _mqtt_encode_utf8(packet.get("client_id", ""), "client_id")
        if has_will:
            body += _mqtt_encode_utf8(will_topic, "will_topic")
            body += _mqtt_encode_utf8(will_message, "will_message")
        if "username" in packet:
            body += _mqtt_encode_utf8(packet["username"], "username")
        if "password" in packet:
            body += _mqtt_encode_utf8(packet["password"], "password")
    elif packet_type == "CONNACK":
        return_code = _mqtt_byte(packet, "return_code", 0)
        if return_code not in {0, 1, 2, 3, 4, 5, 0x80}:
            raise EmulatorInputError("MQTT CONNACK has an invalid return code")
        session_present = _mqtt_flag(packet, "session_present")
        if session_present and return_code != 0:
            raise EmulatorInputError(
                "MQTT CONNACK session_present requires a zero return code"
            )
        body += bytes([session_present, return_code])
    elif packet_type == "PUBLISH":
        qos = _mqtt_int(packet, "qos", 0)
        if qos > 2:
            raise EmulatorInputError("MQTT qos must be 0, 1, or 2")
        flags = (_mqtt_flag(packet, "dup") << 3) | (qos << 1) | _mqtt_flag(packet, "retain")
        topic = str(packet.get("topic", ""))
        if not topic:
            raise EmulatorInputError("MQTT PUBLISH topic must not be empty")
        body += _mqtt_encode_utf8(topic, "topic")
        if qos:
            packet_id = _mqtt_int(packet, "packet_id")
            if packet_id == 0:
                raise EmulatorInputError("MQTT PUBLISH packet id must be nonzero")
            body += packet_id.to_bytes(2, "big")
        payload = packet.get("payload", "")
        body += payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8")
    elif packet_type in {"PUBACK", "PUBREC", "PUBREL", "PUBCOMP", "UNSUBACK"}:
        packet_id = _mqtt_int(packet, "packet_id")
        if packet_id == 0:
            raise EmulatorInputError(f"MQTT {packet_type} packet id must be nonzero")
        body += packet_id.to_bytes(2, "big")
    elif packet_type in {"SUBSCRIBE", "UNSUBSCRIBE"}:
        packet_id = _mqtt_int(packet, "packet_id")
        if packet_id == 0:
            raise EmulatorInputError(f"MQTT {packet_type} packet id must be nonzero")
        body += packet_id.to_bytes(2, "big")
        for item in _mqtt_topic_list(packet):
            body += _mqtt_encode_utf8(item[0], "topic")
            if not item[0]:
                raise EmulatorInputError("MQTT topic filters must not be empty")
            if packet_type == "SUBSCRIBE":
                try:
                    requested_qos = int(item[1])
                except (IndexError, TypeError, ValueError) as exc:
                    raise EmulatorInputError(
                        "MQTT SUBSCRIBE topic QoS must be 0, 1, or 2"
                    ) from exc
                if requested_qos < 0 or requested_qos > 2:
                    raise EmulatorInputError("MQTT SUBSCRIBE topic QoS must be 0, 1, or 2")
                body.append(requested_qos)
    elif packet_type == "SUBACK":
        packet_id = _mqtt_int(packet, "packet_id")
        if packet_id == 0:
            raise EmulatorInputError("MQTT SUBACK packet id must be nonzero")
        body += packet_id.to_bytes(2, "big")
        raw_codes = packet.get("return_code_list", "[]")
        if isinstance(raw_codes, str):
            try:
                raw_codes = json.loads(raw_codes)
            except json.JSONDecodeError as exc:
                raise EmulatorInputError("MQTT return_code_list must be JSON") from exc
        if not isinstance(raw_codes, list):
            raise EmulatorInputError("MQTT return_code_list must be an array")
        if not raw_codes:
            raise EmulatorInputError("MQTT SUBACK requires at least one return code")
        body += bytes(_mqtt_byte({"value": code}, "value") for code in raw_codes)
    return bytes([(numbers[packet_type] << 4) | flags]) + _mqtt_encode_remaining_length(len(body)) + body


SIP_COMPACT_HEADERS = {
    "b": "Content-Type",
    "c": "Content-Type",
    "e": "Content-Encoding",
    "f": "From",
    "i": "Call-ID",
    "k": "Supported",
    "l": "Content-Length",
    "m": "Contact",
    "r": "Refer-To",
    "s": "Subject",
    "t": "To",
    "v": "Via",
}


def _sip_header_name(value: Any, field: str = "SIP header name") -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\r" in value
        or "\n" in value
        or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", value.strip())
    ):
        raise EmulatorInputError(f"{field} must be a non-empty header name")
    return value.strip()


def _sip_header_value(value: Any, field: str = "SIP header value") -> str:
    if not isinstance(value, str) or "\r" in value or "\n" in value:
        raise EmulatorInputError(f"{field} must not contain newlines")
    return value


def _sip_header_pairs(value: Any, field: str = "SIP headers") -> list[list[str]]:
    if value is None:
        return []
    pairs: list[list[str]] = []
    if isinstance(value, dict):
        items = value.items()
        for name, raw_value in items:
            header_name = _sip_header_name(name)
            values = raw_value if isinstance(raw_value, list) else [raw_value]
            if not values:
                pairs.append([header_name, ""])
            for item in values:
                pairs.append([header_name, _sip_header_value(item)])
        return pairs
    if not isinstance(value, list):
        raise EmulatorInputError(f"{field} must be an object or array of [name, value] pairs")
    for index, item in enumerate(value):
        if not isinstance(item, list) or len(item) != 2:
            raise EmulatorInputError(f"{field}[{index}] must be a [name, value] pair")
        pairs.append([
            _sip_header_name(item[0], f"{field}[{index}] name"),
            _sip_header_value(item[1], f"{field}[{index}] value"),
        ])
    return pairs


def _sip_canonical_header_name(value: Any) -> str:
    name = str(value).strip().lower()
    return SIP_COMPACT_HEADERS.get(name, name)


def _sip_header_matches(name: str, wanted: str) -> bool:
    return _sip_canonical_header_name(name) == _sip_canonical_header_name(wanted)


def _sip_header_values(headers: list[list[str]], wanted: str) -> list[str]:
    return [value for name, value in headers if _sip_header_matches(name, wanted)]


def _sip_content_length(headers: list[list[str]]) -> int:
    values = _sip_header_values(headers, "Content-Length")
    if not values:
        return 0
    if len(values) > 1:
        raise EmulatorInputError("SIP message has multiple Content-Length headers")
    value = values[0].strip()
    if not re.fullmatch(r"[0-9]+", value):
        raise EmulatorInputError("SIP Content-Length must be a decimal integer")
    try:
        length = int(value)
    except ValueError as exc:
        raise EmulatorInputError("SIP Content-Length must be an integer") from exc
    if length < 0 or length > SIP_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("SIP Content-Length is out of range")
    return length


def _sip_derived_fields(headers: list[list[str]]) -> dict[str, str]:
    via_values = _sip_header_values(headers, "Via")
    record_route_values = _sip_header_values(headers, "Record-Route")
    route_values = _sip_header_values(headers, "Route")
    call_id_values = _sip_header_values(headers, "Call-ID")
    from_values = _sip_header_values(headers, "From")
    to_values = _sip_header_values(headers, "To")
    return {
        "call_id": call_id_values[0][:256] if call_id_values else "",
        "from": from_values[0] if from_values else "",
        "to": to_values[0] if to_values else "",
        "record_route": json.dumps(record_route_values, separators=(",", ":")),
        "route": json.dumps(route_values, separators=(",", ":")),
        "via": json.dumps(via_values, separators=(",", ":")),
    }


def _sip_start_line(packet: dict[str, Any]) -> str:
    version = str(packet.get("version", "SIP/2.0"))
    if version != "SIP/2.0":
        raise EmulatorInputError("SIP version must be SIP/2.0")
    if packet.get("type") == "request":
        method = str(packet.get("method", "")).upper()
        uri = str(packet.get("uri", ""))
        if not method or not re.fullmatch(r"[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*", method):
            raise EmulatorInputError("SIP request method is invalid")
        if not uri or any(char in uri for char in "\r\n "):
            raise EmulatorInputError("SIP request URI is invalid")
        return f"{method} {uri} {version}"
    try:
        status = int(packet.get("status", 0))
    except (TypeError, ValueError) as exc:
        raise EmulatorInputError("SIP response status must be an integer") from exc
    if not 100 <= status <= 699:
        raise EmulatorInputError("SIP response status must be between 100 and 699")
    phrase = str(packet.get("phrase", ""))
    if "\r" in phrase or "\n" in phrase:
        raise EmulatorInputError("SIP response phrase must not contain newlines")
    return f"{version} {status} {phrase}".rstrip()


def _encode_sip_message(packet: dict[str, Any]) -> bytes:
    payload = packet.get("payload", packet.get("body", ""))
    if isinstance(payload, (bytes, bytearray)):
        payload_bytes = bytes(payload)
    else:
        try:
            payload_bytes = str(payload).encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EmulatorInputError("SIP payload must be valid UTF-8") from exc
    if len(payload_bytes) > SIP_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("SIP payload exceeds the stream size limit")
    headers = _sip_header_pairs(packet.get("headers", []))
    headers = [pair for pair in headers if not _sip_header_matches(pair[0], "Content-Length")]
    headers.append(["Content-Length", str(len(payload_bytes))])
    lines = [_sip_start_line(packet)] + [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + payload_bytes


def _decode_sip_message(
    payload: bytes, direction: str
) -> tuple[dict[str, Any], int] | None:
    if not payload:
        return None
    delimiter = b"\r\n\r\n"
    delimiter_width = 4
    header_end = payload.find(delimiter)
    if header_end < 0:
        delimiter = b"\n\n"
        delimiter_width = 2
        header_end = payload.find(delimiter)
    if header_end < 0:
        if len(payload) > SIP_MAX_MESSAGE_BYTES:
            raise EmulatorInputError("SIP headers exceed the stream size limit")
        return None
    header_bytes = payload[:header_end]
    try:
        header_text = header_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EmulatorInputError("SIP headers must be valid UTF-8") from exc
    lines = header_text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise EmulatorInputError("SIP message has no start line")
    unfolded: list[str] = []
    for line in lines:
        if line.startswith((" ", "\t")):
            if not unfolded:
                raise EmulatorInputError("SIP header continuation has no preceding header")
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)
    start_line = unfolded[0].strip()
    headers: list[list[str]] = []
    for line in unfolded[1:]:
        if ":" not in line:
            raise EmulatorInputError("SIP header is missing a colon")
        name, value = line.split(":", 1)
        headers.append([_sip_header_name(name), _sip_header_value(value.strip())])
    if start_line.startswith("SIP/"):
        parts = start_line.split(None, 2)
        if len(parts) < 2 or parts[0] != "SIP/2.0" or not re.fullmatch(r"[1-6][0-9][0-9]", parts[1]):
            raise EmulatorInputError("SIP response start line is invalid")
        packet_type = "response"
        version = parts[0]
        status = int(parts[1])
        phrase = parts[2] if len(parts) == 3 else ""
        method = ""
        uri = ""
    else:
        parts = start_line.split()
        if len(parts) != 3 or parts[2] != "SIP/2.0" or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*", parts[0]
        ):
            raise EmulatorInputError("SIP request start line is invalid")
        packet_type = "request"
        method, uri, version = parts
        status = None
        phrase = ""
    body_start = header_end + delimiter_width
    content_length = _sip_content_length(headers)
    total_length = body_start + content_length
    if total_length > SIP_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("SIP message exceeds the stream size limit")
    if len(payload) < total_length:
        return None
    wire_message = bytes(payload[:total_length])
    body = bytes(payload[body_start:total_length])
    result: dict[str, Any] = {
        "protocol": "sip",
        "direction": direction,
        "type": packet_type,
        "version": version,
        "headers": headers,
        "payload": _decode_wire_text(body),
        "_sip_payload": body,
        "message": _decode_wire_text(wire_message),
        "message_length": total_length,
        "_wire_payload": wire_message,
    }
    if packet_type == "request":
        result.update({"method": method.upper(), "uri": uri})
    else:
        result.update({"status": status, "phrase": phrase})
    result.update(_sip_derived_fields(headers))
    return result, total_length


def _decode_sip_messages(
    payload: bytes, direction: str
) -> tuple[list[dict[str, Any]], bytes]:
    messages: list[dict[str, Any]] = []
    position = 0
    while position < len(payload):
        decoded = _decode_sip_message(payload[position:], direction)
        if decoded is None:
            break
        message, consumed = decoded
        if consumed <= 0:
            raise EmulatorInputError("SIP decoder returned an invalid message length")
        messages.append(message)
        if len(messages) > PACKET_MAX_COUNT:
            raise EmulatorInputError(
                f"a TCP segment cannot contain more than {PACKET_MAX_COUNT} SIP messages"
            )
        position += consumed
    return messages, payload[position:]


DIAMETER_AVP_VENDOR_FLAG = 0x80
DIAMETER_FLAG_REQUEST = 0x80
DIAMETER_FLAG_PROXIABLE = 0x40
DIAMETER_FLAG_ERROR = 0x20
DIAMETER_FLAG_RETRANSMIT = 0x10
DIAMETER_HEADER_LENGTH = 20
DIAMETER_AVP_HEADER_LENGTH = 8
DIAMETER_AVP_VENDOR_HEADER_LENGTH = 12
DIAMETER_AVP_NAME_CODES = {
    "session-id": 263,
    "origin-host": 264,
    "origin-realm": 296,
    "destination-host": 293,
    "destination-realm": 283,
    "result-code": 268,
    "product-name": 269,
    "supported-vendor-id": 265,
    "disconnect-cause": 273,
    "auth-application-id": 258,
}
DIAMETER_INTEGER32_AVPS = frozenset(
    {258, 268, 273, 277, 280, 281, 282, 283, 285, 286, 287, 288, 289, 290, 291, 292, 296}
)


def _diameter_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise EmulatorInputError(f"Diameter {field} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value, 10)
    else:
        raise EmulatorInputError(f"Diameter {field} must be an integer")
    if not 0 <= parsed <= maximum:
        raise EmulatorInputError(f"Diameter {field} must be between 0 and {maximum}")
    return parsed


def _diameter_bool(value: Any, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    return _packet_bool(value, f"Diameter {field}") == "1"


def _diameter_hex(value: Any, field: str) -> bytes:
    text = _require_string(value, f"Diameter {field}")
    if len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", text):
        raise EmulatorInputError(f"Diameter {field} must be an even-length hexadecimal string")
    try:
        result = bytes.fromhex(text)
    except ValueError as exc:  # pragma: no cover - regex guards this path
        raise EmulatorInputError(f"Diameter {field} is not valid hexadecimal") from exc
    if len(result) > DIAMETER_MAX_MESSAGE_BYTES:
        raise EmulatorInputError(
            f"Diameter {field} exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
        )
    return result


def _diameter_avp_code(value: Any, field: str) -> int:
    if isinstance(value, str):
        name = value.lower()
        if name in DIAMETER_AVP_NAME_CODES:
            return DIAMETER_AVP_NAME_CODES[name]
    return _diameter_uint(value, field, 0xFFFF_FFFF)


def _diameter_avp_data(value: dict[str, Any], index: int) -> bytes:
    supplied = [field for field in ("data", "data_hex", "data_base64") if field in value]
    if len(supplied) > 1:
        raise EmulatorInputError(
            f"Diameter AVP {index} must specify only one of data, data_hex, or data_base64"
        )
    if not supplied:
        return b""
    field = supplied[0]
    if field == "data_hex":
        return _diameter_hex(value[field], f"AVP {index} data_hex")
    if field == "data_base64":
        encoded = _require_string(value[field], f"Diameter AVP {index} data_base64")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EmulatorInputError(
                f"Diameter AVP {index} data_base64 is not valid base64"
            ) from exc
        if len(decoded) > DIAMETER_MAX_MESSAGE_BYTES:
            raise EmulatorInputError(
                f"Diameter AVP {index} data exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
            )
        return decoded
    data = _require_string(value[field], f"Diameter AVP {index} data")
    data_type = str(value.get("type", "utf8")).lower()
    if data_type in {"hex", "raw"}:
        return _diameter_hex(data, f"AVP {index} data")
    if data_type == "base64":
        try:
            decoded = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EmulatorInputError(f"Diameter AVP {index} data is not valid base64") from exc
        if len(decoded) > DIAMETER_MAX_MESSAGE_BYTES:
            raise EmulatorInputError(
                f"Diameter AVP {index} data exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
            )
        return decoded
    if data_type in {"integer32", "unsigned32"}:
        number = _diameter_uint(data, f"AVP {index} data", 0xFFFF_FFFF)
        return number.to_bytes(4, "big")
    if data_type in {"integer64", "unsigned64"}:
        number = _diameter_uint(data, f"AVP {index} data", 0xFFFF_FFFF_FFFF_FFFF)
        return number.to_bytes(8, "big")
    try:
        encoded = data.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EmulatorInputError(f"Diameter AVP {index} data must be valid UTF-8") from exc
    if len(encoded) > DIAMETER_MAX_MESSAGE_BYTES:
        raise EmulatorInputError(
            f"Diameter AVP {index} data exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
        )
    return encoded


def _diameter_normalise_avps(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EmulatorInputError("Diameter avps must be an array")
    if len(raw) > PACKET_MAX_COUNT:
        raise EmulatorInputError(f"Diameter avps cannot contain more than {PACKET_MAX_COUNT} entries")
    result: list[dict[str, Any]] = []
    allowed = {"code", "flags", "vendor_id", "data", "data_hex", "data_base64", "type"}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EmulatorInputError(f"Diameter AVP {index} must be an object")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"unsupported Diameter AVP {index} field(s): {', '.join(unknown)}"
            )
        if "code" not in item:
            raise EmulatorInputError(f"Diameter AVP {index} requires code")
        code = _diameter_avp_code(item["code"], f"AVP {index} code")
        flags = _diameter_uint(item.get("flags", 0), f"AVP {index} flags", 0xFF)
        vendor_id = _diameter_uint(item.get("vendor_id", 0), f"AVP {index} vendor_id", 0xFFFF_FFFF)
        if vendor_id:
            flags |= DIAMETER_AVP_VENDOR_FLAG
        data = _diameter_avp_data(item, index)
        data_type = str(item.get("type", "utf8"))
        result.append(
            {
                "code": code,
                "flags": flags,
                "vendor_id": vendor_id,
                "data": _decode_wire_text(data),
                "data_hex": data.hex(),
                "type": data_type,
                "_data": data,
            }
        )
    return result


def _diameter_encode_avp(avp: dict[str, Any]) -> bytes:
    code = _diameter_avp_code(avp["code"], "AVP code")
    flags = _diameter_uint(avp.get("flags", 0), "AVP flags", 0xFF)
    vendor_id = _diameter_uint(avp.get("vendor_id", 0), "AVP vendor_id", 0xFFFF_FFFF)
    data = avp.get("_data")
    if not isinstance(data, bytes):
        data = _diameter_avp_data(avp, 0)
    if vendor_id:
        flags |= DIAMETER_AVP_VENDOR_FLAG
    header_length = DIAMETER_AVP_VENDOR_HEADER_LENGTH if flags & DIAMETER_AVP_VENDOR_FLAG else DIAMETER_AVP_HEADER_LENGTH
    length = header_length + len(data)
    if length > 0xFF_FFFF:
        raise EmulatorInputError("Diameter AVP length exceeds the three-byte wire limit")
    header = code.to_bytes(4, "big") + bytes([flags]) + length.to_bytes(3, "big")
    if flags & DIAMETER_AVP_VENDOR_FLAG:
        header += vendor_id.to_bytes(4, "big")
    encoded = header + data
    return encoded + (b"\x00" * ((-len(encoded)) % 4))


def _diameter_avps_payload(avps: list[dict[str, Any]]) -> bytes:
    payload = b"".join(_diameter_encode_avp(avp) for avp in avps)
    if len(payload) > DIAMETER_MAX_MESSAGE_BYTES - DIAMETER_HEADER_LENGTH:
        raise EmulatorInputError(
            f"Diameter AVP payload exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
        )
    return payload


def _diameter_encode_message(packet: dict[str, Any]) -> bytes:
    version = _diameter_uint(packet.get("version", 1), "version", 0xFF)
    flags = 0
    if _diameter_bool(packet.get("rflag"), "rflag", packet.get("type", "request") == "request"):
        flags |= DIAMETER_FLAG_REQUEST
    if _diameter_bool(packet.get("pflag"), "pflag"):
        flags |= DIAMETER_FLAG_PROXIABLE
    if _diameter_bool(packet.get("eflag"), "eflag"):
        flags |= DIAMETER_FLAG_ERROR
    if _diameter_bool(packet.get("tflag"), "tflag"):
        flags |= DIAMETER_FLAG_RETRANSMIT
    if "_diameter_payload" in packet:
        payload = packet["_diameter_payload"]
        if not isinstance(payload, bytes):
            raise EmulatorInputError("Diameter internal payload must be bytes")
    elif "payload_hex" in packet:
        payload = _diameter_hex(packet["payload_hex"], "payload_hex")
    else:
        avps = packet.get("_diameter_avps", packet.get("avps", []))
        if not isinstance(avps, list):
            raise EmulatorInputError("Diameter avps must be an array")
        payload = _diameter_avps_payload(avps)
    length = DIAMETER_HEADER_LENGTH + len(payload)
    if length > DIAMETER_MAX_MESSAGE_BYTES or length > 0xFF_FFFF:
        raise EmulatorInputError("Diameter message length exceeds the supported limit")
    header = bytes([version]) + length.to_bytes(3, "big") + bytes([flags])
    header += _diameter_uint(packet.get("command_code", 0), "command_code", 0xFF_FFFF).to_bytes(3, "big")
    header += _diameter_uint(packet.get("application_id", 0), "application_id", 0xFFFF_FFFF).to_bytes(4, "big")
    header += _diameter_uint(packet.get("hop_by_hop_id", 0), "hop_by_hop_id", 0xFFFF_FFFF).to_bytes(4, "big")
    header += _diameter_uint(packet.get("end_to_end_id", 0), "end_to_end_id", 0xFFFF_FFFF).to_bytes(4, "big")
    return header + payload


def _diameter_parsed_avp(code: int, flags: int, vendor_id: int, data: bytes) -> dict[str, Any]:
    data_type = "integer32" if code in DIAMETER_INTEGER32_AVPS and len(data) == 4 else "utf8"
    value: Any = _decode_wire_text(data)
    if data_type == "integer32":
        value = str(int.from_bytes(data, "big"))
    return {
        "code": code,
        "flags": flags,
        "vendor_id": vendor_id,
        "data": value,
        "data_hex": data.hex(),
        "type": data_type,
        "_data": data,
    }


def _decode_diameter_message(
    payload: bytes, direction: str
) -> tuple[dict[str, Any], int] | None:
    if not payload:
        return None
    if len(payload) < DIAMETER_HEADER_LENGTH:
        return None
    version = payload[0]
    if version != 1:
        raise EmulatorInputError(f"unsupported Diameter version {version}")
    length = int.from_bytes(payload[1:4], "big")
    if length < DIAMETER_HEADER_LENGTH:
        raise EmulatorInputError("Diameter message length is smaller than its header")
    if length > DIAMETER_MAX_MESSAGE_BYTES:
        raise EmulatorInputError(
            f"Diameter message exceeds the {DIAMETER_MAX_MESSAGE_BYTES // (1024 * 1024)} MiB limit"
        )
    if len(payload) < length:
        return None
    message = bytes(payload[:length])
    flags = message[4]
    command_code = int.from_bytes(message[5:8], "big")
    application_id = int.from_bytes(message[8:12], "big")
    hop_by_hop_id = int.from_bytes(message[12:16], "big")
    end_to_end_id = int.from_bytes(message[16:20], "big")
    avps: list[dict[str, Any]] = []
    cursor = DIAMETER_HEADER_LENGTH
    while cursor < length:
        if length - cursor < DIAMETER_AVP_HEADER_LENGTH:
            raise EmulatorInputError("Diameter AVP header is truncated")
        code = int.from_bytes(message[cursor : cursor + 4], "big")
        avp_flags = message[cursor + 4]
        avp_length = int.from_bytes(message[cursor + 5 : cursor + 8], "big")
        header_length = (
            DIAMETER_AVP_VENDOR_HEADER_LENGTH
            if avp_flags & DIAMETER_AVP_VENDOR_FLAG
            else DIAMETER_AVP_HEADER_LENGTH
        )
        if avp_length < header_length or cursor + avp_length > length:
            raise EmulatorInputError("Diameter AVP length is invalid")
        vendor_id = 0
        data_start = cursor + DIAMETER_AVP_HEADER_LENGTH
        if avp_flags & DIAMETER_AVP_VENDOR_FLAG:
            vendor_id = int.from_bytes(message[data_start : data_start + 4], "big")
            data_start += 4
        data = bytes(message[data_start : cursor + avp_length])
        avps.append(_diameter_parsed_avp(code, avp_flags, vendor_id, data))
        padded_length = (avp_length + 3) & ~3
        if cursor + padded_length > length:
            raise EmulatorInputError("Diameter AVP padding exceeds the message")
        if any(message[cursor + avp_length : cursor + padded_length]):
            raise EmulatorInputError("Diameter AVP padding must be zero")
        cursor += padded_length
    return {
        "protocol": "diameter",
        "direction": direction,
        "type": "request" if flags & DIAMETER_FLAG_REQUEST else "response",
        "version": version,
        "rflag": bool(flags & DIAMETER_FLAG_REQUEST),
        "pflag": bool(flags & DIAMETER_FLAG_PROXIABLE),
        "eflag": bool(flags & DIAMETER_FLAG_ERROR),
        "tflag": bool(flags & DIAMETER_FLAG_RETRANSMIT),
        "command_code": command_code,
        "application_id": application_id,
        "hop_by_hop_id": hop_by_hop_id,
        "end_to_end_id": end_to_end_id,
        "avps": avps,
        "payload_hex": message[DIAMETER_HEADER_LENGTH:].hex(),
        "message_hex": message.hex(),
        "message": _decode_wire_text(message),
        "message_length": length,
        "_diameter_avps": avps,
        "_diameter_payload": message[DIAMETER_HEADER_LENGTH:],
        "_wire_payload": message,
    }, length


def _decode_diameter_messages(
    payload: bytes, direction: str
) -> tuple[list[dict[str, Any]], bytes]:
    messages: list[dict[str, Any]] = []
    position = 0
    while position < len(payload):
        decoded = _decode_diameter_message(payload[position:], direction)
        if decoded is None:
            break
        message, consumed = decoded
        if consumed <= 0:
            raise EmulatorInputError("Diameter decoder returned an invalid message length")
        messages.append(message)
        if len(messages) > PACKET_MAX_COUNT:
            raise EmulatorInputError(
                f"a TCP segment cannot contain more than {PACKET_MAX_COUNT} Diameter messages"
            )
        position += consumed
    return messages, payload[position:]


def _diameter_avps_tcl(avps: list[dict[str, Any]]) -> str:
    records = []
    for avp in avps:
        fields = [
            str(avp.get("code", 0)),
            str(avp.get("flags", 0)),
            str(avp.get("vendor_id", 0)),
            str(avp.get("data_hex", "")),
        ]
        # Braces group the inner list for the outer list; the quoted fields
        # remain Tcl list delimiters when the inner value is lindex'ed.
        records.append("{" + " ".join(_tcl_quote(field) for field in fields) + "}")
    return " ".join(records)


def _radius_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise EmulatorInputError(f"RADIUS {field} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value, 10)
    else:
        raise EmulatorInputError(f"RADIUS {field} must be an integer")
    if not 0 <= parsed <= maximum:
        raise EmulatorInputError(f"RADIUS {field} must be between 0 and {maximum}")
    return parsed


def _radius_hex(value: Any, field: str) -> bytes:
    text = _require_string(value, f"RADIUS {field}")
    if len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", text):
        raise EmulatorInputError(f"RADIUS {field} must be an even-length hexadecimal string")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:  # pragma: no cover - regex guards this path
        raise EmulatorInputError(f"RADIUS {field} is not valid hexadecimal") from exc


def _radius_attr_code(value: Any, field: str) -> int:
    if isinstance(value, str):
        key = value.lower().replace("_", "-")
        if key in RADIUS_AUTH_ATTRIBUTE_CODES:
            return RADIUS_AUTH_ATTRIBUTE_CODES[key]
    return _radius_uint(value, field, 255)


def _radius_attr_data(value: dict[str, Any], index: int) -> tuple[bytes, str]:
    supplied = [field for field in ("data", "data_hex", "data_base64") if field in value]
    if len(supplied) > 1:
        raise EmulatorInputError(
            f"RADIUS attribute {index} must specify only one of data, data_hex, or data_base64"
        )
    if not supplied:
        return b"", "octet"
    source = supplied[0]
    if source == "data_hex":
        return _radius_hex(value[source], f"attribute {index} data_hex"), "octet"
    if source == "data_base64":
        encoded = _require_string(value[source], f"RADIUS attribute {index} data_base64")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise EmulatorInputError(
                f"RADIUS attribute {index} data_base64 is not valid base64"
            ) from exc
        return data, "octet"

    raw = _require_string(value[source], f"RADIUS attribute {index} data")
    data_type = str(value.get("type", "string")).lower()
    if data_type in {"integer", "unsigned32"}:
        return _radius_uint(raw, f"attribute {index} data", 0xFFFF_FFFF).to_bytes(4, "big"), "integer"
    if data_type in {"integer64", "unsigned64"}:
        return _radius_uint(raw, f"attribute {index} data", 0xFFFF_FFFF_FFFF_FFFF).to_bytes(8, "big"), "integer64"
    if data_type == "ip4":
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise EmulatorInputError(f"RADIUS attribute {index} data is not an IP address") from exc
        if address.version != 4:
            raise EmulatorInputError(f"RADIUS attribute {index} requires an IPv4 address")
        return address.packed, "ip4"
    if data_type == "ip6":
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise EmulatorInputError(f"RADIUS attribute {index} data is not an IP address") from exc
        if address.version != 6:
            raise EmulatorInputError(f"RADIUS attribute {index} requires an IPv6 address")
        return address.packed, "ip6"
    if data_type in {"hex", "octet", "raw"} and re.fullmatch(r"[0-9a-fA-F]*", raw) and len(raw) % 2 == 0:
        return bytes.fromhex(raw), "octet"
    try:
        return raw.encode("utf-8"), "string"
    except UnicodeEncodeError as exc:
        raise EmulatorInputError(f"RADIUS attribute {index} data must be valid UTF-8") from exc


def _radius_normalise_avps(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EmulatorInputError("RADIUS avps must be an array")
    if len(raw) > PACKET_MAX_COUNT:
        raise EmulatorInputError(f"RADIUS avps cannot contain more than {PACKET_MAX_COUNT} entries")
    allowed = {"code", "vendor_id", "vendor_type", "data", "data_hex", "data_base64", "type"}
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EmulatorInputError(f"RADIUS attribute {index} must be an object")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"unsupported RADIUS attribute {index} field(s): {', '.join(unknown)}"
            )
        if "code" not in item:
            raise EmulatorInputError(f"RADIUS attribute {index} requires code")
        code = _radius_attr_code(item["code"], f"attribute {index} code")
        vendor_id = _radius_uint(item.get("vendor_id", 0), f"attribute {index} vendor_id", 0xFFFF_FFFF)
        vendor_type = _radius_uint(item.get("vendor_type", 0), f"attribute {index} vendor_type", 255)
        if vendor_id or vendor_type:
            if code != RADIUS_VENDOR_SPECIFIC:
                raise EmulatorInputError(
                    f"RADIUS attribute {index} vendor fields require code 26 (Vendor-Specific)"
                )
        data, inferred_type = _radius_attr_data(item, index)
        header_length = 8 if code == RADIUS_VENDOR_SPECIFIC else 2
        if header_length + len(data) > 255:
            raise EmulatorInputError(f"RADIUS attribute {index} exceeds the 255-byte attribute limit")
        result.append(
            {
                "code": code,
                "vendor_id": vendor_id,
                "vendor_type": vendor_type,
                "data": _decode_wire_text(data),
                "data_hex": data.hex(),
                "type": str(item.get("type", inferred_type)),
                "_data": data,
            }
        )
    return result


def _radius_encode_avp(avp: dict[str, Any]) -> bytes:
    code = _radius_attr_code(avp["code"], "attribute code")
    vendor_id = _radius_uint(avp.get("vendor_id", 0), "attribute vendor_id", 0xFFFF_FFFF)
    vendor_type = _radius_uint(avp.get("vendor_type", 0), "attribute vendor_type", 255)
    data = avp.get("_data")
    if not isinstance(data, bytes):
        data, _ = _radius_attr_data(avp, 0)
    if code == RADIUS_VENDOR_SPECIFIC:
        if not vendor_id or not vendor_type:
            raise EmulatorInputError("RADIUS Vendor-Specific attributes require vendor_id and vendor_type")
        data = vendor_id.to_bytes(4, "big") + bytes([vendor_type, len(data) + 2]) + data
    elif vendor_id or vendor_type:
        raise EmulatorInputError("RADIUS vendor fields require attribute code 26")
    length = RADIUS_ATTRIBUTE_HEADER_LENGTH + len(data)
    if length > 255:
        raise EmulatorInputError("RADIUS attribute length exceeds the one-byte wire limit")
    return bytes([code, length]) + data


def _radius_encode_message(packet: dict[str, Any]) -> bytes:
    code = _radius_uint(packet.get("code", RADIUS_AUTH_REQUEST), "code", 255)
    identifier = _radius_uint(packet.get("id", 0), "id", 255)
    authenticator = packet.get("_radius_authenticator")
    if not isinstance(authenticator, bytes):
        authenticator = _radius_hex(packet.get("authenticator_hex", "00" * RADIUS_AUTHENTICATOR_BYTES), "authenticator_hex")
    if len(authenticator) != RADIUS_AUTHENTICATOR_BYTES:
        raise EmulatorInputError("RADIUS authenticator must contain exactly 16 bytes")
    attrs = packet.get("_radius_avps", packet.get("avps", []))
    if not isinstance(attrs, list):
        raise EmulatorInputError("RADIUS avps must be an array")
    payload = b"".join(_radius_encode_avp(avp) for avp in attrs)
    length = RADIUS_HEADER_LENGTH + len(payload)
    if length > RADIUS_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("RADIUS message exceeds the 4096-byte wire limit")
    return bytes([code, identifier]) + length.to_bytes(2, "big") + authenticator + payload


def _radius_parsed_avp(code: int, vendor_id: int, vendor_type: int, data: bytes) -> dict[str, Any]:
    if code in {4, 8} and len(data) == 4:
        data_type = "ip4"
        value: Any = str(ipaddress.ip_address(data))
    elif len(data) == 4 and code in {5, 6, 27, 40, 42, 43, 46, 47, 55, 61}:
        data_type = "integer"
        value = str(int.from_bytes(data, "big"))
    elif len(data) == 8 and code in {42, 43}:
        data_type = "integer64"
        value = str(int.from_bytes(data, "big"))
    else:
        data_type = "string"
        value = _decode_wire_text(data)
    return {
        "code": code,
        "vendor_id": vendor_id,
        "vendor_type": vendor_type,
        "data": value,
        "data_hex": data.hex(),
        "type": data_type,
        "_data": data,
    }


def _decode_radius_message(payload: bytes, direction: str) -> tuple[dict[str, Any], int] | None:
    if not payload:
        return None
    if len(payload) < RADIUS_HEADER_LENGTH:
        return None
    code = payload[0]
    identifier = payload[1]
    length = int.from_bytes(payload[2:4], "big")
    if length < RADIUS_HEADER_LENGTH or length > RADIUS_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("RADIUS message length is invalid")
    if len(payload) < length:
        return None
    message = bytes(payload[:length])
    attrs: list[dict[str, Any]] = []
    cursor = RADIUS_HEADER_LENGTH
    while cursor < length:
        if length - cursor < RADIUS_ATTRIBUTE_HEADER_LENGTH:
            raise EmulatorInputError("RADIUS attribute header is truncated")
        attr_code = message[cursor]
        attr_length = message[cursor + 1]
        if attr_length < RADIUS_ATTRIBUTE_HEADER_LENGTH or cursor + attr_length > length:
            raise EmulatorInputError("RADIUS attribute length is invalid")
        data = message[cursor + RADIUS_ATTRIBUTE_HEADER_LENGTH : cursor + attr_length]
        vendor_id = 0
        vendor_type = 0
        if attr_code == RADIUS_VENDOR_SPECIFIC:
            if len(data) < 6 or data[5] < 2 or 4 + data[5] != len(data):
                raise EmulatorInputError("RADIUS Vendor-Specific attribute is invalid")
            vendor_id = int.from_bytes(data[:4], "big")
            vendor_type = data[4]
            data = data[6 : 4 + data[5]]
        attrs.append(_radius_parsed_avp(attr_code, vendor_id, vendor_type, data))
        cursor += attr_length
    return {
        "protocol": "radius",
        "direction": direction,
        "code": code,
        "id": identifier,
        "authenticator_hex": message[4:20].hex(),
        "avps": attrs,
        "payload_hex": message[20:].hex(),
        "message_hex": message.hex(),
        "message": _decode_wire_text(message),
        "message_length": length,
        "_radius_avps": attrs,
        "_radius_authenticator": message[4:20],
        "_wire_payload": message,
    }, length


def _decode_radius_datagram(payload: bytes, direction: str) -> dict[str, Any]:
    decoded = _decode_radius_message(payload, direction)
    if decoded is None or decoded[1] != len(payload):
        raise EmulatorInputError("a UDP RADIUS datagram must contain exactly one complete message")
    return decoded[0]


def _radius_avps_tcl(avps: list[dict[str, Any]]) -> str:
    records = []
    for avp in avps:
        fields = [
            str(avp.get("code", 0)),
            str(avp.get("vendor_id", 0)),
            str(avp.get("vendor_type", 0)),
            str(avp.get("type", "string")),
            str(avp.get("data_hex", "")),
        ]
        records.append("{" + " ".join(_tcl_quote(field) for field in fields) + "}")
    return " ".join(records)


def _gtp_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise EmulatorInputError(f"GTP {field} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        parsed = int(value, 10)
    else:
        raise EmulatorInputError(f"GTP {field} must be an integer")
    if not 0 <= parsed <= maximum:
        raise EmulatorInputError(f"GTP {field} must be between 0 and {maximum}")
    return parsed


def _gtp_hex(value: Any, field: str) -> bytes:
    text = _require_string(value, f"GTP {field}")
    if len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]*", text):
        raise EmulatorInputError(f"GTP {field} must be an even-length hexadecimal string")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:  # pragma: no cover - regex guards this path
        raise EmulatorInputError(f"GTP {field} is not valid hexadecimal") from exc


def _gtp_normalise_ies(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise EmulatorInputError("GTP ies must be an array")
    if len(raw) > PACKET_MAX_COUNT:
        raise EmulatorInputError(f"GTP ies cannot contain more than {PACKET_MAX_COUNT} entries")
    allowed = {"type", "instance", "data", "data_hex", "data_base64"}
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EmulatorInputError(f"GTP IE {index} must be an object")
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise EmulatorInputError(f"unsupported GTP IE {index} field(s): {', '.join(unknown)}")
        ie_type = _gtp_uint(item.get("type"), f"IE {index} type", 255)
        instance = _gtp_uint(item.get("instance", 0), f"IE {index} instance", 15)
        sources = [key for key in ("data", "data_hex", "data_base64") if key in item]
        if len(sources) > 1:
            raise EmulatorInputError(f"GTP IE {index} must specify only one data source")
        if not sources:
            data = b""
        elif sources[0] == "data_hex":
            data = _gtp_hex(item["data_hex"], f"IE {index} data_hex")
        elif sources[0] == "data_base64":
            encoded = _require_string(item["data_base64"], f"GTP IE {index} data_base64")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise EmulatorInputError(f"GTP IE {index} data_base64 is not valid base64") from exc
        else:
            raw_data = _require_string(item["data"], f"GTP IE {index} data")
            try:
                data = raw_data.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise EmulatorInputError(f"GTP IE {index} data must be valid UTF-8") from exc
        if len(data) > 0xFFFF:
            raise EmulatorInputError(f"GTP IE {index} exceeds the 65535-byte length limit")
        result.append(
            {
                "type": ie_type,
                "instance": instance,
                "data": _decode_wire_text(data),
                "data_hex": data.hex(),
                "_data": data,
            }
        )
    return result


def _gtp_encode_ies(ies: list[dict[str, Any]], version: int) -> bytes:
    encoded: list[bytes] = []
    for index, item in enumerate(ies):
        ie_type = _gtp_uint(item.get("type"), f"IE {index} type", 255)
        instance = _gtp_uint(item.get("instance", 0), f"IE {index} instance", 15)
        data = item.get("_data")
        if not isinstance(data, bytes):
            if "data_hex" in item:
                data = _gtp_hex(item["data_hex"], f"IE {index} data_hex")
            else:
                data = _require_string(item.get("data", ""), f"GTP IE {index} data").encode("utf-8")
        if version == GTP_VERSION_2:
            encoded.append(bytes([ie_type]) + len(data).to_bytes(2, "big") + bytes([instance]) + data)
        else:
            encoded.append(bytes([ie_type]) + len(data).to_bytes(2, "big") + data)
    return b"".join(encoded)


def _gtp_encode_message(packet: dict[str, Any]) -> bytes:
    version = _gtp_uint(packet.get("version", GTP_VERSION_2), "version", 2)
    if version not in {GTP_VERSION_1, GTP_VERSION_2}:
        raise EmulatorInputError("GTP version must be 1 or 2")
    message_type = _gtp_uint(packet.get("type", 1), "type", 255)
    teid = _gtp_uint(packet.get("teid", 0), "teid", 0xFFFF_FFFF)
    sequence = _gtp_uint(
        packet.get("sequence", 0), "sequence", 0xFFFF if version == GTP_VERSION_1 else 0xFFFFFF
    )
    npdu = _gtp_uint(packet.get("npdu", 0), "npdu", 255)
    payload = packet.get("_gtp_payload")
    if not isinstance(payload, bytes):
        if "payload_hex" in packet:
            payload = _gtp_hex(packet["payload_hex"], "payload_hex")
        else:
            payload = _require_string(packet.get("payload", ""), "GTP payload").encode("utf-8")
    if len(payload) > GTP_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("GTP payload exceeds the 2 MiB message limit")
    body = payload if message_type == GTP_GPDU_TYPE else _gtp_encode_ies(packet.get("_gtp_ies", packet.get("ies", [])), version)
    if version == GTP_VERSION_1:
        flags = 0x32
        rest = teid.to_bytes(4, "big") + sequence.to_bytes(2, "big") + bytes([npdu, 0]) + body
        message = bytes([flags, message_type]) + (len(rest) - 4).to_bytes(2, "big") + rest
    else:
        flags = 0x48 if teid else 0x40
        if teid:
            header = bytes([flags, message_type]) + (0).to_bytes(2, "big") + teid.to_bytes(4, "big")
        else:
            header = bytes([flags, message_type]) + (0).to_bytes(2, "big")
        header += sequence.to_bytes(3, "big") + b"\x00"
        message = header + body
        message = message[:2] + (len(message) - 4).to_bytes(2, "big") + message[4:]
    if len(message) > GTP_MAX_WIRE_MESSAGE_BYTES:
        raise EmulatorInputError("GTP message exceeds the 16-bit wire length limit")
    return message


def _gtp_parsed_ie(ie_type: int, instance: int, data: bytes) -> dict[str, Any]:
    return {
        "type": ie_type,
        "instance": instance,
        "data": _decode_wire_text(data),
        "data_hex": data.hex(),
        "_data": data,
    }


def _decode_gtp_message(payload: bytes, direction: str) -> tuple[dict[str, Any], int] | None:
    if not payload:
        return None
    if len(payload) < GTP_HEADER_MIN_BYTES:
        return None
    flags = payload[0]
    version = (flags >> 5) & 0x07
    if version not in {GTP_VERSION_1, GTP_VERSION_2}:
        raise EmulatorInputError("GTP version is not 1 or 2")
    message_type = payload[1]
    declared_length = int.from_bytes(payload[2:4], "big")
    total_length = declared_length + (8 if version == GTP_VERSION_1 else 4)
    if total_length < GTP_HEADER_MIN_BYTES or total_length > GTP_MAX_MESSAGE_BYTES:
        raise EmulatorInputError("GTP message length is invalid")
    if len(payload) < total_length:
        return None
    message = bytes(payload[:total_length])
    if version == GTP_VERSION_1:
        teid = int.from_bytes(message[4:8], "big")
        offset = 8
        sequence = 0
        npdu = 0
        if flags & 0x07:
            if total_length < 12:
                raise EmulatorInputError("GTPv1 optional header is truncated")
            sequence = int.from_bytes(message[8:10], "big")
            npdu = message[10]
            offset = 12
    else:
        teid_present = bool(flags & 0x08)
        if teid_present:
            if total_length < 12:
                raise EmulatorInputError("GTPv2 header is truncated")
            teid = int.from_bytes(message[4:8], "big")
            sequence = int.from_bytes(message[8:11], "big")
            offset = 12
        else:
            teid = 0
            sequence = int.from_bytes(message[4:7], "big")
            offset = 8
        npdu = 0
    body = message[offset:]
    ies: list[dict[str, Any]] = []
    payload_bytes = b""
    if message_type == GTP_GPDU_TYPE:
        payload_bytes = body
    else:
        cursor = 0
        ie_header = 4 if version == GTP_VERSION_2 else 3
        while cursor < len(body):
            if len(body) - cursor < ie_header:
                raise EmulatorInputError("GTP IE header is truncated")
            ie_type = body[cursor]
            ie_length = int.from_bytes(body[cursor + 1:cursor + 3], "big")
            end = cursor + ie_header + ie_length
            if end > len(body):
                raise EmulatorInputError("GTP IE length is invalid")
            instance = body[cursor + 3] & 0x0F if version == GTP_VERSION_2 else 0
            data_start = cursor + ie_header
            ies.append(_gtp_parsed_ie(ie_type, instance, body[data_start:end]))
            cursor = end
    return {
        "protocol": "gtp",
        "direction": direction,
        "version": version,
        "type": message_type,
        "teid": teid,
        "sequence": sequence,
        "npdu": npdu,
        "length": declared_length,
        "ies": ies,
        "payload": _decode_wire_text(payload_bytes),
        "payload_hex": payload_bytes.hex(),
        "payload_length": len(payload_bytes),
        "message": _decode_wire_text(message),
        "message_length": total_length,
        "message_hex": message.hex(),
        "_gtp_ies": ies,
        "_gtp_payload": payload_bytes,
        "_wire_payload": message,
    }, total_length


def _decode_gtp_datagram(payload: bytes, direction: str) -> dict[str, Any]:
    decoded = _decode_gtp_message(payload, direction)
    if decoded is None or decoded[1] != len(payload):
        raise EmulatorInputError("a UDP GTP datagram must contain exactly one complete message")
    return decoded[0]


def _gtp_ies_tcl(ies: list[dict[str, Any]]) -> str:
    return " ".join(
        "{" + " ".join(_tcl_quote(str(item)) for item in (ie.get("type", 0), ie.get("instance", 0), ie.get("data_hex", ""))) + "}"
        for ie in ies
    )


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
        if protocol == "tcp" and "payload" in packet and "payload_hex" in packet:
            raise EmulatorInputError(
                f"packet {index} TCP packets must use payload or payload_hex, not both"
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
            if field == "headers" and protocol == "sip":
                normalised[field] = _sip_header_pairs(packet[field], f"packet {index} headers")
            elif field == "avps" and protocol == "diameter":
                normalised[field] = _diameter_normalise_avps(packet[field])
                normalised["_diameter_avps"] = normalised[field]
            elif field == "avps" and protocol == "radius":
                normalised[field] = _radius_normalise_avps(packet[field])
                normalised["_radius_avps"] = normalised[field]
            elif field in {"headers", "response_headers"}:
                value = packet[field]
                if not isinstance(value, dict) or not all(
                    isinstance(key, str) and isinstance(item, str) for key, item in value.items()
                ):
                    raise EmulatorInputError(f"packet {index} {field} must be an object of strings")
                normalised[field] = value
            elif field in {"body", "response_body", "method", "uri", "host"}:
                normalised[field] = _require_string(packet[field], f"packet {index} {field}")
            elif field == "http2":
                normalised[field] = _normalise_http2_state(
                    packet[field], f"packet {index} http2"
                )
            elif protocol == "tcp" and field == "payload_hex":
                value = _require_string(packet[field], f"packet {index} payload_hex")
                if len(value) % 2:
                    raise EmulatorInputError(
                        f"packet {index} payload_hex must contain complete bytes"
                    )
                try:
                    payload_bytes = bytes.fromhex(value)
                except ValueError as exc:
                    raise EmulatorInputError(
                        f"packet {index} payload_hex must be hexadecimal"
                    ) from exc
                if len(payload_bytes) > STREAM_MAX_BYTES:
                    raise EmulatorInputError(
                        f"packet {index} TCP payload exceeds {STREAM_MAX_BYTES} bytes"
                    )
                normalised[field] = payload_bytes.hex()
                normalised["_wire_payload"] = payload_bytes
            elif protocol == "http2" and field == "payload_hex":
                value = _require_string(packet[field], f"packet {index} payload_hex")
                if len(value) % 2:
                    raise EmulatorInputError(
                        f"packet {index} payload_hex must contain complete bytes"
                    )
                try:
                    payload_bytes = bytes.fromhex(value)
                except ValueError as exc:
                    raise EmulatorInputError(
                        f"packet {index} payload_hex must be hexadecimal"
                    ) from exc
                if len(payload_bytes) > 2 * 1024 * 1024:
                    raise EmulatorInputError(
                        f"packet {index} HTTP/2 payload exceeds 2097152 bytes"
                    )
                normalised[field] = payload_bytes.hex()
                normalised["_http2_payload"] = payload_bytes
            elif field in {"fin", "masked"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "tls" and field in {"sni_required", "disabled"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "tls" and field in {"cipher_bits", "cert_count", "verify_result"}:
                normalised[field] = _dns_uint(
                    packet[field], f"packet {index} {field}",
                    0xFFFF_FFFF if field == "verify_result" else 65535,
                )
            elif protocol == "tls" and field == "cert_mode":
                mode = _require_string(packet[field], f"packet {index} cert_mode").lower()
                if mode not in {"ignore", "request", "require"}:
                    raise EmulatorInputError(
                        f"packet {index} cert_mode must be ignore, request, or require"
                    )
                normalised[field] = mode
            elif field == "type":
                if protocol == "gtp":
                    normalised[field] = _gtp_uint(
                        packet[field], f"packet {index} type", 255
                    )
                    continue
                packet_type = _require_string(packet[field], f"packet {index} type").lower()
                if protocol == "tls":
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
                elif protocol == "websocket":
                    if packet_type not in {"request", "response", "frame"}:
                        raise EmulatorInputError(
                            f"unsupported WebSocket packet type: {packet_type}"
                        )
                elif protocol == "mqtt":
                    packet_type = packet_type.upper()
                    if packet_type not in MQTT_PACKET_TYPES.values():
                        raise EmulatorInputError(
                            f"unsupported MQTT packet type: {packet_type}"
                        )
                elif protocol == "sip":
                    if packet_type not in {"request", "response"}:
                        raise EmulatorInputError(
                            f"unsupported SIP packet type: {packet_type}"
                        )
                elif protocol == "diameter":
                    if packet_type not in {"request", "response"}:
                        raise EmulatorInputError(
                            f"unsupported Diameter packet type: {packet_type}"
                        )
                normalised[field] = packet_type
            elif protocol == "diameter" and field in {
                "version",
                "command_code",
                "application_id",
                "hop_by_hop_id",
                "end_to_end_id",
            }:
                maximum = 0xFF if field == "version" else (
                    0xFF_FFFF if field == "command_code" else 0xFFFF_FFFF
                )
                normalised[field] = _diameter_uint(
                    packet[field], f"packet {index} {field}", maximum
                )
            elif protocol == "diameter" and field in {"rflag", "pflag", "eflag", "tflag"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "diameter" and field in {"message_hex", "payload_hex"}:
                normalised[field] = _require_string(
                    packet[field], f"packet {index} {field}"
                )
            elif protocol == "mr" and field == "fields":
                value = packet[field]
                if not isinstance(value, dict) or not all(
                    isinstance(key, str) and isinstance(item, (bool, str, int, float))
                    for key, item in value.items()
                ):
                    raise EmulatorInputError(
                        f"packet {index} fields must be an object of scalar values"
                    )
                normalised[field] = {
                    key: _packet_scalar(item, f"packet {index} fields.{key}")
                    for key, item in value.items()
                }
            elif protocol == "mr" and field in {
                "proto",
                "payload_hex",
                "peer",
                "route_status",
                "route",
            }:
                normalised[field] = _require_string(
                    packet[field], f"packet {index} {field}"
                )
            elif protocol == "gtp" and field in {"type", "message_type"}:
                normalised["type"] = _gtp_uint(
                    packet[field], f"packet {index} {field}", 255
                )
            elif protocol == "gtp" and field in {
                "version",
                "teid",
                "sequence",
                "npdu",
            }:
                normalised[field] = _gtp_uint(
                    packet[field], f"packet {index} {field}",
                    2 if field == "version" else (255 if field == "npdu" else (0xFFFFFF if field == "sequence" else 0xFFFFFFFF)),
                )
            elif protocol == "gtp" and field == "ies":
                normalised[field] = _gtp_normalise_ies(packet[field])
                normalised["_gtp_ies"] = normalised[field]
            elif protocol == "gtp" and field in {"message_hex", "payload_hex"}:
                normalised[field] = _require_string(
                    packet[field], f"packet {index} {field}"
                )
            else:
                normalised[field] = _packet_scalar(packet[field], f"packet {index} {field}")

        if wire_payload is not None:
            normalised["_wire_payload"] = wire_payload

        if protocol == "tls" and "type" not in normalised:
            raise EmulatorInputError(f"packet {index} TLS packets require type")
        if protocol == "http2" and "_http2_payload" not in normalised:
            raise EmulatorInputError(f"packet {index} HTTP/2 packets require payload_hex")
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
        if protocol == "websocket":
            packet_type = normalised.get("type")
            if packet_type is None:
                raise EmulatorInputError(f"packet {index} WebSocket packets require type")
            if packet_type == "request":
                if direction != "client_to_server":
                    raise EmulatorInputError(
                        f"packet {index} WebSocket requests must be client_to_server"
                    )
                if "headers" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} WebSocket requests require headers"
                    )
            elif packet_type == "response":
                if direction != "server_to_client":
                    raise EmulatorInputError(
                        f"packet {index} WebSocket responses must be server_to_client"
                    )
                if "response_headers" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} WebSocket responses require response_headers"
                    )
                try:
                    status = int(normalised.get("status", "101"))
                except (TypeError, ValueError) as exc:
                    raise EmulatorInputError(
                        f"packet {index} WebSocket response status must be an integer"
                    ) from exc
                if not 100 <= status <= 999:
                    raise EmulatorInputError(
                        f"packet {index} WebSocket response status must be between 100 and 999"
                    )
                normalised.setdefault("status", "101")
            else:
                if "frame_type" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} WebSocket frames require frame_type"
                    )
                frame_type = normalised["frame_type"].lower()
                if frame_type not in WEBSOCKET_FRAME_TYPES:
                    raise EmulatorInputError(
                        f"unsupported WebSocket frame type: {frame_type}"
                    )
                normalised["frame_type"] = frame_type
                if "fin" not in normalised:
                    normalised["fin"] = "1"
                if "masked" not in normalised:
                    normalised["masked"] = "1" if direction == "client_to_server" else "0"
        if protocol == "dns":
            for section in ("answers", "authority", "additional"):
                normalised[section] = _dns_normalise_records(
                    packet.get(section, []), f"packet {index} {section}"
                )
            normalised["qname"] = _require_string(
                packet.get("qname", ""), f"packet {index} qname"
            )
            normalised["qtype"] = _require_string(
                packet.get("qtype", "A"), f"packet {index} qtype"
            ).upper()
            normalised["qclass"] = _require_string(
                packet.get("qclass", "IN"), f"packet {index} qclass"
            ).upper()
            normalised.setdefault("qr", direction == "server_to_client")
            normalised.setdefault("rcode", 0)
            normalised.setdefault("opcode", 0)
            normalised.setdefault("id", 0)
            for flag in ("aa", "tc", "rd", "ra", "cd", "ad"):
                normalised.setdefault(flag, 1 if flag == "rd" else 0)
            normalised["rcode"] = _dns_uint(normalised["rcode"], f"packet {index} rcode", 15)
            normalised["opcode"] = _dns_uint(normalised["opcode"], f"packet {index} opcode", 15)
            normalised["id"] = _dns_uint(normalised["id"], f"packet {index} id", 65535)
            normalised["qr"] = _packet_bool(normalised["qr"], f"packet {index} qr")
            for flag in ("aa", "tc", "rd", "ra", "cd", "ad"):
                normalised[flag] = _packet_bool(normalised[flag], f"packet {index} {flag}")
            normalised.setdefault("qdcount", 1)
            normalised.setdefault("ancount", len(normalised["answers"]))
            normalised.setdefault("nscount", len(normalised["authority"]))
            normalised.setdefault("arcount", len(normalised["additional"]))
            for field in ("qdcount", "ancount", "nscount", "arcount"):
                normalised[field] = _dns_uint(normalised[field], f"packet {index} {field}", 65535)
            normalised.setdefault(
                "ptype",
                _dns_packet_type(
                    normalised["qr"] == "1",
                    normalised["rcode"],
                    normalised["answers"],
                    normalised["authority"],
                ),
            )
            normalised["ptype"] = _require_string(
                normalised["ptype"], f"packet {index} ptype"
            ).upper()
            normalised.setdefault("message_length", 0)
            normalised["message_length"] = _dns_uint(
                normalised["message_length"], f"packet {index} message_length", 0xFFFF
            )
            for field in ("disabled", "dropped", "response_sent"):
                normalised.setdefault(field, "0")
                normalised[field] = _packet_bool(normalised[field], f"packet {index} {field}")
            normalised.setdefault("last_act", "")
            normalised["edns0"] = _dns_normalise_edns0(
                packet.get("edns0"), f"packet {index} edns0"
            )
            normalised["rpz_policy"] = _require_string(
                packet.get("rpz_policy", ""), f"packet {index} rpz_policy"
            )
            raw_wideips = packet.get("wideips", [])
            if not isinstance(raw_wideips, list):
                raise EmulatorInputError(f"packet {index} wideips must be an array")
            normalised["wideips"] = [
                _require_string(value, f"packet {index} wideips entry")
                for value in raw_wideips
            ]
        if protocol == "mqtt":
            packet_type = normalised.get("type")
            if packet_type is None:
                raise EmulatorInputError(f"packet {index} MQTT packets require type")
            valid_types = (
                MQTT_CLIENT_PACKET_TYPES
                if direction == "client_to_server"
                else MQTT_SERVER_PACKET_TYPES
            )
            if packet_type not in valid_types:
                side = "client" if direction == "client_to_server" else "server"
                raise EmulatorInputError(
                    f"packet {index} MQTT {side} direction cannot carry {packet_type}"
                )
            if packet_type == "PUBLISH" and "topic" not in normalised:
                raise EmulatorInputError(f"packet {index} MQTT PUBLISH packets require topic")
            if packet_type in {"CONNECT", "PUBLISH"} and "payload" not in normalised:
                normalised.setdefault("payload", "")
            payload = normalised.get("payload", "")
            try:
                normalised["_mqtt_payload"] = payload.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise EmulatorInputError(f"packet {index} MQTT payload must be valid UTF-8") from exc
            normalised["_wire_payload"] = _encode_mqtt_message(normalised)
        if protocol == "sip":
            packet_type = normalised.get("type")
            if packet_type is None:
                raise EmulatorInputError(f"packet {index} SIP packets require type")
            transport = normalised.get("transport", "tcp").lower()
            if transport not in {"tcp", "udp"}:
                raise EmulatorInputError(
                    f"packet {index} SIP transport must be tcp or udp"
                )
            normalised["transport"] = transport
            if "message" in normalised:
                try:
                    raw_message = normalised["message"].encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise EmulatorInputError(
                        f"packet {index} SIP message must be valid UTF-8"
                    ) from exc
                decoded = _decode_sip_message(raw_message, direction)
                if decoded is None or decoded[1] != len(raw_message):
                    raise EmulatorInputError(
                        f"packet {index} SIP message must contain exactly one complete message"
                    )
                parsed, _ = decoded
                if parsed["type"] != packet_type:
                    raise EmulatorInputError(
                        f"packet {index} SIP type does not match its start line"
                    )
                normalised.update(parsed)
            else:
                if packet_type == "request":
                    if "method" not in normalised or "uri" not in normalised:
                        raise EmulatorInputError(
                            f"packet {index} SIP requests require method and uri"
                        )
                elif "status" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} SIP responses require status"
                    )
                normalised["_wire_payload"] = _encode_sip_message(normalised)
                parsed, _ = _decode_sip_message(normalised["_wire_payload"], direction)
                if parsed is None:  # pragma: no cover - encoder contract guard
                    raise EmulatorInputError(
                        f"packet {index} SIP encoder produced an incomplete message"
                    )
                normalised.update(parsed)
        if protocol == "diameter":
            if "message_hex" in normalised and (
                "avps" in normalised or "payload_hex" in normalised
            ):
                raise EmulatorInputError(
                    f"packet {index} Diameter message_hex cannot be combined with avps or payload_hex"
                )
            if "avps" in normalised and "payload_hex" in normalised:
                raise EmulatorInputError(
                    f"packet {index} Diameter avps cannot be combined with payload_hex"
                )
            if "type" not in normalised:
                normalised["type"] = "request"
            if "rflag" not in normalised:
                normalised["rflag"] = normalised["type"] == "request"
            if "message_hex" in normalised:
                raw_message = _diameter_hex(normalised["message_hex"], f"packet {index} message_hex")
                decoded = _decode_diameter_message(raw_message, direction)
                if decoded is None or decoded[1] != len(raw_message):
                    raise EmulatorInputError(
                        f"packet {index} Diameter message_hex must contain exactly one complete message"
                    )
                parsed, _ = decoded
                if parsed["type"] != normalised["type"]:
                    raise EmulatorInputError(
                        f"packet {index} Diameter type does not match its request flag"
                    )
                normalised.update(parsed)
            else:
                if "avps" not in normalised:
                    normalised["avps"] = []
                    normalised["_diameter_avps"] = []
                normalised["_wire_payload"] = _diameter_encode_message(normalised)
                parsed, _ = _decode_diameter_message(normalised["_wire_payload"], direction)
                if parsed is None:  # pragma: no cover - encoder contract guard
                    raise EmulatorInputError(
                        f"packet {index} Diameter encoder produced an incomplete message"
                    )
                normalised.update(parsed)
        if protocol == "radius":
            if "message_hex" in normalised and (
                "avps" in normalised or "payload_hex" in normalised
            ):
                raise EmulatorInputError(
                    f"packet {index} RADIUS message_hex cannot be combined with avps or payload_hex"
                )
            if "avps" in normalised and "payload_hex" in normalised:
                raise EmulatorInputError(
                    f"packet {index} RADIUS avps cannot be combined with payload_hex"
                )
            if "message_hex" in normalised:
                raw_message = _radius_hex(normalised["message_hex"], f"packet {index} message_hex")
                decoded = _decode_radius_message(raw_message, direction)
                if decoded is None or decoded[1] != len(raw_message):
                    raise EmulatorInputError(
                        f"packet {index} RADIUS message_hex must contain exactly one complete message"
                    )
                normalised.update(decoded[0])
            else:
                normalised.setdefault("code", RADIUS_AUTH_REQUEST)
                normalised.setdefault("id", 0)
                normalised.setdefault(
                    "authenticator_hex", "00" * RADIUS_AUTHENTICATOR_BYTES
                )
                normalised.setdefault("avps", [])
                normalised.setdefault("_radius_avps", [])
                normalised["_wire_payload"] = _radius_encode_message(normalised)
                parsed = _decode_radius_message(normalised["_wire_payload"], direction)
                if parsed is None:  # pragma: no cover - encoder contract guard
                    raise EmulatorInputError(
                        f"packet {index} RADIUS encoder produced an incomplete message"
                    )
                normalised.update(parsed[0])
        if protocol == "mr":
            if "payload" in normalised and "payload_hex" in normalised:
                raise EmulatorInputError(
                    f"packet {index} MR payload cannot be combined with payload_hex"
                )
            proto = str(normalised.get("proto", "generic")).lower()
            if proto not in {"generic", "sip", "diameter"}:
                raise EmulatorInputError(
                    f"packet {index} MR proto must be generic, sip, or diameter"
                )
            packet_type = str(normalised.get("type", "request")).lower()
            if packet_type not in {"request", "response"}:
                raise EmulatorInputError(
                    f"packet {index} MR type must be request or response"
                )
            if "payload_hex" in normalised:
                payload = _radius_hex(normalised["payload_hex"], f"packet {index} payload_hex")
            else:
                try:
                    payload = str(normalised.get("payload", "")).encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise EmulatorInputError(
                        f"packet {index} MR payload must be valid UTF-8"
                    ) from exc
            if len(payload) > STREAM_MAX_BYTES:
                raise EmulatorInputError(
                    f"packet {index} MR payload exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            normalised["proto"] = proto
            normalised["type"] = packet_type
            normalised.setdefault("fields", {})
            normalised.setdefault("peer", "")
            normalised.setdefault("route_status", "unrouted")
            normalised.setdefault("route", "")
            normalised["payload"] = _decode_wire_text(payload)
            normalised["payload_length"] = len(payload)
            normalised["_mr_payload"] = payload
        if protocol == "gtp":
            if "type" in packet and "message_type" in packet:
                packet_type = _gtp_uint(packet["type"], f"packet {index} type", 255)
                message_type = _gtp_uint(
                    packet["message_type"], f"packet {index} message_type", 255
                )
                if packet_type != message_type:
                    raise EmulatorInputError(
                        f"packet {index} type and message_type must match"
                    )
            if "message_hex" in normalised and any(
                field in normalised for field in ("ies", "payload", "payload_hex")
            ):
                raise EmulatorInputError(
                    f"packet {index} GTP message_hex cannot be combined with ies or payload"
                )
            if "payload" in normalised and "payload_hex" in normalised:
                raise EmulatorInputError(
                    f"packet {index} GTP payload cannot be combined with payload_hex"
                )
            if "type" not in normalised and any(
                field in normalised for field in ("payload", "payload_hex")
            ):
                normalised["type"] = GTP_GPDU_TYPE
            message_type = normalised.get("type", 1)
            if message_type == GTP_GPDU_TYPE and packet.get("ies"):
                raise EmulatorInputError(
                    f"packet {index} GTP G-PDU cannot contain information elements"
                )
            if message_type != GTP_GPDU_TYPE and any(
                field in packet for field in ("payload", "payload_hex")
            ):
                raise EmulatorInputError(
                    f"packet {index} non-G-PDU GTP messages cannot contain payload"
                )
            if "message_hex" in normalised:
                raw_message = _gtp_hex(normalised["message_hex"], f"packet {index} message_hex")
                decoded = _decode_gtp_message(raw_message, direction)
                if decoded is None or decoded[1] != len(raw_message):
                    raise EmulatorInputError(
                        f"packet {index} GTP message_hex must contain exactly one complete message"
                    )
                normalised.update(decoded[0])
            else:
                normalised.setdefault("version", GTP_VERSION_2)
                normalised.setdefault("type", 1)
                normalised.setdefault("teid", 0)
                normalised.setdefault("sequence", 0)
                normalised.setdefault("npdu", 0)
                normalised.setdefault("ies", [])
                normalised.setdefault("_gtp_ies", [])
                if "payload_hex" in normalised:
                    payload = _gtp_hex(normalised["payload_hex"], f"packet {index} payload_hex")
                else:
                    try:
                        payload = str(normalised.get("payload", "")).encode("utf-8")
                    except UnicodeEncodeError as exc:
                        raise EmulatorInputError(
                            f"packet {index} GTP payload must be valid UTF-8"
                        ) from exc
                if len(payload) > GTP_MAX_MESSAGE_BYTES:
                    raise EmulatorInputError("GTP payload exceeds the 2 MiB message limit")
                normalised["payload"] = _decode_wire_text(payload)
                normalised["_gtp_payload"] = payload
                normalised["_wire_payload"] = _gtp_encode_message(normalised)
                decoded = _decode_gtp_message(normalised["_wire_payload"], direction)
                if decoded is None:  # pragma: no cover - encoder contract guard
                    raise EmulatorInputError(
                        f"packet {index} GTP encoder produced an incomplete message"
                    )
                normalised.update(decoded[0])
            normalised["message_type"] = normalised["type"]
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
    http_release = _http_release_snapshot(session)
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
        "http2": _http2_snapshot(session),
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
    if http_release.get("requested", "0") == "1":
        result["http_release"] = True
    if str(http_close_requested) == "1":
        result["http_close"] = True
    return result


def _configure_http2_state(
    session: Any, metadata: dict[str, Any] | None, request: dict[str, Any]
) -> None:
    """Install one deterministic HTTP/2 transaction description in Tcl."""
    state = {
        "active": False,
        "version": 0,
        "stream_id": 0,
        "stream_priority": 0,
        "concurrency": 0,
        "requests": 0,
        "enabled": True,
        "clientside_enabled": True,
        "serverside_enabled": True,
        "disconnected": False,
        "discarded": False,
        "pseudo_headers": {},
    }
    if metadata:
        state.update(metadata)
    if state["active"]:
        state["version"] = state["version"] or 2
        pseudo_headers = dict(state["pseudo_headers"])
        pseudo_headers.setdefault(":method", request.get("method", "GET"))
        pseudo_headers.setdefault(":path", request.get("uri", "/"))
        pseudo_headers.setdefault(":scheme", "https")
        if request.get("host"):
            pseudo_headers.setdefault(":authority", request["host"])
        state["pseudo_headers"] = pseudo_headers
        if state["requests"] == 0:
            state["requests"] = 1
    values: list[str] = []
    for field in (
        "active", "version", "stream_id", "stream_priority", "concurrency",
        "requests", "enabled", "clientside_enabled", "serverside_enabled",
        "disconnected", "discarded",
    ):
        value = state[field]
        values.append("1" if isinstance(value, bool) and value else "0" if isinstance(value, bool) else str(value))
    pairs: list[str] = []
    for name, header_value in state["pseudo_headers"].items():
        pairs.extend((name, header_value))
    encoded_headers = _tcl_list(pairs)
    session.eval_tcl(
        "::itest::semantic::http2_set_pending "
        + " ".join(_tcl_quote(value) for value in values)
        + " "
        + encoded_headers
    )


def _http2_snapshot(session: Any) -> dict[str, Any]:
    fields = (
        "active", "version", "stream_id", "stream_priority", "concurrency",
        "requests", "enabled", "clientside_enabled", "serverside_enabled",
        "disconnected", "discarded",
    )
    snapshot: dict[str, Any] = {}
    for field in fields:
        value = session.eval_tcl(f"set ::state::http2::{field}")
        snapshot[field] = value
    raw_headers = _split_tcl_list(
        session.eval_tcl("set ::state::http2::pseudo_headers")
    )
    snapshot["pseudo_headers"] = {
        raw_headers[index]: raw_headers[index + 1]
        for index in range(0, len(raw_headers) - 1, 2)
    }
    return snapshot


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
        source, profiles, pools, resolvers, datagroups = _normalise_scenario_config(
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
        self._resolvers = resolvers
        self._datagroups = datagroups
        self._fidelity = _analyze_rule_capabilities(root, source, profiles)
        incompatible = [
            warning
            for warning in self._fidelity.get("warnings", [])
            if warning.get("code") == "version-incompatible"
        ]
        if incompatible:
            names = sorted(
                {
                    str(item.get("command") or item.get("event"))
                    for item in incompatible
                }
            )
            raise EmulatorInputError(
                "scenario uses iRule features introduced after TMOS 17.5: "
                + ", ".join(names)
            )
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
        self._http2_decoder: Http2ConnectionDecoder | None = None
        self._http2_streams: dict[int, dict[str, Any]] = {}
        self._http2_tcp_active = False
        self._websocket_raw_active = False
        self._mqtt_raw_active = any(
            str(profile).upper() == "MQTT" for profile in self._profiles
        )
        self._sip_raw_active = any(
            str(profile).upper() in {"SIP", "SIPROUTER", "SIPSESSION"}
            for profile in self._profiles
        )
        self._diameter_raw_active = any(
            str(profile).upper() in {"DIAMETER", "DIAMETERSESSION", "DIAMETER_ENDPOINT", "MR"}
            for profile in self._profiles
        )
        self._radius_raw_active = any(
            str(profile).upper() in {"RADIUS", "RADIUS_AAA"} for profile in self._profiles
        )
        self._gtp_raw_active = any(str(profile).upper() == "GTP" for profile in self._profiles)
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
                session.eval_tcl("::itest::semantic::resolver_clear")
                for name, records in self._resolvers.items():
                    session.eval_tcl(
                        "::itest::semantic::resolver_set "
                        f"{_tcl_quote(name)} {_tcl_quote(_dns_records_tcl(records))}"
                    )
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
                session.eval_tcl("::itest::semantic::prepare_http_release")
                session.eval_tcl("::itest::semantic::prepare_http_close")
                session.eval_tcl("set ::itest::semantic::automatic_http_flow 1")
                try:
                    _configure_http2_state(session, kwargs.get("http2"), kwargs)
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
                        session.eval_tcl("::itest::semantic::http2_clear_pending")
                finally:
                    session.eval_tcl(
                        "unset -nocomplain ::itest::semantic::automatic_http_flow"
                    )

                decision_history.extend(result.get("decisions", []))
                log_history.extend(result.get("logs", []))
                retry = result.pop("http_retry", None)
                http_close = bool(result.pop("http_close", False))
                http2_disconnected = result.get("http2", {}).get("disconnected") == "1"
                self._connection_open = True
                if not retry:
                    http_close_requested = http_close or http2_disconnected
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
                if "http2" in original_kwargs:
                    retry_kwargs.setdefault("http2", original_kwargs["http2"])
                kwargs = retry_kwargs
        finally:
            session.eval_tcl(
                "unset -nocomplain ::itest::semantic::automatic_http_flow"
            )
            session.eval_tcl("::itest::semantic::clear_lb_failure")
            session.eval_tcl("::itest::semantic::prepare_http_retry")
            session.eval_tcl("::itest::semantic::prepare_http_release")
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
                if layer in {"websocket", "mqtt", "sip", "diameter", "radius", "mr", "gtp"} and field in {"payload", "message", "authenticator"}:
                    # Structured packet payloads are JSON text at the API
                    # boundary, but WS::payload offsets are wire-byte based.
                    # Install UTF-8 bytes as a Tcl byte array so the
                    # tcl-lsp payload helpers preserve those offsets.
                    if isinstance(value, (bytes, bytearray)):
                        payload_hex = bytes(value).hex()
                    else:
                        payload_hex = str(value).encode("utf-8").hex()
                    session.eval_tcl(
                        f"set {namespace}::{field} [binary format H* {_tcl_quote(payload_hex)}]"
                    )
                else:
                    session.eval_tcl(f"set {namespace}::{field} {_tcl_quote(value)}")
        if "dns" in state:
            session.eval_tcl("::itest::semantic::dns_prepare_message")
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        event_result = session.fire_event(event_name)
        if "sip" in state:
            session.eval_tcl("::itest::semantic::sip_rebuild_message")
        if "diameter" in state:
            session.eval_tcl("::itest::semantic::diameter_rebuild_message")
        if "radius" in state:
            session.eval_tcl("::itest::semantic::radius_rebuild_message")
        if "gtp" in state:
            session.eval_tcl("::itest::semantic::gtp_rebuild_message")
        fired_events = _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
        state_snapshot: dict[str, dict[str, Any]] = {}
        for layer in state:
            state_snapshot[layer] = {}
            for field in EVENT_STATE_FIELDS[layer]:
                if layer == "dns" and field in {"answers", "authority", "additional"}:
                    state_snapshot[layer][field] = session.eval_tcl(
                        f"::itest::semantic::dns_snapshot_section {field}"
                    )
                else:
                    state_snapshot[layer][field] = session.eval_tcl(
                        f"set {EVENT_STATE_NAMESPACES[layer]}::{field}"
                    )
        if "dns" in state:
            try:
                dns_wire = _dns_encode_message(state_snapshot["dns"])
            except EmulatorInputError as exc:
                state_snapshot["dns"]["message_hex"] = ""
                state_snapshot["dns"]["message_encoding_error"] = str(exc)
            else:
                state_snapshot["dns"]["message_hex"] = dns_wire.hex()
                state_snapshot["dns"]["message_length"] = str(len(dns_wire))
        result = {
            "event": event_name,
            "fired": bool(event_result.fired),
            "reason": event_result.reason,
            "events_fired": fired_events[fired_before:],
            "state": state_snapshot,
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
        emissions.extend(self._websocket_disconnect_emissions(session, event_name))
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
        if protocol == "sip" and packet.get("transport", "tcp") == "udp":
            connection.update({"protocol": "17", "transport": "udp"})
        elif protocol in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr"}:
            connection.update({"protocol": "6", "transport": "tcp"})
        elif protocol in {"udp", "dns", "radius"}:
            connection.update({"protocol": "17", "transport": "udp"})
        elif protocol == "gtp":
            endpoints = {
                source.get("port"),
                destination.get("port"),
            }
            transport = "tcp" if GTP_PRIME_PORT in endpoints else "udp"
            connection.update(
                {"protocol": "6" if transport == "tcp" else "17", "transport": transport}
            )
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
                "sni_required",
                "cipher_name",
                "cipher_bits",
                "cipher_version",
                "cipher_clientlist",
                "cert_subject",
                "cert_issuer",
                "cert_serial",
                "cert_hash",
                "cert_count",
                "cert_mode",
                "verify_result",
                "disabled",
                "extensions",
                "alpn",
                "session_id",
            ):
                if field in packet:
                    tls_state[field] = _packet_scalar(packet[field], field)
            if packet.get("type") in {"handshake", "server_handshake"}:
                tls_state["handshake_done"] = "1"
            if tls_state:
                state[layer] = tls_state
        elif protocol == "http" and "http2" in packet:
            http2_state: dict[str, str] = {}
            metadata = packet["http2"]
            for field in EVENT_STATE_FIELDS["http2"]:
                if field not in metadata:
                    continue
                value = metadata[field]
                if field == "pseudo_headers":
                    pairs: list[str] = []
                    for name, header_value in value.items():
                        pairs.extend((name, header_value))
                    http2_state[field] = " ".join(_tcl_quote(item) for item in pairs)
                else:
                    http2_state[field] = _packet_scalar(value, field)
            state["http2"] = http2_state
        elif protocol == "dns":
            dns_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["dns"]:
                if field in packet:
                    if field in {"answers", "authority", "additional"}:
                        dns_state[field] = _dns_records_tcl(packet[field])
                    elif field == "wideips":
                        dns_state[field] = _tcl_list(packet[field])
                    elif field == "edns0":
                        dns_state[field] = _dns_edns0_tcl(packet[field])
                    else:
                        dns_state[field] = _packet_scalar(packet[field], field)
            if dns_state:
                state["dns"] = dns_state
        elif protocol == "websocket":
            websocket_state: dict[str, str] = {}
            packet_type = packet.get("type")
            if packet_type == "request":
                headers = packet.get("headers", {})
                websocket_state["request_headers"] = _tcl_list(
                    [item for pair in headers.items() for item in pair]
                )
                websocket_state["method"] = packet.get("method", "GET")
                websocket_state["uri"] = packet.get("uri", "/")
                websocket_state["host"] = packet.get(
                    "host", _websocket_header_value(headers, "Host")
                )
            elif packet_type == "response":
                headers = packet.get("response_headers", {})
                websocket_state["response_headers"] = _tcl_list(
                    [item for pair in headers.items() for item in pair]
                )
                if "status" in packet:
                    websocket_state["status"] = str(packet["status"])
            elif packet_type == "frame":
                payload = packet.get("payload", "")
                wire_payload = packet.get("_wire_payload")
                if not isinstance(wire_payload, (bytes, bytearray)):
                    wire_payload = payload.encode("utf-8")
                websocket_state.update(
                    {
                        "frame_type": packet["frame_type"],
                        "eom": packet.get("fin", "1"),
                        "orig_masked": packet.get("masked", "0"),
                        "mask": packet.get("mask", ""),
                        "payload": bytes(wire_payload),
                        "payload_length": str(len(wire_payload)),
                    }
                )
            if websocket_state:
                state["websocket"] = websocket_state
        elif protocol == "mqtt":
            mqtt_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["mqtt"]:
                if field in packet:
                    mqtt_state[field] = _packet_scalar(packet[field], field)
            wire_payload = packet.get("_mqtt_payload")
            if not isinstance(wire_payload, (bytes, bytearray)):
                payload = packet.get("payload", "")
                wire_payload = payload.encode("utf-8")
            mqtt_state["payload"] = bytes(wire_payload)
            mqtt_state["payload_length"] = str(len(wire_payload))
            message = packet.get("_wire_payload")
            if not isinstance(message, (bytes, bytearray)):
                message = _encode_mqtt_message(packet)
            mqtt_state["message"] = bytes(message)
            mqtt_state["message_length"] = str(len(message))
            state["mqtt"] = mqtt_state
        elif protocol == "sip":
            sip_state: dict[str, str] = {}
            # Raw SIP TCP messages are synthesized from a generic TCP packet,
            # so make the transport explicit before installing Tcl state.
            sip_state["transport"] = str(packet.get("transport", "tcp"))
            for field in EVENT_STATE_FIELDS["sip"]:
                if field in packet:
                    if field == "headers":
                        headers = _sip_header_pairs(packet[field])
                        # This value is assigned to a Tcl variable by
                        # _fire_event_on_worker, so it must be a list value,
                        # not a braced single-word Tcl command argument.
                        sip_state[field] = " ".join(
                            _tcl_quote(item) for pair in headers for item in pair
                        )
                    else:
                        sip_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_sip_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            sip_state["payload"] = bytes(payload)
            sip_state["payload_length"] = str(len(payload))
            message = packet.get("message")
            wire_message = packet.get("_wire_payload")
            if not isinstance(wire_message, (bytes, bytearray)):
                wire_message = (
                    _encode_sip_message(packet)
                    if message is None
                    else str(message).encode("utf-8")
                )
            if message is None:
                message = _decode_wire_text(bytes(wire_message))
            sip_state["message"] = message
            sip_state["message_length"] = str(len(wire_message))
            state["sip"] = sip_state
        elif protocol == "diameter":
            diameter_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["diameter"]:
                if field not in packet:
                    continue
                if field == "avps":
                    diameter_state[field] = _diameter_avps_tcl(
                        packet.get("_diameter_avps", packet[field])
                    )
                elif field in {"payload", "message"}:
                    diameter_state[field] = packet[field]
                else:
                    diameter_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_diameter_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = _diameter_hex(packet.get("payload_hex", ""), "payload_hex")
            diameter_state["payload"] = bytes(payload)
            diameter_state["payload_length"] = str(len(payload))
            message = packet.get("_diameter_message")
            if not isinstance(message, (bytes, bytearray)):
                message = packet.get("_wire_payload")
            if not isinstance(message, (bytes, bytearray)):
                message = _diameter_encode_message(packet)
            diameter_state["message"] = bytes(message)
            diameter_state["message_length"] = str(len(message))
            state["diameter"] = diameter_state
        elif protocol == "radius":
            radius_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["radius"]:
                if field not in packet:
                    continue
                if field in {"payload", "message", "authenticator"}:
                    radius_state[field] = packet[field]
                elif field == "attributes":
                    radius_state[field] = _radius_avps_tcl(
                        packet.get("_radius_avps", packet.get("avps", []))
                    )
                else:
                    radius_state[field] = _packet_scalar(packet[field], field)
            radius_state["attributes"] = _radius_avps_tcl(
                packet.get("_radius_avps", packet.get("avps", []))
            )
            payload = packet.get("_radius_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = _radius_hex(packet.get("payload_hex", ""), "payload_hex")
            radius_state["payload"] = bytes(payload)
            radius_state["payload_length"] = str(len(payload))
            message = packet.get("_radius_message")
            if not isinstance(message, (bytes, bytearray)):
                message = packet.get("_wire_payload")
            if not isinstance(message, (bytes, bytearray)):
                message = _radius_encode_message(packet)
            radius_state["message"] = bytes(message)
            radius_state["message_length"] = str(len(message))
            radius_state["authenticator"] = _radius_hex(
                packet.get("authenticator_hex", "00" * RADIUS_AUTHENTICATOR_BYTES),
                "authenticator_hex",
            )
            state["radius"] = radius_state
        elif protocol == "gtp":
            gtp_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["gtp"]:
                if field not in packet:
                    continue
                if field in {"payload", "message"}:
                    gtp_state[field] = packet[field]
                elif field == "ies":
                    gtp_state[field] = _gtp_ies_tcl(
                        packet.get("_gtp_ies", packet.get("ies", []))
                    )
                else:
                    gtp_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_gtp_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = _gtp_hex(packet.get("payload_hex", ""), "payload_hex")
            gtp_state["payload"] = bytes(payload)
            gtp_state["payload_length"] = str(len(payload))
            message = packet.get("_wire_payload")
            if not isinstance(message, (bytes, bytearray)):
                message = _gtp_encode_message(packet)
            gtp_state["message"] = bytes(message)
            gtp_state["message_length"] = str(len(message))
            state["gtp"] = gtp_state
        elif protocol == "mr":
            fields = packet.get("fields", {})
            message_state: dict[str, str] = {
                "proto": str(packet.get("proto", "generic")),
                "type": str(packet.get("type", "request")),
                "fields": " ".join(
                    _tcl_quote(str(item))
                    for key, value in fields.items()
                    for item in (key, value)
                ),
            }
            state["message"] = message_state
            mr_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["mr"]:
                if field in packet:
                    mr_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_mr_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            mr_state["payload"] = bytes(payload)
            mr_state["payload_length"] = str(len(payload))
            state["mr"] = mr_state
        return state

    def _current_sip_event_state(
        self, session: Any, packet: dict[str, Any]
    ) -> dict[str, dict[str, str]]:
        """Build event input from the mutable SIP state after an earlier phase."""
        state: dict[str, dict[str, str]] = {
            "connection": self._packet_connection_state(packet),
            "sip": {},
        }
        sip_state = state["sip"]
        for field in EVENT_STATE_FIELDS["sip"]:
            raw = session.eval_tcl(f"set ::state::sip::{field}")
            if field == "headers":
                values = _split_tcl_list(raw)
                if len(values) % 2:
                    raise EmulatorInputError("invalid SIP header state")
                sip_state[field] = " ".join(_tcl_quote(value) for value in values)
            elif field in {"payload", "message"}:
                sip_state[field] = raw
            else:
                sip_state[field] = raw
        return state

    def _current_diameter_event_state(
        self, session: Any, packet: dict[str, Any]
    ) -> dict[str, dict[str, str]]:
        """Build a Diameter event state from the mutable Tcl message."""
        state: dict[str, dict[str, str]] = {
            "connection": self._packet_connection_state(packet),
            "diameter": {},
        }
        diameter_state = state["diameter"]
        for field in EVENT_STATE_FIELDS["diameter"]:
            raw = session.eval_tcl(f"set ::state::diameter::{field}")
            diameter_state[field] = raw
        return state

    def _current_mr_event_state(
        self, session: Any, packet: dict[str, Any]
    ) -> dict[str, dict[str, str]]:
        """Build a Message Routing Framework event from mutable Tcl state."""
        state: dict[str, dict[str, str]] = {
            "connection": self._packet_connection_state(packet),
            "message": {},
            "mr": {},
        }
        for field in EVENT_STATE_FIELDS["message"]:
            state["message"][field] = session.eval_tcl(f"set ::state::message::{field}")
        for field in EVENT_STATE_FIELDS["mr"]:
            if field == "payload":
                payload_hex = session.eval_tcl(
                    "binary encode hex $::state::mr::payload"
                )
                state["mr"][field] = bytes.fromhex(str(payload_hex))
            else:
                state["mr"][field] = session.eval_tcl(f"set ::state::mr::{field}")
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

    @staticmethod
    def _websocket_disconnect_emissions(
        session: Any, event_name: str
    ) -> list[dict[str, Any]]:
        if event_name not in {"WS_CLIENT_FRAME_DONE", "WS_SERVER_FRAME_DONE"}:
            return []
        raw = _split_tcl_list(
            session.eval_tcl("::itest::semantic::ws_take_disconnect_snapshot")
        )
        if len(raw) % 2:
            raise EmulatorInputError("invalid WebSocket disconnect state")
        values = dict(zip(raw[::2], raw[1::2]))
        if values.get("requested") != "1":
            return []
        try:
            code = int(values["code"])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError("invalid WebSocket disconnect code") from None
        reason = values.get("reason", "")
        try:
            reason_bytes = reason.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EmulatorInputError("WebSocket close reason must be valid UTF-8") from exc
        close_payload = code.to_bytes(2, "big") + reason_bytes
        if len(close_payload) > 125:
            raise EmulatorInputError("WebSocket close payload exceeds the control-frame limit")
        emissions: list[dict[str, Any]] = []
        for target_side, direction in (
            ("client", "server_to_client"),
            ("server", "client_to_server"),
        ):
            emissions.append(
                {
                    "protocol": "websocket",
                    "type": "frame",
                    "frame_type": "close",
                    "side": target_side,
                    "direction": direction,
                    "fin": "1",
                    "masked": "1" if direction == "client_to_server" else "0",
                    "mask": "",
                    "close_code": code,
                    "close_reason": reason,
                    "payload_hex": close_payload.hex(),
                    "byte_length": len(close_payload),
                    "control": "CLOSE",
                }
            )
        return emissions

    def _decode_http2_packet(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        if self._http2_decoder is None:
            try:
                self._http2_decoder = Http2ConnectionDecoder()
            except Http2DecodeError as exc:
                raise EmulatorInputError(str(exc)) from exc
        payload = packet.get("_http2_payload", b"")
        try:
            return self._http2_decoder.feed(payload, packet["direction"])
        except Http2DecodeError as exc:
            raise EmulatorInputError(f"invalid HTTP/2 packet: {exc}") from exc

    @staticmethod
    def _http2_trace_event(event: dict[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in event.items() if key != "data"}
        data = event.get("data")
        if isinstance(data, (bytes, bytearray)):
            result["payload_hex"] = bytes(data).hex()
            result["byte_length"] = len(data)
        return result

    def _consume_http2_event(
        self, session: Any, event: dict[str, Any]
    ) -> dict[str, Any] | None:
        stream_id = int(event["stream_id"])
        if stream_id == 0:
            return None
        context = self._http2_streams.setdefault(
            stream_id,
            {
                "request_headers": None,
                "request_body": bytearray(),
                "request_end": False,
                "response_headers": None,
                "response_body": bytearray(),
                "response_end": False,
                "priority": 0,
            },
        )
        direction = event["direction"]
        if event["kind"] == "headers":
            pseudo_headers = dict(event["pseudo_headers"])
            if direction == "client_to_server":
                if context["request_headers"] is not None:
                    raise EmulatorInputError(
                        f"HTTP/2 stream {stream_id} has duplicate request headers"
                    )
                if ":method" not in pseudo_headers or ":path" not in pseudo_headers:
                    raise EmulatorInputError(
                        f"HTTP/2 request stream {stream_id} is missing :method or :path"
                    )
                context["request_headers"] = {
                    "method": pseudo_headers[":method"],
                    "uri": pseudo_headers[":path"],
                    "host": pseudo_headers.get(":authority", ""),
                    "headers": dict(event["headers"]),
                }
                context["request_pseudo_headers"] = pseudo_headers
                context["request_end"] = bool(event["end_stream"])
                context["priority"] = int(event.get("priority", 0))
            else:
                if context["response_headers"] is not None:
                    raise EmulatorInputError(
                        f"HTTP/2 stream {stream_id} has duplicate response headers"
                    )
                status = pseudo_headers.get(":status")
                if status is None or not status.isdigit() or not 100 <= int(status) <= 999:
                    raise EmulatorInputError(
                        f"HTTP/2 response stream {stream_id} has an invalid :status"
                    )
                context["response_headers"] = {
                    "status": int(status),
                    "headers": dict(event["headers"]),
                }
                context["response_end"] = bool(event["end_stream"])
                context["response_pseudo_headers"] = pseudo_headers
        elif event["kind"] == "data":
            if direction == "client_to_server":
                if context["request_headers"] is None:
                    raise EmulatorInputError(
                        f"HTTP/2 DATA arrived before request headers on stream {stream_id}"
                    )
                context["request_body"].extend(event["data"])
                context["request_end"] = bool(event["end_stream"])
            else:
                if context["response_headers"] is None:
                    raise EmulatorInputError(
                        f"HTTP/2 DATA arrived before response headers on stream {stream_id}"
                    )
                context["response_body"].extend(event["data"])
                context["response_end"] = bool(event["end_stream"])
        if not context["request_end"] or not context["response_end"]:
            return None
        request = dict(context["request_headers"])
        request["body"] = _decode_wire_text(bytes(context["request_body"]))
        request["response_status"] = context["response_headers"]["status"]
        request["response_headers"] = context["response_headers"]["headers"]
        request["response_body"] = _decode_wire_text(bytes(context["response_body"]))
        request["http2"] = {
            "active": True,
            "version": 2,
            "stream_id": stream_id,
            "stream_priority": context["priority"],
            "concurrency": len(self._http2_streams),
            "requests": self._connection_request_number + 1,
            "pseudo_headers": context["request_pseudo_headers"],
        }
        result = self._run_request_on_worker(session, request)
        self._http2_streams.pop(stream_id, None)
        return result

    def _configure_packet_connection(self, session: Any, packet: dict[str, Any]) -> None:
        """Make packet endpoints visible to the upstream HTTP orchestrator."""
        if packet["protocol"] not in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr", "gtp"}:
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
        if self._connection_open or packet["protocol"] not in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr", "gtp"}:
            return
        self._configure_packet_connection(session, packet)
        session.eval_tcl("::itest::semantic::ws_reset_connection")
        session.eval_tcl("::itest::semantic::mqtt_reset_connection")
        session.eval_tcl("::itest::semantic::sip_reset_connection")
        session.eval_tcl("::itest::semantic::diameter_reset_connection")
        session.eval_tcl("::itest::semantic::mr_reset_connection")
        session.eval_tcl("::itest::semantic::gtp_reset_connection")
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
        self._http2_decoder = None
        self._http2_streams.clear()
        self._http2_tcp_active = False
        self._tcp_buffers = {"client": "", "server": ""}
        self._websocket_raw_active = False
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

    @staticmethod
    def _http2_tcp_packet(packet: dict[str, Any], payload: bytes) -> dict[str, Any]:
        merged = dict(packet)
        merged["protocol"] = "http2"
        merged["payload_hex"] = payload.hex()
        merged["_http2_payload"] = payload
        merged.pop("payload", None)
        merged.pop("_wire_payload", None)
        return merged

    @staticmethod
    def _looks_like_mqtt_prefix(payload: bytes) -> bool:
        if not payload or payload[0] >> 4 not in MQTT_PACKET_TYPES:
            return False
        return True

    @staticmethod
    def _looks_like_sip_prefix(payload: bytes) -> bool:
        if payload.startswith(b"SIP/2.0 "):
            return True
        methods = (
            b"ACK",
            b"BYE",
            b"CANCEL",
            b"INFO",
            b"INVITE",
            b"MESSAGE",
            b"NOTIFY",
            b"OPTIONS",
            b"PRACK",
            b"PUBLISH",
            b"REFER",
            b"REGISTER",
            b"SUBSCRIBE",
            b"UPDATE",
        )
        return any(
            method.startswith(payload) or payload.startswith(method + b" ")
            for method in methods
        )

    @staticmethod
    def _looks_like_diameter_prefix(payload: bytes) -> bool:
        return bool(payload) and payload[0] == 1

    @staticmethod
    def _looks_like_gtp_prefix(payload: bytes) -> bool:
        return bool(payload) and ((payload[0] >> 5) & 0x07) in {GTP_VERSION_1, GTP_VERSION_2}

    def _reassemble_packet(
        self, packet: dict[str, Any], packet_index: int
    ) -> tuple[dict[str, Any] | None, int]:
        """Join application payloads until a complete HTTP/TLS message is visible.

        Raw TCP packets carry sequence numbers, so gaps are held, overlaps are
        de-duplicated, and retransmissions do not fire application events twice.
        Structured packets without sequence numbers retain the original append-
        in-arrival-order behavior.
        """
        if packet["protocol"] == "udp" and self._sip_raw_active:
            raw_payload = packet.get("_wire_payload")
            if raw_payload is None and packet.get("payload"):
                raw_payload = packet["payload"].encode("utf-8")
            if raw_payload and self._looks_like_sip_prefix(raw_payload):
                decoded = _decode_sip_message(raw_payload, packet["direction"])
                if decoded is None or decoded[1] != len(raw_payload):
                    raise EmulatorInputError(
                        "a UDP SIP datagram must contain exactly one complete message"
                    )
                merged, _ = decoded
                merged["transport"] = "udp"
                for field in ("source", "destination", "timestamp"):
                    if field in packet:
                        merged[field] = packet[field]
                return merged, 0
        if packet["protocol"] == "udp" and self._radius_raw_active:
            source_port = packet.get("source", {}).get("port")
            destination_port = packet.get("destination", {}).get("port")
            if 1812 in {source_port, destination_port} or 1813 in {source_port, destination_port}:
                raw_payload = packet.get("_wire_payload")
                if raw_payload:
                    merged = _decode_radius_datagram(raw_payload, packet["direction"])
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            merged[field] = packet[field]
                    return merged, 0
        if packet["protocol"] == "udp" and self._gtp_raw_active:
            source_port = packet.get("source", {}).get("port")
            destination_port = packet.get("destination", {}).get("port")
            if {GTP_SIGNALING_PORT, GTP_USER_PLANE_PORT}.intersection(
                {source_port, destination_port}
            ):
                raw_payload = packet.get("_wire_payload")
                if raw_payload:
                    merged = _decode_gtp_datagram(raw_payload, packet["direction"])
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            merged[field] = packet[field]
                    return merged, 0
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
        if self._http2_tcp_active:
            stream.buffer = b""
            if not has_gap:
                stream.segments.clear()
            return self._http2_tcp_packet(packet, combined), len(combined)
        if packet["direction"] == "client_to_server":
            if combined.startswith(HTTP2_CLIENT_PREFACE):
                self._http2_tcp_active = True
                stream.buffer = b""
                if not has_gap:
                    stream.segments.clear()
                return self._http2_tcp_packet(packet, combined), len(combined)
            if HTTP2_CLIENT_PREFACE.startswith(combined):
                stream.buffer = combined
                if not has_gap:
                    stream.segments.clear()
                return None, stream.buffered_bytes
        if self._websocket_raw_active:
            decoded_frames, remaining = _decode_websocket_frames(
                combined, packet["direction"]
            )
            if decoded_frames:
                stream.buffer = remaining
                if not has_gap:
                    stream.segments.clear()
                for frame in decoded_frames:
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            frame[field] = packet[field]
                first = decoded_frames[0]
                if len(decoded_frames) > 1:
                    first["_coalesced_packets"] = decoded_frames[1:]
                return first, len(combined) - len(remaining)
            stream.buffer = combined
            if not has_gap:
                stream.segments.clear()
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            return None, stream.buffered_bytes
        looks_like_mqtt = self._mqtt_raw_active and self._looks_like_mqtt_prefix(combined)
        if looks_like_mqtt:
            decoded_messages, remaining = _decode_mqtt_messages(
                combined, packet["direction"]
            )
            if decoded_messages:
                stream.buffer = remaining
                if not has_gap:
                    stream.segments.clear()
                for message in decoded_messages:
                    message["transport"] = "tcp"
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            message[field] = packet[field]
                first = decoded_messages[0]
                if len(decoded_messages) > 1:
                    first["_coalesced_packets"] = decoded_messages[1:]
                return first, len(combined) - len(remaining)
            stream.buffer = combined
            if not has_gap:
                stream.segments.clear()
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            return None, stream.buffered_bytes
        looks_like_sip = self._sip_raw_active and self._looks_like_sip_prefix(combined)
        if looks_like_sip:
            decoded_messages, remaining = _decode_sip_messages(
                combined, packet["direction"]
            )
            if decoded_messages:
                stream.buffer = remaining
                if not has_gap:
                    stream.segments.clear()
                for message in decoded_messages:
                    message["transport"] = "tcp"
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            message[field] = packet[field]
                first = decoded_messages[0]
                if len(decoded_messages) > 1:
                    first["_coalesced_packets"] = decoded_messages[1:]
                return first, len(combined) - len(remaining)
            stream.buffer = combined
            if not has_gap:
                stream.segments.clear()
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            return None, stream.buffered_bytes
        looks_like_diameter = self._diameter_raw_active and self._looks_like_diameter_prefix(combined)
        if looks_like_diameter:
            decoded_messages, remaining = _decode_diameter_messages(
                combined, packet["direction"]
            )
            if decoded_messages:
                stream.buffer = remaining
                if not has_gap:
                    stream.segments.clear()
                for message in decoded_messages:
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            message[field] = packet[field]
                first = decoded_messages[0]
                if len(decoded_messages) > 1:
                    first["_coalesced_packets"] = decoded_messages[1:]
                return first, len(combined) - len(remaining)
            stream.buffer = combined
            if not has_gap:
                stream.segments.clear()
            if stream.buffered_bytes > STREAM_MAX_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError(
                    f"packet stream exceeds the {STREAM_MAX_BYTES // (1024 * 1024)} MiB limit"
                )
            return None, stream.buffered_bytes
        looks_like_gtp = self._gtp_raw_active and GTP_PRIME_PORT in {
            packet.get("source", {}).get("port"),
            packet.get("destination", {}).get("port"),
        } and self._looks_like_gtp_prefix(combined)
        if looks_like_gtp:
            decoded_messages: list[dict[str, Any]] = []
            remaining = combined
            consumed_total = 0
            while self._looks_like_gtp_prefix(remaining):
                decoded_result = _decode_gtp_message(remaining, packet["direction"])
                if decoded_result is None:
                    break
                decoded, consumed = decoded_result
                if consumed <= 0 or consumed > len(remaining):
                    raise EmulatorInputError("GTP decoder returned an invalid frame length")
                decoded_messages.append(decoded)
                remaining = remaining[consumed:]
                consumed_total += consumed
            if decoded_messages:
                stream.buffer = remaining
                if not has_gap:
                    stream.segments.clear()
                for message in decoded_messages:
                    for field in ("source", "destination", "timestamp"):
                        if field in packet:
                            message[field] = packet[field]
                first = decoded_messages[0]
                if len(decoded_messages) > 1:
                    first["_coalesced_packets"] = decoded_messages[1:]
                return first, consumed_total
            stream.buffer = combined
            if not has_gap:
                stream.segments.clear()
            if stream.buffered_bytes > GTP_MAX_MESSAGE_BYTES:
                self._packet_streams.pop(key, None)
                raise EmulatorInputError("GTP stream exceeds the 2 MiB message limit")
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
            decoded_packets: list[dict[str, Any]] = []
            remaining = combined
            consumed_total = 0
            while self._looks_like_http_prefix(remaining):
                decoded_result = _decode_http_payload(remaining, packet["direction"])
                if decoded_result is None:
                    break
                decoded, consumed = decoded_result
                if consumed <= 0 or consumed > len(remaining):
                    raise EmulatorInputError("HTTP decoder returned an invalid frame length")
                merged = dict(packet)
                merged.update(decoded)
                merged.pop("_wire_payload", None)
                decoded_packets.append(merged)
                remaining = remaining[consumed:]
                consumed_total += consumed
            if decoded_packets:
                stream.buffer = remaining
                first = decoded_packets[0]
                if (
                    first.get("protocol") == "http"
                    and first.get("status") == 101
                    and _websocket_response_is_upgrade(first)
                    and remaining
                ):
                    websocket_frames, websocket_remaining = _decode_websocket_frames(
                        remaining, packet["direction"]
                    )
                    if websocket_frames:
                        stream.buffer = websocket_remaining
                        for frame in websocket_frames:
                            for field in ("source", "destination", "timestamp"):
                                if field in packet:
                                    frame[field] = packet[field]
                        first["_coalesced_packets"] = websocket_frames
                if stream.buffer != remaining:
                    remaining = stream.buffer
                if len(decoded_packets) > 1:
                    first.setdefault("_coalesced_packets", []).extend(decoded_packets[1:])
                return first, consumed_total
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

        packet_queue = list(enumerate(packets))
        queue_index = 0
        while queue_index < len(packet_queue):
            index, original_packet = packet_queue[queue_index]
            queue_index += 1
            packet = original_packet
            packet, buffered_bytes = self._reassemble_packet(packet, index)
            if packet is not None:
                coalesced_packets = packet.pop("_coalesced_packets", [])
                if coalesced_packets:
                    packet_queue[queue_index:queue_index] = [
                        (index, coalesced) for coalesced in coalesced_packets
                    ]
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
            if packet["protocol"] == "http":
                if (
                    packet["direction"] == "client_to_server"
                    and _websocket_request_is_upgrade(packet)
                ):
                    packet = dict(packet)
                    packet["protocol"] = "websocket"
                    packet["type"] = "request"
                elif (
                    packet["direction"] == "server_to_client"
                    and _websocket_response_is_upgrade(packet)
                ):
                    packet = dict(packet)
                    packet["protocol"] = "websocket"
                    packet["type"] = "response"
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
                "message_type",
                "method",
                "uri",
                "headers",
                "status",
                "response_headers",
                "sni",
                "qname",
                "qtype",
                "frame_type",
                "fin",
                "masked",
                "mask",
                "payload",
                "protocol_name",
                "protocol_version",
                "client_id",
                "clean_session",
                "keep_alive",
                "username",
                "password",
                "will_topic",
                "will_message",
                "will_qos",
                "will_retain",
                "packet_id",
                "qos",
                "dup",
                "retain",
                "topic",
                "return_code",
                "return_code_list",
                "session_present",
                "topic_list",
                "version",
                "transport",
                "phrase",
                "call_id",
                "from",
                "to",
                "route_status",
                "persist_key",
                "record_route",
                "route",
                "via",
                "rflag",
                "pflag",
                "eflag",
                "tflag",
                "command_code",
                "application_id",
                "hop_by_hop_id",
                "end_to_end_id",
                "avps",
                "code",
                "id",
                "authenticator_hex",
                "attributes",
                "message_hex",
                "payload_hex",
                "rtdom",
                "subscriber",
                "proto",
                "fields",
                "payload_length",
                "peer",
                "route_status",
                "route",
                "route_target",
                "collect_length",
                "available_for_routing",
                "always_match_port",
                "ignore_peer_port",
                "connect_back_port",
                "connection_instance",
                "connection_mode",
                "equivalent_transport",
                "flow_id",
                "instance",
                "max_retries",
                "transport",
                "retry_count",
                "stored",
                "streamed",
                "dropped",
                "released",
                "response",
                "timestamp",
                "seq",
                "ack",
            ):
                if field in packet:
                    if field == "avps" and isinstance(packet[field], list):
                        entry[field] = [
                            {
                                key: value
                                for key, value in avp.items()
                                if not key.startswith("_")
                            }
                            if isinstance(avp, dict)
                            else avp
                            for avp in packet[field]
                        ]
                    else:
                        entry[field] = packet[field]
            trace.append(entry)
            retransmission = bool(packet.pop("_retransmission", False))
            if retransmission:
                entry["ignored"] = "tcp retransmission"
                packet.pop("payload", None)
                packet.pop("_wire_payload", None)
            protocol = packet["protocol"]
            direction = packet["direction"]
            if protocol == "http2":
                self._activate_packet_connection(session, packet, entry["events"])
                frame_events = self._decode_http2_packet(packet)
                entry["http2_frames"] = [
                    self._http2_trace_event(frame_event) for frame_event in frame_events
                ]
                for frame_event in frame_events:
                    transaction = self._consume_http2_event(session, frame_event)
                    if transaction is not None:
                        entry.setdefault("http_results", []).append(transaction)
                        entry.setdefault("http_result", transaction)
                        http_results.append(transaction)
                        if transaction.get("http2", {}).get("disconnected") == "1":
                            self._close_packet_connection(session)
                continue
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
                    if "http2" in packet:
                        request["http2"] = packet["http2"]
                    if "payload" in packet and "body" not in request:
                        request["body"] = packet["payload"]
                    pending_http = (request, index)
                    entry["pending"] = True
                else:
                    response_status = int(packet.get("status", 200))
                    if response_status < 200 and response_status != 101:
                        session.eval_tcl(
                            f"set ::state::http::response::status {response_status}"
                        )
                        session.eval_tcl("set ::state::http::response::payload \"\"")
                        for header_name, header_value in packet.get(
                            "response_headers", {}
                        ).items():
                            session.eval_tcl(
                                "::state::http::response::header set "
                                f"{_tcl_quote(header_name)} {_tcl_quote(header_value)}"
                            )
                        if response_status == 100:
                            entry["events"].append(
                                self._fire_event_on_worker(
                                    session,
                                    "HTTP_RESPONSE_CONTINUE",
                                    self._packet_event_state(packet),
                                )
                            )
                        else:
                            entry["ignored"] = "interim HTTP response"
                    elif pending_http is None:
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

            if protocol == "mqtt":
                self._activate_packet_connection(session, packet, entry["events"])
                if session.eval_tcl("set ::itest::semantic::mqtt_enabled") == "0":
                    entry["ignored"] = "MQTT processing is disabled"
                    continue
                session.eval_tcl("::itest::semantic::mqtt_prepare_message")
                side = "client" if direction == "client_to_server" else "server"
                ingress_event = (
                    "MQTT_CLIENT_INGRESS" if side == "client" else "MQTT_SERVER_INGRESS"
                )
                data_event = (
                    "MQTT_CLIENT_DATA" if side == "client" else "MQTT_SERVER_DATA"
                )
                ingress_result = self._fire_event_on_worker(
                    session, ingress_event, self._packet_event_state(packet)
                )
                entry["events"].append(ingress_result)
                flags = _split_tcl_list(
                    session.eval_tcl("::itest::semantic::mqtt_flags_snapshot")
                )
                if len(flags) % 2:
                    raise EmulatorInputError("invalid MQTT message state")
                message_state = dict(zip(flags[::2], flags[1::2]))
                if message_state.get("dropped") == "1":
                    entry["dropped"] = True
                    entry["drop_reason"] = "message"
                else:
                    collection = _split_tcl_list(
                        session.eval_tcl("::itest::semantic::mqtt_collection_snapshot")
                    )
                    if len(collection) % 2:
                        raise EmulatorInputError("invalid MQTT collection state")
                    collection_state = dict(zip(collection[::2], collection[1::2]))
                    if packet.get("type") == "PUBLISH" and collection_state.get(
                        "requested", "0"
                    ) == "1":
                        try:
                            requested_length = int(collection_state.get("length", "0"))
                        except (TypeError, ValueError):
                            raise EmulatorInputError("invalid MQTT collection length") from None
                        payload_bytes = packet.get("_mqtt_payload")
                        if not isinstance(payload_bytes, (bytes, bytearray)):
                            payload_bytes = packet.get("payload", "").encode("utf-8")
                        payload_bytes = bytes(payload_bytes)
                        if requested_length == 0 or len(payload_bytes) >= requested_length:
                            collected = payload_bytes if requested_length == 0 else payload_bytes[:requested_length]
                            data_packet = dict(packet)
                            data_packet["_mqtt_payload"] = collected
                            data_packet["payload"] = _decode_wire_text(collected)
                            session.eval_tcl(
                                "set ::itest::semantic::mqtt_collection_requested 0"
                            )
                            data_result = self._fire_event_on_worker(
                                session, data_event, self._packet_event_state(data_packet)
                            )
                            entry["events"].append(data_result)
                            data_flags = _split_tcl_list(
                                session.eval_tcl("::itest::semantic::mqtt_flags_snapshot")
                            )
                            data_state = dict(zip(data_flags[::2], data_flags[1::2]))
                            if data_state.get("dropped") == "1":
                                entry["dropped"] = True
                                entry["drop_reason"] = "message"
                if message_state.get("disconnect") == "1":
                    entry["disconnect_requested"] = True
                continue

            if protocol == "sip":
                self._activate_packet_connection(session, packet, entry["events"])
                session.eval_tcl("::itest::semantic::sip_prepare_message")
                is_request = packet.get("type") == "request"
                ingress_event = "SIP_REQUEST" if is_request else "SIP_RESPONSE"
                send_event = "SIP_REQUEST_SEND" if is_request else "SIP_RESPONSE_SEND"
                done_event = "SIP_REQUEST_DONE" if is_request else "SIP_RESPONSE_DONE"
                ingress_result = self._fire_event_on_worker(
                    session, ingress_event, self._packet_event_state(packet)
                )
                entry["events"].append(ingress_result)
                raw_flags = _split_tcl_list(
                    session.eval_tcl("::itest::semantic::sip_flags_snapshot")
                )
                if len(raw_flags) % 2:
                    raise EmulatorInputError("invalid SIP message state")
                flags = dict(zip(raw_flags[::2], raw_flags[1::2]))
                if flags.get("discarded") == "1":
                    entry["discarded"] = True
                    entry["drop_reason"] = "message"
                else:
                    if flags.get("responded") == "1":
                        entry["responded"] = True
                        response_snapshot = _split_tcl_list(
                            session.eval_tcl("::itest::semantic::sip_response_snapshot")
                        )
                        if len(response_snapshot) % 2:
                            raise EmulatorInputError("invalid SIP response state")
                        response_state = dict(
                            zip(response_snapshot[::2], response_snapshot[1::2])
                        )
                        raw_headers = _split_tcl_list(response_state.get("headers", ""))
                        if len(raw_headers) % 2:
                            raise EmulatorInputError("invalid SIP response headers")
                        entry["response"] = {
                            "status": int(response_state.get("code", "0")),
                            "phrase": response_state.get("phrase", ""),
                            "headers": [
                                [raw_headers[index], raw_headers[index + 1]]
                                for index in range(0, len(raw_headers), 2)
                            ],
                        }
                    else:
                        send_result = self._fire_event_on_worker(
                            session, send_event, self._current_sip_event_state(session, packet)
                        )
                        entry["events"].append(send_result)
                        raw_flags = _split_tcl_list(
                            session.eval_tcl("::itest::semantic::sip_flags_snapshot")
                        )
                        if len(raw_flags) % 2:
                            raise EmulatorInputError("invalid SIP message state")
                        flags = dict(zip(raw_flags[::2], raw_flags[1::2]))
                        if flags.get("discarded") == "1":
                            entry["discarded"] = True
                            entry["drop_reason"] = "message"
                        else:
                            entry["events"].append(
                                self._fire_event_on_worker(
                                    session,
                                    done_event,
                                    self._current_sip_event_state(session, packet),
                                )
                            )
                continue

            if protocol == "diameter":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._configure_packet_connection(session, packet)
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "SERVER_CONNECTED",
                            {"connection": self._packet_connection_state(packet)},
                        )
                    )
                    self._server_connection_open = True
                session.eval_tcl("::itest::semantic::diameter_prepare_message")
                event_name = (
                    "DIAMETER_INGRESS"
                    if direction == "client_to_server"
                    else "DIAMETER_EGRESS"
                )
                entry["events"].append(
                    self._fire_event_on_worker(
                        session, event_name, self._packet_event_state(packet)
                    )
                )
                raw_flags = _split_tcl_list(
                    session.eval_tcl("::itest::semantic::diameter_flags_snapshot")
                )
                if len(raw_flags) % 2:
                    raise EmulatorInputError("invalid Diameter message state")
                message_flags = dict(zip(raw_flags[::2], raw_flags[1::2]))
                if message_flags.get("dropped") == "1":
                    entry["dropped"] = True
                    entry["drop_reason"] = "message"
                if message_flags.get("responded") == "1":
                    entry["responded"] = True
                    response_snapshot = _split_tcl_list(
                        session.eval_tcl("::itest::semantic::diameter_response_snapshot")
                    )
                    if len(response_snapshot) % 2:
                        raise EmulatorInputError("invalid Diameter response state")
                    response_state = dict(
                        zip(response_snapshot[::2], response_snapshot[1::2])
                    )
                    response_args = _split_tcl_list(response_state.get("args", ""))
                    entry["response"] = {
                        "arguments": response_args,
                        "message_hex": session.eval_tcl(
                            "binary encode hex $::state::diameter::message"
                        ),
                    }
                if message_flags.get("disconnected") == "1":
                    entry["disconnect_requested"] = True
                if packet.get("tflag"):
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "DIAMETER_RETRANSMISSION",
                            self._current_diameter_event_state(session, packet),
                        )
                    )
                continue

            if protocol == "radius":
                session.eval_tcl("::itest::semantic::radius_prepare_message")
                code = int(packet.get("code", RADIUS_AUTH_REQUEST))
                if direction == "client_to_server":
                    event_name = (
                        "RADIUS_AAA_ACCT_REQUEST"
                        if code == RADIUS_ACCOUNTING_REQUEST
                        else "RADIUS_AAA_AUTH_REQUEST"
                    )
                else:
                    event_name = (
                        "RADIUS_AAA_ACCT_RESPONSE"
                        if code == RADIUS_ACCOUNTING_RESPONSE
                        else "RADIUS_AAA_AUTH_RESPONSE"
                    )
                entry["events"].append(
                    self._fire_event_on_worker(
                        session, event_name, self._packet_event_state(packet)
                    )
                )
                continue

            if protocol == "gtp":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._configure_packet_connection(session, packet)
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "SERVER_CONNECTED",
                            {"connection": self._packet_connection_state(packet)},
                        )
                    )
                    self._server_connection_open = True
                session.eval_tcl("::itest::semantic::gtp_prepare_message")
                endpoints = {
                    packet.get("source", {}).get("port"),
                    packet.get("destination", {}).get("port"),
                }
                if GTP_PRIME_PORT in endpoints:
                    event_base = "GTP_PRIME"
                elif packet.get("type") == GTP_GPDU_TYPE or GTP_USER_PLANE_PORT in endpoints:
                    event_base = "GTP_GPDU"
                else:
                    event_base = "GTP_SIGNALLING"
                event_name = f"{event_base}_{'INGRESS' if direction == 'client_to_server' else 'EGRESS'}"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                gtp_state = event_result.get("state", {}).get("gtp", {})
                if gtp_state.get("discarded") in {"1", "true"}:
                    entry["discarded"] = True
                    entry["drop_reason"] = "message"
                if gtp_state.get("responded") in {"1", "true"}:
                    entry["responded"] = True
                continue

            if protocol == "mr":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._configure_packet_connection(session, packet)
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "SERVER_CONNECTED",
                            {"connection": self._packet_connection_state(packet)},
                        )
                    )
                    self._server_connection_open = True
                session.eval_tcl("::itest::semantic::mr_prepare_message")
                ingress_event = "MR_INGRESS" if direction == "client_to_server" else "MR_EGRESS"
                entry["events"].append(
                    self._fire_event_on_worker(
                        session, ingress_event, self._packet_event_state(packet)
                    )
                )
                try:
                    collect_length = int(
                        session.eval_tcl("set ::state::mr::collect_length")
                    )
                except (TypeError, ValueError):
                    raise EmulatorInputError("invalid MR collection length") from None
                payload = packet.get("_mr_payload", b"")
                if (
                    direction == "client_to_server"
                    and collect_length != 0
                    and (collect_length < 0 or len(payload) >= collect_length)
                ):
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "MR_DATA",
                            self._current_mr_event_state(session, packet),
                        )
                    )
                if packet.get("route_status") in {"failed", "no_route_found"}:
                    entry["events"].append(
                        self._fire_event_on_worker(
                            session,
                            "MR_FAILED",
                            self._current_mr_event_state(session, packet),
                        )
                    )
                continue

            if protocol == "websocket":
                self._activate_packet_connection(session, packet, entry["events"])
                packet_type = packet["type"]
                if packet_type == "request":
                    if not _websocket_request_is_upgrade(packet):
                        entry["ignored"] = "WebSocket upgrade headers are incomplete"
                    elif session.eval_tcl("set ::itest::semantic::ws_enabled") == "0":
                        entry["ignored"] = "WebSocket processing is disabled"
                    else:
                        request_event = self._fire_event_on_worker(
                            session, "WS_REQUEST", self._packet_event_state(packet)
                        )
                        entry["events"].append(request_event)
                        if request_event.get("reason") != "profile_gate":
                            session.eval_tcl("set ::itest::semantic::ws_request_seen 1")
                elif packet_type == "response":
                    if not _websocket_response_is_upgrade(packet):
                        entry["ignored"] = "WebSocket upgrade headers are incomplete"
                    elif session.eval_tcl("set ::itest::semantic::ws_enabled") == "0":
                        entry["ignored"] = "WebSocket processing is disabled"
                    else:
                        response_event = self._fire_event_on_worker(
                            session, "WS_RESPONSE", self._packet_event_state(packet)
                        )
                        entry["events"].append(response_event)
                        status = int(packet.get("status", 101))
                        if response_event.get("reason") != "profile_gate" and status == 101 and session.eval_tcl(
                            "set ::itest::semantic::ws_request_seen"
                        ) == "1":
                            session.eval_tcl("set ::itest::semantic::ws_upgrade_seen 1")
                            self._websocket_raw_active = True
                elif session.eval_tcl("set ::itest::semantic::ws_enabled") == "0":
                    entry["ignored"] = "WebSocket processing is disabled"
                elif session.eval_tcl("set ::itest::semantic::ws_upgrade_seen") != "1":
                    entry["ignored"] = "WebSocket handshake is incomplete"
                else:
                    side = "client" if direction == "client_to_server" else "server"
                    frame_event = (
                        "WS_CLIENT_FRAME" if side == "client" else "WS_SERVER_FRAME"
                    )
                    data_event = "WS_CLIENT_DATA" if side == "client" else "WS_SERVER_DATA"
                    done_event = (
                        "WS_CLIENT_FRAME_DONE" if side == "client" else "WS_SERVER_FRAME_DONE"
                    )
                    frame_state = self._packet_event_state(packet)
                    session.eval_tcl("::itest::semantic::ws_prepare_frame")
                    entry["events"].append(
                        self._fire_event_on_worker(session, frame_event, frame_state)
                    )
                    frame_dropped = session.eval_tcl(
                        "set ::itest::semantic::ws_frame_dropped"
                    ) == "1"
                    message_dropped = session.eval_tcl(
                        "set ::itest::semantic::ws_message_dropped"
                    ) == "1"
                    if frame_dropped or message_dropped:
                        entry["dropped"] = True
                        entry["drop_reason"] = (
                            "frame" if frame_dropped else "message"
                        )
                    else:
                        collection = _split_tcl_list(
                            session.eval_tcl("::itest::semantic::ws_collection_snapshot")
                        )
                        if len(collection) % 2:
                            raise EmulatorInputError("invalid WebSocket collection state")
                        collection_state = dict(zip(collection[::2], collection[1::2]))
                        data_event_fired = False
                        if (
                            collection_state.get("requested", "0") == "1"
                            and packet.get("frame_type")
                            in {"text", "binary", "continuation"}
                        ):
                            try:
                                requested_length = int(collection_state.get("length", "0"))
                            except (TypeError, ValueError):
                                raise EmulatorInputError(
                                    "invalid WebSocket collection length"
                                ) from None
                            wire_payload = packet.get("_wire_payload")
                            if isinstance(wire_payload, (bytes, bytearray)):
                                frame_payload = bytes(wire_payload)
                            else:
                                frame_payload = packet.get("payload", "").encode("utf-8")
                            if requested_length == 0 or len(frame_payload) >= requested_length:
                                data_state = {
                                    layer: dict(values)
                                    for layer, values in frame_state.items()
                                }
                                data_state.setdefault("websocket", {})["payload"] = frame_payload
                                data_state["websocket"]["payload_length"] = str(
                                    len(frame_payload)
                                )
                                entry["events"].append(
                                    self._fire_event_on_worker(session, data_event, data_state)
                                )
                                data_event_fired = True
                        if data_event_fired and session.eval_tcl(
                            "set ::itest::semantic::ws_message_dropped"
                        ) == "1":
                            entry["dropped"] = True
                            entry["drop_reason"] = "message"
                    entry["events"].append(
                        self._fire_event_on_worker(session, done_event, frame_state)
                    )
                    session.eval_tcl(
                        f"::itest::semantic::ws_finish_frame {_tcl_quote(packet.get('fin', '1'))}"
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
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                dns_state = event_result.get("state", {}).get("dns", {})
                dropped = dns_state.get("dropped") in {"1", "true"}
                if dropped:
                    entry["dropped"] = True
                    entry["drop_reason"] = "dns"
                if dns_state.get("disabled") in {"1", "true"}:
                    entry["disabled"] = True
                if dns_state.get("response_sent") in {"1", "true"}:
                    entry["responded"] = True
                if event_name == "DNS_REQUEST" and not dropped and dns_state.get(
                    "response_sent"
                ) in {"1", "true"}:
                    response_state = {
                        layer: dict(values)
                        for layer, values in event_result.get("state", {}).items()
                    }
                    response_dns = response_state.setdefault("dns", {})
                    response_dns["qr"] = "1"
                    response_dns["response_sent"] = "0"
                    response_event = self._fire_event_on_worker(
                        session, "DNS_RESPONSE", response_state
                    )
                    entry["events"].append(response_event)
                    response_dns = response_event.get("state", {}).get("dns", {})
                    if response_dns.get("dropped") in {"1", "true"}:
                        entry["dropped"] = True
                        entry["drop_reason"] = "dns"
                    if response_dns.get("disabled") in {"1", "true"}:
                        entry["disabled"] = True
                    if response_dns.get("response_sent") in {"1", "true"}:
                        entry["responded"] = True
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
                    if self._mqtt_raw_active and direction == "client_to_server":
                        entry["events"].append(
                            self._fire_event_on_worker(
                                session,
                                "MQTT_CLIENT_SHUTDOWN",
                                self._packet_event_state(packet),
                            )
                        )
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
                "description": "Replay a bounded TCP/TLS/HTTP/HTTP2/UDP/DNS packet trace on a persistent emulator session.",
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
