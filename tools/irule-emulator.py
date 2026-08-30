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
import zlib
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
CPU_INTERVALS = frozenset(
    {"1sec", "5secs", "15secs", "1min", "5mins", "15mins", "all_seconds", "all_minutes"}
)
WHEREIS_FIELDS = frozenset(
    {
        "continent", "country", "state", "abbrev", "city", "zip", "area_code",
        "latitude", "longitude", "isp", "org", "country_cf", "state_cf",
        "city_cf", "proxy_type",
    }
)
CPU_INTERVAL_ALIASES = {
    "1sec": "1sec",
    "1secs": "1sec",
    "1second": "1sec",
    "1seconds": "1sec",
    "5sec": "5secs",
    "5secs": "5secs",
    "5second": "5secs",
    "5seconds": "5secs",
    "15sec": "15secs",
    "15secs": "15secs",
    "15second": "15secs",
    "15seconds": "15secs",
    "1min": "1min",
    "1mins": "1min",
    "1minute": "1min",
    "1minutes": "1min",
    "5min": "5mins",
    "5mins": "5mins",
    "5minute": "5mins",
    "5minutes": "5mins",
    "15min": "15mins",
    "15mins": "15mins",
    "15minute": "15mins",
    "15minutes": "15mins",
    "all_seconds": "all_seconds",
    "all_minutes": "all_minutes",
}
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
# The pinned command registry includes the IKE namespace but omits the
# IKE_AUTH event listed in the F5 event reference. Keep the event usable in
# the direct-event API without inventing profile or transport gates that the
# source registry does not provide.
TMOS_17_5_EVENT_OVERRIDES = {
    "IKE_AUTH": {
        "multiplicity": "unknown",
        "client_side": False,
        "server_side": False,
        "transport": None,
        "implied_profiles": frozenset(),
        "flow": True,
        "deprecated": False,
        "common": False,
    }
}
TMOS_17_5_UNAVAILABLE_COMMANDS = frozenset(
    {
        "XML::address",
        "XML::collect",
        "XML::disable",
        "XML::element",
        "XML::enable",
        "XML::event",
        "XML::eventid",
        "XML::parse",
        "XML::payload",
        "XML::release",
        "XML::soap",
        "XML::subscribe",
    }
)
TMOS_17_5_UNAVAILABLE_EVENTS = frozenset(
    {
        "XML_BEGIN_DOCUMENT",
        "XML_BEGIN_ELEMENT",
        "XML_CDATA",
        "XML_END_DOCUMENT",
        "XML_END_ELEMENT",
        "XML_EVENT",
    }
)
ASM_LOGIN_STATUSES = frozenset({"not_logged_in", "logging_in", "logged_in", "failed"})
ASM_CAPTCHA_STATUSES = frozenset({"not_received", "correct", "incorrect", "empty"})
ASM_STATUSES = frozenset({"Alarm", "Blocked", "Clear"})
ASM_SEVERITIES = frozenset(
    {"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational"}
)
ASM_SIGNATURE_FIELDS = (
    "ids",
    "names",
    "set_names",
    "staged_ids",
    "staged_names",
    "staged_set_names",
)
ASM_CAMPAIGN_FIELDS = ("names", "staged_names")
BOTDEFENSE_CAPTCHA_STATUSES = frozenset(
    {"not_received", "correct", "incorrect", "empty", "expired"}
)
BOTDEFENSE_COOKIE_STATUSES = frozenset(
    {"", "valid", "invalid", "expired", "valid_redirect_challenge", "renewal"}
)
BOTDEFENSE_CLIENT_TYPES = frozenset(
    {"bot", "mobile_app", "browser", "uncategorized"}
)
BOTDEFENSE_CLIENT_CLASSES = frozenset(
    {
        "unknown",
        "browser",
        "mobile_application",
        "trusted_bot",
        "untrusted_bot",
        "malicious_bot",
        "suspicious_browser",
    }
)
ANTIFRAUD_ALERT_VALUE_FIELDS = (
    "alert_additional_info",
    "alert_component",
    "alert_defined_value",
    "alert_details",
    "alert_expected_value",
    "alert_fingerprint",
    "alert_html",
    "alert_http_referrer",
    "alert_id",
    "alert_min",
    "alert_origin",
    "alert_resolved_value",
    "alert_score",
    "alert_transaction_data",
    "alert_transaction_id",
    "alert_type",
    "alert_username",
    "alert_view_id",
)
ANTIFRAUD_ALERT_FLAG_FIELDS = (
    "alert_bait_signatures",
    "alert_device_id",
    "alert_forbidden_added_element",
    "alert_guid",
)
ANTIFRAUD_ALERT_LOG_LEVELS = frozenset(
    {"Error", "Warning", "Notice", "Informational", "Debug"}
)
ANTIFRAUD_RESULTS = frozenset({"passed", "failed"})
AAA_RESULTS = frozenset({"OK", "FAIL", "INPROGRESS", "ERROR"})
ACCESS_ACL_RESULTS = frozenset({"Allow", "Reject"})
ACCESS_POLICY_RESULTS = frozenset({"allow", "deny", "redirect"})
ACCESS_PERFLOW_SET_KEYS = frozenset({"perflow.custom", "perflow.scratchpad"})
AUTH_RESULTS = frozenset({"success", "failure", "error", "wantcredential"})
AUTH_PROMPT_STYLES = frozenset({"echo_on", "echo_off", "unknown"})
DEFAULT_PROFILES = ["TCP", "HTTP"]
LB_FAILURE_CAUSES = frozenset(
    {"no_member", "unreachable", "queue_limit", "connection_timeout"}
)
BACKEND_MEMBER_STATES = frozenset({"up", "down", "disabled"})
BACKEND_MAX_MEMBERS = 1024
BACKEND_MAX_RESPONSES_PER_MEMBER = 64
BACKEND_MAX_RESPONSE_BODY_BYTES = 2 * 1024 * 1024
BACKEND_MAX_TOTAL_FIXTURE_BYTES = 64 * 1024 * 1024
POOL_SELECTION_MODES = frozenset({"first", "round_robin"})
HTTP_CLASS_RESULTS = frozenset({"selected", "failed"})
LB_QUEUE_MAX_VALUE = 2**31 - 1
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
    407: "Proxy Authentication Required",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}
DEFAULT_MAX_SESSIONS = 32
DEFAULT_SESSION_IDLE_SECONDS = 1800
MAX_HTTP_RETRIES = 8
MAX_HTTP_PROXY_CHAIN_RETRIES = 1
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
        "forwarded",
        "rateclass",
        "translate_address_enabled",
        "translate_port_enabled",
        "translate_service_enabled",
    },
    "traffic_group": {
        "name",
    },
    "datagram": {
        "ip_version",
        "ip_tos",
        "ip_ttl",
        "ip_flags",
        "ip_options",
        "ip6_hop_limit",
        "ip6_options",
        "l2_dest",
        "protocol",
        "tcp_flags",
        "tcp_window",
        "tcp_options",
        "payload",
        "payload_length",
        "dns_id",
        "dns_qr",
        "dns_opcode",
        "dns_qdcount",
        "dns_ancount",
        "dns_nscount",
        "dns_arcount",
    },
    "route": {
        "domain",
        "destination",
        "gateway",
        "age",
        "expiration",
        "mtu",
        "rtt",
        "rttvar",
        "cwnd",
        "bandwidth",
        "cleared",
    },
    "l7check": {
        "protocol",
    },
    "link": {
        "qos",
        "vlan_id",
        "lasthop_mac",
        "lasthop_id",
        "lasthop_type",
        "lasthop_name",
        "nexthop_mac",
        "nexthop_id",
        "nexthop_type",
        "nexthop_name",
    },
    "socks": {
        "version",
        "allowed",
        "destination_host",
        "destination_port",
    },
    "tls_client": {
        "sni",
        "sni_required",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cipher_clientlist",
        "clientrandom",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_extensions",
        "cert_not_valid_after",
        "cert_not_valid_before",
        "cert_signature_algorithm",
        "cert_public_key",
        "cert_public_key_type",
        "cert_public_key_bits",
        "cert_public_key_curve",
        "cert_version",
        "cert_pem",
        "cert_der",
        "cert_count",
        "cert_mode",
        "verify_result",
        "disabled",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
        "initial_session_id",
        "sessionticket",
        "nextproto",
        "session_secret",
        "tls13_client_app_secret",
        "tls13_client_hs_secret",
        "tls13_client_early_secret",
        "tls13_server_app_secret",
        "tls13_server_hs_secret",
        "c3d_cert",
        "c3d_subject_cn",
        "c3d_extensions",
        "cert_constraints",
        "collect_requested",
        "collect_length",
        "payload",
        "payload_length",
        "release_requested",
        "released_length",
        "forward_proxy_policy",
        "forward_proxy_cert",
        "forward_proxy_extensions",
        "forward_proxy_verified_handshake",
        "forward_proxy_response_control",
        "forward_proxy_cert_status",
        "handshake_held",
        "renegotiation_enabled",
        "renegotiation_requested",
        "renegotiation_secure",
        "secure_renegotiation",
        "allow_nonssl",
        "dynamic_record_sizing",
        "maximum_record_size",
        "profile",
        "session_invalidated",
        "session_drop",
        "unclean_shutdown",
        "authenticate_frequency",
        "authenticate_depth",
    },
    "tls_server": {
        "sni",
        "sni_required",
        "cipher_name",
        "cipher_bits",
        "cipher_version",
        "cipher_clientlist",
        "clientrandom",
        "cert_subject",
        "cert_issuer",
        "cert_serial",
        "cert_hash",
        "cert_extensions",
        "cert_not_valid_after",
        "cert_not_valid_before",
        "cert_signature_algorithm",
        "cert_public_key",
        "cert_public_key_type",
        "cert_public_key_bits",
        "cert_public_key_curve",
        "cert_version",
        "cert_pem",
        "cert_der",
        "cert_count",
        "cert_mode",
        "verify_result",
        "disabled",
        "extensions",
        "alpn",
        "handshake_done",
        "session_id",
        "initial_session_id",
        "sessionticket",
        "nextproto",
        "session_secret",
        "tls13_client_app_secret",
        "tls13_client_hs_secret",
        "tls13_client_early_secret",
        "tls13_server_app_secret",
        "tls13_server_hs_secret",
        "c3d_cert",
        "c3d_subject_cn",
        "c3d_extensions",
        "cert_constraints",
        "collect_requested",
        "collect_length",
        "payload",
        "payload_length",
        "release_requested",
        "released_length",
        "forward_proxy_policy",
        "forward_proxy_cert",
        "forward_proxy_extensions",
        "forward_proxy_verified_handshake",
        "forward_proxy_response_control",
        "forward_proxy_cert_status",
        "handshake_held",
        "renegotiation_enabled",
        "renegotiation_requested",
        "renegotiation_secure",
        "secure_renegotiation",
        "allow_nonssl",
        "dynamic_record_sizing",
        "maximum_record_size",
        "profile",
        "session_invalidated",
        "session_drop",
        "unclean_shutdown",
        "authenticate_frequency",
        "authenticate_depth",
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
        "push_count",
        "pushes",
        "pseudo_headers",
    },
    "stream": {
        "line",
        "match",
        "encoding",
        "expression",
        "max_matchsize",
        "enabled",
        "disabled",
        "replacement",
        "replacement_requested",
        "replaced",
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
        "tsig_present",
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
        "payload_ivs",
        "payload_processing",
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
        "username_flag",
        "password_flag",
        "will_topic",
        "will_message",
        "will_qos",
        "will_retain",
        "will_flag",
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
    "sdp": {
        "session_id",
        "fields",
        "media",
    },
    "acl": {
        "action",
        "l7_present",
        "evaluated",
        "l7_aborted",
        "applied_action",
    },
    "access2": {"proc"},
    "am": {
        "age",
        "application",
        "cache",
        "disabled",
        "expires",
        "media_playlist",
        "policy_node",
    },
    "lsn": {
        "address",
        "port",
        "pool",
        "disabled",
        "inbound_disabled",
        "persistence_mode",
        "persistence_timeout",
        "persistence_entries",
        "inbound_entries",
    },
    "xlat": {
        "src_addr",
        "src_port",
        "src_config",
        "src_nat_valid_range",
        "listeners",
        "reservations",
    },
    "pcp": {
        "version",
        "opcode",
        "lifetime",
        "protocol",
        "internal_port",
        "prefer_failure",
        "client_addr",
        "third_party",
        "third_party_int_addr",
        "suggested_ext_port",
        "suggested_ext_addr",
        "result",
        "assigned_ext_port",
        "assigned_ext_addr",
        "rejected",
        "reject_result",
    },
    "psc": {
        "aaa_reporting_interval",
        "attrs",
        "calling_id",
        "imeisv",
        "imsi",
        "ip_addresses",
        "lease_times",
        "policies",
        "subscriber_id",
        "tower_id",
        "user_name",
    },
    "pem": {
        "flow_enabled",
        "transactional_enabled",
        "eval_count",
        "session_ip",
        "subscriber_id",
        "subscriber_type",
        "state",
        "imsi",
        "imeisv",
        "tower_id",
        "rat_type",
        "user_name",
        "provision",
        "ip_addresses",
        "policies",
        "attrs",
        "policy",
        "action",
        "result",
    },
    "connector": {
        "enabled",
        "profile",
        "client_addr",
        "client_port",
        "server_addr",
        "server_port",
        "remaps",
    },
    "tmm": {
        "cmp_count",
        "cmp_group",
        "cmp_groups",
        "cmp_primary_group",
        "cmp_unit",
    },
    "policy": {
        "controls",
        "targets",
        "active",
        "matched",
        "unmatched",
        "rules",
    },
    "wam": {"enabled"},
    "vdi": {"enabled"},
    "websso": {"enabled", "selected"},
    "tap": {
        "action",
        "score",
        "insight_requested",
        "insight_token",
        "config",
        "insight",
    },
    "ha": {"status"},
    "bigproto": {"enable_fix_reset"},
    "bigtcp": {"released"},
    "bwc": {
        "attached",
        "policy",
        "session_id",
        "rate",
        "rate_category",
        "pps",
        "color_policy",
        "color_category",
        "color_set",
        "mark_scope",
        "mark_category",
        "mark_tos",
        "mark_qos",
        "priority",
        "measure_enabled",
        "measure_scope",
        "measure_session",
        "measure_identifier",
        "measure_rate",
        "measure_bytes",
        "debug_enabled",
    },
    "eca": {"enabled", "selected", "client_machine_name", "domainname", "status", "username"},
    "avr": {"enabled", "cspm_injection_enabled", "log_requested"},
    "fix": {"tags", "tag_maps"},
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
    "udp": {
        "payload",
        "payload_length",
        "client_port",
        "server_port",
        "local_port",
        "remote_port",
        "mss",
        "max_buf_pkts",
        "max_rate",
        "sendbuffer",
        "debug_queue",
        "dropped",
        "held",
        "released",
        "responded",
        "response",
        "response_length",
    },
    "sctp": {
        "payload",
        "payload_length",
        "client_port",
        "server_port",
        "local_port",
        "remote_port",
        "mss",
        "ppi",
        "collect_requested",
        "collect_length",
        "released",
        "released_length",
        "responded",
        "response",
        "response_length",
        "rto_initial",
        "rto_max",
        "rto_min",
        "sack_timeout",
    },
    "dhcp": {
        "version",
    },
    "dhcpv4": {
        "chaddr",
        "ciaddr",
        "drop",
        "giaddr",
        "hlen",
        "hops",
        "htype",
        "len",
        "opcode",
        "options",
        "reject",
        "secs",
        "siaddr",
        "type",
        "xid",
        "yiaddr",
        "payload",
        "payload_length",
    },
    "dhcpv6": {
        "drop",
        "hop_count",
        "len",
        "link_address",
        "msg_type",
        "options",
        "peer_address",
        "reject",
        "transaction_id",
        "payload",
        "payload_length",
    },
    "tds": {
        "type",
        "length",
        "procid",
        "procname",
        "sqltext",
        "xacttype",
        "xactid",
        "is_read",
        "request_type",
        "username",
        "dbname",
        "loginoption",
        "version",
    },
    "qoe": {
        "enabled",
        "width",
        "height",
        "duration",
        "available",
        "framerate",
        "nominal_bitrate",
        "average_bitrate",
        "mos",
    },
    "ike": {
        "auth_success",
        "cert",
        "san_dirname",
        "san_dns",
        "san_ediparty",
        "san_email",
        "san_ipadd",
        "san_othername",
        "san_rid",
        "san_uri",
        "san_x400",
        "subjectAltName",
    },
    "ftp": {
        "allow_active_mode",
        "command",
        "disabled",
        "enabled",
        "enforce_tls_session_reuse",
        "ftps_mode",
        "payload",
        "payload_length",
        "port_first",
        "port_last",
        "response_code",
        "tls_active",
        "tls_session_reused",
        "type",
        "dropped",
        "rejected",
    },
    "imap": {
        "activation_mode",
        "command",
        "disabled",
        "enabled",
        "payload",
        "payload_length",
        "tls_active",
        "type",
    },
    "pop3": {
        "activation_mode",
        "command",
        "disabled",
        "enabled",
        "payload",
        "payload_length",
        "tls_active",
        "type",
    },
    "ldap": {
        "activation_mode",
        "command",
        "disabled",
        "enabled",
        "payload",
        "payload_length",
        "tls_active",
        "type",
    },
    "smtps": {
        "activation_mode",
        "command",
        "disabled",
        "enabled",
        "payload",
        "payload_length",
        "tls_active",
        "type",
    },
    "ntlm": {
        "disabled",
        "enabled",
        "payload",
        "payload_length",
    },
    "protocol_inspection": {
        "disabled",
        "enabled",
        "ids",
        "matched",
        "payload",
        "payload_length",
    },
    "classification": {
        "app",
        "category",
        "classify_application_add",
        "classify_application_set",
        "classify_additions",
        "classify_category_add",
        "classify_category_set",
        "classify_classified",
        "classify_defer",
        "classify_urlcat_add",
        "classify_urlcat_set",
        "classify_username",
        "classify_username_context",
        "detected",
        "deferred",
        "disabled",
        "enabled",
        "payload",
        "payload_length",
        "protocol",
        "result",
        "urlcat",
        "username",
    },
    "category": {
        "analytics",
        "categories",
        "detected",
        "filetype_mimetype",
        "filetype_mimesubtype",
        "lookup_url",
        "matchtype",
        "matched",
        "payload",
        "payload_length",
        "safesearch",
        "url",
    },
    "icap": {
        "headers",
        "method",
        "payload",
        "payload_length",
        "status",
        "type",
        "uri",
    },
    "tcp": {
        "abc",
        "analytics",
        "analytics_key",
        "autowin",
        "delayed_ack",
        "dsack",
        "earlyrxmit",
        "ecn",
        "enhanced_loss_recovery",
        "limxmit",
        "lossfilter_rate",
        "lossfilter_burst",
        "nagle",
        "naglemode",
        "naglestate",
        "keepalive",
        "idletime",
        "sendbuf",
        "recvwnd",
        "rcv_size",
        "snd_wnd",
        "snd_cwnd",
        "rto",
        "rttvar",
        "rexmt_thresh",
        "rt_metrics_timeout",
        "rcv_scale",
        "snd_scale",
        "snd_ssthresh",
        "pacing",
        "proxybuffer_high",
        "proxybuffer_low",
        "push_flag",
        "congestion",
    },
    "rtsp": {
        "type",
        "method",
        "uri",
        "version",
        "status",
        "phrase",
        "msg_source",
        "headers",
        "payload",
        "payload_length",
        "dropped",
        "responded",
        "response_status",
        "response_phrase",
        "response_headers",
        "response_body",
    },
    "cache": {
        "uri",
        "useragent",
        "userkey",
        "accept_encoding",
        "key",
        "headers",
        "payload",
        "age",
        "hits",
        "fresh",
        "disabled",
        "forced",
        "expired",
        "priority",
        "statskey",
        "stored",
        "hit",
    },
}
EVENT_STATE_NAMESPACES = {
    "connection": "::state::connection",
    "datagram": "::state::datagram",
    "route": "::state::route",
    "l7check": "::state::l7check",
    "link": "::state::link",
    "traffic_group": "::state::traffic_group",
    "socks": "::state::socks",
    "tls_client": "::state::tls::client",
    "tls_server": "::state::tls::server",
    "http2": "::state::http2",
    "stream": "::state::stream",
    "dns": "::state::dns",
    "websocket": "::state::websocket",
    "mqtt": "::state::mqtt",
    "sip": "::state::sip",
    "sdp": "::state::sdp",
    "acl": "::state::acl",
    "access2": "::state::access2",
    "am": "::state::am",
    "lsn": "::state::lsn",
    "xlat": "::state::xlat",
    "pcp": "::state::pcp",
    "psc": "::state::psc",
    "pem": "::state::pem",
    "connector": "::state::connector",
    "tmm": "::state::tmm",
    "policy": "::state::policy",
    "wam": "::state::wam",
    "vdi": "::state::vdi",
    "websso": "::state::websso",
    "tap": "::state::tap",
    "ha": "::state::ha",
    "bigproto": "::state::bigproto",
    "bigtcp": "::state::bigtcp",
    "bwc": "::state::bwc",
    "eca": "::state::eca",
    "avr": "::state::avr",
    "fix": "::state::fix",
    "diameter": "::state::diameter",
    "radius": "::state::radius",
    "message": "::state::message",
    "mr": "::state::mr",
    "gtp": "::state::gtp",
    "udp": "::state::udp",
    "sctp": "::state::sctp",
    "dhcp": "::state::dhcp",
    "dhcpv4": "::state::dhcpv4",
    "dhcpv6": "::state::dhcpv6",
    "tds": "::state::tds",
    "qoe": "::state::qoe",
    "ike": "::state::ike",
    "ftp": "::state::ftp",
    "imap": "::state::imap",
    "pop3": "::state::pop3",
    "ldap": "::state::ldap",
    "smtps": "::state::smtps",
    "ntlm": "::state::ntlm",
    "protocol_inspection": "::state::protocol_inspection",
    "classification": "::state::classification",
    "category": "::state::category",
    "icap": "::state::icap",
    "tcp": "::state::tcp",
    "rtsp": "::state::rtsp",
    "cache": "::state::cache",
}
POLICY_LIST_STATE_FIELDS = frozenset(
    {"controls", "targets", "active", "matched", "unmatched"}
)


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


def _extract_irule_procedures(root: Path, source: str) -> list[tuple[str, str, str]]:
    """Extract top-level proc declarations without executing other Tcl.

    The pinned tcl-lsp iRule loader intentionally consumes ``when`` blocks,
    while real iRules commonly declare reusable procedures at top level. Use
    its command segmenter to identify only top-level ``proc`` commands; the
    caller installs those declarations as individually quoted Tcl words.
    """
    _load_session_class(root)
    try:
        from compiler.parsing.command_segmenter import segment_commands

        commands = segment_commands(source, recovery=False)
    except Exception:
        # Procedure support is additive. If a source cannot be segmented,
        # leave event loading and its existing diagnostics to tcl-lsp.
        return []

    procedures: list[tuple[str, str, str]] = []
    for command in commands:
        texts = command.texts
        if len(texts) != 4 or texts[0] != "proc":
            continue
        name, arguments, body = texts[1:]
        if not name:
            continue
        procedures.append((name, arguments, body))
    return procedures


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


def _target_status(
    name: str,
    post_target_names: frozenset[str],
    unavailable_names: frozenset[str],
) -> str:
    if name in unavailable_names:
        return "unavailable-in-tmos-17.5"
    if name in post_target_names:
        return "introduced-after-tmos-17.5"
    return "available-in-tmos-17.5"


SEMANTIC_MOCK_COMMANDS = {
    "ADAPT::allow",
    "ADAPT::context_create",
    "ADAPT::context_current",
    "ADAPT::context_delete_all",
    "ADAPT::context_name",
    "ADAPT::context_static",
    "ADAPT::enable",
    "ADAPT::preview_size",
    "ADAPT::result",
    "ADAPT::select",
    "ADAPT::service_down_action",
    "ADAPT::timeout",
    "AES::decrypt",
    "AES::encrypt",
    "AES::key",
    "call",
    "fasthash",
    "htonl",
    "htons",
    "http_client_ip",
    "http_content_len_max",
    "http_cookie",
    "http_header",
    "http_host",
    "http_method",
    "http_uri",
    "http_version",
    "ifile",
    "ip_addr",
    "lasthop",
    "nexthop",
    "redirect",
    "forward",
    "link_qos",
    "rateclass",
    "translate",
    "session",
    "sharedvar",
    "priority",
    "timing",
    "cpu",
    "imid",
    "pem_dtos",
    "proc",
    "whereis",
    "accumulate",
    "check",
    "tcpdump",
    "DIAG::test",
    "LINE::get",
    "LINE::set",
    "clone",
    "listen",
    "relate_client",
    "relate_server",
    "use",
    "urlcatblindquery",
    "urlcatquery",
    "IPFIX::destination",
    "IPFIX::msg",
    "IPFIX::template",
    "DATAGRAM::dns",
    "DATAGRAM::ip",
    "DATAGRAM::ip6",
    "DATAGRAM::l2",
    "DATAGRAM::tcp",
    "DATAGRAM::udp",
    "SCTP::client_port",
    "SCTP::collect",
    "SCTP::local_port",
    "SCTP::mss",
    "SCTP::payload",
    "SCTP::ppi",
    "SCTP::release",
    "SCTP::respond",
    "SCTP::remote_port",
    "SCTP::rto_initial",
    "SCTP::rto_max",
    "SCTP::rto_min",
    "SCTP::sack_timeout",
    "SCTP::server_port",
    "DHCP::version",
    "DHCPv4::chaddr",
    "DHCPv4::ciaddr",
    "DHCPv4::drop",
    "DHCPv4::giaddr",
    "DHCPv4::hlen",
    "DHCPv4::hops",
    "DHCPv4::htype",
    "DHCPv4::len",
    "DHCPv4::opcode",
    "DHCPv4::option",
    "DHCPv4::reject",
    "DHCPv4::secs",
    "DHCPv4::siaddr",
    "DHCPv4::type",
    "DHCPv4::xid",
    "DHCPv4::yiaddr",
    "DHCPv6::drop",
    "DHCPv6::hop_count",
    "DHCPv6::len",
    "DHCPv6::link_address",
    "DHCPv6::msg_type",
    "DHCPv6::option",
    "DHCPv6::peer_address",
    "DHCPv6::reject",
    "DHCPv6::transaction_id",
    "REST::send",
    "OFFBOX::request",
    "TDS::msg",
    "TDS::session",
    "QOE::disable",
    "QOE::enable",
    "QOE::video",
    "IKE::auth_success",
    "IKE::cert",
    "IKE::san_dirname",
    "IKE::san_dns",
    "IKE::san_ediparty",
    "IKE::san_email",
    "IKE::san_ipadd",
    "IKE::san_othername",
    "IKE::san_rid",
    "IKE::san_uri",
    "IKE::san_x400",
    "IKE::subjectAltName",
    "FTP::allow_active_mode",
    "FTP::disable",
    "FTP::enable",
    "FTP::enforce_tls_session_reuse",
    "FTP::ftps_mode",
    "FTP::port",
    "IMAP::activation_mode",
    "IMAP::disable",
    "IMAP::enable",
    "POP3::activation_mode",
    "POP3::disable",
    "POP3::enable",
    "LDAP::activation_mode",
    "LDAP::disable",
    "LDAP::enable",
    "SMTPS::activation_mode",
    "SMTPS::disable",
    "SMTPS::enable",
    "NTLM::disable",
    "NTLM::enable",
    "PROTOCOL_INSPECTION::disable",
    "PROTOCOL_INSPECTION::id",
    "CLASSIFICATION::app",
    "CLASSIFICATION::category",
    "CLASSIFICATION::disable",
    "CLASSIFICATION::enable",
    "CLASSIFICATION::protocol",
    "CLASSIFICATION::result",
    "CLASSIFICATION::urlcat",
    "CLASSIFICATION::username",
    "CATEGORY::analytics",
    "CATEGORY::filetype",
    "CATEGORY::lookup",
    "CATEGORY::matchtype",
    "CATEGORY::result",
    "CATEGORY::safesearch",
    "ECA::client_machine_name",
    "ECA::disable",
    "ECA::domainname",
    "ECA::enable",
    "ECA::select",
    "ECA::status",
    "ECA::username",
    "AVR::disable",
    "AVR::disable_cspm_injection",
    "AVR::enable",
    "AVR::log",
    "BWC::color",
    "BWC::debug",
    "BWC::mark",
    "BWC::measure",
    "BWC::policy",
    "BWC::pps",
    "BWC::priority",
    "BWC::rate",
    "CLASSIFY::application",
    "CLASSIFY::category",
    "CLASSIFY::defer",
    "CLASSIFY::disable",
    "CLASSIFY::urlcat",
    "CLASSIFY::username",
    "FLOWTABLE::count",
    "FLOWTABLE::limit",
    "L7CHECK::protocol",
    "LINK::lasthop",
    "LINK::nexthop",
    "LINK::qos",
    "LINK::vlan_id",
    "NAME::lookup",
    "NAME::response",
    "RESOLV::lookup",
    "SOCKS::allowed",
    "SOCKS::destination",
    "SOCKS::version",
    "ICAP::header",
    "ICAP::method",
    "ICAP::status",
    "ICAP::uri",
    "CRYPTO::hash",
    "CRYPTO::sign",
    "CRYPTO::verify",
    "CRYPTO::decrypt",
    "CRYPTO::encrypt",
    "CRYPTO::keygen",
    "ASN1::decode",
    "ASN1::element",
    "ASN1::encode",
    "ILX::call",
    "ILX::init",
    "ILX::notify",
    "ip_protocol",
    "ip_tos",
    "ip_ttl",
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
    "DNS::tsig",
    "DNSMSG::header",
    "DNSMSG::record",
    "DNSMSG::section",
    "RESOLVER::name_lookup",
    "RESOLVER::summarize",
    "SSL::cert",
    "SSL::c3d",
    "SSL::cert_constraint",
    "SSL::collect",
    "SSL::cipher",
    "SSL::disable",
    "SSL::enable",
    "SSL::sessionid",
    "SSL::sni",
    "SSL::verify_result",
    "SSL::alpn",
    "SSL::allow_nonssl",
    "SSL::allow_dynamic_record_sizing",
    "SSL::authenticate",
    "SSL::clientrandom",
    "SSL::handshake",
    "SSL::is_renegotiation_secure",
    "SSL::maximum_record_size",
    "SSL::modssl_sessionid_headers",
    "SSL::mode",
    "SSL::nextproto",
    "SSL::payload",
    "SSL::profile",
    "SSL::renegotiate",
    "SSL::release",
    "SSL::secure_renegotiation",
    "SSL::session",
    "SSL::sessionsecret",
    "SSL::sessionticket",
    "SSL::unclean_shutdown",
    "SSL::tls13_secret",
    "SSL::forward_proxy",
    "X509::cert_fields",
    "X509::extensions",
    "X509::hash",
    "X509::issuer",
    "X509::not_valid_after",
    "X509::not_valid_before",
    "X509::pem2der",
    "X509::serial_number",
    "X509::signature_algorithm",
    "X509::subject",
    "X509::subject_public_key",
    "X509::subject_public_key_RSA_bits",
    "X509::subject_public_key_type",
    "X509::verify_cert_error_string",
    "X509::version",
    "X509::whole",
    "HTTP2::active",
    "HTTP2::concurrency",
    "HTTP2::disable",
    "HTTP2::disconnect",
    "HTTP2::enable",
    "HTTP2::header",
    "HTTP2::requests",
    "HTTP2::push",
    "HTTP2::stream",
    "HTTP2::version",
    "STREAM::disable",
    "STREAM::enable",
    "STREAM::encoding",
    "STREAM::expression",
    "STREAM::match",
    "STREAM::max_matchsize",
    "STREAM::replace",
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
    "HTTP::proxy",
    "REWRITE::disable",
    "REWRITE::enable",
    "REWRITE::payload",
    "REWRITE::post_process",
    "HTML::comment",
    "HTML::disable",
    "HTML::enable",
    "HTML::encode",
    "HTML::tag",
    "HTTPLOG::disable",
    "HTTPLOG::enable",
    "ISTATS::get",
    "ISTATS::incr",
    "ISTATS::remove",
    "ISTATS::set",
    "ntohl",
    "ntohs",
    "NSH::chain",
    "NSH::context",
    "NSH::md1",
    "NSH::mocksf",
    "NSH::path_id",
    "NSH::service_index",
    "ONECONNECT::detach",
    "ONECONNECT::label",
    "ONECONNECT::reuse",
    "ONECONNECT::select",
    "COMPRESS::buffer_size",
    "COMPRESS::disable",
    "COMPRESS::enable",
    "COMPRESS::gzip",
    "COMPRESS::method",
    "COMPRESS::nodelay",
    "DECOMPRESS::disable",
    "DECOMPRESS::enable",
    "WS::collect",
    "WS::disconnect",
    "WS::enabled",
    "WS::frame",
    "WS::masking",
    "WS::message",
    "WS::payload",
    "WS::payload_ivs",
    "WS::payload_processing",
    "WS::release",
    "WS::request",
    "WS::response",
    "HTTP::username",
    "IP::addr",
    "IP::version",
    "IP::hops",
    "IP::idle_timeout",
    "IP::ingress_drop_rate",
    "IP::ingress_rate_limit",
    "IP::intelligence",
    "IP::reputation",
    "IP::stats",
    "LB::down",
    "LB::bias",
    "LB::class",
    "LB::command",
    "LB::connect",
    "LB::connlimit",
    "LB::context_id",
    "LB::dst_tag",
    "LB::enable_decisionlog",
    "LB::mode",
    "LB::persist",
    "LB::prime",
    "LB::queue",
    "LB::reselect",
    "LB::server",
    "LB::snat",
    "LB::status",
    "LB::src_tag",
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
    "PROFILE::access",
    "PROFILE::antifraud",
    "PROFILE::auth",
    "PROFILE::avr",
    "PROFILE::diameter",
    "PROFILE::exchange",
    "PROFILE::ftp",
    "PROFILE::httpclass",
    "PROFILE::httpcompression",
    "PROFILE::oneconnect",
    "PROFILE::persist",
    "PROFILE::stream",
    "PROFILE::tftp",
    "PROFILE::vdi",
    "PROFILE::webacceleration",
    "PROFILE::xml",
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
    "md4",
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
    "rmd160",
    "traffic_group",
    "uniq_ordered_ip_list",
    "uniq_sorted_ip_list",
    "vlan_id",
    "substr",
    "close",
    "connect",
    "recv",
    "send",
    "xff_list",
    "xff_uniq_ordered_ip_list",
    "xff_uniq_sorted_ip_list",
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
    "VALIDATE::protocol",
    "MQTT::clean_session",
    "MQTT::client_id",
    "MQTT::insert",
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
    "MQTT::replace",
    "MQTT::respond",
    "MQTT::session_present",
    "MQTT::topic",
    "MQTT::type",
    "MQTT::username",
    "MQTT::will",
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
    "SIPALG::hairpin",
    "SIPALG::hairpin_default",
    "SIPALG::nonregister_subscriber_listener",
    "DEMANGLE::disable",
    "DEMANGLE::enable",
    "ISESSION::deduplication",
    "IVS_ENTRY::result",
    "PLUGIN::disable",
    "PLUGIN::enable",
    "SDP::field",
    "SDP::media",
    "SDP::session_id",
    "ACL::action",
    "ACL::eval",
    "LSN::address",
    "LSN::disable",
    "LSN::inbound",
    "LSN::inbound-entry",
    "LSN::persistence",
    "LSN::persistence-entry",
    "LSN::pool",
    "LSN::port",
    "XLAT::listen",
    "XLAT::listen_lifetime",
    "XLAT::src_addr",
    "XLAT::src_config",
    "XLAT::src_endpoint_reservation",
    "XLAT::src_nat_valid_range",
    "XLAT::src_port",
    "PCP::reject",
    "PCP::request",
    "PCP::response",
    "PSC::aaa_reporting_interval",
    "PSC::attr",
    "PSC::calling_id",
    "PSC::imeisv",
    "PSC::imsi",
    "PSC::ip_address",
    "PSC::lease_time",
    "PSC::policy",
    "PSC::subscriber_id",
    "PSC::tower_id",
    "PSC::user_name",
    "PEM::disable",
    "PEM::enable",
    "PEM::flow",
    "PEM::session",
    "PEM::subscriber",
    "CONNECTOR::disable",
    "CONNECTOR::enable",
    "CONNECTOR::profile",
    "CONNECTOR::remap",
    "TMM::cmp_count",
    "TMM::cmp_group",
    "TMM::cmp_groups",
    "TMM::cmp_primary_group",
    "TMM::cmp_unit",
    "POLICY::controls",
    "POLICY::names",
    "POLICY::rules",
    "POLICY::targets",
    "WAM::disable",
    "WAM::enable",
    "VDI::disable",
    "VDI::enable",
    "WEBSSO::disable",
    "WEBSSO::enable",
    "WEBSSO::select",
    "BIGTCP::release_flow",
    "TAP::action",
    "TAP::config",
    "TAP::insight",
    "TAP::insight_requested",
    "TAP::score",
    "HA::status",
    "DSLITE::remote_addr",
    "BIGPROTO::enable_fix_reset",
    "FIX::tag",
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
    "PSM::FTP::disable",
    "PSM::FTP::enable",
    "PSM::HTTP::disable",
    "PSM::HTTP::enable",
    "PSM::SMTP::disable",
    "PSM::SMTP::enable",
    "UDP::client_port",
    "UDP::debug_queue",
    "UDP::drop",
    "UDP::hold",
    "UDP::local_port",
    "UDP::max_buf_pkts",
    "UDP::max_rate",
    "UDP::mss",
    "UDP::payload",
    "UDP::release",
    "UDP::remote_port",
    "UDP::respond",
    "UDP::sendbuffer",
    "UDP::server_port",
    "UDP::unused_port",
    "TCP::congestion",
    "TCP::idletime",
    "TCP::keepalive",
    "TCP::nagle",
    "TCP::naglemode",
    "TCP::naglestate",
    "TCP::pacing",
    "TCP::proxybuffer",
    "TCP::proxybufferhigh",
    "TCP::proxybufferlow",
    "TCP::push_flag",
    "TCP::rcv_size",
    "TCP::recvwnd",
    "TCP::rto",
    "TCP::rttvar",
    "TCP::sendbuf",
    "TCP::setmss",
    "TCP::snd_cwnd",
    "TCP::snd_wnd",
    "RTSP::collect",
    "RTSP::header",
    "RTSP::method",
    "RTSP::msg_source",
    "RTSP::payload",
    "RTSP::release",
    "RTSP::respond",
    "RTSP::status",
    "RTSP::uri",
    "RTSP::version",
    "CACHE::accept_encoding",
    "CACHE::age",
    "CACHE::disable",
    "CACHE::disabled",
    "CACHE::enable",
    "CACHE::expire",
    "CACHE::fresh",
    "CACHE::header",
    "CACHE::headers",
    "CACHE::hits",
    "CACHE::payload",
    "CACHE::priority",
    "CACHE::statskey",
    "CACHE::trace",
    "CACHE::uri",
    "CACHE::useragent",
    "CACHE::userkey",
    "DOSL7::disable",
    "DOSL7::enable",
    "DOSL7::health",
    "DOSL7::is_ip_slowdown",
    "DOSL7::is_mitigated",
    "DOSL7::profile",
    "DOSL7::slowdown",
    "ASM::captcha",
    "ASM::captcha_age",
    "ASM::captcha_status",
    "ASM::client_ip",
    "ASM::conviction",
    "ASM::deception",
    "ASM::disable",
    "ASM::enable",
    "ASM::fingerprint",
    "ASM::is_authenticated",
    "ASM::login_status",
    "ASM::microservice",
    "ASM::payload",
    "ASM::policy",
    "ASM::raise",
    "ASM::severity",
    "ASM::signature",
    "ASM::status",
    "ASM::support_id",
    "ASM::threat_campaign",
    "ASM::unblock",
    "ASM::uncaptcha",
    "ASM::username",
    "ASM::violation",
    "ASM::violation_data",
    "BOTDEFENSE::action",
    "BOTDEFENSE::bot_anomalies",
    "BOTDEFENSE::bot_categories",
    "BOTDEFENSE::bot_name",
    "BOTDEFENSE::bot_signature",
    "BOTDEFENSE::bot_signature_category",
    "BOTDEFENSE::captcha_age",
    "BOTDEFENSE::captcha_status",
    "BOTDEFENSE::client_class",
    "BOTDEFENSE::client_type",
    "BOTDEFENSE::cookie_age",
    "BOTDEFENSE::cookie_status",
    "BOTDEFENSE::cs_allowed",
    "BOTDEFENSE::cs_attribute",
    "BOTDEFENSE::cs_possible",
    "BOTDEFENSE::device_id",
    "BOTDEFENSE::disable",
    "BOTDEFENSE::enable",
    "BOTDEFENSE::intent",
    "BOTDEFENSE::micro_service",
    "BOTDEFENSE::previous_action",
    "BOTDEFENSE::previous_request_age",
    "BOTDEFENSE::previous_support_id",
    "BOTDEFENSE::reason",
    "BOTDEFENSE::support_id",
    "ANTIFRAUD::alert_additional_info",
    "ANTIFRAUD::alert_bait_signatures",
    "ANTIFRAUD::alert_component",
    "ANTIFRAUD::alert_defined_value",
    "ANTIFRAUD::alert_details",
    "ANTIFRAUD::alert_device_id",
    "ANTIFRAUD::alert_expected_value",
    "ANTIFRAUD::alert_fingerprint",
    "ANTIFRAUD::alert_forbidden_added_element",
    "ANTIFRAUD::alert_guid",
    "ANTIFRAUD::alert_html",
    "ANTIFRAUD::alert_http_referrer",
    "ANTIFRAUD::alert_id",
    "ANTIFRAUD::alert_license_id",
    "ANTIFRAUD::alert_min",
    "ANTIFRAUD::alert_origin",
    "ANTIFRAUD::alert_resolved_value",
    "ANTIFRAUD::alert_score",
    "ANTIFRAUD::alert_transaction_data",
    "ANTIFRAUD::alert_transaction_id",
    "ANTIFRAUD::alert_type",
    "ANTIFRAUD::alert_username",
    "ANTIFRAUD::alert_view_id",
    "ANTIFRAUD::client_id",
    "ANTIFRAUD::device_id",
    "ANTIFRAUD::disable",
    "ANTIFRAUD::disable_alert",
    "ANTIFRAUD::disable_app_layer_encryption",
    "ANTIFRAUD::disable_auto_transactions",
    "ANTIFRAUD::disable_injection",
    "ANTIFRAUD::disable_malware",
    "ANTIFRAUD::disable_phishing",
    "ANTIFRAUD::enable",
    "ANTIFRAUD::enable_log",
    "ANTIFRAUD::fingerprint",
    "ANTIFRAUD::geo",
    "ANTIFRAUD::guid",
    "ANTIFRAUD::result",
    "ANTIFRAUD::username",
    "AAA::acct_result",
    "AAA::acct_send",
    "AAA::auth_result",
    "AAA::auth_send",
    "ACCESS::acl",
    "ACCESS2::access2_proc",
    "AM::age",
    "AM::application",
    "AM::cache",
    "AM::disable",
    "AM::expires",
    "AM::media_playlist",
    "AM::policy_node",
    "ACCESS::disable",
    "ACCESS::enable",
    "ACCESS::ephemeral-auth",
    "ACCESS::flowid",
    "ACCESS::log",
    "ACCESS::oauth",
    "ACCESS::perflow",
    "ACCESS::policy",
    "ACCESS::respond",
    "ACCESS::restrict_irule_events",
    "ACCESS::saml",
    "ACCESS::session",
    "ACCESS::user",
    "ACCESS::uuid",
    "AUTH::abort",
    "AUTH::authenticate",
    "AUTH::authenticate_continue",
    "AUTH::cert_credential",
    "AUTH::cert_issuer_credential",
    "AUTH::last_event_session_id",
    "AUTH::password_credential",
    "AUTH::response_data",
    "AUTH::ssl_cc_ldap_status",
    "AUTH::ssl_cc_ldap_username",
    "AUTH::start",
    "AUTH::status",
    "AUTH::subscribe",
    "AUTH::unsubscribe",
    "AUTH::username_credential",
    "AUTH::wantcredential_prompt",
    "AUTH::wantcredential_prompt_style",
    "AUTH::wantcredential_type",
    "FLOW::create_related",
    "FLOW::idle_duration",
    "FLOW::idle_timeout",
    "FLOW::peer",
    "FLOW::priority",
    "FLOW::refresh",
    "FLOW::this",
    "TCP::abc",
    "TCP::analytics",
    "TCP::autowin",
    "TCP::delayed_ack",
    "TCP::dsack",
    "TCP::earlyrxmit",
    "TCP::ecn",
    "TCP::enhanced_loss_recovery",
    "TCP::limxmit",
    "TCP::lossfilter",
    "TCP::lossfilterburst",
    "TCP::lossfilterrate",
    "TCP::rcv_scale",
    "TCP::rexmt_thresh",
    "TCP::rt_metrics_timeout",
    "TCP::snd_scale",
    "TCP::snd_ssthresh",
    "TCP::unused_port",
    "ROUTE::age",
    "ROUTE::bandwidth",
    "ROUTE::clear",
    "ROUTE::cwnd",
    "ROUTE::domain",
    "ROUTE::expiration",
    "ROUTE::mtu",
    "ROUTE::rtt",
    "ROUTE::rttvar",
}
SEMANTIC_MOCK_PROC_NAMES = {_mock_proc_name(name) for name in SEMANTIC_MOCK_COMMANDS}
RUNTIME_STATUS_VALUES = frozenset(
    {"handwritten-mock", "semantic-mock", "generated-stub", "no-runtime-handler"}
)
TARGET_STATUS_VALUES = frozenset(
    {
        "available-in-tmos-17.5",
        "introduced-after-tmos-17.5",
        "unavailable-in-tmos-17.5",
    }
)


def _capability_status(proc_name: str, handwritten: set[str], generated: set[str]) -> str:
    if proc_name in SEMANTIC_MOCK_PROC_NAMES:
        return "semantic-mock"
    if proc_name in handwritten:
        return "handwritten-mock"
    if proc_name in generated:
        return "generated-stub"
    return "no-runtime-handler"


def _catalog_event_names(namespace_registry: Any) -> list[str]:
    """Return the pinned event catalog plus documented 17.5 compatibility overrides."""
    return sorted(set(namespace_registry.all_event_names()) | set(TMOS_17_5_EVENT_OVERRIDES))


def _f5_catalog_command_names(command_registry: Any) -> list[str]:
    """Return only F5 commands, excluding Tk specs loaded by the Tcl bridge.

    The tcl-lsp test bridge may load Tk after an emulator session starts. Tk
    specs use ``dialects=None`` and therefore appear in a later
    ``command_names(dialect="f5-irules")`` query even though they are not part
    of the F5 iRules catalog. Filter them by their explicit package marker so
    catalog and conformance counts stay stable across process lifetime.
    """
    names: list[str] = []
    for name in command_registry.command_names(dialect="f5-irules"):
        spec = command_registry.get_any(name)
        if spec is not None and getattr(spec, "required_package", None) != "Tk":
            names.append(name)
    return sorted(names)


def _build_capabilities(
    root: Path,
    offset: int,
    limit: int,
    *,
    namespace: str | None = None,
    runtime_status: str | None = None,
    target_status: str | None = None,
) -> dict[str, Any]:
    """Build a chunked, machine-readable view of the tcl-lsp F5 registry."""
    if offset < 0:
        raise EmulatorInputError("capability offset must be non-negative")
    if not 1 <= limit <= 1000:
        raise EmulatorInputError("capability limit must be between 1 and 1000")
    for field, value, allowed in (
        ("namespace", namespace, None),
        ("runtime_status", runtime_status, RUNTIME_STATUS_VALUES),
        ("target_status", target_status, TARGET_STATUS_VALUES),
    ):
        if value is not None and (not isinstance(value, str) or not value):
            raise EmulatorInputError(f"capability {field} must be a non-empty string")
        if value is not None and allowed is not None and value not in allowed:
            raise EmulatorInputError(
                f"capability {field} must be one of: {', '.join(sorted(allowed))}"
            )

    _load_session_class(root)
    try:
        from compiler.registry import REGISTRY
        from compiler.registry.namespace_data import PROFILE_SPECS
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp capability registry: {exc}") from exc

    command_names = _f5_catalog_command_names(REGISTRY)
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
        "unavailable-in-tmos-17.5": 0,
    }
    for name in command_names:
        spec = REGISTRY.get_any(name)
        if spec is None:  # pragma: no cover - registry contract guard
            continue
        proc_name = _mock_proc_name(name)
        command_runtime_status = _capability_status(proc_name, handwritten, generated)
        status_counts[command_runtime_status] += 1
        command_target_status = _target_status(
            name,
            TMOS_17_5_POST_TARGET_COMMANDS,
            TMOS_17_5_UNAVAILABLE_COMMANDS,
        )
        target_status_counts[command_target_status] += 1
        requirement = spec.event_requires
        hover = getattr(spec, "hover", None)
        commands.append(
            {
                "name": name,
                "namespace": name.split("::", 1)[0] if "::" in name else "",
                "subcommands": sorted(spec.subcommands),
                "documentation": {
                    "summary": getattr(hover, "summary", "") if hover else "",
                    "synopsis": list(getattr(hover, "synopsis", ()) or ()) if hover else [],
                    "return_value": getattr(hover, "return_value", "") if hover else "",
                    "source": getattr(hover, "source", "") if hover else "",
                },
                "pure": bool(spec.pure),
                "unsafe": bool(spec.unsafe),
                "runtime_status": command_runtime_status,
                "target_status": command_target_status,
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
    for name in _catalog_event_names(NAMESPACE_REGISTRY):
        props = NAMESPACE_REGISTRY.get_props(name)
        override = TMOS_17_5_EVENT_OVERRIDES.get(name)
        if props is None and override is None:  # pragma: no cover - registry contract guard
            continue
        event_data = override if props is None else {
            "multiplicity": NAMESPACE_REGISTRY.event_multiplicity(name),
            "client_side": bool(props.client_side),
            "server_side": bool(props.server_side),
            "transport": props.transport,
            "implied_profiles": props.implied_profiles,
            "flow": bool(props.flow),
            "deprecated": bool(props.deprecated),
            "common": bool(props.common),
        }
        transport = event_data["transport"]
        events.append(
            {
                "name": name,
                "target_status": _target_status(
                    name,
                    TMOS_17_5_POST_TARGET_EVENTS,
                    TMOS_17_5_UNAVAILABLE_EVENTS,
                ),
                "multiplicity": event_data["multiplicity"],
                "client_side": event_data["client_side"],
                "server_side": event_data["server_side"],
                "transport": list(transport) if isinstance(transport, tuple) else transport,
                "implied_profiles": sorted(event_data["implied_profiles"]),
                "flow": event_data["flow"],
                "deprecated": event_data["deprecated"],
                "common": event_data["common"],
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

    filtered_commands = [
        command
        for command in commands
        if (
            namespace is None
            or command["namespace"] == namespace
        )
        and (runtime_status is None or command["runtime_status"] == runtime_status)
        and (target_status is None or command["target_status"] == target_status)
    ]
    start = min(offset, len(filtered_commands))
    end = min(start + limit, len(filtered_commands))
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "source": {
            "name": "tcl-lsp f5-irules registry",
            "commit": os.environ.get("TCL_LSP_COMMIT", "unknown"),
            "event_overrides": sorted(TMOS_17_5_EVENT_OVERRIDES),
        },
        "summary": {
            "command_count": len(commands),
            "filtered_command_count": len(filtered_commands),
            "event_count": len(events),
            "profile_count": len(profiles),
            "runtime_status_counts": status_counts,
            "target_status_counts": target_status_counts,
        },
        "chunk": {
            "offset": offset,
            "limit": limit,
            "count": end - start,
            "total": len(filtered_commands),
            "has_more": end < len(filtered_commands),
        },
        "filter": {
            "namespace": namespace,
            "runtime_status": runtime_status,
            "target_status": target_status,
        },
        "commands": filtered_commands[start:end],
        "events": events,
        "profiles": profiles,
    }


def _build_catalog(
    root: Path,
    chunk_size: int,
    *,
    namespace: str | None = None,
    runtime_status: str | None = None,
    target_status: str | None = None,
) -> dict[str, Any]:
    """Materialize the complete filtered command catalog as deterministic chunks."""
    if not 1 <= chunk_size <= 1000:
        raise EmulatorInputError("catalog chunk size must be between 1 and 1000")
    filters = {
        "namespace": namespace,
        "runtime_status": runtime_status,
        "target_status": target_status,
    }
    first = _build_capabilities(root, 0, chunk_size, **filters)
    chunks: list[dict[str, Any]] = []
    page = first
    while True:
        chunk = page["chunk"]
        chunks.append(
            {
                "offset": chunk["offset"],
                "limit": chunk["limit"],
                "count": chunk["count"],
                "has_more": chunk["has_more"],
                "commands": page["commands"],
            }
        )
        if not chunk["has_more"]:
            break
        if chunk["count"] <= 0:
            raise EmulatorInputError("catalog chunk pagination made no progress")
        page = _build_capabilities(
            root,
            chunk["offset"] + chunk["count"],
            chunk_size,
            **filters,
        )
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "source": first["source"],
        "filter": first["filter"],
        "summary": first["summary"],
        "chunking": {
            "chunk_size": chunk_size,
            "chunk_count": len(chunks),
        },
        "chunks": chunks,
        "events": first["events"],
        "profiles": first["profiles"],
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
    event_names = _catalog_event_names(NAMESPACE_REGISTRY)
    post_target_commands = sorted(
        name for name in status_map if name in TMOS_17_5_POST_TARGET_COMMANDS
    )
    unavailable_commands = sorted(
        name for name in status_map if name in TMOS_17_5_UNAVAILABLE_COMMANDS
    )
    post_target_events = sorted(
        name for name in event_names if name in TMOS_17_5_POST_TARGET_EVENTS
    )
    unavailable_events = sorted(
        name for name in event_names if name in TMOS_17_5_UNAVAILABLE_EVENTS
    )
    supported_events = [
        name
        for name in event_names
        if (
            name in PACKET_EVENT_ADAPTERS
            and name not in TMOS_17_5_POST_TARGET_EVENTS
            and name not in TMOS_17_5_UNAVAILABLE_EVENTS
        )
    ]
    implementation_buckets: dict[tuple[str, str], list[str]] = {}
    implementation_statuses = {"generated-stub", "no-runtime-handler"}
    for name, status in status_map.items():
        if (
            name in TMOS_17_5_POST_TARGET_COMMANDS
            or name in TMOS_17_5_UNAVAILABLE_COMMANDS
            or status not in implementation_statuses
        ):
            continue
        spec = registry.get_any(name)
        namespace = name.split("::", 1)[0] if "::" in name else ""
        # F5 command namespaces are conventionally uppercase. Global F5
        # commands are retained when their registry entry has event metadata;
        # lower-case Tcl library commands are not implementation work items.
        is_f5_command = bool(getattr(spec, "event_requires", None)) or namespace.isupper()
        if is_f5_command:
            implementation_buckets.setdefault((namespace, status), []).append(name)
    implementation_queue = [
        {
            "namespace": namespace,
            "runtime_status": status,
            "count": len(names),
        }
        for (namespace, status), names in sorted(implementation_buckets.items())
    ]
    return {
        "status": "ok",
        "schema_version": 1,
        "profile": "tmos-17.5",
        "tmos_version": TMOS_VERSION,
        "source": {
            "name": "tcl-lsp f5-irules registry",
            "commit": os.environ.get("TCL_LSP_COMMIT", "unknown"),
            "event_overrides": sorted(TMOS_17_5_EVENT_OVERRIDES),
            "unavailable_commands": sorted(TMOS_17_5_UNAVAILABLE_COMMANDS),
            "unavailable_events": sorted(TMOS_17_5_UNAVAILABLE_EVENTS),
        },
        "commands": {
            "catalog_count": len(status_map),
            "target_catalog_count": (
                len(status_map) - len(post_target_commands) - len(unavailable_commands)
            ),
            "post_target_count": len(post_target_commands),
            "post_target_commands": post_target_commands,
            "unavailable_count": len(unavailable_commands),
            "unavailable_commands": unavailable_commands,
            "runtime_status_counts": command_counts,
            "implementation_queue": {
                "candidate_statuses": sorted(implementation_statuses),
                "command_count": sum(item["count"] for item in implementation_queue),
                "buckets": implementation_queue,
            },
            "runtime_status_meaning": {
                "handwritten-mock": "implemented behavioral mock in the loaded Tcl framework",
                "semantic-mock": "implemented behavioral mock in the TesTcl adapter overlay",
                "generated-stub": "recognized command with generated placeholder behavior",
                "no-runtime-handler": "catalogued command without a matching runtime proc",
            },
        },
        "events": {
            "catalog_count": len(event_names),
            "target_catalog_count": len(event_names) - len(post_target_events) - len(unavailable_events),
            "post_target_count": len(post_target_events),
            "post_target_events": post_target_events,
            "unavailable_count": len(unavailable_events),
            "unavailable_events": unavailable_events,
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
    for name in _f5_catalog_command_names(REGISTRY):
        status_map[name] = _capability_status(_mock_proc_name(name), handwritten, generated)
    return REGISTRY, status_map


def _is_f5_runtime_command(name: str, spec: Any) -> bool:
    """Avoid warning on ordinary Tcl control commands in a rule."""
    return "::" in name or bool(getattr(spec, "event_requires", None))


def _rule_priority(value: str, context: str) -> int:
    """Validate one TMOS event priority declaration."""
    try:
        priority = int(value, 10)
    except (TypeError, ValueError):
        raise EmulatorInputError(f"{context} priority must be an integer from 0 through 1000") from None
    if not 0 <= priority <= 1000:
        raise EmulatorInputError(f"{context} priority must be an integer from 0 through 1000")
    return priority


def _rule_timing(value: str, context: str) -> str:
    """Normalize the timing spelling accepted by the pinned Tcl loader."""
    normalized = value.lower()
    if normalized in {"on", "enable"}:
        return "on"
    if normalized in {"off", "disable"}:
        return "off"
    raise EmulatorInputError(f"{context} timing must be on or off")


def _prepare_irule_source(
    root: Path, source: str
) -> tuple[str, list[dict[str, Any]]]:
    """Apply top-level ``priority``/``timing`` directives to event headers.

    The pinned tcl-lsp loader already handles explicit ``when EVENT priority N``
    headers, but it intentionally does not interpret the outer-scope forms.
    Segmenting the source with tcl-lsp keeps directives inside braced handler
    bodies from being mistaken for outer-scope declarations. The returned
    source is only a normalized copy; the user's source remains unchanged.
    """
    try:
        _load_session_class(root)
        from compiler.parsing.green_tree import tokenise
        from shared.tokens import TokenType
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp source parser: {exc}") from exc

    try:
        lex_tokens, _ = tokenise(source, 0, 0, 0)
        commands: list[tuple[list[str], list[Any]]] = []
        argv: list[Any] = []
        texts: list[str] = []

        def flush() -> None:
            if argv:
                commands.append((list(texts), list(argv)))
            argv.clear()
            texts.clear()

        previous_type = TokenType.EOL
        for token in lex_tokens:
            if token.type is TokenType.COMMENT:
                previous_type = token.type
                continue
            if token.type is TokenType.EOL:
                flush()
                previous_type = token.type
                continue
            if token.type is TokenType.SEP:
                previous_type = token.type
                continue
            # The upstream loader accepts adjacent ``when`` blocks in a
            # single line even though Tcl normally requires a separator. A
            # braced body is an unambiguous boundary for that compatibility
            # form, so split it here before interpreting attributes.
            if (
                token.text == "when"
                and texts
                and texts[0] == "when"
                and argv[-1].type is TokenType.STR
            ):
                flush()
                previous_type = TokenType.SEP
            if previous_type in (TokenType.SEP, TokenType.EOL):
                argv.append(token)
                texts.append(token.text)
            elif texts:
                texts[-1] += token.text
            previous_type = token.type
        flush()
    except Exception as exc:  # pragma: no cover - parser compatibility guard
        raise EmulatorInputError(f"could not parse iRule source controls: {exc}") from exc

    active_priority = 500
    active_timing = "on"
    replacements: list[tuple[int, int, str]] = []
    controls: list[dict[str, Any]] = []

    for texts, argv in commands:
        command_name = texts[0] if texts else ""
        if command_name == "priority":
            if len(texts) != 2:
                raise EmulatorInputError("priority requires exactly one value")
            active_priority = _rule_priority(texts[1], "outer")
            continue
        if command_name == "timing":
            if len(texts) != 2:
                raise EmulatorInputError("timing requires exactly one value")
            active_timing = _rule_timing(texts[1], "outer")
            continue
        if command_name != "when" or len(texts) < 3 or not argv:
            continue
        body_token = argv[-1]
        if body_token.type is not TokenType.STR or len(texts) < 3:
            continue

        event_name = texts[1]
        priority = active_priority
        timing = active_timing
        header = texts[2:-1]
        index = 0
        while index < len(header):
            keyword = header[index]
            if keyword == "priority":
                if index + 1 >= len(header):
                    raise EmulatorInputError(
                        f"when {event_name} priority requires a value"
                    )
                priority = _rule_priority(header[index + 1], f"when {event_name}")
                index += 2
                continue
            if keyword == "timing":
                if index + 1 >= len(header):
                    raise EmulatorInputError(
                        f"when {event_name} timing requires a value"
                    )
                timing = _rule_timing(header[index + 1], f"when {event_name}")
                index += 2
                continue
            raise EmulatorInputError(
                f"when {event_name} has unsupported event attribute {keyword}"
            )

        # Replace only the command header, leaving the body byte-for-byte
        # intact. Offsets are character offsets in the tcl-lsp token model,
        # which matches Python string slicing for the decoded source.
        header_start = argv[0].start.offset
        body_start = body_token.start.offset
        replacements.append(
            (
                header_start,
                body_start,
                f"when {event_name} priority {priority} timing {timing} ",
            )
        )
        controls.append(
            {
                "ordinal": len(controls),
                "event": event_name,
                "priority": priority,
                "timing": timing,
            }
        )

    prepared = source
    for start, end, replacement in reversed(replacements):
        prepared = prepared[:start] + replacement + prepared[end:]
    return prepared, controls


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
            target_status = _target_status(
                name,
                TMOS_17_5_POST_TARGET_COMMANDS,
                TMOS_17_5_UNAVAILABLE_COMMANDS,
            )
            row = {
                "name": name,
                "occurrences": usage[name]["occurrences"],
                "events": sorted(usage[name]["events"]),
                "runtime_status": status,
                "target_status": target_status,
            }
            command_rows.append(row)
            if target_status != "available-in-tmos-17.5":
                if target_status == "introduced-after-tmos-17.5":
                    message = f"{name} was introduced after TMOS 17.5"
                else:
                    message = f"{name} is unavailable in TMOS 17.5"
                warnings.append(
                    {
                        "code": "version-incompatible",
                        "severity": "error",
                        "command": name,
                        "target_status": target_status,
                        "message": message,
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
            event_target_status = _target_status(
                event_name,
                TMOS_17_5_POST_TARGET_EVENTS,
                TMOS_17_5_UNAVAILABLE_EVENTS,
            )
            if event_target_status != "available-in-tmos-17.5":
                if event_target_status == "introduced-after-tmos-17.5":
                    message = f"{event_name} was introduced after TMOS 17.5"
                else:
                    message = f"{event_name} is unavailable in TMOS 17.5"
                warnings.append(
                    {
                        "code": "version-incompatible",
                        "severity": "error",
                        "event": event_name,
                        "target_status": event_target_status,
                        "message": message,
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


def _tcl_list_value(values: list[str]) -> str:
    """Encode a Tcl list as a variable value rather than command syntax."""
    return " ".join(_tcl_quote(value) for value in values)


def _tcl_dict_value(values: dict[str, str]) -> str:
    """Encode a flat Tcl dictionary as a variable value."""
    flattened = [item for key, value in values.items() for item in (key, value)]
    return _tcl_list_value(flattened)


def _configure_asm(session: Any, asm: dict[str, Any]) -> None:
    """Install the deterministic ASM/WAF policy inputs in the Tcl session."""
    scalar_values = (
        "1" if asm["enabled"] else "0",
        asm["policy"],
        asm["client_ip"],
        asm["fingerprint"],
        asm["username"],
        asm["login_status"],
        asm["microservice"],
        asm["status"],
        asm["severity"],
        asm["support_id"],
        asm["captcha_status"],
        str(asm["captcha_age"]),
        asm["payload"],
    )
    session.eval_tcl(
        "::itest::semantic::asm_configure "
        + " ".join(_tcl_quote(value) for value in scalar_values)
    )

    records: list[str] = []
    for violation in asm["violations"]:
        details_flattened = [
            item
            for key, value in violation["details"].items()
            for item in (key, value)
        ]
        records.append(
            " ".join(
                [
                    _tcl_quote(violation["name"]),
                    _tcl_quote(violation["attack_type"]),
                    _tcl_quote(violation["rating"]),
                    _tcl_list(details_flattened),
                ]
            )
        )
    command = "::itest::semantic::asm_set_violations"
    if records:
        command += " " + " ".join(_tcl_quote(record) for record in records)
    session.eval_tcl(command)
    for field in ASM_SIGNATURE_FIELDS:
        session.eval_tcl(
            "::itest::semantic::asm_set_signatures "
            f"{_tcl_quote(field)} "
            f"{_tcl_list(asm['signatures'][field])}"
        )
    for field in ASM_CAMPAIGN_FIELDS:
        session.eval_tcl(
            "::itest::semantic::asm_set_campaigns "
            f"{_tcl_quote(field)} "
            f"{_tcl_list(asm['threat_campaigns'][field])}"
        )
    session.eval_tcl("::itest::semantic::asm_prepare_request 0 \"\"")


def _configure_botdefense(session: Any, botdefense: dict[str, Any]) -> None:
    """Install deterministic Bot Defense policy results in the Tcl session."""
    scalar_values = (
        "1" if botdefense["enabled"] else "0",
        botdefense["action"],
        botdefense["bot_name"],
        botdefense["bot_signature"],
        botdefense["bot_signature_category"],
        str(botdefense["captcha_age"]),
        botdefense["captcha_status"],
        botdefense["client_class"],
        botdefense["client_type"],
        str(botdefense["cookie_age"]),
        botdefense["cookie_status"],
        "1" if botdefense["cs_allowed"] else "0",
        "1" if botdefense["cs_possible"] else "0",
        "1" if botdefense["cs_attribute_device_id"] else "0",
        str(botdefense["device_id"]),
        botdefense["intent"],
        botdefense["previous_action"],
        str(botdefense["previous_request_age"]),
        botdefense["previous_support_id"],
        botdefense["reason"],
        botdefense["support_id"],
    )
    session.eval_tcl(
        "::itest::semantic::botdefense_configure " + _tcl_list(list(scalar_values))
    )
    session.eval_tcl(
        "::itest::semantic::botdefense_set_lists "
        f"{_tcl_list(botdefense['bot_anomalies'])} "
        f"{_tcl_list(botdefense['bot_categories'])}"
    )
    session.eval_tcl(
        "::itest::semantic::botdefense_set_micro_service "
        f"{_tcl_list([botdefense['micro_service']['name'], botdefense['micro_service']['type']])}"
    )
    session.eval_tcl("::itest::semantic::botdefense_prepare_request")


def _configure_antifraud(session: Any, antifraud: dict[str, Any]) -> None:
    """Install deterministic Anti-Fraud identity, alert, and policy state."""
    scalar_values = (
        "1" if antifraud["enabled"] else "0",
        antifraud["profile"],
        "1" if antifraud["login"] else "0",
        "1" if antifraud["alert"] else "0",
        antifraud["client_id"],
        antifraud["device_id"],
        antifraud["fingerprint"],
        antifraud["geo"],
        antifraud["guid"],
        antifraud["result"],
        antifraud["username"],
        antifraud["license_id"],
    )
    session.eval_tcl(
        "::itest::semantic::antifraud_configure " + _tcl_list(list(scalar_values))
    )
    field_pairs: list[str] = []
    for field in (*ANTIFRAUD_ALERT_VALUE_FIELDS, *ANTIFRAUD_ALERT_FLAG_FIELDS):
        field_pairs.extend((field, antifraud["fields"][field]))
    session.eval_tcl(
        "::itest::semantic::antifraud_set_alert_fields " + _tcl_list(field_pairs)
    )
    session.eval_tcl(
        "::itest::semantic::antifraud_prepare_request "
        f"{_tcl_quote('1' if antifraud['login'] else '0')} "
        f"{_tcl_quote('1' if antifraud['alert'] else '0')}"
    )


def _configure_auth(session: Any, auth: dict[str, Any]) -> None:
    """Install deterministic AUTH session defaults and result behavior."""
    response_pairs: list[str] = []
    for key, value in auth["response_data"].items():
        response_pairs.extend((key, value))
    scalar_values = [
        "1" if auth["enabled"] else "0",
        auth["result"],
        auth["type"],
        auth["service"],
        auth["prompt"],
        auth["prompt_style"],
        auth["credential_type"],
        auth["ldap_status"],
        auth["ldap_username"],
    ]
    session.eval_tcl(
        "::itest::semantic::auth_configure "
        + _tcl_list(scalar_values)
        + " "
        + _tcl_list(response_pairs)
    )


def _configure_aaa(session: Any, aaa: dict[str, Any]) -> None:
    """Install deterministic AAA request result defaults."""
    values = [
        "1" if aaa["enabled"] else "0",
        aaa["auth_result"],
        aaa["acct_result"],
    ]
    session.eval_tcl("::itest::semantic::aaa_configure " + _tcl_list(values))


def _configure_access(
    session: Any, access: dict[str, Any], *, auto_interest: bool = False
) -> None:
    """Install deterministic APM access-policy and session defaults."""
    scalar_values = [
        "1" if access["enabled"] else "0",
        access["acl_result"],
        access["policy_result"],
        access["policy_agent_id"],
        "1" if access["policy_uri"] else "0",
        access["flow_id"],
        access["ephemeral_auth_password"],
        "1" if auto_interest else "0",
    ]
    session_data: list[str] = []
    for key, value in access["session_data"].items():
        session_data.extend((key, value))
    perflow_data: list[str] = []
    for key, value in access["perflow"].items():
        perflow_data.extend((key, value))
    session.eval_tcl(
        "::itest::semantic::access_configure "
        + _tcl_list(scalar_values)
        + " "
        + _tcl_list(access["acl_lookup"])
        + " "
        + _tcl_list(access["acl_matched"])
        + " "
        + _tcl_list(session_data)
        + " "
        + _tcl_list(perflow_data)
    )


def _configure_ip(session: Any, ip_config: dict[str, Any]) -> None:
    """Install deterministic IP path, intelligence, and reputation inputs."""
    session.eval_tcl(
        "::itest::semantic::ip_configure "
        f"{_tcl_quote(str(ip_config['hops']))}"
    )
    for address, categories in ip_config["intelligence"].items():
        category_list = "[list " + " ".join(_tcl_quote(category) for category in categories) + "]"
        session.eval_tcl(
            "::itest::semantic::ip_set_intelligence "
            f"{_tcl_quote(address)} {category_list}"
        )
    for address, categories in ip_config["reputation"].items():
        category_list = "[list " + " ".join(_tcl_quote(category) for category in categories) + "]"
        session.eval_tcl(
            "::itest::semantic::ip_set_reputation "
            f"{_tcl_quote(address)} {category_list}"
        )


def _configure_route(session: Any, route_config: dict[str, Any]) -> None:
    """Install deterministic route-domain and congestion-metric inputs."""
    flattened: list[str] = []
    for metric in route_config["metrics"]:
        flattened.extend(
            [
                metric["destination"],
                metric["gateway"],
                str(metric["age"]),
                str(metric["expiration"]),
                str(metric["mtu"]),
                str(metric["rtt"]),
                str(metric["rttvar"]),
                str(metric["cwnd"]),
                str(metric["bandwidth"]),
            ]
        )
    session.eval_tcl(
        "::itest::semantic::route_configure "
        f"{_tcl_quote(route_config['domain'])} {_tcl_list(flattened)}"
    )


def _configure_http_proxy(session: Any, proxy_config: dict[str, Any]) -> None:
    """Install deterministic explicit-proxy and proxy-chaining inputs."""
    chain = proxy_config["chain"]
    values = (
        "1" if proxy_config["enabled"] else "0",
        "1" if proxy_config["uri_rewrite"] else "0",
        "1" if proxy_config["resolved"] else "0",
        proxy_config["addr"],
        str(proxy_config["port"]),
        str(proxy_config["rtdom"]),
        proxy_config["iptuple"],
        "1" if chain["enabled"] else "0",
        chain["host"],
        str(chain["port"]),
    )
    session.eval_tcl(
        "::itest::semantic::http_proxy_configure "
        + " ".join(_tcl_quote(value) for value in values)
    )
    if not chain["responses_explicit"]:
        response = chain["response"]
        response_values = (
            "1" if response is not None else "0",
            str(response["status"] if response is not None else 200),
            response["reason"] if response is not None else "",
            _tcl_list(
                [
                    item
                    for name, value in (response["headers"] if response is not None else {}).items()
                    for item in (name, value)
                ]
            ),
            response["body"] if response is not None else "",
        )
        session.eval_tcl(
            "::itest::semantic::http_proxy_chain_response_configure "
            + " ".join(
                value if index == 3 else _tcl_quote(value)
                for index, value in enumerate(response_values)
            )
        )
        return
    response_records = []
    for response in chain["responses"]:
        response_headers = _tcl_list(
            [
                item
                for name, value in response["headers"].items()
                for item in (name, value)
            ]
        )
        response_records.append(
            "{" + " ".join(
                (
                    _tcl_quote(str(response["status"])),
                    _tcl_quote(response["reason"]),
                    response_headers,
                    _tcl_quote(response["body"]),
                )
            ) + "}"
        )
    session.eval_tcl(
        "::itest::semantic::http_proxy_chain_responses_configure "
        + "{" + " ".join(response_records) + "}"
    )


def _configure_flowtable(session: Any, flowtable_config: dict[str, Any]) -> None:
    """Install deterministic FLOWTABLE counts and limits."""
    def flatten_pairs(values: dict[str, int]) -> list[str]:
        return [
            item
            for key, value in values.items()
            for item in (key, str(value))
        ]

    session.eval_tcl(
        "::itest::semantic::flowtable_configure "
        f"{_tcl_quote(str(flowtable_config['count_global']))} "
        f"{_tcl_list(flatten_pairs(flowtable_config['count_virtual']))} "
        f"{_tcl_list(flatten_pairs(flowtable_config['count_route_domain']))} "
        f"{_tcl_list(flatten_pairs(flowtable_config['limit_virtual']))} "
        f"{_tcl_list(flatten_pairs(flowtable_config['limit_route_domain']))}"
    )


def _configure_sideband(session: Any, sideband_config: dict[str, dict[str, str]]) -> None:
    """Install bounded, deterministic sideband connection fixtures."""
    flattened: list[str] = []
    for destination, fixture in sideband_config.items():
        flattened.extend(
            (destination, fixture["connect_status"], fixture["response"])
        )
    session.eval_tcl(
        "::itest::semantic::sideband_configure " + _tcl_list(flattened)
    )


def _configure_ifiles(session: Any, ifiles: dict[str, dict[str, str]]) -> None:
    """Install bounded, deterministic iFile fixtures in the Tcl session."""
    records = [
        _tcl_list_value(
            [
                name,
                fixture["content_base64"],
                fixture["last_updated_by"],
                fixture["last_update_time"],
                fixture["revision"],
                fixture["checksum"],
            ]
        )
        for name, fixture in ifiles.items()
    ]
    session.eval_tcl("::itest::semantic::ifile_configure " + _tcl_list(records))


def _configure_urlcat(session: Any, urlcat: dict[str, Any]) -> None:
    """Install deterministic URL-categorization lookup fixtures."""
    def category_list(values: list[str]) -> str:
        return "[list " + " ".join(_tcl_quote(value) for value in values) + "]"

    session.eval_tcl(
        "::itest::semantic::urlcat_configure "
        + category_list(urlcat["default"])
    )
    for kind in ("queries", "blind_queries"):
        for lookup, categories in urlcat[kind].items():
            session.eval_tcl(
                "::itest::semantic::urlcat_set "
                f"{_tcl_quote(kind)} {_tcl_quote(lookup)} "
                f"{category_list(categories)}"
            )


def _configure_cpu(session: Any, cpu_usage: dict[str, str | list[str]]) -> None:
    flattened: list[str] = []
    for interval, value in cpu_usage.items():
        encoded = _tcl_list_value(value) if isinstance(value, list) else value
        flattened.extend((interval, encoded))
    session.eval_tcl("::itest::semantic::cpu_configure " + _tcl_list(flattened))


def _configure_whereis(
    session: Any, records: dict[str, dict[str, str]]
) -> None:
    flattened: list[str] = []
    for address, record in records.items():
        flattened.extend((address, _tcl_dict_value(record)))
    session.eval_tcl("::itest::semantic::whereis_configure " + _tcl_list(flattened))


def _configure_pem_dtos(session: Any, records: dict[str, str]) -> None:
    flattened: list[str] = []
    for input_value, result in records.items():
        flattened.extend((input_value, result))
    session.eval_tcl("::itest::semantic::pem_dtos_configure " + _tcl_list(flattened))


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


def _event_error_snapshot(session: Any) -> list[dict[str, str]]:
    """Decode handler errors captured by the adapter's fire_event wrapper."""
    errors: list[dict[str, str]] = []
    for raw_error in _split_tcl_list(
        session.eval_tcl("::itest::semantic::event_errors_snapshot")
    ):
        parts = _split_tcl_list(raw_error)
        if len(parts) != 3:
            raise EmulatorInputError("invalid iRule handler error state")
        errors.append({"event": parts[0], "priority": parts[1], "message": parts[2]})
    return errors


def _semantic_snapshot(session: Any) -> dict[str, Any]:
    stats_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::stats_snapshot"))
    stats = {
        name: value
        for name, value in zip(stats_parts[::2], stats_parts[1::2])
    }
    istats_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::istats_snapshot")
    )
    if len(istats_parts) % 2:
        raise EmulatorInputError("invalid ISTATS state")
    istats_keys = istats_parts[::2]
    if len(set(istats_keys)) != len(istats_keys):
        raise EmulatorInputError("duplicate ISTATS key")
    istats = dict(zip(istats_keys, istats_parts[1::2]))
    oneconnect_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::oneconnect_snapshot")
    )
    if len(oneconnect_parts) != 4:
        raise EmulatorInputError("invalid ONECONNECT state")
    oneconnect = {
        "detach_enabled": oneconnect_parts[0] == "1",
        "reuse_enabled": oneconnect_parts[1] == "1",
        "select": oneconnect_parts[2],
        "label": oneconnect_parts[3],
    }
    link_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::link_snapshot")
    )
    if len(link_parts) != 20 or link_parts[::2] != [
        "qos",
        "vlan_id",
        "lasthop_mac",
        "lasthop_id",
        "lasthop_type",
        "lasthop_name",
        "nexthop_mac",
        "nexthop_id",
        "nexthop_type",
        "nexthop_name",
    ]:
        raise EmulatorInputError("invalid link state")
    link_values = dict(zip(link_parts[::2], link_parts[1::2]))
    try:
        link_qos = int(link_values["qos"])
        link_vlan_id = int(link_values["vlan_id"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid link numeric state") from None
    if not 0 <= link_qos <= 7 or link_vlan_id < 0:
        raise EmulatorInputError("invalid link numeric state")
    for hop in ("lasthop", "nexthop"):
        for field in (f"{hop}_mac", f"{hop}_id", f"{hop}_type", f"{hop}_name"):
            value = link_values[field]
            if "\x00" in value or len(value.encode("utf-8")) > 4096:
                raise EmulatorInputError(f"invalid link {hop} {field} state")
    link = {
        "qos": link_qos,
        "vlan_id": link_vlan_id,
        "lasthop_mac": link_values["lasthop_mac"],
        "lasthop_id": link_values["lasthop_id"],
        "lasthop_type": link_values["lasthop_type"],
        "lasthop_name": link_values["lasthop_name"],
        "nexthop_mac": link_values["nexthop_mac"],
        "nexthop_id": link_values["nexthop_id"],
        "nexthop_type": link_values["nexthop_type"],
        "nexthop_name": link_values["nexthop_name"],
    }
    legacy_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::legacy_connection_snapshot")
    )
    if len(legacy_parts) != 12 or legacy_parts[::2] != [
        "forwarded",
        "rateclass",
        "translate_address_enabled",
        "translate_port_enabled",
        "translate_service_enabled",
        "link_qos",
    ]:
        raise EmulatorInputError("invalid legacy connection state")
    legacy_values = dict(zip(legacy_parts[::2], legacy_parts[1::2]))
    for name in (
        "forwarded",
        "translate_address_enabled",
        "translate_port_enabled",
        "translate_service_enabled",
    ):
        if legacy_values[name] not in {"0", "1"}:
            raise EmulatorInputError(f"invalid legacy {name} state")
    try:
        legacy_qos = int(legacy_values["link_qos"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid legacy link QoS state") from None
    if not 0 <= legacy_qos <= 7:
        raise EmulatorInputError("invalid legacy link QoS state")
    legacy = {
        "forwarded": legacy_values["forwarded"] == "1",
        "rateclass": legacy_values["rateclass"],
        "translate_address_enabled": legacy_values["translate_address_enabled"] == "1",
        "translate_port_enabled": legacy_values["translate_port_enabled"] == "1",
        "translate_service_enabled": legacy_values["translate_service_enabled"] == "1",
        "link_qos": legacy_qos,
    }
    sideband_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::sideband_snapshot")
    )
    if (
        len(sideband_parts) != 4
        or sideband_parts[0] != "next_id"
        or sideband_parts[2] != "connections"
    ):
        raise EmulatorInputError("invalid sideband state")
    try:
        sideband_next_id = int(sideband_parts[1])
    except (TypeError, ValueError):
        raise EmulatorInputError("invalid sideband next-id state") from None
    if sideband_next_id < 0:
        raise EmulatorInputError("invalid sideband next-id state")
    sideband_connections: list[dict[str, Any]] = []
    sideband_handles: set[str] = set()
    for raw_connection in _split_tcl_list(sideband_parts[3]):
        connection_parts = _split_tcl_list(raw_connection)
        if len(connection_parts) != 16 or connection_parts[::2] != [
            "handle",
            "destination",
            "protocol",
            "status",
            "closed",
            "sent_bytes",
            "received_bytes",
            "buffered_bytes",
        ]:
            raise EmulatorInputError("invalid sideband connection state")
        connection = dict(
            zip(connection_parts[::2], connection_parts[1::2])
        )
        handle = connection["handle"]
        if not handle or handle in sideband_handles:
            raise EmulatorInputError("invalid or duplicate sideband connection handle")
        sideband_handles.add(handle)
        if connection["status"] not in {
            "connected", "closed", "error", "refused", "timeout", "unreachable"
        }:
            raise EmulatorInputError("invalid sideband connection status")
        if connection["closed"] not in {"0", "1"}:
            raise EmulatorInputError("invalid sideband closed state")
        try:
            protocol = int(connection["protocol"])
            sent_bytes = int(connection["sent_bytes"])
            received_bytes = int(connection["received_bytes"])
            buffered_bytes = int(connection["buffered_bytes"])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError("invalid sideband numeric state") from None
        if (
            not 0 <= protocol <= 255
            or sent_bytes < 0
            or received_bytes < 0
            or buffered_bytes < 0
        ):
            raise EmulatorInputError("invalid sideband numeric state")
        sideband_connections.append(
            {
                "handle": handle,
                "destination": connection["destination"],
                "protocol": protocol,
                "status": connection["status"],
                "closed": connection["closed"] == "1",
                "sent_bytes": sent_bytes,
                "received_bytes": received_bytes,
                "buffered_bytes": buffered_bytes,
            }
        )
    sideband = {
        "next_id": sideband_next_id,
        "connections": sideband_connections,
    }
    ifile_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::ifile_snapshot")
    )
    if len(ifile_parts) != 4 or ifile_parts[::2] != ["names", "accesses"]:
        raise EmulatorInputError("invalid iFile state")
    ifile_names = _split_tcl_list(ifile_parts[1])
    ifile_accesses: list[dict[str, str]] = []
    for raw_access in _split_tcl_list(ifile_parts[3]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or access_parts[0] not in {
            "listall",
            "get",
            "attributes",
            "size",
            "last_updated_by",
            "last_update_time",
            "revision",
            "checksum",
        }:
            raise EmulatorInputError("invalid iFile access state")
        ifile_accesses.append({"operation": access_parts[0], "name": access_parts[1]})
    ifile = {
        "names": ifile_names,
        "accesses": ifile_accesses,
    }
    urlcat_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::urlcat_snapshot")
    )
    if len(urlcat_parts) != 8 or urlcat_parts[::2] != [
        "default",
        "query_count",
        "blind_query_count",
        "accesses",
    ]:
        raise EmulatorInputError("invalid URL categorization state")
    urlcat_default = _split_tcl_list(urlcat_parts[1])
    if not urlcat_default or any(
        not category or "\x00" in category or len(category.encode("utf-8")) > 4096
        for category in urlcat_default
    ):
        raise EmulatorInputError("invalid URL categorization default state")
    try:
        query_count = int(urlcat_parts[3])
        blind_query_count = int(urlcat_parts[5])
    except (TypeError, ValueError):
        raise EmulatorInputError("invalid URL categorization fixture count") from None
    if query_count < 0 or blind_query_count < 0:
        raise EmulatorInputError("invalid URL categorization fixture count")
    urlcat_accesses: list[dict[str, str]] = []
    for raw_access in _split_tcl_list(urlcat_parts[7]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or access_parts[0] not in {
            "queries",
            "blind_queries",
        }:
            raise EmulatorInputError("invalid URL categorization access state")
        if not access_parts[1] or "\x00" in access_parts[1] or len(
            access_parts[1].encode("utf-8")
        ) > 4096:
            raise EmulatorInputError("invalid URL categorization access state")
        urlcat_accesses.append(
            {"kind": access_parts[0], "input": access_parts[1]}
        )
    urlcat = {
        "default": urlcat_default,
        "query_count": query_count,
        "blind_query_count": blind_query_count,
        "accesses": urlcat_accesses,
    }
    session_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::session_snapshot")
    )
    if len(session_parts) != 6 or session_parts[::2] != [
        "count", "records", "accesses"
    ]:
        raise EmulatorInputError("invalid session table state")
    try:
        session_count = int(session_parts[1])
    except (TypeError, ValueError):
        raise EmulatorInputError("invalid session table count") from None
    if session_count < 0 or session_count > 1024:
        raise EmulatorInputError("invalid session table count")
    session_records: list[dict[str, Any]] = []
    session_keys: set[tuple[str, str]] = set()
    for raw_record in _split_tcl_list(session_parts[3]):
        record_parts = _split_tcl_list(raw_record)
        if len(record_parts) != 8 or record_parts[::2] != [
            "mode", "key", "data", "timeout"
        ]:
            raise EmulatorInputError("invalid session table record")
        record = dict(zip(record_parts[::2], record_parts[1::2]))
        mode = record["mode"]
        key = record["key"]
        if mode not in {"simple", "source_addr", "sticky", "dest_addr", "ssl", "uie", "hash", "sip"}:
            raise EmulatorInputError("invalid session table mode")
        if not key or "\x00" in key or len(key.encode("utf-8")) > 4096:
            raise EmulatorInputError("invalid session table key")
        if "\x00" in record["data"] or len(record["data"].encode("utf-8")) > 1048576:
            raise EmulatorInputError("invalid session table data")
        try:
            timeout = int(record["timeout"])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid session table timeout") from None
        if not 0 <= timeout <= 2147483647:
            raise EmulatorInputError("invalid session table timeout")
        identity = (mode, key)
        if identity in session_keys:
            raise EmulatorInputError("duplicate session table record")
        session_keys.add(identity)
        session_records.append({
            "mode": mode,
            "key": key,
            "data": record["data"],
            "timeout": timeout,
        })
    if len(session_records) != session_count:
        raise EmulatorInputError("inconsistent session table count")
    session_accesses: list[dict[str, str]] = []
    for raw_access in _split_tcl_list(session_parts[5]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 3 or access_parts[0] not in {"add", "lookup", "delete"}:
            raise EmulatorInputError("invalid session table access state")
        if access_parts[1] not in {"simple", "source_addr", "sticky", "dest_addr", "ssl", "uie", "hash", "sip"}:
            raise EmulatorInputError("invalid session table access mode")
        if not access_parts[2] or "\x00" in access_parts[2] or len(access_parts[2].encode("utf-8")) > 4096:
            raise EmulatorInputError("invalid session table access key")
        session_accesses.append({
            "operation": access_parts[0],
            "mode": access_parts[1],
            "key": access_parts[2],
        })
    session_state = {
        "count": session_count,
        "records": session_records,
        "accesses": session_accesses,
    }
    sharedvar_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::sharedvar_snapshot")
    )
    if len(sharedvar_parts) != 2 or sharedvar_parts[0] != "names":
        raise EmulatorInputError("invalid sharedvar state")
    sharedvar_values: list[dict[str, str]] = []
    sharedvar_names: set[str] = set()
    for raw_value in _split_tcl_list(sharedvar_parts[1]):
        value_parts = _split_tcl_list(raw_value)
        if len(value_parts) != 4 or value_parts[::2] != ["name", "value"]:
            raise EmulatorInputError("invalid sharedvar value state")
        name = value_parts[1]
        value = value_parts[3]
        if (
            not name
            or name in sharedvar_names
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            or len(name.encode("utf-8")) > 256
            or "\x00" in value
        ):
            raise EmulatorInputError("invalid sharedvar value state")
        sharedvar_names.add(name)
        sharedvar_values.append({"name": name, "value": value})
    sharedvar_state = {"names": sharedvar_values}
    traffic_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::traffic_intents_snapshot")
    )
    if len(traffic_parts) != 2 or traffic_parts[0] != "intents":
        raise EmulatorInputError("invalid traffic intent state")
    traffic_intents: list[dict[str, Any]] = []
    previous_ordinal = 0
    seen_ordinals: set[int] = set()
    for raw_intent in _split_tcl_list(traffic_parts[1]):
        intent_parts = _split_tcl_list(raw_intent)
        if len(intent_parts) != 6 or intent_parts[::2] != [
            "ordinal", "kind", "data"
        ]:
            raise EmulatorInputError("invalid traffic intent record")
        try:
            ordinal = int(intent_parts[1])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid traffic intent ordinal") from None
        if ordinal <= previous_ordinal or ordinal in seen_ordinals:
            raise EmulatorInputError("invalid traffic intent ordinal")
        kind = intent_parts[3]
        if kind not in {"clone", "listen", "relate_client", "relate_server", "use"}:
            raise EmulatorInputError("invalid traffic intent kind")
        data = _split_tcl_list(intent_parts[5])
        if any("\x00" in value for value in data) or sum(
            len(value.encode("utf-8")) for value in data
        ) > 16384:
            raise EmulatorInputError("invalid traffic intent data")
        previous_ordinal = ordinal
        seen_ordinals.add(ordinal)
        traffic_intents.append({
            "ordinal": ordinal,
            "kind": kind,
            "data": data,
        })
    if len(traffic_intents) > 256:
        raise EmulatorInputError("too many traffic intent records")
    traffic_state = {"intents": traffic_intents}
    utility_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::legacy_fixture_snapshot")
    )
    if len(utility_parts) != 6 or utility_parts[::2] != [
        "cpu", "whereis", "pem_dtos"
    ]:
        raise EmulatorInputError("invalid legacy utility state")
    cpu_accesses: list[dict[str, Any]] = []
    for raw_access in _split_tcl_list(utility_parts[1]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or access_parts[0] not in CPU_INTERVALS:
            raise EmulatorInputError("invalid CPU access state")
        values = _split_tcl_list(access_parts[1])
        expected_count = 3 if access_parts[0] in {"all_seconds", "all_minutes"} else 1
        if len(values) != expected_count:
            raise EmulatorInputError("invalid CPU access value")
        for value in values:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                raise EmulatorInputError("invalid CPU access value") from None
            if not math.isfinite(numeric) or not 0 <= numeric <= 100:
                raise EmulatorInputError("invalid CPU access value")
        cpu_accesses.append({
            "interval": access_parts[0],
            "value": values if expected_count == 3 else values[0],
        })
    if len(cpu_accesses) > 1024:
        raise EmulatorInputError("too many CPU access records")

    whereis_accesses: list[dict[str, Any]] = []
    for raw_access in _split_tcl_list(utility_parts[3]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 3:
            raise EmulatorInputError("invalid whereis access state")
        address = access_parts[0]
        fields = _split_tcl_list(access_parts[1])
        values = _split_tcl_list(access_parts[2])
        if (
            not address
            or "\x00" in address
            or len(address.encode("utf-8")) > 4096
            or not fields
            or len(fields) > 8
            or len(fields) != len(values)
            or any(field not in WHEREIS_FIELDS for field in fields)
            or any(
                "\x00" in value or len(value.encode("utf-8")) > 4096
                for value in values
            )
        ):
            raise EmulatorInputError("invalid whereis access state")
        whereis_accesses.append({
            "address": address,
            "fields": fields,
            "values": values,
        })
    if len(whereis_accesses) > 1024:
        raise EmulatorInputError("too many whereis access records")

    pem_dtos_accesses: list[dict[str, str]] = []
    for raw_access in _split_tcl_list(utility_parts[5]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or any(
            "\x00" in value or len(value.encode("utf-8")) > 4096
            for value in access_parts
        ):
            raise EmulatorInputError("invalid pem_dtos access state")
        pem_dtos_accesses.append({
            "input": access_parts[0],
            "value": access_parts[1],
        })
    if len(pem_dtos_accesses) > 1024:
        raise EmulatorInputError("too many pem_dtos access records")
    legacy_utilities = {
        "cpu": cpu_accesses,
        "whereis": whereis_accesses,
        "pem_dtos": pem_dtos_accesses,
    }
    diagnostics_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::diagnostics_snapshot")
    )
    if len(diagnostics_parts) != 20 or diagnostics_parts[::2] != [
        "check_level",
        "check_accesses",
        "tcpdump_accesses",
        "diag_test_accesses",
        "line_accesses",
        "accumulate_pending",
        "accumulate_invoked",
        "accumulate_suspended",
        "accumulate_count",
        "accumulate_accesses",
    ]:
        raise EmulatorInputError("invalid diagnostic/control state")
    check_level = diagnostics_parts[1]
    if check_level not in {"none", "syntax", "config", "strict"}:
        raise EmulatorInputError("invalid iRule validation level")
    check_accesses: list[dict[str, Any]] = []
    for raw_access in _split_tcl_list(diagnostics_parts[3]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or access_parts[0] not in {
            "none", "syntax", "config", "strict"
        }:
            raise EmulatorInputError("invalid check access state")
        try:
            argument_count = int(access_parts[1])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid check access state") from None
        if argument_count not in {0, 1}:
            raise EmulatorInputError("invalid check access argument count")
        check_accesses.append({
            "level": access_parts[0],
            "argument_count": argument_count,
        })
    if len(check_accesses) > 1024:
        raise EmulatorInputError("too many check access records")

    tcpdump_accesses: list[list[str]] = []
    for raw_access in _split_tcl_list(diagnostics_parts[5]):
        args = _split_tcl_list(raw_access)
        if len(args) > 32 or any(
            "\x00" in value or len(value.encode("utf-8")) > 1048576
            for value in args
        ) or sum(len(value.encode("utf-8")) for value in args) > 16384:
            raise EmulatorInputError("invalid tcpdump access state")
        tcpdump_accesses.append(args)
    if len(tcpdump_accesses) > 1024:
        raise EmulatorInputError("too many tcpdump access records")

    diag_test_accesses = _split_tcl_list(diagnostics_parts[7])
    if any(value != "" for value in diag_test_accesses) or len(diag_test_accesses) > 1024:
        raise EmulatorInputError("invalid DIAG::test access state")

    line_accesses: list[dict[str, str]] = []
    for raw_access in _split_tcl_list(diagnostics_parts[9]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2 or access_parts[0] not in {"get", "set"}:
            raise EmulatorInputError("invalid LINE access state")
        value = access_parts[1]
        if "\x00" in value or len(value.encode("utf-8")) > 1048576:
            raise EmulatorInputError("invalid LINE access value")
        line_accesses.append({"operation": access_parts[0], "value": value})
    if len(line_accesses) > 1024:
        raise EmulatorInputError("too many LINE access records")

    accumulate_accesses: list[dict[str, Any]] = []
    previous_accumulate_count = 0
    for raw_access in _split_tcl_list(diagnostics_parts[19]):
        access_parts = _split_tcl_list(raw_access)
        if len(access_parts) != 2:
            raise EmulatorInputError("invalid accumulate access state")
        try:
            count = int(access_parts[1])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid accumulate access state") from None
        if count <= previous_accumulate_count or count < 1:
            raise EmulatorInputError("invalid accumulate access ordinal")
        previous_accumulate_count = count
        accumulate_accesses.append({"event": access_parts[0], "count": count})
    if len(accumulate_accesses) > 1024:
        raise EmulatorInputError("too many accumulate access records")
    if any(value not in {"0", "1"} for value in (
        diagnostics_parts[11], diagnostics_parts[13], diagnostics_parts[15]
    )):
        raise EmulatorInputError("invalid accumulate flags")
    try:
        accumulate_count = int(diagnostics_parts[17])
    except (TypeError, ValueError):
        raise EmulatorInputError("invalid accumulate count") from None
    if accumulate_count < 0 or accumulate_count < previous_accumulate_count:
        raise EmulatorInputError("invalid accumulate count")
    diagnostics = {
        "check": {
            "level": check_level,
            "accesses": check_accesses,
        },
        "tcpdump": {"accesses": tcpdump_accesses},
        "diag_test": {"access_count": len(diag_test_accesses)},
        "line": {"accesses": line_accesses},
        "accumulate": {
            "pending": diagnostics_parts[11] == "1",
            "invoked": diagnostics_parts[13] == "1",
            "suspended": diagnostics_parts[15] == "1",
            "count": accumulate_count,
            "accesses": accumulate_accesses,
        },
    }
    bwc_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::bwc_snapshot")
    )
    if len(bwc_parts) % 2:
        raise EmulatorInputError("invalid BWC state")
    bwc_keys = bwc_parts[::2]
    if len(set(bwc_keys)) != len(bwc_keys):
        raise EmulatorInputError("duplicate BWC state field")
    bwc_values = dict(zip(bwc_parts[::2], bwc_parts[1::2]))
    expected_bwc_fields = {
        "attached", "policy", "session_id", "rate", "rate_category", "pps",
        "color_policy", "color_category", "color_set", "mark_scope",
        "mark_category", "mark_tos", "mark_qos", "priority", "measure_enabled",
        "measure_scope", "measure_session", "measure_identifier", "measure_rate",
        "measure_bytes", "debug_enabled",
    }
    if set(bwc_values) != expected_bwc_fields:
        raise EmulatorInputError("invalid BWC state fields")
    if any(
        bwc_values[name] not in {"0", "1"}
        for name in ("attached", "color_set", "measure_enabled", "debug_enabled")
    ):
        raise EmulatorInputError("invalid BWC boolean state")
    if bwc_values["measure_scope"] not in {"", "flow", "session"}:
        raise EmulatorInputError("invalid BWC measurement scope")
    if bwc_values["mark_scope"] not in {"", "policy", "category"}:
        raise EmulatorInputError("invalid BWC mark scope")
    if bwc_values["color_set"] == "1" and not (
        bwc_values["color_policy"] and bwc_values["color_category"]
    ):
        raise EmulatorInputError("invalid BWC color state")
    bwc_ints: dict[str, int] = {}
    for name in ("measure_rate", "measure_bytes"):
        try:
            value = int(bwc_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid BWC {name} state") from None
        if value < 0:
            raise EmulatorInputError(f"invalid BWC {name} state")
        bwc_ints[name] = value
    if bwc_values["pps"] == "":
        bwc_pps: int | None = None
    else:
        try:
            bwc_pps = int(bwc_values["pps"])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid BWC PPS state") from None
        if bwc_pps < 0:
            raise EmulatorInputError("invalid BWC PPS state")
    priority_parts = _split_tcl_list(bwc_values["priority"])
    if len(priority_parts) % 2:
        raise EmulatorInputError("invalid BWC priority state")
    priority: dict[str, int] = {}
    for name, raw_weight in zip(priority_parts[::2], priority_parts[1::2]):
        if not name or name in priority:
            raise EmulatorInputError("invalid BWC priority class state")
        try:
            weight = int(raw_weight)
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid BWC priority weight state") from None
        if not 0 <= weight <= 100:
            raise EmulatorInputError("invalid BWC priority weight state")
        priority[name] = weight
    bwc = {
        "attached": bwc_values["attached"] == "1",
        "policy": bwc_values["policy"],
        "session_id": bwc_values["session_id"],
        "rate": {
            "value": bwc_values["rate"],
            "category": bwc_values["rate_category"],
        },
        "pps": bwc_pps,
        "color": {
            "set": bwc_values["color_set"] == "1",
            "policy": bwc_values["color_policy"],
            "category": bwc_values["color_category"],
        },
        "mark": {
            "scope": bwc_values["mark_scope"],
            "category": bwc_values["mark_category"],
            "tos": bwc_values["mark_tos"],
            "qos": bwc_values["mark_qos"],
        },
        "priority": priority,
        "measurement": {
            "enabled": bwc_values["measure_enabled"] == "1",
            "scope": bwc_values["measure_scope"],
            "session_id": bwc_values["measure_session"],
            "identifier": bwc_values["measure_identifier"],
            "rate": bwc_ints["measure_rate"],
            "bytes": bwc_ints["measure_bytes"],
        },
        "debug": bwc_values["debug_enabled"] == "1",
    }
    ipfix_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::ipfix_snapshot")
    )
    if len(ipfix_parts) % 2:
        raise EmulatorInputError("invalid IPFIX state")
    ipfix_keys = ipfix_parts[::2]
    if len(set(ipfix_keys)) != len(ipfix_keys):
        raise EmulatorInputError("duplicate IPFIX state field")
    ipfix_values = dict(zip(ipfix_parts[::2], ipfix_parts[1::2]))
    if set(ipfix_values) != {"templates", "destinations", "messages", "sends"}:
        raise EmulatorInputError("invalid IPFIX state fields")

    ipfix_templates: list[dict[str, Any]] = []
    seen_ipfix_templates: set[str] = set()
    for raw_template in _split_tcl_list(ipfix_values["templates"]):
        template_parts = _split_tcl_list(raw_template)
        if (
            len(template_parts) != 2
            or not template_parts[0]
            or template_parts[0] in seen_ipfix_templates
        ):
            raise EmulatorInputError("invalid IPFIX template state")
        handle, raw_fields = template_parts
        fields = _split_tcl_list(raw_fields)
        if not fields or any(not field for field in fields):
            raise EmulatorInputError("invalid IPFIX template fields")
        seen_ipfix_templates.add(handle)
        ipfix_templates.append({"handle": handle, "fields": fields})

    ipfix_destinations: list[dict[str, Any]] = []
    seen_ipfix_destinations: set[str] = set()
    for raw_destination in _split_tcl_list(ipfix_values["destinations"]):
        destination_parts = _split_tcl_list(raw_destination)
        if (
            len(destination_parts) != 3
            or not destination_parts[0]
            or destination_parts[0] in seen_ipfix_destinations
            or destination_parts[2] not in {"0", "1"}
        ):
            raise EmulatorInputError("invalid IPFIX destination state")
        handle, publisher, closed = destination_parts
        if not publisher:
            raise EmulatorInputError("invalid IPFIX destination publisher")
        seen_ipfix_destinations.add(handle)
        ipfix_destinations.append(
            {"handle": handle, "publisher": publisher, "closed": closed == "1"}
        )

    def parse_ipfix_message_fields(
        raw_fields: str, raw_values: str, field_error: str
    ) -> list[dict[str, Any]]:
        fields = _split_tcl_list(raw_fields)
        if not fields or any(not field for field in fields):
            raise EmulatorInputError(f"invalid IPFIX {field_error} fields")
        value_parts = _split_tcl_list(raw_values)
        if len(value_parts) % 2:
            raise EmulatorInputError(f"invalid IPFIX {field_error} values")
        values: dict[int, str] = {}
        for raw_position, value in zip(value_parts[::2], value_parts[1::2]):
            try:
                position = int(raw_position)
            except (TypeError, ValueError):
                raise EmulatorInputError(f"invalid IPFIX {field_error} position") from None
            if not 0 <= position < len(fields) or position in values:
                raise EmulatorInputError(f"invalid IPFIX {field_error} position")
            values[position] = value
        occurrence_positions: dict[str, int] = {}
        result: list[dict[str, Any]] = []
        for position, name in enumerate(fields):
            field_position = occurrence_positions.get(name, 0)
            occurrence_positions[name] = field_position + 1
            result.append(
                {
                    "name": name,
                    "position": position,
                    "field_position": field_position,
                    "set": position in values,
                    "value": values.get(position, ""),
                }
            )
        return result

    ipfix_messages: list[dict[str, Any]] = []
    seen_ipfix_messages: set[str] = set()
    for raw_message in _split_tcl_list(ipfix_values["messages"]):
        message_parts = _split_tcl_list(raw_message)
        if (
            len(message_parts) != 4
            or not message_parts[0]
            or message_parts[0] in seen_ipfix_messages
        ):
            raise EmulatorInputError("invalid IPFIX message state")
        handle, template, raw_fields, raw_values = message_parts
        seen_ipfix_messages.add(handle)
        ipfix_messages.append(
            {
                "handle": handle,
                "template": template,
                "fields": parse_ipfix_message_fields(raw_fields, raw_values, "message"),
            }
        )

    ipfix_sends: list[dict[str, Any]] = []
    for raw_send in _split_tcl_list(ipfix_values["sends"]):
        send_parts = _split_tcl_list(raw_send)
        if len(send_parts) != 5:
            raise EmulatorInputError("invalid IPFIX send state")
        destination, message, template, raw_fields, raw_values = send_parts
        # Send history survives connection cleanup, while message objects do
        # not. A historical message handle therefore need not be present in
        # the current connection's live-message table.
        if destination not in seen_ipfix_destinations or not message:
            raise EmulatorInputError("invalid IPFIX send object reference")
        ipfix_sends.append(
            {
                "destination": destination,
                "message": message,
                "template": template,
                "fields": parse_ipfix_message_fields(raw_fields, raw_values, "send"),
            }
        )
    ipfix = {
        "templates": ipfix_templates,
        "destinations": ipfix_destinations,
        "messages": ipfix_messages,
        "sends": ipfix_sends,
    }
    ilx_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::ilx_snapshot"))
    if len(ilx_parts) % 2:
        raise EmulatorInputError("invalid ILX state")
    ilx_keys = ilx_parts[::2]
    if len(set(ilx_keys)) != len(ilx_keys):
        raise EmulatorInputError("invalid ILX state fields")
    ilx_values = dict(zip(ilx_parts[::2], ilx_parts[1::2]))
    if set(ilx_values) != {"handles", "calls", "notifies"}:
        raise EmulatorInputError("invalid ILX state fields")
    ilx_handles: list[dict[str, str]] = []
    for raw_handle in _split_tcl_list(ilx_values["handles"]):
        parts = _split_tcl_list(raw_handle)
        if len(parts) != 3:
            raise EmulatorInputError("invalid ILX handle state")
        ilx_handles.append({"handle": parts[0], "plugin": parts[1], "extension": parts[2]})
    ilx_calls: list[dict[str, Any]] = []
    for raw_call in _split_tcl_list(ilx_values["calls"]):
        parts = _split_tcl_list(raw_call)
        if len(parts) != 7:
            raise EmulatorInputError("invalid ILX call state")
        try:
            timeout = int(parts[4])
        except ValueError:
            raise EmulatorInputError("invalid ILX call timeout state") from None
        if timeout < 0:
            raise EmulatorInputError("invalid ILX call timeout state")
        ilx_calls.append({
            "handle": parts[0],
            "plugin": parts[1],
            "extension": parts[2],
            "method": parts[3],
            "timeout_ms": timeout,
            "args": _split_tcl_list(parts[5]),
            "result": parts[6],
        })
    ilx_notifies: list[dict[str, Any]] = []
    for raw_notify in _split_tcl_list(ilx_values["notifies"]):
        parts = _split_tcl_list(raw_notify)
        if len(parts) != 5:
            raise EmulatorInputError("invalid ILX notify state")
        ilx_notifies.append({
            "handle": parts[0],
            "plugin": parts[1],
            "extension": parts[2],
            "method": parts[3],
            "args": _split_tcl_list(parts[4]),
        })
    ilx = {"handles": ilx_handles, "calls": ilx_calls, "notifies": ilx_notifies}
    nsh_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::nsh_snapshot")
    )
    if len(nsh_parts) % 2:
        raise EmulatorInputError("invalid NSH state")
    nsh_keys = nsh_parts[::2]
    if len(set(nsh_keys)) != len(nsh_keys):
        raise EmulatorInputError("duplicate NSH state field")
    nsh_values = dict(zip(nsh_keys, nsh_parts[1::2]))
    expected_nsh_fields = {
        "chains", "contexts", "md1", "mocksf", "path_ids", "service_indices",
    }
    if set(nsh_values) != expected_nsh_fields:
        raise EmulatorInputError("invalid NSH state fields")
    nsh_directions = {
        "clientside_ingress", "clientside_egress",
        "serverside_ingress", "serverside_egress",
    }
    nsh_chains: list[dict[str, str]] = []
    seen_nsh_chain_directions: set[str] = set()
    for raw_chain in _split_tcl_list(nsh_values["chains"]):
        parts = _split_tcl_list(raw_chain)
        if (
            len(parts) != 2
            or parts[0] not in nsh_directions
            or parts[0] in seen_nsh_chain_directions
            or not parts[1]
        ):
            raise EmulatorInputError("invalid NSH chain state")
        seen_nsh_chain_directions.add(parts[0])
        nsh_chains.append({"direction": parts[0], "chain": parts[1]})

    nsh_contexts: list[dict[str, Any]] = []
    seen_nsh_contexts: set[tuple[int, str]] = set()
    for raw_context in _split_tcl_list(nsh_values["contexts"]):
        parts = _split_tcl_list(raw_context)
        if len(parts) != 3 or parts[1] not in nsh_directions:
            raise EmulatorInputError("invalid NSH context state")
        try:
            index, context = int(parts[0]), int(parts[2])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid NSH context numeric state") from None
        if not 0 <= index <= 0xFFFFFFFF or not 0 <= context <= 0xFFFFFFFF:
            raise EmulatorInputError("invalid NSH context numeric state")
        context_key = (index, parts[1])
        if context_key in seen_nsh_contexts:
            raise EmulatorInputError("duplicate NSH context state")
        seen_nsh_contexts.add(context_key)
        nsh_contexts.append({
            "index": index,
            "direction": parts[1],
            "context": context,
        })

    nsh_md1: list[dict[str, Any]] = []
    seen_nsh_md1: set[tuple[str, int, int]] = set()
    for raw_md1 in _split_tcl_list(nsh_values["md1"]):
        parts = _split_tcl_list(raw_md1)
        if len(parts) != 4 or parts[0] not in nsh_directions:
            raise EmulatorInputError("invalid NSH md1 state")
        try:
            offset, length = int(parts[1]), int(parts[2])
            encoded_metadata = parts[3].encode("ascii")
            metadata = base64.b64decode(encoded_metadata, validate=True)
        except (binascii.Error, UnicodeError, TypeError, ValueError):
            raise EmulatorInputError("invalid NSH md1 metadata state") from None
        if (
            not 0 <= offset <= 0xFFFFFFFF
            or not 0 <= length <= 16 * 1024 * 1024
            or len(metadata) != length
            or base64.b64encode(metadata).decode("ascii") != parts[3]
        ):
            raise EmulatorInputError("invalid NSH md1 metadata state")
        md1_key = (parts[0], offset, length)
        if md1_key in seen_nsh_md1:
            raise EmulatorInputError("duplicate NSH md1 state")
        seen_nsh_md1.add(md1_key)
        nsh_md1.append({
            "direction": parts[0],
            "offset": offset,
            "length": length,
            "metadata_base64": parts[3],
        })

    if nsh_values["mocksf"] not in {"0", "1"}:
        raise EmulatorInputError("invalid NSH mocksf state")

    def parse_nsh_direction_values(
        raw_values: str, field_name: str, maximum: int
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen_directions: set[str] = set()
        for raw_value in _split_tcl_list(raw_values):
            parts = _split_tcl_list(raw_value)
            if (
                len(parts) != 2
                or parts[0] not in nsh_directions
                or parts[0] in seen_directions
            ):
                raise EmulatorInputError(f"invalid NSH {field_name} state")
            try:
                value = int(parts[1])
            except (TypeError, ValueError):
                raise EmulatorInputError(f"invalid NSH {field_name} numeric state") from None
            if not 0 <= value <= maximum:
                raise EmulatorInputError(f"invalid NSH {field_name} numeric state")
            seen_directions.add(parts[0])
            result.append({"direction": parts[0], "value": value})
        return result

    nsh = {
        "chains": nsh_chains,
        "contexts": nsh_contexts,
        "md1": nsh_md1,
        "mocksf": nsh_values["mocksf"] == "1",
        "path_ids": parse_nsh_direction_values(nsh_values["path_ids"], "path ID", 0xFFFFFF),
            "service_indices": parse_nsh_direction_values(
                nsh_values["service_indices"], "service index", 0xFF
        ),
    }
    sipalg_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::sipalg_snapshot")
    )
    if len(sipalg_parts) % 2:
        raise EmulatorInputError("invalid SIPALG state")
    sipalg_keys = sipalg_parts[::2]
    if len(set(sipalg_keys)) != len(sipalg_keys):
        raise EmulatorInputError("duplicate SIPALG state field")
    sipalg_values = dict(zip(sipalg_keys, sipalg_parts[1::2]))
    if set(sipalg_values) != {
        "hairpin", "hairpin_default", "nonregister_subscriber_listener"
    }:
        raise EmulatorInputError("invalid SIPALG state fields")
    if any(
        sipalg_values[name] not in {"detect", "disable", "enable"}
        for name in ("hairpin", "hairpin_default")
    ):
        raise EmulatorInputError("invalid SIPALG hairpin state")
    if sipalg_values["nonregister_subscriber_listener"] not in {"0", "1"}:
        raise EmulatorInputError("invalid SIPALG listener state")
    sipalg = {
        "hairpin": sipalg_values["hairpin"],
        "hairpin_default": sipalg_values["hairpin_default"],
        "nonregister_subscriber_listener": (
            sipalg_values["nonregister_subscriber_listener"] == "1"
        ),
    }
    feature_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::feature_controls_snapshot")
    )
    if len(feature_parts) % 2:
        raise EmulatorInputError("invalid feature-control state")
    feature_keys = feature_parts[::2]
    if len(set(feature_keys)) != len(feature_keys):
        raise EmulatorInputError("duplicate feature-control state field")
    feature_values = dict(zip(feature_keys, feature_parts[1::2]))
    expected_feature_fields = {
        "demangle_enabled",
        "isession_deduplication_enabled",
        "ivs_entry_result",
        "ivs_entry_results",
        "plugin_all_disabled",
        "plugin_states",
    }
    if set(feature_values) != expected_feature_fields:
        raise EmulatorInputError("invalid feature-control state fields")

    def parse_feature_bool(name: str) -> bool:
        if feature_values[name] not in {"0", "1"}:
            raise EmulatorInputError(f"invalid feature-control boolean: {name}")
        return feature_values[name] == "1"

    ivs_results: list[dict[str, str]] = []
    for raw_result in _split_tcl_list(feature_values["ivs_entry_results"]):
        result_parts = _split_tcl_list(raw_result)
        if len(result_parts) != 2 or not result_parts[0] or result_parts[1] not in {
            "noop", "modified", "response"
        }:
            raise EmulatorInputError("invalid IVS_ENTRY result history")
        ivs_results.append({"event": result_parts[0], "result": result_parts[1]})

    if feature_values["ivs_entry_result"] not in {"", "noop", "modified", "response"}:
        raise EmulatorInputError("invalid IVS_ENTRY result state")
    if len(ivs_results) > 1024:
        raise EmulatorInputError("IVS_ENTRY result history exceeds its limit")

    plugin_parts = _split_tcl_list(feature_values["plugin_states"])
    if len(plugin_parts) % 2:
        raise EmulatorInputError("invalid plugin state")
    plugin_states: dict[str, bool] = {}
    for plugin, enabled in zip(plugin_parts[::2], plugin_parts[1::2]):
        if not plugin or plugin in plugin_states or enabled not in {"0", "1"}:
            raise EmulatorInputError("invalid plugin state")
        plugin_states[plugin] = enabled == "1"
    feature_controls = {
        "demangle_enabled": parse_feature_bool("demangle_enabled"),
        "isession_deduplication_enabled": parse_feature_bool(
            "isession_deduplication_enabled"
        ),
        "ivs_entry_result": feature_values["ivs_entry_result"],
        "ivs_entry_results": ivs_results,
        "plugin_all_disabled": parse_feature_bool("plugin_all_disabled"),
        "plugin_states": plugin_states,
    }
    rest_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::rest_snapshot"))
    if len(rest_parts) % 2:
        raise EmulatorInputError("invalid REST state")
    rest_keys = rest_parts[::2]
    if len(set(rest_keys)) != len(rest_keys):
        raise EmulatorInputError("duplicate REST state field")
    rest_values = dict(zip(rest_parts[::2], rest_parts[1::2]))
    if set(rest_values) != {
        "request_count", "last_method", "last_uri", "last_body", "requests"
    }:
        raise EmulatorInputError("invalid REST state fields")
    try:
        rest_request_count = int(rest_values["request_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid REST request count") from None
    if rest_request_count < 0:
        raise EmulatorInputError("invalid REST request count")
    rest_requests: list[dict[str, str]] = []
    for raw_request in _split_tcl_list(rest_values["requests"]):
        request_parts = _split_tcl_list(raw_request)
        if len(request_parts) != 3:
            raise EmulatorInputError("invalid REST request history")
        rest_requests.append(
            {
                "method": request_parts[0],
                "uri": request_parts[1],
                "body": request_parts[2],
            }
        )
    if len(rest_requests) > 1024 or rest_request_count < len(rest_requests):
        raise EmulatorInputError("invalid REST request history length")
    if rest_request_count == 0 and any(
        rest_values[name] for name in ("last_method", "last_uri", "last_body")
    ):
        raise EmulatorInputError("invalid REST last request state")
    if rest_request_count > 0:
        if not rest_requests or rest_requests[-1] != {
            "method": rest_values["last_method"],
            "uri": rest_values["last_uri"],
            "body": rest_values["last_body"],
        }:
            raise EmulatorInputError("invalid REST last request state")
    rest = {
        "request_count": rest_request_count,
        "last": {
            "method": rest_values["last_method"],
            "uri": rest_values["last_uri"],
            "body": rest_values["last_body"],
        },
        "requests": rest_requests,
    }
    offbox_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::offbox_snapshot")
    )
    if len(offbox_parts) % 2:
        raise EmulatorInputError("invalid OFFBOX state")
    offbox_keys = offbox_parts[::2]
    if len(set(offbox_keys)) != len(offbox_keys):
        raise EmulatorInputError("duplicate OFFBOX state field")
    offbox_values = dict(zip(offbox_keys, offbox_parts[1::2]))
    expected_offbox_fields = {
        "request_count", "last_service", "last_payload", "last_cache_key",
        "last_blocking", "last_timeout", "requests",
    }
    if set(offbox_values) != expected_offbox_fields:
        raise EmulatorInputError("invalid OFFBOX state fields")
    if offbox_values["last_blocking"] not in {"0", "1"}:
        raise EmulatorInputError("invalid OFFBOX blocking state")
    try:
        offbox_request_count = int(offbox_values["request_count"])
        offbox_timeout = int(offbox_values["last_timeout"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid OFFBOX numeric state") from None
    if offbox_request_count < 0 or offbox_timeout < 0:
        raise EmulatorInputError("invalid OFFBOX numeric state")
    offbox_requests: list[dict[str, Any]] = []
    for raw_request in _split_tcl_list(offbox_values["requests"]):
        request_parts = _split_tcl_list(raw_request)
        if len(request_parts) != 6:
            raise EmulatorInputError("invalid OFFBOX request history")
        if request_parts[3] not in {"0", "1"}:
            raise EmulatorInputError("invalid OFFBOX request blocking state")
        try:
            timeout = int(request_parts[4])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid OFFBOX request timeout state") from None
        if timeout < 0:
            raise EmulatorInputError("invalid OFFBOX request timeout state")
        offbox_requests.append(
            {
                "service": request_parts[0],
                "payload": request_parts[1],
                "cache_key": request_parts[2],
                "blocking": request_parts[3] == "1",
                "timeout": timeout,
                "result": request_parts[5],
            }
        )
    if len(offbox_requests) > 1024 or offbox_request_count < len(offbox_requests):
        raise EmulatorInputError("invalid OFFBOX request history length")
    if offbox_request_count == 0:
        if any(
            offbox_values[name]
            for name in ("last_service", "last_payload", "last_cache_key")
        ) or offbox_values["last_blocking"] != "0":
            raise EmulatorInputError("invalid OFFBOX last request state")
    elif not offbox_requests:
        raise EmulatorInputError("invalid OFFBOX last request state")
    else:
        last_offbox_request = offbox_requests[-1]
        if {
            "service": last_offbox_request["service"],
            "payload": last_offbox_request["payload"],
            "cache_key": last_offbox_request["cache_key"],
            "blocking": "1" if last_offbox_request["blocking"] else "0",
            "timeout": str(last_offbox_request["timeout"]),
        } != {
            "service": offbox_values["last_service"],
            "payload": offbox_values["last_payload"],
            "cache_key": offbox_values["last_cache_key"],
            "blocking": offbox_values["last_blocking"],
            "timeout": offbox_values["last_timeout"],
        }:
            raise EmulatorInputError("invalid OFFBOX last request state")
    offbox = {
        "request_count": offbox_request_count,
        "last": {
            "service": offbox_values["last_service"],
            "payload": offbox_values["last_payload"],
            "cache_key": offbox_values["last_cache_key"],
            "blocking": offbox_values["last_blocking"] == "1",
            "timeout": offbox_timeout,
        },
        "requests": offbox_requests,
    }
    tds_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::tds_snapshot"))
    if len(tds_parts) % 2:
        raise EmulatorInputError("invalid TDS state")
    tds_keys = tds_parts[::2]
    if len(set(tds_keys)) != len(tds_keys):
        raise EmulatorInputError("duplicate TDS state field")
    tds_values = dict(zip(tds_keys, tds_parts[1::2]))
    expected_tds_fields = {
        "type", "length", "procid", "procname", "sqltext", "xacttype",
        "xactid", "is_read", "request_type", "username", "dbname",
        "loginoption", "version",
    }
    if set(tds_values) != expected_tds_fields:
        raise EmulatorInputError("invalid TDS state fields")
    tds_numeric: dict[str, int] = {}
    for name in ("type", "length", "procid", "xacttype", "xactid"):
        try:
            value = int(tds_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid TDS {name} state") from None
        if value < 0:
            raise EmulatorInputError(f"invalid TDS {name} state")
        tds_numeric[name] = value
    if tds_values["is_read"] not in {"0", "1"}:
        raise EmulatorInputError("invalid TDS is_read state")
    if tds_values["request_type"] not in {"read", "write"}:
        raise EmulatorInputError("invalid TDS request_type state")
    tds = {
        "message": {
            **{name: tds_numeric[name] for name in ("type", "length", "procid", "xacttype", "xactid")},
            "procname": tds_values["procname"],
            "sqltext": tds_values["sqltext"],
            "is_read": tds_values["is_read"] == "1",
            "request_type": tds_values["request_type"],
        },
        "session": {
            "username": tds_values["username"],
            "dbname": tds_values["dbname"],
            "loginoption": tds_values["loginoption"],
            "version": tds_values["version"],
        },
    }
    qoe_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::qoe_snapshot"))
    if len(qoe_parts) % 2:
        raise EmulatorInputError("invalid QOE state")
    qoe_keys = qoe_parts[::2]
    if len(set(qoe_keys)) != len(qoe_keys):
        raise EmulatorInputError("duplicate QOE state field")
    qoe_values = dict(zip(qoe_keys, qoe_parts[1::2]))
    expected_qoe_fields = {
        "enabled", "width", "height", "duration", "available", "framerate",
        "nominal_bitrate", "average_bitrate", "mos",
    }
    if set(qoe_values) != expected_qoe_fields:
        raise EmulatorInputError("invalid QOE state fields")
    if any(qoe_values[name] not in {"0", "1"} for name in ("enabled", "available")):
        raise EmulatorInputError("invalid QOE boolean state")
    qoe = {
        "enabled": qoe_values["enabled"] == "1",
        "video": {
            name: qoe_values[name]
            for name in (
                "width", "height", "duration", "available", "framerate",
                "nominal_bitrate", "average_bitrate", "mos",
            )
        },
    }
    adapt_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::adapt_snapshot")
    )
    if len(adapt_parts) != 6 or set(adapt_parts[::2]) != {
        "current_handle", "current_side", "contexts"
    }:
        raise EmulatorInputError("invalid ADAPT state")
    adapt_values = dict(zip(adapt_parts[::2], adapt_parts[1::2]))
    if adapt_values["current_side"] not in {"request", "response"}:
        raise EmulatorInputError("invalid ADAPT current side")
    adapt_contexts: list[dict[str, Any]] = []
    seen_adapt_handles: set[str] = set()
    for raw_context in _split_tcl_list(adapt_values["contexts"]):
        fields = _split_tcl_list(raw_context)
        if len(fields) != 12 or fields[0] in seen_adapt_handles:
            raise EmulatorInputError("invalid ADAPT context state")
        seen_adapt_handles.add(fields[0])
        if fields[1] not in {"request", "response"} or fields[3] not in {"0", "1"}:
            raise EmulatorInputError("invalid ADAPT context side or dynamic state")
        if fields[4] not in {"0", "1"} or fields[5] not in {"0", "1"}:
            raise EmulatorInputError("invalid ADAPT context boolean state")
        if fields[7] not in {"unknown", "bypass", "modify", "respond", "close", "reset", "timeout"}:
            raise EmulatorInputError("invalid ADAPT context result state")
        if fields[9] not in {"ignore", "drop", "reset"}:
            raise EmulatorInputError("invalid ADAPT service-down action state")
        try:
            preview_size, timeout, order = (int(value) for value in (fields[6], fields[10], fields[11]))
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid ADAPT context numeric state") from None
        if min(preview_size, timeout, order) < 0:
            raise EmulatorInputError("invalid ADAPT context numeric state")
        adapt_contexts.append({
            "handle": fields[0],
            "side": fields[1],
            "name": fields[2],
            "dynamic": fields[3] == "1",
            "enabled": fields[4] == "1",
            "allow_http_v1": fields[5] == "1",
            "preview_size": preview_size,
            "result": fields[7],
            "select": fields[8],
            "service_down_action": fields[9],
            "timeout": timeout,
            "order": order,
        })
    if adapt_values["current_handle"] not in seen_adapt_handles:
        raise EmulatorInputError("invalid ADAPT current context")
    adapt = {
        "current_handle": adapt_values["current_handle"],
        "current_side": adapt_values["current_side"],
        "contexts": adapt_contexts,
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
    lb_control_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::lb_control_snapshot")
    )
    if len(lb_control_parts) % 2:
        raise EmulatorInputError("invalid LB control state")
    lb_control = {
        name: value
        for name, value in zip(lb_control_parts[::2], lb_control_parts[1::2])
    }
    lb_event_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::lb_event_snapshot")
    )
    if len(lb_event_parts) % 2:
        raise EmulatorInputError("invalid LB event state")
    lb_events = {
        name: value
        for name, value in zip(lb_event_parts[::2], lb_event_parts[1::2])
    }
    backend_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::backend_snapshot")
    )
    backend_names = {
        "active",
        "member",
        "state",
        "matched",
        "match_index",
        "status",
    }
    if len(backend_parts) != 12 or set(backend_parts[::2]) != backend_names:
        raise EmulatorInputError("invalid backend fixture state")
    backend_values = dict(zip(backend_parts[::2], backend_parts[1::2]))
    if backend_values["active"] not in {"0", "1"} or backend_values["matched"] not in {"0", "1"}:
        raise EmulatorInputError("invalid backend fixture boolean state")
    try:
        backend_match_index = int(backend_values["match_index"])
    except (TypeError, ValueError):
        raise EmulatorInputError("invalid backend fixture match index") from None
    if backend_match_index < -1:
        raise EmulatorInputError("invalid backend fixture match index")
    if backend_values["status"] != "" and not backend_values["status"].isdigit():
        raise EmulatorInputError("invalid backend fixture response status")
    backend = {
        "active": backend_values["active"] == "1",
        "member": backend_values["member"],
        "state": backend_values["state"],
        "matched": backend_values["matched"] == "1",
        "match_index": backend_match_index,
        "status": int(backend_values["status"]) if backend_values["status"] else None,
    }
    pool_selection: list[dict[str, Any]] = []
    for raw_selection in _split_tcl_list(
        session.eval_tcl("::itest::semantic::lb_pool_selection_snapshot")
    ):
        selection_parts = _split_tcl_list(raw_selection)
        if len(selection_parts) != 3:
            raise EmulatorInputError("invalid pool selection state")
        if selection_parts[1] not in {"first", "round_robin"}:
            raise EmulatorInputError("invalid pool selection mode")
        try:
            selection_cursor = int(selection_parts[2])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid pool selection cursor") from None
        if selection_cursor < 0:
            raise EmulatorInputError("invalid pool selection cursor")
        pool_selection.append({
            "pool": selection_parts[0],
            "mode": selection_parts[1],
            "next_index": selection_cursor,
        })
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
    psm_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::psm_snapshot"))
    if len(psm_parts) % 2:
        raise EmulatorInputError("invalid PSM state")
    psm = {
        name: value == "1"
        for name, value in zip(psm_parts[::2], psm_parts[1::2])
    }
    if set(psm) != {"FTP", "HTTP", "SMTP"} or any(
        value not in {"0", "1"} for value in psm_parts[1::2]
    ):
        raise EmulatorInputError("invalid PSM state")
    http_proxy_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::http_proxy_snapshot")
    )
    if len(http_proxy_parts) % 2:
        raise EmulatorInputError("invalid HTTP proxy state")
    http_proxy_keys = http_proxy_parts[::2]
    if len(set(http_proxy_keys)) != len(http_proxy_keys):
        raise EmulatorInputError("duplicate HTTP proxy state field")
    http_proxy_values = dict(
        zip(http_proxy_parts[::2], http_proxy_parts[1::2])
    )
    expected_http_proxy_fields = {
        "enabled", "uri_rewrite", "resolved", "addr", "port", "rtdom",
        "iptuple", "chain_enabled", "chain_host", "chain_port",
        "chain_retry_requested", "chain_response_enabled", "chain_response_status",
        "chain_response_reason", "chain_response_headers", "chain_response_body",
        "chain_response_index", "chain_retry_count", "chain_failed",
    }
    if set(http_proxy_values) != expected_http_proxy_fields:
        raise EmulatorInputError("invalid HTTP proxy state fields")
    http_proxy_bool_fields = {
        "enabled", "uri_rewrite", "resolved", "chain_enabled",
        "chain_retry_requested", "chain_response_enabled", "chain_failed",
    }
    if any(
        http_proxy_values[name] not in {"0", "1"}
        for name in http_proxy_bool_fields
    ):
        raise EmulatorInputError("invalid HTTP proxy boolean state")
    http_proxy_ints: dict[str, int] = {}
    for name in (
        "port", "rtdom", "chain_port", "chain_response_status",
        "chain_response_index", "chain_retry_count",
    ):
        try:
            value = int(http_proxy_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid HTTP proxy {name} state") from None
        if value < 0:
            raise EmulatorInputError(f"invalid HTTP proxy {name} state")
        http_proxy_ints[name] = value
    chain_response = None
    if http_proxy_values["chain_response_enabled"] == "1":
        chain_response = {
            "status": http_proxy_ints["chain_response_status"],
            "reason": http_proxy_values["chain_response_reason"],
            "headers": _header_dict(http_proxy_values["chain_response_headers"]),
            "body": http_proxy_values["chain_response_body"],
        }
    rewrite_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::rewrite_snapshot")
    )
    if len(rewrite_parts) % 2:
        raise EmulatorInputError("invalid REWRITE state")
    rewrite_keys = rewrite_parts[::2]
    if len(set(rewrite_keys)) != len(rewrite_keys):
        raise EmulatorInputError("duplicate REWRITE state field")
    rewrite_values = dict(zip(rewrite_parts[::2], rewrite_parts[1::2]))
    expected_rewrite_fields = {
        "enabled", "post_process", "payload_side", "payload_replaced",
        "request_payload_length", "response_payload_length",
    }
    if set(rewrite_values) != expected_rewrite_fields:
        raise EmulatorInputError("invalid REWRITE state fields")
    if any(
        rewrite_values[name] not in {"0", "1"}
        for name in ("enabled", "post_process", "payload_replaced")
    ):
        raise EmulatorInputError("invalid REWRITE boolean state")
    if rewrite_values["payload_side"] not in {"", "request", "response"}:
        raise EmulatorInputError("invalid REWRITE payload side state")
    rewrite_lengths: dict[str, int] = {}
    for name in ("request_payload_length", "response_payload_length"):
        try:
            value = int(rewrite_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid REWRITE {name} state") from None
        if value < 0:
            raise EmulatorInputError(f"invalid REWRITE {name} state")
        rewrite_lengths[name] = value
    html_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::html_snapshot")
    )
    if len(html_parts) % 2:
        raise EmulatorInputError("invalid HTML state")
    html_keys = html_parts[::2]
    if len(set(html_keys)) != len(html_keys):
        raise EmulatorInputError("duplicate HTML state field")
    html_values = dict(zip(html_parts[::2], html_parts[1::2]))
    expected_html_fields = {
        "enabled", "processing", "current_type", "current_name",
        "current_removed", "token_count", "mutated",
    }
    if set(html_values) != expected_html_fields:
        raise EmulatorInputError("invalid HTML state fields")
    if any(
        html_values[name] not in {"0", "1"}
        for name in ("enabled", "processing", "current_removed", "mutated")
    ):
        raise EmulatorInputError("invalid HTML boolean state")
    if html_values["current_type"] not in {"", "tag", "comment"}:
        raise EmulatorInputError("invalid HTML current type state")
    try:
        html_token_count = int(html_values["token_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid HTML token count state") from None
    if html_token_count < 0:
        raise EmulatorInputError("invalid HTML token count state")
    compression_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::compression_snapshot")
    )
    if len(compression_parts) % 2:
        raise EmulatorInputError("invalid compression state")
    compression_keys = compression_parts[::2]
    if len(set(compression_keys)) != len(compression_keys):
        raise EmulatorInputError("duplicate compression state field")
    compression_values = dict(
        zip(compression_parts[::2], compression_parts[1::2])
    )
    expected_compression_fields = {
        "compress_request_enabled", "compress_response_enabled",
        "compress_request_method", "compress_response_method",
        "compress_request_buffer_size", "compress_response_buffer_size",
        "compress_request_gzip_level", "compress_response_gzip_level",
        "compress_request_gzip_memory_level", "compress_response_gzip_memory_level",
        "compress_request_gzip_window_size", "compress_response_gzip_window_size",
        "compress_request_nodelay", "compress_response_nodelay",
        "decompress_request_enabled", "decompress_response_enabled",
        "compress_applied", "compress_applied_side",
        "compress_input_length", "compress_output_length",
        "decompress_applied", "decompress_applied_side",
        "decompress_input_length", "decompress_output_length", "codec_error",
    }
    if set(compression_values) != expected_compression_fields:
        raise EmulatorInputError("invalid compression state fields")
    compression_bool_fields = {
        "compress_request_enabled", "compress_response_enabled",
        "compress_request_nodelay", "compress_response_nodelay",
        "decompress_request_enabled", "decompress_response_enabled",
        "compress_applied", "decompress_applied",
    }
    if any(
        compression_values[name] not in {"0", "1"}
        for name in compression_bool_fields
    ):
        raise EmulatorInputError("invalid compression boolean state")
    if any(
        compression_values[name] not in {"gzip", "deflate"}
        for name in ("compress_request_method", "compress_response_method")
    ):
        raise EmulatorInputError("invalid compression method state")
    if any(
        compression_values[name] not in {"", "request", "response"}
        for name in ("compress_applied_side", "decompress_applied_side")
    ):
        raise EmulatorInputError("invalid compression side state")
    compression_ints: dict[str, int] = {}
    for name in (
        "compress_request_buffer_size", "compress_response_buffer_size",
        "compress_request_gzip_level", "compress_response_gzip_level",
        "compress_request_gzip_memory_level", "compress_response_gzip_memory_level",
        "compress_request_gzip_window_size", "compress_response_gzip_window_size",
        "compress_input_length", "compress_output_length",
        "decompress_input_length", "decompress_output_length",
    ):
        try:
            value = int(compression_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid compression {name} state") from None
        if value < 0:
            raise EmulatorInputError(f"invalid compression {name} state")
        compression_ints[name] = value
    for name in (
        "compress_request_gzip_level", "compress_response_gzip_level",
    ):
        if not 0 <= compression_ints[name] <= 9:
            raise EmulatorInputError(f"invalid compression {name} state")
    for name in (
        "compress_request_gzip_memory_level", "compress_response_gzip_memory_level",
    ):
        if not 1 <= compression_ints[name] <= 9:
            raise EmulatorInputError(f"invalid compression {name} state")
    for name in (
        "compress_request_gzip_window_size", "compress_response_gzip_window_size",
    ):
        if not 8 <= compression_ints[name] <= 15:
            raise EmulatorInputError(f"invalid compression {name} state")
    httplog_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::httplog_snapshot")
    )
    if len(httplog_parts) % 2:
        raise EmulatorInputError("invalid HTTPLOG state")
    httplog_keys = httplog_parts[::2]
    if len(set(httplog_keys)) != len(httplog_keys):
        raise EmulatorInputError("duplicate HTTPLOG state field")
    httplog_values = dict(zip(httplog_keys, httplog_parts[1::2]))
    if set(httplog_values) != {"enabled", "records"}:
        raise EmulatorInputError("invalid HTTPLOG state fields")
    if httplog_values["enabled"] not in {"0", "1"}:
        raise EmulatorInputError("invalid HTTPLOG enabled state")
    httplog_records: list[dict[str, Any]] = []
    record_fields = {
        "phase", "method", "uri", "host", "status", "bytes", "headers",
    }
    for raw_record in _split_tcl_list(httplog_values["records"]):
        record_parts = _split_tcl_list(raw_record)
        if len(record_parts) % 2:
            raise EmulatorInputError("invalid HTTPLOG record")
        record_keys = record_parts[::2]
        if len(set(record_keys)) != len(record_keys):
            raise EmulatorInputError("duplicate HTTPLOG record field")
        record_values = dict(zip(record_parts[::2], record_parts[1::2]))
        if set(record_values) != record_fields:
            raise EmulatorInputError("invalid HTTPLOG record fields")
        phase = record_values["phase"]
        if phase not in {"request", "response"}:
            raise EmulatorInputError("invalid HTTPLOG record phase")
        status: int | None
        if phase == "request":
            if record_values["status"] != "":
                raise EmulatorInputError("invalid HTTPLOG request status")
            status = None
        else:
            try:
                status = int(record_values["status"])
            except (TypeError, ValueError):
                raise EmulatorInputError("invalid HTTPLOG response status") from None
            if not 100 <= status <= 999:
                raise EmulatorInputError("invalid HTTPLOG response status")
        try:
            byte_count = int(record_values["bytes"])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid HTTPLOG byte count") from None
        if byte_count < 0:
            raise EmulatorInputError("invalid HTTPLOG byte count")
        header_parts = _split_tcl_list(record_values["headers"])
        if len(header_parts) % 2:
            raise EmulatorInputError("invalid HTTPLOG headers")
        httplog_records.append(
            {
                "phase": phase,
                "method": record_values["method"],
                "uri": record_values["uri"],
                "host": record_values["host"],
                "status": status,
                "bytes": byte_count,
                "headers": _header_dict(record_values["headers"]),
            }
        )
    cache_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::cache_snapshot"))
    if len(cache_parts) % 2:
        raise EmulatorInputError("invalid cache state")
    cache = {
        name: value
        for name, value in zip(cache_parts[::2], cache_parts[1::2])
    }
    profile_settings: dict[str, dict[str, str]] = {}
    for raw_setting in _split_tcl_list(
        session.eval_tcl("::itest::semantic::profile_settings_snapshot")
    ):
        setting_parts = _split_tcl_list(raw_setting)
        if len(setting_parts) != 3:
            raise EmulatorInputError("invalid profile settings state")
        profile_name, attribute, value = setting_parts
        profile_settings.setdefault(profile_name, {})[attribute] = value
    asm_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::asm_snapshot"))
    if len(asm_parts) % 2:
        raise EmulatorInputError("invalid ASM state")
    asm_keys = asm_parts[::2]
    if len(set(asm_keys)) != len(asm_keys):
        raise EmulatorInputError("duplicate ASM state field")
    asm_values = dict(zip(asm_parts[::2], asm_parts[1::2]))
    expected_asm_fields = {
        "enabled", "policy", "client_ip", "fingerprint", "username",
        "login_status", "microservice", "status", "severity", "support_id",
        "captcha_status", "captcha_age", "payload", "captcha_sent", "uncaptcha",
        "unblocked", "conviction", "deception", "violations", "signatures",
        "threat_campaigns",
    }
    if set(asm_values) != expected_asm_fields:
        raise EmulatorInputError("invalid ASM state fields")
    bool_fields = {"enabled", "captcha_sent", "uncaptcha", "unblocked", "conviction", "deception"}
    if any(asm_values[name] not in {"0", "1"} for name in bool_fields):
        raise EmulatorInputError("invalid ASM boolean state")
    try:
        asm_captcha_age = int(asm_values["captcha_age"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid ASM CAPTCHA age state") from None
    if asm_captcha_age < -1:
        raise EmulatorInputError("invalid ASM CAPTCHA age state")
    asm_violations: list[dict[str, Any]] = []
    for raw_record in _split_tcl_list(asm_values["violations"]):
        record = _split_tcl_list(raw_record)
        if len(record) != 4:
            raise EmulatorInputError("invalid ASM violation state")
        details_parts = _split_tcl_list(record[3])
        if len(details_parts) % 2:
            raise EmulatorInputError("invalid ASM violation details state")
        details: dict[str, str] = {}
        for key, value in zip(details_parts[::2], details_parts[1::2]):
            if key in details:
                raise EmulatorInputError("duplicate ASM violation detail")
            details[key] = value
        asm_violations.append(
            {
                "name": record[0],
                "attack_type": record[1],
                "rating": record[2],
                "details": details,
            }
        )
    asm_signatures: dict[str, list[str]] = {}
    for raw_record in _split_tcl_list(asm_values["signatures"]):
        record = _split_tcl_list(raw_record)
        if len(record) != 2 or record[0] not in ASM_SIGNATURE_FIELDS or record[0] in asm_signatures:
            raise EmulatorInputError("invalid ASM signature state")
        asm_signatures[record[0]] = _split_tcl_list(record[1])
    if set(asm_signatures) != set(ASM_SIGNATURE_FIELDS):
        raise EmulatorInputError("incomplete ASM signature state")
    asm_campaigns: dict[str, list[str]] = {}
    for raw_record in _split_tcl_list(asm_values["threat_campaigns"]):
        record = _split_tcl_list(raw_record)
        if len(record) != 2 or record[0] not in ASM_CAMPAIGN_FIELDS or record[0] in asm_campaigns:
            raise EmulatorInputError("invalid ASM threat campaign state")
        asm_campaigns[record[0]] = _split_tcl_list(record[1])
    if set(asm_campaigns) != set(ASM_CAMPAIGN_FIELDS):
        raise EmulatorInputError("incomplete ASM threat campaign state")
    botdefense_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::botdefense_snapshot")
    )
    if len(botdefense_parts) % 2:
        raise EmulatorInputError("invalid Bot Defense state")
    botdefense_keys = botdefense_parts[::2]
    if len(set(botdefense_keys)) != len(botdefense_keys):
        raise EmulatorInputError("duplicate Bot Defense state field")
    botdefense_values = dict(
        zip(botdefense_parts[::2], botdefense_parts[1::2])
    )
    expected_botdefense_fields = {
        "enabled", "action", "action_overridden", "bot_anomalies", "bot_categories",
        "bot_name", "bot_signature", "bot_signature_category", "captcha_age",
        "captcha_status", "client_class", "client_type", "cookie_age",
        "cookie_status", "cs_allowed", "cs_attribute_device_id", "cs_possible",
        "device_id", "intent", "micro_service", "previous_action",
        "previous_request_age", "previous_support_id", "reason", "support_id",
    }
    if set(botdefense_values) != expected_botdefense_fields:
        raise EmulatorInputError("invalid Bot Defense state fields")
    botdefense_bool_fields = {
        "enabled", "action_overridden", "cs_allowed",
        "cs_attribute_device_id", "cs_possible",
    }
    if any(
        botdefense_values[name] not in {"0", "1"}
        for name in botdefense_bool_fields
    ):
        raise EmulatorInputError("invalid Bot Defense boolean state")
    botdefense_int_fields = (
        "captcha_age", "cookie_age", "device_id", "previous_request_age"
    )
    botdefense_ints: dict[str, int] = {}
    for name in botdefense_int_fields:
        try:
            value = int(botdefense_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError("invalid Bot Defense numeric state") from None
        if name in {"captcha_age", "cookie_age"} and value < -1:
            raise EmulatorInputError("invalid Bot Defense age state")
        if name in {"device_id", "previous_request_age"} and value < 0:
            raise EmulatorInputError("invalid Bot Defense numeric state")
        botdefense_ints[name] = value
    botdefense_micro_service = _split_tcl_list(botdefense_values["micro_service"])
    if len(botdefense_micro_service) != 2:
        raise EmulatorInputError("invalid Bot Defense micro-service state")
    antifraud_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::antifraud_snapshot")
    )
    if len(antifraud_parts) % 2:
        raise EmulatorInputError("invalid Anti-Fraud state")
    antifraud_keys = antifraud_parts[::2]
    if len(set(antifraud_keys)) != len(antifraud_keys):
        raise EmulatorInputError("duplicate Anti-Fraud state field")
    antifraud_values = dict(zip(antifraud_parts[::2], antifraud_parts[1::2]))
    expected_antifraud_fields = {
        "enabled", "profile", "client_id", "device_id", "fingerprint", "geo",
        "guid", "result", "username", "license_id", "login_requested",
        "alert_requested", "alert_disabled", "log_enabled", "log_level",
        "alert_license_id",
        *ANTIFRAUD_ALERT_VALUE_FIELDS,
        *ANTIFRAUD_ALERT_FLAG_FIELDS,
        *(f"disable_{field}" for field in (
            "app_layer_encryption", "auto_transactions", "injection", "malware", "phishing"
        )),
    }
    if set(antifraud_values) != expected_antifraud_fields:
        raise EmulatorInputError("invalid Anti-Fraud state fields")
    antifraud_bool_fields = {
        "enabled", "login_requested", "alert_requested", "alert_disabled", "log_enabled",
        *(f"disable_{field}" for field in (
            "app_layer_encryption", "auto_transactions", "injection", "malware", "phishing"
        )),
    }
    if any(antifraud_values[name] not in {"0", "1"} for name in antifraud_bool_fields):
        raise EmulatorInputError("invalid Anti-Fraud boolean state")
    if antifraud_values["result"] not in ANTIFRAUD_RESULTS:
        raise EmulatorInputError("invalid Anti-Fraud result state")
    if antifraud_values["log_level"] not in ANTIFRAUD_ALERT_LOG_LEVELS:
        raise EmulatorInputError("invalid Anti-Fraud log level state")
    antifraud_alert = {
        field: antifraud_values[field]
        for field in (*ANTIFRAUD_ALERT_VALUE_FIELDS, *ANTIFRAUD_ALERT_FLAG_FIELDS)
    }
    auth_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::auth_snapshot"))
    if len(auth_parts) % 2:
        raise EmulatorInputError("invalid AUTH state")
    auth_values = dict(zip(auth_parts[::2], auth_parts[1::2]))
    expected_auth_fields = {
        "enabled", "result", "type", "service", "prompt", "prompt_style",
        "credential_type", "ldap_status", "ldap_username", "last_event_session_id",
        "last_event", "session_count", "sessions",
    }
    if set(auth_values) != expected_auth_fields:
        raise EmulatorInputError("invalid AUTH state fields")
    if auth_values["enabled"] not in {"0", "1"}:
        raise EmulatorInputError("invalid AUTH boolean state")
    if auth_values["result"] not in AUTH_RESULTS:
        raise EmulatorInputError("invalid AUTH result state")
    if auth_values["prompt_style"] not in AUTH_PROMPT_STYLES:
        raise EmulatorInputError("invalid AUTH prompt style state")
    try:
        auth_session_count = int(auth_values["session_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid AUTH session count") from None
    if auth_session_count < 0:
        raise EmulatorInputError("invalid AUTH session count")
    auth_sessions: list[dict[str, Any]] = []
    seen_auth_ids: set[str] = set()
    for raw_session in _split_tcl_list(auth_values["sessions"]):
        session_parts = _split_tcl_list(raw_session)
        if len(session_parts) != 6 or session_parts[0] in seen_auth_ids:
            raise EmulatorInputError("invalid AUTH session state")
        seen_auth_ids.add(session_parts[0])
        if any(value not in {"0", "1"} for value in session_parts[1:2] + session_parts[3:5]):
            raise EmulatorInputError("invalid AUTH session boolean state")
        try:
            session_status = int(session_parts[2])
        except (IndexError, TypeError, ValueError):
            raise EmulatorInputError("invalid AUTH session status") from None
        if session_status not in {-1, 0, 1, 2}:
            raise EmulatorInputError("invalid AUTH session status")
        auth_sessions.append({
            "id": session_parts[0],
            "valid": session_parts[1] == "1",
            "status": session_status,
            "in_progress": session_parts[3] == "1",
            "subscribed": session_parts[4] == "1",
            "last_event": session_parts[5],
        })
    if len(auth_sessions) != auth_session_count:
        raise EmulatorInputError("inconsistent AUTH session count")
    aaa_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::aaa_snapshot"))
    if len(aaa_parts) % 2:
        raise EmulatorInputError("invalid AAA state")
    aaa_values = dict(zip(aaa_parts[::2], aaa_parts[1::2]))
    expected_aaa_fields = {
        "enabled", "auth_result", "acct_result", "request_count", "requests",
    }
    if set(aaa_values) != expected_aaa_fields:
        raise EmulatorInputError("invalid AAA state fields")
    if aaa_values["enabled"] not in {"0", "1"}:
        raise EmulatorInputError("invalid AAA boolean state")
    if aaa_values["auth_result"] not in AAA_RESULTS or aaa_values["acct_result"] not in AAA_RESULTS:
        raise EmulatorInputError("invalid AAA result state")
    try:
        aaa_request_count = int(aaa_values["request_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid AAA request count") from None
    if aaa_request_count < 0:
        raise EmulatorInputError("invalid AAA request count")
    aaa_requests: list[dict[str, Any]] = []
    seen_aaa_ids: set[str] = set()
    for raw_request in _split_tcl_list(aaa_values["requests"]):
        request_parts = _split_tcl_list(raw_request)
        if len(request_parts) != 6 or request_parts[0] in seen_aaa_ids:
            raise EmulatorInputError("invalid AAA request state")
        seen_aaa_ids.add(request_parts[0])
        if request_parts[1] not in {"auth", "acct"}:
            raise EmulatorInputError("invalid AAA request kind")
        if request_parts[2] not in AAA_RESULTS or request_parts[3] not in {"0", "1"}:
            raise EmulatorInputError("invalid AAA request result state")
        aaa_requests.append({
            "id": request_parts[0],
            "kind": request_parts[1],
            "result": request_parts[2],
            "valid": request_parts[3] == "1",
            "virtual_server": request_parts[4],
            "username": request_parts[5],
        })
    if len(aaa_requests) != aaa_request_count:
        raise EmulatorInputError("inconsistent AAA request count")
    access_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::access_snapshot"))
    if len(access_parts) % 2:
        raise EmulatorInputError("invalid ACCESS state")
    access_keys = access_parts[::2]
    if len(set(access_keys)) != len(access_keys):
        raise EmulatorInputError("duplicate ACCESS state field")
    access_values = dict(zip(access_parts[::2], access_parts[1::2]))
    expected_access_fields = {
        "enabled", "acl_result", "acl_lookup", "acl_matched", "acl_evaluated",
        "policy_result", "policy_agent_id", "policy_uri", "flow_id",
        "request_enabled", "restrict_irule_events", "current_sid", "session_count",
        "sessions", "perflow", "saml",
    }
    if set(access_values) != expected_access_fields:
        raise EmulatorInputError("invalid ACCESS state fields")
    access_bool_fields = {"enabled", "policy_uri", "request_enabled", "restrict_irule_events"}
    if any(access_values[name] not in {"0", "1"} for name in access_bool_fields):
        raise EmulatorInputError("invalid ACCESS boolean state")
    if access_values["acl_result"] not in ACCESS_ACL_RESULTS:
        raise EmulatorInputError("invalid ACCESS ACL result state")
    if access_values["policy_result"] not in ACCESS_POLICY_RESULTS:
        raise EmulatorInputError("invalid ACCESS policy result state")
    try:
        access_session_count = int(access_values["session_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid ACCESS session count") from None
    if access_session_count < 0:
        raise EmulatorInputError("invalid ACCESS session count")
    access_sessions: list[dict[str, Any]] = []
    seen_access_ids: set[str] = set()
    for raw_session in _split_tcl_list(access_values["sessions"]):
        session_parts = _split_tcl_list(raw_session)
        if len(session_parts) != 7 or session_parts[0] in seen_access_ids:
            raise EmulatorInputError("invalid ACCESS session state")
        seen_access_ids.add(session_parts[0])
        if session_parts[1] not in {"0", "1"}:
            raise EmulatorInputError("invalid ACCESS session validity state")
        if session_parts[2] not in {"allow", "deny", "redirect", "inprogress"}:
            raise EmulatorInputError("invalid ACCESS session policy state")
        try:
            timeout, lifetime, remaining = (int(value) for value in session_parts[3:6])
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid ACCESS session timing state") from None
        if min(timeout, lifetime, remaining) < 0:
            raise EmulatorInputError("invalid ACCESS session timing state")
        data_parts = _split_tcl_list(session_parts[6])
        if len(data_parts) % 2:
            raise EmulatorInputError("invalid ACCESS session data state")
        data: dict[str, str] = {}
        for key, value in zip(data_parts[::2], data_parts[1::2]):
            if key in data:
                raise EmulatorInputError("duplicate ACCESS session data key")
            data[key] = value
        access_sessions.append({
            "id": session_parts[0],
            "valid": session_parts[1] == "1",
            "state": session_parts[2],
            "timeout": timeout,
            "lifetime": lifetime,
            "remaining": remaining,
            "data": data,
        })
    if len(access_sessions) != access_session_count:
        raise EmulatorInputError("inconsistent ACCESS session count")
    access2_parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::access2_snapshot")
    )
    if len(access2_parts) != 2 or access2_parts[0] != "proc":
        raise EmulatorInputError("invalid ACCESS2 state")
    access2 = {"proc": access2_parts[1]}
    am_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::am_snapshot"))
    if len(am_parts) % 2:
        raise EmulatorInputError("invalid AM state")
    am_values = dict(zip(am_parts[::2], am_parts[1::2]))
    expected_am_fields = {
        "age", "application", "cache", "disabled", "expires",
        "media_playlist", "policy_node",
    }
    if set(am_values) != expected_am_fields:
        raise EmulatorInputError("invalid AM state fields")
    if am_values["disabled"] not in {"0", "1"}:
        raise EmulatorInputError("invalid AM disabled state")
    am = {
        "age": am_values["age"],
        "application": am_values["application"],
        "cache": am_values["cache"],
        "disabled": am_values["disabled"] == "1",
        "expires": am_values["expires"],
        "media_playlist": am_values["media_playlist"],
        "policy_node": am_values["policy_node"],
    }

    def parse_access_map(raw: str, label: str) -> dict[str, str]:
        parts = _split_tcl_list(raw)
        if len(parts) % 2:
            raise EmulatorInputError(f"invalid ACCESS {label} state")
        result: dict[str, str] = {}
        for key, value in zip(parts[::2], parts[1::2]):
            if key in result:
                raise EmulatorInputError(f"duplicate ACCESS {label} key")
            result[key] = value
        return result

    access_perflow = parse_access_map(access_values["perflow"], "perflow")
    access_saml = parse_access_map(access_values["saml"], "SAML")
    if set(access_saml) != {"authn", "assertion", "slo_req", "slo_resp"}:
        raise EmulatorInputError("invalid ACCESS SAML state fields")
    flow_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::flow_snapshot"))
    if len(flow_parts) % 2:
        raise EmulatorInputError("invalid FLOW state")
    flow_values = dict(zip(flow_parts[::2], flow_parts[1::2]))
    expected_flow_fields = {"clock", "current_side", "current_handle", "flow_count", "flows"}
    if set(flow_values) != expected_flow_fields:
        raise EmulatorInputError("invalid FLOW state fields")
    if flow_values["current_side"] not in {"client", "server"}:
        raise EmulatorInputError("invalid FLOW current side")
    try:
        flow_clock = int(flow_values["clock"])
        flow_count = int(flow_values["flow_count"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid FLOW clock or count") from None
    if flow_clock < 0 or flow_count < 0:
        raise EmulatorInputError("invalid FLOW clock or count")
    flow_rows: list[dict[str, Any]] = []
    seen_flow_handles: set[str] = set()
    for raw_flow in _split_tcl_list(flow_values["flows"]):
        flow_row = _split_tcl_list(raw_flow)
        if len(flow_row) != 17 or flow_row[0] in seen_flow_handles:
            raise EmulatorInputError("invalid FLOW handle state")
        seen_flow_handles.add(flow_row[0])
        if flow_row[1] not in {"client", "server"} or flow_row[6] not in {"0", "1"}:
            raise EmulatorInputError("invalid FLOW side or active state")
        if flow_row[7] not in {"0", "1"}:
            raise EmulatorInputError("invalid FLOW related state")
        try:
            timeout, priority, last_used, protocol = (
                int(value) for value in (flow_row[3], flow_row[4], flow_row[5], flow_row[8])
            )
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid FLOW numeric state") from None
        if timeout < 0 or not 0 <= priority <= 7 or last_used < 0 or not 0 <= protocol <= 255:
            raise EmulatorInputError("invalid FLOW numeric state")
        if flow_row[14] not in {"0", "1"} or flow_row[15] not in {"0", "1"}:
            raise EmulatorInputError("invalid FLOW option state")
        flow_rows.append({
            "handle": flow_row[0],
            "side": flow_row[1],
            "peer": flow_row[2],
            "timeout": timeout,
            "priority": priority,
            "last_used": last_used,
            "active": flow_row[6] == "1",
            "related": flow_row[7] == "1",
            "protocol": protocol,
            "local_addr": flow_row[9],
            "local_port": flow_row[10],
            "remote_addr": flow_row[11],
            "remote_port": flow_row[12],
            "vlan": flow_row[13],
            "translation_loose": flow_row[14] == "1",
            "hairpin": flow_row[15] == "1",
            "inherit_vs": flow_row[16],
        })
    if len(flow_rows) != flow_count or flow_values["current_handle"] not in seen_flow_handles:
        raise EmulatorInputError("inconsistent FLOW handle state")
    for flow in flow_rows:
        if flow["peer"] not in seen_flow_handles:
            raise EmulatorInputError("FLOW peer references an unknown handle")
    dosl7_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::dosl7_snapshot"))
    if len(dosl7_parts) % 2:
        raise EmulatorInputError("invalid DOSL7 state")
    dosl7_values = dict(zip(dosl7_parts[::2], dosl7_parts[1::2]))
    if set(dosl7_values) != {
        "enabled", "health", "profile", "mitigated", "profile_object", "greylist"
    }:
        raise EmulatorInputError("invalid DOSL7 state fields")
    if any(dosl7_values[name] not in {"0", "1"} for name in ("enabled", "mitigated")):
        raise EmulatorInputError("invalid DOSL7 boolean state")
    try:
        dosl7_health = int(dosl7_values["health"])
    except (KeyError, TypeError, ValueError):
        raise EmulatorInputError("invalid DOSL7 health state") from None
    if dosl7_health < 0:
        raise EmulatorInputError("invalid DOSL7 health state")
    dosl7_greylist: dict[str, dict[str, int]] = {}
    for raw_record in _split_tcl_list(dosl7_values["greylist"]):
        record = _split_tcl_list(raw_record)
        if len(record) != 3 or record[0] in dosl7_greylist:
            raise EmulatorInputError("invalid DOSL7 greylist state")
        try:
            rate = int(record[1])
            timeout = int(record[2])
        except (IndexError, TypeError, ValueError):
            raise EmulatorInputError("invalid DOSL7 greylist state") from None
        if not 0 <= rate <= 100 or timeout < 0:
            raise EmulatorInputError("invalid DOSL7 greylist state")
        dosl7_greylist[record[0]] = {"rate": rate, "timeout": timeout}

    ip_parts = _split_tcl_list(session.eval_tcl("::itest::semantic::ip_snapshot"))
    if len(ip_parts) % 2:
        raise EmulatorInputError("invalid IP state")
    ip_values = dict(zip(ip_parts[::2], ip_parts[1::2]))
    expected_ip_fields = {
        "hops", "idle_timeout", "pkts_in", "pkts_out", "bytes_in", "bytes_out",
        "age_ms", "intelligence", "reputation", "drop_rates",
        "global_gray_list_rate", "global_rate",
    }
    if set(ip_values) != expected_ip_fields:
        raise EmulatorInputError("invalid IP state fields")

    def parse_ip_integer(name: str, minimum: int = 0) -> int:
        try:
            value = int(ip_values[name])
        except (KeyError, TypeError, ValueError):
            raise EmulatorInputError(f"invalid IP {name} state") from None
        if value < minimum:
            raise EmulatorInputError(f"invalid IP {name} state")
        return value

    def parse_ip_records(raw_records: str, name: str) -> dict[str, list[str]]:
        parts = _split_tcl_list(raw_records)
        if len(parts) % 2:
            raise EmulatorInputError(f"invalid IP {name} records")
        result: dict[str, list[str]] = {}
        for address, raw_categories in zip(parts[::2], parts[1::2]):
            if address in result:
                raise EmulatorInputError(f"duplicate IP {name} record")
            categories = _split_tcl_list(raw_categories)
            if any(not category for category in categories):
                raise EmulatorInputError(f"invalid IP {name} category")
            result[address] = categories
        return result

    drop_parts = _split_tcl_list(ip_values["drop_rates"])
    if len(drop_parts) % 2:
        raise EmulatorInputError("invalid IP drop-rate state")
    drop_rates: dict[str, dict[str, int]] = {}
    for address, raw_rate in zip(drop_parts[::2], drop_parts[1::2]):
        if address in drop_rates:
            raise EmulatorInputError("duplicate IP drop-rate state")
        rate_parts = _split_tcl_list(raw_rate)
        if len(rate_parts) != 2:
            raise EmulatorInputError("invalid IP drop-rate state")
        try:
            rate, timeout = (int(value) for value in rate_parts)
        except (TypeError, ValueError):
            raise EmulatorInputError("invalid IP drop-rate state") from None
        if not 0 <= rate <= 100 or timeout < 0:
            raise EmulatorInputError("invalid IP drop-rate state")
        drop_rates[address] = {"rate": rate, "timeout": timeout}

    ip = {
        "hops": parse_ip_integer("hops"),
        "idle_timeout": parse_ip_integer("idle_timeout"),
        "pkts_in": parse_ip_integer("pkts_in"),
        "pkts_out": parse_ip_integer("pkts_out"),
        "bytes_in": parse_ip_integer("bytes_in"),
        "bytes_out": parse_ip_integer("bytes_out"),
        "age_ms": parse_ip_integer("age_ms"),
        "intelligence": parse_ip_records(ip_values["intelligence"], "intelligence"),
        "reputation": parse_ip_records(ip_values["reputation"], "reputation"),
        "drop_rates": drop_rates,
        "global_gray_list_rate": parse_ip_integer("global_gray_list_rate"),
        "global_rate": parse_ip_integer("global_rate"),
    }
    return {
        "adapt": adapt,
        "stats": stats,
        "istats": {
            "count": len(istats),
            "values": istats,
        },
        "oneconnect": oneconnect,
        "link": link,
        "legacy": legacy,
        "sideband": sideband,
        "ifile": ifile,
        "urlcat": urlcat,
        "session": session_state,
        "sharedvar": sharedvar_state,
        "traffic": traffic_state,
        "utilities": legacy_utilities,
        "diagnostics": diagnostics,
        "bwc": bwc,
        "ipfix": ipfix,
        "ilx": ilx,
        "nsh": nsh,
        "sipalg": sipalg,
        "feature_controls": feature_controls,
        "rest": rest,
        "offbox": offbox,
        "tds": tds,
        "qoe": qoe,
        "hsl_messages": hsl_messages,
        "lb_status": lb_status,
        "lb": lb_control,
        "lb_events": lb_events,
        "backend": backend,
        "pool_selection": pool_selection,
        "table": table_entries,
        "psm": psm,
        "http_proxy": {
            "enabled": http_proxy_values["enabled"] == "1",
            "uri_rewrite": http_proxy_values["uri_rewrite"] == "1",
            "resolved": http_proxy_values["resolved"] == "1",
            "addr": http_proxy_values["addr"],
            "port": http_proxy_ints["port"],
            "rtdom": http_proxy_ints["rtdom"],
            "iptuple": http_proxy_values["iptuple"],
            "chain_enabled": http_proxy_values["chain_enabled"] == "1",
            "chain_host": http_proxy_values["chain_host"],
            "chain_port": http_proxy_ints["chain_port"],
            "chain_retry_requested": http_proxy_values["chain_retry_requested"] == "1",
            "chain_response": chain_response,
            "chain_response_index": http_proxy_ints["chain_response_index"],
            "chain_retry_count": http_proxy_ints["chain_retry_count"],
            "chain_failed": http_proxy_values["chain_failed"] == "1",
        },
        "rewrite": {
            "enabled": rewrite_values["enabled"] == "1",
            "post_process": rewrite_values["post_process"] == "1",
            "payload_side": rewrite_values["payload_side"],
            "payload_replaced": rewrite_values["payload_replaced"] == "1",
            "request_payload_length": rewrite_lengths["request_payload_length"],
            "response_payload_length": rewrite_lengths["response_payload_length"],
        },
        "html": {
            "enabled": html_values["enabled"] == "1",
            "processing": html_values["processing"] == "1",
            "current_type": html_values["current_type"],
            "current_name": html_values["current_name"],
            "current_removed": html_values["current_removed"] == "1",
            "token_count": html_token_count,
            "mutated": html_values["mutated"] == "1",
        },
        "compression": {
            "compress_request_enabled": compression_values["compress_request_enabled"] == "1",
            "compress_response_enabled": compression_values["compress_response_enabled"] == "1",
            "compress_request_method": compression_values["compress_request_method"],
            "compress_response_method": compression_values["compress_response_method"],
            "compress_request_buffer_size": compression_ints["compress_request_buffer_size"],
            "compress_response_buffer_size": compression_ints["compress_response_buffer_size"],
            "compress_request_gzip_level": compression_ints["compress_request_gzip_level"],
            "compress_response_gzip_level": compression_ints["compress_response_gzip_level"],
            "compress_request_gzip_memory_level": compression_ints["compress_request_gzip_memory_level"],
            "compress_response_gzip_memory_level": compression_ints["compress_response_gzip_memory_level"],
            "compress_request_gzip_window_size": compression_ints["compress_request_gzip_window_size"],
            "compress_response_gzip_window_size": compression_ints["compress_response_gzip_window_size"],
            "compress_request_nodelay": compression_values["compress_request_nodelay"] == "1",
            "compress_response_nodelay": compression_values["compress_response_nodelay"] == "1",
            "decompress_request_enabled": compression_values["decompress_request_enabled"] == "1",
            "decompress_response_enabled": compression_values["decompress_response_enabled"] == "1",
            "compress_applied": compression_values["compress_applied"] == "1",
            "compress_applied_side": compression_values["compress_applied_side"],
            "compress_input_length": compression_ints["compress_input_length"],
            "compress_output_length": compression_ints["compress_output_length"],
            "decompress_applied": compression_values["decompress_applied"] == "1",
            "decompress_applied_side": compression_values["decompress_applied_side"],
            "decompress_input_length": compression_ints["decompress_input_length"],
            "decompress_output_length": compression_ints["decompress_output_length"],
            "codec_error": compression_values["codec_error"],
        },
        "http_log": {
            "enabled": httplog_values["enabled"] == "1",
            "records": httplog_records,
        },
        "cache": cache,
        "profile_settings": profile_settings,
        "asm": {
            "enabled": asm_values["enabled"] == "1",
            "policy": asm_values["policy"],
            "client_ip": asm_values["client_ip"],
            "fingerprint": asm_values["fingerprint"],
            "username": asm_values["username"],
            "login_status": asm_values["login_status"],
            "microservice": asm_values["microservice"],
            "status": asm_values["status"],
            "severity": asm_values["severity"],
            "support_id": asm_values["support_id"],
            "captcha_status": asm_values["captcha_status"],
            "captcha_age": asm_captcha_age,
            "payload": asm_values["payload"],
            "captcha_sent": asm_values["captcha_sent"] == "1",
            "uncaptcha": asm_values["uncaptcha"] == "1",
            "unblocked": asm_values["unblocked"] == "1",
            "conviction": asm_values["conviction"] == "1",
            "deception": asm_values["deception"] == "1",
            "violations": asm_violations,
            "signatures": asm_signatures,
            "threat_campaigns": asm_campaigns,
        },
        "botdefense": {
            "enabled": botdefense_values["enabled"] == "1",
            "action": botdefense_values["action"],
            "action_overridden": botdefense_values["action_overridden"] == "1",
            "bot_anomalies": _split_tcl_list(botdefense_values["bot_anomalies"]),
            "bot_categories": _split_tcl_list(botdefense_values["bot_categories"]),
            "bot_name": botdefense_values["bot_name"],
            "bot_signature": botdefense_values["bot_signature"],
            "bot_signature_category": botdefense_values["bot_signature_category"],
            "captcha_age": botdefense_ints["captcha_age"],
            "captcha_status": botdefense_values["captcha_status"],
            "client_class": botdefense_values["client_class"],
            "client_type": botdefense_values["client_type"],
            "cookie_age": botdefense_ints["cookie_age"],
            "cookie_status": botdefense_values["cookie_status"],
            "cs_allowed": botdefense_values["cs_allowed"] == "1",
            "cs_attribute_device_id": botdefense_values["cs_attribute_device_id"] == "1",
            "cs_possible": botdefense_values["cs_possible"] == "1",
            "device_id": botdefense_ints["device_id"],
            "intent": botdefense_values["intent"],
            "micro_service": {
                "name": botdefense_micro_service[0],
                "type": botdefense_micro_service[1],
            },
            "previous_action": botdefense_values["previous_action"],
            "previous_request_age": botdefense_ints["previous_request_age"],
            "previous_support_id": botdefense_values["previous_support_id"],
            "reason": botdefense_values["reason"],
            "support_id": botdefense_values["support_id"],
        },
        "antifraud": {
            "enabled": antifraud_values["enabled"] == "1",
            "profile": antifraud_values["profile"],
            "client_id": antifraud_values["client_id"],
            "device_id": antifraud_values["device_id"],
            "fingerprint": antifraud_values["fingerprint"],
            "geo": antifraud_values["geo"],
            "guid": antifraud_values["guid"],
            "result": antifraud_values["result"],
            "username": antifraud_values["username"],
            "license_id": antifraud_values["license_id"],
            "login_requested": antifraud_values["login_requested"] == "1",
            "alert_requested": antifraud_values["alert_requested"] == "1",
            "alert_disabled": antifraud_values["alert_disabled"] == "1",
            "log_enabled": antifraud_values["log_enabled"] == "1",
            "log_level": antifraud_values["log_level"],
            "alert": antifraud_alert,
            "alert_license_id": antifraud_values["alert_license_id"],
            "disabled_features": {
                field: antifraud_values[f"disable_{field}"] == "1"
                for field in (
                    "app_layer_encryption", "auto_transactions", "injection", "malware", "phishing"
                )
            },
        },
        "auth": {
            "enabled": auth_values["enabled"] == "1",
            "result": auth_values["result"],
            "type": auth_values["type"],
            "service": auth_values["service"],
            "prompt": auth_values["prompt"],
            "prompt_style": auth_values["prompt_style"],
            "credential_type": auth_values["credential_type"],
            "ldap_status": auth_values["ldap_status"],
            "ldap_username": auth_values["ldap_username"],
            "last_event_session_id": auth_values["last_event_session_id"],
            "last_event": auth_values["last_event"],
            "session_count": auth_session_count,
            "sessions": auth_sessions,
        },
        "aaa": {
            "enabled": aaa_values["enabled"] == "1",
            "auth_result": aaa_values["auth_result"],
            "acct_result": aaa_values["acct_result"],
            "request_count": aaa_request_count,
            "requests": aaa_requests,
        },
        "access": {
            "enabled": access_values["enabled"] == "1",
            "acl_result": access_values["acl_result"],
            "acl_lookup": _split_tcl_list(access_values["acl_lookup"]),
            "acl_matched": _split_tcl_list(access_values["acl_matched"]),
            "acl_evaluated": _split_tcl_list(access_values["acl_evaluated"]),
            "policy_result": access_values["policy_result"],
            "policy_agent_id": access_values["policy_agent_id"],
            "policy_uri": access_values["policy_uri"] == "1",
            "flow_id": access_values["flow_id"],
            "request_enabled": access_values["request_enabled"] == "1",
            "restrict_irule_events": access_values["restrict_irule_events"] == "1",
            "current_sid": access_values["current_sid"],
            "session_count": access_session_count,
            "sessions": access_sessions,
            "perflow": access_perflow,
            "saml": access_saml,
        },
        "access2": access2,
        "am": am,
        "flow": {
            "clock": flow_clock,
            "current_side": flow_values["current_side"],
            "current_handle": flow_values["current_handle"],
            "flow_count": flow_count,
            "flows": flow_rows,
        },
        "dosl7": {
            "enabled": dosl7_values["enabled"] == "1",
            "health": dosl7_health,
            "profile": dosl7_values["profile"],
            "mitigated": dosl7_values["mitigated"] == "1",
            "profile_object": dosl7_values["profile_object"],
            "greylist": dosl7_greylist,
        },
        "ip": ip,
    }


def _oneconnect_runtime_state(session: Any) -> dict[str, Any]:
    """Read the small connection-control state used by the request scheduler."""
    parts = _split_tcl_list(
        session.eval_tcl("::itest::semantic::oneconnect_snapshot")
    )
    if len(parts) != 4:
        raise EmulatorInputError("invalid ONECONNECT state")
    return {
        "detach_enabled": parts[0] == "1",
        "reuse_enabled": parts[1] == "1",
        "select": parts[2],
        "label": parts[3],
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
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_http_disable_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::http_disable ::itest::cmd::_testcl_http_disable_orig
            proc ::itest::cmd::http_disable {args} {
                set rc [catch {
                    eval [linsert $args 0 ::itest::cmd::_testcl_http_disable_orig]
                } result options]
                if {$rc} {
                    return -options $options $result
                }
                set ::state::http::disabled 1
                set ::state::http::disable_discard [expr {
                    [llength $args] == 1 && [lindex $args 0] eq "discard"
                }]
                set ::state::http::passthrough_reason "iRule"
                set ::state::http::passthrough_reason_num 1
                return $result
            }
        }
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_http_enable_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::http_enable ::itest::cmd::_testcl_http_enable_orig
            proc ::itest::cmd::http_enable {args} {
                set rc [catch {
                    eval [linsert $args 0 ::itest::cmd::_testcl_http_enable_orig]
                } result options]
                if {$rc} {
                    return -options $options $result
                }
                set ::state::http::disabled 0
                set ::state::http::disable_discard 0
                return $result
            }
        }
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_http_class_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::http_class ::itest::cmd::_testcl_http_class_orig
            proc ::itest::cmd::http_class {args} {
                if {[llength $args] == 0} {
                    return $::state::http::class_name
                }
                set command [lindex $args 0]
                switch -exact -- $command {
                    asm - wa {
                        if {[llength $args] != 1} {
                            error "HTTP::class $command takes no arguments"
                        }
                        return [set ::state::http::class_$command]
                    }
                    enable - disable {
                        if {[llength $args] != 1} {
                            error "HTTP::class $command takes no arguments"
                        }
                        set ::state::http::class_enabled [expr {$command eq "enable"}]
                        ::itest::log_decision http class_$command
                        return
                    }
                    select {
                        if {[llength $args] != 2} {
                            error "HTTP::class select requires a class name"
                        }
                        set name [lindex $args 1]
                        set ::state::http::class_name $name
                        ::itest::log_decision http class_select $name
                        return
                    }
                    default {
                        error "unsupported HTTP::class operation $command"
                    }
                }
            }
        }
        if {[::tmm::_orig_info commands ::itest::cmd::_testcl_cmd_reject_orig] eq ""} {
            ::tmm::_orig_rename ::itest::cmd::cmd_reject ::itest::cmd::_testcl_cmd_reject_orig
            proc ::itest::cmd::cmd_reject {args} {
                if {[llength $args] != 0} {
                    error "reject takes no arguments"
                }
                set rc [catch {
                    ::itest::cmd::_testcl_cmd_reject_orig
                } result options]
                if {$rc} {
                    return -options $options $result
                }
                if {[string match "HTTP_*" $::itest::current_event]} {
                    set ::state::http::rejected 1
                    set ::state::http::reject_reason "iRule"
                    set ::state::http::reject_reason_num 1
                }
                return $result
            }
        }
        namespace eval ::itest::semantic {}
        proc ::itest::semantic::http_control_reset {} {
            set ::state::http::disabled 0
            set ::state::http::disable_discard 0
            set ::state::http::passthrough_reason ""
            set ::state::http::passthrough_reason_num 0
        }
        proc ::itest::semantic::http_class_reset {} {
            set ::state::http::class_name ""
            set ::state::http::class_enabled 1
            set ::state::http::class_asm 0
            set ::state::http::class_wa 0
        }
        proc ::itest::semantic::http_class_configure {name asm wa} {
            set ::state::http::class_name $name
            set ::state::http::class_asm $asm
            set ::state::http::class_wa $wa
        }
        proc ::itest::semantic::http_reject_reset {} {
            set ::state::http::rejected 0
            set ::state::http::reject_reason ""
            set ::state::http::reject_reason_num 0
        }
        ::itest::semantic::http_control_reset
        ::itest::semantic::http_class_reset
        ::itest::semantic::http_reject_reset
        """
    )
    _install_python_digest_helper(session)
    _install_python_fasthash_helper(session)
    _install_python_crypto_helper(session)
    _install_python_crypto_cipher_helper(session)
    _install_python_aes_helper(session)
    _install_python_codec_helper(session)
    _install_python_ip_helper(session)
    semantic_path = Path(__file__).with_name("semantic-mocks.tcl")
    if not semantic_path.exists():
        raise EmulatorInputError(f"missing adapter semantic mock file: {semantic_path}")
    session.eval_tcl(f"::tmm::_orig_source {_tcl_quote(str(semantic_path))}")
    session.eval_tcl("::itest::semantic::install_lb_causal_chain_steps")


def _install_python_backend_helper(
    session: Any, backends: dict[str, dict[str, Any]]
) -> None:
    """Expose bounded upstream fixtures to the Tcl flow at LB selection time."""
    if not backends:
        return
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError(
            "backend response fixtures require the in-process Tcl backend"
        )

    def backend_callback(*args: str) -> str:
        if len(args) != 6:
            raise ValueError("backend lookup requires pool, member, method, uri, host, and override flags")
        pool, member, method, uri, host, override_flags = args
        override_parts = _split_tcl_list(override_flags)
        if len(override_parts) != 3 or any(
            value not in {"0", "1"} for value in override_parts
        ):
            raise ValueError("backend response override flags must contain three 0/1 values")
        status_override, headers_override, body_override = override_parts
        lookup = _backend_lookup(backends, pool, member, method, uri, host)
        if lookup is None:
            return ""
        values = [
            "member", lookup["member"],
            "state", lookup["state"],
            "matched", "1" if lookup["matched"] else "0",
            "match_index", str(lookup["match_index"] if lookup["match_index"] is not None else -1),
        ]
        selected = lookup["response"]
        if selected is not None:
            if "status" in selected and status_override != "1":
                values.extend(("status", str(selected["status"])))
            if "headers" in selected and headers_override != "1":
                flattened_headers = [
                    item
                    for name, value in selected["headers"].items()
                    for item in (name, value)
                ]
                values.extend(("headers", _tcl_list_value(flattened_headers)))
            if "body" in selected and body_override != "1":
                values.extend(("body", selected["body"]))
        return _tcl_list_value(values)

    interpreter.createcommand("::itest::semantic::py_backend_lookup", backend_callback)
    setattr(session, "_testcl_backend_callback", backend_callback)


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

    algorithms = {
        "md4",
        "md5",
        "ripemd160",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
    }

    def digest_callback(*args: str) -> str:
        if len(args) != 2 or args[0] not in algorithms:
            raise ValueError("digest helper requires a supported algorithm and one value")
        raw_value = base64.b64decode(args[1].encode("ascii"), validate=True)
        digest = (
            _md4_digest(raw_value)
            if args[0] == "md4"
            else hashlib.new(args[0], raw_value).digest()
        )
        return base64.b64encode(digest).decode("ascii")

    interpreter.createcommand("::itest::semantic::py_digest", digest_callback)
    # Keep a strong reference on the session for bridge implementations that
    # do not retain Python callbacks independently of tkinter's command table.
    setattr(session, "_testcl_digest_callback", digest_callback)


def _md4_digest(value: bytes) -> bytes:
    """Return the legacy MD4 digest used by the iRules compatibility command."""
    mask = 0xFFFFFFFF
    bit_length = (len(value) * 8) & ((1 << 64) - 1)
    padded = value + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += bit_length.to_bytes(8, "little")

    def rotate_left(number: int, amount: int) -> int:
        return ((number << amount) | (number >> (32 - amount))) & mask

    def round_f(x: int, y: int, z: int) -> int:
        return ((x & y) | (~x & z)) & mask

    def round_g(x: int, y: int, z: int) -> int:
        return ((x & y) | (x & z) | (y & z)) & mask

    def round_h(x: int, y: int, z: int) -> int:
        return (x ^ y ^ z) & mask

    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    round_one_shifts = (3, 7, 11, 19)
    round_two_indices = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    round_three_indices = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)

    for offset in range(0, len(padded), 64):
        words = struct.unpack("<16I", padded[offset : offset + 64])
        a, b, c, d = state

        for index in range(16):
            shift = round_one_shifts[index % 4]
            if index % 4 == 0:
                a = rotate_left((a + round_f(b, c, d) + words[index]) & mask, shift)
            elif index % 4 == 1:
                d = rotate_left((d + round_f(a, b, c) + words[index]) & mask, shift)
            elif index % 4 == 2:
                c = rotate_left((c + round_f(d, a, b) + words[index]) & mask, shift)
            else:
                b = rotate_left((b + round_f(c, d, a) + words[index]) & mask, shift)

        for index, word_index in enumerate(round_two_indices):
            shift = (3, 5, 9, 13)[index % 4]
            if index % 4 == 0:
                a = rotate_left((a + round_g(b, c, d) + words[word_index] + 0x5A827999) & mask, shift)
            elif index % 4 == 1:
                d = rotate_left((d + round_g(a, b, c) + words[word_index] + 0x5A827999) & mask, shift)
            elif index % 4 == 2:
                c = rotate_left((c + round_g(d, a, b) + words[word_index] + 0x5A827999) & mask, shift)
            else:
                b = rotate_left((b + round_g(c, d, a) + words[word_index] + 0x5A827999) & mask, shift)

        for index, word_index in enumerate(round_three_indices):
            shift = (3, 9, 11, 15)[index % 4]
            if index % 4 == 0:
                a = rotate_left((a + round_h(b, c, d) + words[word_index] + 0x6ED9EBA1) & mask, shift)
            elif index % 4 == 1:
                d = rotate_left((d + round_h(a, b, c) + words[word_index] + 0x6ED9EBA1) & mask, shift)
            elif index % 4 == 2:
                c = rotate_left((c + round_h(d, a, b) + words[word_index] + 0x6ED9EBA1) & mask, shift)
            else:
                b = rotate_left((b + round_h(c, d, a) + words[word_index] + 0x6ED9EBA1) & mask, shift)

        state = [
            (previous + current) & mask
            for previous, current in zip(state, (a, b, c, d))
        ]

    return struct.pack("<4I", *state)


def _install_python_fasthash_helper(session: Any) -> None:
    """Expose a deterministic 63-bit fast hash to the Tcl overlay.

    BIG-IP documents ``fasthash`` as high quality and fast, but does not
    promise values across versions or reboots. Blake2b is available in the
    Python standard library and provides a stable bounded substitute for
    off-box tests without claiming bit-for-bit TMM compatibility.
    """
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("fasthash support requires the in-process Tcl backend")

    max_value = (1 << 63) - 1

    def fasthash_callback(*args: str) -> str:
        if len(args) != 1:
            raise ValueError("fasthash helper requires one value")
        try:
            raw_value = base64.b64decode(args[0].encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise ValueError("fasthash value is not valid base64") from exc
        digest = hashlib.blake2b(raw_value, digest_size=8).digest()
        return str(int.from_bytes(digest, "big") & max_value)

    interpreter.createcommand("::itest::semantic::py_fasthash", fasthash_callback)
    setattr(session, "_testcl_fasthash_callback", fasthash_callback)


def _install_python_crypto_helper(session: Any) -> None:
    """Expose bounded hash and HMAC operations to semantic Tcl."""
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("crypto support requires the in-process Tcl backend")

    import hmac

    hash_algorithms = {
        "md5",
        "ripemd160",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
    }
    hmac_algorithms = {f"hmac-{algorithm}" for algorithm in hash_algorithms}
    max_bytes = 16 * 1024 * 1024

    def decode(value: str, field: str) -> bytes:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise ValueError(f"crypto {field} is not valid base64") from exc
        if len(raw) > max_bytes:
            raise ValueError(f"crypto {field} exceeds the {max_bytes}-byte limit")
        return raw

    def crypto_callback(*args: str) -> str:
        if len(args) != 5:
            raise ValueError(
                "crypto helper requires operation, algorithm, key, data, and signature"
            )
        operation, algorithm, key_encoded, data_encoded, signature_encoded = args
        key = decode(key_encoded, "key")
        data = decode(data_encoded, "data")
        signature = decode(signature_encoded, "signature")
        if operation == "hash":
            if algorithm not in hash_algorithms:
                raise ValueError(f"unsupported hash algorithm: {algorithm}")
            digest = hashlib.new(algorithm, data).digest()
        elif operation == "sign":
            if algorithm not in hmac_algorithms:
                raise ValueError(f"unsupported HMAC algorithm: {algorithm}")
            digest = hmac.new(key, data, algorithm.removeprefix("hmac-")).digest()
        elif operation == "verify":
            if algorithm not in hmac_algorithms:
                raise ValueError(f"unsupported HMAC algorithm: {algorithm}")
            expected = hmac.new(key, data, algorithm.removeprefix("hmac-")).digest()
            return "1" if hmac.compare_digest(expected, signature) else "0"
        else:
            raise ValueError(f"unsupported crypto operation: {operation}")
        return base64.b64encode(digest).decode("ascii")

    interpreter.createcommand("::itest::semantic::py_crypto", crypto_callback)
    setattr(session, "_testcl_crypto_callback", crypto_callback)


def _install_python_crypto_cipher_helper(session: Any) -> None:
    """Expose bounded CRYPTO cipher and key-generation operations to Tcl."""
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("CRYPTO cipher support requires the in-process Tcl backend")

    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - dependency installation failure
        raise EmulatorInputError(
            "CRYPTO cipher support requires the cryptography package in the uv environment"
        ) from exc

    max_bytes = 16 * 1024 * 1024
    max_keygen_bits = 16 * 1024 * 8
    max_rsa_bits = 8192
    max_pbkdf2_rounds = 10_000_000

    def decode(value: str, field: str) -> bytes:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise ValueError(f"CRYPTO {field} is not valid base64") from exc
        if len(raw) > max_bytes:
            raise ValueError(f"CRYPTO {field} exceeds the {max_bytes}-byte limit")
        return raw

    def encode(value: bytes) -> str:
        if len(value) > max_bytes:
            raise ValueError(f"CRYPTO result exceeds the {max_bytes}-byte limit")
        return base64.b64encode(value).decode("ascii")

    def block_cipher(algorithm_name: str, key: bytes, iv: bytes):
        match = re.fullmatch(r"aes-(128|192|256)-(cbc|cfb|ecb|ofb)", algorithm_name)
        if match:
            bits = int(match.group(1))
            mode_name = match.group(2)
            if len(key) != bits // 8:
                raise ValueError(f"{algorithm_name} requires a {bits // 8}-byte key")
            cipher_algorithm = algorithms.AES(key)
        else:
            match = re.fullmatch(r"(bf|des|des-ede|des-ede3|dea)-(cbc|cfb|ecb|ofb)", algorithm_name)
            if not match:
                if algorithm_name.endswith("-cwc"):
                    raise ValueError("CRYPTO CWC mode is not supported by the portable backend")
                if algorithm_name == "rc2-mode":
                    raise ValueError("CRYPTO RC2 is not supported by the portable backend")
                raise ValueError(f"unsupported CRYPTO symmetric algorithm: {algorithm_name}")
            family, mode_name = match.groups()
            if family == "bf":
                if not 4 <= len(key) <= 56:
                    raise ValueError("bf-* requires a key between 4 and 56 bytes")
                cipher_algorithm = decrepit_algorithms.Blowfish(key)
            elif family == "des":
                if len(key) != 8:
                    raise ValueError("des-* requires an 8-byte key")
                cipher_algorithm = decrepit_algorithms.TripleDES(key * 3)
            elif family == "des-ede":
                if len(key) != 16:
                    raise ValueError("des-ede-* requires a 16-byte key")
                cipher_algorithm = decrepit_algorithms.TripleDES(key + key[:8])
            elif family == "des-ede3":
                if len(key) != 24:
                    raise ValueError("des-ede3-* requires a 24-byte key")
                cipher_algorithm = decrepit_algorithms.TripleDES(key)
            else:
                if len(key) != 16:
                    raise ValueError("dea-* requires a 16-byte key")
                cipher_algorithm = decrepit_algorithms.IDEA(key)

        block_size = cipher_algorithm.block_size // 8
        if mode_name == "ecb":
            if iv:
                raise ValueError(f"{algorithm_name} does not accept an IV")
            cipher_mode = modes.ECB()
        else:
            if len(iv) != block_size:
                raise ValueError(f"{algorithm_name} requires a {block_size}-byte IV")
            cipher_mode = {"cbc": modes.CBC, "cfb": modes.CFB, "ofb": modes.OFB}[mode_name](iv)
        return Cipher(cipher_algorithm, cipher_mode), mode_name, block_size

    def pkcs7_pad(data: bytes, block_size: int) -> bytes:
        pad_length = block_size - (len(data) % block_size)
        padded = data + bytes([pad_length]) * pad_length
        if len(padded) > max_bytes:
            raise ValueError(f"CRYPTO result exceeds the {max_bytes}-byte limit")
        return padded

    def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
        if not data or len(data) % block_size:
            raise ValueError("CRYPTO ciphertext length is not a positive block multiple")
        pad_length = data[-1]
        if not 1 <= pad_length <= block_size or data[-pad_length:] != bytes([pad_length]) * pad_length:
            raise ValueError("CRYPTO ciphertext has invalid PKCS padding")
        return data[:-pad_length]

    def rsa_key(value: bytes, operation: str):
        if operation == "rsa-pub":
            loaders = [(serialization.load_pem_public_key, False), (serialization.load_der_public_key, False)]
            expected = rsa.RSAPublicKey
        else:
            loaders = [(serialization.load_pem_private_key, True), (serialization.load_der_private_key, True)]
            expected = rsa.RSAPrivateKey
        last_error = None
        for loader, private in loaders:
            try:
                loaded = loader(value, password=None) if private else loader(value)
                if not isinstance(loaded, expected):
                    raise ValueError(f"{operation} requires an RSA key")
                return loaded
            except (TypeError, ValueError, NotImplementedError) as exc:
                last_error = exc
        raise ValueError(f"{operation} key is not a supported PEM or DER RSA key") from last_error

    def cipher_callback(*args: str) -> str:
        if len(args) != 8:
            raise ValueError("CRYPTO cipher helper requires eight arguments")
        operation, algorithm_name, key_encoded, iv_encoded, padding_name, data_encoded, iv_present_text, _ = args
        key = decode(key_encoded, "key")
        iv = decode(iv_encoded, "iv")
        data = decode(data_encoded, "data")
        if iv_present_text not in {"0", "1"}:
            raise ValueError("CRYPTO IV presence flag is invalid")
        iv_present = iv_present_text == "1"
        if padding_name not in {"pkcs", "oaep"}:
            raise ValueError("CRYPTO padding must be pkcs or oaep")
        if algorithm_name in {"rsa-pub", "rsa-priv"}:
            if (operation == "encrypt" and algorithm_name != "rsa-pub") or (
                operation == "decrypt" and algorithm_name != "rsa-priv"
            ):
                raise ValueError(
                    f"CRYPTO {algorithm_name} is not valid for {operation}; use the matching RSA key direction"
                )
            key_object = rsa_key(key, algorithm_name)
            rsa_padding = (
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                )
                if padding_name == "oaep"
                else asym_padding.PKCS1v15()
            )
            try:
                output = key_object.encrypt(data, rsa_padding) if operation == "encrypt" else key_object.decrypt(data, rsa_padding)
            except ValueError as exc:
                raise ValueError(f"CRYPTO RSA operation failed: {exc}") from exc
            return encode(output)
        if padding_name == "oaep":
            raise ValueError("CRYPTO oaep padding is only valid for RSA")
        if algorithm_name == "rc4":
            if not 1 <= len(key) <= 256:
                raise ValueError("rc4 requires a key between 1 and 256 bytes")
            # The cryptography backend only accepts a sparse set of RC4 key
            # sizes. BIG-IP accepts variable-length keys, so use the bounded
            # reference KSA/PRGA here; this is an emulator primitive, not a
            # recommendation to deploy RC4.
            state = list(range(256))
            j = 0
            for index in range(256):
                j = (j + state[index] + key[index % len(key)]) & 0xFF
                state[index], state[j] = state[j], state[index]
            output = bytearray()
            index = 0
            j = 0
            for value in data:
                index = (index + 1) & 0xFF
                j = (j + state[index]) & 0xFF
                state[index], state[j] = state[j], state[index]
                output.append(value ^ state[(state[index] + state[j]) & 0xFF])
            return encode(bytes(output))
        if algorithm_name.endswith("-ecb") and iv_present:
            raise ValueError(f"{algorithm_name} does not accept an IV")
        if (
            not iv_present
            and not algorithm_name.endswith("-ecb")
            and re.fullmatch(r"(?:aes-(?:128|192|256)|bf|des|des-ede|des-ede3|dea)-.*", algorithm_name)
        ):
            iv = bytes(16 if algorithm_name.startswith("aes-") else 8)
        cipher, mode_name, block_size = block_cipher(algorithm_name, key, iv)
        uses_block_padding = mode_name in {"cbc", "ecb"}
        if operation == "encrypt":
            input_data = pkcs7_pad(data, block_size) if uses_block_padding else data
            transform = cipher.encryptor()
            output = transform.update(input_data) + transform.finalize()
        elif operation == "decrypt":
            transform = cipher.decryptor()
            decrypted = transform.update(data) + transform.finalize()
            output = pkcs7_unpad(decrypted, block_size) if uses_block_padding else decrypted
        else:
            raise ValueError(f"unsupported CRYPTO operation: {operation}")
        return encode(output)

    def keygen_callback(*args: str) -> str:
        if len(args) != 7:
            raise ValueError("CRYPTO keygen helper requires seven arguments")
        algorithm_name, length_text, exponent_text, passphrase_encoded, salt_encoded, rounds_text, _ = args
        try:
            length_bits = int(length_text)
        except ValueError as exc:
            raise ValueError("CRYPTO keygen length must be an integer") from exc
        if length_bits <= 0 or length_bits % 8:
            raise ValueError("CRYPTO keygen length must be a positive multiple of 8")
        passphrase = decode(passphrase_encoded, "passphrase")
        salt = decode(salt_encoded, "salt")
        try:
            rounds = int(rounds_text) if rounds_text else 1000
        except ValueError as exc:
            raise ValueError("CRYPTO keygen rounds must be an integer") from exc
        if not 1 <= rounds <= max_pbkdf2_rounds:
            raise ValueError(f"CRYPTO keygen rounds must be between 1 and {max_pbkdf2_rounds}")
        if algorithm_name == "random":
            if length_bits > max_keygen_bits:
                raise ValueError(f"CRYPTO random key length cannot exceed {max_keygen_bits} bits")
            return "raw|" + encode(secrets.token_bytes(length_bits // 8))
        if algorithm_name == "pbkdf2-md5":
            if not passphrase:
                raise ValueError("CRYPTO pbkdf2-md5 requires -passphrase")
            if length_bits > max_keygen_bits:
                raise ValueError(f"CRYPTO pbkdf2-md5 key length cannot exceed {max_keygen_bits} bits")
            derived = hashlib.pbkdf2_hmac("md5", passphrase, salt, rounds, length_bits // 8)
            return "raw|" + encode(derived)
        if algorithm_name == "rsa":
            if not 1024 <= length_bits <= max_rsa_bits:
                raise ValueError("CRYPTO RSA key length must be between 1024 and 8192 bits")
            try:
                exponent = int(exponent_text) if exponent_text else 65537
            except ValueError as exc:
                raise ValueError("CRYPTO RSA exponent must be an integer") from exc
            if exponent not in {3, 65537}:
                raise ValueError("CRYPTO RSA exponent must be 3 or 65537")
            private_key = rsa.generate_private_key(public_exponent=exponent, key_size=length_bits)
            public_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            private_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            return "rsa|" + encode(public_pem) + "|" + encode(private_pem)
        raise ValueError(f"unsupported CRYPTO keygen algorithm: {algorithm_name}")

    interpreter.createcommand("::itest::semantic::py_crypto_cipher", cipher_callback)
    interpreter.createcommand("::itest::semantic::py_crypto_keygen", keygen_callback)
    setattr(session, "_testcl_crypto_cipher_callback", cipher_callback)
    setattr(session, "_testcl_crypto_keygen_callback", keygen_callback)


def _install_python_aes_helper(session: Any) -> None:
    """Expose the bounded AES-ECB primitive used by the AES iRule family."""
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("AES support requires the in-process Tcl backend")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover - dependency installation failure
        raise EmulatorInputError(
            "AES support requires the cryptography package in the uv environment"
        ) from exc

    max_bytes = 16 * 1024 * 1024
    key_pattern = re.compile(r"^AES (128|192|256) ([0-9a-fA-F]+)$")

    def decode(value: str, field: str) -> bytes:
        try:
            raw = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise ValueError(f"AES {field} is not valid base64") from exc
        if len(raw) > max_bytes:
            raise ValueError(f"AES {field} exceeds the {max_bytes}-byte limit")
        return raw

    def parse_key(value: bytes) -> bytes:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        match = key_pattern.fullmatch(text)
        if match is not None:
            bits = int(match.group(1))
            encoded = match.group(2)
            if len(encoded) != bits // 4:
                raise ValueError(
                    f"AES key must contain exactly {bits // 4} hexadecimal characters"
                )
            return bytes.fromhex(encoded)

        if not value:
            raise ValueError("AES key or pass phrase must not be empty")
        # F5 accepts a pass phrase as a convenience. The public command
        # reference specifies that behavior but not its internal KDF. Keep the
        # emulator deterministic and bounded, while recommending formatted
        # AES keys for cross-device interoperability.
        return hashlib.sha256(value).digest()[:16]

    def aes_callback(*args: str) -> str:
        if len(args) != 3:
            raise ValueError("AES helper requires operation, key, and data")
        operation, key_encoded, data_encoded = args
        key = parse_key(decode(key_encoded, "key"))
        data = decode(data_encoded, "data")
        pad_length = 16 - (len(data) % 16)
        if operation == "encrypt":
            padded = data + bytes([pad_length]) * pad_length
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            encryptor = cipher.encryptor()
            output = encryptor.update(padded) + encryptor.finalize()
        elif operation == "decrypt":
            if not data or len(data) % 16:
                raise ValueError("AES ciphertext length must be a positive multiple of 16")
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            padded = decryptor.update(data) + decryptor.finalize()
            pad_length = padded[-1]
            if (
                not 1 <= pad_length <= 16
                or padded[-pad_length:] != bytes([pad_length]) * pad_length
            ):
                raise ValueError("AES ciphertext has invalid PKCS padding")
            output = padded[:-pad_length]
        else:
            raise ValueError(f"unsupported AES operation: {operation}")
        return base64.b64encode(output).decode("ascii")

    def key_callback(*args: str) -> str:
        if len(args) > 1 or (args and args[0] not in {"128", "192", "256"}):
            raise ValueError("AES::key accepts an optional size of 128, 192, or 256")
        bits = int(args[0]) if args else 128
        return f"AES {bits} {secrets.token_hex(bits // 8)}"

    interpreter.createcommand("::itest::semantic::py_aes", aes_callback)
    interpreter.createcommand("::itest::semantic::py_aes_key", key_callback)
    setattr(session, "_testcl_aes_callback", aes_callback)
    setattr(session, "_testcl_aes_key_callback", key_callback)


def _install_python_codec_helper(session: Any) -> None:
    """Expose bounded gzip/deflate codecs to semantic Tcl commands."""
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("compression support requires the in-process Tcl backend")

    max_bytes = 16 * 1024 * 1024

    def codec_callback(*args: str) -> str:
        if len(args) != 6:
            raise ValueError("codec helper requires operation, method, level, memory level, window, and data")
        operation, method, level_text, memory_text, window_text, encoded = args
        if operation not in {"compress", "decompress"}:
            raise ValueError("codec operation must be compress or decompress")
        if method not in {"gzip", "deflate"}:
            raise ValueError("codec method must be gzip or deflate")
        try:
            level = int(level_text)
            memory_level = int(memory_text)
            window_size = int(window_text)
        except ValueError as exc:
            raise ValueError("codec tuning values must be integers") from exc
        if not 0 <= level <= 9:
            raise ValueError("codec level must be between 0 and 9")
        if not 1 <= memory_level <= 9:
            raise ValueError("codec memory level must be between 1 and 9")
        if not 8 <= window_size <= 15:
            raise ValueError("codec window size must be between 8 and 15")
        try:
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("codec input is not valid base64") from exc
        if len(raw) > max_bytes:
            raise ValueError(f"codec input exceeds the {max_bytes}-byte limit")

        if operation == "compress":
            wbits = window_size + (16 if method == "gzip" else 0)
            compressor = zlib.compressobj(level, zlib.DEFLATED, wbits, memory_level)
            result = compressor.compress(raw) + compressor.flush()
        else:
            windows = [window_size + 16] if method == "gzip" else [window_size, -window_size]
            last_error: zlib.error | None = None
            for wbits in windows:
                try:
                    decompressor = zlib.decompressobj(wbits)
                    result = decompressor.decompress(raw, max_bytes + 1)
                    if len(result) > max_bytes or decompressor.unconsumed_tail:
                        raise ValueError(f"codec output exceeds the {max_bytes}-byte limit")
                    result += decompressor.flush(max_bytes + 1 - len(result))
                    if len(result) > max_bytes:
                        raise ValueError(f"codec output exceeds the {max_bytes}-byte limit")
                    if not decompressor.eof:
                        raise ValueError("codec input is incomplete")
                    break
                except zlib.error as exc:
                    last_error = exc
            else:
                raise ValueError("codec input is not valid compressed data") from last_error
        if len(result) > max_bytes:
            raise ValueError(f"codec output exceeds the {max_bytes}-byte limit")
        return base64.b64encode(result).decode("ascii")

    interpreter.createcommand("::itest::semantic::py_codec", codec_callback)
    setattr(session, "_testcl_codec_callback", codec_callback)


def _install_python_ip_helper(session: Any) -> None:
    """Expose bounded IP normalization and ordering primitives to Tcl helpers."""
    inner = getattr(session, "_session", None)
    inprocess = getattr(inner, "_inprocess", None)
    interpreter = getattr(inprocess, "_interp", None)
    if interpreter is None or not hasattr(interpreter, "createcommand"):
        raise EmulatorInputError("IP-list support requires the in-process Tcl backend")

    max_address_bytes = 4096

    def parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        candidate = value.strip()
        if not candidate or "\x00" in candidate:
            return None
        try:
            if len(candidate.encode("utf-8")) > max_address_bytes:
                return None
        except UnicodeEncodeError:
            return None
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:
            return None

    def ip_callback(*args: str) -> str:
        if not args or args[0] not in {"normalize", "non_loopback", "compare"}:
            raise ValueError("IP helper requires normalize, non_loopback, or compare")
        operation = args[0]
        if operation == "compare":
            if len(args) != 3:
                raise ValueError("IP compare helper requires two addresses")
            first = parse_address(args[1])
            second = parse_address(args[2])
            if first is None or second is None:
                raise ValueError("IP compare helper received an invalid address")
            first_key = (first.version, int(first))
            second_key = (second.version, int(second))
            return str((first_key > second_key) - (first_key < second_key))
        if len(args) != 2:
            raise ValueError(f"IP {operation} helper requires one address")
        address = parse_address(args[1])
        if address is None:
            return "" if operation == "normalize" else "0"
        if operation == "normalize":
            return str(address)
        return "0" if address.is_loopback or address.is_unspecified else "1"

    interpreter.createcommand("::itest::semantic::py_ip", ip_callback)
    setattr(session, "_testcl_ip_callback", ip_callback)


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


def _normalise_backends(raw: Any) -> dict[str, dict[str, Any]]:
    """Normalize bounded, deterministic upstream fixtures keyed by member."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError(
            "backends must be an object mapping pool members to fixtures"
        )
    if len(raw) > BACKEND_MAX_MEMBERS:
        raise EmulatorInputError(
            f"backends cannot contain more than {BACKEND_MAX_MEMBERS} members"
        )

    def bounded_text(value: Any, field: str, maximum: int = 4096) -> str:
        text = _require_string(value, field)
        if "\x00" in text:
            raise EmulatorInputError(f"{field} must not contain NUL")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise EmulatorInputError(f"{field} must be valid UTF-8") from None
        if size > maximum:
            raise EmulatorInputError(f"{field} cannot exceed {maximum} UTF-8 bytes")
        return text

    def response(value: Any, field: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise EmulatorInputError(f"{field} must be an object")
        allowed = {"match", "status", "headers", "body"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"{field} unsupported field(s): {', '.join(unknown)}"
            )
        if not any(name in value for name in ("status", "headers", "body")):
            raise EmulatorInputError(
                f"{field} must provide status, headers, or body"
            )

        result: dict[str, Any] = {}
        if "match" in value:
            match = value["match"]
            if not isinstance(match, dict):
                raise EmulatorInputError(f"{field}.match must be an object")
            match_allowed = {"method", "uri", "path", "host", "pool"}
            unknown_match = sorted(set(match) - match_allowed)
            if unknown_match:
                raise EmulatorInputError(
                    f"{field}.match unsupported field(s): {', '.join(unknown_match)}"
                )
            if "uri" in match and "path" in match:
                raise EmulatorInputError(
                    f"{field}.match may contain uri or path, not both"
                )
            result["match"] = {
                name: bounded_text(item, f"{field}.match.{name}")
                for name, item in match.items()
            }
            if "method" in result["match"]:
                result["match"]["method"] = result["match"]["method"].upper()
        else:
            result["match"] = {}

        if "status" in value:
            status = value["status"]
            if (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 999
            ):
                raise EmulatorInputError(
                    f"{field}.status must be an integer between 100 and 999"
                )
            result["status"] = status
        if "headers" in value:
            headers = value["headers"]
            if not isinstance(headers, dict) or not all(
                isinstance(name, str) and isinstance(item, str)
                for name, item in headers.items()
            ):
                raise EmulatorInputError(f"{field}.headers must be an object of strings")
            normalised_headers: dict[str, str] = {}
            seen_header_names: set[str] = set()
            for name, item in headers.items():
                header_name = bounded_text(name, f"{field}.headers name", 256)
                header_value = bounded_text(item, f"{field}.headers.{header_name}", 8192)
                if "\r" in header_name or "\n" in header_name:
                    raise EmulatorInputError(
                        f"{field}.headers names must not contain newlines"
                    )
                if "\r" in header_value or "\n" in header_value:
                    raise EmulatorInputError(
                        f"{field}.headers.{header_name} must not contain newlines"
                    )
                canonical_name = header_name.lower()
                if canonical_name in seen_header_names:
                    raise EmulatorInputError(
                        f"{field}.headers contains duplicate name {header_name!r}"
                    )
                seen_header_names.add(canonical_name)
                normalised_headers[header_name] = header_value
            result["headers"] = normalised_headers
        if "body" in value:
            body = bounded_text(value["body"], f"{field}.body", BACKEND_MAX_RESPONSE_BODY_BYTES)
            result["body"] = body
        return result

    backends: dict[str, dict[str, Any]] = {}
    total_fixture_bytes = 0
    for raw_member, definition in raw.items():
        member = bounded_text(raw_member, "backend member", 512)
        if not member:
            raise EmulatorInputError("backend member names must not be empty")
        if not isinstance(definition, dict):
            raise EmulatorInputError(f"backends.{member} must be an object")
        unknown = sorted(set(definition) - {"state", "responses"})
        if unknown:
            raise EmulatorInputError(
                f"backends.{member} unsupported field(s): {', '.join(unknown)}"
            )
        state = definition.get("state", "up")
        if not isinstance(state, str) or state not in BACKEND_MEMBER_STATES:
            allowed_states = ", ".join(sorted(BACKEND_MEMBER_STATES))
            raise EmulatorInputError(
                f"backends.{member}.state must be one of: {allowed_states}"
            )
        raw_responses = definition.get("responses", [])
        if not isinstance(raw_responses, list):
            raise EmulatorInputError(f"backends.{member}.responses must be an array")
        if len(raw_responses) > BACKEND_MAX_RESPONSES_PER_MEMBER:
            raise EmulatorInputError(
                f"backends.{member}.responses cannot contain more than "
                f"{BACKEND_MAX_RESPONSES_PER_MEMBER} entries"
            )
        responses = [
            response(item, f"backends.{member}.responses[{index}]")
            for index, item in enumerate(raw_responses)
        ]
        if sum(not item["match"] for item in responses) > 1:
            raise EmulatorInputError(
                f"backends.{member}.responses may contain only one default response"
            )
        total_fixture_bytes += len(member.encode("utf-8"))
        for item in responses:
            total_fixture_bytes += sum(
                len(str(name).encode("utf-8")) + len(str(value).encode("utf-8"))
                for name, value in item["match"].items()
            )
            total_fixture_bytes += sum(
                len(str(name).encode("utf-8")) + len(str(value).encode("utf-8"))
                for name, value in item.get("headers", {}).items()
            )
            if "body" in item:
                total_fixture_bytes += len(item["body"].encode("utf-8"))
        if total_fixture_bytes > BACKEND_MAX_TOTAL_FIXTURE_BYTES:
            raise EmulatorInputError(
                "backends fixture data cannot exceed "
                f"{BACKEND_MAX_TOTAL_FIXTURE_BYTES} UTF-8 bytes"
            )
        backends[member] = {"state": state, "responses": responses}
    return backends


def _normalise_pool_modes(raw: Any) -> dict[str, str]:
    """Normalize optional per-pool selection policies."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("pool_modes must map pool names to selection modes")
    if len(raw) > BACKEND_MAX_MEMBERS:
        raise EmulatorInputError(
            f"pool_modes cannot contain more than {BACKEND_MAX_MEMBERS} pools"
        )
    modes: dict[str, str] = {}
    for raw_name, raw_mode in raw.items():
        name = _require_string(raw_name, "pool mode pool name")
        if not name or "\x00" in name or len(name.encode("utf-8")) > 256:
            raise EmulatorInputError(
                "pool mode pool names must be non-empty and at most 256 UTF-8 bytes"
            )
        if not isinstance(raw_mode, str):
            raise EmulatorInputError(f"pool_modes.{name} must be a string")
        mode = raw_mode.lower().replace("-", "_")
        if mode == "rr":
            mode = "round_robin"
        if mode not in POOL_SELECTION_MODES:
            allowed = ", ".join(sorted(POOL_SELECTION_MODES))
            raise EmulatorInputError(
                f"pool_modes.{name} must be one of: {allowed}"
            )
        modes[name] = mode
    return modes


def _backend_lookup(
    backends: dict[str, dict[str, Any]],
    pool: str,
    member: str,
    method: str,
    uri: str,
    host: str,
) -> dict[str, Any] | None:
    """Select the first matching response for the chosen upstream member."""
    fixture = backends.get(member)
    if fixture is None:
        return None
    path = uri.split("?", 1)[0] or "/"
    values = {
        "method": method.upper(),
        "uri": uri,
        "path": path,
        "host": host,
        "pool": pool,
    }
    selected: dict[str, Any] | None = None
    selected_index: int | None = None
    for index, candidate in enumerate(fixture["responses"]):
        if all(values[name] == expected for name, expected in candidate["match"].items()):
            selected = candidate
            selected_index = index
            break
    return {
        "member": member,
        "state": fixture["state"],
        "matched": selected is not None,
        "match_index": selected_index,
        "response": selected,
    }


def _normalise_cpu(raw: Any) -> dict[str, str | list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("cpu must map intervals to fixture values")
    if len(raw) > len(CPU_INTERVALS):
        raise EmulatorInputError("cpu cannot contain more than eight intervals")

    def normalise_value(value: Any, field: str) -> str:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise EmulatorInputError(f"{field} must be a number from 0 through 100")
        text = str(value)
        try:
            numeric = float(text)
        except ValueError:
            raise EmulatorInputError(f"{field} must be a number from 0 through 100") from None
        if not math.isfinite(numeric) or not 0 <= numeric <= 100:
            raise EmulatorInputError(f"{field} must be a number from 0 through 100")
        return text

    result: dict[str, str | list[str]] = {}
    for raw_interval, raw_value in raw.items():
        interval = _require_string(raw_interval, "cpu interval")
        canonical = CPU_INTERVAL_ALIASES.get("".join(interval.lower().split()))
        if canonical is None:
            raise EmulatorInputError(f"unsupported cpu interval {interval!r}")
        if canonical in result:
            raise EmulatorInputError(f"cpu interval {interval!r} was configured more than once")
        if canonical in {"all_seconds", "all_minutes"}:
            if not isinstance(raw_value, list) or len(raw_value) != 3:
                raise EmulatorInputError(
                    f"cpu.{canonical} must contain three numeric values"
                )
            result[canonical] = [
                normalise_value(value, f"cpu.{canonical}[{index}]")
                for index, value in enumerate(raw_value)
            ]
        else:
            if isinstance(raw_value, list):
                raise EmulatorInputError(f"cpu.{canonical} must contain one numeric value")
            result[canonical] = normalise_value(raw_value, f"cpu.{canonical}")
    return result


def _normalise_whereis(raw: Any) -> dict[str, dict[str, str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("whereis must map lookup addresses to field objects")
    if len(raw) > 256:
        raise EmulatorInputError("whereis cannot contain more than 256 fixtures")
    result: dict[str, dict[str, str]] = {}
    for raw_address, raw_record in raw.items():
        address = _require_string(raw_address, "whereis fixture address")
        if not address or "\x00" in address or len(address.encode("utf-8")) > 4096:
            raise EmulatorInputError(
                "whereis fixture addresses must be non-empty strings of at most 4096 UTF-8 bytes"
            )
        if not isinstance(raw_record, dict):
            raise EmulatorInputError(f"whereis fixture {address!r} must be an object")
        unknown = [
            raw_field
            for raw_field in raw_record
            if not isinstance(raw_field, str) or raw_field not in WHEREIS_FIELDS
        ]
        if unknown:
            raise EmulatorInputError(
                f"whereis fixture {address!r} has unsupported field(s): "
                + ", ".join(str(field) for field in unknown)
            )
        record: dict[str, str] = {}
        for raw_field, raw_value in raw_record.items():
            field = _require_string(raw_field, "whereis fixture field")
            if isinstance(raw_value, bool) or not isinstance(raw_value, (str, int, float)):
                raise EmulatorInputError(
                    f"whereis fixture {address!r}.{field} must be a string or number"
                )
            value = str(raw_value)
            if "\x00" in value or len(value.encode("utf-8")) > 4096:
                raise EmulatorInputError(
                    f"whereis fixture {address!r}.{field} must be at most 4096 UTF-8 bytes"
                )
            record[field] = value
        result[address] = record
    return result


def _normalise_pem_dtos(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("pem_dtos must map IMEI values to fixture results")
    if len(raw) > 256:
        raise EmulatorInputError("pem_dtos cannot contain more than 256 fixtures")
    result: dict[str, str] = {}
    for raw_input, raw_value in raw.items():
        input_value = _require_string(raw_input, "pem_dtos fixture input")
        if not input_value or "\x00" in input_value or len(input_value.encode("utf-8")) > 4096:
            raise EmulatorInputError(
                "pem_dtos fixture inputs must be non-empty strings of at most 4096 UTF-8 bytes"
            )
        value = _require_string(raw_value, f"pem_dtos fixture {input_value!r} result")
        if "\x00" in value or len(value.encode("utf-8")) > 4096:
            raise EmulatorInputError(
                f"pem_dtos fixture {input_value!r} result must be at most 4096 UTF-8 bytes"
            )
        result[input_value] = value
    return result


def _normalise_profile_settings(raw: Any) -> dict[str, dict[str, str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError(
            "profile_settings must map profile names to attribute objects"
        )
    settings: dict[str, dict[str, str]] = {}
    for profile, attributes in raw.items():
        profile_name = _require_string(profile, "profile settings name")
        if not profile_name or "\x00" in profile_name:
            raise EmulatorInputError(
                "profile settings names cannot be empty or contain NUL"
            )
        if not isinstance(attributes, dict):
            raise EmulatorInputError(
                f"profile settings for {profile_name!r} must be an object"
            )
        normalised_attributes: dict[str, str] = {}
        for attribute, value in attributes.items():
            attribute_name = _require_string(attribute, "profile attribute name")
            if not attribute_name or "\x00" in attribute_name:
                raise EmulatorInputError(
                    "profile attribute names cannot be empty or contain NUL"
                )
            if isinstance(value, bool):
                normalised_attributes[attribute_name] = "1" if value else "0"
            elif isinstance(value, (str, int, float)):
                normalised_attributes[attribute_name] = str(value)
            else:
                raise EmulatorInputError(
                    f"profile attribute {profile_name}.{attribute_name} "
                    "must be a string, number, or boolean"
                )
        canonical_profile = profile_name.upper()
        if canonical_profile in settings:
            raise EmulatorInputError(
                f"profile_settings contains duplicate profile {profile_name!r}"
            )
        settings[canonical_profile] = normalised_attributes
    return settings


def _normalise_dosl7(raw: Any) -> dict[str, Any]:
    """Normalize deterministic inputs for the bounded DOSL7 policy model."""
    if raw is None:
        return {
            "enabled": True,
            "health": 0,
            "profile": "",
            "mitigated": False,
            "greylist": [],
        }
    if not isinstance(raw, dict):
        raise EmulatorInputError("dosl7 must be an object")
    allowed = {"enabled", "health", "profile", "mitigated", "greylist"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(f"dosl7 unsupported field(s): {', '.join(unknown)}")

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("dosl7.enabled must be a boolean")
    mitigated = raw.get("mitigated", False)
    if not isinstance(mitigated, bool):
        raise EmulatorInputError("dosl7.mitigated must be a boolean")

    health = raw.get("health", 0)
    if isinstance(health, bool) or not isinstance(health, int) or not 0 <= health <= 2**31 - 1:
        raise EmulatorInputError("dosl7.health must be an integer from 0 to 2147483647")

    profile = raw.get("profile", "")
    if not isinstance(profile, str) or "\x00" in profile:
        raise EmulatorInputError("dosl7.profile must be a string without NUL")

    greylist = raw.get("greylist", {})
    if not isinstance(greylist, dict):
        raise EmulatorInputError("dosl7.greylist must map source IPs to rate/timeout objects")
    records: list[tuple[str, int, int]] = []
    for address, record in greylist.items():
        if not isinstance(address, str) or not address or "\x00" in address:
            raise EmulatorInputError(
                "dosl7.greylist source IPs must be non-empty strings without NUL"
            )
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise EmulatorInputError(
                f"dosl7.greylist source IP {address!r} is not a valid IPv4 or IPv6 address"
            ) from None
        if not isinstance(record, dict):
            raise EmulatorInputError(f"dosl7.greylist entry {address!r} must be an object")
        unsupported = sorted(set(record) - {"rate", "timeout"})
        if unsupported:
            raise EmulatorInputError(
                f"dosl7.greylist entry {address!r} has unsupported field(s): "
                f"{', '.join(unsupported)}"
            )
        rate = record.get("rate")
        timeout = record.get("timeout")
        if isinstance(rate, bool) or not isinstance(rate, int) or not 0 <= rate <= 100:
            raise EmulatorInputError(
                f"dosl7.greylist entry {address!r}.rate must be an integer from 0 to 100"
            )
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 0 <= timeout <= 2**31 - 1
        ):
            raise EmulatorInputError(
                f"dosl7.greylist entry {address!r}.timeout must be an integer from 0 to 2147483647"
            )
        records.append((address, rate, timeout))
    return {
        "enabled": enabled,
        "health": health,
        "profile": profile,
        "mitigated": mitigated,
        "greylist": records,
    }


def _normalise_dosl7_request(raw: Any) -> dict[str, bool]:
    """Normalize per-transaction DOSL7 decision inputs."""
    if not isinstance(raw, dict):
        raise EmulatorInputError("request.dosl7 must be an object")
    unknown = sorted(set(raw) - {"mitigated"})
    if unknown:
        raise EmulatorInputError(
            f"request.dosl7 unsupported field(s): {', '.join(unknown)}"
        )
    mitigated = raw.get("mitigated", False)
    if not isinstance(mitigated, bool):
        raise EmulatorInputError("request.dosl7.mitigated must be a boolean")
    return {"mitigated": mitigated}


def _normalise_asm_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise EmulatorInputError(f"{field} must be a string without NUL")
    return value


def _normalise_asm_string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and "\x00" not in item for item in value
    ):
        raise EmulatorInputError(f"{field} must be an array of strings without NUL")
    return list(value)


def _normalise_asm_violations(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise EmulatorInputError("asm.violations must be an array")
    violations: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        field = f"asm.violations[{index}]"
        if not isinstance(item, dict):
            raise EmulatorInputError(f"{field} must be an object")
        unknown = sorted(set(item) - {"name", "attack_type", "rating", "details"})
        if unknown:
            raise EmulatorInputError(
                f"{field} unsupported field(s): {', '.join(unknown)}"
            )
        name = _normalise_asm_string(item.get("name"), f"{field}.name")
        if not name:
            raise EmulatorInputError(f"{field}.name cannot be empty")
        attack_type = _normalise_asm_string(
            item.get("attack_type", ""), f"{field}.attack_type"
        )
        rating = _normalise_asm_string(item.get("rating", ""), f"{field}.rating")
        details = item.get("details", {})
        if not isinstance(details, dict) or not all(
            isinstance(key, str)
            and "\x00" not in key
            and isinstance(value, str)
            and "\x00" not in value
            for key, value in details.items()
        ):
            raise EmulatorInputError(f"{field}.details must be an object of strings")
        violations.append(
            {
                "name": name,
                "attack_type": attack_type,
                "rating": rating,
                "details": dict(details),
            }
        )
    return violations


def _normalise_asm(raw: Any) -> dict[str, Any]:
    """Normalize deterministic inputs for the bounded ASM/WAF policy model."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("asm must be an object")
    allowed = {
        "enabled",
        "policy",
        "client_ip",
        "fingerprint",
        "username",
        "login_status",
        "microservice",
        "status",
        "severity",
        "support_id",
        "captcha_status",
        "captcha_age",
        "payload",
        "violations",
        "signatures",
        "threat_campaigns",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(f"asm unsupported field(s): {', '.join(unknown)}")

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("asm.enabled must be a boolean")
    policy = _normalise_asm_string(raw.get("policy", ""), "asm.policy")
    client_ip = _normalise_asm_string(raw.get("client_ip", ""), "asm.client_ip")
    if client_ip:
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            raise EmulatorInputError(
                f"asm.client_ip {client_ip!r} is not a valid IPv4 or IPv6 address"
            ) from None
    fingerprint = _normalise_asm_string(raw.get("fingerprint", "0"), "asm.fingerprint")
    username = _normalise_asm_string(raw.get("username", ""), "asm.username")
    login_status = _normalise_asm_string(
        raw.get("login_status", "not_logged_in"), "asm.login_status"
    )
    if login_status not in ASM_LOGIN_STATUSES:
        raise EmulatorInputError(
            "asm.login_status must be one of: " + ", ".join(sorted(ASM_LOGIN_STATUSES))
        )
    microservice = _normalise_asm_string(
        raw.get("microservice", ""), "asm.microservice"
    )
    status = _normalise_asm_string(raw.get("status", ""), "asm.status")
    if status not in {"", *ASM_STATUSES}:
        raise EmulatorInputError(
            "asm.status must be empty or one of: " + ", ".join(sorted(ASM_STATUSES))
        )
    severity = _normalise_asm_string(raw.get("severity", ""), "asm.severity")
    if severity not in {"", *ASM_SEVERITIES}:
        raise EmulatorInputError(
            "asm.severity must be empty or one of: " + ", ".join(sorted(ASM_SEVERITIES))
        )
    support_id = _normalise_asm_string(raw.get("support_id", ""), "asm.support_id")
    captcha_status = _normalise_asm_string(
        raw.get("captcha_status", "not_received"), "asm.captcha_status"
    )
    if captcha_status not in ASM_CAPTCHA_STATUSES:
        raise EmulatorInputError(
            "asm.captcha_status must be one of: "
            + ", ".join(sorted(ASM_CAPTCHA_STATUSES))
        )
    captcha_age = raw.get("captcha_age", -1)
    if (
        isinstance(captcha_age, bool)
        or not isinstance(captcha_age, int)
        or not -1 <= captcha_age <= 2**31 - 1
    ):
        raise EmulatorInputError("asm.captcha_age must be an integer from -1 to 2147483647")
    payload = _normalise_asm_string(raw.get("payload", ""), "asm.payload")

    signatures_raw = raw.get("signatures", {})
    if not isinstance(signatures_raw, dict):
        raise EmulatorInputError("asm.signatures must be an object")
    unknown_signatures = sorted(set(signatures_raw) - set(ASM_SIGNATURE_FIELDS))
    if unknown_signatures:
        raise EmulatorInputError(
            "asm.signatures unsupported field(s): " + ", ".join(unknown_signatures)
        )
    signatures = {
        field: _normalise_asm_string_list(
            signatures_raw.get(field, []), f"asm.signatures.{field}"
        )
        for field in ASM_SIGNATURE_FIELDS
    }

    campaigns_raw = raw.get("threat_campaigns", {})
    if not isinstance(campaigns_raw, dict):
        raise EmulatorInputError("asm.threat_campaigns must be an object")
    unknown_campaigns = sorted(set(campaigns_raw) - set(ASM_CAMPAIGN_FIELDS))
    if unknown_campaigns:
        raise EmulatorInputError(
            "asm.threat_campaigns unsupported field(s): "
            + ", ".join(unknown_campaigns)
        )
    campaigns = {
        field: _normalise_asm_string_list(
            campaigns_raw.get(field, []), f"asm.threat_campaigns.{field}"
        )
        for field in ASM_CAMPAIGN_FIELDS
    }
    return {
        "enabled": enabled,
        "policy": policy,
        "client_ip": client_ip,
        "fingerprint": fingerprint,
        "username": username,
        "login_status": login_status,
        "microservice": microservice,
        "status": status,
        "severity": severity,
        "support_id": support_id,
        "captcha_status": captcha_status,
        "captcha_age": captcha_age,
        "payload": payload,
        "violations": _normalise_asm_violations(raw.get("violations", [])),
        "signatures": signatures,
        "threat_campaigns": campaigns,
    }


def _normalise_botdefense(raw: Any) -> dict[str, Any]:
    """Normalize deterministic inputs for the bounded Bot Defense model."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("botdefense must be an object")
    allowed = {
        "enabled",
        "action",
        "bot_anomalies",
        "bot_categories",
        "bot_name",
        "bot_signature",
        "bot_signature_category",
        "captcha_age",
        "captcha_status",
        "client_class",
        "client_type",
        "cookie_age",
        "cookie_status",
        "cs_allowed",
        "cs_attribute_device_id",
        "cs_possible",
        "device_id",
        "intent",
        "micro_service",
        "previous_action",
        "previous_request_age",
        "previous_support_id",
        "reason",
        "support_id",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            "botdefense unsupported field(s): " + ", ".join(unknown)
        )

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("botdefense.enabled must be a boolean")

    def string_field(name: str, default: str = "") -> str:
        return _normalise_asm_string(raw.get(name, default), f"botdefense.{name}")

    def string_list_field(name: str) -> list[str]:
        return _normalise_asm_string_list(
            raw.get(name, []), f"botdefense.{name}"
        )

    def boolean_field(name: str, default: bool) -> bool:
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise EmulatorInputError(f"botdefense.{name} must be a boolean")
        return value

    def integer_field(name: str, default: int, minimum: int = -1) -> int:
        value = raw.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise EmulatorInputError(
                f"botdefense.{name} must be an integer from {minimum}"
            )
        if value > 2**31 - 1:
            raise EmulatorInputError(
                f"botdefense.{name} must be at most 2147483647"
            )
        return value

    action = string_field("action", "allow")
    if not action:
        raise EmulatorInputError("botdefense.action cannot be empty")
    captcha_status = string_field("captcha_status", "not_received")
    if captcha_status not in BOTDEFENSE_CAPTCHA_STATUSES:
        raise EmulatorInputError(
            "botdefense.captcha_status must be one of: "
            + ", ".join(sorted(BOTDEFENSE_CAPTCHA_STATUSES))
        )
    client_type = string_field("client_type", "uncategorized")
    if client_type not in BOTDEFENSE_CLIENT_TYPES:
        raise EmulatorInputError(
            "botdefense.client_type must be one of: "
            + ", ".join(sorted(BOTDEFENSE_CLIENT_TYPES))
        )
    client_class = string_field("client_class", "unknown")
    if client_class not in BOTDEFENSE_CLIENT_CLASSES:
        raise EmulatorInputError(
            "botdefense.client_class must be one of: "
            + ", ".join(sorted(BOTDEFENSE_CLIENT_CLASSES))
        )
    cookie_status = string_field("cookie_status", "")
    if cookie_status not in BOTDEFENSE_COOKIE_STATUSES:
        raise EmulatorInputError(
            "botdefense.cookie_status must be one of: "
            + ", ".join(sorted(BOTDEFENSE_COOKIE_STATUSES))
        )
    micro_service = raw.get("micro_service", {})
    if not isinstance(micro_service, dict):
        raise EmulatorInputError("botdefense.micro_service must be an object")
    unknown_micro_service = sorted(set(micro_service) - {"name", "type"})
    if unknown_micro_service:
        raise EmulatorInputError(
            "botdefense.micro_service unsupported field(s): "
            + ", ".join(unknown_micro_service)
        )
    micro_service_result = {
        "name": _normalise_asm_string(
            micro_service.get("name", ""), "botdefense.micro_service.name"
        ),
        "type": _normalise_asm_string(
            micro_service.get("type", ""), "botdefense.micro_service.type"
        ),
    }
    return {
        "enabled": enabled,
        "action": action,
        "bot_anomalies": string_list_field("bot_anomalies"),
        "bot_categories": string_list_field("bot_categories"),
        "bot_name": string_field("bot_name"),
        "bot_signature": string_field("bot_signature"),
        "bot_signature_category": string_field("bot_signature_category"),
        "captcha_age": integer_field("captcha_age", -1),
        "captcha_status": captcha_status,
        "client_class": client_class,
        "client_type": client_type,
        "cookie_age": integer_field("cookie_age", -1),
        "cookie_status": cookie_status,
        "cs_allowed": boolean_field("cs_allowed", True),
        "cs_attribute_device_id": boolean_field("cs_attribute_device_id", True),
        "cs_possible": boolean_field("cs_possible", True),
        "device_id": integer_field("device_id", 0, 0),
        "intent": string_field("intent"),
        "micro_service": micro_service_result,
        "previous_action": string_field("previous_action", "undetermined"),
        "previous_request_age": integer_field("previous_request_age", 0, 0),
        "previous_support_id": string_field("previous_support_id", "0"),
        "reason": string_field("reason"),
        "support_id": string_field("support_id"),
    }


def _normalise_antifraud(raw: Any) -> dict[str, Any]:
    """Normalize deterministic inputs for the bounded Anti-Fraud model."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("antifraud must be an object")
    allowed = {
        "enabled",
        "profile",
        "login",
        "alert",
        "client_id",
        "device_id",
        "fingerprint",
        "geo",
        "guid",
        "result",
        "username",
        "license_id",
        "fields",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            "antifraud unsupported field(s): " + ", ".join(unknown)
        )

    def string_field(name: str, default: str = "") -> str:
        return _normalise_asm_string(raw.get(name, default), f"antifraud.{name}")

    def boolean_field(name: str, default: bool) -> bool:
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise EmulatorInputError(f"antifraud.{name} must be a boolean")
        return value

    enabled = boolean_field("enabled", True)
    result = string_field("result", "passed")
    if result not in ANTIFRAUD_RESULTS:
        raise EmulatorInputError(
            "antifraud.result must be one of: "
            + ", ".join(sorted(ANTIFRAUD_RESULTS))
        )
    fields = raw.get("fields", {})
    if not isinstance(fields, dict):
        raise EmulatorInputError("antifraud.fields must be an object")
    allowed_fields = set(ANTIFRAUD_ALERT_VALUE_FIELDS) | set(ANTIFRAUD_ALERT_FLAG_FIELDS)
    unknown_fields = sorted(set(fields) - allowed_fields)
    if unknown_fields:
        raise EmulatorInputError(
            "antifraud.fields unsupported field(s): " + ", ".join(unknown_fields)
        )
    alert_fields = {
        field: _normalise_asm_string(
            fields.get(field, ""), f"antifraud.fields.{field}"
        )
        for field in allowed_fields
    }
    return {
        "enabled": enabled,
        "profile": string_field("profile"),
        "login": boolean_field("login", False),
        "alert": boolean_field("alert", False),
        "client_id": string_field("client_id"),
        "device_id": string_field("device_id"),
        "fingerprint": string_field("fingerprint"),
        "geo": string_field("geo"),
        "guid": string_field("guid"),
        "result": result,
        "username": string_field("username"),
        "license_id": string_field("license_id"),
        "fields": {
            field: alert_fields[field]
            for field in (*ANTIFRAUD_ALERT_VALUE_FIELDS, *ANTIFRAUD_ALERT_FLAG_FIELDS)
        },
    }


def _normalise_antifraud_request(raw: Any) -> dict[str, bool]:
    if not isinstance(raw, dict):
        raise EmulatorInputError("request.antifraud must be an object")
    unknown = sorted(set(raw) - {"login", "alert"})
    if unknown:
        raise EmulatorInputError(
            "request.antifraud unsupported field(s): " + ", ".join(unknown)
        )
    result: dict[str, bool] = {}
    for field in ("login", "alert"):
        if field in raw:
            value = raw[field]
            if not isinstance(value, bool):
                raise EmulatorInputError(f"request.antifraud.{field} must be a boolean")
            result[field] = value
    return result


def _normalise_auth(raw: Any) -> dict[str, Any]:
    """Normalize deterministic authentication-session inputs."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("auth must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise EmulatorInputError("auth field names must be strings")
    allowed = {
        "enabled", "result", "type", "service", "prompt", "prompt_style",
        "credential_type", "ldap_status", "ldap_username", "response_data",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("auth unsupported field(s): " + ", ".join(unknown))

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("auth.enabled must be a boolean")

    def string_field(name: str, default: str = "") -> str:
        return _normalise_asm_string(raw.get(name, default), f"auth.{name}")

    result = string_field("result", "success")
    if result not in AUTH_RESULTS:
        raise EmulatorInputError(
            "auth.result must be one of: " + ", ".join(sorted(AUTH_RESULTS))
        )
    prompt_style = string_field("prompt_style", "echo_off")
    if prompt_style not in AUTH_PROMPT_STYLES:
        raise EmulatorInputError(
            "auth.prompt_style must be one of: "
            + ", ".join(sorted(AUTH_PROMPT_STYLES))
        )
    response_data = raw.get("response_data", {})
    if not isinstance(response_data, dict):
        raise EmulatorInputError("auth.response_data must be an object")
    normalised_response: dict[str, str] = {}
    for key, value in response_data.items():
        if not isinstance(key, str) or not key or "\x00" in key:
            raise EmulatorInputError("auth.response_data keys must be non-empty strings without NUL")
        normalised_response[key] = _normalise_asm_string(
            value, f"auth.response_data.{key}"
        )
    return {
        "enabled": enabled,
        "result": result,
        "type": string_field("type", "pam"),
        "service": string_field("service", "default_radius"),
        "prompt": string_field("prompt", "Password:"),
        "prompt_style": prompt_style,
        "credential_type": string_field("credential_type", "password"),
        "ldap_status": string_field("ldap_status"),
        "ldap_username": string_field("ldap_username"),
        "response_data": normalised_response,
    }


def _normalise_aaa(raw: Any) -> dict[str, Any]:
    """Normalize deterministic AAA request result inputs."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("aaa must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise EmulatorInputError("aaa field names must be strings")
    allowed = {"enabled", "auth_result", "acct_result"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("aaa unsupported field(s): " + ", ".join(unknown))
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("aaa.enabled must be a boolean")

    def result_field(name: str) -> str:
        value = _normalise_asm_string(raw.get(name, "OK"), f"aaa.{name}")
        if value not in AAA_RESULTS:
            raise EmulatorInputError(
                f"aaa.{name} must be one of: " + ", ".join(sorted(AAA_RESULTS))
            )
        return value

    return {
        "enabled": enabled,
        "auth_result": result_field("auth_result"),
        "acct_result": result_field("acct_result"),
    }


def _normalise_access(raw: Any) -> dict[str, Any]:
    """Normalize deterministic APM access-policy and session inputs."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("access must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise EmulatorInputError("access field names must be strings")
    allowed = {
        "enabled", "acl_result", "acl_lookup", "acl_matched", "policy_result",
        "policy_agent_id", "policy_uri", "flow_id", "session_data", "perflow",
        "ephemeral_auth_password",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("access unsupported field(s): " + ", ".join(unknown))

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise EmulatorInputError("access.enabled must be a boolean")

    def string_field(name: str, default: str = "") -> str:
        return _normalise_asm_string(raw.get(name, default), f"access.{name}")

    acl_result = string_field("acl_result", "Allow")
    if acl_result not in ACCESS_ACL_RESULTS:
        raise EmulatorInputError(
            "access.acl_result must be one of: " + ", ".join(sorted(ACCESS_ACL_RESULTS))
        )
    policy_result = string_field("policy_result", "allow")
    if policy_result not in ACCESS_POLICY_RESULTS:
        raise EmulatorInputError(
            "access.policy_result must be one of: "
            + ", ".join(sorted(ACCESS_POLICY_RESULTS))
        )
    policy_uri = raw.get("policy_uri", False)
    if not isinstance(policy_uri, bool):
        raise EmulatorInputError("access.policy_uri must be a boolean")

    def string_list(name: str) -> list[str]:
        value = raw.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise EmulatorInputError(f"access.{name} must be an array of strings")
        if any("\x00" in item for item in value):
            raise EmulatorInputError(f"access.{name} values cannot contain NUL")
        return list(value)

    def string_map(name: str) -> dict[str, str]:
        value = raw.get(name, {})
        if not isinstance(value, dict):
            raise EmulatorInputError(f"access.{name} must be an object")
        result: dict[str, str] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise EmulatorInputError(f"access.{name} keys must be non-empty strings without NUL")
            result[key] = _normalise_asm_string(item, f"access.{name}.{key}")
        return result

    ephemeral_password = string_field("ephemeral_auth_password", "temporary-password")
    if not ephemeral_password:
        raise EmulatorInputError("access.ephemeral_auth_password must not be empty")
    return {
        "enabled": enabled,
        "acl_result": acl_result,
        "acl_lookup": string_list("acl_lookup"),
        "acl_matched": string_list("acl_matched"),
        "policy_result": policy_result,
        "policy_agent_id": string_field("policy_agent_id"),
        "policy_uri": policy_uri,
        "flow_id": string_field("flow_id"),
        "session_data": string_map("session_data"),
        "perflow": string_map("perflow"),
        "ephemeral_auth_password": ephemeral_password,
    }


def _normalise_access_request(raw: Any) -> dict[str, Any]:
    """Normalize per-request APM access-policy and ACL overrides."""
    if not isinstance(raw, dict):
        raise EmulatorInputError("request.access must be an object")
    allowed = {
        "acl_result", "acl_lookup", "acl_matched", "policy_result",
        "policy_agent_id", "policy_uri", "flow_id",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            "request.access unsupported field(s): " + ", ".join(unknown)
        )

    def string_field(name: str, default: str = "") -> str:
        return _normalise_asm_string(raw.get(name, default), f"request.access.{name}")

    acl_result = string_field("acl_result", "Allow")
    if acl_result not in ACCESS_ACL_RESULTS:
        raise EmulatorInputError(
            "request.access.acl_result must be one of: "
            + ", ".join(sorted(ACCESS_ACL_RESULTS))
        )
    policy_result = string_field("policy_result", "allow")
    if policy_result not in ACCESS_POLICY_RESULTS:
        raise EmulatorInputError(
            "request.access.policy_result must be one of: "
            + ", ".join(sorted(ACCESS_POLICY_RESULTS))
        )
    policy_uri = raw.get("policy_uri", False)
    if not isinstance(policy_uri, bool):
        raise EmulatorInputError("request.access.policy_uri must be a boolean")

    def string_list(name: str) -> list[str]:
        value = raw.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise EmulatorInputError(f"request.access.{name} must be an array of strings")
        if any("\x00" in item for item in value):
            raise EmulatorInputError(f"request.access.{name} values cannot contain NUL")
        return list(value)

    result: dict[str, Any] = {}
    if "acl_result" in raw:
        result["acl_result"] = acl_result
    if "acl_lookup" in raw:
        result["acl_lookup"] = string_list("acl_lookup")
    if "acl_matched" in raw:
        result["acl_matched"] = string_list("acl_matched")
    if "policy_result" in raw:
        result["policy_result"] = policy_result
    if "policy_agent_id" in raw:
        result["policy_agent_id"] = string_field("policy_agent_id")
    if "policy_uri" in raw:
        result["policy_uri"] = policy_uri
    if "flow_id" in raw:
        result["flow_id"] = string_field("flow_id")
    return result


def _normalise_route(raw: Any) -> dict[str, Any]:
    """Normalize deterministic route/congestion-metric cache inputs."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("route must be an object")
    allowed = {"domain", "metrics"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("route unsupported field(s): " + ", ".join(unknown))

    domain = raw.get("domain", "0")
    if not isinstance(domain, str) or not domain or "\x00" in domain:
        raise EmulatorInputError("route.domain must be a non-empty string without NUL")

    metrics = raw.get("metrics", [])
    if not isinstance(metrics, list):
        raise EmulatorInputError("route.metrics must be an array of metric objects")
    if len(metrics) > 1024:
        raise EmulatorInputError("route.metrics cannot contain more than 1024 entries")

    metric_fields = {
        "destination", "gateway", "age", "expiration", "mtu", "rtt", "rttvar",
        "cwnd", "bandwidth",
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, metric in enumerate(metrics):
        if not isinstance(metric, dict):
            raise EmulatorInputError(f"route.metrics[{index}] must be an object")
        unknown_metric = sorted(set(metric) - metric_fields)
        if unknown_metric:
            raise EmulatorInputError(
                f"route.metrics[{index}] unsupported field(s): {', '.join(unknown_metric)}"
            )
        destination = metric.get("destination")
        gateway = metric.get("gateway", "")
        for name, value in (("destination", destination), ("gateway", gateway)):
            if not isinstance(value, str) or "\x00" in value:
                raise EmulatorInputError(
                    f"route.metrics[{index}].{name} must be a string without NUL"
                )
            if name == "destination" and not value:
                raise EmulatorInputError(
                    f"route.metrics[{index}].destination must not be empty"
                )
        key = (destination, gateway)
        if key in seen:
            raise EmulatorInputError(
                f"route.metrics contains duplicate destination/gateway pair {key!r}"
            )
        seen.add(key)
        normalised_metric: dict[str, Any] = {
            "destination": destination,
            "gateway": gateway,
        }
        for name in ("age", "expiration", "mtu", "rtt", "rttvar", "cwnd", "bandwidth"):
            value = metric.get(name, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EmulatorInputError(
                    f"route.metrics[{index}].{name} must be a non-negative integer"
                )
            normalised_metric[name] = value
        result.append(normalised_metric)
    return {"domain": domain, "metrics": result}


def _normalise_http_proxy(raw: Any) -> dict[str, Any]:
    """Normalize deterministic explicit-proxy and proxy-chaining inputs."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("http_proxy must be an object")
    allowed = {
        "enabled", "uri_rewrite", "resolved", "addr", "port", "rtdom",
        "iptuple", "chain",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            "http_proxy unsupported field(s): " + ", ".join(unknown)
        )

    def boolean(name: str, default: bool) -> bool:
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise EmulatorInputError(f"http_proxy.{name} must be a boolean")
        return value

    def string(name: str, default: str = "") -> str:
        value = raw.get(name, default)
        if not isinstance(value, str) or "\x00" in value:
            raise EmulatorInputError(
                f"http_proxy.{name} must be a string without NUL"
            )
        return value

    def integer(name: str, minimum: int, maximum: int) -> int:
        value = raw.get(name, 0)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= maximum
        ):
            raise EmulatorInputError(
                f"http_proxy.{name} must be an integer from {minimum} to {maximum}"
            )
        return value

    addr = string("addr")
    resolved = boolean("resolved", bool(addr))
    chain_raw = raw.get("chain", {})
    if not isinstance(chain_raw, dict):
        raise EmulatorInputError("http_proxy.chain must be an object")
    unknown_chain = sorted(
        set(chain_raw) - {"enabled", "host", "port", "response", "responses"}
    )
    if unknown_chain:
        raise EmulatorInputError(
            "http_proxy.chain unsupported field(s): " + ", ".join(unknown_chain)
        )
    chain_enabled = chain_raw.get("enabled", True)
    if not isinstance(chain_enabled, bool):
        raise EmulatorInputError("http_proxy.chain.enabled must be a boolean")
    chain_host = chain_raw.get("host", "")
    if not isinstance(chain_host, str) or "\x00" in chain_host:
        raise EmulatorInputError(
            "http_proxy.chain.host must be a string without NUL"
        )
    chain_port = chain_raw.get("port", 0)
    if (
        isinstance(chain_port, bool)
        or not isinstance(chain_port, int)
        or not 0 <= chain_port <= 65535
    ):
        raise EmulatorInputError(
            "http_proxy.chain.port must be an integer from 0 to 65535"
        )

    def normalise_response(raw_response: Any, field: str) -> dict[str, Any]:
        if not isinstance(raw_response, dict):
            raise EmulatorInputError(f"{field} must be an object")
        unknown_response = sorted(set(raw_response) - {"status", "headers", "body"})
        if unknown_response:
            raise EmulatorInputError(
                f"{field} unsupported field(s): "
                + ", ".join(unknown_response)
            )
        response_status = raw_response.get("status", 200)
        if (
            isinstance(response_status, bool)
            or not isinstance(response_status, int)
            or not 100 <= response_status <= 999
        ):
            raise EmulatorInputError(
                f"{field}.status must be an integer from 100 to 999"
            )
        response_headers = raw_response.get("headers", {})
        if not isinstance(response_headers, dict) or not all(
            isinstance(name, str)
            and isinstance(value, str)
            and "\x00" not in name
            and "\x00" not in value
            for name, value in response_headers.items()
        ):
            raise EmulatorInputError(
                f"{field}.headers must be an object of strings without NUL"
            )
        response_body = raw_response.get("body", "")
        if not isinstance(response_body, str) or "\x00" in response_body:
            raise EmulatorInputError(
                f"{field}.body must be a string without NUL"
            )
        if len(response_body.encode("utf-8")) > STREAM_MAX_BYTES:
            raise EmulatorInputError(
                f"{field}.body exceeds the 2 MiB limit"
            )
        return {
            "status": response_status,
            "reason": HTTP_REASON_PHRASES.get(response_status, ""),
            "headers": dict(response_headers),
            "body": response_body,
        }

    has_single_response = "response" in chain_raw
    has_response_sequence = "responses" in chain_raw
    if has_single_response and has_response_sequence:
        raise EmulatorInputError(
            "http_proxy.chain accepts response or responses, not both"
        )
    responses: list[dict[str, Any]] = []
    if has_single_response:
        response_raw = chain_raw["response"]
        if response_raw is not None:
            responses.append(
                normalise_response(response_raw, "http_proxy.chain.response")
            )
    elif has_response_sequence:
        response_raw = chain_raw["responses"]
        if not isinstance(response_raw, list) or not response_raw:
            raise EmulatorInputError(
                "http_proxy.chain.responses must be a non-empty array"
            )
        if len(response_raw) > MAX_HTTP_PROXY_CHAIN_RETRIES + 1:
            raise EmulatorInputError(
                "http_proxy.chain.responses must contain at most "
                f"{MAX_HTTP_PROXY_CHAIN_RETRIES + 1} entries"
            )
        responses = [
            normalise_response(item, f"http_proxy.chain.responses[{index}]")
            for index, item in enumerate(response_raw)
        ]

    return {
        "enabled": boolean("enabled", True),
        "uri_rewrite": boolean("uri_rewrite", True),
        "resolved": resolved,
        "addr": addr,
        "port": integer("port", 0, 65535),
        "rtdom": integer("rtdom", 0, 2**32 - 1),
        "iptuple": string("iptuple"),
        "chain": {
            "enabled": chain_enabled,
            "host": chain_host,
            "port": chain_port,
            "response": responses[0] if len(responses) == 1 else None,
            "responses": responses,
            "responses_explicit": has_response_sequence,
        },
    }


def _normalise_http_class(raw: Any, field: str) -> dict[str, Any]:
    """Normalize one bounded HTTP class-selector outcome."""
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"{field} must be an object")
    if any(not isinstance(key, str) for key in raw):
        raise EmulatorInputError(f"{field} field names must be strings")
    allowed = {"result", "name", "asm", "wa"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            f"{field} unsupported field(s): " + ", ".join(unknown)
        )
    result = _require_string(raw.get("result", "selected"), f"{field}.result").lower()
    if result not in HTTP_CLASS_RESULTS:
        raise EmulatorInputError(
            f"{field}.result must be one of: "
            + ", ".join(sorted(HTTP_CLASS_RESULTS))
        )
    name = _require_string(raw.get("name", ""), f"{field}.name")
    if "\x00" in name:
        raise EmulatorInputError(f"{field}.name must not contain NUL")
    if result == "selected" and not name:
        raise EmulatorInputError(f"{field}.name is required when result is selected")
    asm = raw.get("asm", False)
    wa = raw.get("wa", False)
    if not isinstance(asm, bool):
        raise EmulatorInputError(f"{field}.asm must be a boolean")
    if not isinstance(wa, bool):
        raise EmulatorInputError(f"{field}.wa must be a boolean")
    return {"result": result, "name": name, "asm": asm, "wa": wa}


def _normalise_flowtable(raw: Any) -> dict[str, Any]:
    """Normalize bounded flow-table counts and configured limits."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("flowtable must be an object")
    unknown = sorted(
        (str(key) for key in set(raw) - {"count", "limit"}),
    )
    if unknown:
        raise EmulatorInputError(
            "flowtable unsupported field(s): " + ", ".join(unknown)
        )

    def groups(container: dict[str, Any], name: str) -> dict[str, int]:
        value = container.get(name, {})
        if not isinstance(value, dict):
            raise EmulatorInputError(f"flowtable.{name} must be an object")
        result: dict[str, int] = {}
        for key, count in value.items():
            if not isinstance(key, str) or not key or "\x00" in key:
                raise EmulatorInputError(
                    f"flowtable.{name} keys must be non-empty strings without NUL"
                )
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise EmulatorInputError(
                    f"flowtable.{name}.{key} must be a non-negative integer"
                )
            result[key] = count
        return result

    count = raw.get("count", {})
    if not isinstance(count, dict):
        raise EmulatorInputError("flowtable.count must be an object")
    unknown_count = sorted(
        (str(key) for key in set(count) - {"global", "virtual", "route_domain"}),
    )
    if unknown_count:
        raise EmulatorInputError(
            "flowtable.count unsupported field(s): " + ", ".join(unknown_count)
        )
    global_count = count.get("global", 0)
    if (
        isinstance(global_count, bool)
        or not isinstance(global_count, int)
        or global_count < 0
    ):
        raise EmulatorInputError(
            "flowtable.count.global must be a non-negative integer"
        )
    limit = raw.get("limit", {})
    if not isinstance(limit, dict):
        raise EmulatorInputError("flowtable.limit must be an object")
    unknown_limit = sorted(
        (str(key) for key in set(limit) - {"virtual", "route_domain"}),
    )
    if unknown_limit:
        raise EmulatorInputError(
            "flowtable.limit unsupported field(s): " + ", ".join(unknown_limit)
        )
    return {
        "count_global": global_count,
        "count_virtual": groups(count, "virtual"),
        "count_route_domain": groups(count, "route_domain"),
        "limit_virtual": groups(limit, "virtual"),
        "limit_route_domain": groups(limit, "route_domain"),
    }


def _normalise_sideband(raw: Any) -> dict[str, dict[str, str]]:
    """Normalize deterministic sideband destinations and response fixtures."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("sideband must be an object mapping destinations to fixtures")
    if len(raw) > 32:
        raise EmulatorInputError("sideband cannot contain more than 32 destination fixtures")

    result: dict[str, dict[str, str]] = {}
    allowed = {"connect_status", "response"}
    valid_statuses = {"connected", "error", "refused", "timeout", "unreachable"}
    for destination, fixture in raw.items():
        valid_destination_encoding = True
        try:
            destination_bytes = destination.encode("utf-8") if isinstance(destination, str) else b""
        except UnicodeEncodeError:
            valid_destination_encoding = False
            destination_bytes = b""
        if (
            not isinstance(destination, str)
            or not destination
            or not valid_destination_encoding
            or "\x00" in destination
            or len(destination_bytes) > 4096
        ):
            raise EmulatorInputError(
                "sideband destination keys must be non-empty strings of at most 4096 UTF-8 bytes without NUL"
            )
        if isinstance(fixture, str):
            connect_status = "connected"
            response = fixture
        elif isinstance(fixture, dict):
            unknown = sorted(set(fixture) - allowed)
            if unknown:
                raise EmulatorInputError(
                    f"sideband.{destination} unsupported field(s): {', '.join(unknown)}"
                )
            connect_status = fixture.get("connect_status", "connected")
            response = fixture.get("response", "")
        else:
            raise EmulatorInputError(
                f"sideband.{destination} must be a response string or fixture object"
            )
        if not isinstance(connect_status, str) or connect_status not in valid_statuses:
            raise EmulatorInputError(
                f"sideband.{destination}.connect_status must be one of: "
                + ", ".join(sorted(valid_statuses))
            )
        if not isinstance(response, str) or "\x00" in response:
            raise EmulatorInputError(
                f"sideband.{destination}.response must be a string without NUL"
            )
        valid_response_encoding = True
        try:
            response_bytes = response.encode("utf-8")
        except UnicodeEncodeError:
            valid_response_encoding = False
            response_bytes = b""
        if len(response_bytes) > 1024 * 1024 or not valid_response_encoding:
            raise EmulatorInputError(
                f"sideband.{destination}.response cannot exceed 1048576 UTF-8 bytes"
            )
        result[destination] = {
            "connect_status": connect_status,
            "response": response,
        }
    return result


def _normalise_ifiles(raw: Any) -> dict[str, dict[str, str]]:
    """Normalize scenario-owned iFile content and metadata without file I/O."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("ifiles must be an object mapping iFile names to fixtures")
    if len(raw) > 128:
        raise EmulatorInputError("ifiles cannot contain more than 128 fixtures")

    result: dict[str, dict[str, str]] = {}
    total_bytes = 0
    allowed = {
        "content",
        "content_base64",
        "last_updated_by",
        "last_update_time",
        "revision",
        "checksum",
    }
    for name, fixture in raw.items():
        if not isinstance(name, str) or not name or "\x00" in name:
            raise EmulatorInputError("ifile names must be non-empty strings without NUL")
        try:
            name_bytes = name.encode("utf-8")
        except UnicodeEncodeError:
            name_bytes = b""
        if not name_bytes or len(name_bytes) > 4096:
            raise EmulatorInputError("ifile names must be at most 4096 UTF-8 bytes")

        if isinstance(fixture, str):
            fixture = {"content": fixture}
        if not isinstance(fixture, dict):
            raise EmulatorInputError(f"ifiles.{name} must be a string or fixture object")
        unknown = sorted(set(fixture) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"ifiles.{name} unsupported field(s): {', '.join(unknown)}"
            )
        if "content" in fixture and "content_base64" in fixture:
            raise EmulatorInputError(
                f"ifiles.{name} must provide only one of content or content_base64"
            )

        if "content_base64" in fixture:
            encoded = fixture["content_base64"]
            if not isinstance(encoded, str):
                raise EmulatorInputError(f"ifiles.{name}.content_base64 must be a string")
            if len(encoded) > ((32 * 1024 * 1024 + 2) // 3) * 4:
                raise EmulatorInputError(
                    f"ifiles.{name}.content cannot exceed 33554432 bytes"
                )
            try:
                content = base64.b64decode(encoded.encode("ascii"), validate=True)
            except (UnicodeEncodeError, ValueError, binascii.Error):
                raise EmulatorInputError(
                    f"ifiles.{name}.content_base64 must be valid base64"
                ) from None
            content_base64 = encoded
        else:
            content_value = fixture.get("content", "")
            if not isinstance(content_value, str) or "\x00" in content_value:
                raise EmulatorInputError(
                    f"ifiles.{name}.content must be a string without NUL"
                )
            try:
                content = content_value.encode("utf-8")
            except UnicodeEncodeError:
                raise EmulatorInputError(
                    f"ifiles.{name}.content must be valid UTF-8"
                ) from None
            content_base64 = base64.b64encode(content).decode("ascii")
        if len(content) > 32 * 1024 * 1024:
            raise EmulatorInputError(
                f"ifiles.{name}.content cannot exceed 33554432 bytes"
            )
        total_bytes += len(content)
        if total_bytes > 64 * 1024 * 1024:
            raise EmulatorInputError("ifiles content cannot exceed 67108864 bytes in total")

        def metadata_string(field: str, default: str) -> str:
            value = fixture.get(field, default)
            if not isinstance(value, str) or "\x00" in value:
                raise EmulatorInputError(
                    f"ifiles.{name}.{field} must be a string without NUL"
                )
            try:
                value_bytes = value.encode("utf-8")
            except UnicodeEncodeError:
                raise EmulatorInputError(
                    f"ifiles.{name}.{field} must be valid UTF-8"
                ) from None
            if len(value_bytes) > 4096:
                raise EmulatorInputError(
                    f"ifiles.{name}.{field} cannot exceed 4096 UTF-8 bytes"
                )
            return value

        revision_value = fixture.get("revision", 1)
        if isinstance(revision_value, bool) or not isinstance(revision_value, int):
            raise EmulatorInputError(f"ifiles.{name}.revision must be a positive integer")
        if revision_value < 1:
            raise EmulatorInputError(f"ifiles.{name}.revision must be a positive integer")
        checksum = metadata_string(
            "checksum", hashlib.sha256(content).hexdigest()
        )
        result[name] = {
            "content_base64": content_base64,
            "last_updated_by": metadata_string("last_updated_by", "emulator"),
            "last_update_time": metadata_string("last_update_time", ""),
            "revision": str(revision_value),
            "checksum": checksum,
        }
    return result


def _normalise_urlcat(raw: Any) -> dict[str, Any]:
    """Normalize deterministic URL categorization lookup fixtures."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("urlcat must be an object")
    allowed = {"queries", "blind_queries", "default"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("urlcat unsupported field(s): " + ", ".join(unknown))

    def value(field: str, raw_value: Any, default: list[str] | None = None) -> list[str]:
        if raw_value is None:
            if default is not None:
                return list(default)
            raise EmulatorInputError(f"urlcat.{field} must contain at least one category")
        if isinstance(raw_value, str):
            categories = [raw_value]
        elif isinstance(raw_value, list):
            categories = raw_value
        else:
            raise EmulatorInputError(
                f"urlcat.{field} values must be strings or arrays of strings"
            )
        if not categories or len(categories) > 64:
            raise EmulatorInputError(
                f"urlcat.{field} values must contain 1 to 64 categories"
            )
        result: list[str] = []
        total_bytes = 0
        for index, category in enumerate(categories):
            if not isinstance(category, str) or not category or "\x00" in category:
                raise EmulatorInputError(
                    f"urlcat.{field}[{index}] must be a non-empty string without NUL"
                )
            try:
                category_bytes = category.encode("utf-8")
            except UnicodeEncodeError:
                raise EmulatorInputError(
                    f"urlcat.{field}[{index}] must be valid UTF-8"
                ) from None
            if len(category_bytes) > 4096:
                raise EmulatorInputError(
                    f"urlcat.{field}[{index}] cannot exceed 4096 UTF-8 bytes"
                )
            total_bytes += len(category_bytes)
            result.append(category)
        if total_bytes > 8192:
            raise EmulatorInputError(f"urlcat.{field} categories cannot exceed 8192 bytes")
        return result

    def mappings(field: str) -> dict[str, list[str]]:
        raw_mappings = raw.get(field, {})
        if not isinstance(raw_mappings, dict):
            raise EmulatorInputError(f"urlcat.{field} must be an object mapping inputs to categories")
        if len(raw_mappings) > 256:
            raise EmulatorInputError(f"urlcat.{field} cannot contain more than 256 entries")
        result: dict[str, list[str]] = {}
        for lookup, raw_value in raw_mappings.items():
            if not isinstance(lookup, str) or not lookup or "\x00" in lookup:
                raise EmulatorInputError(
                    f"urlcat.{field} lookup keys must be non-empty strings without NUL"
                )
            try:
                lookup_bytes = lookup.encode("utf-8")
            except UnicodeEncodeError:
                raise EmulatorInputError(
                    f"urlcat.{field} lookup keys must be valid UTF-8"
                ) from None
            if len(lookup_bytes) > 4096:
                raise EmulatorInputError(
                    f"urlcat.{field} lookup keys cannot exceed 4096 UTF-8 bytes"
                )
            result[lookup] = value(field, raw_value)
        return result

    default = value("default", raw.get("default"), ["Unknown"])
    return {
        "queries": mappings("queries"),
        "blind_queries": mappings("blind_queries"),
        "default": default,
    }


def _normalise_ip(raw: Any) -> dict[str, Any]:
    """Normalize deterministic inputs for the bounded IP command model."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise EmulatorInputError("ip must be an object")
    allowed = {"hops", "intelligence", "reputation"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError("ip unsupported field(s): " + ", ".join(unknown))

    hops = raw.get("hops", 0)
    if isinstance(hops, bool) or not isinstance(hops, int) or not 0 <= hops <= 255:
        raise EmulatorInputError("ip.hops must be an integer from 0 to 255")

    def records(name: str) -> dict[str, list[str]]:
        value = raw.get(name, {})
        if not isinstance(value, dict):
            raise EmulatorInputError(f"ip.{name} must be an object mapping IP addresses to category arrays")
        result: dict[str, list[str]] = {}
        for address, categories in value.items():
            if not isinstance(address, str) or not address or "\x00" in address:
                raise EmulatorInputError(f"ip.{name} keys must be non-empty IP address strings without NUL")
            try:
                canonical_address = str(ipaddress.ip_address(address))
            except ValueError:
                raise EmulatorInputError(
                    f"ip.{name} key {address!r} is not a valid IPv4 or IPv6 address"
                ) from None
            if canonical_address in result:
                raise EmulatorInputError(
                    f"ip.{name} contains duplicate address {address!r}"
                )
            if not isinstance(categories, list) or not all(
                isinstance(category, str)
                and category
                and "\x00" not in category
                and not any(delimiter in category for delimiter in "{}")
                for category in categories
            ):
                raise EmulatorInputError(
                    f"ip.{name}.{address} must be an array of non-empty strings without NUL or Tcl braces"
                )
            if len(categories) > 128:
                raise EmulatorInputError(
                    f"ip.{name}.{address} cannot contain more than 128 categories"
                )
            result[canonical_address] = list(categories)
        return result

    return {
        "hops": hops,
        "intelligence": records("intelligence"),
        "reputation": records("reputation"),
    }


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
        "http_class",
        "lb_failure",
        "persist_down",
        "lb_queue",
        "dosl7",
        "antifraud",
        "access",
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
    if "http_class" in request:
        kwargs["http_class"] = _normalise_http_class(
            request["http_class"], "http_class"
        )
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
    if "persist_down" in request:
        kwargs["persist_down"] = _normalise_persist_down(
            request["persist_down"], "persist_down"
        )
    if "lb_queue" in request:
        kwargs["lb_queue"] = _normalise_lb_queue(request["lb_queue"], "lb_queue")
    causal_queue = kwargs.get("lb_queue")
    if "lb_failure" in kwargs and (
        "persist_down" in kwargs
        or (causal_queue is not None and causal_queue["queued"])
    ):
        raise EmulatorInputError(
            "lb_failure cannot be combined with persist_down or a queued lb_queue"
        )
    if "dosl7" in request:
        kwargs["dosl7"] = _normalise_dosl7_request(request["dosl7"])
    if "antifraud" in request:
        kwargs["antifraud"] = _normalise_antifraud_request(request["antifraud"])
    if "access" in request:
        kwargs["access"] = _normalise_access_request(request["access"])
    return kwargs


def _normalise_persist_down(raw: Any, field: str) -> dict[str, str]:
    """Validate a deterministic persistence target for ``PERSIST_DOWN``."""
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"{field} must be an object")
    unknown = sorted(set(raw) - {"pool", "member"})
    if unknown:
        raise EmulatorInputError(
            f"{field} unsupported field(s): {', '.join(unknown)}"
        )
    member = _require_string(raw.get("member"), f"{field}.member")
    if not member or "\x00" in member or len(member.encode("utf-8")) > 512:
        raise EmulatorInputError(
            f"{field}.member must be a non-empty string of at most 512 UTF-8 bytes"
        )
    pool = raw.get("pool", "")
    if not isinstance(pool, str) or "\x00" in pool or len(pool.encode("utf-8")) > 256:
        raise EmulatorInputError(
            f"{field}.pool must be a string of at most 256 UTF-8 bytes"
        )
    return {"pool": pool, "member": member}


def _normalise_lb_queue(raw: Any, field: str) -> dict[str, Any]:
    """Validate bounded queue observations and the optional queue trigger."""
    if not isinstance(raw, dict):
        raise EmulatorInputError(f"{field} must be an object")
    allowed = {
        "queued",
        "on_connlimit",
        "depth",
        "limit_depth",
        "limit_time",
        "age_head",
        "age_max",
        "age_edm",
        "age_ema",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise EmulatorInputError(
            f"{field} unsupported field(s): {', '.join(unknown)}"
        )

    def boolean(name: str, default: bool) -> bool:
        value = raw.get(name, default)
        if not isinstance(value, bool):
            raise EmulatorInputError(f"{field}.{name} must be a boolean")
        return value

    def integer(name: str) -> int:
        value = raw.get(name, 0)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= LB_QUEUE_MAX_VALUE
        ):
            raise EmulatorInputError(
                f"{field}.{name} must be an integer from 0 to {LB_QUEUE_MAX_VALUE}"
            )
        return value

    queued = boolean("queued", False)
    on_connlimit = boolean("on_connlimit", queued)
    if queued and not on_connlimit:
        raise EmulatorInputError(
            f"{field}.on_connlimit must be true when {field}.queued is true"
        )
    depth = integer("depth")
    if queued and depth < 1:
        raise EmulatorInputError(
            f"{field}.depth must be at least 1 when {field}.queued is true"
        )
    return {
        "queued": queued,
        "on_connlimit": on_connlimit,
        "depth": depth,
        "limit_depth": integer("limit_depth"),
        "limit_time": integer("limit_time"),
        "age_head": integer("age_head"),
        "age_max": integer("age_max"),
        "age_edm": integer("age_edm"),
        "age_ema": integer("age_ema"),
    }


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
    dict[str, dict[str, Any]],
    dict[str, str],
    dict[str, list[dict[str, Any]]],
    list[tuple[str, dict[str, str], str]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, dict[str, str]],
    dict[str, str | list[str]],
    dict[str, dict[str, str]],
    dict[str, str],
]:
    if not isinstance(scenario, dict):
        raise EmulatorInputError("scenario must be a JSON object")

    allowed_fields = {
        "tmos_version",
        "irule",
        "irule_file",
        "profiles",
        "pools",
        "backends",
        "pool_modes",
        "resolvers",
        "datagroups",
        "profile_settings",
        "dosl7",
        "asm",
        "botdefense",
        "antifraud",
        "auth",
        "aaa",
        "access",
        "ip",
        "route",
        "http_proxy",
        "flowtable",
        "sideband",
        "ifiles",
        "urlcat",
        "cpu",
        "whereis",
        "pem_dtos",
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

    pools = _normalise_pools(scenario.get("pools"))
    backends = _normalise_backends(scenario.get("backends"))
    pool_modes = _normalise_pool_modes(scenario.get("pool_modes"))
    unknown_pool_modes = sorted(set(pool_modes) - set(pools))
    if unknown_pool_modes:
        names = ", ".join(unknown_pool_modes)
        raise EmulatorInputError(
            f"pool_modes references unknown pool(s): {names}"
        )

    return (
        source,
        profiles,
        pools,
        backends,
        pool_modes,
        _normalise_resolvers(scenario.get("resolvers")),
        _normalise_datagroups(scenario.get("datagroups")),
        _normalise_profile_settings(scenario.get("profile_settings")),
        _normalise_dosl7(scenario.get("dosl7")),
        _normalise_asm(scenario.get("asm")),
        _normalise_botdefense(scenario.get("botdefense")),
        _normalise_antifraud(scenario.get("antifraud")),
        _normalise_auth(scenario.get("auth")),
        _normalise_aaa(scenario.get("aaa")),
        _normalise_access(scenario.get("access")),
        _normalise_ip(scenario.get("ip")),
        _normalise_route(scenario.get("route")),
        _normalise_http_proxy(scenario.get("http_proxy")),
        _normalise_flowtable(scenario.get("flowtable")),
        _normalise_sideband(scenario.get("sideband")),
        _normalise_ifiles(scenario.get("ifiles")),
        _normalise_urlcat(scenario.get("urlcat")),
        _normalise_cpu(scenario.get("cpu")),
        _normalise_whereis(scenario.get("whereis")),
        _normalise_pem_dtos(scenario.get("pem_dtos")),
    )


def _load_event_profiles(root: Path) -> dict[str, set[str]]:
    _load_session_class(root)
    try:
        from compiler.registry.namespace_registry import NAMESPACE_REGISTRY
    except ImportError as exc:  # pragma: no cover - depends on external checkout
        raise EmulatorInputError(f"could not load tcl-lsp event registry: {exc}") from exc
    event_profiles: dict[str, set[str]] = {}
    for name in _catalog_event_names(NAMESPACE_REGISTRY):
        if name in TMOS_17_5_POST_TARGET_EVENTS or name in TMOS_17_5_UNAVAILABLE_EVENTS:
            continue
        props = NAMESPACE_REGISTRY.get_props(name)
        if props is not None:
            event_profiles[name] = set(props.implied_profiles)
        else:
            event_profiles[name] = set(
                TMOS_17_5_EVENT_OVERRIDES[name]["implied_profiles"]
            )
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
            if layer == "policy" and field in POLICY_LIST_STATE_FIELDS and isinstance(value, list):
                if len(value) > 256 or any(
                    not isinstance(item, str) or not item or "\x00" in item
                    for item in value
                ):
                    raise EmulatorInputError(
                        f"event state policy.{field} must be an array of at most 256 non-empty strings"
                    )
                layer_values[field] = _tcl_list_value(value)
            elif layer == "policy" and field == "rules" and isinstance(value, dict):
                if len(value) > 256:
                    raise EmulatorInputError(
                        "event state policy.rules must contain at most 256 policies"
                    )
                flattened: list[str] = []
                for policy_name, rules in value.items():
                    if (
                        not isinstance(policy_name, str)
                        or not policy_name
                        or "\x00" in policy_name
                        or not isinstance(rules, list)
                        or len(rules) > 256
                        or any(
                            not isinstance(rule, str) or not rule or "\x00" in rule
                            for rule in rules
                        )
                    ):
                        raise EmulatorInputError(
                            "event state policy.rules must map policy names to arrays of at most 256 non-empty strings"
                        )
                    flattened.extend((policy_name, _tcl_list_value(rules)))
                layer_values[field] = _tcl_list_value(flattened)
            elif layer == "tap" and field == "config" and isinstance(value, dict):
                if len(value) > 256:
                    raise EmulatorInputError(
                        "event state tap.config must contain at most 256 applications"
                    )
                encoded_config: dict[str, str] = {}
                for application, entities in value.items():
                    if (
                        not isinstance(application, str)
                        or not application
                        or "\x00" in application
                        or not isinstance(entities, dict)
                        or len(entities) > 256
                    ):
                        raise EmulatorInputError(
                            "event state tap.config must map application names to objects of at most 256 entities"
                        )
                    encoded_entities: dict[str, str] = {}
                    for entity, item in entities.items():
                        if not isinstance(entity, str) or not entity or "\x00" in entity:
                            raise EmulatorInputError(
                                "event state tap.config entity names must be non-empty strings without NUL"
                            )
                        if isinstance(item, bool):
                            item_text = "1" if item else "0"
                        elif isinstance(item, (str, int, float)):
                            item_text = str(item)
                        else:
                            raise EmulatorInputError(
                                "event state tap.config values must be strings or numbers"
                            )
                        if "\x00" in item_text:
                            raise EmulatorInputError(
                                "event state tap.config values must not contain NUL"
                            )
                        encoded_entities[entity] = item_text
                    encoded_config[application] = _tcl_dict_value(encoded_entities)
                layer_values[field] = _tcl_dict_value(encoded_config)
            elif layer == "tap" and field == "insight" and isinstance(value, dict):
                if len(value) > 256:
                    raise EmulatorInputError(
                        "event state tap.insight must contain at most 256 fields"
                    )
                encoded_insight: dict[str, str] = {}
                for key, item in value.items():
                    if not isinstance(key, str) or not key or "\x00" in key:
                        raise EmulatorInputError(
                            "event state tap.insight keys must be non-empty strings without NUL"
                        )
                    if isinstance(item, bool):
                        item_text = "1" if item else "0"
                    elif isinstance(item, (str, int, float)):
                        item_text = str(item)
                    else:
                        raise EmulatorInputError(
                            "event state tap.insight values must be strings or numbers"
                        )
                    if "\x00" in item_text:
                        raise EmulatorInputError(
                            "event state tap.insight values must not contain NUL"
                        )
                    encoded_insight[key] = item_text
                layer_values[field] = _tcl_dict_value(encoded_insight)
            elif layer == "tmm" and field == "cmp_groups" and isinstance(value, list):
                if not value or any(
                    isinstance(item, bool)
                    or not isinstance(item, int)
                    or item < 0
                    for item in value
                ):
                    raise EmulatorInputError(
                        "event state tmm.cmp_groups must be a non-empty array of non-negative integers"
                    )
                layer_values[field] = " ".join(str(item) for item in value)
            elif layer == "bigproto" and field == "enable_fix_reset":
                if isinstance(value, bool):
                    layer_values[field] = "1" if value else "0"
                elif isinstance(value, str) and value.lower() in {
                    "0", "1", "true", "false", "yes", "no", "on", "off"
                }:
                    layer_values[field] = "1" if value.lower() in {"1", "true", "yes", "on"} else "0"
                elif isinstance(value, int) and value in {0, 1}:
                    layer_values[field] = str(value)
                else:
                    raise EmulatorInputError(
                        "event state bigproto.enable_fix_reset must be a Tcl boolean"
                    )
            elif layer == "fix" and field in {"tags", "tag_maps"} and isinstance(value, dict):
                if len(value) > 256:
                    raise EmulatorInputError(
                        f"event state fix.{field} must contain at most 256 entries"
                    )
                encoded: dict[str, str] = {}
                for key, item in value.items():
                    if (
                        not isinstance(key, str)
                        or not key
                        or any(character in key for character in "\x00\r\n")
                    ):
                        raise EmulatorInputError(
                            f"event state fix.{field} keys must be non-empty strings without NUL or newlines"
                        )
                    if isinstance(item, bool):
                        item_text = "1" if item else "0"
                    elif isinstance(item, (str, int, float)):
                        item_text = str(item)
                    else:
                        raise EmulatorInputError(
                            f"event state fix.{field} values must be strings or numbers"
                        )
                    if any(character in item_text for character in "\x00\r\n"):
                        raise EmulatorInputError(
                            f"event state fix.{field} values must not contain NUL or newlines"
                        )
                    if field == "tag_maps" and not item_text:
                        raise EmulatorInputError(
                            "event state fix.tag_maps data-group names must be non-empty"
                        )
                    encoded[key] = item_text
                layer_values[field] = _tcl_dict_value(encoded)
            elif layer == "access2" and field == "proc":
                procedure = _require_string(value, "event state access2.proc")
                if "\x00" in procedure:
                    raise EmulatorInputError(
                        "event state access2.proc must not contain NUL bytes"
                    )
                if len(procedure.encode("utf-8")) > 4096:
                    raise EmulatorInputError(
                        "event state access2.proc exceeds 4096 UTF-8 bytes"
                    )
                layer_values[field] = procedure
            elif isinstance(value, bool):
                layer_values[field] = "1" if value else "0"
            elif isinstance(value, (str, int, float)):
                layer_values[field] = str(value)
            else:
                raise EmulatorInputError(
                    f"event state value {layer}.{field} must be a string or number"
                )
            if (
                layer in {"tls_client", "tls_server"}
                and field == "payload"
                and "\x00" in layer_values[field]
            ):
                raise EmulatorInputError("TLS payload must not contain NUL bytes")
        if layer == "sdp":
            state_bytes = sum(len(value.encode("utf-8")) for value in layer_values.values())
            if state_bytes > SDP_MAX_STATE_BYTES:
                raise EmulatorInputError(
                    f"event SDP state exceeds {SDP_MAX_STATE_BYTES} bytes"
                )
        if layer == "psc":
            state_bytes = sum(len(value.encode("utf-8")) for value in layer_values.values())
            if state_bytes > PSC_MAX_STATE_BYTES:
                raise EmulatorInputError(
                    f"event PSC state exceeds {PSC_MAX_STATE_BYTES} bytes"
                )
        normalised[layer] = layer_values
    supplied_version = normalised.get("dhcp", {}).get("version")
    if supplied_version is not None and supplied_version not in {"4", "6"}:
        raise EmulatorInputError("event DHCP version must be 4 or 6")
    dhcp_family_layers = [layer for layer in ("dhcpv4", "dhcpv6") if layer in normalised]
    if len(dhcp_family_layers) > 1:
        raise EmulatorInputError("event state cannot contain both dhcpv4 and dhcpv6 layers")
    if dhcp_family_layers:
        inferred_version = "4" if dhcp_family_layers[0] == "dhcpv4" else "6"
        if supplied_version is not None and supplied_version != inferred_version:
            raise EmulatorInputError(
                f"event DHCP version {supplied_version!r} does not match {dhcp_family_layers[0]}"
            )
        normalised.setdefault("dhcp", {})["version"] = inferred_version
    if "tds" in normalised and event_name not in {"TDS_REQUEST", "TDS_RESPONSE"}:
        raise EmulatorInputError(
            "event state tds is only valid during TDS_REQUEST or TDS_RESPONSE"
        )
    if "ike" in normalised and event_name != "IKE_AUTH":
        raise EmulatorInputError("event state ike is only valid during IKE_AUTH")
    if "access2" in normalised and event_name != "ACCESS2_POLICY_EXPRESSION_EVAL":
        raise EmulatorInputError(
            "event state access2 is only valid during ACCESS2_POLICY_EXPRESSION_EVAL"
        )
    return event_name, normalised


PACKET_MAX_COUNT = 1000
STREAM_MAX_BYTES = 2 * 1024 * 1024
WEBSOCKET_MAX_FRAME_BYTES = STREAM_MAX_BYTES
MQTT_MAX_MESSAGE_BYTES = STREAM_MAX_BYTES
SIP_MAX_MESSAGE_BYTES = STREAM_MAX_BYTES
SDP_MAX_STATE_BYTES = 64 * 1024
SDP_MAX_LINE_BYTES = 4096
SDP_MAX_MEDIA = 128
SOCKS_MAX_MESSAGE_BYTES = 64 * 1024
PSC_MAX_STATE_BYTES = 64 * 1024
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
STARTTLS_PROTOCOLS = frozenset({"imap", "pop3", "ldap", "smtps"})
STARTTLS_PACKET_TYPES = frozenset({"command", "response", "data"})
STARTTLS_COMMAND_MAX_BYTES = 64 * 1024
STARTTLS_PAYLOAD_MAX_BYTES = 2 * 1024 * 1024
QOE_PACKET_FIELDS = frozenset(
    {
        "width",
        "height",
        "duration",
        "available",
        "framerate",
        "nominal_bitrate",
        "average_bitrate",
        "mos",
    }
)
PROTOCOL_INSPECTION_ID_MAX_BYTES = 4 * 1024
PROTOCOL_INSPECTION_IDS_MAX_BYTES = 64 * 1024
STREAM_EXPRESSION_MAX_BYTES = 64 * 1024
STREAM_MAX_EXPRESSION_PAIRS = 128
CATEGORY_RESULT_MAX_ITEMS = 128
CATEGORY_RESULT_MAX_BYTES = 64 * 1024
PACKET_PROTOCOLS = {"event", "tcp", "udp", "sctp", "dhcpv4", "dhcpv6", "ftp", "icap", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category", "tls", "http", "http2", "dns", "websocket", "mqtt", "sip", "socks", "diameter", "radius", "mr", "gtp", "rtsp", "tds", "qoe", "l7check", "fix", "wire"}
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
    "hops",
    "ttl",
    "tos",
    "datagram",
}
PACKET_PROTOCOL_FIELDS = {
    "event": {
        "event",
        "state",
    },
    "tcp": {
        "payload_hex",
    },
    "udp": set(),
    "sctp": {
        "payload_hex",
        "ppi",
        "mss",
        "rto_initial",
        "rto_max",
        "rto_min",
        "sack_timeout",
    },
    "dhcpv4": {
        "payload_hex",
        "options",
        "chaddr",
        "ciaddr",
        "giaddr",
        "hlen",
        "hops",
        "htype",
        "len",
        "opcode",
        "reject",
        "secs",
        "siaddr",
        "type",
        "xid",
        "yiaddr",
    },
    "dhcpv6": {
        "payload_hex",
        "options",
        "hop_count",
        "len",
        "link_address",
        "msg_type",
        "peer_address",
        "reject",
        "transaction_id",
    },
    "ftp": {
        "payload_hex",
        "type",
        "command",
        "response_code",
        "tls_active",
        "tls_session_reused",
    },
    "tds": {
        "payload_hex",
        "type",
        "length",
        "procid",
        "procname",
        "sqltext",
        "xacttype",
        "xactid",
        "is_read",
        "request_type",
        "username",
        "dbname",
        "loginoption",
        "version",
    },
    "qoe": {
        "qoe",
    },
    "l7check": {
        "payload_hex",
        "l7_protocol",
    },
    "fix": {
        "fix",
        "payload_hex",
    },
    "icap": {
        "payload_hex",
        "type",
        "method",
        "uri",
        "status",
        "headers",
    },
    "imap": {
        "payload_hex",
        "type",
        "command",
        "tls_active",
    },
    "pop3": {
        "payload_hex",
        "type",
        "command",
        "tls_active",
    },
    "ldap": {
        "payload_hex",
        "type",
        "command",
        "tls_active",
    },
    "smtps": {
        "payload_hex",
        "type",
        "command",
        "tls_active",
    },
    "ntlm": {
        "payload_hex",
        "eca",
        "eca_result",
    },
    "protocol_inspection": {
        "payload_hex",
        "ids",
        "matched",
    },
    "classification": {
        "payload_hex",
        "app",
        "category",
        "classification_protocol",
        "detected",
        "deferred",
        "result",
        "urlcat",
        "username",
    },
    "category": {
        "payload_hex",
        "categories",
        "detected",
        "filetype",
        "lookup",
        "matchtype",
        "matched",
        "safesearch",
        "url",
    },
    "tls": {"type"}
    | (EVENT_STATE_FIELDS["tls_client"] | EVENT_STATE_FIELDS["tls_server"])
    - {"handshake_done"},
    "http": {
        "method",
        "uri",
        "host",
        "headers",
        "body",
        "http_class",
        "lb_failure",
        "persist_down",
        "lb_queue",
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
        "tsig_present",
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
        "username_flag",
        "password_flag",
        "will_topic",
        "will_message",
        "will_qos",
        "will_retain",
        "will_flag",
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
    "socks": {
        "payload_hex",
        "version",
        "allowed",
        "destination_host",
        "destination_port",
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
    "rtsp": {
        "type",
        "method",
        "uri",
        "version",
        "status",
        "phrase",
        "headers",
        "response_headers",
        "body",
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
    "CLIENT_ACCEPTED": "connection start (TCP or generic UDP)",
    "CLIENT_CLOSED": "tcp FIN/RST from client",
    "SERVER_CLOSED": "tcp FIN/RST from server",
    "SERVER_INIT": "first server-side flow initialization",
    "CLIENT_DATA": "client payload (TCP or generic UDP)",
    "ECA_REQUEST_ALLOWED": "injected NTLM/ECA authentication success",
    "ECA_REQUEST_DENIED": "injected NTLM/ECA authentication failure",
    "PROTOCOL_INSPECTION_MATCH": "protocol inspection match packet",
    "FIX_MESSAGE": "structured FIX message event",
    "SERVER_DATA": "server payload (TCP or generic UDP)",
    "TDS_REQUEST": "structured TDS request message",
    "TDS_RESPONSE": "structured TDS response message",
    "L7CHECK_CLIENT_DATA": "L7 check client ingress data",
    "L7CHECK_SERVER_DATA": "L7 check server ingress data",
    "FIX_HEADER": "structured FIX header event",
    "CLIENTSSL_CLIENTHELLO": "TLS client hello",
    "CLIENTSSL_CLIENTCERT": "TLS client certificate",
    "CLIENTSSL_HANDSHAKE": "TLS client handshake",
    "CLIENTSSL_DATA": "TLS client data",
    "CLIENTSSL_PASSTHROUGH": "TLS client plaintext passthrough",
    "CLIENTSSL_SERVERHELLO_SEND": "TLS client-side server hello send",
    "SERVERSSL_CLIENTHELLO_SEND": "TLS server-side client hello send",
    "SERVERSSL_SERVERHELLO": "TLS server hello",
    "SERVERSSL_SERVERCERT": "TLS server certificate",
    "SERVERSSL_HANDSHAKE": "TLS server handshake",
    "SERVERSSL_DATA": "TLS server data",
    "FLOW_INIT": "FLOW profile connection initialization",
    "HTTP_REQUEST": "HTTP request transaction",
    "HTTP_CLASS_SELECTED": "supplied HTTP class selection outcome",
    "HTTP_CLASS_FAILED": "supplied HTTP class selection failure",
    "HTTP_DISABLED": "HTTP::disable control outcome",
    "HTTP_PROXY_REQUEST": "explicit HTTP proxy request ingress",
    "HTTP_PROXY_CONNECT": "proxy chaining CONNECT request",
    "HTTP_PROXY_RESPONSE": "proxy chaining CONNECT response",
    "HTTP_REJECT": "rule-caused HTTP abort",
    "HTTP_REQUEST_DATA": "collected HTTP request body",
    "HTTP_REQUEST_SEND": "HTTP request serverside send",
    "HTTP_REQUEST_RELEASE": "HTTP request transaction release phase",
    "HTTP_RESPONSE": "HTTP response transaction",
    "HTTP_RESPONSE_DATA": "collected HTTP response body",
    "HTTP_RESPONSE_CONTINUE": "raw HTTP 100 Continue response",
    "HTTP_RESPONSE_RELEASE": "HTTP response transaction release phase",
    "HTML_TAG_MATCHED": "HTML response tag matching",
    "HTML_COMMENT_MATCHED": "HTML response comment matching",
    "REWRITE_REQUEST": "HTTP request rewrite phase",
    "REWRITE_RESPONSE": "HTTP response rewrite phase",
    "REWRITE_REQUEST_DONE": "HTTP request rewrite completion",
    "REWRITE_RESPONSE_DONE": "HTTP response rewrite completion",
    "STREAM_MATCHED": "TCP stream expression match",
    "PERSIST_DOWN": "scenario-supplied persisted member marked down",
    "LB_SELECTED": "HTTP pool-member selection",
    "LB_QUEUED": "scenario-supplied connection-limit queue",
    "LB_FAILED": "scenario-supplied load-balancer failure",
    "SA_PICKED": "source-address translation selection",
    "SERVER_CONNECTED": "server-side connection establishment",
    "CATEGORY_MATCHED": "supplied URL categorization match",
    "CLASSIFICATION_DETECTED": "supplied flow classification result",
    "DNS_REQUEST": "DNS request packet",
    "DNS_RESPONSE": "DNS response packet",
    "CONNECTOR_OPEN": "structured connector event",
    "TAP_REQUEST": "structured TAP security-token event",
    "PEM_POLICY": "structured PEM policy event",
    "PEM_SUBS_SESS_CREATED": "structured PEM subscriber-session creation event",
    "PEM_SUBS_SESS_UPDATED": "structured PEM subscriber-session update event",
    "PEM_SUBS_SESS_DELETED": "structured PEM subscriber-session deletion event",
    "ICAP_REQUEST": "ICAP request before adaptation-server send",
    "ICAP_RESPONSE": "ICAP response before adaptation result delivery",
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
    "MQTT_CLIENT_EGRESS": "MQTT message sent to client",
    "MQTT_SERVER_INGRESS": "MQTT message received from server",
    "MQTT_SERVER_DATA": "collected MQTT server PUBLISH payload",
    "MQTT_SERVER_EGRESS": "MQTT message sent to server",
    "MQTT_CLIENT_SHUTDOWN": "MQTT client TCP shutdown",
    "SIP_REQUEST": "SIP client request ingress",
    "SIP_REQUEST_DONE": "SIP request routing completion",
    "SIP_REQUEST_SEND": "SIP request server-side send",
    "SIP_RESPONSE": "SIP server response ingress",
    "SIP_RESPONSE_DONE": "SIP response routing completion",
    "SIP_RESPONSE_SEND": "SIP response client-side send",
    "SOCKS_REQUEST": "SOCKS4/SOCKS5 request packet",
    "RTSP_REQUEST": "RTSP request ingress",
    "RTSP_REQUEST_DATA": "collected RTSP request payload",
    "RTSP_RESPONSE": "RTSP response ingress",
    "RTSP_RESPONSE_DATA": "collected RTSP response payload",
    "QOE_PARSE_DONE": "supplied video-header parse completion",
    "CACHE_REQUEST": "cache lookup request",
    "CACHE_RESPONSE": "cached response delivery",
    "CACHE_UPDATE": "cache object update",
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


def _socks_host_from_bytes(value: bytes) -> str:
    try:
        host = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EmulatorInputError("SOCKS domain name must be valid UTF-8") from exc
    if not host or any(char in host for char in "\x00\r\n"):
        raise EmulatorInputError("SOCKS domain name is invalid")
    return host


def _parse_socks_request(payload: bytes) -> dict[str, Any]:
    """Decode one bounded SOCKS4/SOCKS5 request message."""
    if not payload:
        raise EmulatorInputError("SOCKS request payload must not be empty")
    if len(payload) > SOCKS_MAX_MESSAGE_BYTES:
        raise EmulatorInputError(
            f"SOCKS request exceeds {SOCKS_MAX_MESSAGE_BYTES} bytes"
        )
    version = payload[0]
    if version == 5:
        if len(payload) < 4 or payload[2] != 0:
            raise EmulatorInputError("SOCKS5 request header is invalid")
        command = {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}.get(
            payload[1], f"0x{payload[1]:02x}"
        )
        address_type = payload[3]
        cursor = 4
        if address_type == 1:
            end = cursor + 4
            if len(payload) < end:
                raise EmulatorInputError("SOCKS5 IPv4 destination is incomplete")
            host = str(ipaddress.ip_address(payload[cursor:end]))
            cursor = end
        elif address_type == 3:
            if len(payload) <= cursor:
                raise EmulatorInputError("SOCKS5 domain destination is incomplete")
            domain_length = payload[cursor]
            cursor += 1
            end = cursor + domain_length
            if domain_length == 0 or len(payload) < end:
                raise EmulatorInputError("SOCKS5 domain destination is incomplete")
            host = _socks_host_from_bytes(payload[cursor:end])
            cursor = end
        elif address_type == 4:
            end = cursor + 16
            if len(payload) < end:
                raise EmulatorInputError("SOCKS5 IPv6 destination is incomplete")
            host = str(ipaddress.ip_address(payload[cursor:end]))
            cursor = end
        else:
            raise EmulatorInputError(
                f"unsupported SOCKS5 address type {address_type}"
            )
        if len(payload) < cursor + 2:
            raise EmulatorInputError("SOCKS5 destination port is incomplete")
        port = int.from_bytes(payload[cursor : cursor + 2], "big")
        return {
            "version": "5",
            "destination_host": host,
            "destination_port": port,
            "_socks_command": command,
            "_socks_address_type": address_type,
        }

    if version == 4:
        if len(payload) < 9:
            raise EmulatorInputError("SOCKS4 request header is incomplete")
        command = {1: "CONNECT", 2: "BIND"}.get(
            payload[1], f"0x{payload[1]:02x}"
        )
        port = int.from_bytes(payload[2:4], "big")
        address = payload[4:8]
        user_end = payload.find(b"\x00", 8)
        if user_end < 0:
            raise EmulatorInputError("SOCKS4 user ID is not terminated")
        if address[:3] == b"\x00\x00\x00" and address[3] != 0:
            domain_start = user_end + 1
            domain_end = payload.find(b"\x00", domain_start)
            if domain_end < 0:
                raise EmulatorInputError("SOCKS4a domain name is not terminated")
            host = _socks_host_from_bytes(payload[domain_start:domain_end])
            address_type = 3
        else:
            host = str(ipaddress.ip_address(address))
            address_type = 1
        return {
            "version": "4",
            "destination_host": host,
            "destination_port": port,
            "_socks_command": command,
            "_socks_address_type": address_type,
        }

    raise EmulatorInputError(f"unsupported SOCKS version {version}")


def _stream_expression_pairs(expression: str) -> list[tuple[str, str]]:
    """Parse the bounded ``@match@replacement@`` stream-profile form."""
    if not expression or len(expression.encode("utf-8")) > STREAM_EXPRESSION_MAX_BYTES:
        return []
    delimiter = expression[0]
    if delimiter.isalnum() or delimiter.isspace():
        return []
    pairs: list[tuple[str, str]] = []
    cursor = 1
    while cursor < len(expression):
        match_end = expression.find(delimiter, cursor)
        if match_end < 0:
            return []
        replacement_end = expression.find(delimiter, match_end + 1)
        if replacement_end < 0:
            return []
        match = expression[cursor:match_end]
        replacement = expression[match_end + 1 : replacement_end]
        if match:
            pairs.append((match, replacement))
            if len(pairs) > STREAM_MAX_EXPRESSION_PAIRS:
                return []
        cursor = replacement_end + 1
        while cursor < len(expression) and expression[cursor].isspace():
            cursor += 1
        if cursor < len(expression):
            if expression[cursor] != delimiter:
                return []
            cursor += 1
    return pairs


def _stream_value_bytes(value: str, encoding: str) -> bytes | None:
    codec = "ascii" if encoding == "ascii" else "utf-8"
    try:
        return value.encode(codec)
    except UnicodeEncodeError:
        return None


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
            "ttl": raw[8],
            "tos": raw[1],
            "flags": flag_names,
            "seq": int.from_bytes(payload[4:8], "big"),
            "ack": int.from_bytes(payload[8:12], "big"),
            "source": {"address": source_address, "port": int.from_bytes(payload[0:2], "big")},
            "destination": {"address": destination_address, "port": int.from_bytes(payload[2:4], "big")},
            "_wire_length": total_length,
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
            "ttl": raw[8],
            "tos": raw[1],
            "source": {"address": source_address, "port": int.from_bytes(payload[0:2], "big")},
            "destination": {"address": destination_address, "port": int.from_bytes(payload[2:4], "big")},
            "_wire_length": total_length,
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
            "unsupported capture format; classic PCAP or pcapng is required"
        ) from exc


PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
PCAPNG_SECTION = 0x0A0D0D0A
PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
PCAPNG_SIMPLE_PACKET = 0x00000003
PCAPNG_ENHANCED_PACKET = 0x00000006
PCAPNG_MAX_INTERFACES = 256
PCAPNG_MAX_TIMESTAMP_SCALE = 1 << 63


def _pcapng_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    if not data:
        return options
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise EmulatorInputError("pcapng interface options are incomplete")
        option_code, option_length = struct.unpack(
            endian + "HH", data[offset : offset + 4]
        )
        offset += 4
        if option_code == 0:
            if option_length:
                raise EmulatorInputError("pcapng end-of-options has a nonzero length")
            if offset != len(data):
                raise EmulatorInputError("pcapng interface options contain trailing bytes")
            return options
        padded_length = (option_length + 3) & ~3
        if offset + padded_length > len(data):
            raise EmulatorInputError("pcapng interface option exceeds its block")
        options.setdefault(option_code, []).append(data[offset : offset + option_length])
        offset += padded_length
    raise EmulatorInputError("pcapng interface options have no end marker")


def _pcapng_block(
    data: bytes, offset: int, endian: str
) -> tuple[int, bytes, int]:
    if len(data) - offset < 12:
        raise EmulatorInputError("pcapng block header is incomplete")
    block_type, block_length = struct.unpack(
        endian + "II", data[offset : offset + 8]
    )
    if block_length < 12 or block_length % 4:
        raise EmulatorInputError("pcapng block has an invalid length")
    if block_length > len(data) - offset:
        raise EmulatorInputError("pcapng block length exceeds the capture")
    (trailing_length,) = struct.unpack(
        endian + "I", data[offset + block_length - 4 : offset + block_length]
    )
    if trailing_length != block_length:
        raise EmulatorInputError("pcapng block length trailer does not match")
    body = data[offset + 8 : offset + block_length - 4]
    return block_type, body, offset + block_length


def _pcapng_timestamp_resolution(options: dict[int, list[bytes]]) -> float:
    values = options.get(9, [])  # if_tsresol
    if not values:
        return 1_000_000.0
    if len(values) != 1 or len(values[0]) != 1:
        raise EmulatorInputError("pcapng if_tsresol must be one byte")
    value = values[0][0]
    scale = 2**(value & 0x7F) if value & 0x80 else 10**value
    if scale > PCAPNG_MAX_TIMESTAMP_SCALE:
        raise EmulatorInputError("pcapng if_tsresol is outside the supported range")
    return float(scale)


def _pcapng_packets(
    data: bytes,
    *,
    direction: str,
    client_addr: str | None,
    server_addr: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if len(data) < 12 or data[:4] != PCAPNG_SECTION_HEADER:
        raise EmulatorInputError("pcapng section header is incomplete")
    for field, value in (
        ("pcap client_addr", client_addr),
        ("pcap server_addr", server_addr),
    ):
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
    interfaces: list[tuple[int, int, float]] = []
    all_interfaces: list[tuple[int, int, float]] = []
    offset = 0
    endian: str | None = None
    block_count = 0
    record_count = 0
    section_count = 0
    section_end: int | None = None
    skipped_non_ipv4 = 0
    skipped_unmatched = 0
    while offset < len(data):
        if data[offset : offset + 4] == PCAPNG_SECTION_HEADER:
            if len(data) - offset < 28:
                raise EmulatorInputError("pcapng section header is incomplete")
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise EmulatorInputError("pcapng section has an invalid byte-order magic")
            block_type, body, next_offset = _pcapng_block(data, offset, endian)
            if block_type != PCAPNG_SECTION:
                raise EmulatorInputError("pcapng section header block is invalid")
            if len(body) < 16:
                raise EmulatorInputError("pcapng section header body is incomplete")
            major, minor = struct.unpack(endian + "HH", body[4:8])
            if (major, minor) != (1, 0):
                raise EmulatorInputError(
                    f"unsupported pcapng version {major}.{minor}"
                )
            (declared_length,) = struct.unpack(endian + "q", body[8:16])
            if declared_length != -1:
                if declared_length < 28 or declared_length % 4:
                    raise EmulatorInputError("pcapng section has an invalid length")
                section_end = offset + declared_length
                if section_end > len(data):
                    raise EmulatorInputError("pcapng section length exceeds the capture")
            else:
                section_end = None
            section_count += 1
            interfaces = []
            block_count += 1
            offset = next_offset
            continue
        if endian is None:
            raise EmulatorInputError("pcapng must begin with a section header")
        if section_end is not None and offset == section_end:
            raise EmulatorInputError("pcapng section must be followed by a section header")
        block_type, body, next_offset = _pcapng_block(data, offset, endian)
        if section_end is not None and next_offset > section_end:
            raise EmulatorInputError("pcapng block exceeds its section")
        block_count += 1
        frame: bytes | None = None
        if block_type == PCAPNG_INTERFACE_DESCRIPTION:
            if len(body) < 8:
                raise EmulatorInputError("pcapng interface description is incomplete")
            linktype, reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            if reserved != 0:
                raise EmulatorInputError("pcapng interface reserved field is nonzero")
            if snaplen < 1 or snaplen > PCAP_MAX_PACKET_BYTES:
                raise EmulatorInputError(
                    "pcapng interface snaplen is outside the supported packet-size limit"
                )
            options = _pcapng_options(body[8:], endian)
            interface = (linktype, snaplen, _pcapng_timestamp_resolution(options))
            if len(interfaces) >= PCAPNG_MAX_INTERFACES:
                raise EmulatorInputError(
                    f"pcapng cannot contain more than {PCAPNG_MAX_INTERFACES} interfaces"
                )
            interfaces.append(interface)
            all_interfaces.append(interface)
        elif block_type == PCAPNG_ENHANCED_PACKET:
            if len(body) < 20:
                raise EmulatorInputError("pcapng enhanced packet block is incomplete")
            interface_id, ts_high, ts_low, included_length, original_length = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if interface_id >= len(interfaces):
                raise EmulatorInputError("pcapng packet references an unknown interface")
            linktype, snaplen, timestamp_scale = interfaces[interface_id]
            if included_length > snaplen or included_length > PCAP_MAX_PACKET_BYTES:
                raise EmulatorInputError("pcapng packet exceeds the packet-size limit")
            if original_length < included_length:
                raise EmulatorInputError("pcapng packet has invalid captured length")
            padded_length = (included_length + 3) & ~3
            if 20 + padded_length > len(body):
                raise EmulatorInputError("pcapng packet payload is incomplete")
            frame = body[20 : 20 + included_length]
            timestamp = ((ts_high << 32) | ts_low) / timestamp_scale
            record_count += 1
            if record_count > PACKET_MAX_COUNT:
                raise EmulatorInputError(
                    f"pcapng cannot contain more than {PACKET_MAX_COUNT} records"
                )
        elif block_type == PCAPNG_SIMPLE_PACKET:
            if len(body) < 4 or not interfaces:
                raise EmulatorInputError("pcapng simple packet lacks an interface")
            original_length = int.from_bytes(body[:4], endian)
            linktype, snaplen, _timestamp_scale = interfaces[0]
            included_length = min(original_length, snaplen, len(body) - 4)
            if included_length > PCAP_MAX_PACKET_BYTES:
                raise EmulatorInputError("pcapng simple packet exceeds the packet-size limit")
            expected_length = min(original_length, snaplen)
            if len(body) - 4 < expected_length:
                raise EmulatorInputError("pcapng simple packet payload is incomplete")
            frame = body[4 : 4 + included_length]
            timestamp = 0.0
            record_count += 1
            if record_count > PACKET_MAX_COUNT:
                raise EmulatorInputError(
                    f"pcapng cannot contain more than {PACKET_MAX_COUNT} records"
                )
        else:
            offset = next_offset
            continue
        offset = next_offset
        if frame is None:
            continue
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
                "timestamp": timestamp,
            }
        )
    if not packets:
        raise EmulatorInputError("pcapng contained no usable IPv4 packets")
    resolutions = {scale for _linktype, _snaplen, scale in all_interfaces}
    if len(resolutions) == 1:
        scale = next(iter(resolutions))
        if scale == 1_000_000.0:
            timestamp_resolution = "microseconds"
        elif scale == 1_000_000_000.0:
            timestamp_resolution = "nanoseconds"
        else:
            timestamp_resolution = "custom"
    else:
        timestamp_resolution = "mixed"
    linktypes = sorted({linktype for linktype, _snaplen, _scale in all_interfaces})
    return packets, {
        "format": "pcapng",
        "version": "1.0",
        "linktype": linktypes[0] if len(linktypes) == 1 else linktypes,
        "interface_count": len(all_interfaces),
        "timestamp_resolution": timestamp_resolution,
        "record_count": record_count,
        "block_count": block_count,
        "section_count": section_count,
        "ipv4_packet_count": len(packets),
        "skipped_non_ipv4": skipped_non_ipv4,
        "skipped_unmatched": skipped_unmatched,
        "direction": direction,
    }


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
    if data[:4] == PCAPNG_SECTION_HEADER:
        return _pcapng_packets(
            data,
            direction=direction,
            client_addr=client_addr,
            server_addr=server_addr,
        )
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
        address = _require_string(raw["address"], f"packet {prefix} address")
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            # Preserve non-IP endpoint labels for existing structured tests;
            # IP-specific lookups still validate addresses at command use.
            pass
        result["address"] = address
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


def _normalise_qoe_packet(value: Any, field: str) -> dict[str, str]:
    """Validate a supplied video-header parse result for QOE_PARSE_DONE."""
    if not isinstance(value, dict):
        raise EmulatorInputError(f"{field} must be an object")
    unknown = sorted(set(value) - QOE_PACKET_FIELDS)
    if unknown:
        raise EmulatorInputError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )
    if not value:
        raise EmulatorInputError(f"{field} requires at least one video measurement")
    result = {name: "0" for name in QOE_PACKET_FIELDS}
    for name, raw in value.items():
        if name == "available":
            result[name] = _packet_bool(raw, f"{field}.{name}")
            continue
        if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
            raise EmulatorInputError(
                f"{field}.{name} must be a string or number"
            )
        if isinstance(raw, float) and not math.isfinite(raw):
            raise EmulatorInputError(f"{field}.{name} must be finite")
        text = str(raw)
        if "\x00" in text:
            raise EmulatorInputError(f"{field}.{name} must not contain NUL bytes")
        if len(text.encode("utf-8")) > 256:
            raise EmulatorInputError(f"{field}.{name} exceeds 256 bytes")
        result[name] = text
    result.setdefault("available", "1")
    if "available" not in value:
        result["available"] = "1"
    return result


def _dhcp_options_tcl(options: dict[str, str]) -> str:
    flattened: list[str] = []
    for option_id in sorted(options, key=lambda item: (len(item), item)):
        flattened.extend((option_id, options[option_id]))
    # The result is installed as one Tcl scalar and later consumed by
    # ``dict``.  Do not wrap it in braces: braces would make the inner quotes
    # literal and turn the complete dictionary into one malformed key.
    return " ".join(
        value if re.fullmatch(r"[A-Za-z0-9_./:+-]+", value) else _tcl_quote(value)
        for value in flattened
    )


def _packet_bool(value: Any, field: str) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int) and value in {0, 1}:
        return str(value)
    if isinstance(value, str) and value.lower() in {"0", "1", "false", "true"}:
        return "1" if value.lower() in {"1", "true"} else "0"
    raise EmulatorInputError(f"{field} must be a boolean or 0/1")


DATAGRAM_METADATA_FIELDS = frozenset(
    {
        "ip_version",
        "ip_tos",
        "ip_ttl",
        "ip_flags",
        "ip_options",
        "ip6_hop_limit",
        "ip6_options",
        "l2_dest",
        "tcp_flags",
        "tcp_window",
        "tcp_options",
        "dns_id",
        "dns_qr",
        "dns_opcode",
        "dns_qdcount",
        "dns_ancount",
        "dns_nscount",
        "dns_arcount",
    }
)
DATAGRAM_OPTION_FIELDS = frozenset({"ip_options", "ip6_options", "tcp_options"})
DATAGRAM_INTEGER_RANGES = {
    "ip_tos": (0, 255),
    "ip_ttl": (0, 255),
    "ip_flags": (0, 7),
    "ip6_hop_limit": (0, 255),
    "tcp_flags": (0, 65535),
    "tcp_window": (0, 65535),
    "dns_id": (0, 65535),
    "dns_qdcount": (0, 65535),
    "dns_ancount": (0, 65535),
    "dns_nscount": (0, 65535),
    "dns_arcount": (0, 65535),
}


def _normalise_datagram_options(value: Any, field: str) -> list[list[str]]:
    if not isinstance(value, list):
        raise EmulatorInputError(f"packet datagram {field} must be an array")
    options: list[list[str]] = []
    for index, option in enumerate(value):
        if not isinstance(option, list) or len(option) not in {1, 2}:
            raise EmulatorInputError(
                f"packet datagram {field}[{index}] must be [code] or [code, value]"
            )
        code = option[0]
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
            raise EmulatorInputError(
                f"packet datagram {field}[{index}] code must be an integer from 0 to 255"
            )
        normalised = [str(code)]
        if len(option) == 2:
            item = _require_string(option[1], f"packet datagram {field}[{index}] value")
            if "\x00" in item:
                raise EmulatorInputError(
                    f"packet datagram {field}[{index}] value must not contain NUL bytes"
                )
            normalised.append(item)
        options.append(normalised)
    return options


def _normalise_datagram_metadata(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EmulatorInputError(f"{field} must be an object")
    unknown = sorted(set(value) - DATAGRAM_METADATA_FIELDS)
    if unknown:
        raise EmulatorInputError(
            f"{field} contains unsupported field(s): {', '.join(unknown)}"
        )
    result: dict[str, Any] = {}
    for name, raw in value.items():
        if name in DATAGRAM_OPTION_FIELDS:
            result[name] = _normalise_datagram_options(raw, name)
            continue
        if name == "ip_version":
            if isinstance(raw, bool) or not isinstance(raw, int) or raw not in {4, 6}:
                raise EmulatorInputError(f"{field}.ip_version must be 4 or 6")
            result[name] = raw
            continue
        if name in DATAGRAM_INTEGER_RANGES:
            low, high = DATAGRAM_INTEGER_RANGES[name]
            if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
                raise EmulatorInputError(
                    f"{field}.{name} must be an integer from {low} to {high}"
                )
            result[name] = raw
            continue
        if name == "dns_qr":
            result[name] = _packet_bool(raw, f"{field}.dns_qr")
            continue
        if name in {"dns_opcode", "l2_dest"}:
            item = _require_string(raw, f"{field}.{name}")
            if "\x00" in item:
                raise EmulatorInputError(f"{field}.{name} must not contain NUL bytes")
            result[name] = item
            continue
    return result


def _datagram_options_tcl(options: list[list[str]]) -> str:
    return " ".join(
        "{" + " ".join(_tcl_quote(item) for item in option) + "}"
        for option in options
    )


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
                "will_flag": will_flag,
                "username_flag": bool(connect_flags & 0x80),
                "password_flag": bool(connect_flags & 0x40),
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


def _mqtt_topic_list_from_state(value: Any) -> list[list[Any]]:
    """Convert either JSON or Tcl-list MQTT topic-list state to wire fields."""
    if isinstance(value, list):
        raw: Any = value
    elif isinstance(value, str):
        try:
            raw = json.loads(value)
        except json.JSONDecodeError:
            entries = _split_tcl_list(value)
            raw = []
            for entry in entries:
                fields = _split_tcl_list(entry)
                if fields:
                    raw.append(fields)
    else:
        raw = []
    if not isinstance(raw, list):
        raise EmulatorInputError("MQTT topic_list state must be an array or Tcl list")
    result: list[list[Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, (list, tuple)) or not item or not isinstance(item[0], str):
            raise EmulatorInputError(f"MQTT topic_list entry {index} is invalid")
        if len(item) > 2:
            raise EmulatorInputError(f"MQTT topic_list entry {index} has too many fields")
        result.append(list(item))
    return result


def _mqtt_packet_from_state(state: dict[str, Any]) -> dict[str, Any]:
    """Build an encoder packet from the post-handler Tcl MQTT snapshot."""
    packet = {
        field: value
        for field, value in state.items()
        if field not in {"message", "message_length", "payload_length", "topic_list"}
    }
    packet["payload"] = state.get("payload", "")
    if "topic_list" in state:
        packet["topic_list"] = _mqtt_topic_list_from_state(state["topic_list"])
    return packet


def _mqtt_tcl_dict(value: Any, field: str) -> dict[str, Any]:
    parts = _split_tcl_list(value)
    if len(parts) % 2:
        raise EmulatorInputError(f"MQTT {field} state is not a key/value list")
    return dict(zip(parts[::2], parts[1::2]))


def _mqtt_public_packet(packet: dict[str, Any]) -> dict[str, Any]:
    public = dict(packet)
    payload = public.get("payload")
    if isinstance(payload, (bytes, bytearray)):
        public["payload"] = _decode_wire_text(bytes(payload))
    if "topic_list" in public:
        public["topic_list"] = _mqtt_topic_list_from_state(public["topic_list"])
    return public


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
        has_will = _mqtt_flag(
            packet,
            "will_flag",
            "will_topic" in packet or "will_message" in packet,
        )
        will_qos = _mqtt_int(packet, "will_qos", 0)
        if will_qos > 2:
            raise EmulatorInputError("MQTT will_qos must be 0, 1, or 2")
        connect_flags = (_mqtt_flag(packet, "clean_session", True) << 1)
        if has_will:
            connect_flags |= 0x04 | (will_qos << 3) | (_mqtt_flag(packet, "will_retain") << 5)
        has_username = _mqtt_flag(
            packet, "username_flag", "username" in packet
        )
        has_password = _mqtt_flag(
            packet, "password_flag", "password" in packet
        )
        if has_password and not has_username:
            raise EmulatorInputError("MQTT CONNECT password requires username")
        if has_password:
            connect_flags |= 0x40
        if has_username:
            connect_flags |= 0x80
        body.append(connect_flags)
        body += _mqtt_int(packet, "keep_alive", 60).to_bytes(2, "big")
        body += _mqtt_encode_utf8(packet.get("client_id", ""), "client_id")
        if has_will:
            body += _mqtt_encode_utf8(will_topic, "will_topic")
            body += _mqtt_encode_utf8(will_message, "will_message")
        if has_username:
            body += _mqtt_encode_utf8(packet["username"], "username")
        if has_password:
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


def _sdp_content_type(headers: list[list[str]]) -> bool:
    """Return whether SIP headers identify an application/sdp body."""
    return any(
        _sip_header_matches(name, "Content-Type")
        and value.split(";", 1)[0].strip().lower() == "application/sdp"
        for name, value in headers
    )


def _sdp_origin_session_id(fields: list[tuple[str, str]]) -> str:
    for name, value in fields:
        if name.lower() != "o":
            continue
        parts = value.split()
        if len(parts) >= 2:
            return parts[1]
    return ""


def _parse_sdp_payload(
    payload: bytes, headers: list[list[str]]
) -> dict[str, Any] | None:
    """Parse the bounded SDP subset exposed by the existing SDP Tcl commands.

    Invalid or unsupported SDP bodies are deliberately treated as opaque SIP
    payloads.  This keeps packet replay useful for non-SDP content and avoids
    turning a malformed application body into an emulator crash.
    """
    if not _sdp_content_type(headers) or not payload:
        return None
    if len(payload) > SDP_MAX_STATE_BYTES:
        return None
    try:
        body = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in body:
        return None

    if "\r" in body:
        if "\r\n" not in body or "\r" in body.replace("\r\n", ""):
            return None
        separator = "\r\n"
        if "\n" in body.replace("\r\n", ""):
            return None
    elif "\n" in body:
        separator = "\n"
    else:
        separator = "\r\n"
    raw_lines = body.split(separator)
    trailing_separator = bool(raw_lines and raw_lines[-1] == "")
    if trailing_separator:
        raw_lines.pop()
    if not raw_lines or any(not line for line in raw_lines):
        return None

    parsed_lines: list[tuple[str, str]] = []
    for line in raw_lines:
        if len(line.encode("utf-8")) > SDP_MAX_LINE_BYTES:
            return None
        if len(line) < 2 or line[1] != "=" or not (
            "a" <= line[0] <= "z" or "A" <= line[0] <= "Z"
        ):
            return None
        parsed_lines.append((line[0], line[2:]))

    fields: list[tuple[str, str]] = []
    media: list[dict[str, Any]] = []
    media_blocks: list[dict[str, Any]] = []
    current_media: dict[str, Any] | None = None
    first_media_index = len(parsed_lines)
    for index, (name, value) in enumerate(parsed_lines):
        if name.lower() == "m":
            parts = value.split()
            if len(parts) < 4 or not re.fullmatch(r"[0-9]+(?:/[0-9]+)?", parts[1]):
                return None
            port_parts = parts[1].split("/")
            try:
                port = int(port_parts[0])
                count = int(port_parts[1]) if len(port_parts) == 2 else None
            except ValueError:
                return None
            if not 0 <= port <= 65535 or (
                count is not None and not 1 <= count <= 65535
            ):
                return None
            if len(media) >= SDP_MAX_MEDIA:
                return None
            if current_media is not None:
                current_media["end"] = index
            current_media = {
                "start": index,
                "end": len(parsed_lines),
                "m_name": name,
                "type": parts[0],
                "port": parts[1],
                "transport": parts[2],
                "formats": " ".join(parts[3:]),
                "conn": "",
                "attrs": [],
                "connection_indices": [],
                "attribute_indices": [],
            }
            media.append(current_media)
            media_blocks.append(current_media)
            if first_media_index == len(parsed_lines):
                first_media_index = index
        elif current_media is None:
            fields.append((name, value))
        elif name.lower() == "c":
            current_media["connection_indices"].append(index)
            if not current_media["conn"]:
                current_media["conn"] = value
        elif name.lower() == "a":
            current_media["attribute_indices"].append(index)
            current_media["attrs"].append(value)

    state_media = [
        {
            "type": item["type"],
            "port": item["port"],
            "transport": item["transport"],
            "conn": item["conn"],
            "attrs": list(item["attrs"]),
        }
        for item in media
    ]
    state = {
        "session_id": _sdp_origin_session_id(fields),
        "fields": list(fields),
        "media": state_media,
    }
    return {
        "original_body": payload,
        "separator": separator,
        "trailing_separator": trailing_separator,
        "lines": list(raw_lines),
        "session_indices": list(range(first_media_index)),
        "fields": list(fields),
        "media": media_blocks,
        "state": state,
    }


def _sdp_event_layer(state: dict[str, Any]) -> dict[str, str]:
    fields: list[str] = []
    for name, value in state["fields"]:
        fields.extend((str(name), str(value)))
    media_values: list[str] = []
    for media in state["media"]:
        flattened = [
            "type", str(media.get("type", "")),
            "port", str(media.get("port", "")),
            "transport", str(media.get("transport", "")),
            "conn", str(media.get("conn", "")),
            "attrs", _tcl_list_value([str(value) for value in media.get("attrs", [])]),
        ]
        media_values.append(_tcl_list_value(flattened))
    layer = {
        "session_id": str(state["session_id"]),
        "fields": _tcl_list_value(fields),
        "media": _tcl_list_value(media_values),
    }
    state_bytes = sum(len(value.encode("utf-8")) for value in layer.values())
    if state_bytes > SDP_MAX_STATE_BYTES:
        raise EmulatorInputError(
            f"event SDP state exceeds {SDP_MAX_STATE_BYTES} bytes"
        )
    return layer


def _install_sdp_state(session: Any, state: dict[str, Any]) -> None:
    for field, value in _sdp_event_layer(state).items():
        session.eval_tcl(
            f"set ::state::sdp::{field} {_tcl_quote(value)}"
        )


def _sdp_state_from_tcl(session: Any) -> dict[str, Any]:
    raw_fields = _split_tcl_list(session.eval_tcl("set ::state::sdp::fields"))
    if len(raw_fields) % 2:
        raise EmulatorInputError("invalid SDP field state")
    fields = [
        (raw_fields[index], raw_fields[index + 1])
        for index in range(0, len(raw_fields), 2)
    ]
    raw_media = _split_tcl_list(session.eval_tcl("set ::state::sdp::media"))
    media: list[dict[str, Any]] = []
    for raw_entry in raw_media:
        values = _split_tcl_list(raw_entry)
        if len(values) % 2:
            raise EmulatorInputError("invalid SDP media state")
        entry = dict(zip(values[::2], values[1::2]))
        attrs = _split_tcl_list(entry.get("attrs", ""))
        media.append(
            {
                "type": entry.get("type", ""),
                "port": entry.get("port", ""),
                "transport": entry.get("transport", ""),
                "conn": entry.get("conn", ""),
                "attrs": attrs,
            }
        )
    state = {
        "session_id": str(session.eval_tcl("set ::state::sdp::session_id")),
        "fields": fields,
        "media": media,
    }
    _sdp_event_layer(state)
    return state


def _sdp_safe_value(value: Any, field: str) -> str:
    text = str(value)
    if "\x00" in text or "\r" in text or "\n" in text:
        raise EmulatorInputError(f"invalid SDP {field} state")
    return text


def _sdp_serialize(template: dict[str, Any], state: dict[str, Any]) -> bytes:
    """Apply mutable supported SDP state while retaining unknown SDP lines."""
    if state == template["state"]:
        return bytes(template["original_body"])
    if len(state["fields"]) != len(template["state"]["fields"]):
        raise EmulatorInputError("SDP field count changed unexpectedly")
    if len(state["media"]) != len(template["state"]["media"]):
        raise EmulatorInputError("SDP media count changed unexpectedly")

    lines = template["lines"]
    session_lines = template["session_indices"]
    rendered: list[str] = []
    field_by_line = dict(zip(session_lines, state["fields"]))
    blocks_by_start = {block["start"]: (block, position) for position, block in enumerate(template["media"])}
    for index, line in enumerate(lines):
        if index in field_by_line:
            name, value = field_by_line[index]
            if len(name) != 1:
                raise EmulatorInputError("invalid SDP field state")
            rendered.append(f"{name}={_sdp_safe_value(value, 'field')}")
            continue
        block_info = blocks_by_start.get(index)
        if block_info is not None:
            block, media_index = block_info
            media_state = state["media"][media_index]
            media_type = _sdp_safe_value(media_state["type"], "media type")
            media_port = _sdp_safe_value(media_state["port"], "media port")
            media_transport = _sdp_safe_value(
                media_state["transport"], "media transport"
            )
            m_value = " ".join(
                (media_type, media_port, media_transport)
            )
            if block["formats"]:
                m_value += " " + block["formats"]
            rendered.append(f"{block['m_name']}={m_value}")
            media_conn = _sdp_safe_value(media_state["conn"], "media connection")
            if not block["connection_indices"] and media_conn:
                rendered.append(f"c={media_conn}")
            continue
        owner = next(
            (
                (block, media_index)
                for media_index, block in enumerate(template["media"])
                if block["start"] <= index < block["end"]
            ),
            None,
        )
        if owner is None:
            rendered.append(line)
            continue
        block, media_index = owner
        media_state = state["media"][media_index]
        connection_indices = block["connection_indices"]
        if index in connection_indices:
            if index == connection_indices[0]:
                rendered.append(
                    f"{line[0]}={_sdp_safe_value(media_state['conn'], 'media connection')}"
                )
            else:
                rendered.append(line)
            continue
        attribute_indices = block["attribute_indices"]
        if index in attribute_indices:
            attribute_position = attribute_indices.index(index)
            if attribute_position < len(media_state["attrs"]):
                rendered.append(
                    f"{line[0]}={_sdp_safe_value(media_state['attrs'][attribute_position], 'media attribute')}"
                )
            else:
                rendered.append(line)
            if index == block["end"] - 1 and len(media_state["attrs"]) > len(attribute_indices):
                rendered.extend(
                    f"a={_sdp_safe_value(value, 'media attribute')}"
                    for value in media_state["attrs"][len(attribute_indices):]
                )
            continue
        rendered.append(line)

    separator = template["separator"]
    body = separator.join(rendered)
    if template["trailing_separator"]:
        body += separator
    encoded = body.encode("utf-8")
    if len(encoded) > SDP_MAX_STATE_BYTES:
        raise EmulatorInputError(
            f"serialized SDP body exceeds {SDP_MAX_STATE_BYTES} bytes"
        )
    return encoded


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
        if protocol == "event":
            unknown_event_fields = sorted(set(packet) - {"protocol", "event", "state"})
            if unknown_event_fields:
                raise EmulatorInputError(
                    f"unsupported synthetic event packet field(s): {', '.join(unknown_event_fields)}"
                )
        direction = _packet_direction(packet.get("direction", "client_to_server"))
        wire_payload: bytes | None = None
        wire_length: int | None = None
        if protocol == "wire":
            packet = _decode_wire_packet(packet, index, direction)
            protocol = packet["protocol"]
            direction = packet["direction"]
            wire_payload = packet.pop("_wire_payload", None)
            wire_length = packet.pop("_wire_length", None)
        allowed = PACKET_COMMON_FIELDS | PACKET_PROTOCOL_FIELDS[protocol]
        unknown = sorted(set(packet) - allowed)
        if unknown:
            raise EmulatorInputError(
                f"unsupported packet {index} field(s): {', '.join(unknown)}"
            )
        if protocol in {"tcp", "sctp", "dhcpv4", "dhcpv6", "ftp", "icap", "tds", "socks", "l7check", "fix", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category"} and "payload" in packet and "payload_hex" in packet:
            raise EmulatorInputError(
                f"packet {index} {protocol.upper()} packets must use payload or payload_hex, not both"
            )

        normalised: dict[str, Any] = {
            "protocol": protocol,
            "direction": direction,
            "source": _packet_endpoint(packet.get("source"), "source", index),
            "destination": _packet_endpoint(packet.get("destination"), "destination", index),
        }
        if protocol == "event":
            event_name, event_state = _normalise_event(
                packet.get("event"), packet.get("state")
            )
            normalised["event"] = event_name
            normalised["state"] = event_state
            packets.append(normalised)
            continue
        if "datagram" in packet:
            normalised["datagram"] = _normalise_datagram_metadata(
                packet["datagram"], f"packet {index} datagram"
            )
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
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    pass
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
            if (
                protocol in STARTTLS_PROTOCOLS
                and len(normalised["payload"].encode("utf-8")) > STARTTLS_PAYLOAD_MAX_BYTES
            ):
                raise EmulatorInputError(
                    f"packet {index} {protocol.upper()} payload exceeds "
                    f"{STARTTLS_PAYLOAD_MAX_BYTES} bytes"
                )
            if protocol in {"l7check", "fix", "ntlm", "protocol_inspection", "classification", "category"} and len(
                normalised["payload"].encode("utf-8")
            ) > STREAM_MAX_BYTES:
                raise EmulatorInputError(
                    f"packet {index} {protocol.upper()} payload exceeds "
                    f"{STREAM_MAX_BYTES // (1024 * 1024)} MiB"
                )
            if protocol == "tls" and "\x00" in normalised["payload"]:
                raise EmulatorInputError(
                    f"packet {index} TLS payload cannot contain NUL bytes"
                )
            if protocol == "tls" and len(normalised["payload"].encode("utf-8")) > STREAM_MAX_BYTES:
                raise EmulatorInputError(
                    f"packet {index} TLS payload exceeds {STREAM_MAX_BYTES // (1024 * 1024)} MiB"
                )
        for field in ("seq", "ack"):
            if field not in packet:
                continue
            value = packet[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < TCP_SEQUENCE_MODULUS:
                raise EmulatorInputError(
                    f"packet {index} {field} must be an integer from 0 to {TCP_SEQUENCE_MODULUS - 1}"
                )
            normalised[field] = value

        for field in ("hops", "ttl", "tos"):
            if field not in packet:
                continue
            value = packet[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
                raise EmulatorInputError(
                    f"packet {index} {field} must be an integer from 0 to 255"
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
            elif protocol == "http" and field == "lb_failure":
                failure = _require_string(packet[field], f"packet {index} lb_failure")
                if failure not in LB_FAILURE_CAUSES:
                    causes = ", ".join(sorted(LB_FAILURE_CAUSES))
                    raise EmulatorInputError(
                        f"packet {index} lb_failure must be one of: {causes}"
                    )
                normalised[field] = failure
            elif protocol == "http" and field == "http_class":
                normalised[field] = _normalise_http_class(
                    packet[field], f"packet {index} http_class"
                )
            elif protocol == "http" and field == "persist_down":
                normalised[field] = _normalise_persist_down(
                    packet[field], f"packet {index} persist_down"
                )
            elif protocol == "http" and field == "lb_queue":
                normalised[field] = _normalise_lb_queue(
                    packet[field], f"packet {index} lb_queue"
                )
            elif field in {"body", "response_body", "method", "uri", "host"}:
                normalised[field] = _require_string(packet[field], f"packet {index} {field}")
            elif field == "http2":
                normalised[field] = _normalise_http2_state(
                    packet[field], f"packet {index} http2"
                )
            elif field == "eca" and protocol == "ntlm":
                value = packet[field]
                if not isinstance(value, dict):
                    raise EmulatorInputError(
                        f"packet {index} NTLM eca state must be an object"
                    )
                unknown_eca_fields = sorted(set(value) - EVENT_STATE_FIELDS["eca"])
                if unknown_eca_fields:
                    raise EmulatorInputError(
                        f"packet {index} unsupported NTLM eca field(s): "
                        f"{', '.join(unknown_eca_fields)}"
                    )
                eca_state: dict[str, str] = {}
                for eca_field, eca_value in value.items():
                    if eca_field == "enabled":
                        try:
                            eca_text = _packet_bool(
                                eca_value, f"packet {index} NTLM eca.enabled"
                            )
                        except EmulatorInputError:
                            raise
                    elif isinstance(eca_value, bool):
                        eca_text = "1" if eca_value else "0"
                    elif isinstance(eca_value, (str, int, float)):
                        eca_text = str(eca_value)
                    else:
                        raise EmulatorInputError(
                            f"packet {index} NTLM eca.{eca_field} must be a string or number"
                        )
                    if "\x00" in eca_text:
                        raise EmulatorInputError(
                            f"packet {index} NTLM eca.{eca_field} must not contain NUL"
                        )
                    eca_state[eca_field] = eca_text
                normalised[field] = eca_state
            elif field == "eca_result" and protocol == "ntlm":
                if direction != "client_to_server":
                    raise EmulatorInputError(
                        f"packet {index} eca_result must be client_to_server"
                    )
                result = _require_string(packet[field], f"packet {index} eca_result").lower()
                if result not in {"allowed", "denied"}:
                    raise EmulatorInputError(
                        f"packet {index} eca_result must be allowed or denied"
                    )
                normalised[field] = result
            elif field == "options" and protocol in {"dhcpv4", "dhcpv6"}:
                value = packet[field]
                if not isinstance(value, dict):
                    raise EmulatorInputError(
                        f"packet {index} {protocol.upper()} options must be an object"
                    )
                options: dict[str, str] = {}
                for option_id, option_value in value.items():
                    if not isinstance(option_id, str) or not option_id:
                        raise EmulatorInputError(
                            f"packet {index} {protocol.upper()} option IDs must be non-empty strings"
                        )
                    if not option_id.isdigit() or not 0 <= int(option_id) <= 65535:
                        raise EmulatorInputError(
                            f"packet {index} {protocol.upper()} option IDs must be integers from 0 to 65535"
                        )
                    canonical_id = str(int(option_id))
                    if canonical_id in options:
                        raise EmulatorInputError(
                            f"packet {index} {protocol.upper()} contains duplicate option ID {canonical_id}"
                        )
                    if isinstance(option_value, bool):
                        options[canonical_id] = "1" if option_value else "0"
                    elif isinstance(option_value, (str, int, float)):
                        options[canonical_id] = str(option_value)
                    else:
                        options[canonical_id] = _packet_scalar(option_value, "options")
                normalised[field] = options
            elif protocol in {"tcp", "sctp", "dhcpv4", "dhcpv6", "ftp", "icap", "tds", "socks", "l7check", "fix", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category"} and field == "payload_hex":
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
                        f"packet {index} {protocol.upper()} payload exceeds {STREAM_MAX_BYTES} bytes"
                    )
                normalised[field] = payload_bytes.hex()
                normalised["_wire_payload"] = payload_bytes
            elif protocol == "socks" and field == "version":
                value = _packet_scalar(packet[field], f"packet {index} SOCKS version")
                if value not in {"4", "5"}:
                    raise EmulatorInputError(
                        f"packet {index} SOCKS version must be 4 or 5"
                    )
                normalised[field] = value
            elif protocol == "socks" and field == "allowed":
                normalised[field] = _packet_bool(
                    packet[field], f"packet {index} SOCKS allowed"
                )
            elif protocol == "socks" and field == "destination_host":
                normalised[field] = _require_string(
                    packet[field], f"packet {index} SOCKS destination_host"
                )
            elif protocol == "socks" and field == "destination_port":
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                    raise EmulatorInputError(
                        f"packet {index} SOCKS destination_port must be an integer from 0 to 65535"
                    )
                normalised[field] = value
            elif protocol == "sctp" and field in {
                "ppi",
                "mss",
                "rto_initial",
                "rto_max",
                "rto_min",
                "sack_timeout",
            }:
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise EmulatorInputError(
                        f"packet {index} {field} must be a non-negative integer"
                    )
                if field == "ppi" and value > 65535:
                    raise EmulatorInputError(
                        f"packet {index} ppi must be an integer from 0 to 65535"
                    )
                normalised[field] = value
            elif protocol in {"dhcpv4", "dhcpv6"} and field in {
                "hlen",
                "hops",
                "htype",
                "len",
                "opcode",
                "secs",
                "xid",
                "hop_count",
            }:
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise EmulatorInputError(
                        f"packet {index} {field} must be a non-negative integer"
                    )
                limits = {
                    "hlen": 255,
                    "hops": 255,
                    "htype": 255,
                    "len": 65535,
                    "opcode": 255,
                    "secs": 65535,
                    "xid": 2**32 - 1,
                    "hop_count": 255,
                }
                if value > limits[field]:
                    raise EmulatorInputError(
                        f"packet {index} {field} must be an integer from 0 to {limits[field]}"
                    )
                normalised[field] = value
            elif protocol in {"dhcpv4", "dhcpv6"} and field in {"drop", "reject"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "dhcpv4" and field in {
                "chaddr",
                "ciaddr",
                "giaddr",
                "siaddr",
                "type",
            }:
                normalised[field] = _require_string(packet[field], f"packet {index} {field}")
            elif protocol == "dhcpv6" and field in {
                "link_address",
                "msg_type",
                "peer_address",
                "transaction_id",
            }:
                normalised[field] = _require_string(packet[field], f"packet {index} {field}")
            elif protocol in {"dhcpv4", "dhcpv6"}:
                normalised[field] = _packet_scalar(packet[field], field)
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
                if protocol == "tds":
                    value = packet[field]
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        raise EmulatorInputError(
                            f"packet {index} TDS type must be a non-negative integer"
                        )
                    normalised[field] = value
                    continue
                packet_type = _require_string(packet[field], f"packet {index} type").lower()
                if protocol == "tls":
                    if packet_type not in {
                        "client_hello",
                        "client_cert",
                        "handshake",
                        "client_data",
                        "passthrough",
                        "server_hello_send",
                        "server_hello",
                        "server_cert",
                        "server_handshake",
                        "server_data",
                        "client_hello_send",
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
                elif protocol == "rtsp":
                    if packet_type not in {"request", "response"}:
                        raise EmulatorInputError(
                            f"unsupported RTSP packet type: {packet_type}"
                        )
                elif protocol == "diameter":
                    if packet_type not in {"request", "response"}:
                        raise EmulatorInputError(
                            f"unsupported Diameter packet type: {packet_type}"
                        )
                elif protocol == "ftp":
                    if packet_type not in {"command", "response", "data"}:
                        raise EmulatorInputError(
                            f"unsupported FTP packet type: {packet_type}"
                        )
                elif protocol == "icap":
                    if packet_type not in {"request", "response"}:
                        raise EmulatorInputError(
                            f"unsupported ICAP packet type: {packet_type}"
                        )
                elif protocol in STARTTLS_PROTOCOLS:
                    if packet_type not in STARTTLS_PACKET_TYPES:
                        raise EmulatorInputError(
                            f"unsupported {protocol.upper()} packet type: {packet_type}"
                        )
                normalised[field] = packet_type
            elif protocol == "ftp" and field == "command":
                normalised[field] = _require_string(packet[field], f"packet {index} command")
            elif protocol == "ftp" and field == "response_code":
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
                    raise EmulatorInputError(
                        f"packet {index} response_code must be an integer from 100 to 599"
                    )
                normalised[field] = value
            elif protocol == "ftp" and field in {"tls_active", "tls_session_reused"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "tds" and field in {
                "type",
                "length",
                "procid",
                "xacttype",
                "xactid",
            }:
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise EmulatorInputError(
                        f"packet {index} TDS {field} must be a non-negative integer"
                    )
                normalised[field] = value
            elif protocol == "tds" and field == "is_read":
                normalised[field] = _packet_bool(packet[field], f"packet {index} is_read")
            elif protocol == "tds" and field == "request_type":
                request_type = _require_string(
                    packet[field], f"packet {index} request_type"
                ).lower()
                if request_type not in {"read", "write"}:
                    raise EmulatorInputError(
                        f"packet {index} TDS request_type must be read or write"
                    )
                normalised[field] = request_type
            elif protocol == "tds" and field in {
                "procname",
                "sqltext",
                "username",
                "dbname",
                "loginoption",
                "version",
            }:
                normalised[field] = _require_string(
                    packet[field], f"packet {index} {field}"
                )
            elif protocol in STARTTLS_PROTOCOLS and field == "command":
                command = _require_string(packet[field], f"packet {index} command")
                if len(command.encode("utf-8")) > STARTTLS_COMMAND_MAX_BYTES:
                    raise EmulatorInputError(
                        f"packet {index} {protocol.upper()} command exceeds "
                        f"{STARTTLS_COMMAND_MAX_BYTES} bytes"
                    )
                normalised[field] = command
            elif protocol in STARTTLS_PROTOCOLS and field == "tls_active":
                normalised[field] = _packet_bool(packet[field], f"packet {index} tls_active")
            elif protocol == "protocol_inspection" and field == "ids":
                value = packet[field]
                if not isinstance(value, list) or len(value) > 128:
                    raise EmulatorInputError(
                        f"packet {index} PROTOCOL_INSPECTION ids must be a list of at most 128 strings"
                    )
                ids = []
                for item_index, item in enumerate(value):
                    item_value = _require_string(
                        item, f"packet {index} PROTOCOL_INSPECTION ids[{item_index}]"
                    )
                    if not item_value:
                        raise EmulatorInputError(
                            f"packet {index} PROTOCOL_INSPECTION ids cannot contain empty strings"
                        )
                    if len(item_value.encode("utf-8")) > PROTOCOL_INSPECTION_ID_MAX_BYTES:
                        raise EmulatorInputError(
                            f"packet {index} PROTOCOL_INSPECTION id exceeds "
                            f"{PROTOCOL_INSPECTION_ID_MAX_BYTES} bytes"
                        )
                    ids.append(item_value)
                encoded_ids = _tcl_list(ids)
                if len(encoded_ids.encode("utf-8")) > PROTOCOL_INSPECTION_IDS_MAX_BYTES:
                    raise EmulatorInputError(
                        f"packet {index} PROTOCOL_INSPECTION ids exceed "
                        f"{PROTOCOL_INSPECTION_IDS_MAX_BYTES} bytes"
                    )
                normalised[field] = encoded_ids
            elif protocol == "protocol_inspection" and field == "matched":
                normalised[field] = _packet_bool(packet[field], f"packet {index} matched")
            elif protocol == "classification" and field in {
                "app",
                "category",
                "classification_protocol",
                "urlcat",
                "username",
            }:
                normalised[field] = _require_string(
                    packet[field], f"packet {index} {field}"
                )
            elif protocol == "classification" and field == "result":
                value = packet[field]
                if not isinstance(value, list) or len(value) > 128:
                    raise EmulatorInputError(
                        f"packet {index} CLASSIFICATION result must be a list of at most 128 strings"
                    )
                result = []
                for item_index, item in enumerate(value):
                    item_value = _require_string(
                        item, f"packet {index} CLASSIFICATION result[{item_index}]"
                    )
                    if not item_value:
                        raise EmulatorInputError(
                            f"packet {index} CLASSIFICATION result cannot contain empty strings"
                        )
                    result.append(item_value)
                encoded_result = _tcl_list(result)
                if len(encoded_result.encode("utf-8")) > PROTOCOL_INSPECTION_IDS_MAX_BYTES:
                    raise EmulatorInputError(
                        f"packet {index} CLASSIFICATION result exceeds "
                        f"{PROTOCOL_INSPECTION_IDS_MAX_BYTES} bytes"
                    )
                normalised[field] = encoded_result
            elif protocol == "classification" and field == "detected":
                normalised[field] = _packet_bool(packet[field], f"packet {index} detected")
            elif protocol == "classification" and field == "deferred":
                normalised[field] = _packet_bool(packet[field], f"packet {index} deferred")
            elif protocol == "category" and field in {"categories", "lookup", "safesearch"}:
                value = packet[field]
                if not isinstance(value, list) or len(value) > CATEGORY_RESULT_MAX_ITEMS:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY {field} must be a list of at most "
                        f"{CATEGORY_RESULT_MAX_ITEMS} strings"
                    )
                values = []
                for item_index, item in enumerate(value):
                    item_value = _require_string(
                        item, f"packet {index} CATEGORY {field}[{item_index}]"
                    )
                    if not item_value:
                        raise EmulatorInputError(
                            f"packet {index} CATEGORY {field} cannot contain empty strings"
                        )
                    values.append(item_value)
                # This value is installed into a Tcl variable, rather than
                # passed as a command argument. Do not add the outer grouping
                # braces used by _tcl_list, or llength/lindex would see one
                # element containing the serialized list.
                encoded_values = " ".join(_tcl_quote(value) for value in values)
                if len(encoded_values.encode("utf-8")) > CATEGORY_RESULT_MAX_BYTES:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY {field} exceeds "
                        f"{CATEGORY_RESULT_MAX_BYTES} bytes"
                    )
                normalised[field] = encoded_values
            elif protocol == "category" and field == "filetype":
                value = packet[field]
                if not isinstance(value, dict) or set(value) - {"mimetype", "mimesubtype"}:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY filetype must contain mimetype and/or mimesubtype"
                    )
                filetype = {}
                for name, item in value.items():
                    filetype[name] = _require_string(
                        item, f"packet {index} CATEGORY filetype.{name}"
                    )
                if not filetype:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY filetype must contain mimetype and/or mimesubtype"
                    )
                normalised[field] = filetype
            elif protocol == "category" and field == "matchtype":
                value = _require_string(packet[field], f"packet {index} CATEGORY matchtype")
                if value not in {"custom", "request_default", "request_default_and_custom"}:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY matchtype must be custom, request_default, or request_default_and_custom"
                    )
                normalised[field] = value
            elif protocol == "category" and field in {"detected", "matched"}:
                normalised[field] = _packet_bool(packet[field], f"packet {index} {field}")
            elif protocol == "category" and field == "analytics":
                value = _require_string(packet[field], f"packet {index} CATEGORY analytics")
                value = value.lower()
                if value not in {"enable", "disable"}:
                    raise EmulatorInputError(
                        f"packet {index} CATEGORY analytics must be enable or disable"
                    )
                normalised[field] = value
            elif protocol == "category" and field == "url":
                normalised[field] = _require_string(packet[field], f"packet {index} CATEGORY url")
            elif protocol == "qoe" and field == "qoe":
                normalised[field] = _normalise_qoe_packet(
                    packet[field], f"packet {index} qoe"
                )
            elif protocol == "l7check" and field == "l7_protocol":
                value = _require_string(
                    packet[field], f"packet {index} l7_protocol"
                )
                if "\x00" in value:
                    raise EmulatorInputError(
                        f"packet {index} l7_protocol cannot contain NUL bytes"
                    )
                if len(value.encode("utf-8")) > 256:
                    raise EmulatorInputError(
                        f"packet {index} l7_protocol exceeds 256 bytes"
                    )
                normalised[field] = value
            elif protocol == "fix" and field == "fix":
                _, fix_state = _normalise_event(
                    "FIX_MESSAGE", {"fix": packet[field]}
                )
                normalised[field] = fix_state["fix"]
            elif protocol == "icap" and field == "status":
                value = packet[field]
                if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 999:
                    raise EmulatorInputError(
                        f"packet {index} ICAP status must be an integer from 100 to 999"
                    )
                normalised[field] = value
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
        if wire_length is not None:
            normalised["_wire_length"] = wire_length

        if protocol == "tls" and "type" not in normalised:
            raise EmulatorInputError(f"packet {index} TLS packets require type")
        if protocol == "http2" and "_http2_payload" not in normalised:
            raise EmulatorInputError(f"packet {index} HTTP/2 packets require payload_hex")
        if protocol == "tls":
            client_types = {
                "client_hello",
                "client_cert",
                "handshake",
                "client_data",
                "passthrough",
                "server_hello_send",
            }
            server_types = {
                "server_hello",
                "server_cert",
                "server_handshake",
                "server_data",
                "client_hello_send",
            }
            valid_types = client_types if direction == "client_to_server" else server_types
            if normalised["type"] not in valid_types:
                side = "client" if direction == "client_to_server" else "server"
                raise EmulatorInputError(
                    f"packet {index} TLS {side} direction cannot carry {normalised['type']}"
                )
        if protocol == "ftp":
            normalised.setdefault(
                "type", "command" if direction == "client_to_server" else "response"
            )
            normalised.setdefault("command", "")
            normalised.setdefault("response_code", 0)
            normalised.setdefault("tls_active", "0")
            normalised.setdefault("tls_session_reused", "0")
        if protocol == "tds":
            normalised.setdefault("type", 0)
            normalised.setdefault("length", 0)
            normalised.setdefault("procid", 0)
            normalised.setdefault("procname", "")
            normalised.setdefault("sqltext", "")
            normalised.setdefault("xacttype", 0)
            normalised.setdefault("xactid", 0)
            normalised.setdefault("is_read", "0")
            normalised.setdefault("request_type", "read")
            normalised.setdefault("username", "")
            normalised.setdefault("dbname", "")
            normalised.setdefault("loginoption", "")
            normalised.setdefault("version", "")
        if protocol == "icap":
            normalised.setdefault(
                "type", "request" if direction == "client_to_server" else "response"
            )
            expected_type = "request" if direction == "client_to_server" else "response"
            if normalised["type"] != expected_type:
                raise EmulatorInputError(
                    f"packet {index} ICAP {expected_type}s must be {direction}"
                )
            normalised.setdefault("method", "REQMOD")
            normalised["method"] = str(normalised["method"]).upper()
            if normalised["method"] not in {"REQMOD", "RESPMOD"}:
                raise EmulatorInputError(
                    f"packet {index} ICAP method must be REQMOD or RESPMOD"
                )
            normalised.setdefault("uri", "icap://icap.example.net/reqmod")
            normalised.setdefault("status", 200)
            normalised.setdefault("headers", {})
        if protocol in STARTTLS_PROTOCOLS:
            normalised.setdefault(
                "type", "command" if direction == "client_to_server" else "response"
            )
            if direction == "client_to_server" and normalised["type"] == "response":
                raise EmulatorInputError(
                    f"packet {index} {protocol.upper()} responses must be server_to_client"
                )
            if direction == "server_to_client" and normalised["type"] == "command":
                raise EmulatorInputError(
                    f"packet {index} {protocol.upper()} commands must be client_to_server"
                )
            normalised.setdefault("command", "")
            normalised.setdefault("tls_active", "0")
        if protocol == "ntlm":
            normalised.setdefault("payload_hex", "")
        if protocol == "qoe":
            if "qoe" not in normalised:
                raise EmulatorInputError(
                    f"packet {index} QOE packets require a qoe measurement object"
                )
            if direction != "server_to_client":
                raise EmulatorInputError(
                    f"packet {index} QOE packets must be server_to_client"
                )
        if protocol == "fix" and "fix" not in normalised:
            raise EmulatorInputError(
                f"packet {index} FIX packets require a fix tag object"
            )
        if protocol == "protocol_inspection":
            if direction != "client_to_server":
                raise EmulatorInputError(
                    f"packet {index} PROTOCOL_INSPECTION packets must be client_to_server"
                )
            normalised.setdefault("ids", _tcl_list([]))
            normalised.setdefault("matched", "1")
        if protocol == "classification":
            if direction != "client_to_server" and normalised.get("deferred") != "1":
                raise EmulatorInputError(
                    f"packet {index} CLASSIFICATION packets must be client_to_server unless deferred"
                )
            normalised.setdefault("app", "")
            normalised.setdefault("category", "")
            normalised.setdefault("classification_protocol", "")
            normalised.setdefault("detected", "1")
            normalised.setdefault("deferred", "0")
            normalised.setdefault("result", _tcl_list([]))
            normalised.setdefault("urlcat", "")
            normalised.setdefault("username", "")
        if protocol == "category":
            if direction != "client_to_server":
                raise EmulatorInputError(
                    f"packet {index} CATEGORY packets must be client_to_server"
                )
            normalised.setdefault("detected", "1")
            normalised.setdefault("matched", "1")
            normalised.setdefault("url", "")
            normalised.setdefault("matchtype", "request_default")
            normalised.setdefault("safesearch", "")
            normalised.setdefault("categories", normalised.get("lookup", ""))
            normalised.setdefault("lookup", normalised.get("categories", ""))
            normalised.setdefault("filetype", {})
            normalised.setdefault("analytics", "disable")
        if protocol == "http" and direction == "client_to_server" and "status" in normalised:
            raise EmulatorInputError(f"packet {index} HTTP requests cannot specify status")
        if protocol == "http" and direction == "server_to_client" and "lb_failure" in normalised:
            raise EmulatorInputError(
                f"packet {index} HTTP responses cannot specify lb_failure"
            )
        if protocol == "http" and direction == "server_to_client" and "persist_down" in normalised:
            raise EmulatorInputError(
                f"packet {index} HTTP responses cannot specify persist_down"
            )
        if protocol == "http" and direction == "server_to_client" and "lb_queue" in normalised:
            raise EmulatorInputError(
                f"packet {index} HTTP responses cannot specify lb_queue"
            )
        if protocol == "http" and direction == "server_to_client" and "http_class" in normalised:
            raise EmulatorInputError(
                f"packet {index} HTTP responses cannot specify http_class"
            )
        if protocol == "http" and "lb_failure" in normalised and (
            "persist_down" in normalised
            or (
                "lb_queue" in normalised
                and normalised["lb_queue"]["queued"]
            )
        ):
            raise EmulatorInputError(
                f"packet {index} lb_failure cannot be combined with "
                "persist_down or a queued lb_queue"
            )
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
            if packet_type == "CONNECT":
                has_will_fields = any(
                    field in normalised
                    for field in ("will_topic", "will_message", "will_qos", "will_retain")
                )
                normalised["will_flag"] = _packet_bool(
                    normalised.get("will_flag", has_will_fields),
                    f"packet {index} MQTT will_flag",
                )
                has_username = "username" in normalised
                has_password = "password" in normalised
                normalised["username_flag"] = _packet_bool(
                    normalised.get("username_flag", has_username),
                    f"packet {index} MQTT username_flag",
                )
                normalised["password_flag"] = _packet_bool(
                    normalised.get("password_flag", has_password),
                    f"packet {index} MQTT password_flag",
                )
                if normalised["password_flag"] == "1" and normalised["username_flag"] != "1":
                    raise EmulatorInputError(
                        f"packet {index} MQTT password requires username"
                    )
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
            sdp_template = _parse_sdp_payload(
                normalised.get("_sip_payload", b""),
                normalised.get("headers", []),
            )
            if sdp_template is not None:
                normalised["_sdp_template"] = sdp_template
        if protocol == "socks":
            if direction != "client_to_server":
                raise EmulatorInputError(
                    f"packet {index} SOCKS requests must be client_to_server"
                )
            if "payload" in normalised and "_wire_payload" not in normalised:
                normalised["_wire_payload"] = normalised["payload"].encode("utf-8")
            raw_socks = normalised.get("_wire_payload")
            has_wire_input = "payload" in packet or "payload_hex" in packet
            if has_wire_input:
                if not isinstance(raw_socks, (bytes, bytearray)) or not raw_socks:
                    raise EmulatorInputError(
                        f"packet {index} SOCKS request payload must not be empty"
                    )
                parsed_socks = _parse_socks_request(bytes(raw_socks))
                for field in ("version", "destination_host", "destination_port"):
                    if field in normalised and str(normalised[field]) != str(parsed_socks[field]):
                        raise EmulatorInputError(
                            f"packet {index} SOCKS {field} conflicts with payload"
                        )
                normalised.update(parsed_socks)
            else:
                normalised.setdefault("version", "5")
                normalised.setdefault("allowed", "1")
                normalised.setdefault("destination_host", "")
                normalised.setdefault("destination_port", 0)
                if normalised["version"] not in {"4", "5"}:
                    raise EmulatorInputError(
                        f"packet {index} SOCKS version must be 4 or 5"
                    )
        if protocol == "rtsp":
            if "body" in packet and "payload" in packet:
                raise EmulatorInputError(
                    f"packet {index} RTSP packets must use body or payload, not both"
                )
            packet_type = normalised.get("type")
            if packet_type is None:
                raise EmulatorInputError(f"packet {index} RTSP packets require type")
            if packet_type == "request":
                if direction != "client_to_server":
                    raise EmulatorInputError(
                        f"packet {index} RTSP requests must be client_to_server"
                    )
                if "method" not in normalised or "uri" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} RTSP requests require method and uri"
                    )
            else:
                if direction != "server_to_client":
                    raise EmulatorInputError(
                        f"packet {index} RTSP responses must be server_to_client"
                    )
                if "status" not in normalised:
                    raise EmulatorInputError(
                        f"packet {index} RTSP responses require status"
                    )
                try:
                    status = int(normalised["status"])
                except (TypeError, ValueError) as exc:
                    raise EmulatorInputError(
                        f"packet {index} RTSP status must be an integer"
                    ) from exc
                if not 100 <= status <= 999:
                    raise EmulatorInputError(
                        f"packet {index} RTSP status must be between 100 and 999"
                    )
                normalised["status"] = status
            normalised.setdefault("version", "RTSP/1.0")
            if packet_type == "response":
                normalised.setdefault("phrase", "OK" if normalised["status"] == 200 else "")
            normalised.setdefault("headers", normalised.get("response_headers", {}))
            if packet_type == "response":
                normalised.setdefault("response_headers", normalised["headers"])
            normalised["payload"] = normalised.get("payload", normalised.get("body", ""))
            try:
                normalised["_rtsp_payload"] = normalised["payload"].encode("utf-8")
            except UnicodeEncodeError as exc:
                raise EmulatorInputError(
                    f"packet {index} RTSP payload must be valid UTF-8"
                ) from exc
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
    session.eval_tcl("::itest::semantic::diagnostics_begin_packet")
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

    session.eval_tcl(
        "::itest::semantic::backend_prepare_request "
        + " ".join(
            _tcl_quote("1" if field in kwargs else "0")
            for field in ("response_status", "response_headers", "response_body")
        )
    )

    command = "::orch::{} {}".format(proc_name, " ".join(args))
    body = kwargs.get("body")
    if body is None:
        session.eval_tcl(command)
    else:
        body_value = _tcl_quote(body)
        script = f"""
            set ::orch::_testcl_request_payload {body_value}
            set ::orch::_testcl_request_payload_seeded 0
            proc ::orch::_testcl_request_payload_trace {{name1 name2 op}} {{
                if {{!$::orch::_testcl_request_payload_seeded}} {{
                    set ::orch::_testcl_request_payload_seeded 1
                    set ::state::http::request::payload $::orch::_testcl_request_payload
                }}
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

    # The upstream orchestrator only invokes fire_event for events with an
    # iRule handler.  Fill in any enabled HTTPLOG phases that therefore did
    # not pass through the wrapper, while avoiding duplicates for handled
    # HTTP_REQUEST/HTTP_RESPONSE events.
    session.eval_tcl("::itest::semantic::httplog_record_if_missing request")
    session.eval_tcl("::itest::semantic::httplog_record_if_missing response")
    request_state = session.get_state("http_request")
    response_state = session.get_state("http_response")
    committed = session.eval_tcl("set ::state::http::response_committed")
    fired_events = _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
    decisions = session.get_decisions()
    logs = session.get_logs()
    semantic = _semantic_snapshot(session)
    event_errors = _event_error_snapshot(session)
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
        "http_log": semantic["http_log"]["records"],
        "http2": _http2_snapshot(session),
    }
    if semantic["diagnostics"]["accumulate"]["suspended"]:
        result["suspended"] = True
        result["suspension"] = "accumulate"
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
    if event_errors:
        result["errors"] = event_errors
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
    snapshot["push_count"] = int(
        session.eval_tcl("set ::state::http2::push_count") or 0
    )
    pushes: list[dict[str, Any]] = []
    for raw_push in _split_tcl_list(session.eval_tcl("set ::state::http2::pushes")):
        parts = _split_tcl_list(raw_push)
        if len(parts) % 2:
            raise EmulatorInputError("invalid HTTP/2 push state")
        record = dict(zip(parts[::2], parts[1::2]))
        for header_field in ("request_headers", "response_headers"):
            record[header_field] = _header_dict(record.get(header_field, ""))
        for numeric_field in ("id", "priority"):
            if numeric_field in record:
                record[numeric_field] = int(record[numeric_field])
        for boolean_field in ("noserver", "nohost"):
            if boolean_field in record:
                record[boolean_field] = record[boolean_field] == "1"
        pushes.append(record)
    snapshot["pushes"] = pushes
    return snapshot


def _http_class_snapshot(session: Any) -> dict[str, Any]:
    """Read the bounded HTTP class-selector state exposed by the shim."""
    return {
        "name": session.eval_tcl("set ::state::http::class_name"),
        "enabled": session.eval_tcl("set ::state::http::class_enabled") == "1",
        "asm": session.eval_tcl("set ::state::http::class_asm") == "1",
        "wa": session.eval_tcl("set ::state::http::class_wa") == "1",
    }


def _prepare_http_class_request_state(session: Any, kwargs: dict[str, Any]) -> None:
    """Seed request-visible HTTP fields before a class event fires."""
    header_values = [
        item
        for name, value in kwargs.get("headers", {}).items()
        for item in (name, value)
    ]
    command = (
        "::state::http::request::configure "
        f"-method {_tcl_quote(kwargs.get('method', 'GET'))} "
        f"-uri {_tcl_quote(kwargs.get('uri', '/'))} "
        f"-host {_tcl_quote(kwargs.get('host', ''))} "
        f"-headers {_tcl_list(header_values)}"
    )
    session.eval_tcl(command)
    body = kwargs.get("body", "")
    session.eval_tcl(
        "set ::state::http::request::payload " + _tcl_quote(body)
    )
    session.eval_tcl(
        "set ::state::http::request::payload_length "
        + str(len(body.encode("utf-8")))
    )


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
        (
            source,
            profiles,
            pools,
            backends,
            pool_modes,
            resolvers,
            datagroups,
            profile_settings,
            dosl7,
            asm,
            botdefense,
            antifraud,
            auth,
            aaa,
            access,
            ip_config,
            route_config,
            http_proxy_config,
            flowtable_config,
            sideband_config,
            ifile_config,
            urlcat_config,
            cpu_config,
            whereis_config,
            pem_dtos_config,
        ) = _normalise_scenario_config(
            scenario,
            allow_irule_file=allow_irule_file,
            allow_requests=allow_requests,
            allow_packets=allow_packets,
            require_http=False,
        )
        self._root = root
        self._backend = backend
        self._source = source
        self._prepared_source, self._event_controls = _prepare_irule_source(root, source)
        self._profiles = profiles
        self._pools = pools
        self._backends = backends
        self._pool_modes = pool_modes
        self._resolvers = resolvers
        self._datagroups = datagroups
        self._profile_settings = profile_settings
        self._dosl7 = dosl7
        self._asm = asm
        self._botdefense = botdefense
        self._antifraud = antifraud
        self._auth = auth
        self._aaa = aaa
        self._access = access
        self._ip_config = ip_config
        self._route_config = route_config
        self._route_visible = bool(route_config["metrics"]) or "ROUTE::" in source
        self._http_proxy_config = http_proxy_config
        self._flowtable_config = flowtable_config
        self._sideband_config = sideband_config
        self._ifile_config = ifile_config
        self._urlcat_config = urlcat_config
        self._cpu_config = cpu_config
        self._whereis_config = whereis_config
        self._pem_dtos_config = pem_dtos_config
        self._fidelity = _analyze_rule_capabilities(root, self._prepared_source, profiles)
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
        self._name_resolution_dispatching = False
        self._tcp_notify_dispatching = False
        self._packet_trace_active = False
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
        self._server_connection_id = 0
        self._server_connection_detached = False
        self._tcp_buffers = {"client": "", "server": ""}
        self._stream_buffers = {"client": b"", "server": b""}
        self._sctp_buffers = {"client": b"", "server": b""}
        self._ssl_buffers = {"client": b"", "server": b""}
        self._packet_streams: dict[tuple[Any, ...], _TcpStream] = {}
        self._http2_decoder: Http2ConnectionDecoder | None = None
        self._http2_streams: dict[int, dict[str, Any]] = {}
        self._http2_tcp_active = False
        self._websocket_raw_active = False
        self._ip_connection_initialized = False
        self._ip_connection_start_timestamp: float | None = None
        self._ip_age_ms = 0
        self._ip_virtual_age_ms = 0
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

    @property
    def event_controls(self) -> list[dict[str, Any]]:
        return [dict(control) for control in self._event_controls]

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
                _install_python_backend_helper(session, self._backends)
                session.eval_tcl("::itest::semantic::session_reset")
                session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
                session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
                session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
                session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
                for procedure, arguments, body in _extract_irule_procedures(
                    self._root, self._prepared_source
                ):
                    procedure_name = (
                        procedure if procedure.startswith("::") else "::" + procedure
                    )
                    session.eval_tcl(
                        "proc {} {} {}".format(
                            _tcl_quote(procedure_name),
                            _tcl_quote(arguments),
                            _tcl_quote(body),
                        )
                    )
                self._registered_events = session.load_irule(self._prepared_source)
                session.eval_tcl("::itest::semantic::backend_reset_request")
                session.eval_tcl("::itest::semantic::backend_install_flow_hook")
                session.eval_tcl("::itest::semantic::lb_reset_connection")
                session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
                session.eval_tcl("::itest::semantic::crypto_reset_connection")
                session.eval_tcl("::itest::semantic::bwc_reset_connection")
                session.eval_tcl("::itest::semantic::ipfix_reset_connection")
                session.eval_tcl("::itest::semantic::adapt_reset_connection")
                session.eval_tcl("::itest::semantic::datagram_reset_connection")
                session.eval_tcl("::itest::semantic::sctp_reset_connection")
                session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
                session.eval_tcl("::itest::semantic::l7check_reset_connection")
                session.eval_tcl("::itest::semantic::link_reset_connection")
                session.eval_tcl("::itest::semantic::name_reset_connection")
                session.eval_tcl("::itest::semantic::socks_reset_connection")
                session.eval_tcl("::itest::semantic::sdp_reset_connection")
                session.eval_tcl("::itest::semantic::dhcp_reset_connection")
                session.eval_tcl("::itest::semantic::tds_reset_connection")
                session.eval_tcl("::itest::semantic::offbox_reset_connection")
                session.eval_tcl("::itest::semantic::qoe_reset_connection")
                session.eval_tcl("::itest::semantic::ike_reset_event")
                session.eval_tcl("::itest::semantic::sideband_reset_connection")
                session.eval_tcl("::itest::semantic::ftp_reset_connection")
                session.eval_tcl("::itest::semantic::imap_reset_connection")
                session.eval_tcl("::itest::semantic::pop3_reset_connection")
                session.eval_tcl("::itest::semantic::ldap_reset_connection")
                session.eval_tcl("::itest::semantic::smtps_reset_connection")
                session.eval_tcl("::itest::semantic::ntlm_reset_connection")
                session.eval_tcl("::itest::semantic::eca_reset_connection")
                session.eval_tcl("::itest::semantic::avr_reset_connection")
                session.eval_tcl("::itest::semantic::protocol_inspection_reset_connection")
                session.eval_tcl("::itest::semantic::classification_reset_connection")
                session.eval_tcl("::itest::semantic::category_reset_connection")
                session.eval_tcl("::itest::semantic::icap_reset_connection")
                session.eval_tcl("::itest::semantic::profile_settings_clear")
                for profile_name, attributes in self._profile_settings.items():
                    flattened = [
                        item
                        for attribute_name, value in attributes.items()
                        for item in (attribute_name, value)
                    ]
                    session.eval_tcl(
                        "::itest::semantic::profile_settings_set "
                        f"{_tcl_quote(profile_name)} {_tcl_list(flattened)}"
                    )
                dosl7_flattened = [
                    item
                    for address, rate, timeout in self._dosl7["greylist"]
                    for item in (address, str(rate), str(timeout))
                ]
                session.eval_tcl(
                    "::itest::semantic::dosl7_configure "
                    f"{_tcl_quote('1' if self._dosl7['enabled'] else '0')} "
                    f"{_tcl_quote(str(self._dosl7['health']))} "
                    f"{_tcl_quote(self._dosl7['profile'])} "
                    f"{_tcl_quote('1' if self._dosl7['mitigated'] else '0')} "
                    f"{_tcl_list(dosl7_flattened)}"
                )
                _configure_asm(session, self._asm)
                _configure_botdefense(session, self._botdefense)
                _configure_antifraud(session, self._antifraud)
                _configure_auth(session, self._auth)
                _configure_aaa(session, self._aaa)
                access_auto_interest = bool(
                    "ACCESS::" in self._prepared_source
                    or any(event.startswith("ACCESS_") for event in self._registered_events)
                )
                _configure_access(
                    session, self._access, auto_interest=access_auto_interest
                )
                _configure_ip(session, self._ip_config)
                _configure_route(session, self._route_config)
                _configure_http_proxy(session, self._http_proxy_config)
                _configure_flowtable(session, self._flowtable_config)
                _configure_sideband(session, self._sideband_config)
                _configure_ifiles(session, self._ifile_config)
                _configure_urlcat(session, self._urlcat_config)
                _configure_cpu(session, self._cpu_config)
                _configure_whereis(session, self._whereis_config)
                _configure_pem_dtos(session, self._pem_dtos_config)
                session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
                session.eval_tcl("::itest::semantic::rewrite_reset_connection")
                session.eval_tcl("::itest::semantic::html_reset_connection")
                session.eval_tcl("::itest::semantic::compression_reset_connection")
                session.eval_tcl("::itest::semantic::httplog_reset_connection")
                session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
                session.eval_tcl("::itest::semantic::crypto_reset_connection")
                session.eval_tcl("::itest::semantic::bwc_reset_connection")
                session.eval_tcl("::itest::semantic::ipfix_reset_connection")
                session.eval_tcl("::itest::semantic::adapt_reset_connection")
                session.eval_tcl("::itest::semantic::datagram_reset_connection")
                session.eval_tcl("::itest::semantic::sctp_reset_connection")
                session.eval_tcl("::itest::semantic::flow_reset_connection")
                session.eval_tcl("::itest::semantic::acl_reset_connection")
                session.eval_tcl("::itest::semantic::lsn_reset_connection")
                session.eval_tcl("::itest::semantic::xlat_reset_connection")
                session.eval_tcl("::itest::semantic::pcp_reset_connection")
                session.eval_tcl("::itest::semantic::psc_reset_connection")
                session.eval_tcl("::itest::semantic::pem_reset_connection")
                session.eval_tcl("::itest::semantic::connector_reset_connection")
                session.eval_tcl("::itest::semantic::wam_reset_connection")
                session.eval_tcl("::itest::semantic::vdi_reset_connection")
                session.eval_tcl("::itest::semantic::tap_reset_connection")
                if any(str(profile).upper() == "REWRITE" for profile in self._profiles):
                    session.eval_tcl("::itest::semantic::rewrite_install_flow_hooks")
                if any(
                    str(profile).upper() in {"CACHE", "WEBACCELERATION"}
                    for profile in self._profiles
                ):
                    session.eval_tcl("::itest::semantic::cache_install_flow_hooks")
                for name, members in self._pools.items():
                    pool_mode = self._pool_modes.get(name)
                    if pool_mode is None:
                        session.add_pool(name, members)
                    else:
                        session.eval_tcl(
                            "::state::lb::add_pool "
                            f"{_tcl_quote(name)} {_tcl_list(members)} "
                            f"-lb_mode {_tcl_quote(pool_mode)}"
                        )
                for member, fixture in self._backends.items():
                    session.eval_tcl(
                        "::state::lb::set_node_status "
                        f"{_tcl_quote(member)} {_tcl_quote(fixture['state'])}"
                    )
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

    def _prepare_server_connection(
        self, session: Any, oneconnect_enabled: bool
    ) -> tuple[int, bool, str]:
        """Choose a deterministic server-side connection for one request."""
        if not self._server_connection_open:
            self._server_connection_id += 1
            self._server_connection_open = True
            return self._server_connection_id, False, "new"
        if self._server_connection_detached and oneconnect_enabled:
            controls = _oneconnect_runtime_state(session)
            if controls["reuse_enabled"]:
                return self._server_connection_id, True, "idle-reuse"
            self._server_connection_id += 1
            return self._server_connection_id, False, "reuse-disabled"
        return self._server_connection_id, False, "attached"

    def _run_request_on_worker(self, session: Any, request: dict[str, Any]) -> dict[str, Any]:
        _validate_request_flags(request)
        session.eval_tcl("::itest::semantic::event_errors_reset")
        if request.get("close_before") or request.get("new_connection"):
            if self._connection_open:
                session.close_connection()
                session.eval_tcl("::itest::semantic::access_auto_close_session")
                session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
                session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
                session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
                session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
                session.eval_tcl("::itest::semantic::stream_reset_connection")
                session.eval_tcl("::itest::semantic::route_reset_connection")
                session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
                session.eval_tcl("::itest::semantic::rewrite_reset_connection")
                session.eval_tcl("::itest::semantic::html_reset_connection")
                session.eval_tcl("::itest::semantic::compression_reset_connection")
                session.eval_tcl("::itest::semantic::httplog_reset_connection")
            session.eval_tcl("::itest::semantic::ilx_reset_connection")
            session.eval_tcl("::itest::semantic::nsh_reset_connection")
            session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
            self._connection_open = False
            self._connection_request_number = 0
        if not self._connection_open:
            self._connection_request_number = 0
            self._server_connection_open = False
            self._server_connection_detached = False
            session.eval_tcl("::state::reset_connection_state")
            session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
            session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
            session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
            session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
            session.eval_tcl("::itest::semantic::lb_reset_connection")
            session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
            session.eval_tcl("::itest::semantic::psm_reset_connection")
            session.eval_tcl("::itest::semantic::dosl7_reset_connection")
            session.eval_tcl("::itest::semantic::asm_reset_connection")
            session.eval_tcl("::itest::semantic::botdefense_reset_connection")
            session.eval_tcl("::itest::semantic::antifraud_reset_connection")
            session.eval_tcl("::itest::semantic::auth_reset_connection")
            session.eval_tcl("::itest::semantic::aaa_reset_connection")
            session.eval_tcl("::itest::semantic::access_reset_connection")
            session.eval_tcl("::itest::semantic::ssl_reset_connection")
            session.eval_tcl("::itest::semantic::sideband_reset_connection")
            session.eval_tcl("::itest::semantic::stream_reset_connection")
            session.eval_tcl("::itest::semantic::route_reset_connection")
            session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
            session.eval_tcl("::itest::semantic::rewrite_reset_connection")
            session.eval_tcl("::itest::semantic::html_reset_connection")
            session.eval_tcl("::itest::semantic::compression_reset_connection")
            session.eval_tcl("::itest::semantic::adapt_reset_connection")
            session.eval_tcl("::itest::semantic::datagram_reset_connection")
            session.eval_tcl("::itest::semantic::sctp_reset_connection")
            session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
            session.eval_tcl("::itest::semantic::link_reset_connection")
            session.eval_tcl("::itest::semantic::tcp_reset_transport")
        request_number = self._connection_request_number + 1
        session.eval_tcl(
            f"set ::itest::semantic::http_request_number {request_number}"
        )
        kwargs = _request_kwargs(request)
        http_class = kwargs.pop("http_class", None)
        lb_failure = kwargs.pop("lb_failure", "")
        persist_down = kwargs.pop("persist_down", None)
        lb_queue = kwargs.pop("lb_queue", None)
        dosl7_request = kwargs.pop("dosl7", None)
        antifraud_request = kwargs.pop("antifraud", None)
        access_request = kwargs.pop("access", None)
        antifraud_login = self._antifraud["login"]
        antifraud_alert = self._antifraud["alert"]
        if antifraud_request is not None:
            antifraud_login = antifraud_request.get("login", antifraud_login)
            antifraud_alert = antifraud_request.get("alert", antifraud_alert)
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        original_kwargs = dict(kwargs)
        oneconnect_enabled = any(
            str(profile).upper() == "ONECONNECT" for profile in self._profiles
        )
        server_connection_id, server_connection_reused, server_connection_reason = (
            self._prepare_server_connection(session, oneconnect_enabled)
        )
        retry_count = 0
        retry_exhausted = False
        http_close_requested = False
        decision_history: list[Any] = []
        log_history: list[Any] = []
        class_decision_history: list[Any] = []
        class_log_history: list[Any] = []

        def normalise_history_entry(entry: Any) -> Any:
            return list(entry) if isinstance(entry, tuple) else entry

        def merge_missing_history(prefix: list[Any], existing: list[Any]) -> list[Any]:
            remaining = list(existing)
            missing: list[Any] = []
            for item in prefix:
                try:
                    remaining.remove(item)
                except ValueError:
                    missing.append(item)
            return missing + list(existing)

        result: dict[str, Any]
        try:
            while True:
                session.eval_tcl("::itest::semantic::http_control_reset")
                session.eval_tcl("::itest::semantic::http_class_reset")
                session.eval_tcl("::itest::semantic::http_reject_reset")
                if http_class is not None:
                    _prepare_http_class_request_state(session, kwargs)
                    class_decisions_before = len(session.get_decisions())
                    class_logs_before = len(session.get_logs())
                    session.eval_tcl(
                        "::itest::semantic::http_class_configure "
                        + " ".join(
                            _tcl_quote(value)
                            for value in (
                                http_class["name"],
                                "1" if http_class["asm"] else "0",
                                "1" if http_class["wa"] else "0",
                            )
                        )
                    )
                    self._fire_event_on_worker(
                        session,
                        "HTTP_CLASS_SELECTED"
                        if http_class["result"] == "selected"
                        else "HTTP_CLASS_FAILED",
                        {},
                    )
                    class_decision_history.extend(
                        normalise_history_entry(entry)
                        for entry in session.get_decisions()[class_decisions_before:]
                    )
                    class_log_history.extend(session.get_logs()[class_logs_before:])
                session.eval_tcl("::itest::semantic::http_proxy_prepare_request")
                session.eval_tcl("::itest::semantic::rewrite_prepare_request")
                session.eval_tcl("::itest::semantic::html_prepare_request")
                session.eval_tcl("::itest::semantic::compression_prepare_request")
                session.eval_tcl("::itest::semantic::httplog_prepare_request")
                attempt_failure = lb_failure if retry_count == 0 else ""
                dosl7_mitigated = "0"
                if dosl7_request is not None and dosl7_request["mitigated"]:
                    dosl7_mitigated = "1"
                session.eval_tcl(
                    "::itest::semantic::dosl7_prepare_request "
                    f"{_tcl_quote('1' if dosl7_request is not None else '0')} "
                    f"{_tcl_quote(dosl7_mitigated)}"
                )
                session.eval_tcl(
                    "::itest::semantic::asm_prepare_request "
                    f"{_tcl_quote('1' if 'body' in kwargs else '0')} "
                    f"{_tcl_quote(kwargs.get('body', ''))}"
                )
                session.eval_tcl("::itest::semantic::botdefense_prepare_request")
                session.eval_tcl(
                    "::itest::semantic::antifraud_prepare_request "
                    f"{_tcl_quote('1' if antifraud_login else '0')} "
                    f"{_tcl_quote('1' if antifraud_alert else '0')}"
                )
                session.eval_tcl("::itest::semantic::access_prepare_request")
                if access_request is not None:
                    access_args: list[str] = []
                    for field, value in access_request.items():
                        access_args.append(_tcl_quote(field))
                        if isinstance(value, list):
                            access_args.append(_tcl_list(value))
                        elif isinstance(value, bool):
                            access_args.append(_tcl_quote("1" if value else "0"))
                        else:
                            access_args.append(_tcl_quote(str(value)))
                    session.eval_tcl(
                        "::itest::semantic::access_prepare_request "
                        + " ".join(access_args)
                    )
                session.eval_tcl("::itest::semantic::websso_prepare_request")
                session.eval_tcl(
                    f"::itest::semantic::prepare_lb_failure {_tcl_quote(attempt_failure)}"
                )
                attempt_persist_down = persist_down if retry_count == 0 else None
                persist_pool = "" if attempt_persist_down is None else attempt_persist_down["pool"]
                persist_member = "" if attempt_persist_down is None else attempt_persist_down["member"]
                session.eval_tcl(
                    "::itest::semantic::prepare_persist_down "
                    f"{_tcl_quote(persist_pool)} {_tcl_quote(persist_member)}"
                )
                attempt_queue = lb_queue if retry_count == 0 else None
                queue_values = attempt_queue or {
                    "queued": False,
                    "on_connlimit": False,
                    "depth": 0,
                    "limit_depth": 0,
                    "limit_time": 0,
                    "age_head": 0,
                    "age_max": 0,
                    "age_edm": 0,
                    "age_ema": 0,
                }
                queue_fields = (
                    "queued",
                    "on_connlimit",
                    "depth",
                    "limit_depth",
                    "limit_time",
                    "age_head",
                    "age_max",
                    "age_edm",
                    "age_ema",
                )
                queue_args = " ".join(
                    _tcl_quote(
                        ("1" if queue_values[field] else "0")
                        if isinstance(queue_values[field], bool)
                        else str(queue_values[field])
                    )
                    for field in queue_fields
                )
                session.eval_tcl(f"::itest::semantic::prepare_lb_queue {queue_args}")
                session.eval_tcl("::itest::semantic::prepare_http_retry")
                session.eval_tcl("::itest::semantic::prepare_http_release")
                session.eval_tcl("::itest::semantic::prepare_http_close")
                session.eval_tcl("set ::itest::semantic::automatic_http_flow 1")
                try:
                    session.eval_tcl("::itest::semantic::http2_reset_pushes")
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

                if session.eval_tcl("set ::state::http::disabled") == "1":
                    decisions_before_disabled = len(session.get_decisions())
                    logs_before_disabled = len(session.get_logs())
                    disabled_event = self._fire_event_on_worker(
                        session, "HTTP_DISABLED", {}
                    )
                    result["events_fired"].extend(
                        disabled_event.get("events_fired", [])
                    )
                    result["decisions"].extend(
                        session.get_decisions()[decisions_before_disabled:]
                    )
                    result["logs"].extend(
                        session.get_logs()[logs_before_disabled:]
                    )
                    result["http_disabled"] = True
                    result["http_disable_discard"] = (
                        session.eval_tcl(
                            "set ::state::http::disable_discard"
                        )
                        == "1"
                    )

                if session.eval_tcl("set ::state::http::rejected") == "1":
                    decisions_before_reject = len(session.get_decisions())
                    logs_before_reject = len(session.get_logs())
                    reject_event = self._fire_event_on_worker(
                        session, "HTTP_REJECT", {}
                    )
                    result["events_fired"].extend(
                        reject_event.get("events_fired", [])
                    )
                    result["decisions"].extend(
                        session.get_decisions()[decisions_before_reject:]
                    )
                    result["logs"].extend(
                        session.get_logs()[logs_before_reject:]
                    )
                    result["http_rejected"] = True
                    result["http_reject_reason"] = session.eval_tcl(
                        "set ::state::http::reject_reason"
                    )
                    result["http_reject_reason_num"] = int(
                        session.eval_tcl("set ::state::http::reject_reason_num")
                    )

                result["decisions"] = merge_missing_history(
                    class_decision_history, result.get("decisions", [])
                )
                result["logs"] = merge_missing_history(
                    class_log_history, result.get("logs", [])
                )

                if result.get("errors"):
                    first_error = result["errors"][0]
                    self._close_packet_connection(session)
                    self._connection_request_number = 0
                    raise EmulatorInputError(
                        "iRule handler error in {}: {}".format(
                            first_error["event"], first_error["message"]
                        )
                    )

                decision_history.extend(result.get("decisions", []))
                log_history.extend(result.get("logs", []))
                retry = result.pop("http_retry", None)
                http_close = bool(result.pop("http_close", False))
                http2_disconnected = result.get("http2", {}).get("disconnected") == "1"
                self._connection_open = True
                if not retry:
                    oneconnect = result.get("semantic", {}).get("oneconnect", {})
                    detached = oneconnect_enabled and bool(
                        oneconnect.get("detach_enabled", False)
                    )
                    self._server_connection_detached = detached
                    result["server_connection"] = {
                        "id": server_connection_id,
                        "enabled": oneconnect_enabled,
                        "reused": server_connection_reused,
                        "reason": server_connection_reason,
                        "state_after_response": "detached" if detached else "attached",
                        "reuse_enabled": oneconnect_enabled and bool(
                            oneconnect.get("reuse_enabled", False)
                        ),
                        "select": oneconnect.get("select", "none") if oneconnect_enabled else "none",
                        "label": oneconnect.get("label", "") if oneconnect_enabled else "",
                    }
                    http_close_requested = (
                        http_close
                        or http2_disconnected
                        or bool(result.get("http_rejected"))
                    )
                    break
                if retry_count >= MAX_HTTP_RETRIES:
                    retry_exhausted = True
                    break
                retry_count += 1
                if retry.get("reset") is True or retry.get("reset") == "1":
                    # HTTP::retry -reset tears down only the serverside
                    # connection.  Keep the client-side connection and iRule
                    # variables alive, then allocate a fresh deterministic
                    # server connection for the replay.
                    self._server_connection_open = False
                    self._server_connection_detached = False
                    (
                        server_connection_id,
                        server_connection_reused,
                        server_connection_reason,
                    ) = self._prepare_server_connection(session, oneconnect_enabled)
                retry_kwargs = _parse_http_retry_request(retry["request"])
                for field in (
                    "response_status",
                    "response_headers",
                    "response_body",
                ):
                    if field in original_kwargs:
                        retry_kwargs.setdefault(field, original_kwargs[field])
                if dosl7_request is not None:
                    retry_kwargs["dosl7"] = dosl7_request
                if antifraud_request is not None:
                    retry_kwargs["antifraud"] = antifraud_request
                if access_request is not None:
                    retry_kwargs["access"] = access_request
                if "http2" in original_kwargs:
                    retry_kwargs.setdefault("http2", original_kwargs["http2"])
                kwargs = retry_kwargs
        finally:
            session.eval_tcl(
                "unset -nocomplain ::itest::semantic::automatic_http_flow"
            )
            session.eval_tcl("::itest::semantic::clear_lb_failure")
            session.eval_tcl("::itest::semantic::prepare_persist_down {} {}")
            session.eval_tcl("::itest::semantic::prepare_lb_queue 0 0 0 0 0 0 0 0 0")
            session.eval_tcl("::itest::semantic::prepare_http_retry")
            session.eval_tcl("::itest::semantic::prepare_http_release")
            session.eval_tcl("::itest::semantic::prepare_http_close")
            session.eval_tcl("::itest::semantic::http_control_reset")
            session.eval_tcl("::itest::semantic::http_reject_reset")
        if http_close_requested:
            events_before_close = _split_tcl_list(
                session.eval_tcl("::itest::get_fired_events")
            )
            decisions_before_close = len(session.get_decisions())
            logs_before_close = len(session.get_logs())
            event_errors_before_close = len(_event_error_snapshot(session))
            connection_active = session.eval_tcl("set ::orch::_connection_active")
            if str(connection_active) == "1":
                session.fire_event("CLIENT_CLOSED")
                session.eval_tcl("::itest::semantic::access_auto_close_session")
                close_errors = _event_error_snapshot(session)
                if len(close_errors) > event_errors_before_close:
                    first_error = close_errors[event_errors_before_close]
                    self._close_packet_connection(session)
                    self._connection_request_number = 0
                    raise EmulatorInputError(
                        "iRule handler error in {}: {}".format(
                            first_error["event"], first_error["message"]
                        )
                    )
            events_after_close = _split_tcl_list(
                session.eval_tcl("::itest::get_fired_events")
            )
            result["events_fired"].extend(events_after_close[len(events_before_close):])
            decision_history.extend(session.get_decisions()[decisions_before_close:])
            log_history.extend(session.get_logs()[logs_before_close:])
            session.eval_tcl("set ::orch::_connection_active 0")
            session.eval_tcl("::state::reset_connection_state")
            session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
            session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
            session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
            session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
            session.eval_tcl("::itest::semantic::psm_reset_connection")
            session.eval_tcl("::itest::semantic::ssl_reset_connection")
            session.eval_tcl("::itest::semantic::flow_reset_connection")
            session.eval_tcl("::itest::semantic::acl_reset_connection")
            session.eval_tcl("::itest::semantic::lsn_reset_connection")
            session.eval_tcl("::itest::semantic::xlat_reset_connection")
            session.eval_tcl("::itest::semantic::pcp_reset_connection")
            session.eval_tcl("::itest::semantic::psc_reset_connection")
            session.eval_tcl("::itest::semantic::pem_reset_connection")
            session.eval_tcl("::itest::semantic::connector_reset_connection")
            session.eval_tcl("::itest::semantic::wam_reset_connection")
            session.eval_tcl("::itest::semantic::vdi_reset_connection")
            session.eval_tcl("::itest::semantic::tap_reset_connection")
            session.eval_tcl("::itest::semantic::stream_reset_connection")
            session.eval_tcl("::itest::semantic::route_reset_connection")
            session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
            session.eval_tcl("::itest::semantic::rewrite_reset_connection")
            session.eval_tcl("::itest::semantic::html_reset_connection")
            session.eval_tcl("::itest::semantic::compression_reset_connection")
            session.eval_tcl("::itest::semantic::httplog_reset_connection")
            session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
            session.eval_tcl("::itest::semantic::crypto_reset_connection")
            session.eval_tcl("::itest::semantic::bwc_reset_connection")
            session.eval_tcl("::itest::semantic::ipfix_reset_connection")
            session.eval_tcl("::itest::semantic::adapt_reset_connection")
            session.eval_tcl("::itest::semantic::datagram_reset_connection")
            session.eval_tcl("::itest::semantic::sctp_reset_connection")
            session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
            session.eval_tcl("::itest::semantic::l7check_reset_connection")
            session.eval_tcl("::itest::semantic::link_reset_connection")
            session.eval_tcl("::itest::semantic::name_reset_connection")
            session.eval_tcl("::itest::semantic::socks_reset_connection")
            session.eval_tcl("::itest::semantic::sdp_reset_connection")
            self._connection_open = False
            self._server_connection_open = False
            self._server_connection_detached = False
            self._connection_request_number = 0
        result["decisions"] = decision_history
        result["logs"] = log_history
        result["events_fired"] = result["events_fired"][fired_before:]
        if http_class is not None:
            result["http_class"] = {
                "outcome": http_class["result"],
                **_http_class_snapshot(session),
            }
        self._request_count += 1
        self._connection_request_number = request_number
        if retry_count:
            result["retry"] = {
                "attempts": retry_count,
                "exhausted": retry_exhausted,
            }
        if request.get("close_after"):
            close_events_before = len(
                _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
            )
            close_decisions_before = len(session.get_decisions())
            close_logs_before = len(session.get_logs())
            session.close_connection()
            session.eval_tcl("::itest::semantic::access_auto_close_session")
            close_events_after = _split_tcl_list(
                session.eval_tcl("::itest::get_fired_events")
            )
            result["events_fired"].extend(
                close_events_after[close_events_before:]
            )
            result["decisions"].extend(
                session.get_decisions()[close_decisions_before:]
            )
            result["logs"].extend(session.get_logs()[close_logs_before:])
            session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
            session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
            session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
            session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
            session.eval_tcl("::itest::semantic::stream_reset_connection")
            session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
            session.eval_tcl("::itest::semantic::rewrite_reset_connection")
            session.eval_tcl("::itest::semantic::html_reset_connection")
            session.eval_tcl("::itest::semantic::compression_reset_connection")
            session.eval_tcl("::itest::semantic::httplog_reset_connection")
            session.eval_tcl("::itest::semantic::http_control_reset")
            session.eval_tcl("::itest::semantic::http_reject_reset")
            session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
            session.eval_tcl("::itest::semantic::crypto_reset_connection")
            session.eval_tcl("::itest::semantic::bwc_reset_connection")
            session.eval_tcl("::itest::semantic::ipfix_reset_connection")
            session.eval_tcl("::itest::semantic::adapt_reset_connection")
            session.eval_tcl("::itest::semantic::datagram_reset_connection")
            session.eval_tcl("::itest::semantic::sctp_reset_connection")
            session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
            self._connection_open = False
            self._server_connection_open = False
            self._server_connection_detached = False
            self._connection_request_number = 0
        return result

    def run_request(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._call(lambda session: self._run_request_on_worker(session, request))

    @staticmethod
    def _mqtt_event_outputs(
        session: Any,
        event_name: str,
        mqtt_state: dict[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        current_packet = _mqtt_packet_from_state(mqtt_state)
        current_wire = _encode_mqtt_message(current_packet)
        outgoing_side = (
            "client"
            if event_name in {"MQTT_SERVER_INGRESS", "MQTT_CLIENT_EGRESS"}
            else "server"
        )
        response_side = "client" if event_name.startswith("MQTT_CLIENT_") else "server"
        forwarded = {
            "to": outgoing_side,
            "packet": _mqtt_public_packet(current_packet),
            "wire_hex": current_wire.hex(),
        }
        snapshot = _mqtt_tcl_dict(
            session.eval_tcl("::itest::semantic::mqtt_emissions_snapshot"),
            "emissions",
        )
        emissions: list[dict[str, Any]] = []
        for raw_operation in _split_tcl_list(snapshot.get("operations", "")):
            operation = _split_tcl_list(raw_operation)
            if len(operation) == 2 and operation[0] == "response":
                response = _mqtt_tcl_dict(operation[1], "response")
                response_wire = _encode_mqtt_message(response)
                emissions.append(
                    {
                        "kind": "response",
                        "to": response_side,
                        "packet": _mqtt_public_packet(response),
                        "wire_hex": response_wire.hex(),
                    }
                )
            elif len(operation) == 3 and operation[0] == "insert":
                insertion_packet = _mqtt_tcl_dict(operation[2], "insertion")
                insertion_wire = _encode_mqtt_message(insertion_packet)
                emissions.append(
                    {
                        "kind": "insert",
                        "position": operation[1],
                        "to": outgoing_side,
                        "packet": _mqtt_public_packet(insertion_packet),
                        "wire_hex": insertion_wire.hex(),
                    }
                )
            else:
                raise EmulatorInputError("MQTT operation state is invalid")
        return forwarded, emissions

    @staticmethod
    def _sip_tcl_bytes(session: Any, field: str) -> bytes:
        encoded = session.eval_tcl(
            f"binary encode hex $::state::sip::{field}"
        )
        try:
            return bytes.fromhex(str(encoded))
        except ValueError as exc:  # pragma: no cover - Tcl binary contract guard
            raise EmulatorInputError(f"invalid SIP {field} state") from exc

    @staticmethod
    def _sip_tcl_headers(session: Any) -> list[list[str]]:
        values = _split_tcl_list(session.eval_tcl("set ::state::sip::headers"))
        if len(values) % 2:
            raise EmulatorInputError("invalid SIP header state")
        return [
            [values[index], values[index + 1]]
            for index in range(0, len(values), 2)
        ]

    @classmethod
    def _sync_sip_sdp_state(
        cls, session: Any, packet: dict[str, Any]
    ) -> None:
        """Synchronize mutable SDP state with the SIP payload and message."""
        current_payload = cls._sip_tcl_bytes(session, "payload")
        headers = cls._sip_tcl_headers(session)
        template = packet.get("_sdp_template")
        if not _sdp_content_type(headers):
            if isinstance(template, dict):
                session.eval_tcl("::itest::semantic::sdp_reset_connection")
                packet.pop("_sdp_template", None)
            packet["_sip_payload"] = current_payload
            packet["payload"] = _decode_wire_text(current_payload)
            return

        payload_changed = current_payload != packet.get("_sip_payload", b"")
        if not isinstance(template, dict) or payload_changed:
            parsed = _parse_sdp_payload(current_payload, headers)
            if parsed is None:
                session.eval_tcl("::itest::semantic::sdp_reset_connection")
                packet.pop("_sdp_template", None)
                packet["_sip_payload"] = current_payload
                packet["payload"] = _decode_wire_text(current_payload)
                return
            packet["_sdp_template"] = parsed
            _install_sdp_state(session, parsed["state"])
            session.eval_tcl("::itest::semantic::sip_rebuild_message")
            packet["_sip_payload"] = current_payload
            packet["payload"] = _decode_wire_text(current_payload)
            return

        state = _sdp_state_from_tcl(session)
        if any(name.lower() == "o" for name, _ in state["fields"]):
            derived_session_id = _sdp_origin_session_id(state["fields"])
            if state["session_id"] != derived_session_id:
                state["session_id"] = derived_session_id
                session.eval_tcl(
                    f"set ::state::sdp::session_id "
                    f"{_tcl_quote(derived_session_id)}"
                )
        rendered_payload = _sdp_serialize(template, state)
        if rendered_payload != current_payload:
            payload_hex = rendered_payload.hex()
            session.eval_tcl(
                "set ::state::sip::payload [binary format H* "
                f"{_tcl_quote(payload_hex)}]"
            )
            session.eval_tcl("::itest::semantic::sip_rebuild_message")
            current_payload = rendered_payload
        packet["_sip_payload"] = current_payload
        packet["payload"] = _decode_wire_text(current_payload)

    @classmethod
    def _sip_output_from_tcl(cls, session: Any) -> dict[str, Any]:
        payload = cls._sip_tcl_bytes(session, "payload")
        message = cls._sip_tcl_bytes(session, "message")
        return {
            "payload_after": _decode_wire_text(payload),
            "message_after": _decode_wire_text(message),
            "wire_hex": message.hex(),
        }

    def _fire_event_on_worker(
        self,
        session: Any,
        event_name: str,
        state: dict[str, dict[str, str]],
        packet: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        session.eval_tcl("::itest::semantic::diagnostics_begin_packet")
        session.eval_tcl("::itest::semantic::tcp_clear_event_state")
        if "mqtt" in state:
            session.eval_tcl("::itest::semantic::mqtt_prepare_event")
        if "udp" in state:
            session.eval_tcl("::itest::semantic::udp_prepare_event")
        if "sctp" in state:
            session.eval_tcl("::itest::semantic::sctp_prepare_event")
        if "dhcpv4" in state or "dhcpv6" in state:
            session.eval_tcl("::itest::semantic::dhcp_prepare_event")
        if event_name in {"TDS_REQUEST", "TDS_RESPONSE"}:
            session.eval_tcl("::itest::semantic::tds_prepare_event")
        if event_name == "IKE_AUTH":
            session.eval_tcl("::itest::semantic::ike_reset_event")
        if "ftp" in state:
            session.eval_tcl("::itest::semantic::ftp_prepare_event")
        for protocol in STARTTLS_PROTOCOLS.intersection(state):
            session.eval_tcl(
                f"::itest::semantic::{protocol}_prepare_event"
            )
        for protocol in ("ntlm", "protocol_inspection"):
            if protocol in state:
                session.eval_tcl(
                    f"::itest::semantic::{protocol}_prepare_event"
                )
        if "classification" in state:
            session.eval_tcl("::itest::semantic::classification_prepare_event")
        if "category" in state:
            session.eval_tcl("::itest::semantic::category_prepare_event")
        session.eval_tcl("::itest::semantic::datagram_prepare_event")
        if "rtsp" in state:
            session.eval_tcl("::itest::semantic::rtsp_prepare_event")
        if "stream" in state or event_name == "STREAM_MATCHED":
            session.eval_tcl("::itest::semantic::stream_prepare_event")
        if "access2" in state or event_name == "ACCESS2_POLICY_EXPRESSION_EVAL":
            session.eval_tcl("::itest::semantic::access2_prepare_event")
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
        session.eval_tcl(
            "::itest::semantic::adapt_prepare_event "
            f"{_tcl_quote(event_name)}"
        )
        if event_name == "CLIENT_ACCEPTED":
            session.eval_tcl("::itest::semantic::bigtcp_prepare_connection")
        if (
            event_name not in {
                "CLIENT_ACCEPTED",
                "SERVER_ACCEPTED",
                "SERVER_CONNECTED",
                "CLIENT_CLOSED",
                "SERVER_CLOSED",
                "RULE_INIT",
            }
            and session.eval_tcl("info exists ::state::bigtcp::released") == "1"
            and session.eval_tcl("set ::state::bigtcp::released") == "1"
        ):
            return {
                "event": event_name,
                "fired": False,
                "reason": "bigtcp_passthrough",
                "events_fired": [],
                "state": {},
                "decisions": [],
                "logs": [],
            }
        if event_name in {"FIX_HEADER", "FIX_MESSAGE"} or "fix" in state:
            session.eval_tcl("::itest::semantic::fix_prepare_event")
        if event_name == "HTTP_REQUEST":
            session.eval_tcl("::itest::semantic::websso_prepare_request")
        def install_state_layer(layer: str, values: dict[str, str]) -> None:
            namespace = EVENT_STATE_NAMESPACES[layer]
            for field, value in values.items():
                if layer in {"websocket", "mqtt", "sip", "diameter", "radius", "mr", "gtp", "udp", "sctp", "dhcpv4", "dhcpv6", "ftp", "icap", "l7check", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category", "rtsp", "cache", "datagram", "tls_client", "tls_server"} and field in {"payload", "message", "authenticator"}:
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
        for layer, values in state.items():
            if layer != "datagram":
                install_state_layer(layer, values)
        session.eval_tcl("::itest::semantic::datagram_sync_from_layers")
        if "datagram" in state:
            install_state_layer("datagram", state["datagram"])
        if event_name == "CLASSIFICATION_DETECTED":
            session.eval_tcl("::itest::semantic::classification_apply_overrides")
        if "dns" in state:
            session.eval_tcl("::itest::semantic::dns_prepare_message")
        event_errors_before = len(_event_error_snapshot(session))
        fired_before = len(_split_tcl_list(session.eval_tcl("::itest::get_fired_events")))
        event_result = session.fire_event(event_name)
        tcp_notifications: list[dict[str, Any]] = []
        # Direct event injection is intentionally synchronous.  Packet replay
        # models the transport boundary, so TCP::notify remains queued until
        # a serverside connection has been established.
        tcp_notifications_ready = (
            not self._packet_trace_active or self._server_connection_open
        )
        if tcp_notifications_ready and not self._tcp_notify_dispatching:
            self._tcp_notify_dispatching = True
            try:
                notification_dispatches = 0
                while True:
                    notification_event = session.eval_tcl(
                        "::itest::semantic::tcp_notify_pop"
                    )
                    if notification_event == "":
                        break
                    if notification_dispatches >= 32:
                        raise EmulatorInputError(
                            "TCP::notify exceeded the 32-event dispatch limit"
                        )
                    notification_dispatches += 1
                    tcp_notifications.append(
                        self._fire_event_on_worker(
                            session, notification_event, {}, packet
                        )
                    )
            finally:
                self._tcp_notify_dispatching = False
        if not self._name_resolution_dispatching:
            self._name_resolution_dispatching = True
            try:
                name_resolution_dispatches = 0
                while session.eval_tcl("::itest::semantic::name_resolution_pending") == "1":
                    if name_resolution_dispatches >= 32:
                        raise EmulatorInputError(
                            "NAME::lookup exceeded the 32-event NAME_RESOLVED dispatch limit"
                        )
                    session.eval_tcl("::itest::semantic::name_resolution_clear_pending")
                    name_resolution_dispatches += 1
                    if "NAME_RESOLVED" in self._registered_events:
                        session.fire_event("NAME_RESOLVED")
            finally:
                self._name_resolution_dispatching = False
        event_errors = _event_error_snapshot(session)
        if len(event_errors) > event_errors_before:
            first_error = event_errors[event_errors_before]
            self._close_packet_connection(session)
            self._connection_request_number = 0
            raise EmulatorInputError(
                "iRule handler error in {}: {}".format(
                    first_error["event"], first_error["message"]
                )
            )
        if "sip" in state:
            session.eval_tcl("::itest::semantic::sip_rebuild_message")
            if packet is not None:
                self._sync_sip_sdp_state(session, packet)
        if "diameter" in state:
            session.eval_tcl("::itest::semantic::diameter_rebuild_message")
        if "radius" in state:
            session.eval_tcl("::itest::semantic::radius_rebuild_message")
        if "gtp" in state:
            session.eval_tcl("::itest::semantic::gtp_rebuild_message")
        fired_events = _split_tcl_list(session.eval_tcl("::itest::get_fired_events"))
        state_snapshot: dict[str, dict[str, Any]] = {}
        snapshot_layers = list(state)
        if (
            packet is not None
            and isinstance(packet.get("_sdp_template"), dict)
            and "sdp" not in snapshot_layers
        ):
            snapshot_layers.append("sdp")
        if self._route_visible and "route" not in state:
            snapshot_layers.append("route")
        for layer in snapshot_layers:
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
        mqtt_forwarded: dict[str, Any] | None = None
        mqtt_emissions: list[dict[str, Any]] = []
        if (
            event_name
            in {
                "MQTT_CLIENT_INGRESS",
                "MQTT_SERVER_INGRESS",
                "MQTT_CLIENT_DATA",
                "MQTT_SERVER_DATA",
                "MQTT_CLIENT_EGRESS",
                "MQTT_SERVER_EGRESS",
            }
            and "mqtt" in state
            and state_snapshot.get("mqtt", {}).get("type")
        ):
            mqtt_forwarded, mqtt_emissions = self._mqtt_event_outputs(
                session, event_name, state_snapshot["mqtt"]
            )
        semantic_snapshot = _semantic_snapshot(session)
        result = {
            "event": event_name,
            "fired": bool(event_result.fired),
            "reason": event_result.reason,
            "events_fired": fired_events[fired_before:],
            "notifications": tcp_notifications,
            "state": state_snapshot,
            "decisions": [
                entry if not isinstance(entry, tuple) else list(entry)
                for entry in session.get_decisions()
            ],
            "logs": [
                entry if not isinstance(entry, tuple) else list(entry)
                for entry in session.get_logs()
            ],
            "semantic": {
                "link": semantic_snapshot["link"],
                "legacy": semantic_snapshot["legacy"],
                "sideband": semantic_snapshot["sideband"],
                "ifile": semantic_snapshot["ifile"],
                "urlcat": semantic_snapshot["urlcat"],
                "session": semantic_snapshot["session"],
                "sharedvar": semantic_snapshot["sharedvar"],
                "traffic": semantic_snapshot["traffic"],
                "utilities": semantic_snapshot["utilities"],
                "diagnostics": semantic_snapshot["diagnostics"],
                "adapt": semantic_snapshot["adapt"],
                "psm": semantic_snapshot["psm"],
                "ip": semantic_snapshot["ip"],
                "http_proxy": semantic_snapshot["http_proxy"],
                "rewrite": semantic_snapshot["rewrite"],
                "html": semantic_snapshot["html"],
                "nsh": semantic_snapshot["nsh"],
                "sipalg": semantic_snapshot["sipalg"],
                "feature_controls": semantic_snapshot["feature_controls"],
                "rest": semantic_snapshot["rest"],
                "offbox": semantic_snapshot["offbox"],
                "tds": semantic_snapshot["tds"],
                "qoe": semantic_snapshot["qoe"],
                "access2": semantic_snapshot["access2"],
                "am": semantic_snapshot["am"],
            },
        }
        if semantic_snapshot["diagnostics"]["accumulate"]["suspended"]:
            result["suspended"] = True
            result["suspension"] = "accumulate"
        if mqtt_forwarded is not None:
            result["forwarded"] = mqtt_forwarded
        emissions = self._tcp_emissions(session)
        emissions.extend(self._websocket_disconnect_emissions(session, event_name))
        emissions.extend(mqtt_emissions)
        if emissions:
            result["emissions"] = emissions
        return result

    def fire_event(self, event: Any, state: Any = None) -> dict[str, Any]:
        event_name, normalised_state = _normalise_event(event, state)
        if event_name not in self._event_profiles:
            raise EmulatorInputError(f"unknown iRule event: {event_name}")

        def dispatch(session: Any) -> dict[str, Any]:
            # CLIENT_ACCEPTED starts a new client-side connection. Reset only
            # the connection-scoped network-observation layers here, before
            # installing any caller-supplied state for this event.
            if event_name == "CLIENT_ACCEPTED":
                session.eval_tcl("::itest::semantic::l7check_reset_connection")
                session.eval_tcl("::itest::semantic::link_reset_connection")
                session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
                session.eval_tcl("::itest::semantic::bwc_reset_connection")
                session.eval_tcl("::itest::semantic::ipfix_reset_connection")
                session.eval_tcl("::itest::semantic::eca_reset_connection")
                session.eval_tcl("::itest::semantic::avr_reset_connection")
                session.eval_tcl("::itest::semantic::am_reset_connection")
            result = self._fire_event_on_worker(session, event_name, normalised_state)
            if event_name == "RULE_INIT" and result.get("fired"):
                session.eval_tcl("set ::orch::_init_done 1")
            return result

        return self._call(
            dispatch
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
        elif protocol in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr", "rtsp", "ftp", "icap", "socks", "qoe", "l7check", "fix", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category"}:
            connection.update({"protocol": "6", "transport": "tcp"})
        elif protocol == "sctp":
            connection.update({"protocol": "132", "transport": "sctp"})
        elif protocol in {"udp", "dns", "radius", "dhcpv4", "dhcpv6"}:
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
        for field in ("ttl", "tos"):
            if field in packet:
                connection[field] = str(packet[field])
        return connection

    @staticmethod
    def _packet_datagram_state(packet: dict[str, Any]) -> dict[str, Any]:
        """Build the packet-facing state consumed by DATAGRAM::* commands."""
        metadata = packet.get("datagram", {})
        if not isinstance(metadata, dict):  # guarded by packet normalisation
            metadata = {}
        source = packet["source"]
        destination = packet["destination"]
        addresses = [str(source.get("address", "")), str(destination.get("address", ""))]
        inferred_version = 6 if any(":" in address for address in addresses) else 4
        protocol = (
            17
            if packet["protocol"] in {"udp", "dns", "radius", "dhcpv4", "dhcpv6"}
            or (packet["protocol"] == "sip" and packet.get("transport", "tcp") == "udp")
            else 6
            if packet["protocol"] in {
                "tcp",
                "tls",
                "http",
                "http2",
                "websocket",
                "mqtt",
                "sip",
                "diameter",
                "mr",
                "rtsp",
                "socks",
                "classification",
                "category",
                "qoe",
                "l7check",
                "fix",
            }
            else 132
            if packet["protocol"] == "sctp"
            else 0
        )
        payload = packet.get("_wire_payload")
        if not isinstance(payload, (bytes, bytearray)):
            payload = str(packet.get("payload", "")).encode("utf-8")
        tcp_flags = 0
        tcp_flag_bits = {
            "FIN": 0x01,
            "SYN": 0x02,
            "RST": 0x04,
            "PSH": 0x08,
            "ACK": 0x10,
            "URG": 0x20,
            "ECE": 0x40,
            "CWR": 0x80,
            "NS": 0x100,
        }
        for flag in packet.get("flags", []):
            tcp_flags |= tcp_flag_bits.get(str(flag).upper(), 0)
        state: dict[str, Any] = {
            "ip_version": metadata.get("ip_version", inferred_version),
            "ip_tos": metadata.get("ip_tos", packet.get("tos", 0)),
            "ip_ttl": metadata.get("ip_ttl", packet.get("ttl", 64)),
            "ip_flags": metadata.get("ip_flags", 0),
            "ip_options": _datagram_options_tcl(metadata.get("ip_options", [])),
            "ip6_hop_limit": metadata.get(
                "ip6_hop_limit", packet.get("ttl", 64)
            ),
            "ip6_options": _datagram_options_tcl(metadata.get("ip6_options", [])),
            "l2_dest": metadata.get("l2_dest", ""),
            "protocol": protocol,
            "tcp_flags": metadata.get("tcp_flags", tcp_flags),
            "tcp_window": metadata.get("tcp_window", 0),
            "tcp_options": _datagram_options_tcl(metadata.get("tcp_options", [])),
            "payload": bytes(payload),
            "payload_length": len(payload),
            "dns_id": metadata.get("dns_id", packet.get("id", 0)),
            "dns_qr": metadata.get("dns_qr", packet.get("qr", 0)),
            "dns_opcode": metadata.get("dns_opcode", packet.get("opcode", "QUERY")),
            "dns_qdcount": metadata.get("dns_qdcount", packet.get("qdcount", 0)),
            "dns_ancount": metadata.get("dns_ancount", packet.get("ancount", 0)),
            "dns_nscount": metadata.get("dns_nscount", packet.get("nscount", 0)),
            "dns_arcount": metadata.get("dns_arcount", packet.get("arcount", 0)),
        }
        for field in DATAGRAM_OPTION_FIELDS:
            if field in metadata:
                state[field] = _datagram_options_tcl(metadata[field])
        for field, value in state.items():
            if field != "payload":
                state[field] = str(value)
        return state

    @staticmethod
    def _packet_event_state(packet: dict[str, Any]) -> dict[str, dict[str, str]]:
        state: dict[str, dict[str, str]] = {}
        connection = EmulatorSession._packet_connection_state(packet)
        if connection:
            state["connection"] = connection
        state["datagram"] = EmulatorSession._packet_datagram_state(packet)
        protocol = packet["protocol"]
        direction = packet["direction"]
        if protocol == "tls":
            layer = "tls_client" if direction == "client_to_server" else "tls_server"
            tls_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS[layer] - {"handshake_done"}:
                if field in packet:
                    tls_state[field] = _packet_scalar(packet[field], field)
            if "payload" in packet:
                payload = packet["payload"].encode("utf-8")
                tls_state["payload"] = payload
                tls_state["payload_length"] = str(len(payload))
            if packet.get("type") in {"handshake", "server_handshake"}:
                tls_state["handshake_done"] = "1"
            state[layer] = tls_state
        elif protocol == "udp":
            source = packet.get("source", {})
            destination = packet.get("destination", {})
            if direction == "client_to_server":
                client, server = source, destination
                local, remote = destination, source
            else:
                client, server = destination, source
                local, remote = source, destination
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            udp_state: dict[str, Any] = {
                "payload": bytes(payload),
                "payload_length": str(len(payload)),
                "client_port": str(client.get("port", 0)),
                "server_port": str(server.get("port", 0)),
                "local_port": str(local.get("port", 0)),
                "remote_port": str(remote.get("port", 0)),
            }
            state["udp"] = udp_state
        elif protocol == "icap":
            icap_state: dict[str, Any] = {}
            for field in EVENT_STATE_FIELDS["icap"] - {"headers", "payload"}:
                if field in packet:
                    icap_state[field] = _packet_scalar(packet[field], field)
            headers = packet.get("headers", {})
            icap_state["headers"] = " ".join(
                _tcl_quote(item)
                for name, value in headers.items()
                for item in (name, value)
            )
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            icap_state["payload"] = bytes(payload)
            icap_state["payload_length"] = str(len(payload))
            state["icap"] = icap_state
        elif protocol in STARTTLS_PROTOCOLS:
            protocol_state: dict[str, Any] = {}
            for field in EVENT_STATE_FIELDS[protocol] - {"payload"}:
                if field in packet:
                    protocol_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            protocol_state["payload"] = bytes(payload)
            protocol_state["payload_length"] = str(len(payload))
            state[protocol] = protocol_state
        elif protocol == "ntlm":
            ntlm_state: dict[str, Any] = {}
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            ntlm_state["payload"] = bytes(payload)
            ntlm_state["payload_length"] = str(len(payload))
            state["ntlm"] = ntlm_state
            if isinstance(packet.get("eca"), dict):
                state["eca"] = {
                    field: _packet_scalar(value, f"eca.{field}")
                    for field, value in packet["eca"].items()
                }
        elif protocol == "protocol_inspection":
            inspection_state: dict[str, Any] = {}
            for field in ("ids", "matched"):
                if field in packet:
                    inspection_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            inspection_state["payload"] = bytes(payload)
            inspection_state["payload_length"] = str(len(payload))
            state["protocol_inspection"] = inspection_state
        elif protocol == "classification":
            classification_state: dict[str, Any] = {}
            for packet_field, state_field in (
                ("app", "app"),
                ("category", "category"),
                ("classification_protocol", "protocol"),
                ("detected", "detected"),
                ("deferred", "deferred"),
                ("result", "result"),
                ("urlcat", "urlcat"),
                ("username", "username"),
            ):
                if packet_field in packet:
                    classification_state[state_field] = _packet_scalar(
                        packet[packet_field], packet_field
                    )
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            classification_state["payload"] = bytes(payload)
            classification_state["payload_length"] = str(len(payload))
            state["classification"] = classification_state
        elif protocol == "category":
            category_state: dict[str, Any] = {}
            for packet_field, state_field in (
                ("analytics", "analytics"),
                ("categories", "categories"),
                ("detected", "detected"),
                ("matchtype", "matchtype"),
                ("matched", "matched"),
                ("safesearch", "safesearch"),
                ("url", "url"),
            ):
                if packet_field in packet:
                    category_state[state_field] = _packet_scalar(
                        packet[packet_field], packet_field
                    )
            category_state["lookup_url"] = str(packet.get("url", ""))
            filetype = packet.get("filetype", {})
            if isinstance(filetype, dict):
                if "mimetype" in filetype:
                    category_state["filetype_mimetype"] = str(filetype["mimetype"])
                if "mimesubtype" in filetype:
                    category_state["filetype_mimesubtype"] = str(
                        filetype["mimesubtype"]
                    )
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            category_state["payload"] = bytes(payload)
            category_state["payload_length"] = str(len(payload))
            state["category"] = category_state
        elif protocol == "ftp":
            ftp_state: dict[str, Any] = {}
            for field in EVENT_STATE_FIELDS["ftp"] - {"payload"}:
                if field in packet:
                    ftp_state[field] = _packet_scalar(packet[field], field)
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            ftp_state["payload"] = bytes(payload)
            ftp_state["payload_length"] = str(len(payload))
            state["ftp"] = ftp_state
        elif protocol == "tds":
            tds_state: dict[str, Any] = {}
            for field in EVENT_STATE_FIELDS["tds"]:
                if field in packet:
                    tds_state[field] = _packet_scalar(packet[field], field)
            state["tds"] = tds_state
        elif protocol == "qoe":
            state["qoe"] = {
                field: _packet_scalar(value, f"qoe.{field}")
                for field, value in packet["qoe"].items()
            }
        elif protocol == "l7check":
            l7check_state: dict[str, Any] = {}
            if "l7_protocol" in packet:
                l7check_state["protocol"] = packet["l7_protocol"]
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            l7check_state["payload"] = bytes(payload)
            l7check_state["payload_length"] = str(len(payload))
            state["l7check"] = l7check_state
        elif protocol == "fix":
            state["fix"] = dict(packet["fix"])
        elif protocol in {"dhcpv4", "dhcpv6"}:
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            version = "4" if protocol == "dhcpv4" else "6"
            state["dhcp"] = {"version": version}
            common_state = {
                "payload": bytes(payload),
                "payload_length": str(len(payload)),
            }
            if protocol == "dhcpv4":
                dhcp_state: dict[str, Any] = {
                    **common_state,
                    "chaddr": str(packet.get("chaddr", "")),
                    "ciaddr": str(packet.get("ciaddr", "0.0.0.0")),
                    "drop": str(packet.get("drop", "0")),
                    "giaddr": str(packet.get("giaddr", "0.0.0.0")),
                    "hlen": str(packet.get("hlen", 6)),
                    "hops": str(packet.get("hops", 0)),
                    "htype": str(packet.get("htype", 1)),
                    "len": str(packet.get("len", len(payload))),
                    "opcode": str(packet.get("opcode", 1)),
                    "options": _dhcp_options_tcl(packet.get("options", {})),
                    "reject": str(packet.get("reject", "0")),
                    "secs": str(packet.get("secs", 0)),
                    "siaddr": str(packet.get("siaddr", "0.0.0.0")),
                    "type": str(packet.get("type", "DISCOVER")),
                    "xid": str(packet.get("xid", 0)),
                    "yiaddr": str(packet.get("yiaddr", "0.0.0.0")),
                }
                state["dhcpv4"] = dhcp_state
            else:
                dhcp_state = {
                    **common_state,
                    "drop": str(packet.get("drop", "0")),
                    "hop_count": str(packet.get("hop_count", 0)),
                    "len": str(packet.get("len", len(payload))),
                    "link_address": str(packet.get("link_address", "::")),
                    "msg_type": str(packet.get("msg_type", "SOLICIT")),
                    "options": _dhcp_options_tcl(packet.get("options", {})),
                    "peer_address": str(packet.get("peer_address", "::")),
                    "reject": str(packet.get("reject", "0")),
                    "transaction_id": str(packet.get("transaction_id", "000000")),
                }
                state["dhcpv6"] = dhcp_state
        elif protocol == "sctp":
            source = packet.get("source", {})
            destination = packet.get("destination", {})
            if direction == "client_to_server":
                client, server = source, destination
                local, remote = destination, source
            else:
                client, server = destination, source
                local, remote = source, destination
            payload = packet.get("_wire_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            sctp_state: dict[str, Any] = {
                "payload": bytes(payload),
                "payload_length": str(len(payload)),
                "client_port": str(client.get("port", 0)),
                "server_port": str(server.get("port", 0)),
                "local_port": str(local.get("port", 0)),
                "remote_port": str(remote.get("port", 0)),
                "mss": str(packet.get("mss", 1460)),
                "ppi": str(packet.get("ppi", 0)),
                "rto_initial": str(packet.get("rto_initial", 1000)),
                "rto_max": str(packet.get("rto_max", 60000)),
                "rto_min": str(packet.get("rto_min", 100)),
                "sack_timeout": str(packet.get("sack_timeout", 200)),
            }
            state["sctp"] = sctp_state
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
            dns_state["tsig_present"] = _packet_scalar(
                packet.get("tsig_present", False), "tsig_present"
            )
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
        elif protocol == "rtsp":
            rtsp_state: dict[str, str] = {}
            for field in EVENT_STATE_FIELDS["rtsp"]:
                if field in {"headers", "response_headers", "payload"}:
                    continue
                if field in packet:
                    rtsp_state[field] = _packet_scalar(packet[field], field)
            headers = packet.get("headers", packet.get("response_headers", {}))
            rtsp_state["headers"] = " ".join(
                _tcl_quote(item) for pair in headers.items() for item in pair
            )
            if packet.get("type") == "response":
                response_headers = packet.get("response_headers", headers)
                rtsp_state["response_headers"] = " ".join(
                    _tcl_quote(item)
                    for pair in response_headers.items()
                    for item in pair
                )
            payload = packet.get("_rtsp_payload")
            if not isinstance(payload, (bytes, bytearray)):
                payload = str(packet.get("payload", "")).encode("utf-8")
            rtsp_state["payload"] = bytes(payload)
            rtsp_state["payload_length"] = str(len(payload))
            state["rtsp"] = rtsp_state
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
            sdp_template = packet.get("_sdp_template")
            if isinstance(sdp_template, dict):
                state["sdp"] = _sdp_event_layer(sdp_template["state"])
        elif protocol == "socks":
            socks_state: dict[str, Any] = {
                "version": str(packet.get("version", "5")),
                "allowed": str(packet.get("allowed", "1")),
                "destination_host": str(packet.get("destination_host", "")),
                "destination_port": str(packet.get("destination_port", 0)),
            }
            state["socks"] = socks_state
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
        if (
            protocol in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "diameter", "mr", "rtsp", "ftp", "icap", "socks", "tds", "qoe"}
            or (protocol == "sip" and packet.get("transport", "tcp") == "tcp")
        ):
            state["tcp"] = {}
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
        if isinstance(packet.get("_sdp_template"), dict):
            state["sdp"] = _sdp_event_layer(_sdp_state_from_tcl(session))
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
            "passthrough": "CLIENTSSL_PASSTHROUGH",
            "server_hello_send": "CLIENTSSL_SERVERHELLO_SEND",
        }
        server_events = {
            "client_hello_send": "SERVERSSL_CLIENTHELLO_SEND",
            "server_hello": "SERVERSSL_SERVERHELLO",
            "server_cert": "SERVERSSL_SERVERCERT",
            "server_handshake": "SERVERSSL_HANDSHAKE",
            "server_data": "SERVERSSL_DATA",
        }
        events = client_events if packet["direction"] == "client_to_server" else server_events
        return events[packet["type"]]

    @staticmethod
    def _tls_plaintext_payload(packet: dict[str, Any]) -> bytes:
        """Return structured TLS plaintext supplied by the test scenario."""
        payload = packet.get("payload", "")
        if not isinstance(payload, str):  # pragma: no cover - normalizer guard
            raise EmulatorInputError("TLS plaintext payload must be a string")
        try:
            return payload.encode("utf-8")
        except UnicodeEncodeError as exc:  # pragma: no cover - normalizer guard
            raise EmulatorInputError("TLS plaintext payload must be valid UTF-8") from exc

    @staticmethod
    def _ssl_payload_from_tcl(session: Any, side: str) -> bytes:
        if side not in {"client", "server"}:
            raise EmulatorInputError("SSL payload side must be client or server")
        encoded = session.eval_tcl(
            f"binary encode hex $::state::tls::{side}::payload"
        )
        try:
            return bytes.fromhex(str(encoded))
        except ValueError as exc:  # pragma: no cover - Tcl binary contract guard
            raise EmulatorInputError("invalid SSL payload state") from exc

    @staticmethod
    def _sctp_payload_from_tcl(session: Any) -> bytes:
        encoded = session.eval_tcl("binary encode hex $::state::sctp::payload")
        try:
            return bytes.fromhex(str(encoded))
        except ValueError as exc:  # pragma: no cover - Tcl binary contract guard
            raise EmulatorInputError("invalid SCTP payload state") from exc

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
        direction = event["direction"]
        if event["kind"] == "control":
            existing = self._http2_streams.get(stream_id)
            if existing is not None:
                existing["control_frames"].append(self._http2_trace_event(event))
            if event["frame_type"] == "RST_STREAM":
                self._http2_streams.pop(stream_id, None)
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
                "request_trailers": {},
                "response_trailers": {},
                "response_informational": [],
                "control_frames": [],
            },
        )
        if event["kind"] == "headers":
            pseudo_headers = dict(event["pseudo_headers"])
            if direction == "client_to_server":
                if context["request_headers"] is None:
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
                    if context["request_end"]:
                        raise EmulatorInputError(
                            f"HTTP/2 stream {stream_id} has headers after request end"
                        )
                    if pseudo_headers or not event["end_stream"]:
                        raise EmulatorInputError(
                            f"HTTP/2 request trailers on stream {stream_id} must be regular headers with END_STREAM"
                        )
                    context["request_trailers"] = dict(event["headers"])
                    context["request_end"] = True
            else:
                if context["response_headers"] is None:
                    status = pseudo_headers.get(":status")
                    if status is None or not status.isdigit() or not 100 <= int(status) <= 999:
                        raise EmulatorInputError(
                            f"HTTP/2 response stream {stream_id} has an invalid :status"
                        )
                    status_code = int(status)
                    if status_code < 200:
                        if event["end_stream"]:
                            raise EmulatorInputError(
                                f"HTTP/2 informational response on stream {stream_id} cannot end the stream"
                            )
                        context["response_informational"].append(
                            {"status": status_code, "headers": dict(event["headers"])}
                        )
                    else:
                        context["response_headers"] = {
                            "status": status_code,
                            "headers": dict(event["headers"]),
                        }
                        context["response_end"] = bool(event["end_stream"])
                        context["response_pseudo_headers"] = pseudo_headers
                else:
                    if pseudo_headers or not event["end_stream"]:
                        raise EmulatorInputError(
                            f"HTTP/2 response trailers on stream {stream_id} must be regular headers with END_STREAM"
                        )
                    context["response_trailers"] = dict(event["headers"])
                    context["response_end"] = True
        elif event["kind"] == "data":
            if direction == "client_to_server":
                if context["request_headers"] is None:
                    raise EmulatorInputError(
                        f"HTTP/2 DATA arrived before request headers on stream {stream_id}"
                    )
                if context["request_end"]:
                    raise EmulatorInputError(
                        f"HTTP/2 request stream {stream_id} received DATA after END_STREAM"
                    )
                context["request_body"].extend(event["data"])
                context["request_end"] = bool(event["end_stream"])
            else:
                if context["response_headers"] is None:
                    raise EmulatorInputError(
                        f"HTTP/2 DATA arrived before response headers on stream {stream_id}"
                    )
                if context["response_end"]:
                    raise EmulatorInputError(
                        f"HTTP/2 response stream {stream_id} received DATA after END_STREAM"
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
        if context["request_trailers"]:
            result["request"]["trailers"] = dict(context["request_trailers"])
        if context["response_trailers"]:
            result["response"]["trailers"] = dict(context["response_trailers"])
        if context["response_informational"]:
            result["response"]["informational"] = list(context["response_informational"])
        if context["control_frames"]:
            result["http2"]["control_frames"] = list(context["control_frames"])
        self._http2_streams.pop(stream_id, None)
        return result

    def _configure_packet_connection(self, session: Any, packet: dict[str, Any]) -> None:
        """Make packet endpoints visible to the upstream HTTP orchestrator."""
        if packet["protocol"] not in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr", "gtp", "rtsp", "ftp", "icap", "socks", "qoe", "l7check", "fix", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category"}:
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

    @staticmethod
    def _packet_byte_count(packet: dict[str, Any]) -> int:
        """Return the adapter's byte-count boundary for one observed packet."""
        wire_length = packet.get("_wire_length")
        if isinstance(wire_length, int) and wire_length >= 0:
            return wire_length
        for field in ("_wire_payload", "_mqtt_payload", "_http2_payload", "_rtsp_payload"):
            payload = packet.get(field)
            if isinstance(payload, (bytes, bytearray)):
                return len(payload)
        payload = packet.get("payload")
        if isinstance(payload, str):
            return len(payload.encode("utf-8"))
        for field in ("message_hex", "payload_hex"):
            value = packet.get(field)
            if isinstance(value, str) and len(value) % 2 == 0:
                try:
                    return len(bytes.fromhex(value))
                except ValueError:
                    pass
        return 0

    def _record_ip_packet(self, session: Any, packet: dict[str, Any]) -> None:
        """Record one real trace packet before protocol adapters emit events."""
        if packet.get("_synthetic_coalesced"):
            return
        if not self._ip_connection_initialized:
            session.eval_tcl("::itest::semantic::ip_reset_connection")
            self._ip_connection_initialized = True
            self._ip_connection_start_timestamp = None
            self._ip_age_ms = 0
            self._ip_virtual_age_ms = 0

        timestamp = packet.get("timestamp")
        if timestamp is None:
            age_ms = self._ip_virtual_age_ms
            self._ip_virtual_age_ms += 1
        else:
            timestamp_value = float(timestamp)
            if self._ip_connection_start_timestamp is None:
                self._ip_connection_start_timestamp = timestamp_value
                age_ms = 0
            else:
                age_ms = max(
                    0,
                    int(round((timestamp_value - self._ip_connection_start_timestamp) * 1000)),
                )
        self._ip_age_ms = max(self._ip_age_ms, age_ms)
        command = (
            "::itest::semantic::ip_record_packet "
            f"{_tcl_quote(packet['direction'])} "
            f"{_tcl_quote(str(self._packet_byte_count(packet)))} "
            f"{_tcl_quote(str(self._ip_age_ms))}"
        )
        if "hops" in packet:
            command += f" {_tcl_quote(str(packet['hops']))}"
        session.eval_tcl(command)

    def _activate_packet_server_connection(
        self,
        session: Any,
        packet: dict[str, Any],
        events: list[dict[str, Any]],
        *,
        emit_init: bool = False,
    ) -> None:
        """Emit the server-side initialization and connection lifecycle once."""
        if self._server_connection_open:
            return
        self._configure_packet_connection(session, packet)
        connection_state = {"connection": self._packet_connection_state(packet)}
        if emit_init:
            events.append(
                self._fire_event_on_worker(session, "SERVER_INIT", connection_state)
            )
        self._server_connection_open = True
        try:
            events.append(
                self._fire_event_on_worker(
                    session, "SERVER_CONNECTED", connection_state
                )
            )
        except BaseException:
            self._server_connection_open = False
            raise

    def _activate_packet_connection(
        self, session: Any, packet: dict[str, Any], events: list[dict[str, Any]]
    ) -> None:
        if self._connection_open or packet["protocol"] not in {"tcp", "udp", "sctp", "dhcpv4", "dhcpv6", "ftp", "icap", "socks", "qoe", "l7check", "fix", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category", "tls", "http", "http2", "websocket", "mqtt", "sip", "diameter", "mr", "gtp", "rtsp"}:
            return
        self._configure_packet_connection(session, packet)
        session.eval_tcl("::itest::semantic::ws_reset_connection")
        session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
        session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
        session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
        session.eval_tcl("::itest::semantic::mqtt_reset_connection")
        session.eval_tcl("::itest::semantic::sip_reset_connection")
        session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
        session.eval_tcl("::itest::semantic::diameter_reset_connection")
        session.eval_tcl("::itest::semantic::mr_reset_connection")
        session.eval_tcl("::itest::semantic::gtp_reset_connection")
        session.eval_tcl("::itest::semantic::rtsp_reset_connection")
        session.eval_tcl("::itest::semantic::psm_reset_connection")
        session.eval_tcl("::itest::semantic::dosl7_reset_connection")
        session.eval_tcl("::itest::semantic::asm_reset_connection")
        session.eval_tcl("::itest::semantic::botdefense_reset_connection")
        session.eval_tcl("::itest::semantic::antifraud_reset_connection")
        session.eval_tcl("::itest::semantic::auth_reset_connection")
        session.eval_tcl("::itest::semantic::aaa_reset_connection")
        session.eval_tcl("::itest::semantic::access_reset_connection")
        session.eval_tcl("::itest::semantic::am_reset_connection")
        session.eval_tcl("::itest::semantic::flow_reset_connection")
        session.eval_tcl("::itest::semantic::acl_reset_connection")
        session.eval_tcl("::itest::semantic::lsn_reset_connection")
        session.eval_tcl("::itest::semantic::xlat_reset_connection")
        session.eval_tcl("::itest::semantic::pcp_reset_connection")
        session.eval_tcl("::itest::semantic::psc_reset_connection")
        session.eval_tcl("::itest::semantic::pem_reset_connection")
        session.eval_tcl("::itest::semantic::connector_reset_connection")
        session.eval_tcl("::itest::semantic::wam_reset_connection")
        session.eval_tcl("::itest::semantic::vdi_reset_connection")
        session.eval_tcl("::itest::semantic::tap_reset_connection")
        session.eval_tcl("::itest::semantic::ssl_reset_connection")
        session.eval_tcl("::itest::semantic::stream_reset_connection")
        session.eval_tcl("::itest::semantic::route_reset_connection")
        session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
        session.eval_tcl("::itest::semantic::rewrite_reset_connection")
        session.eval_tcl("::itest::semantic::html_reset_connection")
        session.eval_tcl("::itest::semantic::compression_reset_connection")
        session.eval_tcl("::itest::semantic::httplog_reset_connection")
        session.eval_tcl("::itest::semantic::oneconnect_reset_connection")
        session.eval_tcl("::itest::semantic::crypto_reset_connection")
        session.eval_tcl("::itest::semantic::bwc_reset_connection")
        session.eval_tcl("::itest::semantic::ipfix_reset_connection")
        session.eval_tcl("::itest::semantic::adapt_reset_connection")
        session.eval_tcl("::itest::semantic::datagram_reset_connection")
        session.eval_tcl("::itest::semantic::sctp_reset_connection")
        session.eval_tcl("::itest::semantic::l7check_reset_connection")
        session.eval_tcl("::itest::semantic::link_reset_connection")
        session.eval_tcl("::itest::semantic::name_reset_connection")
        session.eval_tcl("::itest::semantic::socks_reset_connection")
        session.eval_tcl("::itest::semantic::sdp_reset_connection")
        session.eval_tcl("::itest::semantic::sip_reset_connection")
        session.eval_tcl("::itest::semantic::dhcp_reset_connection")
        session.eval_tcl("::itest::semantic::ftp_reset_connection")
        session.eval_tcl("::itest::semantic::imap_reset_connection")
        session.eval_tcl("::itest::semantic::pop3_reset_connection")
        session.eval_tcl("::itest::semantic::ldap_reset_connection")
        session.eval_tcl("::itest::semantic::smtps_reset_connection")
        session.eval_tcl("::itest::semantic::ntlm_reset_connection")
        session.eval_tcl("::itest::semantic::eca_reset_connection")
        session.eval_tcl("::itest::semantic::avr_reset_connection")
        session.eval_tcl("::itest::semantic::protocol_inspection_reset_connection")
        session.eval_tcl("::itest::semantic::classification_reset_connection")
        session.eval_tcl("::itest::semantic::category_reset_connection")
        session.eval_tcl("::itest::semantic::icap_reset_connection")
        session.eval_tcl("::itest::semantic::udp_reset_connection")
        session.eval_tcl("::itest::semantic::tcp_reset_transport")
        # RULE_INIT belongs to the loaded iRule/TMM lifetime, not to each
        # client connection. The HTTP orchestrator already owns this flag;
        # consult it so packet replay and HTTP replay share one lifecycle.
        if session.eval_tcl("set ::orch::_init_done") != "1":
            events.append(self._fire_event_on_worker(session, "RULE_INIT", {}))
            session.eval_tcl("set ::orch::_init_done 1")
        packet_has_tcp_layer = (
            packet["protocol"] in {"tcp", "tls", "http", "http2", "websocket", "mqtt", "diameter", "mr", "rtsp", "ftp", "socks", *STARTTLS_PROTOCOLS, "ntlm", "protocol_inspection", "classification", "category"}
            or (packet["protocol"] == "sip" and packet.get("transport", "tcp") == "tcp")
            or packet["protocol"] in {"qoe", "l7check", "fix"}
        )
        accepted_state = (
            self._packet_event_state(packet)
            if packet["protocol"] in {"udp", "sctp", "dhcpv4", "dhcpv6"} or packet_has_tcp_layer
            else {"connection": self._packet_connection_state(packet)}
        )
        if any(str(profile).upper() == "FLOW" for profile in self._profiles):
            events.append(self._fire_event_on_worker(session, "FLOW_INIT", accepted_state))
        events.append(
            self._fire_event_on_worker(
                session, "CLIENT_ACCEPTED", accepted_state
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
        session.eval_tcl("::itest::semantic::sharedvar_reset_connection")
        session.eval_tcl("::itest::semantic::traffic_intents_reset_connection")
        session.eval_tcl("::itest::semantic::diagnostics_reset_connection")
        session.eval_tcl("::itest::semantic::legacy_fixture_reset_connection")
        session.eval_tcl("::itest::semantic::bigtcp_prepare_connection")
        session.eval_tcl("::itest::semantic::psm_reset_connection")
        session.eval_tcl("::itest::semantic::dosl7_reset_connection")
        session.eval_tcl("::itest::semantic::asm_reset_connection")
        session.eval_tcl("::itest::semantic::botdefense_reset_connection")
        session.eval_tcl("::itest::semantic::antifraud_reset_connection")
        session.eval_tcl("::itest::semantic::auth_reset_connection")
        session.eval_tcl("::itest::semantic::aaa_reset_connection")
        session.eval_tcl("::itest::semantic::access_reset_connection")
        session.eval_tcl("::itest::semantic::am_reset_connection")
        session.eval_tcl("::itest::semantic::flow_reset_connection")
        session.eval_tcl("::itest::semantic::acl_reset_connection")
        session.eval_tcl("::itest::semantic::lsn_reset_connection")
        session.eval_tcl("::itest::semantic::xlat_reset_connection")
        session.eval_tcl("::itest::semantic::pcp_reset_connection")
        session.eval_tcl("::itest::semantic::psc_reset_connection")
        session.eval_tcl("::itest::semantic::pem_reset_connection")
        session.eval_tcl("::itest::semantic::connector_reset_connection")
        session.eval_tcl("::itest::semantic::wam_reset_connection")
        session.eval_tcl("::itest::semantic::vdi_reset_connection")
        session.eval_tcl("::itest::semantic::tap_reset_connection")
        session.eval_tcl("::itest::semantic::ssl_reset_connection")
        session.eval_tcl("::itest::semantic::udp_reset_connection")
        session.eval_tcl("::itest::semantic::datagram_reset_connection")
        session.eval_tcl("::itest::semantic::sctp_reset_connection")
        session.eval_tcl("::itest::semantic::l7check_reset_connection")
        session.eval_tcl("::itest::semantic::link_reset_connection")
        session.eval_tcl("::itest::semantic::name_reset_connection")
        session.eval_tcl("::itest::semantic::socks_reset_connection")
        session.eval_tcl("::itest::semantic::sdp_reset_connection")
        session.eval_tcl("::itest::semantic::feature_controls_reset_connection")
        session.eval_tcl("::itest::semantic::dhcp_reset_connection")
        session.eval_tcl("::itest::semantic::ftp_reset_connection")
        session.eval_tcl("::itest::semantic::icap_reset_connection")
        session.eval_tcl("::itest::semantic::imap_reset_connection")
        session.eval_tcl("::itest::semantic::pop3_reset_connection")
        session.eval_tcl("::itest::semantic::ldap_reset_connection")
        session.eval_tcl("::itest::semantic::smtps_reset_connection")
        session.eval_tcl("::itest::semantic::ntlm_reset_connection")
        session.eval_tcl("::itest::semantic::eca_reset_connection")
        session.eval_tcl("::itest::semantic::avr_reset_connection")
        session.eval_tcl("::itest::semantic::protocol_inspection_reset_connection")
        session.eval_tcl("::itest::semantic::classification_reset_connection")
        session.eval_tcl("::itest::semantic::category_reset_connection")
        session.eval_tcl("::itest::semantic::rtsp_reset_connection")
        session.eval_tcl("::itest::semantic::tcp_reset_transport")
        session.eval_tcl("::itest::semantic::http_proxy_reset_connection")
        session.eval_tcl("::itest::semantic::rewrite_reset_connection")
        session.eval_tcl("::itest::semantic::html_reset_connection")
        session.eval_tcl("::itest::semantic::compression_reset_connection")
        session.eval_tcl("::itest::semantic::httplog_reset_connection")
        self._packet_streams.clear()
        self._stream_buffers = {"client": b"", "server": b""}
        self._http2_decoder = None
        self._http2_streams.clear()
        self._http2_tcp_active = False
        self._tcp_buffers = {"client": "", "server": ""}
        self._sctp_buffers = {"client": b"", "server": b""}
        self._ssl_buffers = {"client": b"", "server": b""}
        self._websocket_raw_active = False
        self._ip_connection_initialized = False
        self._ip_connection_start_timestamp = None
        self._ip_age_ms = 0
        self._ip_virtual_age_ms = 0
        self._connection_open = False
        self._server_connection_open = False
        self._server_connection_detached = False

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

    def _maybe_fire_stream_match(
        self, session: Any, packet: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, bytes | None, bytes | None]:
        """Run one bounded stream-profile match against a TCP packet."""
        if not any(str(profile).upper() == "STREAM" for profile in self._profiles):
            return None, None, None
        expression = session.eval_tcl("set ::state::stream::expression")
        pairs = _stream_expression_pairs(expression)
        if not pairs or session.eval_tcl("set ::state::stream::enabled") != "1":
            return None, None, None
        encoding = session.eval_tcl("set ::state::stream::encoding")
        compiled_pairs: list[tuple[bytes, bytes]] = []
        for match, replacement in pairs:
            match_bytes = _stream_value_bytes(match, encoding)
            replacement_bytes = _stream_value_bytes(replacement, encoding)
            if not match_bytes or replacement_bytes is None:
                continue
            compiled_pairs.append((match_bytes, replacement_bytes))
        if not compiled_pairs:
            return None, None, None

        side = "client" if packet["direction"] == "client_to_server" else "server"
        wire_payload = packet.get("_wire_payload")
        if not isinstance(wire_payload, (bytes, bytearray)):
            wire_payload = str(packet.get("payload", "")).encode("utf-8")
        payload = bytes(wire_payload)
        if not payload:
            return None, None, None
        if len(payload) > STREAM_MAX_BYTES:
            raise EmulatorInputError(
                f"TCP stream payload exceeds {STREAM_MAX_BYTES // (1024 * 1024)} MiB"
            )
        try:
            max_matchsize = int(session.eval_tcl("set ::state::stream::max_matchsize"))
        except (TypeError, ValueError):
            max_matchsize = 4096
        max_matchsize = max(1, min(max_matchsize, STREAM_MAX_BYTES))
        retain = max_matchsize - 1
        prefix = self._stream_buffers[side][-retain:] if retain else b""
        candidate = prefix + payload
        selected: tuple[int, bytes, bytes] | None = None
        for match_bytes, replacement_bytes in compiled_pairs:
            if len(match_bytes) > max_matchsize:
                continue
            position = candidate.find(match_bytes)
            if position >= 0 and (selected is None or position < selected[0]):
                selected = (position, match_bytes, replacement_bytes)
        if selected is None:
            self._stream_buffers[side] = candidate[-retain:] if retain else b""
            return None, None, None

        position, match_bytes, _ = selected
        self._stream_buffers[side] = candidate[
            position + len(match_bytes) :
        ][-retain:] if retain else b""
        match_text = _decode_wire_text(match_bytes)
        event_state = self._packet_event_state(packet)
        event_state["stream"] = {
            "line": _decode_wire_text(candidate),
            "match": match_text,
        }
        event_result = self._fire_event_on_worker(
            session, "STREAM_MATCHED", event_state
        )
        stream_state = event_result.get("state", {}).get("stream", {})
        replacement_requested = stream_state.get("replacement_requested") == "1"
        replacement = stream_state.get("replacement", "")
        replacement_bytes = _stream_value_bytes(replacement, encoding)
        if not replacement_requested or replacement_bytes is None:
            return event_result, None, match_bytes
        transformed = (
            candidate[:position]
            + replacement_bytes
            + candidate[position + len(match_bytes) :]
        )
        if position >= len(prefix):
            return event_result, transformed[len(prefix) :], match_bytes
        return event_result, None, match_bytes

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
        previous_packet_trace_active = self._packet_trace_active
        self._packet_trace_active = True
        try:
            return self._run_packet_trace_body_on_worker(session, packets)
        finally:
            self._packet_trace_active = previous_packet_trace_active

    def _run_packet_trace_body_on_worker(
        self, session: Any, packets: list[dict[str, Any]]
    ) -> dict[str, Any]:
        session.eval_tcl("::itest::semantic::event_errors_reset")
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

        def finish_packet_connection(packet: dict[str, Any], entry: dict[str, Any], at_index: int) -> None:
            """Apply FIN/RST lifecycle events before a protocol branch returns."""
            if not set(packet.get("flags", [])).intersection({"FIN", "RST"}):
                return
            finish_http(at_index=at_index)
            event_name = (
                "CLIENT_CLOSED"
                if packet["direction"] == "client_to_server"
                else "SERVER_CLOSED"
            )
            entry["events"].append(
                self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
            )
            self._close_packet_connection(session)

        packet_queue = list(enumerate(packets))
        queue_index = 0
        while queue_index < len(packet_queue):
            index, original_packet = packet_queue[queue_index]
            queue_index += 1
            if original_packet["protocol"] == "event":
                packet = original_packet
                buffered_bytes = 0
            else:
                self._record_ip_packet(session, original_packet)
                packet = original_packet
                packet, buffered_bytes = self._reassemble_packet(packet, index)
            if packet is not None:
                coalesced_packets = packet.pop("_coalesced_packets", [])
                if coalesced_packets:
                    synthetic_packets = []
                    for coalesced_packet in coalesced_packets:
                        coalesced_packet = dict(coalesced_packet)
                        coalesced_packet["_synthetic_coalesced"] = True
                        synthetic_packets.append(coalesced_packet)
                    packet_queue[queue_index:queue_index] = [
                        (index, coalesced) for coalesced in synthetic_packets
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
                    "hops",
                    "ttl",
                    "tos",
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
                "event",
                "state",
                "flags",
                "type",
                "message_type",
                "method",
                "uri",
                "http_class",
                "headers",
                "status",
                "response_headers",
                "sni",
                "initial_session_id",
                "nextproto",
                "session_secret",
                "tls13_client_app_secret",
                "tls13_client_hs_secret",
                "tls13_client_early_secret",
                "tls13_server_app_secret",
                "tls13_server_hs_secret",
                "c3d_cert",
                "c3d_subject_cn",
                "c3d_extensions",
                "cert_constraints",
                "cert_extensions",
                "cert_not_valid_after",
                "cert_not_valid_before",
                "cert_signature_algorithm",
                "cert_public_key",
                "cert_public_key_type",
                "cert_public_key_bits",
                "cert_public_key_curve",
                "cert_version",
                "cert_pem",
                "cert_der",
                "collect_requested",
                "collect_length",
                "payload_length",
                "release_requested",
                "released_length",
                "forward_proxy_policy",
                "forward_proxy_cert",
                "forward_proxy_extensions",
                "forward_proxy_verified_handshake",
                "forward_proxy_response_control",
                "forward_proxy_cert_status",
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
                "username_flag",
                "password_flag",
                "will_topic",
                "will_message",
                "will_qos",
                "will_retain",
                "will_flag",
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
                "length",
                "procid",
                "procname",
                "sqltext",
                "xacttype",
                "xactid",
                "is_read",
                "request_type",
                "lb_failure",
                "persist_down",
                "lb_queue",
                "username",
                "dbname",
                "loginoption",
                "version",
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
                "hops",
                "ttl",
                "tos",
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
            if packet["protocol"] == "event":
                if packet["event"] not in self._event_profiles:
                    raise EmulatorInputError(
                        f"unknown iRule event: {packet['event']}"
                    )
                event_result = self._fire_event_on_worker(
                    session, packet["event"], packet["state"]
                )
                entry["events"].append(event_result)
                if event_result.get("suspended"):
                    entry["suspended"] = True
                    entry["suspension"] = event_result["suspension"]
                continue
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
                    if "http_class" in packet:
                        request["http_class"] = packet["http_class"]
                    if "lb_failure" in packet:
                        request["lb_failure"] = packet["lb_failure"]
                    for field in ("persist_down", "lb_queue"):
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

            if protocol == "rtsp":
                self._activate_packet_connection(session, packet, entry["events"])
                is_request = packet["type"] == "request"
                ingress_event = "RTSP_REQUEST" if is_request else "RTSP_RESPONSE"
                data_event = "RTSP_REQUEST_DATA" if is_request else "RTSP_RESPONSE_DATA"
                ingress_result = self._fire_event_on_worker(
                    session, ingress_event, self._packet_event_state(packet)
                )
                entry["events"].append(ingress_result)
                rtsp_state = ingress_result.get("state", {}).get("rtsp", {})
                if rtsp_state.get("dropped") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = "rtsp"
                if rtsp_state.get("responded") in {"1", "true"}:
                    entry["responded"] = True
                    raw_headers = _split_tcl_list(rtsp_state.get("response_headers", ""))
                    if len(raw_headers) % 2:
                        raise EmulatorInputError("invalid RTSP response headers")
                    response = {
                        "status": int(rtsp_state.get("response_status", "0")),
                        "phrase": rtsp_state.get("response_phrase", ""),
                        "headers": [
                            [raw_headers[offset], raw_headers[offset + 1]]
                            for offset in range(0, len(raw_headers), 2)
                        ],
                        "body": rtsp_state.get("response_body", ""),
                    }
                    entry["response"] = response
                    ingress_result.setdefault("emissions", []).append(
                        {
                            "protocol": "rtsp",
                            "direction": "server_to_client",
                            "payload": response["body"],
                            "byte_length": len(response["body"].encode("utf-8")),
                            "status": response["status"],
                            "phrase": response["phrase"],
                            "headers": response["headers"],
                        }
                    )
                else:
                    try:
                        requested_length = int(
                            session.eval_tcl(
                                "set ::itest::semantic::rtsp_collection_length"
                            )
                        )
                    except (TypeError, ValueError):
                        raise EmulatorInputError("invalid RTSP collection length") from None
                    requested = session.eval_tcl(
                        "set ::itest::semantic::rtsp_collection_requested"
                    ) == "1"
                    payload = packet.get("_rtsp_payload", b"")
                    if not isinstance(payload, (bytes, bytearray)):
                        payload = packet.get("payload", "").encode("utf-8")
                    payload = bytes(payload)
                    if requested and (requested_length == 0 or len(payload) >= requested_length):
                        collected = payload if requested_length == 0 else payload[:requested_length]
                        data_state = {
                            layer: dict(values)
                            for layer, values in ingress_result.get("state", {}).items()
                        }
                        data_state.setdefault("rtsp", {})["payload"] = collected
                        data_state["rtsp"]["payload_length"] = str(len(collected))
                        session.eval_tcl("set ::itest::semantic::rtsp_collection_requested 0")
                        data_result = self._fire_event_on_worker(
                            session, data_event, data_state
                        )
                        entry["events"].append(data_result)
                        data_rtsp = data_result.get("state", {}).get("rtsp", {})
                        if data_rtsp.get("dropped") in {"1", "true"}:
                            entry["dropped"] = True
                            entry["drop_reason"] = "rtsp"
                        if session.eval_tcl(
                            "set ::itest::semantic::rtsp_release_requested"
                        ) == "1":
                            entry["released"] = True
                        entry["payload_after"] = data_rtsp.get("payload", "")
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
                last_event_result = ingress_result
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
                            last_event_result = data_result
                            data_flags = _split_tcl_list(
                                session.eval_tcl("::itest::semantic::mqtt_flags_snapshot")
                            )
                            data_state = dict(zip(data_flags[::2], data_flags[1::2]))
                            if data_state.get("dropped") == "1":
                                entry["dropped"] = True
                                entry["drop_reason"] = "message"
                if message_state.get("disconnect") == "1":
                    entry["disconnect_requested"] = True
                if not entry.get("dropped"):
                    egress_event = (
                        "MQTT_SERVER_EGRESS"
                        if direction == "client_to_server"
                        else "MQTT_CLIENT_EGRESS"
                    )
                    egress_state = last_event_result.get("state", {})
                    if not isinstance(egress_state, dict) or "mqtt" not in egress_state:
                        egress_state = self._packet_event_state(packet)
                    egress_result = self._fire_event_on_worker(
                        session, egress_event, egress_state
                    )
                    entry["events"].append(egress_result)
                    egress_flags = _split_tcl_list(
                        session.eval_tcl("::itest::semantic::mqtt_flags_snapshot")
                    )
                    if len(egress_flags) % 2:
                        raise EmulatorInputError("invalid MQTT egress state")
                    egress_message_state = dict(
                        zip(egress_flags[::2], egress_flags[1::2])
                    )
                    if egress_message_state.get("dropped") == "1":
                        entry["dropped"] = True
                        entry["drop_reason"] = "message"
                    if egress_message_state.get("disconnect") == "1":
                        entry["disconnect_requested"] = True
                continue

            if protocol == "sip":
                self._activate_packet_connection(session, packet, entry["events"])
                session.eval_tcl("::itest::semantic::sip_prepare_message")
                # SDP is message-scoped even when the SIP connection is reused.
                session.eval_tcl("::itest::semantic::sdp_reset_connection")
                is_request = packet.get("type") == "request"
                ingress_event = "SIP_REQUEST" if is_request else "SIP_RESPONSE"
                send_event = "SIP_REQUEST_SEND" if is_request else "SIP_RESPONSE_SEND"
                done_event = "SIP_REQUEST_DONE" if is_request else "SIP_RESPONSE_DONE"
                ingress_result = self._fire_event_on_worker(
                    session,
                    ingress_event,
                    self._packet_event_state(packet),
                    packet=packet,
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
                            session,
                            send_event,
                            self._current_sip_event_state(session, packet),
                            packet=packet,
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
                                    packet=packet,
                                )
                            )
                entry.update(self._sip_output_from_tcl(session))
                continue

            if protocol == "socks":
                self._activate_packet_connection(session, packet, entry["events"])
                event_result = self._fire_event_on_worker(
                    session,
                    "SOCKS_REQUEST",
                    self._packet_event_state(packet),
                )
                entry["events"].append(event_result)
                socks_state = event_result.get("state", {}).get("socks", {})
                entry["socks"] = {
                    "version": socks_state.get("version", packet.get("version", "5")),
                    "command": packet.get("_socks_command", "STRUCTURED"),
                    "destination_host": socks_state.get(
                        "destination_host", packet.get("destination_host", "")
                    ),
                    "destination_port": socks_state.get(
                        "destination_port", str(packet.get("destination_port", 0))
                    ),
                    "allowed": socks_state.get(
                        "allowed", str(packet.get("allowed", "1"))
                    ),
                }
                if entry["socks"]["allowed"] == "0":
                    entry["discarded"] = True
                    entry["drop_reason"] = "socks"
                continue

            if protocol == "diameter":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(session, packet, entry["events"])
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
                    self._activate_packet_server_connection(session, packet, entry["events"])
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
                    self._activate_packet_server_connection(session, packet, entry["events"])
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

            if protocol == "qoe":
                self._activate_packet_connection(session, packet, entry["events"])
                if not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                if session.eval_tcl("set ::state::qoe::enabled") == "0":
                    entry["ignored"] = "QOE processing is disabled"
                    entry["disabled"] = True
                    finish_packet_connection(packet, entry, index)
                    continue
                event_result = self._fire_event_on_worker(
                    session,
                    "QOE_PARSE_DONE",
                    self._packet_event_state(packet),
                )
                entry["events"].append(event_result)
                if not event_result.get("fired") and event_result.get("reason") == "profile_gate":
                    entry["ignored"] = "QOE profile is not attached"
                finish_packet_connection(packet, entry, index)
                continue

            if protocol == "l7check":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                event_name = (
                    "L7CHECK_CLIENT_DATA"
                    if direction == "client_to_server"
                    else "L7CHECK_SERVER_DATA"
                )
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                if not event_result.get("fired") and event_result.get("reason") == "profile_gate":
                    entry["ignored"] = "L7CHECK profile is not attached"
                l7check_state = event_result.get("state", {}).get("l7check", {})
                if "protocol" in l7check_state:
                    entry["l7_protocol"] = l7check_state["protocol"]
                finish_packet_connection(packet, entry, index)
                continue

            if protocol == "fix":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                fix_state = self._packet_event_state(packet)
                header_result = self._fire_event_on_worker(
                    session, "FIX_HEADER", fix_state
                )
                entry["events"].append(header_result)
                message_result = self._fire_event_on_worker(
                    session, "FIX_MESSAGE", fix_state
                )
                entry["events"].append(message_result)
                if (
                    not header_result.get("fired")
                    and header_result.get("reason") == "profile_gate"
                ) or (
                    not message_result.get("fired")
                    and message_result.get("reason") == "profile_gate"
                ):
                    entry["ignored"] = "FIX profile is not attached"
                finish_packet_connection(packet, entry, index)
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
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                stream_event, stream_payload, stream_match = (
                    self._maybe_fire_stream_match(session, packet)
                )
                if stream_event is not None:
                    entry["events"].append(stream_event)
                    entry["stream_match"] = _decode_wire_text(stream_match or b"")
                    if stream_payload is not None:
                        packet["_wire_payload"] = stream_payload
                        packet["payload"] = _decode_wire_text(stream_payload)
                        entry["payload_after"] = packet["payload"]
                    elif stream_event.get("state", {}).get("stream", {}).get(
                        "replacement_requested"
                    ) == "1":
                        entry["stream_replacement_deferred"] = True
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
            elif protocol in {"dhcpv4", "dhcpv6"}:
                self._activate_packet_connection(session, packet, entry["events"])
                layer = protocol
                accepted_event = next(
                    (
                        event
                        for event in reversed(entry["events"])
                        if event.get("event") == "CLIENT_ACCEPTED"
                    ),
                    None,
                )
                accepted_state = (
                    accepted_event.get("state", {}).get(layer, {})
                    if accepted_event is not None
                    else {}
                )
                if accepted_state.get("drop") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = layer
                if accepted_state.get("reject") in {"1", "true"}:
                    entry["rejected"] = True
                    entry["dropped"] = True
                    entry["drop_reason"] = f"{layer} reject"
                if entry.get("dropped"):
                    continue
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(session, packet, entry["events"])
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                dhcp_state = event_result.get("state", {}).get(layer, {})
                if dhcp_state.get("drop") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = layer
                if dhcp_state.get("reject") in {"1", "true"}:
                    entry["rejected"] = True
                    entry["dropped"] = True
                    entry["drop_reason"] = f"{layer} reject"
                if "payload" in dhcp_state:
                    entry["payload_after"] = dhcp_state["payload"]
                if "options" in dhcp_state:
                    entry["options_after"] = dhcp_state["options"]
                continue
            elif protocol == "ntlm":
                self._activate_packet_connection(session, packet, entry["events"])
                if session.eval_tcl("set ::state::ntlm::enabled") == "0":
                    entry["ignored"] = "NTLM processing is disabled"
                    entry["disabled"] = True
                    finish_packet_connection(packet, entry, index)
                    continue
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                ntlm_state = event_result.get("state", {}).get("ntlm", {})
                if ntlm_state.get("enabled") == "0":
                    entry["disabled"] = True
                if "payload" in ntlm_state:
                    entry["payload_after"] = ntlm_state["payload"]
                eca_result = packet.get("eca_result")
                if eca_result is not None:
                    if session.eval_tcl("set ::state::eca::enabled") != "1":
                        entry["ignored"] = "ECA processing is disabled"
                    else:
                        eca_event = (
                            "ECA_REQUEST_ALLOWED"
                            if eca_result == "allowed"
                            else "ECA_REQUEST_DENIED"
                        )
                        eca_event_result = self._fire_event_on_worker(
                            session,
                            eca_event,
                            self._packet_event_state(packet),
                        )
                        entry["events"].append(eca_event_result)
                        entry["eca_result"] = eca_result
                finish_packet_connection(packet, entry, index)
                continue
            elif protocol == "protocol_inspection":
                self._activate_packet_connection(session, packet, entry["events"])
                if packet.get("matched") == "0":
                    entry["ignored"] = "protocol inspection packet did not match"
                    finish_packet_connection(packet, entry, index)
                    continue
                if session.eval_tcl("set ::state::protocol_inspection::enabled") == "0":
                    entry["ignored"] = "protocol inspection is disabled"
                    entry["disabled"] = True
                    finish_packet_connection(packet, entry, index)
                    continue
                event_result = self._fire_event_on_worker(
                    session,
                    "PROTOCOL_INSPECTION_MATCH",
                    self._packet_event_state(packet),
                )
                entry["events"].append(event_result)
                if not event_result.get("fired") and event_result.get("reason") == "profile_gate":
                    entry["ignored"] = "PROTOCOL_INSPECTION profile is not attached"
                    finish_packet_connection(packet, entry, index)
                    continue
                inspection_state = event_result.get("state", {}).get(
                    "protocol_inspection", {}
                )
                if inspection_state.get("enabled") == "0":
                    entry["disabled"] = True
                if "ids" in inspection_state:
                    entry["inspection_ids"] = inspection_state["ids"]
                if "payload" in inspection_state:
                    entry["payload_after"] = inspection_state["payload"]
                finish_packet_connection(packet, entry, index)
                continue
            elif protocol == "classification":
                self._activate_packet_connection(session, packet, entry["events"])
                if packet["direction"] == "server_to_client":
                    deferred = session.eval_tcl(
                        "set ::state::classification::classify_defer"
                    )
                    if deferred != "1":
                        entry["ignored"] = "classification packet was not deferred"
                        finish_packet_connection(packet, entry, index)
                        continue
                if packet.get("detected") == "0":
                    entry["ignored"] = "classification packet was not detected"
                    finish_packet_connection(packet, entry, index)
                    continue
                if session.eval_tcl("set ::state::classification::enabled") == "0":
                    entry["ignored"] = "classification is disabled"
                    entry["disabled"] = True
                    finish_packet_connection(packet, entry, index)
                    continue
                event_result = self._fire_event_on_worker(
                    session,
                    "CLASSIFICATION_DETECTED",
                    self._packet_event_state(packet),
                )
                entry["events"].append(event_result)
                if not event_result.get("fired") and event_result.get("reason") == "profile_gate":
                    entry["ignored"] = "CLASSIFICATION profile is not attached"
                    finish_packet_connection(packet, entry, index)
                    continue
                classification_state = event_result.get("state", {}).get(
                    "classification", {}
                )
                if classification_state.get("enabled") == "0":
                    entry["disabled"] = True
                if "result" in classification_state:
                    entry["classification_result"] = classification_state["result"]
                if "payload" in classification_state:
                    entry["payload_after"] = classification_state["payload"]
                finish_packet_connection(packet, entry, index)
                continue
            elif protocol == "category":
                self._activate_packet_connection(session, packet, entry["events"])
                if packet.get("matched") == "0":
                    entry["ignored"] = "category packet did not match"
                    finish_packet_connection(packet, entry, index)
                    continue
                if packet.get("detected") == "0":
                    entry["ignored"] = "category packet was not detected"
                    finish_packet_connection(packet, entry, index)
                    continue
                event_result = self._fire_event_on_worker(
                    session,
                    "CATEGORY_MATCHED",
                    self._packet_event_state(packet),
                )
                entry["events"].append(event_result)
                if not event_result.get("fired") and event_result.get("reason") == "profile_gate":
                    entry["ignored"] = "CATEGORY profile is not attached"
                    finish_packet_connection(packet, entry, index)
                    continue
                category_state = event_result.get("state", {}).get("category", {})
                if "categories" in category_state:
                    entry["category_result"] = category_state["categories"]
                if "safesearch" in category_state:
                    entry["safesearch_result"] = category_state["safesearch"]
                if "payload" in category_state:
                    entry["payload_after"] = category_state["payload"]
                finish_packet_connection(packet, entry, index)
                continue
            elif protocol in STARTTLS_PROTOCOLS:
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                if session.eval_tcl(f"set ::state::{protocol}::enabled") == "0":
                    entry["ignored"] = f"{protocol.upper()} processing is disabled"
                    entry["disabled"] = True
                    continue
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                protocol_state = event_result.get("state", {}).get(protocol, {})
                if protocol_state.get("enabled") == "0":
                    entry["disabled"] = True
                if "payload" in protocol_state:
                    entry["payload_after"] = protocol_state["payload"]
                continue
            elif protocol == "ftp":
                self._activate_packet_connection(session, packet, entry["events"])
                accepted_event = next(
                    (
                        event
                        for event in reversed(entry["events"])
                        if event.get("event") == "CLIENT_ACCEPTED"
                    ),
                    None,
                )
                accepted_ftp = (
                    accepted_event.get("state", {}).get("ftp", {})
                    if accepted_event is not None
                    else {}
                )
                if accepted_ftp.get("enabled") == "0" or session.eval_tcl(
                    "set ::state::ftp::enabled"
                ) == "0":
                    entry["ignored"] = "FTP processing is disabled"
                    continue
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                ftp_state = event_result.get("state", {}).get("ftp", {})
                if ftp_state.get("dropped") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = "ftp"
                if ftp_state.get("rejected") in {"1", "true"}:
                    entry["rejected"] = True
                    entry["dropped"] = True
                    entry["drop_reason"] = "ftp reject"
                if ftp_state.get("enabled") == "0":
                    entry["disabled"] = True
                if "payload" in ftp_state:
                    entry["payload_after"] = ftp_state["payload"]
                continue
            elif protocol == "tds":
                self._activate_packet_connection(session, packet, entry["events"])
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(
                        session, packet, entry["events"], emit_init=True
                    )
                event_name = (
                    "TDS_REQUEST"
                    if direction == "client_to_server"
                    else "TDS_RESPONSE"
                )
                entry["events"].append(
                    self._fire_event_on_worker(
                        session, event_name, self._packet_event_state(packet)
                    )
                )
                finish_packet_connection(packet, entry, index)
                continue
            elif protocol == "icap":
                self._activate_packet_connection(session, packet, entry["events"])
                event_name = "ICAP_REQUEST" if direction == "client_to_server" else "ICAP_RESPONSE"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                icap_state = event_result.get("state", {}).get("icap", {})
                if "payload" in icap_state:
                    entry["payload_after"] = icap_state["payload"]
                continue
            elif protocol == "sctp":
                self._activate_packet_connection(session, packet, entry["events"])
                accepted_event = next(
                    (
                        event
                        for event in reversed(entry["events"])
                        if event.get("event") == "CLIENT_ACCEPTED"
                    ),
                    None,
                )
                accepted_sctp = (
                    accepted_event.get("state", {}).get("sctp", {})
                    if accepted_event is not None
                    else {}
                )
                if accepted_sctp.get("responded") in {"1", "true"}:
                    response = accepted_sctp.get("response", "")
                    entry["responded"] = True
                    entry["response"] = response
                    accepted_event.setdefault("emissions", []).append(
                        {
                            "protocol": "sctp",
                            "direction": "server_to_client",
                            "payload": response,
                            "byte_length": int(
                                accepted_sctp.get(
                                    "response_length", len(response.encode("utf-8"))
                                )
                            ),
                        }
                    )
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(session, packet, entry["events"])
                side = "client" if direction == "client_to_server" else "server"
                wire_payload = packet.get("_wire_payload")
                if not isinstance(wire_payload, (bytes, bytearray)):
                    wire_payload = str(packet.get("payload", "")).encode("utf-8")
                if not wire_payload:
                    continue
                collection = _split_tcl_list(
                    session.eval_tcl(
                        f"::itest::semantic::sctp_collection_request {side}"
                    )
                )
                if len(collection) != 4:
                    entry["ignored"] = "sctp payload not collected"
                    continue
                try:
                    collection_values = {
                        collection[index]: int(collection[index + 1])
                        for index in range(0, len(collection), 2)
                    }
                except (TypeError, ValueError):
                    raise EmulatorInputError("invalid SCTP collection state") from None
                buffered = self._sctp_buffers[side] + bytes(wire_payload)
                if len(buffered) > STREAM_MAX_BYTES:
                    raise EmulatorInputError(
                        f"SCTP collection exceeds {STREAM_MAX_BYTES // (1024 * 1024)} MiB"
                    )
                length = collection_values.get("length", 0)
                every_packet = collection_values.get("every_packet", 0) == 1
                if length and len(buffered) < length:
                    self._sctp_buffers[side] = buffered
                    entry["buffered"] = True
                    entry["buffered_bytes"] = len(buffered)
                    continue
                event_payload = buffered if not length else buffered[:length]
                remainder = buffered[len(event_payload):]
                event_packet = dict(packet)
                event_packet["payload"] = _decode_wire_text(event_payload)
                event_packet["_wire_payload"] = event_payload
                if not every_packet:
                    session.eval_tcl(
                        f"::itest::semantic::sctp_clear_collection {side}"
                    )
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(event_packet)
                )
                entry["events"].append(event_result)
                sctp_state = event_result.get("state", {}).get("sctp", {})
                released = sctp_state.get("released") in {"1", "true"}
                entry["released"] = released
                if released:
                    try:
                        released_length = int(sctp_state.get("released_length", "0"))
                    except (TypeError, ValueError):
                        raise EmulatorInputError("invalid SCTP release length") from None
                    entry["released_length"] = released_length
                retained_payload = self._sctp_payload_from_tcl(session) if not released else b""
                self._sctp_buffers[side] = retained_payload + remainder
                if sctp_state.get("responded") in {"1", "true"} and not entry.get("dropped"):
                    response = sctp_state.get("response", "")
                    entry["responded"] = True
                    entry["response"] = response
                    event_result.setdefault("emissions", []).append(
                        {
                            "protocol": "sctp",
                            "direction": (
                                "server_to_client"
                                if direction == "client_to_server"
                                else "client_to_server"
                            ),
                            "payload": response,
                            "byte_length": int(
                                sctp_state.get(
                                    "response_length", len(response.encode("utf-8"))
                                )
                            ),
                        }
                    )
                if "payload" in sctp_state:
                    entry["payload_after"] = sctp_state["payload"]
                continue
            elif protocol == "udp":
                self._activate_packet_connection(session, packet, entry["events"])
                accepted_event = next(
                    (
                        event
                        for event in reversed(entry["events"])
                        if event.get("event") == "CLIENT_ACCEPTED"
                    ),
                    None,
                )
                accepted_udp = (
                    accepted_event.get("state", {}).get("udp", {})
                    if accepted_event is not None
                    else {}
                )
                if accepted_udp.get("dropped") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = "udp"
                if accepted_udp.get("held") in {"1", "true"}:
                    entry["held"] = True
                if accepted_udp.get("responded") in {"1", "true"} and not entry.get("dropped"):
                    response = accepted_udp.get("response", "")
                    entry["responded"] = True
                    entry["response"] = response
                    accepted_event.setdefault("emissions", []).append(
                        {
                            "protocol": "udp",
                            "direction": "server_to_client",
                            "payload": response,
                            "byte_length": len(response.encode("utf-8")),
                        }
                    )
                if entry.get("dropped"):
                    continue
                if direction == "server_to_client" and not self._server_connection_open:
                    self._activate_packet_server_connection(session, packet, entry["events"])
                event_name = "CLIENT_DATA" if direction == "client_to_server" else "SERVER_DATA"
                event_result = self._fire_event_on_worker(
                    session, event_name, self._packet_event_state(packet)
                )
                entry["events"].append(event_result)
                udp_state = event_result.get("state", {}).get("udp", {})
                if udp_state.get("dropped") in {"1", "true"}:
                    entry["dropped"] = True
                    entry["drop_reason"] = "udp"
                if udp_state.get("held") in {"1", "true"}:
                    entry["held"] = True
                if udp_state.get("released") in {"1", "true"}:
                    entry["released"] = True
                if udp_state.get("responded") in {"1", "true"} and not entry.get("dropped"):
                    response = udp_state.get("response", "")
                    entry["responded"] = True
                    entry["response"] = response
                    event_result.setdefault("emissions", []).append(
                        {
                            "protocol": "udp",
                            "direction": (
                                "server_to_client"
                                if direction == "client_to_server"
                                else "client_to_server"
                            ),
                            "payload": response,
                            "byte_length": len(response.encode("utf-8")),
                        }
                    )
                if "payload" in udp_state:
                    entry["payload_after"] = udp_state["payload"]
                continue
            else:  # Generic UDP has no single catalogued iRule data event.
                entry["ignored"] = "generic UDP packet has no protocol-specific event adapter"
                continue

            if protocol == "tls":
                event_name = self._packet_tls_event(packet)
                side = "client" if direction == "client_to_server" else "server"
                data_event = event_name in {"CLIENTSSL_DATA", "SERVERSSL_DATA"}
                event_packet = packet
                event_payload = b""
                remainder = b""
                collection_requested = False
                if data_event:
                    collection_requested = session.eval_tcl(
                        f"set ::state::tls::{side}::collect_requested"
                    ) == "1"
                    if collection_requested:
                        requested_length_raw = session.eval_tcl(
                            f"set ::state::tls::{side}::collect_length"
                        )
                        try:
                            requested_length = int(requested_length_raw)
                        except (TypeError, ValueError):
                            raise EmulatorInputError("invalid SSL collection length") from None
                        if requested_length < 0:
                            raise EmulatorInputError("invalid SSL collection length")
                        incoming = self._tls_plaintext_payload(packet)
                        buffered = self._ssl_buffers[side] + incoming
                        if len(buffered) > STREAM_MAX_BYTES:
                            raise EmulatorInputError(
                                f"SSL collection exceeds {STREAM_MAX_BYTES // (1024 * 1024)} MiB"
                            )
                        if requested_length and len(buffered) < requested_length:
                            self._ssl_buffers[side] = buffered
                            entry["buffered"] = True
                            entry["buffered_bytes"] = len(buffered)
                            continue
                        event_payload = (
                            buffered
                            if requested_length == 0
                            else buffered[:requested_length]
                        )
                        remainder = buffered[len(event_payload):]
                        self._ssl_buffers[side] = remainder
                        session.eval_tcl(
                            f"set ::state::tls::{side}::collect_requested 0"
                        )
                        event_packet = dict(packet)
                        event_packet["payload"] = _decode_wire_text(event_payload)
                event_state = self._packet_event_state(event_packet)
                if data_event and collection_requested:
                    tls_layer = (
                        "tls_client" if direction == "client_to_server" else "tls_server"
                    )
                    event_state.setdefault(tls_layer, {})["payload"] = event_payload
                    event_state[tls_layer]["payload_length"] = str(len(event_payload))
                event_result = self._fire_event_on_worker(
                    session, event_name, event_state
                )
                entry["events"].append(event_result)
                if data_event and collection_requested:
                    after_event = self._ssl_payload_from_tcl(session, side)
                    self._ssl_buffers[side] = after_event + remainder
                    if session.eval_tcl(
                        f"set ::state::tls::{side}::release_requested"
                    ) == "1":
                        entry["released"] = True
                        entry["released_length"] = int(
                            session.eval_tcl(
                                f"set ::state::tls::{side}::released_length"
                            )
                        )
                    entry["payload_after"] = _decode_wire_text(after_event)
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
                "event_controls": self.event_controls,
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
                "title": "Replay a PCAP or pcapng capture",
                "description": "Replay a bounded classic PCAP or pcapng capture through the BIG-IP 17.5 packet and Tcl event adapters.",
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
                        "namespace": {"type": "string", "minLength": 1},
                        "runtime_status": {
                            "type": "string",
                            "enum": sorted(RUNTIME_STATUS_VALUES),
                        },
                        "target_status": {
                            "type": "string",
                            "enum": sorted(TARGET_STATUS_VALUES),
                        },
                    }
                ),
            },
            {
                "name": "irule_catalog",
                "title": "Export the iRule catalog",
                "description": "Materialize the complete pinned BIG-IP 17.5 command catalog as deterministic bounded chunks.",
                "inputSchema": _mcp_object_schema(
                    {
                        "chunk_size": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 250},
                        "namespace": {"type": "string", "minLength": 1},
                        "runtime_status": {
                            "type": "string",
                            "enum": sorted(RUNTIME_STATUS_VALUES),
                        },
                        "target_status": {
                            "type": "string",
                            "enum": sorted(TARGET_STATUS_VALUES),
                        },
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
                "description": "Replay a bounded protocol packet trace or synthetic catalogued-event sequence on a persistent emulator session.",
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
            unknown = sorted(
                set(args) - {"offset", "limit", "namespace", "runtime_status", "target_status"}
            )
            if unknown:
                raise McpProtocolError(-32602, f"unsupported irule_capabilities field(s): {', '.join(unknown)}")
            offset = args.get("offset", 0)
            limit = args.get("limit", 100)
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise McpProtocolError(-32602, "capability offset must be an integer")
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise McpProtocolError(-32602, "capability limit must be an integer")
            filters = {
                field: args[field]
                for field in ("namespace", "runtime_status", "target_status")
                if field in args
            }
            return self._tool_success(
                _build_capabilities(self._root, offset, limit, **filters)
            )

        if name == "irule_catalog":
            unknown = sorted(
                set(args) - {"chunk_size", "namespace", "runtime_status", "target_status"}
            )
            if unknown:
                raise McpProtocolError(-32602, f"unsupported irule_catalog field(s): {', '.join(unknown)}")
            chunk_size = args.get("chunk_size", 250)
            if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
                raise McpProtocolError(-32602, "catalog chunk size must be an integer")
            filters = {
                field: args[field]
                for field in ("namespace", "runtime_status", "target_status")
                if field in args
            }
            return self._tool_success(_build_catalog(self._root, chunk_size, **filters))

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
        packet_result["event_controls"] = session.event_controls
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
        "event_controls": session.event_controls,
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
            if parsed.path == "/v1/catalog":
                query = parse_qs(parsed.query, strict_parsing=False)
                try:
                    chunk_size = int(query.get("chunk_size", ["250"])[0])
                    filters = {
                        field: query[field][0]
                        for field in ("namespace", "runtime_status", "target_status")
                        if field in query
                    }
                    payload = _build_catalog(root, chunk_size, **filters)
                except (TypeError, ValueError, EmulatorInputError) as exc:
                    _json_response(self, 400, {"status": "error", "error": str(exc)})
                    return
                _json_response(self, 200, payload)
                return
            if parsed.path == "/v1/capabilities":
                query = parse_qs(parsed.query, strict_parsing=False)
                try:
                    offset = int(query.get("offset", ["0"])[0])
                    limit = int(query.get("limit", ["100"])[0])
                    filters = {
                        field: query[field][0]
                        for field in ("namespace", "runtime_status", "target_status")
                        if field in query
                    }
                    payload = _build_capabilities(root, offset, limit, **filters)
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
    parser.add_argument("--pcap", help="classic PCAP or pcapng file to replay for the scenario")
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
        "--catalog",
        action="store_true",
        help="emit the complete catalog as a bounded-chunk manifest",
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
    parser.add_argument("--namespace", help="limit capabilities to one exact command namespace")
    parser.add_argument(
        "--runtime-status",
        choices=sorted(RUNTIME_STATUS_VALUES),
        help="limit capabilities by runtime implementation status",
    )
    parser.add_argument(
        "--target-status",
        choices=sorted(TARGET_STATUS_VALUES),
        help="limit capabilities by TMOS 17.5 target status",
    )
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
        if args.pcap and (
            args.serve or args.mcp or args.capabilities or args.catalog or args.conformance
        ):
            raise EmulatorInputError(
                "--pcap can only be used with one-shot scenario execution"
            )
        if args.catalog and args.offset != 0:
            raise EmulatorInputError("--offset cannot be used with --catalog")
        if args.serve:
            serve(root, args.host, args.port)
            return 0
        if args.mcp:
            serve_mcp(root)
            return 0
        if args.catalog:
            response = _build_catalog(
                root,
                args.limit,
                namespace=args.namespace,
                runtime_status=args.runtime_status,
                target_status=args.target_status,
            )
        elif args.capabilities:
            response = _build_capabilities(
                root,
                args.offset,
                args.limit,
                namespace=args.namespace,
                runtime_status=args.runtime_status,
                target_status=args.target_status,
            )
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
