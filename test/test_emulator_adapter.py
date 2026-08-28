"""Regression tests for the optional tmos-17.5 emulator adapter."""

from __future__ import annotations

import importlib.util
import base64
import io
import ipaddress
import json
import os
import struct
import subprocess
import sys
import threading
import time
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "tools" / "irule-emulator.py"
FIXTURE_PATH = ROOT / "test" / "fixtures" / "emulator_http.json"


def _raw_ipv4_tcp_hex(
    source: str, destination: str, source_port: int, destination_port: int,
    flags: int, payload: bytes = b"", *, sequence: int = 0, acknowledgment: int = 0,
) -> str:
    tcp = struct.pack(
        "!HHLLBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64, 6, 0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return (ip + tcp + payload).hex()


def _tls_client_hello_payload(host: str) -> bytes:
    host_bytes = host.encode("ascii")
    server_name = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
    server_names = struct.pack("!H", len(server_name)) + server_name
    extension = struct.pack("!HH", 0, len(server_names)) + server_names
    body = (
        b"\x03\x03" + b"\x00" * 32 + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
        + struct.pack("!H", len(extension)) + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def _raw_ipv4_udp_hex(
    source: str, destination: str, source_port: int, destination_port: int,
    payload: bytes,
) -> str:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    total_length = 20 + len(udp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0, 64, 17, 0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return (ip + udp + payload).hex()


def _pcap_bytes(
    records: list[tuple[int, int, bytes]], *, linktype: int = 1, nano: bool = False
) -> bytes:
    """Build a little-endian classic PCAP for decoder tests."""
    magic = b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1"
    header = magic + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype)
    body = bytearray(header)
    for seconds, fraction, frame in records:
        body.extend(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
        body.extend(frame)
    return bytes(body)


def _ethernet_ipv4(raw_hex: str) -> bytes:
    return b"\x00" * 12 + b"\x08\x00" + bytes.fromhex(raw_hex)


def _load_adapter():
    spec = importlib.util.spec_from_file_location("testcl_irule_emulator", ADAPTER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {ADAPTER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EmulatorAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = os.environ.get("TCL_LSP_ROOT")
        if not root:
            raise unittest.SkipTest("set TCL_LSP_ROOT to run emulator integration tests")
        cls.adapter = _load_adapter()
        cls.tcl_lsp_root = root

    def test_http_fixture_models_request_and_response(self) -> None:
        scenario = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        result = self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        self.assertEqual(result["profile"], "tmos-17.5")
        self.assertEqual(len(result["results"]), 2)
        first, second = result["results"]
        self.assertEqual(first["pool"], "api_pool")
        self.assertEqual(first["request"]["body"], "ping")
        self.assertEqual(first["response"]["body"], "pong")
        self.assertEqual(first["response"]["headers"]["x-emulator"], "yes")
        self.assertEqual(second["response"]["status"], 403)
        self.assertEqual(second["response"]["reason"], "Forbidden")
        self.assertEqual(second["response"]["body"], "denied")
        self.assertEqual(result["fidelity"]["analysis"], "static-tcl-lsp")
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        self.assertIn("HTTP::payload", usage)
        self.assertIn("HTTP::respond", usage)
        self.assertEqual(usage["HTTP::payload"]["runtime_status"], "semantic-mock")
        self.assertEqual(result["fidelity"]["warnings"], [])

    def test_http_data_events_require_collection_and_honor_length(self) -> None:
        no_collect = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": 'when HTTP_REQUEST_DATA { log local0. "unexpected-data" }',
                "requests": [{"body": "abc"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_REQUEST_DATA", no_collect["results"][0]["events_fired"])
        self.assertFalse(any("unexpected-data" in entry for entry in no_collect["results"][0]["logs"]))

        collected = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { HTTP::collect 3 }
when HTTP_REQUEST_DATA { log local0. "collected=[HTTP::payload]"; HTTP::release }
when HTTP_RESPONSE { HTTP::collect 2 }
when HTTP_RESPONSE_DATA { log local0. "response=[HTTP::payload]"; HTTP::release }
""",
                "requests": [{"body": "abc", "response_body": "ok"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertIn("HTTP_REQUEST_DATA", collected["results"][0]["events_fired"])
        self.assertTrue(any("collected=abc" in entry for entry in collected["results"][0]["logs"]))
        self.assertIn("HTTP_RESPONSE_DATA", collected["results"][0]["events_fired"])
        self.assertTrue(any("response=ok" in entry for entry in collected["results"][0]["logs"]))
        self.assertTrue(collected["results"][0]["http_release"])
        self.assertGreaterEqual(
            sum(1 for entry in collected["results"][0]["decisions"] if "release" in str(entry)),
            2,
        )

        short = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { HTTP::collect 4 }
when HTTP_REQUEST_DATA { log local0. "should-not-fire" }
""",
                "requests": [{"body": "abc"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_REQUEST_DATA", short["results"][0]["events_fired"])

    def test_http_release_events_follow_data_and_reject_body_commands(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { HTTP::collect 1 }
when HTTP_REQUEST_DATA { HTTP::release }
when HTTP_REQUEST_RELEASE {
    set payload_rc [catch { HTTP::payload }]
    set collect_rc [catch { HTTP::collect 1 }]
    log local0. "request-release payload=$payload_rc collect=$collect_rc"
}
when HTTP_RESPONSE { HTTP::collect 1 }
when HTTP_RESPONSE_DATA { HTTP::release }
when HTTP_RESPONSE_RELEASE {
    set payload_rc [catch { HTTP::payload }]
    set collect_rc [catch { HTTP::collect 1 }]
    log local0. "response-release payload=$payload_rc collect=$collect_rc"
}
""",
                "request": {"body": "abc", "response_body": "ok"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["results"][0]["events_fired"]
        self.assertLess(events.index("HTTP_REQUEST_DATA"), events.index("HTTP_REQUEST_RELEASE"))
        self.assertLess(events.index("HTTP_RESPONSE_DATA"), events.index("HTTP_RESPONSE_RELEASE"))
        logs = result["results"][0]["logs"]
        self.assertTrue(any("request-release payload=1 collect=1" in entry for entry in logs))
        self.assertTrue(any("response-release payload=1 collect=1" in entry for entry in logs))

    def test_capabilities_are_complete_and_chunked(self) -> None:
        result = self.adapter._build_capabilities(self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 0, 7)

        self.assertEqual(result["profile"], "tmos-17.5")
        self.assertGreaterEqual(result["summary"]["command_count"], 1400)
        self.assertGreaterEqual(result["summary"]["event_count"], 170)
        self.assertEqual(result["chunk"]["count"], 7)
        self.assertTrue(result["chunk"]["has_more"])
        self.assertEqual(len(result["commands"]), 7)
        self.assertEqual(result["commands"][0]["name"], "AAA::acct_result")

        final = self.adapter._build_capabilities(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 5000, 7
        )
        self.assertEqual(final["chunk"]["count"], 0)
        self.assertFalse(final["chunk"]["has_more"])
        self.assertEqual(final["commands"], [])

    def test_common_global_string_and_pool_functions_are_semantic(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80", "10.0.0.11:80"]},
                "datagroups": {
                    "routes": {
                        "records": {"/api": "api_pool", "/static": "static_pool"}
                    }
                },
                "irule": """
when HTTP_REQUEST {
    log local0. "unselected-server=[server_addr]:[server_port]"
    pool api_pool
    log local0. "findstr=[findstr [HTTP::path] / 1] field=[getfield [HTTP::host] . 2] char=[getfield abc {} 2]"
    log local0. "client=[client_addr]:[client_port] server=[server_addr]:[server_port] local=[local_addr]:[local_port]"
    log local0. "findclass=[findclass /api routes] matchclass=[matchclass /api equals routes]"
    log local0. "active=[active_members -list api_pool] all=[members -list api_pool] nodes=[nodes -list api_pool]"
    log local0. "substr=[substr prefix:/api?x=1 7 ?]"
    log local0. "uri=[decode_uri /api%2Fv1] domain=[domain www.sub.example.co.uk 2] crc=[crc32 abc] signed=[crc32 0]"
    set mmap [list [list route api_pool] [list owner platform] [list route backup_pool]]
    log local0. "lookup=[llookup $mmap route] missing=[llookup $mmap absent]"
    log local0. "md5=[binary encode hex [md5 abc]] sha1=[binary encode hex [sha1 abc]] sha256=[binary encode hex [sha256 abc]]"
    log local0. "sha384=[binary encode hex [sha384 abc]] sha512=[binary encode hex [sha512 abc]]"
    log local0. "binary-md5=[binary encode hex [md5 [binary format H* 00616263ff]]]"
    log local0. "b64=[b64decode [b64encode hello]]"
}
""",
                "requests": [{"host": "app.example.com", "uri": "/api/v1"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(any("findstr=api/v1" in entry for entry in logs))
        self.assertTrue(any("field=example" in entry for entry in logs))
        self.assertTrue(any("char=b" in entry for entry in logs))
        self.assertTrue(any("unselected-server=0.0.0.0:0" in entry for entry in logs))
        self.assertTrue(any("client=10.0.0.1:54321" in entry and "server=10.0.0.10:80" in entry and "local=192.168.1.100:443" in entry for entry in logs))
        self.assertTrue(any("findclass=/api api_pool matchclass=1" in entry for entry in logs))
        self.assertTrue(any("active={10.0.0.10 80} {10.0.0.11 80}" in entry for entry in logs))
        self.assertTrue(any("all={10.0.0.10 80} {10.0.0.11 80}" in entry for entry in logs))
        self.assertTrue(any("nodes=10.0.0.10 10.0.0.11" in entry for entry in logs))
        self.assertTrue(any("substr=/api" in entry for entry in logs))
        self.assertTrue(any("uri=/api/v1" in entry and "domain=co.uk" in entry and "crc=891568578" in entry and "signed=-186917087" in entry for entry in logs))
        self.assertTrue(any("lookup=api_pool backup_pool missing=" in entry for entry in logs))
        self.assertTrue(any("md5=900150983cd24fb0d6963f7d28e17f72" in entry and "sha1=a9993e364706816aba3e25717850c26c9cd0d89d" in entry and "sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in entry for entry in logs))
        self.assertTrue(any("sha384=cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" in entry and "sha512=ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" in entry for entry in logs))
        self.assertTrue(any("binary-md5=9fd6d2a57559960e059c385892142915" in entry for entry in logs))
        self.assertTrue(any("b64=hello" in entry for entry in logs))

    def test_server_endpoint_aliases_clear_stale_member_after_pool_failure(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "irule": """
when HTTP_REQUEST {
    pool api_pool
    LB::down pool api_pool
    pool api_pool
    log local0. "server=[server_addr]:[server_port]"
}
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("server=0.0.0.0:0" in entry for entry in result["results"][0]["logs"]))

        bare_member = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"bare_pool": ["10.0.0.20"]},
                "irule": "when HTTP_REQUEST { pool bare_pool; log local0. \"server=[server_addr]:[server_port]\" }",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("server=10.0.0.20:0" in entry for entry in bare_member["results"][0]["logs"]))

    def test_conformance_reports_catalog_and_packet_adapter_coverage(self) -> None:
        report = self.adapter._build_conformance(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        )

        self.assertEqual(report["profile"], "tmos-17.5")
        self.assertGreaterEqual(report["commands"]["catalog_count"], 1400)
        self.assertGreaterEqual(report["events"]["catalog_count"], 170)
        self.assertIn("HTTP_REQUEST", {
            entry["name"] for entry in report["events"]["packet_adapter_events"]
        })
        packet_adapters = {
            entry["name"]: entry["adapter"]
            for entry in report["events"]["packet_adapter_events"]
        }
        self.assertEqual(
            packet_adapters["HTTP_REQUEST_RELEASE"],
            "HTTP request transaction release phase",
        )
        self.assertEqual(
            packet_adapters["HTTP_RESPONSE_CONTINUE"],
            "raw HTTP 100 Continue response",
        )
        self.assertEqual(
            packet_adapters["HTTP_RESPONSE_RELEASE"],
            "HTTP response transaction release phase",
        )
        for event_name in (
            "WS_REQUEST",
            "WS_RESPONSE",
            "WS_CLIENT_FRAME",
            "WS_SERVER_FRAME",
            "WS_CLIENT_FRAME_DONE",
            "WS_SERVER_FRAME_DONE",
            "WS_CLIENT_DATA",
            "WS_SERVER_DATA",
        ):
            self.assertIn(event_name, packet_adapters)
        self.assertGreater(
            report["events"]["catalog_count"], report["events"]["packet_adapter_count"]
        )

    def test_fidelity_analysis_warns_for_stub_and_profile_gated_usage(self) -> None:
        root = self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        report = self.adapter._analyze_rule_capabilities(
            root,
            "when HTTP_REQUEST { ASM::status }\n"
            "when CLIENTSSL_HANDSHAKE { log local0. tls }",
            ["TCP", "HTTP"],
        )
        usage = {entry["name"]: entry for entry in report["commands"]}
        self.assertEqual(usage["ASM::status"]["runtime_status"], "generated-stub")
        warning_codes = {warning["code"] for warning in report["warnings"]}
        self.assertIn("runtime-fidelity", warning_codes)
        self.assertIn("profile-gated-event", warning_codes)

    def test_semantic_overlay_implements_profiles_auth_uri_stats_and_hsl(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "irule": (
                    "when HTTP_REQUEST { "
                    "if {[PROFILE::exists HTTP]} { pool api_pool }\n"
                    "set user [HTTP::username]\n"
                    "set encoded [URI::encode_component [HTTP::uri]]\n"
                    "if {[IP::addr [IP::client_addr] equals 10.0.0.1]} { "
                    "HTTP::header insert X-Address matched }\n"
                    "STATS::incr app requests\n"
                    "STATS::setmax app peak 5\n"
                    "STATS::setmin app floor 5\n"
                    "set h [HSL::open -proto TCP]\n"
                    "HSL::send $h \"$user|$encoded\""
                    "}"
                ),
                "requests": [
                    {
                        "uri": "/a b?x=1",
                        "headers": {"Authorization": "Basic YWxpY2U6c2VjcmV0"},
                    },
                    {"uri": "/second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second = result["results"]
        self.assertEqual(first["pool"], "api_pool")
        self.assertEqual(first["request"]["headers"]["x-address"], "matched")
        self.assertEqual(first["semantic"]["stats"], {
            "app|requests": "1",
            "app|peak": "5",
            "app|floor": "5",
        })
        self.assertEqual(second["semantic"]["stats"]["app|requests"], "2")
        self.assertEqual(second["semantic"]["stats"]["app|peak"], "5")
        self.assertEqual(second["semantic"]["stats"]["app|floor"], "5")
        self.assertEqual(first["semantic"]["hsl_messages"], [
            {"handle": "hsl1", "message": "alice|%2Fa%20b%3Fx%3D1"}
        ])
        self.assertEqual(first["semantic"]["lb_status"], {})
        self.assertEqual(len(second["semantic"]["hsl_messages"]), 2)
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"].startswith(("HSL::", "HTTP::username", "LB::", "PROFILE::", "STATS::", "URI::", "IP::addr"))},
            {
                "HSL::open": "semantic-mock",
                "HSL::send": "semantic-mock",
                "HTTP::username": "semantic-mock",
                "PROFILE::exists": "semantic-mock",
                "STATS::incr": "semantic-mock",
                "STATS::setmax": "semantic-mock",
                "STATS::setmin": "semantic-mock",
                "URI::encode_component": "semantic-mock",
                "IP::addr": "semantic-mock",
            },
        )

    def test_semantic_overlay_tracks_lb_node_and_pool_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST {
    pool api_pool
    LB::down node 192.0.2.10 443
    HTTP::header insert X-Down [LB::status pool api_pool member 192.0.2.10:443]
    LB::up pool api_pool
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            result["results"][0]["semantic"]["lb_status"],
            {"192.0.2.10:443": "down", "pool:api_pool": "up"},
        )
        self.assertEqual(result["results"][0]["request"]["headers"]["x-down"], "down")
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"].startswith("LB::")
            },
            {
                "LB::down": "semantic-mock",
                "LB::up": "semantic-mock",
                "LB::status": "semantic-mock",
            },
        )

    def test_semantic_overlay_reselects_away_from_down_pool_member(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "api_pool": [
                        "192.0.2.10:443",
                        "192.0.2.11:443",
                    ]
                },
                "irule": """
when HTTP_REQUEST {
    pool api_pool
    LB::down node 192.0.2.10 443
    LB::reselect
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertEqual(request_result["pool"], "api_pool")
        self.assertEqual(request_result["node"], "192.0.2.11")
        self.assertEqual(
            request_result["semantic"]["lb_status"]["192.0.2.10:443"],
            "down",
        )
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"].startswith("LB::")},
            {
                "LB::down": "semantic-mock",
                "LB::reselect": "semantic-mock",
            },
        )

    def test_lb_failure_injection_fires_event_info_and_fallback(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "primary_pool": ["192.0.2.10:443"],
                    "fallback_pool": ["192.0.2.20:443"],
                },
                "irule": """
when HTTP_REQUEST { pool primary_pool }
when LB_FAILED {
    log local0. "failure=[event info] before=[server_addr]:[server_port]"
    pool fallback_pool
    LB::reselect
}
""",
                "requests": [
                    {"uri": "/health", "lb_failure": "connection_timeout"},
                    {"uri": "/healthy"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertIn("LB_FAILED", request_result["events_fired"])
        self.assertLess(
            request_result["events_fired"].index("HTTP_REQUEST"),
            request_result["events_fired"].index("LB_FAILED"),
        )
        self.assertEqual(request_result["pool"], "fallback_pool")
        self.assertEqual(request_result["node"], "192.0.2.20")
        self.assertEqual(
            request_result["lb_failure"],
            {"cause": "connection_timeout", "fired": True, "selected": True},
        )
        self.assertTrue(
            any("failure=connection_timeout before=192.0.2.10:443" in entry
                for entry in request_result["logs"])
        )
        self.assertNotIn("lb_failure", result["results"][1])

    def test_failed_pool_selection_automatically_fires_lb_failed(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST {
    LB::down pool api_pool
    pool api_pool
}
when LB_FAILED { log local0. "automatic=[event info]" }
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertIn("LB_FAILED", request_result["events_fired"])
        self.assertEqual(
            request_result["lb_failure"],
            {"cause": "no_member", "fired": True, "selected": False},
        )
        self.assertTrue(any("automatic=no_member" in entry for entry in request_result["logs"]))

    def test_http_retry_replays_request_and_reselects_next_member(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "api_pool": ["192.0.2.10:443", "192.0.2.11:443"],
                },
                "irule": """
when CLIENT_ACCEPTED { set ::retried 0 }
when HTTP_REQUEST { pool api_pool }
when LB_SELECTED {
    if {$::retried} { LB::reselect pool api_pool }
}
when HTTP_RESPONSE {
    if {[HTTP::status] == 503 && !$::retried} {
        set ::retried 1
        HTTP::retry "GET /retry HTTP/1.1\r\nHost: retry.example.com\r\nX-Retry: yes\r\n\r\n"
    }
}
""",
                "requests": [
                    {
                        "uri": "/initial",
                        "host": "initial.example.com",
                        "response_status": 503,
                        "response_body": "temporary failure",
                    },
                    {
                        "uri": "/after-retry",
                        "host": "initial.example.com",
                        "response_status": 200,
                        "response_body": "ok",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result, next_result = result["results"]
        self.assertEqual(request_result["retry"], {"attempts": 1, "exhausted": False})
        self.assertEqual(request_result["node"], "192.0.2.11")
        self.assertEqual(request_result["request"]["uri"], "/retry")
        self.assertEqual(request_result["request"]["host"], "retry.example.com")
        self.assertEqual(request_result["request"]["headers"]["x-retry"], "yes")
        self.assertEqual(request_result["events_fired"].count("HTTP_REQUEST"), 2)
        self.assertEqual(request_result["events_fired"].count("HTTP_RESPONSE"), 2)
        self.assertTrue(any("http retry" in str(entry) for entry in request_result["decisions"]))
        self.assertNotIn("retry", next_result)
        self.assertEqual(next_result["request"]["uri"], "/after-retry")

    def test_http_retry_has_bounded_attempts(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST { pool api_pool }
when HTTP_RESPONSE { HTTP::retry }
""",
                "request": {
                    "uri": "/always-retry",
                    "response_status": 503,
                    "response_body": "temporary failure",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertEqual(request_result["retry"], {"attempts": 8, "exhausted": True})
        self.assertEqual(request_result["events_fired"].count("HTTP_RESPONSE"), 9)

    def test_http_keepalive_and_redirect_are_state_derived(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "keepalive=[HTTP::is_keepalive] header=[HTTP::header is_keepalive]"
}
when HTTP_RESPONSE {
    log local0. "redirect=[HTTP::is_redirect] header=[HTTP::header is_redirect]"
}
""",
                "requests": [
                    {
                        "headers": {"Connection": "close"},
                        "response_status": 302,
                        "response_headers": {"Location": "/new"},
                        "response_body": "redirect",
                    },
                    {
                        "response_status": 304,
                        "response_headers": {"Location": "/not-a-redirect"},
                        "response_body": "not modified",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first, second = result["results"]
        self.assertTrue(any("keepalive=0 header=0" in entry for entry in first["logs"]))
        self.assertTrue(any("redirect=1 header=1" in entry for entry in first["logs"]))
        self.assertTrue(any("keepalive=1 header=1" in entry for entry in second["logs"]))
        self.assertTrue(any("redirect=0 header=0" in entry for entry in second["logs"]))

    def test_http_redirect_commits_response_and_has_responded_tracks_it(self) -> None:
        request_redirect = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": (
                    'when HTTP_REQUEST { '
                    'HTTP::redirect "https://example.com/new"; '
                    'set header_rc [catch {HTTP::header insert X-After blocked}]; '
                    'log local0. "responded=[HTTP::has_responded] header_rc=$header_rc" '
                    '}'
                ),
                "requests": [{"uri": "/old"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )["results"][0]
        self.assertTrue(request_redirect["response_committed"])
        self.assertEqual(request_redirect["response"]["status"], 302)
        self.assertEqual(request_redirect["response"]["headers"]["location"], "https://example.com/new")
        self.assertEqual(request_redirect["response"]["body"], "")
        self.assertTrue(any("responded=1 header_rc=1" in entry for entry in request_redirect["logs"]))
        self.assertEqual(request_redirect["pool"], "")

        direct_response = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": (
                    'when HTTP_REQUEST { HTTP::respond 401 content "denied"; '
                    'log local0. "responded=[HTTP::has_responded]" }'
                ),
                "requests": [{"uri": "/private"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )["results"][0]
        self.assertTrue(direct_response["response_committed"])
        self.assertEqual(direct_response["response"]["status"], 401)
        self.assertEqual(direct_response["response"]["body"], "denied")
        self.assertTrue(any("responded=1" in entry for entry in direct_response["logs"]))

        response_redirect = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "irule": (
                    "when HTTP_REQUEST { pool api_pool } "
                    'when HTTP_RESPONSE { if {[HTTP::status] == 404} { '
                    'HTTP::redirect "/fallback"; '
                    'log local0. "responded=[HTTP::has_responded]" } }'
                ),
                "request": {
                    "uri": "/missing",
                    "response_status": 404,
                    "response_headers": {"Content-Length": "7"},
                    "response_body": "missing",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )["results"][0]
        self.assertEqual(response_redirect["response"]["status"], 302)
        self.assertEqual(response_redirect["response"]["headers"]["location"], "/fallback")
        self.assertEqual(response_redirect["response"]["headers"].get("content-length"), None)
        self.assertTrue(any("responded=1" in entry for entry in response_redirect["logs"]))

    def test_http_request_num_tracks_connection_requests_and_resets(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": 'when HTTP_REQUEST { log local0. "request-num=[HTTP::request_num]" }',
                "requests": [
                    {"uri": "/one"},
                    {"uri": "/two"},
                    {"uri": "/new-connection", "close_before": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first, second, third = result["results"]
        self.assertTrue(any("request-num=1" in entry for entry in first["logs"]))
        self.assertTrue(any("request-num=2" in entry for entry in second["logs"]))
        self.assertTrue(any("request-num=1" in entry for entry in third["logs"]))

    def test_http_close_terminates_persistent_session(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when CLIENT_ACCEPTED { log local0. accepted }
when HTTP_REQUEST { log local0. request }
when HTTP_RESPONSE { HTTP::close }
when CLIENT_CLOSED { log local0. closed }
""",
                "requests": [
                    {"uri": "/one", "response_body": "one"},
                    {"uri": "/two", "response_body": "two"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first, second = result["results"]
        self.assertEqual(first["connection_state"], "closing")
        self.assertIn("CLIENT_CLOSED", first["events_fired"])
        self.assertTrue(any("closed" in entry for entry in first["logs"]))
        self.assertIn("CLIENT_ACCEPTED", second["events_fired"])
        self.assertTrue(any("accepted" in entry for entry in second["logs"]))

    def test_lb_server_reports_selected_member(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when CLIENT_ACCEPTED { log local0. "before=[LB::server]" }
when HTTP_REQUEST { pool api_pool }
when LB_SELECTED {
    log local0. "server=[LB::server] pool=[LB::server pool] addr=[LB::server addr] port=[LB::server port] priority=[LB::server priority]"
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(any("before=" in entry for entry in logs))
        self.assertTrue(
            any(
                "server=api_pool 192.0.2.10 443 pool=api_pool addr=192.0.2.10 port=443 priority=1"
                in entry
                for entry in logs
            )
        )

    def test_lb_server_hides_pool_member_after_direct_node_override(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST {
    pool api_pool
    node 192.0.2.99 8080
    log local0. "server=[LB::server] addr=[LB::server addr] port=[LB::server port]"
}
""",
                "request": {"uri": "/node"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(any("server=api_pool addr= port=" in entry for entry in logs))

    def test_http_request_and_response_return_raw_header_blocks(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "request=[HTTP::request]"
}
when HTTP_RESPONSE {
    log local0. "response=[HTTP::response]"
}
""",
                "request": {
                    "method": "POST",
                    "uri": "/submit?mode=full",
                    "host": "api.example.com",
                    "headers": {"X-Test": "yes"},
                    "body": "payload",
                    "response_status": 503,
                    "response_headers": {"X-Upstream": "retry", "Location": "/later"},
                    "response_body": "temporary failure",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(
            any(
                "request=POST /submit?mode=full HTTP/1.1\r\n"
                in entry
                for entry in logs
            )
        )
        self.assertTrue(
            any(
                "X-Test: yes\r\nHost: api.example.com\r\n\r\n"
                in entry
                for entry in logs
            )
        )
        self.assertTrue(
            any(
                "response=HTTP/1.1 503 Service Unavailable\r\nX-Upstream: retry\r\nLocation: /later\r\n\r\n"
                in entry
                for entry in logs
            )
        )

    def test_semantic_overlay_preserves_lb_select_pool_integration(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "api_pool": [
                        "192.0.2.10:443",
                        "192.0.2.11:443",
                    ]
                },
                "irule": """
when HTTP_REQUEST {
    LB::select pool api_pool
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["results"][0]["pool"], "api_pool")
        self.assertEqual(result["results"][0]["node"], "192.0.2.10")

    def test_semantic_overlay_persists_and_restores_member_across_requests(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443", "192.0.2.11:443"]},
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/seed"} {
        pool api_pool
        persist add uie client-key 60 api_pool 192.0.2.10:443
    } elseif {[HTTP::uri] eq "/restore"} {
        set member [LB::persist client-key]
        HTTP::header insert X-Persisted $member
        HTTP::header insert X-Lookup-Node [persist lookup uie client-key node]
        HTTP::header insert X-Lookup-Pool [persist lookup uie client-key pool]
    } elseif {[HTTP::uri] eq "/delete"} {
        persist delete uie client-key
    } else {
        HTTP::header insert X-Persisted [LB::persist client-key]
    }
}
""",
                "requests": [
                    {"uri": "/seed"},
                    {"uri": "/restore"},
                    {"uri": "/delete"},
                    {"uri": "/missing"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        seeded, restored, deleted, missing = result["results"]
        self.assertEqual(seeded["node"], "192.0.2.10")
        self.assertEqual(restored["node"], "192.0.2.10")
        self.assertEqual(restored["request"]["headers"]["x-persisted"], "192.0.2.10:443")
        self.assertEqual(restored["request"]["headers"]["x-lookup-node"], "192.0.2.10")
        self.assertEqual(restored["request"]["headers"]["x-lookup-pool"], "api_pool")
        self.assertEqual(deleted["node"], "")
        self.assertEqual(missing["request"]["headers"]["x-persisted"], "")
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] in {"LB::persist", "persist"}
            },
            {"LB::persist": "semantic-mock", "persist": "semantic-mock"},
        )

    def test_semantic_overlay_models_connection_table_subtables_and_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/write"} {
        table set -subtable counters visits 1 60 60
        table incr -subtable counters visits 2
        table append -subtable counters message " ok"
        table add -subtable counters added first indefinite 60
        table replace -subtable counters added second 30 60
        table set -subtable other visits 9 indefinite indefinite
    } elseif {[HTTP::uri] eq "/read"} {
        HTTP::header insert X-Visits [table lookup -subtable counters visits]
        HTTP::header insert X-Message [table lookup -subtable counters message]
        HTTP::header insert X-Added [table lookup -subtable counters added]
        HTTP::header insert X-Keys [table keys -subtable counters -count]
        HTTP::header insert X-Timeout [table timeout -subtable counters visits]
        HTTP::header insert X-Lifetime [table lifetime -subtable counters added]
    } elseif {[HTTP::uri] eq "/delete"} {
        table delete -subtable counters -all
    } else {
        HTTP::header insert X-Visits [table lookup -subtable counters visits]
        HTTP::header insert X-Keys [table keys -subtable counters -count]
    }
}
""",
                "requests": [
                    {"uri": "/write"},
                    {"uri": "/read"},
                    {"uri": "/delete"},
                    {"uri": "/empty"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        written, read, deleted, empty = result["results"]
        self.assertEqual(read["request"]["headers"]["x-visits"], "3")
        self.assertEqual(read["request"]["headers"]["x-message"], " ok")
        self.assertEqual(read["request"]["headers"]["x-added"], "second")
        self.assertEqual(read["request"]["headers"]["x-keys"], "3")
        self.assertEqual(read["request"]["headers"]["x-timeout"], "60")
        self.assertEqual(read["request"]["headers"]["x-lifetime"], "30")
        self.assertEqual(empty["request"]["headers"]["x-visits"], "")
        self.assertEqual(empty["request"]["headers"]["x-keys"], "0")
        self.assertEqual(
            {entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"] == "table"},
            {"semantic-mock"},
        )
        self.assertEqual(
            {entry["key"] for entry in read["semantic"]["table"]},
            {"visits", "message", "added"},
        )

    def test_semantic_overlay_models_class_data_groups_and_iterators(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "datagroups": {
                    "allowed_paths": {
                        "type": "string",
                        "records": {"/health": "allow", "/api": "allow"},
                    },
                    "route_map": {
                        "type": "string",
                        "records": {"admin": "pool_admin", "public": "pool_public"},
                    },
                },
                "irule": """
when HTTP_REQUEST {
    HTTP::header insert X-Match [class match -- [HTTP::path] starts_with allowed_paths]
    HTTP::header insert X-Lookup [class lookup admin route_map]
    HTTP::header insert X-Type [class type route_map]
    HTTP::header insert X-Size [class size route_map]
    HTTP::header insert X-Element [class element -value 0 route_map]
    HTTP::header insert X-Names [class names -nocase route_map A*]
    set search [class startsearch route_map]
    set first [class nextelement $search]
    set has_more [class anymore $search]
    class donesearch $search
    HTTP::header insert X-Search "$first:$has_more"
}
""",
                "request": {"uri": "/healthz"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request = result["results"][0]["request"]
        self.assertEqual(request["headers"]["x-match"], "1")
        self.assertEqual(request["headers"]["x-lookup"], "pool_admin")
        self.assertEqual(request["headers"]["x-type"], "string")
        self.assertEqual(request["headers"]["x-size"], "2")
        self.assertEqual(request["headers"]["x-element"], "pool_admin")
        self.assertEqual(request["headers"]["x-names"], "admin")
        self.assertEqual(request["headers"]["x-search"], "admin:1")
        self.assertEqual(
            {entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"] == "class"},
            {"semantic-mock"},
        )

    def test_semantic_overlay_models_request_and_response_cookie_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    HTTP::header insert X-Session [HTTP::cookie value session]
    HTTP::cookie insert name request_seen value yes
    HTTP::cookie remove obsolete
}
when HTTP_RESPONSE {
    HTTP::cookie insert name issued value abc path /
    HTTP::cookie remove expired
}
""",
                "request": {
                    "uri": "/cookie",
                    "headers": {"Cookie": "session=abc; obsolete=gone"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request_result = result["results"][0]
        self.assertEqual(request_result["request"]["headers"]["x-session"], "abc")
        self.assertEqual(
            request_result["request"]["headers"]["cookie"],
            "session=abc; request_seen=yes",
        )
        self.assertEqual(
            request_result["response"]["headers"]["set-cookie"],
            ["issued=abc; Path=/", "expired=; Max-Age=0"],
        )
        self.assertEqual(
            {entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"] == "HTTP::cookie"},
            {"semantic-mock"},
        )

    def test_semantic_overlay_handles_zero_stats_and_malformed_uri_octets(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set decoded [URI::decode %FF]
    STATS::set app floor 0
    STATS::setmin app floor 5
    STATS::set app ceiling 0
    STATS::setmax app ceiling -1
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            result["results"][0]["semantic"]["stats"],
            {"app|floor": "0", "app|ceiling": "0"},
        )

    def test_semantic_overlay_compares_and_escapes_uris(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    HTTP::header insert X-Compare [URI::compare http://Example.com/a HTTP://example.com:80/a]
    HTTP::header insert X-Escape [URI::escape {a b/c}]
    HTTP::header insert X-Profiles [PROFILE::list http]
}
""",
                "request": {"uri": "/health"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        headers = result["results"][0]["request"]["headers"]
        self.assertEqual(headers["x-compare"], "1")
        self.assertEqual(headers["x-escape"], "a%20b/c")
        self.assertEqual(headers["x-profiles"], "HTTP")

    def test_packet_trace_drives_transport_tls_and_http_events(self) -> None:
        scenario = {
            "profiles": ["TCP", "CLIENTSSL", "HTTP"],
            "pools": {"api_pool": ["10.0.0.10:80"]},
            "irule": (
                "when CLIENT_ACCEPTED { log local0. accepted }\n"
                "when CLIENTSSL_CLIENTHELLO { log local0. hello }\n"
                "when CLIENTSSL_HANDSHAKE { log local0. handshake }\n"
                "when HTTP_REQUEST { if {[HTTP::host] eq \"api.example.com\"} { pool api_pool } }\n"
                "when HTTP_RESPONSE { HTTP::header replace X-Trace packet }\n"
                "when CLIENT_CLOSED { log local0. closed }"
            ),
            "packets": [
                {
                    "protocol": "tcp",
                    "direction": "client_to_server",
                    "flags": ["SYN"],
                    "source": {"address": "10.0.0.5", "port": 51000},
                    "destination": {"address": "192.0.2.10", "port": 443},
                },
                {
                    "protocol": "tls",
                    "type": "client_hello",
                    "direction": "client_to_server",
                    "sni": "api.example.com",
                },
                {
                    "protocol": "tls",
                    "type": "handshake",
                    "direction": "client_to_server",
                    "cipher_version": "TLSv1.3",
                },
                {
                    "protocol": "http",
                    "direction": "client_to_server",
                    "method": "GET",
                    "uri": "/health",
                    "host": "api.example.com",
                },
                {
                    "protocol": "http",
                    "direction": "server_to_client",
                    "status": 200,
                    "response_body": "ok",
                },
                {
                    "protocol": "tcp",
                    "direction": "client_to_server",
                    "flags": ["FIN", "ACK"],
                },
            ],
        }
        result = self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        self.assertEqual(result["packets_processed"], 6)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["pool"], "api_pool")
        self.assertEqual(result["results"][0]["response"]["body"], "ok")
        self.assertEqual(result["results"][0]["response"]["headers"]["x-trace"], "packet")
        events = [
            event["event"]
            for packet in result["trace"]
            for event in packet["events"]
        ]
        self.assertIn("CLIENT_ACCEPTED", events)
        self.assertIn("CLIENTSSL_CLIENTHELLO", events)
        self.assertIn("CLIENTSSL_HANDSHAKE", events)
        self.assertIn("CLIENT_CLOSED", events)

    def test_packet_trace_exposes_directional_tcp_payload_and_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    TCP::collect 11
}
when CLIENT_DATA {
    log local0. "client=[TCP::payload] length=[TCP::payload length] offset=[TCP::offset]"
    TCP::payload replace 0 6 edited!
    TCP::release 1
}
when SERVER_CONNECTED {
    TCP::collect 11
}
when SERVER_DATA {
    log local0. "server=[TCP::payload] length=[TCP::payload length]"
    TCP::respond reply
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "client-data",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "payload": "server-data",
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        client_event = result["trace"][1]["events"][0]
        server_connected = result["trace"][2]["events"][0]
        server_event = result["trace"][2]["events"][1]
        self.assertEqual(client_event["event"], "CLIENT_DATA")
        self.assertTrue(
            any("client=client-data length=11 offset=11" in entry for entry in client_event["logs"])
        )
        self.assertIn("tcp payload_replace", str(client_event["decisions"]))
        self.assertEqual(server_event["event"], "SERVER_DATA")
        self.assertEqual(server_connected["event"], "SERVER_CONNECTED")
        self.assertTrue(
            any("server=server-data length=11" in entry for entry in server_event["logs"])
        )
        self.assertIn("tcp respond", str(server_event["decisions"]))
        self.assertEqual(
            result["emitted"],
            [
                {
                    "protocol": "tcp",
                    "side": "server",
                    "direction": "client_to_server",
                    "payload": "reply",
                    "byte_length": 5,
                    "packet_index": 2,
                    "event": "SERVER_DATA",
                }
            ],
        )

    def test_packet_trace_drives_websocket_events_and_byte_payload_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": """
when WS_REQUEST {
    log local0. "request=[WS::request key]"
}
when WS_RESPONSE {
    log local0. "response=[WS::response key] valid=[WS::response valid]"
}
when WS_CLIENT_FRAME {
    log local0. "frame=[WS::frame type] eom=[WS::frame eom] masked=[WS::frame orig_masked]"
    WS::collect frame
}
when WS_CLIENT_DATA {
    binary scan [WS::payload 2] H* first
    WS::payload replace 1 2 X
    binary scan [WS::payload] H* replaced
    log local0. "data-length=[WS::payload length] first=$first replaced=$replaced"
    WS::release
}
when WS_CLIENT_FRAME_DONE { log local0. client-done }
when WS_SERVER_FRAME { WS::collect frame 3 }
when WS_SERVER_DATA {
    log local0. "server-data=[WS::payload]"
    WS::release
}
when WS_SERVER_FRAME_DONE { log local0. server-done }
""",
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "method": "GET",
                        "uri": "/socket",
                        "host": "example.com",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "keep-alive, Upgrade",
                            "Sec-WebSocket-Key": "abc",
                            "Sec-WebSocket-Version": "13",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "response_headers": {
                            "Upgrade": "WebSocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "fin": True,
                        "masked": True,
                        "mask": "01020304",
                        "payload": "Józ",
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "server_to_client",
                        "frame_type": "text",
                        "fin": True,
                        "masked": False,
                        "payload": "world",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        events = [
            event["event"]
            for packet in result["trace"]
            for event in packet["events"]
        ]
        self.assertEqual(
            events,
            [
                "RULE_INIT",
                "CLIENT_ACCEPTED",
                "WS_REQUEST",
                "WS_RESPONSE",
                "WS_CLIENT_FRAME",
                "WS_CLIENT_DATA",
                "WS_CLIENT_FRAME_DONE",
                "WS_SERVER_FRAME",
                "WS_SERVER_DATA",
                "WS_SERVER_FRAME_DONE",
            ],
        )
        request_event = next(
            event for event in result["trace"][0]["events"] if event["event"] == "WS_REQUEST"
        )
        response_event = next(
            event for event in result["trace"][1]["events"] if event["event"] == "WS_RESPONSE"
        )
        client_data_event = next(
            event for event in result["trace"][2]["events"] if event["event"] == "WS_CLIENT_DATA"
        )
        server_data_event = next(
            event for event in result["trace"][3]["events"] if event["event"] == "WS_SERVER_DATA"
        )
        self.assertTrue(
            any("request=abc" in entry for entry in request_event["logs"])
        )
        self.assertTrue(
            any(
                "response=xyz valid=1" in entry
                for entry in response_event["logs"]
            )
        )
        self.assertTrue(
            any(
                "data-length=3 first=4ac3 replaced=4a587a" in entry
                for entry in client_data_event["logs"]
            )
        )
        self.assertTrue(
            any("server-data=world" in entry for entry in server_data_event["logs"])
        )
        self.assertEqual(result["trace"][2]["payload"], "Józ")

    def test_websocket_processing_honors_collection_thresholds_and_drops(self) -> None:
        threshold = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": (
                    "when WS_CLIENT_FRAME { WS::collect frame 4 } "
                    "when WS_CLIENT_DATA { log local0. unexpected }"
                ),
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "payload": "abc",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        threshold_events = [
            event["event"]
            for event in threshold["trace"][2]["events"]
        ]
        self.assertEqual(threshold_events, ["WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE"])
        self.assertNotIn("unexpected", str(threshold["trace"][2]))

        dropped = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": (
                    "when WS_CLIENT_FRAME { "
                    "if {[WS::frame type] eq \"text\"} { WS::collect frame; WS::message drop }"
                    " } "
                    "when WS_CLIENT_DATA { log local0. unexpected }"
                ),
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "fin": False,
                        "payload": "abc",
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "continuation",
                        "fin": True,
                        "payload": "def",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(dropped["trace"][2]["dropped"])
        self.assertEqual(dropped["trace"][2]["drop_reason"], "message")
        self.assertEqual(
            [event["event"] for event in dropped["trace"][2]["events"]],
            ["WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertTrue(dropped["trace"][3]["dropped"])
        self.assertEqual(dropped["trace"][3]["drop_reason"], "message")
        self.assertEqual(
            [event["event"] for event in dropped["trace"][3]["events"]],
            ["WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertNotIn("WS_CLIENT_DATA", str(dropped["trace"][2]))
        self.assertNotIn("WS_CLIENT_DATA", str(dropped["trace"][3]))

    def test_websocket_collection_uses_frame_payload_and_release_rearms(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": """
when WS_CLIENT_FRAME { WS::collect frame 4 }
when WS_CLIENT_DATA {
    log local0. "collected=[WS::payload] length=[WS::payload length]"
    WS::release
}
""",
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "fin": False,
                        "payload": "ab",
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "continuation",
                        "fin": True,
                        "payload": "cdef",
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "fin": True,
                        "payload": "wxyz",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_data = result["trace"][2]["events"]
        second_data = result["trace"][3]["events"]
        self.assertEqual(
            [event["event"] for event in first_data],
            ["WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertEqual(
            [event["event"] for event in second_data],
            ["WS_CLIENT_FRAME", "WS_CLIENT_DATA", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertIn("collected=cdef length=4", str(second_data[1]["logs"]))
        self.assertEqual(
            [event["event"] for event in result["trace"][4]["events"]],
            ["WS_CLIENT_FRAME", "WS_CLIENT_DATA", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertIn(
            "collected=wxyz length=4",
            str(result["trace"][4]["events"][1]["logs"]),
        )

    def test_websocket_disconnect_emits_bounded_close_result(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": 'when WS_CLIENT_FRAME_DONE { WS::disconnect 1008 "policy" }',
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "text",
                        "payload": "hello",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        close_event = result["trace"][2]["events"][-1]
        self.assertEqual(close_event["event"], "WS_CLIENT_FRAME_DONE")
        self.assertEqual(
            close_event["emissions"],
            [
                {
                    "protocol": "websocket",
                    "type": "frame",
                    "frame_type": "close",
                    "side": "client",
                    "direction": "server_to_client",
                    "fin": "1",
                    "masked": "0",
                    "mask": "",
                    "close_code": 1008,
                    "close_reason": "policy",
                    "payload_hex": "03f0706f6c696379",
                    "byte_length": 8,
                    "control": "CLOSE",
                },
                {
                    "protocol": "websocket",
                    "type": "frame",
                    "frame_type": "close",
                    "side": "server",
                    "direction": "client_to_server",
                    "fin": "1",
                    "masked": "1",
                    "mask": "",
                    "close_code": 1008,
                    "close_reason": "policy",
                    "payload_hex": "03f0706f6c696379",
                    "byte_length": 8,
                    "control": "CLOSE",
                },
            ],
        )
        self.assertEqual(
            result["emitted"],
            [
                {
                    **emission,
                    "packet_index": 2,
                    "event": "WS_CLIENT_FRAME_DONE",
                }
                for emission in close_event["emissions"]
            ],
        )

    def test_websocket_control_frames_do_not_enter_data_collection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": (
                    "when WS_CLIENT_FRAME { WS::collect frame } "
                    "when WS_CLIENT_DATA { log local0. unexpected }"
                ),
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "frame",
                        "direction": "client_to_server",
                        "frame_type": "ping",
                        "payload": "keepalive",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            [event["event"] for event in result["trace"][2]["events"]],
            ["WS_CLIENT_FRAME", "WS_CLIENT_FRAME_DONE"],
        )
        self.assertNotIn("unexpected", str(result["trace"][2]))

    def test_websocket_disabled_processing_and_invalid_upgrade_are_ignored(self) -> None:
        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": (
                    "when WS_REQUEST { WS::enabled false } "
                    "when WS_RESPONSE { log local0. unexpected }"
                ),
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "abc",
                        },
                    },
                    {
                        "protocol": "websocket",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 101,
                        "response_headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Accept": "xyz",
                        },
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertIn(
            "WS_REQUEST",
            [event["event"] for event in disabled["trace"][0]["events"]],
        )
        self.assertEqual(disabled["trace"][1]["ignored"], "WebSocket processing is disabled")
        self.assertNotIn("unexpected", str(disabled["trace"][1]))

        invalid = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": "when WS_REQUEST { log local0. unexpected }",
                "packets": [
                    {
                        "protocol": "websocket",
                        "type": "request",
                        "direction": "client_to_server",
                        "headers": {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                        },
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(invalid["trace"][0]["ignored"], "WebSocket upgrade headers are incomplete")
        self.assertNotIn("unexpected", str(invalid["trace"][0]))

        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "WS"],
                    "irule": "when WS_CLIENT_FRAME { log local0. frame }",
                    "packets": [
                        {
                            "protocol": "websocket",
                            "type": "frame",
                            "direction": "client_to_server",
                            "frame_type": "text",
                            "fin": {"unexpected": "object"},
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_packet_trace_gates_tcp_data_until_collection_length_and_skip_are_met(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect 5 2 }
when CLIENT_DATA {
    log local0. "collected=[TCP::payload] offset=[TCP::offset]"
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "ab",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "cdefgh",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertTrue(result["trace"][1]["buffered"])
        self.assertEqual(result["trace"][1]["events"], [])
        data_event = result["trace"][2]["events"][0]
        self.assertEqual(data_event["event"], "CLIENT_DATA")
        self.assertTrue(
            any("collected=cdefg offset=5" in entry for entry in data_event["logs"])
        )

    def test_tcp_collect_can_be_rearmed_from_data_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect 3 }
when CLIENT_DATA {
    log local0. "collected=[TCP::payload]"
    TCP::collect 3
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "one",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "two",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first_event = result["trace"][1]["events"][0]
        second_event = result["trace"][2]["events"][0]
        self.assertTrue(any("collected=one" in entry for entry in first_event["logs"]))
        self.assertTrue(any("collected=two" in entry for entry in second_event["logs"]))

    def test_tcp_collection_buffer_survives_persistent_trace_calls(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect 3 }
when CLIENT_DATA { log local0. "collected=[TCP::payload]" }
""",
            },
            allow_irule_file=False,
            allow_requests=False,
            allow_packets=True,
        )
        try:
            first = session.run_packet_trace(
                [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "a",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ]
            )
            second = session.run_packet_trace(
                [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "bc",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    }
                ]
            )
        finally:
            session.close()

        self.assertTrue(first["trace"][1]["buffered"])
        data_event = second["trace"][0]["events"][0]
        self.assertEqual(data_event["event"], "CLIENT_DATA")
        self.assertTrue(any("collected=abc" in entry for entry in data_event["logs"]))

    def test_tcp_collect_without_length_fires_for_each_received_packet(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect }
when CLIENT_DATA { log local0. "collected=[TCP::payload]" }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "one",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "two",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first_event = result["trace"][1]["events"][0]
        second_event = result["trace"][2]["events"][0]
        self.assertTrue(any("collected=one" in entry for entry in first_event["logs"]))
        self.assertTrue(any("collected=two" in entry for entry in second_event["logs"]))

    def test_tcp_release_stops_continuous_collection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect }
when CLIENT_DATA {
    log local0. "collected=[TCP::payload]"
    TCP::release
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "one",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "two",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(len(result["trace"][1]["events"]), 1)
        self.assertEqual(result["trace"][2]["events"], [])
        self.assertTrue(
            any("collected=one" in entry for entry in result["trace"][1]["events"][0]["logs"])
        )

    def test_peer_switches_tcp_context_and_emits_to_the_opposite_side(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    TCP::collect
    peer { TCP::collect 4 }
}
when CLIENT_DATA { peer { TCP::respond peer-reply } }
when SERVER_DATA { log local0. "server=[TCP::payload]" }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "client-data",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "payload": "pong",
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        client_event = result["trace"][1]["events"][0]
        server_event = result["trace"][2]["events"][1]
        self.assertEqual(client_event["event"], "CLIENT_DATA")
        self.assertEqual(server_event["event"], "SERVER_DATA")
        self.assertTrue(any("server=pong" in entry for entry in server_event["logs"]))
        self.assertEqual(result["emitted"][0]["side"], "server")
        self.assertEqual(result["emitted"][0]["direction"], "client_to_server")
        self.assertEqual(result["emitted"][0]["payload"], "peer-reply")

    def test_tcp_close_emits_fin_without_tearing_down_until_peer_fin(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect }
when CLIENT_DATA { TCP::close; TCP::close }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload": "hello",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "flags": ["FIN", "ACK"],
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        close_event = result["trace"][1]["events"][0]
        self.assertEqual(close_event["event"], "CLIENT_DATA")
        self.assertEqual(
            result["emitted"][0],
            {
                "protocol": "tcp",
                "side": "client",
                "direction": "server_to_client",
                "control": "FIN",
                "packet_index": 1,
                "event": "CLIENT_DATA",
            },
        )
        self.assertEqual(result["trace"][2]["events"][-1]["event"], "SERVER_CLOSED")

    def test_raw_ipv4_tcp_packets_decode_into_http_transaction(self) -> None:
        request_payload = b"GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        tls_payload = _tls_client_hello_payload("api.example.com")
        response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        scenario = {
            "profiles": ["TCP", "CLIENTSSL", "HTTP"],
            "pools": {"api_pool": ["10.0.0.10:80"]},
            "irule": (
                "when CLIENTSSL_CLIENTHELLO { log local0. hello }\n"
                "when HTTP_REQUEST { pool api_pool }"
            ),
            "packets": [
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                        tls_payload[: len(tls_payload) // 2],
                        sequence=1001,
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                        tls_payload[len(tls_payload) // 2 :],
                        sequence=1001 + len(tls_payload) // 2,
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                        request_payload[:20],
                        sequence=1001 + len(tls_payload),
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                        request_payload[20:],
                        sequence=1001 + len(tls_payload) + 20,
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "server_to_client",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "192.0.2.10", "10.0.0.5", 443, 51000, 0x18, response_payload,
                        sequence=5000,
                    ),
                },
            ],
        }
        result = self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        self.assertEqual(result["packets_processed"], 6)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["request"]["uri"], "/health")
        self.assertEqual(result["results"][0]["response"]["status"], 200)
        self.assertEqual(result["results"][0]["response"]["body"], "ok")

    def test_mqtt_structured_messages_drive_ingress_data_and_field_commands(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MQTT"],
                "irule": """
when MQTT_CLIENT_INGRESS {
    log local0. "client=[MQTT::client_id] type=[MQTT::type] topic=[MQTT::topic]"
    if {[MQTT::type] eq "PUBLISH"} { MQTT::collect 3 }
}
when MQTT_CLIENT_DATA {
    log local0. "payload=[MQTT::payload] length=[MQTT::payload length]"
    MQTT::payload replace xyz
    MQTT::release
}
when MQTT_SERVER_INGRESS {
    log local0. "server=[MQTT::type] code=[MQTT::return_code]"
    MQTT::drop
}
""",
                "packets": [
                    {
                        "protocol": "mqtt",
                        "type": "CONNECT",
                        "direction": "client_to_server",
                        "client_id": "sensor-1",
                        "clean_session": True,
                        "keep_alive": 30,
                    },
                    {
                        "protocol": "mqtt",
                        "type": "PUBLISH",
                        "direction": "client_to_server",
                        "topic": "sensors/temp",
                        "payload": "abc",
                        "qos": 0,
                    },
                    {
                        "protocol": "mqtt",
                        "type": "CONNACK",
                        "direction": "server_to_client",
                        "return_code": 0,
                        "session_present": True,
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        publish_events = result["trace"][1]["events"]
        connack_events = result["trace"][2]["events"]
        self.assertEqual(
            [event["event"] for event in publish_events],
            ["MQTT_CLIENT_INGRESS", "MQTT_CLIENT_DATA"],
        )
        self.assertTrue(
            any("client=sensor-1 type=PUBLISH topic=sensors/temp" in entry for entry in publish_events[0]["logs"])
        )
        self.assertTrue(
            any("payload=abc length=3" in entry for entry in publish_events[1]["logs"])
        )
        self.assertEqual(publish_events[1]["state"]["mqtt"]["payload"], "xyz")
        self.assertTrue(connack_events[-1]["fired"])
        self.assertTrue(any("server=CONNACK code=0" in entry for entry in connack_events[-1]["logs"]))
        self.assertTrue(result["trace"][2]["dropped"])
        self.assertEqual(result["trace"][2]["drop_reason"], "message")
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("MQTT::collect", "MQTT::payload", "MQTT::release", "MQTT::drop"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_raw_mqtt_tcp_reassembly_handles_partial_messages_and_shutdown(self) -> None:
        connect = bytes.fromhex("101400044d5154540402001e000873656e736f722d31")
        publish = bytes.fromhex("300800017868656c6c6f")
        result = self.adapter.run_scenario(
            {
                "profiles": ["MQTT"],
                "irule": """
when MQTT_CLIENT_INGRESS {
    log local0. "type=[MQTT::type] client=[MQTT::client_id] topic=[MQTT::topic]"
    if {[MQTT::type] eq "PUBLISH"} { MQTT::collect }
}
when MQTT_CLIENT_DATA {
    log local0. "payload=[MQTT::payload] message-length=[MQTT::length]"
    MQTT::release
}
when MQTT_CLIENT_SHUTDOWN { log local0. shutdown }
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 1883, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 1883, 0x18,
                            connect[:7], sequence=1001,
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 1883, 0x18,
                            connect[7:], sequence=1008,
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 1883, 0x18,
                            publish, sequence=1023,
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 1883, 0x11,
                            sequence=1033,
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        mqtt_entries = [
            entry
            for entry in result["trace"]
            if any(event["event"] == "MQTT_CLIENT_INGRESS" for event in entry["events"])
        ]
        self.assertEqual(len(mqtt_entries), 2)
        self.assertTrue(any("type=CONNECT client=sensor-1" in entry for entry in mqtt_entries[0]["events"][-1]["logs"]))
        self.assertTrue(any("type=PUBLISH client=sensor-1 topic=x" in entry for entry in mqtt_entries[1]["events"][0]["logs"]))
        self.assertTrue(any("payload=hello message-length=10" in entry for entry in mqtt_entries[1]["events"][1]["logs"]))
        shutdown = result["trace"][-1]["events"][-2]
        self.assertEqual(shutdown["event"], "MQTT_CLIENT_SHUTDOWN")
        self.assertTrue(any("shutdown" in entry for entry in shutdown["logs"]))
        self.assertTrue(result["trace"][1]["buffered"])
        self.assertEqual(result["trace"][2]["protocol"], "mqtt")
        self.assertEqual(result["trace"][3]["protocol"], "mqtt")
        self.assertEqual(result["trace"][4]["protocol"], "tcp")

    def test_mqtt_rejects_unsupported_structured_direction_and_version(self) -> None:
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {
                    "profiles": ["MQTT"],
                    "irule": "when MQTT_SERVER_INGRESS { log local0. server }",
                    "packets": [
                        {
                            "protocol": "mqtt",
                            "direction": "server_to_client",
                            "type": "CONNECT",
                            "client_id": "bad-direction",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {
                    "profiles": ["MQTT"],
                    "irule": "when MQTT_CLIENT_INGRESS { log local0. client }",
                    "packets": [
                        {
                            "protocol": "mqtt",
                            "direction": "client_to_server",
                            "type": "CONNECT",
                            "protocol_version": 5,
                            "client_id": "bad-version",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_raw_ipv4_tcp_websocket_upgrade_and_frames_decode(self) -> None:
        request = (
            b"GET /socket HTTP/1.1\r\nHost: api.example.com\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: xyz\r\n\r\n"
        )
        mask = bytes.fromhex("01020304")
        client_payload = b"hello"
        client_frame = (
            b"\x81" + bytes([0x80 | len(client_payload)]) + mask
            + bytes(value ^ mask[index % 4] for index, value in enumerate(client_payload))
        )
        server_payload = b"world"
        server_frame = b"\x81" + bytes([len(server_payload)]) + server_payload
        response += server_frame
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "WS"],
                "irule": """
when WS_REQUEST { log local0. "raw-request=[WS::request key]" }
when WS_RESPONSE { log local0. "raw-response=[WS::response valid]" }
when WS_CLIENT_FRAME { WS::collect frame }
when WS_CLIENT_DATA { log local0. "raw-client=[WS::payload]" }
when WS_SERVER_FRAME { WS::collect frame }
when WS_SERVER_DATA { log local0. "raw-server=[WS::payload]" }
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            request, sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            response, sequence=5000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            client_frame, sequence=1001 + len(request)
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            [entry["protocol"] for entry in result["trace"]],
            ["tcp", "websocket", "websocket", "websocket", "websocket"],
        )
        self.assertEqual(
            [
                event["event"]
                for packet in result["trace"]
                for event in packet["events"]
                if event["event"].startswith("WS_")
            ],
            [
                "WS_REQUEST",
                "WS_RESPONSE",
                "WS_SERVER_FRAME",
                "WS_SERVER_DATA",
                "WS_SERVER_FRAME_DONE",
                "WS_CLIENT_FRAME",
                "WS_CLIENT_DATA",
                "WS_CLIENT_FRAME_DONE",
            ],
        )
        self.assertEqual(result["trace"][4]["payload"], "hello")
        self.assertEqual(result["trace"][4]["masked"], "1")
        self.assertTrue(
            any("raw-client=hello" in entry for entry in result["trace"][4]["events"][1]["logs"])
        )
        self.assertTrue(
            any("raw-server=world" in entry for entry in result["trace"][3]["events"][1]["logs"])
        )

    def test_websocket_frame_decoder_handles_partial_and_extended_lengths(self) -> None:
        payload = b"a" * 126
        frame = b"\x82\x7e\x00\x7e" + payload
        partial_frames, partial_remaining = self.adapter._decode_websocket_frames(
            frame[:5], "server_to_client"
        )
        self.assertEqual(partial_frames, [])
        self.assertEqual(partial_remaining, frame[:5])

        frames, remaining = self.adapter._decode_websocket_frames(
            partial_remaining + frame[5:], "server_to_client"
        )
        self.assertEqual(remaining, b"")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["frame_type"], "binary")
        self.assertEqual(frames[0]["masked"], "0")
        self.assertEqual(frames[0]["_wire_payload"], payload)
        self.assertEqual(len(frames[0]["payload"]), 126)

    def test_http_stream_decoder_honors_chunked_and_content_length_framing(self) -> None:
        request_one = b"GET /chunked HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        request_two = b"GET /length HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        response_one = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\npong\r\n0\r\nX-Trace: one\r\n\r\n"
        )
        response_two = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        response_two_split = len(response_two) // 2
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api_pool }",
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            request_one, sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            response_one, sequence=5000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            request_two, sequence=1001 + len(request_one)
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            response_two[:response_two_split], sequence=5000 + len(response_one)
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            response_two[response_two_split:],
                            sequence=5000 + len(response_one) + response_two_split
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["results"][0]["response"]["body"], "pong")
        self.assertEqual(result["results"][1]["response"]["body"], "ok")
        self.assertTrue(result["trace"][4]["buffered"])

    def test_http_stream_decoder_does_not_wait_for_no_body_status(self) -> None:
        decoded = self.adapter._decode_http_payload(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 999\r\n\r\n",
            "server_to_client",
        )
        self.assertIsNotNone(decoded)
        assert decoded is not None
        message, consumed = decoded
        self.assertEqual(message["status"], 204)
        self.assertEqual(message["response_body"], "")
        self.assertEqual(consumed, len(b"HTTP/1.1 204 No Content\r\nContent-Length: 999\r\n\r\n"))

    def test_http_stream_decoder_emits_coalesced_messages(self) -> None:
        request = b"GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        responses = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
            b"HTTP/1.1 204 No Content\r\n\r\n"
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api_pool }",
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            request, sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            responses, sequence=5000
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["response"]["body"], "ok")
        self.assertEqual([entry["protocol"] for entry in result["trace"]], ["tcp", "http", "http", "http"])
        self.assertEqual(result["trace"][3]["status"], 204)
        self.assertEqual(result["trace"][3]["ignored"], "HTTP response has no pending HTTP request")

    def test_http_continue_response_does_not_complete_pending_transaction(self) -> None:
        request = b"POST /upload HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        interim = b"HTTP/1.1 100 Continue\r\nX-Continue: yes\r\n\r\n"
        final = b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": (
                    "when HTTP_REQUEST { pool api_pool } "
                    'when HTTP_RESPONSE_CONTINUE { log local0. "continue=[HTTP::status] '
                    'header=[HTTP::header value X-Continue]" } '
                    'when HTTP_RESPONSE { log local0. "final=[HTTP::status]" }'
                ),
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            request, sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            interim, sequence=5000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            final, sequence=5000 + len(interim)
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["response"]["status"], 201)
        continue_event = result["trace"][2]["events"][0]
        self.assertTrue(
            any("continue=100 header=yes" in entry for entry in continue_event["logs"]),
            continue_event,
        )
        self.assertTrue(any("final=201" in entry for entry in result["results"][0]["logs"]))
        self.assertEqual(continue_event["event"], "HTTP_RESPONSE_CONTINUE")
        self.assertTrue(continue_event["fired"])

    def test_raw_ipv4_udp_dns_packet_decodes_query_state(self) -> None:
        dns_payload = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": "when DNS_REQUEST { log local0. dns-packet }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "10.0.0.5", "192.0.2.53", 53000, 53, dns_payload
                        ),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        packet = result["trace"][0]
        self.assertEqual(packet["protocol"], "dns")
        event = packet["events"][0]
        self.assertEqual(event["event"], "DNS_REQUEST")
        self.assertTrue(event["fired"])
        self.assertEqual(event["state"]["dns"]["qname"], "example.com")
        self.assertEqual(event["state"]["dns"]["qtype"], "A")

    def test_semantic_overlay_reads_dns_question_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": """
when DNS_REQUEST {
    log local0. "[DNS::question name] [DNS::question type] [DNS::origin]"
}
""",
                "packets": [
                    {
                        "protocol": "dns",
                        "direction": "client_to_server",
                        "qname": "example.com",
                        "qtype": "AAAA",
                        "qclass": "IN",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][0]
        self.assertIn("example.com AAAA client", event["logs"][0])
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"].startswith("DNS::")},
            {
                "DNS::origin": "semantic-mock",
                "DNS::question": "semantic-mock",
            },
        )

    def test_sequence_aware_reassembly_handles_out_of_order_and_retransmission(self) -> None:
        request_payload = b"GET /ordered HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        first = request_payload[:20]
        second = request_payload[20:]
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "irule": "when HTTP_REQUEST { pool api_pool }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            second, sequence=1021
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            first, sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                            second, sequence=1021
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", sequence=5000
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertTrue(result["trace"][1]["buffered"])
        self.assertEqual(result["trace"][2]["protocol"], "http")
        self.assertEqual(result["trace"][3]["ignored"], "tcp retransmission")
        self.assertEqual(result["results"][0]["request"]["uri"], "/ordered")
        self.assertEqual(result["results"][0]["response"]["status"], 200)

    def test_golden_capture_fixture_replays_to_expected_http_result(self) -> None:
        fixture = json.loads(
            (ROOT / "test" / "fixtures" / "pcap_golden.json").read_text(encoding="utf-8")
        )
        records = []
        for record in fixture["records"]:
            if record["direction"] == "client_to_server":
                source, destination = "10.0.0.5", "192.0.2.10"
                source_port, destination_port = 51000, 443
            else:
                source, destination = "192.0.2.10", "10.0.0.5"
                source_port, destination_port = 443, 51000
            raw_hex = _raw_ipv4_tcp_hex(
                source,
                destination,
                source_port,
                destination_port,
                record["flags"],
                record["payload"].encode("ascii"),
                sequence=record["sequence"],
            )
            records.append(
                (record["seconds"], record["fraction"], _ethernet_ipv4(raw_hex))
            )
        result = self.adapter.run_pcap_scenario(
            fixture["scenario"],
            _pcap_bytes(records),
            tcl_lsp_root=self.tcl_lsp_root,
            direction=fixture["direction"],
            client_addr=fixture["client_addr"],
            server_addr=fixture["server_addr"],
        )
        expected = fixture["expected"]
        self.assertEqual(result["packets_processed"], expected["packets_processed"])
        self.assertEqual(result["results"][0]["request"]["uri"], expected["request_uri"])
        self.assertEqual(result["results"][0]["response"]["status"], expected["response_status"])
        self.assertEqual(result["results"][0]["response"]["body"], expected["response_body"])
        self.assertEqual(result["trace"][expected["retransmission_trace_index"]]["ignored"], "tcp retransmission")
        self.assertEqual(result["trace"][0]["timestamp"], expected["timestamp"] - 0.4)

    def test_new_syn_closes_previous_pending_http_transaction_first(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api_pool }",
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "uri": "/first",
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.6", "port": 51001},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["request"]["uri"], "/first")
        self.assertEqual(result["trace"][0]["completed_at"], 1)

    def test_raw_wire_rejects_fragmented_ipv4_input(self) -> None:
        raw = bytearray.fromhex(
            _raw_ipv4_tcp_hex("10.0.0.5", "192.0.2.10", 51000, 443, 0x02)
        )
        raw[6:8] = (0x2000).to_bytes(2, "big")  # IPv4 more-fragments flag
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter._normalise_packets(
                [{"protocol": "wire", "direction": "client_to_server", "raw_hex": raw.hex()}]
            )

    def test_classic_pcap_replay_decodes_ethernet_and_preserves_timestamps(self) -> None:
        request_payload = b"GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        request_hex = _raw_ipv4_tcp_hex(
            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18, request_payload[:20], sequence=1001
        )
        request_tail_hex = _raw_ipv4_tcp_hex(
            "10.0.0.5", "192.0.2.10", 51000, 443, 0x18, request_payload[20:], sequence=1021
        )
        capture = _pcap_bytes(
            [
                (1, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                ))),
                (1, 500_000, _ethernet_ipv4(request_hex)),
                (1, 600_000, _ethernet_ipv4(request_tail_hex)),
                (2, 125_000, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "192.0.2.10", "10.0.0.5", 443, 51000, 0x18, response_payload,
                    sequence=2000,
                ))),
            ]
        )
        result = self.adapter.run_pcap_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "irule": "when HTTP_REQUEST { pool api_pool }",
            },
            capture,
            tcl_lsp_root=self.tcl_lsp_root,
            direction="auto",
            client_addr="10.0.0.5",
            server_addr="192.0.2.10",
        )

        self.assertEqual(result["capture"]["record_count"], 4)
        self.assertEqual(result["capture"]["ipv4_packet_count"], 4)
        self.assertEqual(result["capture"]["timestamp_resolution"], "microseconds")
        self.assertEqual(result["trace"][0]["timestamp"], 1.0)
        self.assertEqual(result["trace"][1]["timestamp"], 1.5)
        self.assertEqual(result["trace"][2]["timestamp"], 1.6)
        self.assertEqual(result["trace"][3]["timestamp"], 2.125)
        self.assertEqual(result["results"][0]["request"]["uri"], "/health")
        self.assertEqual(result["results"][0]["response"]["body"], "ok")

    def test_pcap_decoder_rejects_truncated_and_unsupported_captures(self) -> None:
        valid_header = _pcap_bytes([])
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter._pcap_packets(
                valid_header + struct.pack("<IIII", 1, 0, 20, 20) + b"short",
                direction="client_to_server",
                client_addr=None,
                server_addr=None,
            )
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter._pcap_packets(
                b"\x0a\x0d\x0d\x0a" + b"\x00" * 32,
                direction="client_to_server",
                client_addr=None,
                server_addr=None,
            )
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter._pcap_packets(
                _pcap_bytes(
                    [(1, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
                    )))],
                    linktype=147,
                ),
                direction="client_to_server",
                client_addr=None,
                server_addr=None,
            )
        nano_packets, nano_capture = self.adapter._pcap_packets(
            _pcap_bytes(
                [(7, 123_456_789, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
                )))],
                nano=True,
            ),
            direction="client_to_server",
            client_addr=None,
            server_addr=None,
        )
        self.assertEqual(nano_capture["timestamp_resolution"], "nanoseconds")
        self.assertAlmostEqual(nano_packets[0]["timestamp"], 7.123456789, places=9)

    def test_http_api_replays_base64_classic_pcap(self) -> None:
        dns_payload = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00"
            + struct.pack("!HH", 1, 1)
        )
        capture = _pcap_bytes([
            (3, 42, _ethernet_ipv4(_raw_ipv4_udp_hex(
                "10.0.0.5", "192.0.2.53", 53000, 53, dns_payload
            )))
        ])
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/simulations/pcap",
                data=json.dumps(
                    {
                        "scenario": {
                            "profiles": ["UDP", "DNS"],
                            "irule": "when DNS_REQUEST { log local0. dns-pcap }",
                        },
                        "pcap_base64": base64.b64encode(capture).decode("ascii"),
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["capture"]["record_count"], 1)
            self.assertEqual(payload["trace"][0]["protocol"], "dns")
            self.assertEqual(payload["trace"][0]["events"][0]["event"], "DNS_REQUEST")
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_cli_replays_classic_pcap_file(self) -> None:
        capture = _pcap_bytes([
            (5, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
            )))
        ])
        with tempfile.NamedTemporaryFile(suffix=".pcap") as capture_file:
            capture_file.write(capture)
            capture_file.flush()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER_PATH),
                    "--scenario",
                    "-",
                    "--pcap",
                    capture_file.name,
                    "--tcl-lsp-root",
                    self.tcl_lsp_root,
                ],
                input=json.dumps(
                    {
                        "profiles": ["TCP"],
                        "irule": "when CLIENT_ACCEPTED { log local0. pcap-cli }",
                    }
                ),
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["capture"]["ipv4_packet_count"], 1)
        self.assertEqual(payload["trace"][0]["timestamp"], 5.0)

    def test_input_contract_rejects_wrong_profile_and_unknown_fields(self) -> None:
        base = {"irule": "when HTTP_REQUEST { pool api_pool }"}
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario({**base, "tmos_version": "16.1"}, tcl_lsp_root=self.tcl_lsp_root)
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario({**base, "unknown": True}, tcl_lsp_root=self.tcl_lsp_root)
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario([], tcl_lsp_root=self.tcl_lsp_root)
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {**base, "request": {"lb_failure": "not-a-cause"}},
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_session_manager_bounds_and_expires_sessions(self) -> None:
        config = {"irule": "when HTTP_REQUEST { pool api_pool }"}
        manager = self.adapter.SessionManager(
            Path(self.tcl_lsp_root), max_sessions=1, idle_timeout=0.01
        )
        try:
            session_id = manager.create(config)
            with self.assertRaises(self.adapter.EmulatorResourceError):
                manager.create(config)
            time.sleep(0.03)
            with self.assertRaises(self.adapter.EmulatorNotFoundError):
                manager.metadata(session_id)
        finally:
            manager.close_all()

    def test_http_api_rejects_file_rules(self) -> None:
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            body = json.dumps({"irule_file": "/etc/passwd"}).encode("utf-8")
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/simulations",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request)
            payload = json.loads(raised.exception.read())
            self.assertEqual(raised.exception.code, 400)
            self.assertIn("inline irule only", payload["error"])
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_mcp_stdio_handshake_tools_and_protocol_errors(self) -> None:
        messages = "\n".join(
            [
                "not-json",
                '{"jsonrpc":"2.0","id":NaN,"method":"ping"}',
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1"},
                        },
                    }
                ),
                json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "irule_capabilities",
                            "arguments": {"offset": 1498, "limit": 2},
                        },
                    }
                ),
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {"name": "missing_tool", "arguments": {}},
                    }
                ),
            ]
        ) + "\n"
        output = io.StringIO()
        self.adapter.serve_mcp(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            input_stream=io.StringIO(messages),
            output_stream=output,
        )

        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(responses), 6)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["error"]["code"], -32700)
        self.assertEqual(responses[2]["id"], 1)
        self.assertEqual(responses[2]["result"]["protocolVersion"], "2025-06-18")
        tool_names = {tool["name"] for tool in responses[3]["result"]["tools"]}
        self.assertIn("irule_simulate", tool_names)
        self.assertIn("irule_conformance", tool_names)
        self.assertIn("irule_pcap_replay", tool_names)
        self.assertIn("irule_session_trace", tool_names)
        capability_payload = responses[4]["result"]["structuredContent"]
        self.assertEqual(capability_payload["chunk"]["offset"], 1498)
        self.assertLessEqual(capability_payload["chunk"]["count"], 2)
        self.assertEqual(responses[5]["error"]["code"], -32602)

    def test_mcp_tools_use_the_same_session_contract(self) -> None:
        root = self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        server = self.adapter.McpProtocolServer(root)
        try:
            initialized = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            )
            self.assertEqual(initialized["result"]["capabilities"], {"tools": {}})
            server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})

            pcap = _pcap_bytes([
                (4, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
                )))
            ])
            replayed = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_pcap_replay",
                        "arguments": {
                            "scenario": {
                                "profiles": ["TCP"],
                                "irule": "when CLIENT_ACCEPTED { log local0. pcap-mcp }",
                            },
                            "pcap_base64": base64.b64encode(pcap).decode("ascii"),
                        },
                    },
                }
            )
            self.assertEqual(
                replayed["result"]["structuredContent"]["capture"]["ipv4_packet_count"], 1
            )

            created = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_session_create",
                        "arguments": {
                            "scenario": {
                                "profiles": ["UDP", "DNS"],
                                "irule": "when DNS_REQUEST { log local0. dns-request }",
                            }
                        },
                    },
                }
            )
            created_payload = created["result"]["structuredContent"]
            session_id = created_payload["session_id"]
            fired = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_session_event",
                        "arguments": {
                            "session_id": session_id,
                            "event": "DNS_REQUEST",
                            "state": {"dns": {"qname": "example.com"}},
                        },
                    },
                }
            )
            self.assertTrue(fired["result"]["structuredContent"]["result"]["fired"])
            traced = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_session_trace",
                        "arguments": {
                            "session_id": session_id,
                            "packets": [
                                {
                                    "protocol": "dns",
                                    "direction": "client_to_server",
                                    "qname": "trace.example.com",
                                }
                            ],
                        },
                    },
                }
            )
            self.assertTrue(
                traced["result"]["structuredContent"]["result"]["trace"][0]["events"][0]["fired"]
            )
            closed = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_session_close",
                        "arguments": {"session_id": session_id},
                    },
                }
            )
            self.assertTrue(closed["result"]["structuredContent"]["closed"])
        finally:
            server.close()

    def test_persistent_http_session_preserves_connection_state(self) -> None:
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root), manager)
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        def request_json(path: str, method: str = "GET", payload: object | None = None):
            data = None if payload is None else json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}{path}",
                data=data,
                headers={"Content-Type": "application/json"} if data is not None else {},
                method=method,
            )
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())

        config = {
            "irule": (
                'when HTTP_REQUEST { if {[HTTP::payload] eq "ping"} '
                '{ pool api_pool } else { HTTP::respond 403 content "denied" } } '
                'when HTTP_RESPONSE { HTTP::header replace X-Emulator yes }'
            ),
            "pools": {"api_pool": ["10.0.0.1:80"]},
        }
        session_id = ""
        try:
            status, conformance = request_json("/v1/conformance")
            self.assertEqual(status, 200)
            self.assertGreaterEqual(conformance["commands"]["catalog_count"], 1400)
            self.assertGreater(conformance["events"]["packet_adapter_count"], 0)

            status, created = request_json("/v1/sessions", "POST", config)
            session_id = created["session_id"]
            self.assertEqual(status, 201)
            self.assertEqual(created["request_count"], 0)

            status, first = request_json(
                f"/v1/sessions/{session_id}/requests",
                "POST",
                {
                    "body": "ping",
                    "response_body": "pong",
                    "response_headers": {"Content-Type": "text/plain"},
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(first["request_number"], 1)
            self.assertEqual(first["result"]["pool"], "api_pool")

            status, second = request_json(
                f"/v1/sessions/{session_id}/requests", "POST", {"body": "nope"}
            )
            self.assertEqual(status, 200)
            self.assertEqual(second["request_number"], 2)
            self.assertEqual(second["result"]["connection_state"], "new")
            self.assertEqual(second["result"]["response"]["status"], 403)

            status, metadata = request_json(f"/v1/sessions/{session_id}")
            self.assertEqual(status, 200)
            self.assertEqual(metadata["request_count"], 2)
            self.assertTrue(metadata["connection_open"])

            status, closed = request_json(f"/v1/sessions/{session_id}", "DELETE")
            self.assertEqual(status, 200)
            self.assertTrue(closed["closed"])
            with self.assertRaises(urllib.error.HTTPError) as raised:
                request_json(f"/v1/sessions/{session_id}")
            self.assertEqual(raised.exception.code, 404)

            status, dns_session = request_json(
                "/v1/sessions",
                "POST",
                {
                    "profiles": ["UDP", "DNS"],
                    "irule": "when DNS_REQUEST { log local0. dns-request }",
                },
            )
            dns_session_id = dns_session["session_id"]
            self.assertEqual(status, 201)
            status, event = request_json(
                f"/v1/sessions/{dns_session_id}/events",
                "POST",
                {"event": "DNS_REQUEST", "state": {"dns": {"qname": "example.com"}}},
            )
            self.assertEqual(status, 200)
            self.assertTrue(event["result"]["fired"])
            self.assertEqual(event["result"]["state"]["dns"]["qname"], "example.com")

            status, packet_trace = request_json(
                f"/v1/sessions/{dns_session_id}/packets",
                "POST",
                {
                    "packets": [
                        {
                            "protocol": "dns",
                            "direction": "client_to_server",
                            "qname": "packet.example.com",
                            "qtype": "A",
                        }
                    ]
                },
            )
            self.assertEqual(status, 200)
            self.assertTrue(packet_trace["result"]["trace"][0]["events"][0]["fired"])
            request_json(f"/v1/sessions/{dns_session_id}", "DELETE")

            status, tls_session = request_json(
                "/v1/sessions",
                "POST",
                {
                    "profiles": ["TCP", "CLIENTSSL"],
                    "irule": "when CLIENTSSL_CLIENTHELLO { log local0. tls-clienthello }",
                },
            )
            tls_session_id = tls_session["session_id"]
            self.assertEqual(status, 201)
            status, event = request_json(
                f"/v1/sessions/{tls_session_id}/events",
                "POST",
                {
                    "event": "CLIENTSSL_CLIENTHELLO",
                    "state": {"tls_client": {"sni": "secure.example.com"}},
                },
            )
            self.assertEqual(status, 200)
            self.assertTrue(event["result"]["fired"])
            self.assertEqual(
                event["result"]["state"]["tls_client"]["sni"], "secure.example.com"
            )
            request_json(f"/v1/sessions/{tls_session_id}", "DELETE")
        finally:
            manager.close_all()
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
