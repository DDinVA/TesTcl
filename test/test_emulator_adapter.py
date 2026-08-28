"""Regression tests for the optional tmos-17.5 emulator adapter."""

from __future__ import annotations

import importlib.util
import io
import ipaddress
import json
import os
import struct
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "tools" / "irule-emulator.py"
FIXTURE_PATH = ROOT / "test" / "fixtures" / "emulator_http.json"


def _raw_ipv4_tcp_hex(
    source: str, destination: str, source_port: int, destination_port: int,
    flags: int, payload: bytes = b"",
) -> str:
    tcp = struct.pack(
        "!HHLLBBHHH", source_port, destination_port, 0, 0, 5 << 4, flags, 65535, 0, 0
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
        self.assertEqual(usage["HTTP::payload"]["runtime_status"], "handwritten-mock")
        self.assertEqual(result["fidelity"]["warnings"], [])

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
        self.assertGreater(
            report["events"]["catalog_count"], report["events"]["packet_adapter_count"]
        )

    def test_fidelity_analysis_warns_for_stub_and_profile_gated_usage(self) -> None:
        root = self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        report = self.adapter._analyze_rule_capabilities(
            root,
            "when HTTP_REQUEST { HSL::open -proto TCP }\n"
            "when CLIENTSSL_HANDSHAKE { log local0. tls }",
            ["TCP", "HTTP"],
        )
        usage = {entry["name"]: entry for entry in report["commands"]}
        self.assertEqual(usage["HSL::open"]["runtime_status"], "generated-stub")
        warning_codes = {warning["code"] for warning in report["warnings"]}
        self.assertIn("runtime-fidelity", warning_codes)
        self.assertIn("profile-gated-event", warning_codes)

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

    def test_raw_ipv4_tcp_packets_decode_into_http_transaction(self) -> None:
        request_payload = b"GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
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
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                        _tls_client_hello_payload("api.example.com"),
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "10.0.0.5", "192.0.2.10", 51000, 443, 0x18, request_payload
                    ),
                },
                {
                    "protocol": "wire",
                    "direction": "server_to_client",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "192.0.2.10", "10.0.0.5", 443, 51000, 0x18, response_payload
                    ),
                },
            ],
        }
        result = self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        self.assertEqual(result["packets_processed"], 4)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["request"]["uri"], "/health")
        self.assertEqual(result["results"][0]["response"]["status"], 200)
        self.assertEqual(result["results"][0]["response"]["body"], "ok")
        self.assertEqual(result["trace"][1]["protocol"], "tls")
        self.assertEqual(result["trace"][2]["protocol"], "http")
        self.assertEqual(result["trace"][3]["protocol"], "http")
        self.assertIn(
            "CLIENTSSL_CLIENTHELLO",
            [event["event"] for event in result["trace"][1]["events"]],
        )

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

    def test_input_contract_rejects_wrong_profile_and_unknown_fields(self) -> None:
        base = {"irule": "when HTTP_REQUEST { pool api_pool }"}
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario({**base, "tmos_version": "16.1"}, tcl_lsp_root=self.tcl_lsp_root)
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario({**base, "unknown": True}, tcl_lsp_root=self.tcl_lsp_root)
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario([], tcl_lsp_root=self.tcl_lsp_root)

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
