"""Regression tests for the optional tmos-17.5 emulator adapter."""

from __future__ import annotations

import importlib.util
import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "tools" / "irule-emulator.py"
FIXTURE_PATH = ROOT / "test" / "fixtures" / "emulator_http.json"


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
