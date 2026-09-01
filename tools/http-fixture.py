#!/usr/bin/env python3
"""Serve a bounded, deterministic HTTP backend for Compose smoke tests."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY_BYTES = 2 * 1024 * 1024


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "testcl-http-fixture/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _respond(self) -> None:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            self.send_error(400, "invalid content length")
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400, "incomplete request body")
            return

        result = {
            "method": self.command,
            "path": self.path,
            "x_from_rule": self.headers.get("X-From-Rule", ""),
            "body": body.decode("utf-8", errors="replace"),
        }
        payload = (json.dumps(result, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend", "testcl-http-fixture")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18090)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    return args


def main() -> int:
    args = _parse_args()
    server = ThreadingHTTPServer((args.host, args.port), FixtureHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
