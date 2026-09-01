#!/usr/bin/env python3
"""Serve a bounded deterministic UDP echo fixture for the Compose workbench."""

from __future__ import annotations

import argparse
import socketserver


class _UDPFixtureHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # noqa: D401 - socketserver API
        payload, socket_object = self.request
        maximum = self.server.maximum_bytes  # type: ignore[attr-defined]
        if not isinstance(payload, bytes) or len(payload) > maximum:
            return
        prefix = self.server.prefix  # type: ignore[attr-defined]
        response = prefix + payload
        if len(response) <= maximum:
            socket_object.sendto(response, self.client_address)


class _UDPFixtureServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--prefix", default="origin:")
    parser.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    args = parser.parse_args()
    if not 0 < args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.max_bytes <= 2 * 1024 * 1024:
        parser.error("--max-bytes must be between 1 and 2097152")
    if "\x00" in args.prefix:
        parser.error("--prefix cannot contain NUL")
    try:
        prefix = args.prefix.encode("utf-8")
    except UnicodeEncodeError:
        parser.error("--prefix must be valid UTF-8")
    if len(prefix) > args.max_bytes:
        parser.error("--prefix exceeds --max-bytes")

    server = _UDPFixtureServer((args.host, args.port), _UDPFixtureHandler)
    server.maximum_bytes = args.max_bytes
    server.prefix = prefix
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
