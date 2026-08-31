#!/usr/bin/env python3
"""Send bounded protocol stimuli for the TMOS 17.5 observation collector.

This executable consumes one JSON object on stdin, matching the contract sent
by ``tools/tmos17-collector.py --trigger-command``.  It is deliberately
standard-library-only and does not attempt to inspect BIG-IP state.  The
collector remains responsible for the temporary iRule and observation log;
this driver only generates traffic toward the requested endpoint.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


MAX_INPUT_BYTES = 512 * 1024
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
MAX_HTTP_HEADERS = 128
MAX_HTTP_LINE_BYTES = 8 * 1024
MAX_FTP_LINE_BYTES = 64 * 1024
MAX_WEBSOCKET_FRAME_BYTES = MAX_PAYLOAD_BYTES
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 60.0
DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "HTTPS": 65,
}
PCP_OPCODES = {"announce": 0, "map": 1, "peer": 2}
PCP_PROTOCOLS = {"tcp": 6, "udp": 17}
RADIUS_CODES = {
    "access-request": 1,
    "access-accept": 2,
    "access-reject": 3,
    "accounting-request": 4,
    "accounting-response": 5,
}
RADIUS_ATTRIBUTE_CODES = {
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


class DriverError(RuntimeError):
    """Raised for invalid driver input or a failed network stimulus."""


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def read_request(stream: Any = sys.stdin.buffer) -> dict[str, Any]:
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise DriverError("driver input exceeds the 512 KiB limit")
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DriverError(f"driver input is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DriverError("driver input must be a JSON object")
    return value


def _text(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise DriverError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise DriverError(f"{field} is too long or contains NUL")
    try:
        text_bytes = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DriverError(f"{field} contains an invalid Unicode character") from exc
    if len(text_bytes) > MAX_TEXT_BYTES:
        raise DriverError(f"{field} is too long or contains NUL")
    return value


def _single_line(value: str, field: str) -> str:
    if "\r" in value or "\n" in value:
        raise DriverError(f"{field} cannot contain line breaks")
    return value


def _timeout(request: dict[str, Any]) -> float:
    value = request.get("timeout", DEFAULT_TIMEOUT)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DriverError("request timeout must be a number")
    if not math.isfinite(float(value)) or not 0 < float(value) <= MAX_TIMEOUT:
        raise DriverError(f"request timeout must be greater than 0 and at most {MAX_TIMEOUT:g}")
    return float(value)


def _payload_bytes(request: dict[str, Any]) -> bytes:
    encoded = request.get("payload_base64")
    if encoded is not None:
        if not isinstance(encoded, str):
            raise DriverError("payload_base64 must be a string")
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise DriverError("payload_base64 is not valid base64") from exc
    else:
        text = _text(request.get("payload"), "payload", required=True)
        assert text is not None
        payload = text.encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise DriverError("payload exceeds the 2 MiB limit")
    return payload


def endpoint_from_request(
    request: dict[str, Any], fallback: str | None, *, default_scheme: str, default_port: int
) -> Endpoint:
    destination = request.get("destination", fallback)
    if not isinstance(destination, str) or not destination:
        raise DriverError("request.destination or a udp:// / tcp:// traffic_url is required")
    parsed = urlparse(destination)
    scheme = parsed.scheme.lower() or default_scheme
    if scheme not in {"udp", "tcp"}:
        raise DriverError("protocol driver destinations must use udp:// or tcp://")
    if not parsed.hostname:
        raise DriverError("protocol driver destination must include a host")
    try:
        port = parsed.port or default_port
    except ValueError as exc:
        raise DriverError("protocol driver destination has an invalid port") from exc
    if not 1 <= port <= 65535:
        raise DriverError("protocol driver destination port must be between 1 and 65535")
    return Endpoint(scheme=scheme, host=parsed.hostname, port=port)


def _dns_name(value: str) -> bytes:
    if value.endswith("."):
        value = value[:-1]
    try:
        qname_bytes = value.encode("idna")
    except UnicodeError as exc:
        raise DriverError("DNS qname contains an invalid label") from exc
    if not value or len(qname_bytes) > 253:
        raise DriverError("DNS qname must be 1 to 253 bytes")
    labels = value.split(".")
    encoded = bytearray()
    for label in labels:
        try:
            label_bytes = label.encode("idna")
        except UnicodeError as exc:
            raise DriverError("DNS qname contains an invalid label") from exc
        if not 1 <= len(label_bytes) <= 63:
            raise DriverError("DNS labels must be 1 to 63 bytes")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    return bytes(encoded)


def build_dns_query(request: dict[str, Any]) -> bytes:
    qname = _text(request.get("qname"), "qname", required=True)
    assert qname is not None
    qtype_value = request.get("qtype", "A")
    if isinstance(qtype_value, str):
        qtype = DNS_TYPES.get(qtype_value.upper())
    elif isinstance(qtype_value, int) and not isinstance(qtype_value, bool):
        qtype = qtype_value
    else:
        qtype = None
    if qtype is None or not 1 <= qtype <= 65535:
        raise DriverError("qtype must be a known DNS type name or a value from 1 to 65535")
    qclass = request.get("qclass", 1)
    if isinstance(qclass, bool) or not isinstance(qclass, int) or not 1 <= qclass <= 65535:
        raise DriverError("qclass must be between 1 and 65535")
    transaction_id = request.get("transaction_id", 0x1705)
    if (
        isinstance(transaction_id, bool)
        or not isinstance(transaction_id, int)
        or not 0 <= transaction_id <= 65535
    ):
        raise DriverError("transaction_id must be between 0 and 65535")
    recursion_desired = request.get("recursion_desired", True)
    if not isinstance(recursion_desired, bool):
        raise DriverError("recursion_desired must be a boolean")
    flags = 0x0100 if recursion_desired else 0
    return (
        struct.pack(">HHHHHH", transaction_id, flags, 1, 0, 0, 0)
        + _dns_name(qname)
        + struct.pack(">HH", qtype, qclass)
    )


def _mqtt_remaining_length(length: int) -> bytes:
    if not 0 <= length <= 268_435_455:
        raise DriverError("MQTT remaining length is out of range")
    encoded = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        encoded.append(digit)
        if not length:
            return bytes(encoded)


def _mqtt_utf8(value: str, field: str) -> bytes:
    encoded = _text(value, field, required=True).encode("utf-8")
    if len(encoded) > 65_535:
        raise DriverError(f"{field} exceeds the MQTT two-byte string limit")
    return struct.pack(">H", len(encoded)) + encoded


def build_mqtt_connect_publish(request: dict[str, Any]) -> bytes:
    client_id = _text(request.get("client_id", "testcl-1705"), "client_id", required=True)
    topic = _text(request.get("topic"), "topic", required=True)
    assert client_id is not None and topic is not None
    if "payload_base64" in request:
        payload = _payload_bytes(request)
    else:
        payload_value = request.get("payload", "testcl")
        if not isinstance(payload_value, str):
            raise DriverError("MQTT payload must be a string when payload_base64 is not used")
        payload = payload_value.encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise DriverError("MQTT payload exceeds the 2 MiB limit")
    keepalive = request.get("keepalive", 30)
    if isinstance(keepalive, bool) or not isinstance(keepalive, int) or not 0 <= keepalive <= 65535:
        raise DriverError("MQTT keepalive must be between 0 and 65535")
    connect_body = (
        b"\x00\x04MQTT"
        + b"\x04"
        + b"\x02"
        + struct.pack(">H", keepalive)
        + _mqtt_utf8(client_id, "client_id")
    )
    connect = b"\x10" + _mqtt_remaining_length(len(connect_body)) + connect_body
    publish_body = _mqtt_utf8(topic, "topic") + payload
    publish = b"0" + _mqtt_remaining_length(len(publish_body)) + publish_body
    return connect + publish


def _http_header_value(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DriverError(f"HTTP {field} must be a non-empty string")
    if "\r" in value or "\n" in value or "\x00" in value:
        raise DriverError(f"HTTP {field} cannot contain line breaks or NUL")
    try:
        encoded = value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise DriverError(f"HTTP {field} must contain Latin-1 header bytes") from exc
    if len(encoded) > MAX_HTTP_LINE_BYTES:
        raise DriverError(f"HTTP {field} is too long")
    return value


def _http_ascii_value(value: Any, field: str) -> str:
    value = _http_header_value(value, field)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DriverError(f"HTTP {field} must contain ASCII characters") from exc
    return value


def build_http_request(request: dict[str, Any]) -> bytes:
    """Build one bounded HTTP/1.1 request from a structured plan fixture."""
    method = request.get("method", "GET")
    if not isinstance(method, str) or not method or not method.isascii() or not method.isalpha():
        raise DriverError("HTTP method must contain ASCII letters")
    uri = request.get("uri", "/")
    if not isinstance(uri, str) or not uri.startswith("/"):
        raise DriverError("HTTP uri must be an absolute path")
    _http_ascii_value(uri, "uri")
    host = _http_header_value(request.get("host", "example.test"), "host")
    headers = request.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > MAX_HTTP_HEADERS:
        raise DriverError(
            f"HTTP headers must be an object with at most {MAX_HTTP_HEADERS} items"
        )
    normalised_headers: list[tuple[str, str]] = []
    header_names: set[str] = set()
    for key, value in headers.items():
        if not isinstance(key, str) or not key or not key.isascii() or any(
            character not in "!#$%&'*+-.^_`|~" and not character.isalnum()
            for character in key
        ):
            raise DriverError(
                "HTTP header names must be non-empty and cannot contain separators"
            )
        _http_header_value(key, "header name")
        normalised_value = _http_header_value(value, "header value", allow_empty=True)
        lowered = key.lower()
        if lowered in header_names:
            raise DriverError(f"HTTP header {key!r} is repeated")
        header_names.add(lowered)
        normalised_headers.append((key, normalised_value))
    if "host" not in header_names:
        normalised_headers.insert(0, ("Host", host))
    if len(normalised_headers) > MAX_HTTP_HEADERS:
        raise DriverError(
            f"HTTP headers must contain at most {MAX_HTTP_HEADERS} items"
        )

    body_sources = [
        field for field in ("body", "payload", "payload_base64") if field in request
    ]
    if len(body_sources) > 1:
        raise DriverError(
            "HTTP request must use exactly one of body, payload, or payload_base64"
        )
    if body_sources and body_sources[0] in {"payload", "payload_base64"}:
        body = _payload_bytes(request)
    else:
        body_value = request.get("body", "")
        if not isinstance(body_value, str):
            raise DriverError("HTTP body must be a string when payload_base64 is not used")
        try:
            body = body_value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DriverError("HTTP body must be valid UTF-8") from exc
        if len(body) > MAX_PAYLOAD_BYTES:
            raise DriverError("HTTP body exceeds the 2 MiB limit")
    if body and "content-length" not in header_names and "transfer-encoding" not in header_names:
        normalised_headers.append(("Content-Length", str(len(body))))
    if "connection" not in header_names:
        normalised_headers.append(("Connection", "close"))

    lines = [f"{method} {uri} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in normalised_headers)
    encoded = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise DriverError("HTTP request exceeds the 2 MiB limit")
    return encoded


def _rtsp_header_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii() or any(
        character not in "!#$%&'*+-.^_`|~" and not character.isalnum()
        for character in value
    ):
        raise DriverError(f"RTSP {field} must be a valid header name")
    return value


def _rtsp_header_value(value: Any, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise DriverError(f"RTSP {field} must be a string")
    if "\r" in value or "\n" in value or "\x00" in value:
        raise DriverError(f"RTSP {field} cannot contain line breaks or NUL")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DriverError(f"RTSP {field} must be valid UTF-8") from exc
    if len(encoded) > MAX_HTTP_LINE_BYTES:
        raise DriverError(f"RTSP {field} is too long")
    return value


def _rtsp_start_line_value(value: Any, field: str) -> str:
    value = _rtsp_header_value(value, field, allow_empty=False)
    if not value.isascii() or any(character.isspace() for character in value):
        raise DriverError(f"RTSP {field} must be an ASCII token")
    return value


def build_rtsp_message(request: dict[str, Any], event: str) -> bytes:
    """Build one bounded RTSP/1.0 request for the collector driver."""
    if event not in {"RTSP_REQUEST", "RTSP_REQUEST_DATA"}:
        raise DriverError(
            "RTSP protocol driver supports RTSP_REQUEST and RTSP_REQUEST_DATA"
        )
    raw = request.get("message")
    structured_fields = {"method", "uri", "version", "headers", "body"}
    if raw is not None:
        if set(request) & structured_fields or "payload" in request or "payload_base64" in request:
            raise DriverError(
                "RTSP message cannot be combined with structured request fields"
            )
        message = _text(raw, "message", required=True)
        assert message is not None
        encoded = message.replace("\r\n", "\n").replace("\r", "\n").replace(
            "\n", "\r\n"
        ).encode("utf-8")
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise DriverError("RTSP message exceeds the 2 MiB limit")
        return encoded

    method = _rtsp_start_line_value(request.get("method", "DESCRIBE"), "method")
    uri = _rtsp_header_value(
        request.get("uri", "rtsp://example.test/live"), "uri", allow_empty=False
    )
    if not uri.isascii() or any(character.isspace() for character in uri):
        raise DriverError("RTSP uri must be an ASCII value without whitespace")
    version = _rtsp_start_line_value(request.get("version", "RTSP/1.0"), "version")
    if not version.startswith("RTSP/"):
        raise DriverError("RTSP version must start with RTSP/")

    headers = request.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > MAX_HTTP_HEADERS:
        raise DriverError(
            f"RTSP headers must be an object with at most {MAX_HTTP_HEADERS} items"
        )
    normalised_headers: list[tuple[str, str]] = []
    header_names: set[str] = set()
    for name, value in headers.items():
        normalised_name = _rtsp_header_name(name, "header name")
        normalised_value = _rtsp_header_value(value, "header value")
        lowered = normalised_name.lower()
        if lowered in header_names:
            raise DriverError(f"RTSP header {normalised_name!r} is repeated")
        header_names.add(lowered)
        normalised_headers.append((normalised_name, normalised_value))
    if "cseq" not in header_names:
        normalised_headers.append(("CSeq", "1"))

    body_sources = [
        field for field in ("body", "payload", "payload_base64") if field in request
    ]
    if len(body_sources) > 1:
        raise DriverError(
            "RTSP request must use exactly one of body, payload, or payload_base64"
        )
    if body_sources and body_sources[0] in {"payload", "payload_base64"}:
        body = _payload_bytes(request)
    else:
        body_value = request.get("body", "")
        if not isinstance(body_value, str):
            raise DriverError("RTSP body must be a string when payload_base64 is not used")
        try:
            body = body_value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DriverError("RTSP body must be valid UTF-8") from exc
        if len(body) > MAX_PAYLOAD_BYTES:
            raise DriverError("RTSP body exceeds the 2 MiB limit")
    if body and "content-length" not in header_names:
        normalised_headers.append(("Content-Length", str(len(body))))
    if len(normalised_headers) > MAX_HTTP_HEADERS:
        raise DriverError(f"RTSP headers must contain at most {MAX_HTTP_HEADERS} items")

    start_line = f"{method} {uri} {version}"
    try:
        encoded_headers = (
            "\r\n".join(
                [start_line] + [f"{name}: {value}" for name, value in normalised_headers]
            )
            + "\r\n\r\n"
        ).encode("ascii")
    except UnicodeEncodeError as exc:
        raise DriverError("RTSP request line and headers must contain ASCII bytes") from exc
    encoded = encoded_headers + body
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise DriverError("RTSP request exceeds the 2 MiB limit")
    return encoded


def _ftp_encode(value: str, field: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DriverError(f"FTP {field} must be valid UTF-8") from exc


def _ftp_line_encode(value: str, field: str) -> bytes:
    encoded = _ftp_encode(value, field)
    if len(encoded) > MAX_FTP_LINE_BYTES:
        raise DriverError(
            f"FTP {field} exceeds the {MAX_FTP_LINE_BYTES} byte line limit"
        )
    return encoded


def build_ftp_message(request: dict[str, Any], event: str) -> bytes:
    """Build one bounded FTP control-channel message for CLIENT/SERVER_DATA."""
    if event not in {"CLIENT_DATA", "SERVER_DATA"}:
        raise DriverError(
            "FTP protocol driver supports CLIENT_DATA and SERVER_DATA"
        )
    ftp = request.get("ftp", {})
    if not isinstance(ftp, dict):
        raise DriverError("FTP request ftp must be an object")
    allowed = {
        "type",
        "command",
        "response_code",
        "text",
        "lines",
        "message",
    }
    unknown = sorted(set(ftp) - allowed)
    if unknown:
        raise DriverError("FTP request unsupported field(s): " + ", ".join(unknown))

    message = ftp.get("message")
    if message is not None:
        if set(ftp) - {"message"}:
            raise DriverError("FTP message cannot be combined with structured fields")
        raw = _text(message, "FTP message", required=True)
        assert raw is not None
        encoded = raw.replace("\r\n", "\n").replace("\r", "\n").replace(
            "\n", "\r\n"
        ).encode("utf-8")
        if not encoded.endswith(b"\r\n"):
            encoded += b"\r\n"
        if any(
            len(line) > MAX_FTP_LINE_BYTES
            for line in encoded.split(b"\r\n")[:-1]
        ):
            raise DriverError(
                f"FTP message contains a line exceeding the {MAX_FTP_LINE_BYTES} byte limit"
            )
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise DriverError("FTP message exceeds the 2 MiB limit")
        return encoded

    expected_type = "command" if event == "CLIENT_DATA" else "response"
    packet_type = ftp.get("type")
    if packet_type is None:
        if "command" in ftp:
            packet_type = "command"
        elif any(field in ftp for field in ("response_code", "text", "lines")):
            packet_type = "response"
        else:
            packet_type = expected_type
    if not isinstance(packet_type, str) or packet_type not in {"command", "response"}:
        raise DriverError("FTP type must be command or response")
    if packet_type != expected_type:
        raise DriverError(f"FTP {event} requires a {expected_type} message")
    if packet_type == "command":
        conflicting = sorted(set(ftp) & {"response_code", "text", "lines"})
        if conflicting:
            raise DriverError(
                "FTP command cannot include response field(s): " + ", ".join(conflicting)
            )
        command = _text(ftp.get("command"), "FTP command", required=True)
        assert command is not None
        command = _single_line(command, "FTP command")
        command_parts = command.split(None, 1)
        if not command_parts:
            raise DriverError("FTP command must not be blank")
        token = command_parts[0]
        if not token.isascii() or not token[0].isalpha() or not token.replace("-", "").isalnum():
            raise DriverError("FTP command must begin with an ASCII command token")
        encoded = _ftp_line_encode(command + "\r\n", "command")
    else:
        if "command" in ftp:
            raise DriverError("FTP response cannot include command")
        code = ftp.get("response_code")
        if isinstance(code, bool) or not isinstance(code, int) or not 100 <= code <= 599:
            raise DriverError("FTP response_code must be an integer from 100 to 599")
        lines = ftp.get("lines")
        if lines is not None:
            if not isinstance(lines, list) or not lines or len(lines) > 1024:
                raise DriverError("FTP lines must contain 1 to 1024 strings")
            if not all(isinstance(line, str) for line in lines):
                raise DriverError("FTP lines must contain only strings")
            text_lines = [_single_line(line, "FTP response line") for line in lines]
            if len(text_lines) == 1:
                encoded = _ftp_line_encode(
                    f"{code:03d} {text_lines[0]}\r\n", "response line"
                )
            else:
                encoded_lines = [f"{code:03d}-{text_lines[0]}"]
                encoded_lines.extend(text_lines[1:-1])
                encoded_lines.append(f"{code:03d} {text_lines[-1]}")
                for line in encoded_lines:
                    _ftp_line_encode(line + "\r\n", "response line")
                encoded = _ftp_encode(
                    "\r\n".join(encoded_lines) + "\r\n", "response line"
                )
        else:
            text_value = ftp.get("text", "")
            if not isinstance(text_value, str):
                raise DriverError("FTP response text must be a string")
            text_value = _single_line(text_value, "FTP response text")
            encoded = _ftp_line_encode(
                f"{code:03d} {text_value}\r\n", "response text"
            )
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise DriverError("FTP message exceeds the 2 MiB limit")
    return encoded


WEBSOCKET_OPCODES = {
    "continuation": 0x0,
    "text": 0x1,
    "binary": 0x2,
    "close": 0x8,
    "ping": 0x9,
    "pong": 0xA,
}
DEFAULT_WEBSOCKET_KEY = "dGhlIHNhbXBsZSBub25jZQ=="


def _websocket_key(value: Any) -> str:
    value = _http_ascii_value(value, "sec_websocket_key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DriverError("HTTP sec_websocket_key must be valid base64") from exc
    if len(decoded) != 16:
        raise DriverError("HTTP sec_websocket_key must decode to 16 bytes")
    return value


def _websocket_frame(request: dict[str, Any]) -> bytes:
    frame_type = request.get("frame_type", "text")
    if not isinstance(frame_type, str) or frame_type.lower() not in WEBSOCKET_OPCODES:
        raise DriverError(
            "WebSocket frame_type must be continuation, text, binary, close, ping, or pong"
        )
    frame_type = frame_type.lower()
    fin = request.get("fin", True)
    if not isinstance(fin, bool):
        raise DriverError("WebSocket fin must be a boolean")
    if "payload_base64" in request:
        if "payload" in request:
            raise DriverError("WebSocket frame must use payload or payload_base64, not both")
        payload = _payload_bytes(request)
    else:
        payload_value = request.get("payload", "")
        if not isinstance(payload_value, str):
            raise DriverError("WebSocket payload must be a string when payload_base64 is not used")
        try:
            payload = payload_value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DriverError("WebSocket payload must be valid UTF-8") from exc
    if len(payload) > MAX_WEBSOCKET_FRAME_BYTES:
        raise DriverError("WebSocket frame exceeds the 2 MiB limit")
    if frame_type in {"close", "ping", "pong"}:
        if not fin:
            raise DriverError("WebSocket control frames must set fin=true")
        if len(payload) > 125:
            raise DriverError("WebSocket control frames cannot exceed 125 bytes")
    mask_hex = request.get("mask_hex", "01020304")
    if not isinstance(mask_hex, str) or len(mask_hex) != 8:
        raise DriverError("WebSocket mask_hex must contain exactly 4 bytes")
    try:
        mask = bytes.fromhex(mask_hex)
    except ValueError as exc:
        raise DriverError("WebSocket mask_hex must be hexadecimal") from exc
    length = len(payload)
    if length < 126:
        length_bytes = bytes([0x80 | length])
    elif length <= 0xFFFF:
        length_bytes = bytes([0x80 | 126]) + struct.pack(">H", length)
    else:
        length_bytes = bytes([0x80 | 127]) + struct.pack(">Q", length)
    masked_payload = bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload)
    )
    return (
        bytes([(0x80 if fin else 0) | WEBSOCKET_OPCODES[frame_type]])
        + length_bytes
        + mask
        + masked_payload
    )


def build_websocket_request(request: dict[str, Any], event: str) -> bytes:
    """Build a WebSocket upgrade and optional masked client frame."""
    websocket = request.get("websocket", {})
    if not isinstance(websocket, dict):
        raise DriverError("WebSocket request websocket must be an object")
    allowed = {
        "method", "uri", "host", "headers", "sec_websocket_key", "frame_type",
        "fin", "mask_hex", "payload", "payload_base64",
    }
    unknown = sorted(set(websocket) - allowed)
    if unknown:
        raise DriverError("WebSocket request unsupported field(s): " + ", ".join(unknown))
    method = websocket.get("method", "GET")
    if not isinstance(method, str) or method != "GET":
        raise DriverError("WebSocket upgrade method must be GET")
    uri = _http_ascii_value(websocket.get("uri", "/socket"), "uri")
    if not uri.startswith("/"):
        raise DriverError("WebSocket uri must be an absolute path")
    host = _http_header_value(websocket.get("host", "example.test"), "host")
    key = _websocket_key(websocket.get("sec_websocket_key", DEFAULT_WEBSOCKET_KEY))
    headers = websocket.get("headers", {})
    if not isinstance(headers, dict) or len(headers) > MAX_HTTP_HEADERS:
        raise DriverError(
            f"WebSocket headers must be an object with at most {MAX_HTTP_HEADERS} items"
        )
    normalised_headers: list[tuple[str, str]] = []
    header_names: set[str] = set()
    for name, value in headers.items():
        if not isinstance(name, str) or not name or not name.isascii() or any(
            character not in "!#$%&'*+-.^_`|~" and not character.isalnum()
            for character in name
        ):
            raise DriverError("WebSocket header names must be valid HTTP names")
        normalised_value = _http_header_value(value, "header value", allow_empty=True)
        lowered = name.lower()
        if lowered in header_names:
            raise DriverError(f"WebSocket header {name!r} is repeated")
        header_names.add(lowered)
        normalised_headers.append((name, normalised_value))
    required_headers = [
        ("Host", host),
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Key", key),
        ("Sec-WebSocket-Version", "13"),
    ]
    for name, value in required_headers:
        lowered = name.lower()
        if lowered not in header_names:
            normalised_headers.append((name, value))
            header_names.add(lowered)
    if len(normalised_headers) > MAX_HTTP_HEADERS:
        raise DriverError(
            f"WebSocket headers must contain at most {MAX_HTTP_HEADERS} items"
        )
    handshake = (
        "\r\n".join(
            [f"{method} {uri} HTTP/1.1"]
            + [f"{name}: {value}" for name, value in normalised_headers]
        )
        + "\r\n\r\n"
    ).encode("latin-1")
    if event == "WS_REQUEST":
        return handshake
    if event in {"WS_CLIENT_FRAME", "WS_CLIENT_DATA"}:
        frame = _websocket_frame(websocket)
        if len(handshake) + len(frame) > MAX_PAYLOAD_BYTES:
            raise DriverError("WebSocket upgrade and frame exceed the 2 MiB limit")
        return handshake + frame
    raise DriverError(
        "WebSocket protocol driver supports WS_REQUEST, WS_CLIENT_FRAME, and WS_CLIENT_DATA"
    )


def build_sip_message(request: dict[str, Any], event: str) -> bytes:
    raw = request.get("message")
    if raw is not None:
        message = _text(raw, "message", required=True)
        assert message is not None
        if "\x00" in message:
            raise DriverError("SIP message contains NUL")
        return message.replace("\r\n", "\n").replace("\r", "\n").replace(
            "\n", "\r\n"
        ).encode("utf-8")

    method = _text(request.get("method", "OPTIONS"), "method", required=True)
    uri = _text(request.get("uri", "sip:test@example.invalid"), "uri", required=True)
    assert method is not None and uri is not None
    method = _single_line(method, "method")
    uri = _single_line(uri, "uri")
    if event.endswith("RESPONSE"):
        start_line = _text(request.get("status", "200 OK"), "status", required=True)
        assert start_line is not None
        start_line = _single_line(start_line, "status")
        start_line = f"SIP/2.0 {start_line}"
    else:
        start_line = f"{method} {uri} SIP/2.0"
    headers = request.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in headers.items()
    ):
        raise DriverError("SIP headers must be an object of string values")
    body = request.get("body", "")
    if not isinstance(body, str):
        raise DriverError("SIP body must be a string")
    lines = [start_line]
    for key, value in headers.items():
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise DriverError("SIP headers cannot contain line breaks")
        lines.append(f"{key}: {value}")
    if not any(key.lower() == "content-length" for key in headers):
        lines.append(f"Content-Length: {len(body.encode('utf-8'))}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


def _pcp_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise DriverError(f"PCP {field} must be an integer from 0 to {maximum}")
    if isinstance(value, str) and value.isdigit() and len(value) <= 32:
        value = int(value, 10)
    if not isinstance(value, int) or not 0 <= value <= maximum:
        raise DriverError(f"PCP {field} must be an integer from 0 to {maximum}")
    return value


def _pcp_address(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise DriverError(f"PCP {field} must be a valid IPv4 or IPv6 address")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DriverError(f"PCP {field} must be a valid IPv4 or IPv6 address") from exc
    if parsed.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + parsed.packed
    return parsed.packed


def _pcp_option(code: int, data: bytes = b"") -> bytes:
    padded_length = (len(data) + 3) & ~3
    return bytes([code, 0]) + struct.pack(">H", len(data)) + data + b"\x00" * (padded_length - len(data))


def build_pcp_request(request: dict[str, Any]) -> bytes:
    """Build one bounded PCPv2 request, suitable for UDP port 5351."""
    pcp = request.get("pcp", {})
    if not isinstance(pcp, dict):
        raise DriverError("PCP request pcp must be an object")
    allowed = {
        "version", "opcode", "lifetime", "protocol", "client_addr", "internal_port",
        "suggested_ext_port", "suggested_ext_addr", "prefer_failure", "third_party",
        "third_party_int_addr",
    }
    if any(not isinstance(key, str) for key in pcp):
        raise DriverError("PCP request field names must be strings")
    unknown = sorted(set(pcp) - allowed)
    if unknown:
        raise DriverError("PCP request unsupported field(s): " + ", ".join(unknown))
    version = _pcp_uint(pcp.get("version", 2), "version", 255)
    opcode_value = pcp.get("opcode", "map")
    if isinstance(opcode_value, str):
        opcode = PCP_OPCODES.get(opcode_value.lower())
        if opcode is None and opcode_value.isdigit():
            opcode = _pcp_uint(opcode_value, "opcode", 127)
    else:
        opcode = opcode_value if isinstance(opcode_value, int) and not isinstance(opcode_value, bool) else None
    if opcode is None or not 0 <= opcode <= 127:
        raise DriverError("PCP opcode must be announce, map, peer, or an integer from 0 to 127")
    body_fields = {
        "protocol", "internal_port", "suggested_ext_port", "suggested_ext_addr",
    }
    if opcode == 0 and body_fields & set(pcp):
        raise DriverError("PCP announce requests cannot contain mapping or peer fields")
    lifetime = _pcp_uint(pcp.get("lifetime", 3600), "lifetime", 0xFFFFFFFF)
    protocol_value = pcp.get("protocol", "tcp")
    if isinstance(protocol_value, str):
        protocol = PCP_PROTOCOLS.get(protocol_value.lower())
        if protocol is None and protocol_value.isdigit():
            protocol = _pcp_uint(protocol_value, "protocol", 255)
    else:
        protocol = _pcp_uint(protocol_value, "protocol", 255)
    if protocol is None:
        raise DriverError("PCP protocol must be tcp, udp, or an integer from 0 to 255")
    client_addr = _pcp_address(pcp.get("client_addr", "192.0.2.10"), "client_addr")
    message = bytearray(bytes([version, opcode, 0, 0]) + struct.pack(">I", lifetime) + client_addr)

    if opcode in {1, 2}:
        internal_port = _pcp_uint(pcp.get("internal_port", 22), "internal_port", 65535)
        suggested_port = _pcp_uint(pcp.get("suggested_ext_port", 0), "suggested_ext_port", 65535)
        suggested_addr = _pcp_address(pcp.get("suggested_ext_addr", "0.0.0.0"), "suggested_ext_addr")
        message.extend(b"\x00" * 12)
        message.extend(bytes([protocol, 0, 0, 0]))
        message.extend(struct.pack(">HH", internal_port, suggested_port))
        message.extend(suggested_addr)
        if opcode == 2:
            message.extend(b"\x00\x00\x00\x00" + _pcp_address("0.0.0.0", "remote_peer_addr"))

    third_party = pcp.get("third_party", False)
    if not isinstance(third_party, bool):
        raise DriverError("PCP third_party must be a boolean")
    if third_party:
        message.extend(_pcp_option(1, _pcp_address(pcp.get("third_party_int_addr", "0.0.0.0"), "third_party_int_addr")))
    elif "third_party_int_addr" in pcp:
        raise DriverError("PCP third_party_int_addr requires third_party=true")
    prefer_failure = pcp.get("prefer_failure", False)
    if not isinstance(prefer_failure, bool):
        raise DriverError("PCP prefer_failure must be a boolean")
    if prefer_failure:
        message.extend(_pcp_option(2))
    if len(message) > 1100:
        raise DriverError("PCP request exceeds the 1100-byte limit")
    return bytes(message)


def _radius_uint(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool):
        raise DriverError(f"RADIUS {field} must be an integer from 0 to {maximum}")
    if isinstance(value, str) and value.isdigit() and len(value) <= 32:
        value = int(value, 10)
    if not isinstance(value, int) or not 0 <= value <= maximum:
        raise DriverError(f"RADIUS {field} must be an integer from 0 to {maximum}")
    return value


def _radius_hex(value: Any, field: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise DriverError(f"RADIUS {field} must be an even-length hexadecimal string")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise DriverError(f"RADIUS {field} must be hexadecimal") from exc
    if length is not None and len(data) != length:
        raise DriverError(f"RADIUS {field} must contain exactly {length} bytes")
    return data


def _radius_attr_code(value: Any, field: str) -> int:
    if isinstance(value, str):
        code = RADIUS_ATTRIBUTE_CODES.get(value.lower())
        if code is None and value.isdigit():
            code = int(value, 10)
    elif isinstance(value, int) and not isinstance(value, bool):
        code = value
    else:
        code = None
    if code is None or not 1 <= code <= 255:
        raise DriverError(f"RADIUS {field} must be a known attribute name or a value from 1 to 255")
    return code


def _radius_attr_data(item: dict[str, Any], index: int) -> bytes:
    sources = [key for key in ("data", "data_hex", "data_base64") if key in item]
    if len(sources) != 1:
        raise DriverError(f"RADIUS attribute {index} must specify exactly one data source")
    source = sources[0]
    if source == "data_hex":
        return _radius_hex(item[source], f"attribute {index} data_hex")
    if source == "data_base64":
        encoded = item[source]
        if not isinstance(encoded, str):
            raise DriverError(f"RADIUS attribute {index} data_base64 must be a string")
        try:
            return base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise DriverError(f"RADIUS attribute {index} data_base64 is not valid base64") from exc
    value = item[source]
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise DriverError(f"RADIUS attribute {index} data must be a string or integer")
    data_type = str(item.get("type", "string")).lower()
    if data_type == "ip4":
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError as exc:
            raise DriverError(f"RADIUS attribute {index} data must be an IPv4 address") from exc
        if address.version != 4:
            raise DriverError(f"RADIUS attribute {index} data must be an IPv4 address")
        return address.packed
    if data_type in {"integer", "integer32"}:
        return _radius_uint(value, f"attribute {index} data", 0xFFFFFFFF).to_bytes(4, "big")
    if data_type == "integer64":
        return _radius_uint(value, f"attribute {index} data", 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    try:
        return str(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DriverError(f"RADIUS attribute {index} data must be valid UTF-8") from exc


def build_radius_request(request: dict[str, Any], event: str) -> bytes:
    """Build one bounded RADIUS request for an authentication or accounting event."""
    radius = request.get("radius", {})
    if not isinstance(radius, dict):
        raise DriverError("RADIUS request radius must be an object")
    allowed = {"code", "id", "authenticator_hex", "avps"}
    if any(not isinstance(key, str) for key in radius):
        raise DriverError("RADIUS request field names must be strings")
    unknown = sorted(set(radius) - allowed)
    if unknown:
        raise DriverError("RADIUS request unsupported field(s): " + ", ".join(unknown))
    default_code = 4 if event.endswith("ACCT_REQUEST") else 1
    code_value = radius.get("code", default_code)
    if isinstance(code_value, str):
        code = RADIUS_CODES.get(code_value.lower())
        if code is None and code_value.isdigit():
            code = _radius_uint(code_value, "code", 255)
    else:
        code = _radius_uint(code_value, "code", 255)
    if code not in {1, 4}:
        raise DriverError("RADIUS request code must be Access-Request (1) or Accounting-Request (4)")
    if code != default_code:
        expected_name = "Accounting-Request (4)" if default_code == 4 else "Access-Request (1)"
        raise DriverError(f"RADIUS {event} requires {expected_name}")
    identifier = _radius_uint(radius.get("id", 0), "id", 255)
    authenticator = _radius_hex(
        radius.get("authenticator_hex", "00" * 16), "authenticator_hex", 16
    )
    avps = radius.get("avps", [])
    if not isinstance(avps, list) or len(avps) > 128:
        raise DriverError("RADIUS avps must be an array of at most 128 items")
    encoded_avps = bytearray()
    for index, item in enumerate(avps):
        if not isinstance(item, dict):
            raise DriverError(f"RADIUS attribute {index} must be an object")
        if any(not isinstance(key, str) for key in item):
            raise DriverError(f"RADIUS attribute {index} field names must be strings")
        code_number = _radius_attr_code(item.get("code"), f"attribute {index} code")
        data = _radius_attr_data(item, index)
        vendor_id = _radius_uint(item.get("vendor_id", 0), f"attribute {index} vendor_id", 0xFFFFFFFF)
        vendor_type = _radius_uint(item.get("vendor_type", 0), f"attribute {index} vendor_type", 255)
        if code_number == 26:
            if not vendor_id or not vendor_type:
                raise DriverError(f"RADIUS attribute {index} Vendor-Specific fields are required")
            if len(data) + 8 > 255:
                raise DriverError(f"RADIUS attribute {index} exceeds the 255-byte limit")
            data = vendor_id.to_bytes(4, "big") + bytes([vendor_type, len(data) + 2]) + data
        elif vendor_id or vendor_type:
            raise DriverError(f"RADIUS attribute {index} vendor fields require code 26")
        if len(data) + 2 > 255:
            raise DriverError(f"RADIUS attribute {index} exceeds the 255-byte limit")
        encoded_avps.extend(bytes([code_number, len(data) + 2]) + data)
    length = 20 + len(encoded_avps)
    if length > 4096:
        raise DriverError("RADIUS request exceeds the 4096-byte limit")
    return bytes([code, identifier]) + struct.pack(">H", length) + authenticator + encoded_avps


def build_payload(trigger: dict[str, Any]) -> tuple[Endpoint, bytes, float]:
    event = _text(trigger.get("event"), "event", required=True)
    assert event is not None
    request = trigger.get("request", {})
    if not isinstance(request, dict):
        raise DriverError("request must be an object")
    timeout = _timeout(request)
    if event.startswith("HTTP_") and any(
        field in request
        for field in ("method", "uri", "host", "headers", "body", "payload_base64")
    ):
        return (
            endpoint_from_request(
                request,
                trigger.get("traffic_url"),
                default_scheme="tcp",
                default_port=80,
            ),
            build_http_request(request),
            timeout,
        )
    if event.startswith("WS_") and "websocket" in request:
        return (
            endpoint_from_request(
                request,
                trigger.get("traffic_url"),
                default_scheme="tcp",
                default_port=80,
            ),
            build_websocket_request(request, event),
            timeout,
        )
    if event.startswith("DNS_"):
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="udp", default_port=53),
            build_dns_query(request),
            timeout,
        )
    if event.startswith("MQTT_"):
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="tcp", default_port=1883),
            build_mqtt_connect_publish(request),
            timeout,
        )
    if event in {"CLIENT_DATA", "SERVER_DATA"} and "ftp" in request:
        return (
            endpoint_from_request(
                request,
                trigger.get("traffic_url"),
                default_scheme="tcp",
                default_port=21,
            ),
            build_ftp_message(request, event),
            timeout,
        )
    if event.startswith("SIP_"):
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="udp", default_port=5060),
            build_sip_message(request, event),
            timeout,
        )
    if event.startswith("RTSP_"):
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="tcp", default_port=554),
            build_rtsp_message(request, event),
            timeout,
        )
    if event == "PCP_REQUEST":
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="udp", default_port=5351),
            build_pcp_request(request),
            timeout,
        )
    if event in {"RADIUS_AAA_AUTH_REQUEST", "RADIUS_AAA_ACCT_REQUEST"}:
        return (
            endpoint_from_request(
                request,
                trigger.get("traffic_url"),
                default_scheme="udp",
                default_port=1813 if event.endswith("ACCT_REQUEST") else 1812,
            ),
            build_radius_request(request, event),
            timeout,
        )
    payload = _payload_bytes(request)
    return (
        endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="tcp", default_port=0),
        payload,
        timeout,
    )


def send_payload(endpoint: Endpoint, payload: bytes, timeout: float) -> None:
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise DriverError("payload exceeds the 2 MiB limit")
    try:
        if endpoint.scheme == "udp":
            addresses = socket.getaddrinfo(
                endpoint.host, endpoint.port, type=socket.SOCK_DGRAM
            )
            if not addresses:
                raise DriverError("protocol driver destination did not resolve")
            family, socktype, proto, _, sockaddr = addresses[0]
            with socket.socket(family, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.sendto(payload, sockaddr)
        else:
            with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
                sock.sendall(payload)
    except OSError as exc:
        raise DriverError(f"protocol stimulus failed for {endpoint.host}:{endpoint.port}: {exc}") from exc


def main() -> int:
    try:
        trigger = read_request()
        endpoint, payload, timeout = build_payload(trigger)
        send_payload(endpoint, payload, timeout)
        return 0
    except DriverError as exc:
        print(f"tmos17-protocol-driver: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
