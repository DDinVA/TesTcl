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


def build_payload(trigger: dict[str, Any]) -> tuple[Endpoint, bytes, float]:
    event = _text(trigger.get("event"), "event", required=True)
    assert event is not None
    request = trigger.get("request", {})
    if not isinstance(request, dict):
        raise DriverError("request must be an object")
    timeout = _timeout(request)
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
    if event.startswith("SIP_"):
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="udp", default_port=5060),
            build_sip_message(request, event),
            timeout,
        )
    if event == "PCP_REQUEST":
        return (
            endpoint_from_request(request, trigger.get("traffic_url"), default_scheme="udp", default_port=5351),
            build_pcp_request(request),
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
