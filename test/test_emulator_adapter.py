"""Regression tests for the optional tmos-17.5 emulator adapter."""

from __future__ import annotations

import importlib.util
import base64
import hashlib
import http.client
import io
import ipaddress
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time
import tempfile
import unittest
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from hpack import Encoder

from tools.http2_wire import HTTP2_CLIENT_PREFACE, Http2ConnectionDecoder


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


def _valid_client_certificate() -> tuple[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Root"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Root CA"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x010203)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("client.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem, der


def _tls_certificate_payload(
    der: bytes, *chain: bytes, tls13: bool = False
) -> bytes:
    certificate_entries = b"".join(
        len(certificate).to_bytes(3, "big")
        + certificate
        + (b"\x00\x00" if tls13 else b"")
        for certificate in (der, *chain)
    )
    certificate_body = (
        (bytes([0]) if tls13 else b"")
        + len(certificate_entries).to_bytes(3, "big")
        + certificate_entries
    )
    handshake = b"\x0b" + len(certificate_body).to_bytes(3, "big") + certificate_body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _http2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + (stream_id & 0x7FFF_FFFF).to_bytes(4, "big")
        + payload
    )


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


def _raw_ipv6_udp_hex(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
    *,
    traffic_class: int = 0,
    hop_limit: int = 64,
    next_header: int = 17,
    extension_header: bytes = b"",
) -> str:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    first_word = (6 << 28) | (traffic_class << 20)
    ip = struct.pack(
        "!IHBB16s16s",
        first_word,
        len(extension_header) + len(udp) + len(payload),
        next_header,
        hop_limit,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return (ip + extension_header + udp + payload).hex()


def _raw_ipv4_fragment_hex(
    source: str,
    destination: str,
    identification: int,
    offset: int,
    payload: bytes,
    *,
    more_fragments: bool,
    protocol: int,
) -> str:
    if offset % 8:
        raise ValueError("IPv4 fragment offsets must be multiples of eight")
    fragment_field = (offset // 8) | (0x2000 if more_fragments else 0)
    total_length = 20 + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        fragment_field,
        64,
        protocol,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return (ip + payload).hex()


def _raw_ipv6_fragment_hex(
    source: str,
    destination: str,
    identification: int,
    offset: int,
    payload: bytes,
    *,
    more_fragments: bool,
    next_header: int,
) -> str:
    if offset % 8:
        raise ValueError("IPv6 fragment offsets must be multiples of eight")
    fragment_field = ((offset // 8) << 3) | (1 if more_fragments else 0)
    fragment_header = (
        bytes([next_header, 0])
        + fragment_field.to_bytes(2, "big")
        + identification.to_bytes(4, "big")
    )
    first_word = 6 << 28
    ip = struct.pack(
        "!IHBB16s16s",
        first_word,
        len(fragment_header) + len(payload),
        44,
        64,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return (ip + fragment_header + payload).hex()


def _ikev2_message(
    *, exchange_type: int = 35, response: bool = False,
    payload_types: tuple[int, ...] = (35, 39),
) -> bytes:
    payload = bytearray()
    for index, payload_type in enumerate(payload_types):
        next_payload = payload_types[index + 1] if index + 1 < len(payload_types) else 0
        payload.extend(bytes([next_payload, 0]) + (4).to_bytes(2, "big"))
    flags = 0x20 if response else 0
    return struct.pack(
        "!8s8sBBBBII",
        bytes.fromhex("0102030405060708"),
        bytes.fromhex("1112131415161718"),
        payload_types[0] if payload_types else 0,
        0x20,
        exchange_type,
        flags,
        1,
        28 + len(payload),
    ) + bytes(payload)


def _pcp_address_bytes(address: str) -> bytes:
    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + parsed.packed
    return parsed.packed


def _pcp_map_request(
    *,
    client_addr: str = "192.0.2.10",
    lifetime: int = 3600,
    internal_port: int = 22,
    suggested_port: int = 40000,
    suggested_addr: str = "0.0.0.0",
    third_party_addr: str | None = None,
    prefer_failure: bool = False,
) -> bytes:
    message = (
        bytes([2, 1, 0, 0])
        + lifetime.to_bytes(4, "big")
        + _pcp_address_bytes(client_addr)
        + b"\x00" * 12
        + bytes([6, 0, 0, 0])
        + internal_port.to_bytes(2, "big")
        + suggested_port.to_bytes(2, "big")
        + _pcp_address_bytes(suggested_addr)
    )
    if third_party_addr is not None:
        option_data = _pcp_address_bytes(third_party_addr)
        message += bytes([1, 0]) + len(option_data).to_bytes(2, "big") + option_data
    if prefer_failure:
        message += bytes([2, 0, 0, 0])
    return message


def _pcp_map_response(
    *,
    lifetime: int = 1800,
    result: int = 0,
    internal_port: int = 22,
    assigned_port: int = 40000,
    assigned_addr: str = "198.51.100.20",
    epoch: int = 123,
) -> bytes:
    return (
        bytes([2, 0x81, 0, result])
        + lifetime.to_bytes(4, "big")
        + epoch.to_bytes(4, "big")
        + b"\x00" * 12
        + b"\x00" * 12
        + bytes([6, 0, 0, 0])
        + internal_port.to_bytes(2, "big")
        + assigned_port.to_bytes(2, "big")
        + _pcp_address_bytes(assigned_addr)
    )


def _pcp_peer_request() -> bytes:
    return (
        bytes([2, 2, 0, 0])
        + (600).to_bytes(4, "big")
        + _pcp_address_bytes("192.0.2.10")
        + b"\x00" * 12
        + bytes([17, 0, 0, 0])
        + (5353).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + _pcp_address_bytes("0.0.0.0")
        + (443).to_bytes(2, "big")
        + b"\x00" * 2
        + _pcp_address_bytes("198.51.100.30")
    )


def _dhcpv4_message(
    *,
    opcode: int = 1,
    xid: int = 0x12345678,
    secs: int = 3,
    chaddr: str = "00:11:22:33:44:55",
    ciaddr: str = "0.0.0.0",
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    options: tuple[tuple[int, bytes], ...] = (
        (53, b"\x01"),
        (12, b"client-a"),
    ),
) -> bytes:
    header = bytearray(236)
    header[0:4] = bytes([opcode, 1, 6, 0])
    header[4:8] = xid.to_bytes(4, "big")
    header[8:10] = secs.to_bytes(2, "big")
    for offset, address in ((12, ciaddr), (16, yiaddr), (20, siaddr), (24, giaddr)):
        header[offset : offset + 4] = ipaddress.ip_address(address).packed
    hardware = bytes.fromhex(chaddr.replace(":", ""))
    header[28 : 28 + len(hardware)] = hardware
    message_options = bytearray(b"\x63\x82\x53\x63")
    for option_code, option_data in options:
        message_options.extend(bytes([option_code, len(option_data)]))
        message_options.extend(option_data)
    message_options.append(255)
    return bytes(header) + bytes(message_options)


def _dhcpv6_message(
    *,
    message_type: int = 1,
    transaction_id: bytes = b"\x01\x02\x03",
    options: tuple[tuple[int, bytes], ...] = ((8, b"\x00\x2a"),),
) -> bytes:
    message = bytearray(bytes([message_type]) + transaction_id)
    for option_code, option_data in options:
        message.extend(struct.pack("!HH", option_code, len(option_data)))
        message.extend(option_data)
    return bytes(message)


def _gtp_v2_hex(
    message_type: int,
    *,
    teid: int = 0,
    sequence: int = 0,
    body: bytes = b"",
) -> str:
    flags = 0x48 if teid else 0x40
    header = bytes([flags, message_type]) + b"\x00\x00"
    if teid:
        header += teid.to_bytes(4, "big")
    header += sequence.to_bytes(3, "big") + b"\x00"
    message = header + body
    message = message[:2] + (len(message) - 4).to_bytes(2, "big") + message[4:]
    return message.hex()


def _gtp_v1_hex(
    message_type: int,
    *,
    teid: int = 0,
    sequence: int = 0,
    npdu: int = 0,
    body: bytes = b"",
) -> str:
    rest = (
        teid.to_bytes(4, "big")
        + sequence.to_bytes(2, "big")
        + bytes([npdu, 0])
        + body
    )
    return (bytes([0x32, message_type]) + len(rest).to_bytes(2, "big") + rest).hex()


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


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((-len(body)) % 4)
    body += padding
    block_length = 12 + len(body)
    return struct.pack("<II", block_type, block_length) + body + struct.pack("<I", block_length)


def _pcapng_bytes(
    records: list[tuple[int, int, bytes]], *, linktype: int = 1, tsresol: int = 6
) -> bytes:
    section = _pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface_options = (
        struct.pack("<HHB", 9, 1, tsresol)
        + b"\x00" * 3
        + struct.pack("<HH", 0, 0)
    )
    interface = _pcapng_block(
        0x00000001,
        struct.pack("<HHI", linktype, 0, 65535) + interface_options,
    )
    packet_blocks = bytearray()
    for seconds, fraction, frame in records:
        ticks = seconds * (10**tsresol) + fraction
        packet_blocks.extend(
            _pcapng_block(
                0x00000006,
                struct.pack(
                    "<IIIII",
                    0,
                    (ticks >> 32) & 0xFFFF_FFFF,
                    ticks & 0xFFFF_FFFF,
                    len(frame),
                    len(frame),
                )
                + frame,
            )
        )
    return section + interface + bytes(packet_blocks)


def _ethernet_ipv4(raw_hex: str) -> bytes:
    return b"\x00" * 12 + b"\x08\x00" + bytes.fromhex(raw_hex)


def _ethernet_ipv6(raw_hex: str) -> bytes:
    return b"\x00" * 12 + b"\x86\xdd" + bytes.fromhex(raw_hex)


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

    def test_interleaved_packet_flows_are_isolated_and_merged(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "a_pool": ["10.0.0.10:80"],
                    "b_pool": ["10.0.0.11:80"],
                },
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::host] eq "a.example"} {
        pool a_pool
    } else {
        pool b_pool
    }
}
""",
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.1", "port": 50001},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "host": "a.example",
                        "uri": "/a",
                    },
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.2", "port": 50002},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "host": "b.example",
                        "uri": "/b",
                    },
                    {
                        "protocol": "http",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.1", "port": 50001},
                        "status": 200,
                        "response_body": "a-response",
                    },
                    {
                        "protocol": "http",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.2", "port": 50002},
                        "status": 200,
                        "response_body": "b-response",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(result["flow_mode"], "isolated")
        self.assertEqual(result["flow_count"], 2)
        self.assertEqual(
            [entry["index"] for entry in result["trace"]], [0, 1, 2, 3]
        )
        self.assertEqual(
            [entry["flow_id"] for entry in result["flows"]],
            [
                "tcp:10.0.0.1:50001->192.0.2.10:80",
                "tcp:10.0.0.2:50002->192.0.2.10:80",
            ],
        )
        self.assertEqual(
            [entry["packet_indexes"] for entry in result["flows"]], [[0, 2], [1, 3]]
        )
        self.assertEqual([item["pool"] for item in result["results"]], ["a_pool", "b_pool"])
        self.assertEqual(
            [item["response"]["body"] for item in result["results"]],
            ["a-response", "b-response"],
        )

    def test_multi_flow_synthetic_events_require_flow_id(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "synthetic event packets in a multi-flow trace require flow_id",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when CLIENT_ACCEPTED { log local0. accepted }",
                    "packets": [
                        {
                            "protocol": "http",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.1", "port": 50001},
                            "destination": {"address": "192.0.2.10", "port": 80},
                            "host": "a.example",
                            "uri": "/a",
                        },
                        {
                            "protocol": "http",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.2", "port": 50002},
                            "destination": {"address": "192.0.2.10", "port": 80},
                            "host": "b.example",
                            "uri": "/b",
                        },
                        {
                            "protocol": "event",
                            "event": "CLIENT_ACCEPTED",
                            "state": {},
                        },
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_flow_id_is_preserved_for_raw_wire_packets(self) -> None:
        raw_hex = _raw_ipv4_tcp_hex(
            "10.0.0.1", "192.0.2.10", 50001, 80, 0x18, b"GET / HTTP/1.0\r\n\r\n"
        )
        packets = self.adapter._normalise_packets(
            [{"protocol": "wire", "flow_id": "raw-a", "raw_hex": raw_hex}]
        )
        self.assertEqual(packets[0]["flow_id"], "raw-a")
        self.assertEqual(packets[0]["protocol"], "tcp")

    def test_raw_http_stages_request_data_after_headers(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "headers=[HTTP::path]"
    HTTP::collect 6
}
when HTTP_REQUEST_DATA {
    log local0. "data=[HTTP::payload]"
    HTTP::release
}
when HTTP_RESPONSE {
    log local0. "response=[HTTP::status]"
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.1", "port": 50001},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "payload": (
                            "POST /upload HTTP/1.1\r\n"
                            "Host: app.example\r\n"
                            "Content-Length: 6\r\n\r\n"
                            "abc"
                        ),
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.1", "port": 50001},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "payload": "def",
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.1", "port": 50001},
                        "payload": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        transaction = result["results"][0]
        self.assertEqual(transaction["request"]["body"], "abcdef")
        self.assertEqual(
            transaction["events_fired"],
            [
                "RULE_INIT",
                "CLIENT_ACCEPTED",
                "HTTP_REQUEST",
                "HTTP_REQUEST_DATA",
                "HTTP_REQUEST_RELEASE",
                "HTTP_RESPONSE",
            ],
        )
        self.assertTrue(any("headers=/upload" in entry for entry in transaction["logs"]))
        self.assertTrue(any("data=abcdef" in entry for entry in transaction["logs"]))
        self.assertTrue(any("response=200" in entry for entry in transaction["logs"]))
        self.assertEqual(result["trace"][0]["http_stage"]["phase"], "HTTP_REQUEST")
        self.assertEqual(result["trace"][1]["staged_body_received"], 6)

    def test_raw_http_staging_preserves_request_pool_selection(self) -> None:
        crlf = "\r\n"
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"upload_pool": ["10.0.0.10:80"]},
                "irule": """
when HTTP_REQUEST { pool upload_pool; HTTP::collect 3 }
when HTTP_REQUEST_DATA { HTTP::release }
when HTTP_RESPONSE { log local0. "pool=[LB::server pool]" }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.1", "port": 50002},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "payload": (
                            "POST /upload HTTP/1.1"
                            + crlf
                            + "Host: app.example"
                            + crlf
                            + "Content-Length: 3"
                            + crlf
                            + crlf
                            + "abc"
                        ),
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.1", "port": 50002},
                        "payload": "HTTP/1.1 200 OK" + crlf + "Content-Length: 0" + crlf + crlf,
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        transaction = result["results"][0]
        self.assertEqual(transaction["pool"], "upload_pool")
        self.assertTrue(any("pool=upload_pool" in entry for entry in transaction["logs"]))

    def test_raw_http_stages_response_data_after_response_headers(self) -> None:
        crlf = "\r\n"
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { HTTP::collect 3 }
when HTTP_REQUEST_DATA { HTTP::release }
when HTTP_RESPONSE {
    log local0. "response-head=[HTTP::payload]"
    HTTP::collect 5
}
when HTTP_RESPONSE_DATA {
    log local0. "response-data=[HTTP::payload]"
    HTTP::release
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.1", "port": 50003},
                        "destination": {"address": "192.0.2.10", "port": 80},
                        "payload": (
                            "POST /upload HTTP/1.1"
                            + crlf
                            + "Host: app.example"
                            + crlf
                            + "Content-Length: 3"
                            + crlf
                            + crlf
                            + "abc"
                        ),
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.1", "port": 50003},
                        "payload": "HTTP/1.1 200 OK" + crlf + "Content-Length: 5" + crlf + crlf + "xy",
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 80},
                        "destination": {"address": "10.0.0.1", "port": 50003},
                        "payload": "z12",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        transaction = result["results"][0]
        self.assertEqual(transaction["response"]["body"], "xyz12")
        self.assertIn("HTTP_RESPONSE", transaction["events_fired"])
        self.assertIn("HTTP_RESPONSE_DATA", transaction["events_fired"])
        self.assertIn("HTTP_RESPONSE_RELEASE", transaction["events_fired"])
        self.assertTrue(
            any("response-head=" in entry for entry in transaction["logs"])
        )
        self.assertTrue(
            any("response-data=xyz12" in entry for entry in transaction["logs"])
        )
        self.assertEqual(result["trace"][1]["http_stage"]["phase"], "HTTP_RESPONSE")
        self.assertEqual(result["trace"][2]["staged_response_body_received"], 5)

    def test_raw_http_staging_survives_persistent_trace_calls(self) -> None:
        crlf = "\r\n"
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        session_id = manager.create(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "request=[HTTP::path]"
    HTTP::collect 6
}
when HTTP_REQUEST_DATA {
    log local0. "request-data=[HTTP::payload]"
    HTTP::release
}
when HTTP_RESPONSE {
    log local0. "response=[HTTP::status]"
    HTTP::collect 5
}
when HTTP_RESPONSE_DATA {
    log local0. "response-data=[HTTP::payload]"
    HTTP::release
}
""",
            }
        )
        source = {"address": "10.0.0.1", "port": 50004}
        destination = {"address": "192.0.2.10", "port": 80}
        try:
            first = manager.execute(
                session_id,
                lambda session: session.run_packet_trace(
                    [
                        {
                            "protocol": "tcp",
                            "direction": "client_to_server",
                            "source": source,
                            "destination": destination,
                            "payload": (
                                "POST /persistent HTTP/1.1"
                                + crlf
                                + "Host: app.example"
                                + crlf
                                + "Content-Length: 6"
                                + crlf
                                + crlf
                                + "abc"
                            ),
                        }
                    ]
                ),
            )
            second = manager.execute(
                session_id,
                lambda session: session.run_packet_trace(
                    [
                        {
                            "protocol": "tcp",
                            "direction": "client_to_server",
                            "source": source,
                            "destination": destination,
                            "payload": "def",
                        },
                        {
                            "protocol": "tcp",
                            "direction": "server_to_client",
                            "source": destination,
                            "destination": source,
                            "payload": (
                                "HTTP/1.1 200 OK"
                                + crlf
                                + "Content-Length: 5"
                                + crlf
                                + crlf
                                + "xy"
                            ),
                        },
                        {
                            "protocol": "tcp",
                            "direction": "server_to_client",
                            "source": destination,
                            "destination": source,
                            "payload": "z12",
                        },
                    ]
                ),
            )
            metadata = manager.metadata(session_id)
        finally:
            manager.close(session_id)

        self.assertEqual(first["results"], [])
        self.assertEqual(len(second["results"]), 1)
        transaction = second["results"][0]
        self.assertEqual(transaction["request"]["body"], "abcdef")
        self.assertEqual(transaction["response"]["body"], "xyz12")
        self.assertIn("HTTP_REQUEST_DATA", transaction["events_fired"])
        self.assertIn("HTTP_RESPONSE_DATA", transaction["events_fired"])
        self.assertTrue(any("request-data=abcdef" in entry for entry in transaction["logs"]))
        self.assertTrue(any("response-data=xyz12" in entry for entry in transaction["logs"]))
        self.assertEqual(metadata["request_count"], 1)

    def test_packet_flow_count_is_bounded_before_child_sessions_start(self) -> None:
        packets = [
            {
                "protocol": "http",
                "direction": "client_to_server",
                "source": {"address": f"192.0.2.{index}", "port": 40000 + index},
                "destination": {"address": "198.51.100.10", "port": 80},
                "host": "example.com",
                "uri": f"/{index}",
            }
            for index in range(1, 66)
        ]
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet trace cannot contain more than 64 flows",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { log local0. bounded }",
                    "packets": packets,
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http_disable_emits_http_disabled_with_passthrough_reason(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/disabled"} { HTTP::disable discard }
}
when HTTP_DISABLED {
    log local0. "reason=[HTTP::passthrough_reason] num=[HTTP::passthrough_reason as_num]"
}
""",
                "requests": [
                    {"uri": "/disabled"},
                    {"uri": "/normal"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        disabled, normal = result["results"]
        self.assertIn("HTTP_DISABLED", disabled["events_fired"])
        self.assertTrue(disabled["http_disabled"])
        self.assertTrue(disabled["http_disable_discard"])
        self.assertTrue(any("reason=iRule num=1" in entry for entry in disabled["logs"]))
        self.assertNotIn("HTTP_DISABLED", normal["events_fired"])
        self.assertNotIn("http_disabled", normal)

        packet_result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { HTTP::disable }
when HTTP_DISABLED { log local0. packet-disabled }
""",
                "packets": [
                    {"protocol": "http", "uri": "/disabled", "method": "GET"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_http_result = packet_result["trace"][0]["http_result"]
        self.assertIn("HTTP_DISABLED", packet_http_result["events_fired"])
        self.assertTrue(packet_http_result["http_disabled"])
        self.assertTrue(any("packet-disabled" in entry for entry in packet_http_result["logs"]))

    def test_http_class_outcome_precedes_request_for_requests_and_packets(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_CLASS_SELECTED {
    log local0. "selected=[HTTP::class] asm=[HTTP::class asm] wa=[HTTP::class wa]"
    HTTP::class disable
    HTTP::class select selected-class
}
when HTTP_CLASS_FAILED { log local0. "failed=[HTTP::class]" }
when HTTP_REQUEST { log local0. "request=[HTTP::class]" }
""",
                "requests": [
                    {
                        "uri": "/selected",
                        "http_class": {
                            "result": "selected",
                            "name": "legacy-class",
                            "asm": True,
                        },
                    },
                    {
                        "uri": "/failed",
                        "http_class": {"result": "failed", "wa": True},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        selected, failed = result["results"]
        self.assertLess(
            selected["events_fired"].index("HTTP_CLASS_SELECTED"),
            selected["events_fired"].index("HTTP_REQUEST"),
        )
        self.assertTrue(any("selected=legacy-class asm=1 wa=0" in entry for entry in selected["logs"]))
        self.assertEqual(selected["http_class"]["name"], "selected-class")
        self.assertFalse(selected["http_class"]["enabled"])
        self.assertTrue(any("failed=" in entry for entry in failed["logs"]))
        self.assertEqual(failed["http_class"]["outcome"], "failed")
        self.assertTrue(failed["http_class"]["wa"])

        packet_result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_CLASS_SELECTED { log local0. packet-class }",
                "packets": [{
                    "protocol": "http",
                    "uri": "/packet",
                    "http_class": {"result": "selected", "name": "packet-class"},
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_http_result = packet_result["trace"][0]["http_result"]
        self.assertIn("HTTP_CLASS_SELECTED", packet_http_result["events_fired"])
        self.assertTrue(any("packet-class" in entry for entry in packet_http_result["logs"]))

        for invalid in (
            {"result": "unknown", "name": "x"},
            {"result": "selected"},
            {"result": "failed", "unexpected": True},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.adapter.EmulatorInputError):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "irule": "when HTTP_REQUEST { log local0. ok }",
                            "requests": [{"http_class": invalid}],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "HTTP responses cannot specify http_class",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_RESPONSE { log local0. ok }",
                    "packets": [{
                        "protocol": "http",
                        "direction": "server_to_client",
                        "status": 200,
                        "http_class": {"result": "selected", "name": "wrong-side"},
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http_reject_emits_http_reject_and_closes_connection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/reject"} { reject }
}
when HTTP_REJECT {
    log local0. "reason=[HTTP::reject_reason] num=[HTTP::reject_reason as_num]"
}
""",
                "requests": [
                    {"uri": "/reject"},
                    {"uri": "/normal"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        rejected, normal = result["results"]
        self.assertIn("HTTP_REJECT", rejected["events_fired"])
        self.assertTrue(rejected["http_rejected"])
        self.assertEqual(rejected["http_reject_reason"], "iRule")
        self.assertEqual(rejected["http_reject_reason_num"], 1)
        self.assertTrue(any("reason=iRule num=1" in entry for entry in rejected["logs"]))
        self.assertEqual(rejected["connection_state"], "closing")
        self.assertNotIn("HTTP_REJECT", normal["events_fired"])
        self.assertNotIn("http_rejected", normal)

        connection_reject = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when CLIENT_ACCEPTED { reject }
when HTTP_REJECT { log local0. should-not-fire }
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_REJECT", connection_reject["results"][0]["events_fired"])
        self.assertNotIn("http_rejected", connection_reject["results"][0])

        packet_result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { reject }
when HTTP_REJECT { log local0. packet-rejected }
""",
                "packets": [{"protocol": "http", "uri": "/reject", "method": "GET"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_http_result = packet_result["trace"][0]["http_result"]
        self.assertIn("HTTP_REJECT", packet_http_result["events_fired"])
        self.assertTrue(packet_http_result["http_rejected"])
        self.assertTrue(any("packet-rejected" in entry for entry in packet_http_result["logs"]))

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "HTTP::reject_reason accepts optional as_num",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": """
when HTTP_REQUEST { reject }
when HTTP_REJECT { log local0. [HTTP::reject_reason invalid] }
""",
                    "requests": [{"uri": "/reject"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http_proxy_profile_runs_proxy_request_before_http_request(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "irule": """
when HTTP_PROXY_REQUEST {
    log local0. "proxy=[HTTP::uri] enabled=[HTTP::proxy]"
    HTTP::uri /rewritten
    HTTP::proxy disable
}
when HTTP_REQUEST {
    log local0. "request=[HTTP::uri] enabled=[HTTP::proxy]"
}
""",
                "requests": [{"uri": "http://origin.example/path"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request = result["results"][0]
        events = request["events_fired"]
        self.assertLess(events.index("HTTP_PROXY_REQUEST"), events.index("HTTP_REQUEST"))
        self.assertTrue(any("proxy=http://origin.example/path enabled=1" in entry for entry in request["logs"]))
        self.assertTrue(any("request=/rewritten enabled=0" in entry for entry in request["logs"]))
        self.assertFalse(request["semantic"]["http_proxy"]["enabled"])

        ordinary = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_PROXY_REQUEST { log local0. should-not-fire }",
                "requests": [{"uri": "/ordinary"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_PROXY_REQUEST", ordinary["results"][0]["events_fired"])

        disabled_proxy = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {"enabled": False},
                "irule": "when HTTP_PROXY_REQUEST { log local0. should-not-fire } when HTTP_REQUEST { log local0. normal-request }",
                "requests": [{"uri": "http://origin.example/disabled"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_PROXY_REQUEST", disabled_proxy["results"][0]["events_fired"])
        self.assertIn("HTTP_REQUEST", disabled_proxy["results"][0]["events_fired"])

        packet_result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "irule": "when HTTP_PROXY_REQUEST { log local0. packet-proxy }",
                "packets": [
                    {"protocol": "http", "uri": "http://origin.example/", "method": "GET"},
                    {"protocol": "http", "direction": "server_to_client", "status": 200},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_http_result = packet_result["trace"][0]["http_result"]
        self.assertIn("HTTP_PROXY_REQUEST", packet_http_result["events_fired"])
        self.assertTrue(any("packet-proxy" in entry for entry in packet_http_result["logs"]))

    def test_http_proxy_chain_models_connect_and_response_fixture(self) -> None:
        scenario = {
            "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
            "http_proxy": {
                "chain": {
                    "enabled": True,
                    "host": "proxy.internal",
                    "port": 8080,
                    "response": {
                        "status": 407,
                        "headers": {
                            "Proxy-Authenticate": 'Basic realm="edge"',
                            "X-Proxy": "chain-1",
                        },
                        "body": "proxy-auth-required",
                    },
                }
            },
            "irule": """
when HTTP_PROXY_REQUEST {
    log local0. "proxy-request=[HTTP::uri]"
}
when HTTP_PROXY_CONNECT {
    HTTP::header insert Proxy-Request-Tag connected
    log local0. "proxy-connect=[HTTP::proxy chain host]:[HTTP::proxy chain port]"
}
when HTTP_PROXY_RESPONSE {
    log local0. "proxy-response=[HTTP::status] auth=[HTTP::header value Proxy-Authenticate] body=[HTTP::payload]"
    HTTP::proxy chain retry
}
when HTTP_REQUEST {
    log local0. "request=[HTTP::uri]"
}
""",
            "requests": [
                {"uri": "http://origin.example/private"},
                {"uri": "http://origin.example/second"},
            ],
        }
        result = self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)
        request = result["results"][0]
        events = request["events_fired"]
        self.assertLess(events.index("HTTP_PROXY_REQUEST"), events.index("HTTP_PROXY_CONNECT"))
        self.assertLess(events.index("HTTP_PROXY_CONNECT"), events.index("HTTP_PROXY_RESPONSE"))
        self.assertLess(events.index("HTTP_PROXY_RESPONSE"), events.index("HTTP_REQUEST"))
        self.assertTrue(any("proxy-connect=proxy.internal:8080" in entry for entry in request["logs"]))
        self.assertTrue(any("proxy-response=407" in entry for entry in request["logs"]))
        self.assertTrue(any('auth=Basic realm="edge"' in entry for entry in request["logs"]))
        self.assertTrue(any("body=proxy-auth-required" in entry for entry in request["logs"]))
        self.assertTrue(request["semantic"]["http_proxy"]["chain_retry_requested"])
        self.assertEqual(request["response"]["status"], 200)
        self.assertEqual(request["response"]["body"], "")
        self.assertEqual(
            request["semantic"]["http_proxy"]["chain_response"],
            {
                "status": 407,
                "reason": "Proxy Authentication Required",
                "headers": {
                    "proxy-authenticate": 'Basic realm="edge"',
                    "x-proxy": "chain-1",
                },
                "body": "proxy-auth-required",
            },
        )
        second_request = result["results"][1]
        self.assertIn("HTTP_PROXY_CONNECT", second_request["events_fired"])
        self.assertIn("HTTP_PROXY_RESPONSE", second_request["events_fired"])
        self.assertTrue(second_request["semantic"]["http_proxy"]["chain_retry_requested"])

        packet_result = self.adapter.run_scenario(
            {
                **{key: value for key, value in scenario.items() if key != "requests"},
                "packets": [
                    {"protocol": "http", "uri": "http://origin.example/packet"},
                    {"protocol": "http", "direction": "server_to_client", "status": 200},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_http_result = packet_result["trace"][0]["http_result"]
        self.assertIn("HTTP_PROXY_CONNECT", packet_http_result["events_fired"])
        self.assertIn("HTTP_PROXY_RESPONSE", packet_http_result["events_fired"])

        no_chain_response = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {"chain": {"enabled": False, "response": {"status": 407}}},
                "irule": "when HTTP_PROXY_CONNECT { log local0. should-not-fire } when HTTP_PROXY_RESPONSE { log local0. should-not-fire }",
                "requests": [{"uri": "http://origin.example/no-chain"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("HTTP_PROXY_CONNECT", no_chain_response["results"][0]["events_fired"])
        self.assertNotIn("HTTP_PROXY_RESPONSE", no_chain_response["results"][0]["events_fired"])

        for invalid_proxy in (
            {"chain": {"response": {"status": 99}}},
            {"chain": {"response": {"unsupported": True}}},
            {"chain": {"responses": []}},
            {
                "chain": {
                    "response": {"status": 407},
                    "responses": [{"status": 200}],
                }
            },
            {
                "chain": {
                    "responses": [{"status": 407}, {"status": 200}, {"status": 200}],
                }
            },
        ):
            with self.assertRaises(self.adapter.EmulatorInputError):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                        "http_proxy": invalid_proxy,
                        "irule": "when HTTP_REQUEST { log local0. request }",
                        "requests": [{"uri": "/invalid-proxy-fixture"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_http_proxy_chain_response_sequence_retries_once_and_bounds_failure(self) -> None:
        success = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {
                    "chain": {
                        "responses": [
                            {
                                "status": 407,
                                "headers": {"Proxy-Authenticate": "Basic realm=\"edge\""},
                                "body": "proxy-auth-required",
                            },
                            {
                                "status": 200,
                                "headers": {"X-Proxy": "chain-ready"},
                                "body": "tunnel-ready",
                            },
                        ]
                    }
                },
                "irule": """
when HTTP_PROXY_CONNECT { log local0. "connect=[HTTP::proxy chain host]" }
when HTTP_PROXY_RESPONSE {
    log local0. "proxy-status=[HTTP::status] body=[HTTP::payload]"
    HTTP::proxy chain retry
}
when HTTP_REQUEST { log local0. "origin-request=[HTTP::uri]" }
""",
                "requests": [{"uri": "http://origin.example/retry"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        successful_request = success["results"][0]
        self.assertEqual(
            successful_request["events_fired"].count("HTTP_PROXY_CONNECT"), 2
        )
        self.assertEqual(
            successful_request["events_fired"].count("HTTP_PROXY_RESPONSE"), 2
        )
        self.assertIn("HTTP_REQUEST", successful_request["events_fired"])
        self.assertTrue(any("proxy-status=407" in entry for entry in successful_request["logs"]))
        self.assertTrue(any("proxy-status=200" in entry for entry in successful_request["logs"]))
        self.assertEqual(successful_request["semantic"]["http_proxy"]["chain_response_index"], 1)
        self.assertEqual(successful_request["semantic"]["http_proxy"]["chain_retry_count"], 1)
        self.assertFalse(successful_request["semantic"]["http_proxy"]["chain_failed"])
        self.assertEqual(
            successful_request["semantic"]["http_proxy"]["chain_response"]["status"], 200
        )

        packet_success = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {
                    "chain": {"responses": [{"status": 407}, {"status": 200}]}
                },
                "irule": "when HTTP_PROXY_RESPONSE { HTTP::proxy chain retry }",
                "packets": [
                    {"protocol": "http", "method": "GET", "uri": "/packet-retry"},
                    {"protocol": "http", "direction": "server_to_client", "status": 200},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet_request = packet_success["trace"][0]["http_result"]
        self.assertEqual(packet_request["events_fired"].count("HTTP_PROXY_RESPONSE"), 2)
        self.assertIn("HTTP_REQUEST", packet_request["events_fired"])
        self.assertEqual(packet_request["semantic"]["http_proxy"]["chain_response_index"], 1)
        self.assertEqual(packet_request["semantic"]["http_proxy"]["chain_retry_count"], 1)

        exhausted = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {
                    "chain": {"responses": [{"status": 407}, {"status": 407}]}
                },
                "irule": """
when HTTP_PROXY_RESPONSE { log local0. retry; HTTP::proxy chain retry }
when HTTP_REQUEST { log local0. should-not-run }
""",
                "requests": [{"uri": "http://origin.example/exhausted"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        exhausted_request = exhausted["results"][0]
        self.assertNotIn("HTTP_REQUEST", exhausted_request["events_fired"])
        self.assertEqual(exhausted_request["connection_state"], "closing")
        self.assertTrue(exhausted_request["semantic"]["http_proxy"]["chain_failed"])
        self.assertEqual(exhausted_request["semantic"]["http_proxy"]["chain_retry_count"], 1)

        no_handler = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {"chain": {"responses": [{"status": 407}]}},
                "irule": "when HTTP_REQUEST { log local0. should-not-run }",
                "requests": [{"uri": "http://origin.example/no-handler"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(no_handler["results"][0]["connection_state"], "closing")
        self.assertTrue(no_handler["results"][0]["semantic"]["http_proxy"]["chain_failed"])

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTTP_PROXY_CONNECT"],
                "http_proxy": {
                    "chain": {"responses": [{"status": 407}, {"status": 200}]}
                },
                "irule": """
when HTTP_PROXY_RESPONSE { HTTP::proxy chain disable; HTTP::proxy chain retry }
when HTTP_REQUEST { log local0. origin-after-disable }
""",
                "requests": [{"uri": "http://origin.example/disabled-retry"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        disabled_request = disabled["results"][0]
        self.assertEqual(disabled_request["events_fired"].count("HTTP_PROXY_RESPONSE"), 1)
        self.assertIn("HTTP_REQUEST", disabled_request["events_fired"])
        self.assertFalse(disabled_request["semantic"]["http_proxy"]["chain_failed"])
        self.assertEqual(disabled_request["semantic"]["http_proxy"]["chain_retry_count"], 0)

    def test_acl_action_and_eval_model_l4_and_l7_decisions(self) -> None:
        action_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["FLOW"],
                "irule": """
when FLOW_INIT {
    ACL::action drop
    log local0. "action=[ACL::action]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            action_result = action_session.fire_event("FLOW_INIT", {"acl": {}})
            self.assertTrue(action_result["fired"])
            self.assertEqual(action_result["state"]["acl"]["action"], "drop")
            self.assertTrue(any("action=1" in entry for entry in action_result["logs"]))
        finally:
            action_session.close()

        eval_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": 'when CLIENT_ACCEPTED { log local0. "result=[ACL::eval -l7]" }',
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            l7_result = eval_session.fire_event(
                "CLIENT_ACCEPTED",
                {"acl": {"action": "drop", "l7_present": 1}},
            )
            self.assertEqual(l7_result["state"]["acl"]["evaluated"], "1")
            self.assertEqual(l7_result["state"]["acl"]["l7_aborted"], "1")
            self.assertEqual(l7_result["state"]["acl"]["applied_action"], "0")
            self.assertTrue(any("result=1" in entry for entry in l7_result["logs"]))

            l4_result = eval_session.fire_event(
                "CLIENT_ACCEPTED",
                {"acl": {"action": "allow-final", "l7_present": 0}},
            )
            self.assertEqual(l4_result["state"]["acl"]["l7_aborted"], "0")
            self.assertEqual(l4_result["state"]["acl"]["applied_action"], "4")
            self.assertTrue(any("result=0" in entry for entry in l4_result["logs"]))
        finally:
            eval_session.close()

        invalid_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["FLOW"], "irule": "when FLOW_INIT { ACL::eval }"},
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "not valid in FLOW_INIT"
            ):
                invalid_session.fire_event("FLOW_INIT")
        finally:
            invalid_session.close()

    def test_xlat_source_translation_listener_and_reservation_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": """
when SA_PICKED {
    log local0. "source=[XLAT::src_addr]:[XLAT::src_port] config=[XLAT::src_config] ranges=[XLAT::src_nat_valid_range]"
}
when SERVER_CONNECTED {
    set listener [XLAT::listen -hairpin -single-connection 30 {
        proto [IP::protocol]
        bind -ip 198.51.100.20 -port 4000
        server [IP::client_addr] 80
        allow 10.0.0.2 0
        inherit-vs /Common/app_vs
    }]
    set lifetime [XLAT::listen_lifetime $listener]
    set updated [XLAT::listen_lifetime $listener 45]
    set reservation [XLAT::src_endpoint_reservation create -pool /Common/snat 10.0.0.2 50000 TCP 120]
    set translation_address [lindex $reservation 0]
    set translation_port [lindex $reservation 1]
    set found [XLAT::src_endpoint_reservation get $translation_address $translation_port /Common/snat TCP]
    set renewed [XLAT::src_endpoint_reservation update_lifetime $translation_address $translation_port /Common/snat TCP 300]
    log local0. "listener=$listener lifetime=$lifetime/$updated reservation=$reservation found=$found renewed=$renewed"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            picked = session.fire_event(
                "SA_PICKED",
                {
                    "xlat": {
                        "src_addr": "198.51.100.30",
                        "src_port": 41000,
                        "src_config": "SNAT /Common/snat",
                        "src_nat_valid_range": "{198.51.100.30 40000 45000}",
                    }
                },
            )
            self.assertTrue(picked["fired"])
            self.assertTrue(any(
                "source=198.51.100.30:41000 config=SNAT /Common/snat ranges={198.51.100.30 40000 45000}" in entry
                for entry in picked["logs"]
            ))

            connected = session.fire_event("SERVER_CONNECTED", {"xlat": {}})
            self.assertTrue(connected["fired"])
            xlat_state = connected["state"]["xlat"]
            self.assertIn("198.51.100.20%0,4000", xlat_state["listeners"])
            self.assertIn("lifetime 45", xlat_state["listeners"])
            self.assertIn("translation_addr 198.51.100.30", xlat_state["reservations"])
            self.assertIn("lifetime 300", xlat_state["reservations"])
            self.assertTrue(any(
                "lifetime=30/45 reservation=198.51.100.30 41000" in entry
                and "found=10.0.0.2 50000 120" in entry
                and "renewed=300" in entry
                for entry in connected["logs"]
            ))
        finally:
            session.close()

    def test_pcp_request_response_fields_and_rejection(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["PCP"],
                "irule": """
when PCP_REQUEST {
    PCP::reject 7
    log local0. "request=[PCP::request version]/[PCP::request opcode]/[PCP::request lifetime] proto=[PCP::request protocol] port=[PCP::request internal-port] prefer=[PCP::request prefer-failure] client=[PCP::request client-addr] third=[PCP::request third-party]/[PCP::request third-party-int-addr] suggested=[PCP::request suggested-ext-port]/[PCP::request suggested-ext-addr]"
}
when PCP_RESPONSE {
    log local0. "response=[PCP::response version]/[PCP::response opcode]/[PCP::response lifetime] proto=[PCP::response protocol] port=[PCP::response internal-port] result=[PCP::response result] assigned=[PCP::response assigned-ext-port]/[PCP::response assigned-ext-addr]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            request = session.fire_event(
                "PCP_REQUEST",
                {
                    "pcp": {
                        "version": 2,
                        "opcode": "map",
                        "lifetime": 3600,
                        "protocol": "tcp",
                        "internal_port": 22,
                        "prefer_failure": True,
                        "client_addr": "192.0.2.10",
                        "third_party": True,
                        "third_party_int_addr": "192.0.2.11",
                        "suggested_ext_port": 40000,
                        "suggested_ext_addr": "198.51.100.10",
                    }
                },
            )
            self.assertTrue(request["fired"])
            self.assertEqual(request["state"]["pcp"]["rejected"], "1")
            self.assertEqual(request["state"]["pcp"]["reject_result"], "7")
            self.assertTrue(any(
                "request=2/map/3600 proto=tcp port=22 prefer=2 client=192.0.2.10"
                " third=1/192.0.2.11 suggested=40000/198.51.100.10" in entry
                for entry in request["logs"]
            ))

            response = session.fire_event(
                "PCP_RESPONSE",
                {
                    "pcp": {
                        "version": 2,
                        "opcode": "map",
                        "lifetime": 1800,
                        "protocol": "udp",
                        "internal_port": 5353,
                        "client_addr": "192.0.2.10",
                        "result": 2,
                        "assigned_ext_port": 45000,
                        "assigned_ext_addr": "198.51.100.20",
                    }
                },
            )
            self.assertTrue(response["fired"])
            self.assertEqual(response["state"]["pcp"]["result"], "2")
            self.assertEqual(response["state"]["pcp"]["assigned_ext_port"], "45000")
            self.assertTrue(any(
                "response=2/map/1800 proto=udp port=5353 result=2 assigned=45000/198.51.100.20" in entry
                for entry in response["logs"]
            ))
        finally:
            session.close()

    def test_pcp_packet_adapter_dispatches_request_and_response(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["PCP"],
                "irule": """
when PCP_REQUEST {
    PCP::reject 7
    log local0. "request=[PCP::request opcode]/[PCP::request client-addr]/[PCP::request internal-port]"
}
when PCP_RESPONSE {
    log local0. "response=[PCP::response opcode]/[PCP::response result]/[PCP::response assigned-ext-port]"
}
""",
                "packets": [
                    {
                        "protocol": "pcp",
                        "direction": "client_to_server",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "192.0.2.20", "port": 5351},
                        "pcp": {
                            "version": 2,
                            "opcode": "map",
                            "lifetime": 3600,
                            "protocol": "tcp",
                            "internal_port": 22,
                            "prefer_failure": True,
                            "client_addr": "192.0.2.10",
                            "suggested_ext_port": 40000,
                            "suggested_ext_addr": "0.0.0.0",
                        },
                    },
                    {
                        "protocol": "pcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.20", "port": 5351},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "pcp": {
                            "version": 2,
                            "opcode": "map",
                            "lifetime": 1800,
                            "protocol": "tcp",
                            "internal_port": 22,
                            "client_addr": "192.0.2.10",
                            "result": 0,
                            "assigned_ext_port": 40000,
                            "assigned_ext_addr": "198.51.100.20",
                        },
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request, response = result["trace"]
        request_events = [event for event in request["events"] if event["event"] == "PCP_REQUEST"]
        response_events = [event for event in response["events"] if event["event"] == "PCP_RESPONSE"]
        self.assertEqual(len(request_events), 1)
        self.assertEqual(len(response_events), 1)
        self.assertTrue(request["rejected"])
        self.assertEqual(request["reject_result"], 7)
        self.assertEqual(request_events[0]["state"]["pcp"]["rejected"], "1")
        self.assertEqual(response_events[0]["state"]["pcp"]["rejected"], "0")
        self.assertTrue(any(
            "request=map/192.0.2.10/22" in entry for entry in request_events[0]["logs"]
        ))
        self.assertTrue(any(
            "response=map/0/40000" in entry for entry in response_events[0]["logs"]
        ))

    def test_pcp_packet_adapter_validates_directional_fields_and_addresses(self) -> None:
        base = {
            "profiles": ["PCP"],
            "irule": "when PCP_REQUEST { log local0. ok }",
            "packets": [
                {
                    "protocol": "pcp",
                    "direction": "client_to_server",
                    "pcp": {},
                }
            ],
        }
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet 0 pcp.third_party_int_addr must be a valid IPv4 or IPv6 address",
        ):
            invalid_address = json.loads(json.dumps(base))
            invalid_address["packets"][0]["pcp"] = {"third_party_int_addr": "not-an-ip"}
            self.adapter.run_scenario(invalid_address, tcl_lsp_root=self.tcl_lsp_root)

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            r"packet 0 pcp unsupported field\(s\): prefer_failure",
        ):
            response_field = json.loads(json.dumps(base))
            response_field["packets"][0].update(
                {
                    "direction": "server_to_client",
                    "pcp": {"prefer_failure": True},
                }
            )
            self.adapter.run_scenario(response_field, tcl_lsp_root=self.tcl_lsp_root)

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet 0 PCP packets require a pcp object",
        ):
            missing_object = json.loads(json.dumps(base))
            del missing_object["packets"][0]["pcp"]
            self.adapter.run_scenario(missing_object, tcl_lsp_root=self.tcl_lsp_root)

    def test_pcp_raw_ipv4_udp_packets_reach_the_same_event_adapter(self) -> None:
        request_payload = _pcp_map_request(
            third_party_addr="192.0.2.11",
            prefer_failure=True,
        )
        response_payload = _pcp_map_response()
        result = self.adapter.run_scenario(
            {
                "profiles": ["PCP"],
                "irule": """
when PCP_REQUEST {
    log local0. "raw-request=[PCP::request opcode]/[PCP::request protocol]/[PCP::request internal-port]/[PCP::request prefer-failure]/[PCP::request third-party-int-addr]"
}
when PCP_RESPONSE {
    log local0. "raw-response=[PCP::response opcode]/[PCP::response result]/[PCP::response assigned-ext-port]/[PCP::response assigned-ext-addr]"
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.10", "192.0.2.20", 40000, 5351, request_payload
                        ),
                    },
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.20", "192.0.2.10", 5351, 40000, response_payload
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request, response = result["trace"]
        self.assertEqual(request["protocol"], "pcp")
        self.assertEqual(response["protocol"], "pcp")
        self.assertEqual(request["pcp"]["client_addr"], "192.0.2.10")
        self.assertEqual(request["pcp"]["third_party_int_addr"], "192.0.2.11")
        self.assertEqual(response["pcp"]["assigned_ext_addr"], "198.51.100.20")
        self.assertEqual(request["payload_hex"], request_payload.hex())
        self.assertEqual(response["message_hex"], response_payload.hex())
        request_event = next(event for event in request["events"] if event["event"] == "PCP_REQUEST")
        response_event = next(event for event in response["events"] if event["event"] == "PCP_RESPONSE")
        self.assertTrue(any(
            "raw-request=map/tcp/22/2/192.0.2.11" in entry
            for entry in request_event["logs"]
        ))
        self.assertTrue(any(
            "raw-response=map/0/40000/198.51.100.20" in entry
            for entry in response_event["logs"]
        ))

    def test_pcp_raw_ipv4_udp_rejects_truncated_message(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "wire packet 0 PCP header is truncated",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["PCP"],
                    "irule": "when PCP_REQUEST { log local0. request }",
                    "packets": [
                        {
                            "protocol": "wire",
                            "network": "ipv4",
                            "direction": "client_to_server",
                            "raw_hex": _raw_ipv4_udp_hex(
                                "192.0.2.10", "192.0.2.20", 40000, 5351, b"\x02\x01"
                            ),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "wire packet 0 PCP header is truncated",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["PCP"],
                    "irule": "when PCP_REQUEST { log local0. request }",
                    "packets": [
                        {
                            "protocol": "wire",
                            "network": "ipv4",
                            "direction": "client_to_server",
                            "raw_hex": _raw_ipv4_udp_hex(
                                "192.0.2.10", "192.0.2.20", 40000, 5351, b""
                            ),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_pcp_raw_ipv4_udp_rejects_truncated_option(self) -> None:
        malformed = _pcp_map_request() + b"\x01\x00\x00\x10" + b"\x00" * 8
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "wire packet 0 PCP option exceeds the datagram",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["PCP"],
                    "irule": "when PCP_REQUEST { log local0. request }",
                    "packets": [
                        {
                            "protocol": "wire",
                            "network": "ipv4",
                            "direction": "client_to_server",
                            "raw_hex": _raw_ipv4_udp_hex(
                                "192.0.2.10", "192.0.2.20", 40000, 5351, malformed
                            ),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_pcp_raw_pcap_replay_uses_the_wire_decoder(self) -> None:
        payload = _pcp_map_request()
        capture = _pcap_bytes([
            (
                7,
                11,
                _ethernet_ipv4(
                    _raw_ipv4_udp_hex(
                        "192.0.2.10", "192.0.2.20", 40000, 5351, payload
                    )
                ),
            )
        ])
        result = self.adapter.run_pcap_scenario(
            {
                "profiles": ["PCP"],
                "irule": "when PCP_REQUEST { log local0. pcp-pcap }",
            },
            capture,
            tcl_lsp_root=self.tcl_lsp_root,
            direction="client_to_server",
        )
        self.assertEqual(result["capture"]["record_count"], 1)
        self.assertEqual(result["trace"][0]["protocol"], "pcp")
        self.assertEqual(
            next(event for event in result["trace"][0]["events"] if event["event"] == "PCP_REQUEST")["event"],
            "PCP_REQUEST",
        )

    def test_pcp_raw_wire_supports_peer_and_announce_opcodes(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["PCP"],
                "irule": """
when PCP_REQUEST {
    log local0. "opcode=[PCP::request opcode] protocol=[PCP::request protocol] port=[PCP::request internal-port]"
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.10", "192.0.2.20", 40000, 5351, _pcp_peer_request()
                        ),
                    },
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.10", "192.0.2.20", 40000, 5351,
                            bytes([2, 0, 0, 0]) + b"\x00" * 4 + _pcp_address_bytes("192.0.2.10"),
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        peer, announce = result["trace"]
        self.assertEqual(peer["pcp"]["opcode"], "peer")
        self.assertEqual(announce["pcp"]["opcode"], "announce")
        peer_event = next(event for event in peer["events"] if event["event"] == "PCP_REQUEST")
        announce_event = next(event for event in announce["events"] if event["event"] == "PCP_REQUEST")
        self.assertTrue(any("opcode=peer protocol=NA port=NA" in entry for entry in peer_event["logs"]))
        self.assertTrue(any("opcode=announce protocol=NA port=NA" in entry for entry in announce_event["logs"]))

    def test_psc_subscriber_identity_policy_address_and_attribute_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["PSC"],
                "irule": """
when CLIENT_ACCEPTED {
    PSC::subscriber_id 310150123456789
    PSC::calling_id +15551212
    PSC::imeisv 356789012345678
    PSC::imsi 310150123456789
    PSC::tower_id tower-a
    PSC::user_name alice
    PSC::aaa_reporting_interval 600
    PSC::ip_address 192.0.2.10 2001:db8::10%10
    PSC::ip_address add 192.0.2.11
    PSC::policy /Common/data /Common/voice
    PSC::policy add /Common/video
    PSC::attr plan premium
    PSC::attr region east
    PSC::lease_time 192.0.2.10 3600
    log local0. "id=[PSC::subscriber_id] calling=[PSC::calling_id] imsi=[PSC::imsi] user=[PSC::user_name] interval=[PSC::aaa_reporting_interval] ips=[PSC::ip_address] policies=[PSC::policy] plan=[PSC::attr plan] lease=[PSC::lease_time 192.0.2.10]"
    PSC::attr remove region
    PSC::policy remove /Common/voice
    PSC::ip_address remove 192.0.2.11
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED", {"psc": {}})
            self.assertTrue(result["fired"])
            psc_state = result["state"]["psc"]
            self.assertEqual(psc_state["subscriber_id"], "310150123456789")
            self.assertEqual(psc_state["aaa_reporting_interval"], "600")
            self.assertIn("192.0.2.10", psc_state["ip_addresses"])
            self.assertIn("2001:db8::10%10", psc_state["ip_addresses"])
            self.assertEqual(psc_state["policies"], "/Common/data /Common/video")
            self.assertEqual(psc_state["attrs"], "plan premium")
            self.assertEqual(psc_state["lease_times"], "192.0.2.10 3600")
            self.assertTrue(any(
                "id=310150123456789 calling=+15551212 imsi=310150123456789 user=alice interval=600"
                " ips=192.0.2.10 2001:db8::10%10 192.0.2.11"
                " policies=/Common/data /Common/voice /Common/video plan=premium lease=3600" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

    def test_psc_state_limits_and_injected_address_validation(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "event PSC state exceeds"):
            self.adapter._normalise_event(
                "CLIENT_ACCEPTED",
                {"psc": {"subscriber_id": "x" * (64 * 1024 + 1)}},
            )

        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["PSC"],
                "irule": "when CLIENT_ACCEPTED { log local0. \"ips=[PSC::ip_address]\" }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "PSC IPv4 address octets must be between 0 and 255",
            ):
                session.fire_event(
                    "CLIENT_ACCEPTED",
                    {"psc": {"ip_addresses": "999.0.0.1"}},
                )
        finally:
            session.close()

    def test_pem_flow_session_and_subscriber_database_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["PEM"],
                "irule": """
when CLIENT_ACCEPTED {
    PEM::disable
    PEM::flow transactional disable
    PEM::flow eval
    PEM::session create 192.0.2.30 subscriber-id 4086007577 subscriber-type e164 imsi 310150123456789 user-name alice tower-id tower-a provision yes plan premium policy {/Common/data /Common/voice}
    PEM::session info attr 192.0.2.30 region east
    PEM::session config policy referential update 192.0.2.30 add /Common/video delete /Common/voice
    set session_info "[PEM::session info 192.0.2.30 subscriber-id]/[PEM::session info 192.0.2.30 state]/[PEM::session info attr 192.0.2.30 region]/[PEM::session config policy get 192.0.2.30]/[PEM::session ip 4086007577 e164]"
    PEM::subscriber create 310150999 subscriber-type imsi ip-address 198.51.100.30 ip-address 2001:db8::30 imsi 310150999 user-name bob policy {/Common/mobile /Common/data}
    PEM::subscriber info attr 310150999 imsi tier gold
    PEM::subscriber config policy referential update 310150999 imsi add /Common/premium delete /Common/data
    set subscriber_info "[PEM::subscriber info 310150999 imsi user-name]/[PEM::subscriber info attr 310150999 imsi tier]/[PEM::subscriber config policy get 310150999 imsi]/[PEM::subscriber ip 310150999 imsi all]"
    PEM::enable
    log local0. "session=$session_info subscriber=$subscriber_info flow=[set ::state::pem::flow_enabled]/[set ::state::pem::transactional_enabled]/[set ::state::pem::eval_count]"
}
when PEM_SUBS_SESS_CREATED { log local0. "pem-event=[set ::state::pem::action]" }
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED", {"pem": {}})
            self.assertTrue(result["fired"])
            pem_state = result["state"]["pem"]
            self.assertEqual(pem_state["flow_enabled"], "1")
            self.assertEqual(pem_state["transactional_enabled"], "0")
            self.assertEqual(pem_state["eval_count"], "1")
            self.assertEqual(pem_state["subscriber_id"], "310150999")
            self.assertEqual(pem_state["subscriber_type"], "imsi")
            self.assertEqual(pem_state["ip_addresses"], "198.51.100.30 2001:db8::30")
            self.assertEqual(pem_state["policies"], "/Common/mobile /Common/premium")
            self.assertEqual(pem_state["attrs"], "tier gold")
            self.assertTrue(any(
                "session=4086007577/provisioned/east//Common/data /Common/video/192.0.2.30"
                " subscriber=bob/gold//Common/mobile /Common/premium/198.51.100.30 2001:db8::30"
                " flow=1/0/1" in entry
                for entry in result["logs"]
            ))
            event_result = session.fire_event(
                "PEM_SUBS_SESS_CREATED",
                {
                    "pem": {
                        "session_ip": "192.0.2.30",
                        "subscriber_id": "4086007577",
                        "subscriber_type": "e164",
                        "action": "created",
                    }
                },
            )
            self.assertTrue(event_result["fired"])
            self.assertEqual(event_result["state"]["pem"]["action"], "created")
        finally:
            session.close()

    def test_connector_controls_profile_and_remap_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["CONNECTOR"],
                "irule": """
when CONNECTOR_OPEN {
    set profile [CONNECTOR::profile]
    CONNECTOR::disable
    CONNECTOR::remap client_addr 192.0.2.40
    CONNECTOR::remap client_port 44000
    CONNECTOR::remap server_addr 198.51.100.40
    CONNECTOR::remap server_port 8443
    CONNECTOR::enable
    log local0. "profile=$profile enabled=[set ::state::connector::enabled] client=[set ::state::connector::client_addr]:[set ::state::connector::client_port] server=[set ::state::connector::server_addr]:[set ::state::connector::server_port]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "CONNECTOR_OPEN",
                {"connector": {"profile": "/Common/connector_profile_1"}},
            )
            self.assertTrue(result["fired"])
            connector_state = result["state"]["connector"]
            self.assertEqual(connector_state["profile"], "/Common/connector_profile_1")
            self.assertEqual(connector_state["enabled"], "1")
            self.assertEqual(connector_state["client_addr"], "192.0.2.40")
            self.assertEqual(connector_state["client_port"], "44000")
            self.assertEqual(connector_state["server_addr"], "198.51.100.40")
            self.assertEqual(connector_state["server_port"], "8443")
            self.assertEqual(
                connector_state["remaps"],
                "{client_addr 192.0.2.40} {client_port 44000} "
                "{server_addr 198.51.100.40} {server_port 8443}",
            )
            self.assertTrue(any(
                "profile=/Common/connector_profile_1 enabled=1 client=192.0.2.40:44000"
                " server=198.51.100.40:8443" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

    def test_tmm_cmp_state_is_configurable(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when CLIENT_ACCEPTED {
    set cmp_values "[TMM::cmp_count]|[TMM::cmp_group]|[join [TMM::cmp_groups] ,]|[TMM::cmp_primary_group]|[TMM::cmp_unit]"
    log local0. "cmp=$cmp_values"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "CLIENT_ACCEPTED",
                {
                    "tmm": {
                        "cmp_count": 8,
                        "cmp_group": 2,
                        "cmp_groups": [0, 2],
                        "cmp_primary_group": 0,
                        "cmp_unit": 3,
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertEqual(
                result["state"]["tmm"],
                {
                    "cmp_count": "8",
                    "cmp_group": "2",
                    "cmp_groups": "0 2",
                    "cmp_primary_group": "0",
                    "cmp_unit": "3",
                },
            )
            self.assertTrue(any("cmp=8|2|0,2|0|3" in entry for entry in result["logs"]))
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "tmm.cmp_groups must be a non-empty array",
            ):
                session.fire_event("CLIENT_ACCEPTED", {"tmm": {"cmp_groups": []}})
        finally:
            session.close()

    def test_policy_queries_use_scenario_policy_matching_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when HTTP_REQUEST {
    set controls "[POLICY::controls]|[POLICY::controls compression]"
    set targets "[POLICY::targets]|[POLICY::targets log]"
    set names "[POLICY::names active]|[POLICY::names matched]|[POLICY::names unmatched]"
    set rules "[POLICY::rules /Common/edge_policy]|[POLICY::rules matched /Common/edge_policy]"
    log local0. "controls=$controls targets=$targets names=$names rules=$rules"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "HTTP_REQUEST",
                {
                    "policy": {
                        "controls": ["compression", "server-ssl"],
                        "targets": ["log", "http-uri"],
                        "active": ["/Common/edge_policy", "/Common/fallback"],
                        "matched": ["/Common/edge_policy"],
                        "unmatched": ["/Common/fallback"],
                        "rules": {
                            "/Common/edge_policy": ["/Common/allow_api", "/Common/route_pool"]
                        },
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertTrue(any(
                "controls=compression server-ssl|1 targets=log http-uri|1"
                " names=/Common/edge_policy /Common/fallback|/Common/edge_policy|/Common/fallback"
                " rules=/Common/allow_api /Common/route_pool|/Common/allow_api /Common/route_pool"
                in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

    def test_wam_and_vdi_plugin_controls_are_connection_scoped(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP", "FASTHTTP"],
                "irule": """
when HTTP_REQUEST {
    WAM::disable
    VDI::disable
    set disabled "[set ::state::wam::enabled]/[set ::state::vdi::enabled]"
    WAM::enable
    VDI::enable
    log local0. "disabled=$disabled enabled=[set ::state::wam::enabled]/[set ::state::vdi::enabled]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST", {"wam": {}, "vdi": {}})
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["wam"]["enabled"], "1")
            self.assertEqual(result["state"]["vdi"]["enabled"], "1")
            self.assertTrue(any("disabled=0/0 enabled=1/1" in entry for entry in result["logs"]))
        finally:
            session.close()

    def test_websso_request_controls_persist_through_request_data(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP", "ACCESS"],
                "irule": """
when HTTP_REQUEST {
    WEBSSO::disable
    WEBSSO::select /Common/owa_sso
    log local0. "request=[set ::state::websso::enabled]/[set ::state::websso::selected]"
}
when HTTP_REQUEST_DATA {
    log local0. "data=[set ::state::websso::enabled]/[set ::state::websso::selected]"
}
when ACCESS_ACL_ALLOWED {
    log local0. "acl=[set ::state::websso::enabled]/[set ::state::websso::selected]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            request = session.fire_event("HTTP_REQUEST", {"websso": {}})
            self.assertTrue(request["fired"])
            self.assertEqual(request["state"]["websso"]["enabled"], "0")
            self.assertEqual(request["state"]["websso"]["selected"], "/Common/owa_sso")
            self.assertTrue(any("request=0//Common/owa_sso" in entry for entry in request["logs"]))

            data = session.fire_event("HTTP_REQUEST_DATA", {"websso": {}})
            self.assertTrue(data["fired"])
            self.assertEqual(data["state"]["websso"]["enabled"], "0")
            self.assertEqual(data["state"]["websso"]["selected"], "/Common/owa_sso")
            self.assertTrue(any("data=0//Common/owa_sso" in entry for entry in data["logs"]))

            acl = session.fire_event("ACCESS_ACL_ALLOWED", {"websso": {}})
            self.assertTrue(acl["fired"])
            self.assertEqual(acl["state"]["websso"]["enabled"], "0")
            self.assertEqual(acl["state"]["websso"]["selected"], "/Common/owa_sso")
            self.assertTrue(any("acl=0//Common/owa_sso" in entry for entry in acl["logs"]))

            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {
                    "profiles": ["HTTP"],
                    "irule": "when CLIENT_ACCEPTED { WEBSSO::disable }",
                },
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "WEBSSO::disable is not valid in CLIENT_ACCEPTED",
                ):
                    invalid.fire_event("CLIENT_ACCEPTED", {"websso": {}})
            finally:
                invalid.close()
        finally:
            session.close()

    def test_tap_token_state_and_insight_submission(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TAP"],
                "irule": """
when TAP_REQUEST {
    set old_action [TAP::action]
    set old_score [TAP::score]
    set config [TAP::config fraud mode]
    set requested [TAP::insight_requested]
    set action_result [TAP::action block]
    set score_result [TAP::score 85]
    TAP::insight set device mobile signal suspicious
    set token [TAP::insight send login suspicious]
    log local0. "old=$old_action/$old_score config=$config requested=$requested updates=$action_result/$score_result token=$token"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "TAP_REQUEST",
                {
                    "tap": {
                        "action": "allow",
                        "score": 10,
                        "insight_requested": True,
                        "insight_token": "block",
                        "config": {"fraud": {"mode": "strict"}},
                        "insight": {"precondition": "present"},
                    }
                },
            )
            self.assertTrue(result["fired"])
            tap_state = result["state"]["tap"]
            self.assertEqual(tap_state["action"], "block")
            self.assertEqual(tap_state["score"], "85")
            self.assertEqual(tap_state["insight_requested"], "1")
            self.assertEqual(tap_state["insight_token"], "block")
            self.assertEqual(tap_state["insight"], "")
            self.assertTrue(any(
                "old=allow/10 config=strict requested=1 updates=allow/10 token=block" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

    def test_ha_status_reads_active_or_standby_scenario_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when CLIENT_ACCEPTED {
    log local0. "active=[HA::status active] standby=[HA::status standby]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            active = session.fire_event("CLIENT_ACCEPTED", {"ha": {"status": "active"}})
            self.assertTrue(active["fired"])
            self.assertEqual(active["state"]["ha"]["status"], "active")
            self.assertTrue(any("active=1 standby=0" in entry for entry in active["logs"]))

            standby = session.fire_event("CLIENT_ACCEPTED", {"ha": {"status": "standby"}})
            self.assertTrue(standby["fired"])
            self.assertEqual(standby["state"]["ha"]["status"], "standby")
            self.assertTrue(any("active=0 standby=1" in entry for entry in standby["logs"]))

            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"irule": "when CLIENT_ACCEPTED { HA::status unknown }"},
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "HA::status argument must be active or standby",
                ):
                    invalid.fire_event("CLIENT_ACCEPTED", {"ha": {"status": "active"}})
            finally:
                invalid.close()

            init_only = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"irule": "when RULE_INIT { HA::status active }"},
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "HA::status is not valid in RULE_INIT",
                ):
                    init_only.fire_event("RULE_INIT", {"ha": {"status": "active"}})
            finally:
                init_only.close()
        finally:
            session.close()

    def test_dslite_remote_addr_and_bigproto_reset_control(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when CLIENT_ACCEPTED {
    set remote [DSLITE::remote_addr]
    BIGPROTO::enable_fix_reset false
    log local0. "remote=$remote reset=[set ::state::bigproto::enable_fix_reset]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "CLIENT_ACCEPTED",
                {"connection": {"remote_addr": "192.0.2.55"}, "bigproto": {}},
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["connection"]["remote_addr"], "192.0.2.55")
            self.assertEqual(result["state"]["bigproto"]["enable_fix_reset"], "0")
            self.assertTrue(any("remote=192.0.2.55 reset=0" in entry for entry in result["logs"]))

            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "event state bigproto.enable_fix_reset must be a Tcl boolean",
            ):
                session.fire_event(
                    "CLIENT_ACCEPTED",
                    {"connection": {"remote_addr": "192.0.2.55"}, "bigproto": {"enable_fix_reset": "maybe"}},
                )

            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"irule": "when CLIENT_ACCEPTED { BIGPROTO::enable_fix_reset maybe }"},
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "BIGPROTO::enable_fix_reset requires a boolean",
                ):
                    invalid.fire_event("CLIENT_ACCEPTED", {"bigproto": {}})
            finally:
                invalid.close()
        finally:
            session.close()

    def test_bigtcp_release_flow_enters_passthrough_for_later_events(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when CLIENT_ACCEPTED {
    if {[set ::state::connection::client_port] eq "1000"} {
        BIGTCP::release_flow
    }
    log local0. "released=[set ::state::bigtcp::released]"
}
when CLIENT_DATA {
    log local0. "must-not-run"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            accepted = session.fire_event(
                "CLIENT_ACCEPTED",
                {"connection": {"client_port": 1000}, "bigtcp": {}},
            )
            self.assertTrue(accepted["fired"])
            self.assertEqual(accepted["state"]["bigtcp"]["released"], "1")
            self.assertTrue(any("released=1" in entry for entry in accepted["logs"]))

            data = session.fire_event(
                "CLIENT_DATA",
                {"connection": {"client_payload": "ignored"}, "bigtcp": {}},
            )
            self.assertFalse(data["fired"])
            self.assertEqual(data["reason"], "bigtcp_passthrough")
            self.assertEqual(data["logs"], [])

            next_accept = session.fire_event(
                "CLIENT_ACCEPTED",
                {"connection": {"client_port": 1001}, "bigtcp": {}},
            )
            self.assertEqual(next_accept["state"]["bigtcp"]["released"], "0")
            next_data = session.fire_event(
                "CLIENT_DATA",
                {"connection": {"client_payload": "new-flow"}, "bigtcp": {}},
            )
            self.assertTrue(next_data["fired"])
            self.assertTrue(any("must-not-run" in entry for entry in next_data["logs"]))

            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {
                    "profiles": ["FIX"],
                    "irule": "when FIX_MESSAGE { BIGTCP::release_flow }",
                },
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "BIGTCP::release_flow is not valid in FIX_MESSAGE",
                ):
                    invalid.fire_event("FIX_MESSAGE", {})
            finally:
                invalid.close()
        finally:
            session.close()

    def test_eca_commands_and_authentication_result_events(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP", "ECA"],
                "irule": """
when HTTP_REQUEST {
    ECA::enable
    ECA::select select_ntlm:/Common/exch_ntlm_auth_config
    log local0. "enabled=[set ::state::eca::enabled] selected=[set ::state::eca::selected]"
}
when ECA_REQUEST_ALLOWED {
    log local0. "allowed=[ECA::username]@[ECA::domainname] machine=[ECA::client_machine_name] status=[ECA::status]"
}
when ECA_REQUEST_DENIED {
    log local0. "denied=[ECA::username] status=[ECA::status]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            configured = session.fire_event("HTTP_REQUEST", {"eca": {}})
            self.assertEqual(configured["state"]["eca"]["enabled"], "1")
            self.assertEqual(
                configured["state"]["eca"]["selected"],
                "select_ntlm:/Common/exch_ntlm_auth_config",
            )
            self.assertTrue(any("enabled=1" in entry for entry in configured["logs"]))

            allowed = session.fire_event(
                "ECA_REQUEST_ALLOWED",
                {
                    "eca": {
                        "username": "alice",
                        "domainname": "EXAMPLE",
                        "client_machine_name": "WKST-01",
                        "status": "NTLM_STATUS_OK",
                    }
                },
            )
            self.assertTrue(allowed["fired"])
            self.assertTrue(any("allowed=alice@EXAMPLE" in entry for entry in allowed["logs"]))

            denied = session.fire_event(
                "ECA_REQUEST_DENIED",
                {"eca": {"username": "mallory", "status": "NTLM_STATUS_WRONG_PASSWORD"}},
            )
            self.assertTrue(denied["fired"])
            self.assertTrue(any("denied=mallory" in entry for entry in denied["logs"]))

            reset = session.fire_event("CLIENT_ACCEPTED", {"eca": {}})
            self.assertEqual(reset["state"]["eca"]["enabled"], "0")
            self.assertEqual(reset["state"]["eca"]["selected"], "")
        finally:
            session.close()

    def test_eca_ntlm_packet_adapter_emits_authentication_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "ECA"],
                "irule": """
when ECA_REQUEST_ALLOWED { log local0. "allowed=[ECA::username] status=[ECA::status]" }
when ECA_REQUEST_DENIED { log local0. "denied=[ECA::username] status=[ECA::status]" }
""",
                "packets": [
                    {
                        "protocol": "ntlm",
                        "payload_hex": "4e544c4d",
                        "eca_result": "allowed",
                        "eca": {
                            "enabled": True,
                            "username": "alice",
                            "status": "NTLM_STATUS_OK",
                        },
                    },
                    {
                        "protocol": "ntlm",
                        "payload": "auth",
                        "eca_result": "denied",
                        "eca": {
                            "enabled": True,
                            "username": "mallory",
                            "status": "NTLM_STATUS_WRONG_PASSWORD",
                        },
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_event = next(
            event for event in result["trace"][0]["events"] if event["event"] == "ECA_REQUEST_ALLOWED"
        )
        second_event = next(
            event for event in result["trace"][1]["events"] if event["event"] == "ECA_REQUEST_DENIED"
        )
        self.assertTrue(any("allowed=alice" in entry for entry in first_event["logs"]))
        self.assertTrue(any("denied=mallory" in entry for entry in second_event["logs"]))
        self.assertEqual(result["trace"][0]["eca_result"], "allowed")
        self.assertEqual(result["trace"][1]["eca_result"], "denied")

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "eca_result must be client_to_server",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "ECA"],
                    "irule": "when ECA_REQUEST_ALLOWED { log local0. allowed }",
                    "packets": [
                        {
                            "protocol": "ntlm",
                            "direction": "server_to_client",
                            "payload": "response",
                            "eca_result": "allowed",
                            "eca": {"enabled": "true"},
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_avr_connection_and_cspm_controls(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP", "AVR"],
                "irule": """
when CLIENT_ACCEPTED {
    AVR::disable
    AVR::enable
    AVR::log
}
when AVR_CSPM_INJECTION {
    AVR::disable_cspm_injection
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            accepted = session.fire_event("CLIENT_ACCEPTED", {"avr": {}})
            self.assertEqual(accepted["state"]["avr"]["enabled"], "1")
            self.assertEqual(accepted["state"]["avr"]["log_requested"], "1")

            injection = session.fire_event("AVR_CSPM_INJECTION", {"avr": {}})
            self.assertTrue(injection["fired"])
            self.assertEqual(
                injection["state"]["avr"]["cspm_injection_enabled"], "0"
            )

            reset = session.fire_event("CLIENT_ACCEPTED", {"avr": {}})
            self.assertEqual(reset["state"]["avr"]["enabled"], "1")
            self.assertEqual(
                reset["state"]["avr"]["cspm_injection_enabled"], "1"
            )
        finally:
            session.close()

    def test_avr_cspm_injection_fixture_emits_response_hook(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "AVR"],
                "avr": {"cspm_injection": True},
                "irule": (
                    "when HTTP_RESPONSE { log local0. origin-response }\n"
                    "when AVR_CSPM_INJECTION { "
                    "HTTP::header insert X-CSPM-Disabled yes; "
                    "AVR::disable_cspm_injection; "
                    "log local0. \"cspm=[HTTP::header X-CSPM-Disabled]\" }"
                ),
                "request": {
                    "uri": "/analytics",
                    "response_body": "origin-body",
                    "response_headers": {"X-Origin": "yes"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            item["events_fired"],
            ["HTTP_RESPONSE", "AVR_CSPM_INJECTION"],
        )
        self.assertEqual(item["response"]["headers"]["x-cspm-disabled"], "yes")
        self.assertEqual(item["response"]["body"], "origin-body")
        self.assertEqual(item["semantic"]["avr"]["cspm_injection_enabled"], False)
        self.assertTrue(any("cspm=yes" in log for log in item["logs"]))

    def test_avr_cspm_injection_fixture_defaults_to_disabled(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "AVR"],
                "irule": "when AVR_CSPM_INJECTION { log local0. should-not-run }",
                "request": {"uri": "/analytics"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertNotIn("AVR_CSPM_INJECTION", item["events_fired"])
        self.assertFalse(any("should-not-run" in log for log in item["logs"]))

    def test_avr_cspm_injection_fixture_validation_rejects_non_boolean_values(self) -> None:
        for invalid_avr in (
            True,
            {"cspm_injection": 1},
            {"cspm_injection": "true"},
            {"unexpected": True},
        ):
            with self.subTest(invalid_avr=invalid_avr):
                with self.assertRaises(self.adapter.EmulatorInputError):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP", "AVR"],
                            "avr": invalid_avr,
                            "irule": "when HTTP_RESPONSE { log local0. ok }",
                            "request": {"uri": "/analytics"},
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

    def test_xml_content_based_routing_exposes_profile_match_arrays(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "XML"],
                "irule": """
when XML_CONTENT_BASED_ROUTING {
    log local0. "count=$XML_count first=$XML_queries(0)=$XML_values(0) second=$XML_queries(1)=$XML_values(1)"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "XML_CONTENT_BASED_ROUTING",
                {
                    "xml": {
                        "count": 2,
                        "queries": ["FinanceObject", "Amount"],
                        "values": ["Invoice", 42],
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["xml"], {
                "count": "2",
                "queries": '"FinanceObject" "Amount"',
                "values": '"Invoice" "42"',
            })
            self.assertTrue(any(
                "count=2 first=FinanceObject=Invoice second=Amount=42" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

    def test_xml_content_based_routing_rejects_mismatched_fixture_lengths(self) -> None:
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "XML"],
                    "irule": "when XML_CONTENT_BASED_ROUTING { log local0. unexpected }",
                    "packets": [{
                        "protocol": "event",
                        "event": "XML_CONTENT_BASED_ROUTING",
                        "state": {
                            "xml": {
                                "count": 2,
                                "queries": ["only-one"],
                                "values": ["one", "two"],
                            }
                        },
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_fix_tag_message_lookup_and_persistent_sender_mapping(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["FIX"],
                "irule": """
when RULE_INIT {
    set mapped [FIX::tag map set client1 /Common/fix_tag_map]
}
when FIX_MESSAGE {
    set sender [FIX::tag get 49]
    set msg_type [FIX::tag get 35]
    set missing [FIX::tag get 999]
    log local0. "sender=$sender type=$msg_type missing=$missing"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            init_result = session.fire_event("RULE_INIT")
            self.assertTrue(init_result["fired"])
            self.assertTrue(any("fix tag_map_set" in entry for entry in init_result["decisions"]))

            message = session.fire_event(
                "FIX_MESSAGE",
                {"fix": {"tags": {"49": "client1", "35": "A"}}},
            )
            self.assertTrue(message["fired"])
            self.assertEqual(message["state"]["fix"]["tags"], '"49" "client1" "35" "A"')
            self.assertEqual(
                message["state"]["fix"]["tag_maps"],
                "client1 /Common/fix_tag_map",
            )
            self.assertTrue(any("sender=client1 type=A missing=" in entry for entry in message["logs"]))

            empty_message = session.fire_event("FIX_MESSAGE", {"fix": {}})
            self.assertTrue(empty_message["fired"])
            self.assertTrue(any("sender= type= missing=" in entry for entry in empty_message["logs"]))

            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {
                    "profiles": ["FIX"],
                    "irule": "when CLIENT_ACCEPTED { FIX::tag get 49 }",
                },
                allow_irule_file=False,
                allow_requests=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    "FIX::tag get is only valid in FIX_HEADER or FIX_MESSAGE",
                ):
                    invalid.fire_event("CLIENT_ACCEPTED", {"fix": {}})
            finally:
                invalid.close()
        finally:
            session.close()

    def test_fix_packet_adapter_emits_header_then_message(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "FIX"],
                "irule": """
when FIX_HEADER {
    log local0. "header=[FIX::tag get 49]/[FIX::tag get 35]/[FIX::tag get 56]"
}
when FIX_MESSAGE {
    log local0. "message=[FIX::tag get 11]/[FIX::tag get 55]/[FIX::tag get 54]"
}
""",
                "packets": [
                    {
                        "protocol": "fix",
                        "direction": "client_to_server",
                        "fix": {
                            "tags": {
                                "8": "FIX.4.4",
                                "35": "D",
                                "49": "client1",
                                "56": "TARGET",
                                "11": "order-1",
                                "55": "AAPL",
                                "54": "1",
                            }
                        },
                        "payload": "8=FIX.4.4|35=D|49=client1|56=TARGET|11=order-1|55=AAPL|54=1|",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        packet_events = [
            event
            for event in result["trace"][0]["events"]
            if event["event"] in {"FIX_HEADER", "FIX_MESSAGE"}
        ]
        self.assertEqual(
            [event["event"] for event in packet_events],
            ["FIX_HEADER", "FIX_MESSAGE"],
        )
        self.assertTrue(all(event["fired"] for event in packet_events))
        self.assertTrue(
            any("header=client1/D/TARGET" in log for log in packet_events[0]["logs"])
        )
        self.assertTrue(
            any("message=order-1/AAPL/1" in log for log in packet_events[1]["logs"])
        )
        self.assertEqual(
            packet_events[1]["state"]["fix"]["tags"],
            '"8" "FIX.4.4" "35" "D" "49" "client1" "56" "TARGET" "11" "order-1" "55" "AAPL" "54" "1"',
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet 0 FIX packets require a fix tag object",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["FIX"],
                    "irule": "when FIX_MESSAGE { return }",
                    "packets": [{"protocol": "fix"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_lsn_translation_controls_and_mapping_lifecycle(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": """
when CLIENT_ACCEPTED {
    LSN::address 198.51.100.10
    LSN::port 45000
    LSN::pool /Common/lsn_pool
    LSN::persistence address-port 60
    LSN::inbound disable
    LSN::disable
    set persistence_created [LSN::persistence-entry create 10.0.0.1:50000 198.51.100.10:45000]
    set inbound_created [LSN::inbound-entry create /Common/lsn_pool 120 10.0.0.1:50000 198.51.100.10:45000 tcp]
    set persistence_found [LSN::persistence-entry get 10.0.0.1:50000]
    set inbound_found [LSN::inbound-entry get 198.51.100.10:45000 TCP]
    log local0. "address=198.51.100.10 port=45000 pool=/Common/lsn_pool mode=address-port p=$persistence_created/$persistence_found i=$inbound_created/$inbound_found"
    LSN::persistence-entry delete 10.0.0.1:50000
    LSN::inbound-entry delete 198.51.100.10:45000 udp
    set persistence_after [LSN::persistence-entry get 10.0.0.1:50000]
    set inbound_after [LSN::inbound-entry get 198.51.100.10:45000 TCP]
    LSN::inbound-entry delete 198.51.100.10:45000 tcp
    set inbound_deleted [LSN::inbound-entry get 198.51.100.10:45000 TCP]
    log local0. "after=$persistence_after/$inbound_after deleted=$inbound_deleted"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED", {"lsn": {}})
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["lsn"]["address"], "198.51.100.10")
            self.assertEqual(result["state"]["lsn"]["port"], "45000")
            self.assertEqual(result["state"]["lsn"]["pool"], "/Common/lsn_pool")
            self.assertEqual(result["state"]["lsn"]["disabled"], "1")
            self.assertEqual(result["state"]["lsn"]["inbound_disabled"], "1")
            self.assertEqual(result["state"]["lsn"]["persistence_mode"], "address-port")
            self.assertEqual(result["state"]["lsn"]["persistence_timeout"], "60")
            self.assertEqual(result["state"]["lsn"]["persistence_entries"], "")
            self.assertEqual(result["state"]["lsn"]["inbound_entries"], "")
            self.assertTrue(any(
                "p=198.51.100.10:45000/198.51.100.10:45000" in entry
                and "i=198.51.100.10:45000 0/10.0.0.1:50000 0" in entry
                for entry in result["logs"]
            ))
            self.assertTrue(any(
                "after=/10.0.0.1:50000 0 deleted=" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["FLOW"], "irule": "when FLOW_INIT { LSN::pool x }"},
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "not valid in FLOW_INIT"
            ):
                invalid.fire_event("FLOW_INIT")
        finally:
            invalid.close()

        invalid_endpoint = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "irule": (
                    "when CLIENT_ACCEPTED { "
                    "LSN::inbound-entry create pool 60 10.0.0.1:50000 "
                    "2001:db8::1:45000 tcp }"
                )
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                r"IPv6 endpoints with ports must use \[HOST\]:PORT",
            ):
                invalid_endpoint.fire_event("CLIENT_ACCEPTED")
        finally:
            invalid_endpoint.close()

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
        catalog = result["commands"] + self.adapter._build_capabilities(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 7, 1000
        )["commands"]
        json_entry = next(entry for entry in catalog if entry["name"] == "JSON::parse")
        self.assertEqual(json_entry["target_status"], "introduced-after-tmos-17.5")
        xml_entry = next(entry for entry in catalog if entry["name"] == "XML::payload")
        self.assertEqual(xml_entry["target_status"], "unavailable-in-tmos-17.5")
        self.assertEqual(
            result["summary"]["target_status_counts"]["introduced-after-tmos-17.5"],
            10,
        )
        self.assertEqual(
            result["summary"]["target_status_counts"]["unavailable-in-tmos-17.5"],
            12,
        )

        final = self.adapter._build_capabilities(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 5000, 7
        )
        self.assertEqual(final["chunk"]["count"], 0)
        self.assertFalse(final["chunk"]["has_more"])
        self.assertEqual(final["commands"], [])

        catalog = self.adapter._build_catalog(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 1000
        )
        self.assertEqual(catalog["chunking"], {"chunk_size": 1000, "chunk_count": 2})
        self.assertEqual(
            sum(chunk["count"] for chunk in catalog["chunks"]),
            catalog["summary"]["command_count"],
        )
        self.assertEqual(
            [chunk["offset"] for chunk in catalog["chunks"]], [0, 1000]
        )
        self.assertEqual(
            [chunk["count"] for chunk in catalog["chunks"]],
            [1000, catalog["summary"]["command_count"] - 1000],
        )
        self.assertEqual(
            catalog["chunks"][0]["commands"][-1]["name"] <
            catalog["chunks"][1]["commands"][0]["name"],
            True,
        )
        self.assertEqual(len(catalog["events"]), catalog["summary"]["event_count"])
        self.assertGreater(len(catalog["profiles"]), 0)

        offbox_catalog = self.adapter._build_catalog(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root), 1, namespace="OFFBOX"
        )
        self.assertEqual(offbox_catalog["chunking"]["chunk_count"], 1)
        self.assertEqual(
            [command["name"] for command in offbox_catalog["chunks"][0]["commands"]],
            ["OFFBOX::request"],
        )

    def test_capability_filters_produce_bounded_implementation_slices(self) -> None:
        root = self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        auth = self.adapter._build_capabilities(
            root, 0, 5, namespace="AUTH", runtime_status="semantic-mock"
        )
        self.assertEqual(auth["filter"], {
            "namespace": "AUTH",
            "runtime_status": "semantic-mock",
            "target_status": None,
        })
        self.assertEqual(auth["chunk"]["total"], 18)
        self.assertEqual(auth["summary"]["filtered_command_count"], 18)
        self.assertEqual(auth["chunk"]["count"], 5)
        self.assertTrue(auth["chunk"]["has_more"])
        self.assertTrue(all(entry["namespace"] == "AUTH" for entry in auth["commands"]))
        self.assertTrue(all(entry["runtime_status"] == "semantic-mock" for entry in auth["commands"]))
        self.assertEqual(auth["commands"][0]["documentation"]["synopsis"], ["AUTH::abort AUTH_ID"])
        self.assertIn("authentication", auth["commands"][0]["documentation"]["summary"])

        aaa = self.adapter._build_capabilities(
            root, 0, 10, namespace="AAA", runtime_status="semantic-mock"
        )
        self.assertEqual(aaa["chunk"]["total"], 4)
        self.assertEqual(
            {entry["name"] for entry in aaa["commands"]},
            {"AAA::acct_result", "AAA::acct_send", "AAA::auth_result", "AAA::auth_send"},
        )

        post_target = self.adapter._build_capabilities(
            root, 0, 100, target_status="introduced-after-tmos-17.5"
        )
        self.assertEqual(post_target["chunk"]["total"], 10)
        self.assertFalse(post_target["chunk"]["has_more"])
        self.assertTrue(all(
            entry["target_status"] == "introduced-after-tmos-17.5"
            for entry in post_target["commands"]
        ))

        empty = self.adapter._build_capabilities(
            root, 0, 10, namespace="AUTH", runtime_status="generated-stub"
        )
        self.assertEqual(empty["chunk"]["total"], 0)
        self.assertFalse(empty["chunk"]["has_more"])
        self.assertEqual(empty["commands"], [])

    def test_runtime_probe_reads_live_dispatch_registration(self) -> None:
        root = self.adapter._find_tcl_lsp_root(self.tcl_lsp_root)
        self.assertEqual(
            self.adapter._mock_proc_name("math::statistics::mean"),
            "math_mean",
        )

        result = self.adapter._build_runtime_probe(
            root, 0, 10, namespace="AAA", runtime_status="semantic-mock"
        )
        self.assertEqual(result["probe"]["method"], "::itest::_command_map")
        self.assertFalse(result["probe"]["executes_catalog_commands"])
        self.assertEqual(result["chunk"]["total"], 4)
        self.assertEqual(result["summary"]["probed_count"], 4)
        self.assertEqual(result["summary"]["registered_count"], 4)
        self.assertEqual(result["summary"]["unregistered_count"], 0)
        self.assertTrue(all(command["registered"] for command in result["commands"]))
        self.assertTrue(all(
            command["resolved_handler"].startswith("::itest::")
            for command in result["commands"]
        ))

        nested = self.adapter._build_runtime_probe(root, 0, 100, namespace="math")
        self.assertGreater(nested["summary"]["probed_count"], 0)
        self.assertTrue(all(command["registered"] for command in nested["commands"]))

        language = self.adapter._build_capabilities(root, 1000, 1000)
        when = next(command for command in language["commands"] if command["name"] == "when")
        self.assertEqual(when["catalog_kind"], "irule-language")

    def test_command_probe_executes_one_catalog_command_with_http_fixture(self) -> None:
        result = self.adapter.run_command_probe(
            {
                "command": "HTTP::header",
                "args": ["value", "X-Test"],
                "event": "HTTP_REQUEST",
                "profiles": ["TCP", "HTTP"],
                "request": {
                    "method": "GET",
                    "uri": "/probe",
                    "host": "api.example.com",
                    "headers": {"X-Test": "safe"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["catalog"]["catalog_kind"], "f5-irule")
        self.assertEqual(result["catalog"]["target_status"], "available-in-tmos-17.5")
        self.assertEqual(result["execution"]["status"], "ok")
        self.assertEqual(result["execution"]["value"], "safe")
        self.assertEqual(result["execution"]["value_bytes"], 4)
        self.assertEqual(result["execution"]["event"]["fired"], True)
        self.assertEqual(
            result["execution"]["event"]["result"]["request"]["uri"], "/probe"
        )

    def test_command_probe_quotes_arguments_and_reports_command_errors(self) -> None:
        result = self.adapter.run_command_probe(
            {
                "command": "HTTP::header",
                "args": ["value", "X-Test; set ::orch::injected 1"],
                "event": "HTTP_REQUEST",
                "request": {"headers": {"X-Test": "safe"}},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["execution"]["status"], "ok")
        self.assertEqual(result["execution"]["value"], "")
        self.assertNotIn("injected", result["execution"]["event"]["result"]["logs"])

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "F5 iRule"):
            self.adapter.run_command_probe(
                {"command": "set", "event": "HTTP_REQUEST"},
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "at most 64"):
            self.adapter.run_command_probe(
                {
                    "command": "HTTP::host",
                    "event": "HTTP_REQUEST",
                    "args": ["x"] * 65,
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "not valid"):
            self.adapter.run_command_probe(
                {"command": "HTTP::host", "event": "DNS_REQUEST"},
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_command_probe_reports_profile_gating_without_executing_command(self) -> None:
        result = self.adapter.run_command_probe(
            {
                "command": "DNS::name",
                "event": "DNS_REQUEST",
                "profiles": ["TCP"],
                "state": {"dns": {"qname": "example.com"}},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["execution"]["status"], "profile-gated")
        self.assertEqual(result["execution"]["event"]["reason"], "profile_gate")

    def test_behavior_pack_runs_catalog_contracts_and_reports_mismatches(self) -> None:
        pack = json.loads(
            (ROOT / "examples" / "behavior-packs" / "http-core-17.5.json")
            .read_text(encoding="utf-8")
        )
        result = self.adapter.run_behavior_pack(
            pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"], {"case_count": 9, "passed": 9, "failed": 0})
        self.assertTrue(all(case["status"] == "passed" for case in result["cases"]))

        pack["cases"][0]["expect"]["value"] = "wrong.example"
        failed = self.adapter.run_behavior_pack(
            pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["summary"]["failed"], 1)
        mismatch = failed["cases"][0]["mismatches"][0]
        self.assertEqual(mismatch["field"], "value")
        self.assertEqual(mismatch["actual"], "api.example.com")

    def test_golden_vectors_compare_independent_reference_observations(self) -> None:
        pack = json.loads(
            (ROOT / "examples" / "golden-vectors" / "http-17.5.json")
            .read_text(encoding="utf-8")
        )
        result = self.adapter.run_golden_vectors(
            pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            result["summary"], {"vector_count": 3, "passed": 3, "failed": 0}
        )
        self.assertEqual(
            result["analysis"],
            {
                "comparison_count": 10,
                "comparison_passed": 10,
                "comparison_failed": 0,
                "comparison_skipped": 0,
                "execution_error_count": 0,
                "execution_error_vector_ids": [],
                "mismatch_groups": [],
            },
        )
        self.assertTrue(all(vector["status"] == "passed" for vector in result["vectors"]))

        pack["vectors"][0]["reference"]["output"]["results"][0]["pool"] = "wrong_pool"
        failed = self.adapter.run_golden_vectors(
            pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["summary"], {"vector_count": 3, "passed": 2, "failed": 1})
        mismatch = failed["vectors"][0]["mismatches"][0]
        self.assertEqual(mismatch["label"], "selected pool")
        self.assertEqual(mismatch["expected"], "wrong_pool")
        self.assertEqual(mismatch["actual"], "api_pool")
        self.assertEqual(failed["analysis"]["comparison_failed"], 1)
        self.assertEqual(
            failed["analysis"]["mismatch_groups"],
            [{
                "operation": "scenario",
                "label": "selected pool",
                "mismatch_count": 1,
                "vector_ids": ["http-request-pool-selection"],
            }],
        )
        self.assertEqual(
            self.adapter._golden_report_value("x" * 65537)["truncated"], True
        )

        invalid_schema = json.loads(
            (ROOT / "examples" / "golden-vectors" / "http-17.5.json")
            .read_text(encoding="utf-8")
        )
        invalid_schema["schema_version"] = 1.0
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "schema_version"):
            self.adapter.run_golden_vectors(
                invalid_schema, tcl_lsp_root=self.tcl_lsp_root
            )

        strict_types = json.loads(
            (ROOT / "examples" / "golden-vectors" / "http-17.5.json")
            .read_text(encoding="utf-8")
        )
        strict_types["vectors"][1]["reference"]["output"]["execution"]["event"]["fired"] = 1
        strict_result = self.adapter.run_golden_vectors(
            strict_types, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(strict_result["status"], "failed")
        self.assertEqual(strict_result["summary"]["failed"], 1)

    def test_golden_vectors_replay_pcap_operation_and_validate_reference_paths(self) -> None:
        capture = _pcap_bytes([
            (5, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
            )))
        ])
        pack = {
            "name": "pcap-vector",
            "vectors": [{
                "id": "client-syn",
                "operation": "pcap",
                "input": {
                    "scenario": {
                        "profiles": ["TCP"],
                        "irule": "when CLIENT_ACCEPTED { log local0. pcap-vector }",
                    },
                    "pcap_base64": base64.b64encode(capture).decode("ascii"),
                },
                "reference": {
                    "source": "tmos-17.5-reference-contract",
                    "output": {
                        "capture": {"record_count": 1},
                        "trace": [{"protocol": "tcp"}],
                    },
                },
                "comparisons": [
                    {
                        "label": "capture records",
                        "actual_path": ["capture", "record_count"],
                        "reference_path": ["capture", "record_count"],
                    },
                    {
                        "label": "decoded protocol",
                        "actual_path": ["trace", 0, "protocol"],
                        "reference_path": ["trace", 0, "protocol"],
                    },
                ],
            }],
        }
        result = self.adapter.run_golden_vectors(
            pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["summary"]["passed"], 1)

        invalid = json.loads(json.dumps(pack))
        invalid["vectors"][0]["comparisons"][0]["reference_path"] = [
            "capture", "missing"
        ]
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "reference_path"):
            self.adapter.run_golden_vectors(
                invalid, tcl_lsp_root=self.tcl_lsp_root
            )

    def test_observation_import_normalises_external_pack_without_execution(self) -> None:
        observation_pack = {
            "schema_version": 1,
            "profile": "tmos-17.5",
            "name": "captured-http-observations",
            "source": "bigip-vlab-17.5.4",
            "provenance": {
                "collector": "tmsh-observe-v1",
                "build": "17.5.4",
                "capture_id": "capture-001",
            },
            "observations": [
                {
                    "id": "http-host",
                    "operation": "command_probe",
                    "input": {
                        "command": "HTTP::host",
                        "event": "HTTP_REQUEST",
                        "profiles": ["TCP", "HTTP"],
                        "request": {"host": "api.example.com", "uri": "/health"},
                    },
                    "output": {
                        "execution": {
                            "status": "ok",
                            "value": "api.example.com",
                        }
                    },
                    "comparisons": [
                        {
                            "label": "host",
                            "actual_path": ["execution", "value"],
                            "reference_path": ["execution", "value"],
                        }
                    ],
                }
            ],
        }
        imported = self.adapter.run_observation_import(
            observation_pack, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(imported["status"], "ok")
        self.assertEqual(imported["summary"]["executed"], False)
        canonical = imported["pack"]
        self.assertEqual(canonical["provenance"]["capture_id"], "capture-001")
        self.assertEqual(
            canonical["vectors"][0]["reference"]["source"], "bigip-vlab-17.5.4"
        )

        replay = self.adapter.run_golden_vectors(
            canonical, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(replay["status"], "passed")
        self.assertEqual(replay["pack"]["provenance"]["build"], "17.5.4")

        nested_provenance = dict(observation_pack)
        nested_provenance["provenance"] = {"tags": ["http"]}
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "must be a scalar"):
            self.adapter.run_observation_import(
                nested_provenance, tcl_lsp_root=self.tcl_lsp_root
            )

        wrong_profile = dict(observation_pack)
        wrong_profile["profile"] = "tmos-16.1"
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "profile"):
            self.adapter.run_observation_import(
                wrong_profile, tcl_lsp_root=self.tcl_lsp_root
            )

    def test_behavior_packs_cover_dns_tcp_lb_uri_sip_and_stateful_scenarios(self) -> None:
        expected_counts = {
            "dns-17.5.json": 7,
            "tcp-17.5.json": 6,
            "lb-17.5.json": 5,
            "uri-17.5.json": 8,
            "stateful-17.5.json": 2,
            "ssl-tls-17.5.json": 16,
            "udp-datagram-17.5.json": 15,
            "sip-17.5.json": 41,
        }
        for filename, case_count in expected_counts.items():
            with self.subTest(filename=filename):
                pack = json.loads(
                    (ROOT / "examples" / "behavior-packs" / filename).read_text(
                        encoding="utf-8"
                    )
                )
                result = self.adapter.run_behavior_pack(
                    pack, tcl_lsp_root=self.tcl_lsp_root
                )
                self.assertEqual(result["status"], "passed")
                self.assertEqual(
                    result["summary"],
                    {"case_count": case_count, "passed": case_count, "failed": 0},
                )
                if filename == "sip-17.5.json":
                    self.assertEqual(
                        {
                            case["probe"]["command"]
                            for case in pack["cases"]
                            if "probe" in case
                            and case["probe"]["command"].startswith("SIP::")
                        },
                        {
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
                        },
                    )
                    self.assertEqual(
                        {
                            case["probe"]["command"]
                            for case in pack["cases"]
                            if "probe" in case and case["probe"]["command"].startswith("SDP::")
                        },
                        {
                            "SDP::field",
                            "SDP::media",
                            "SDP::session_id",
                        },
                    )
                    self.assertEqual(
                        {
                            case["probe"]["command"]
                            for case in pack["cases"]
                            if "probe" in case and case["probe"]["command"].startswith("SIPALG::")
                        },
                        {
                            "SIPALG::hairpin",
                            "SIPALG::hairpin_default",
                            "SIPALG::nonregister_subscriber_listener",
                        },
                    )

        stateful = json.loads(
            (ROOT / "examples" / "behavior-packs" / "stateful-17.5.json").read_text(
                encoding="utf-8"
            )
        )
        stateful["cases"][1]["expect"]["assertions"][2]["equals"] = "wrong"
        failed = self.adapter.run_behavior_pack(
            stateful, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["summary"]["failed"], 1)
        self.assertEqual(
            failed["cases"][1]["mismatches"][0]["path"],
            ["results", 1, "semantic", "table", 0, "value"],
        )
        stateful["cases"][0]["expect"]["assertions"][0]["path"] = [
            "results", 99, "status"
        ]
        missing_path = self.adapter.run_behavior_pack(
            stateful, tcl_lsp_root=self.tcl_lsp_root
        )
        self.assertEqual(missing_path["status"], "failed")
        self.assertIn("path not found", missing_path["cases"][0]["mismatches"][0]["error"])

    def test_behavior_pack_validation_is_bounded_and_atomic(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "schema_version"):
            self.adapter.run_behavior_pack(
                {"schema_version": True, "cases": []},
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "duplicate case id"):
            self.adapter.run_behavior_pack(
                {
                    "name": "bad",
                    "cases": [
                        {"id": "same", "probe": {"command": "HTTP::host", "event": "HTTP_REQUEST"}, "expect": {"status": "ok"}},
                        {"id": "same", "probe": {"command": "HTTP::host", "event": "HTTP_REQUEST"}, "expect": {"status": "ok"}},
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "at most 256"):
            self.adapter.run_behavior_pack(
                {
                    "name": "too-many",
                    "cases": [
                        {"id": str(index), "probe": {"command": "HTTP::host", "event": "HTTP_REQUEST"}, "expect": {"status": "ok"}}
                        for index in range(257)
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "inline irule only"):
            self.adapter.run_behavior_pack(
                {
                    "name": "file-scenario",
                    "cases": [
                        {
                            "id": "file",
                            "scenario": {
                                "irule_file": "./missing.irule",
                                "profiles": ["TCP", "HTTP"],
                                "requests": [{"uri": "/"}],
                            },
                            "expect": {
                                "status": "ok",
                                "assertions": [
                                    {"path": ["status"], "equals": "ok"}
                                ],
                            },
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "exceeds 65536"):
            self.adapter.run_behavior_pack(
                {
                    "name": "large-assertion",
                    "cases": [
                        {
                            "id": "large",
                            "scenario": {
                                "irule": "when HTTP_REQUEST { log local0. ok }",
                                "profiles": ["TCP", "HTTP"],
                                "requests": [{"uri": "/"}],
                            },
                            "expect": {
                                "status": "ok",
                                "assertions": [
                                    {"path": ["status"], "equals": "x" * 65537}
                                ],
                            },
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "packets and requests"):
            self.adapter.run_behavior_pack(
                {
                    "name": "mixed-inputs",
                    "cases": [
                        {
                            "id": "mixed",
                            "scenario": {
                                "irule": "when HTTP_REQUEST { log local0. ok }",
                                "profiles": ["TCP", "HTTP"],
                                "requests": [{"uri": "/"}],
                                "packets": [
                                    {
                                        "protocol": "event",
                                        "event": "CLIENT_ACCEPTED",
                                    }
                                ],
                            },
                            "expect": {
                                "status": "ok",
                                "assertions": [
                                    {"path": ["status"], "equals": "ok"}
                                ],
                            },
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

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

    def test_validate_protocol_matches_bounded_common_signatures(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when CLIENT_ACCEPTED {
    set http [VALIDATE::protocol http {GET /health HTTP/1.1\r\nHost: example.test\r\n}]
    set response [VALIDATE::protocol http {HTTP/1.1 200 OK\r\n}]
    set tls [VALIDATE::protocol tls [binary format H* 1603010000]]
    set tls_app [VALIDATE::protocol tls [binary format H* 1703030000]]
    set ssh [VALIDATE::protocol ssh {SSH-2.0-OpenSSH_9.0\r\n}]
    set smtp [VALIDATE::protocol smtp {220 mail.example.test ESMTP\r\n}]
    set unknown [VALIDATE::protocol mysql {not mysql}]
    log local0. "http=$http response=$response tls=$tls tls_app=$tls_app ssh=$ssh smtp=$smtp unknown=$unknown"
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "http=1 response=1 tls=1 tls_app=1 ssh=1 smtp=1 unknown=0" in entry
            for entry in result["results"][0]["logs"]
        ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        self.assertEqual(usage["VALIDATE::protocol"]["runtime_status"], "semantic-mock")

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires an application and payload"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when CLIENT_ACCEPTED { VALIDATE::protocol http }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_l7check_protocol_is_connection_state_with_event_validation(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "L7CHECK", "CONNECTOR"],
                "irule": """
when L7CHECK_CLIENT_DATA {
    set before [L7CHECK::protocol get]
    set changed [L7CHECK::protocol set https]
    log local0. "before=$before changed=$changed after=[L7CHECK::protocol get]"
}
when L7CHECK_SERVER_DATA {
    log local0. "server=[L7CHECK::protocol get]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            client = session.fire_event(
                "L7CHECK_CLIENT_DATA", {"l7check": {"protocol": "http"}}
            )
            self.assertTrue(client["fired"])
            self.assertEqual(client["state"]["l7check"]["protocol"], "https")
            self.assertTrue(any(
                "before=http changed=https after=https" in entry
                for entry in client["logs"]
            ))

            server = session.fire_event("L7CHECK_SERVER_DATA")
            self.assertTrue(server["fired"])
            self.assertTrue(any("server=https" in entry for entry in server["logs"]))
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "L7CHECK", "CONNECTOR"],
                "irule": "when CLIENT_ACCEPTED { L7CHECK::protocol get }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "not valid in CLIENT_ACCEPTED"
            ):
                invalid.fire_event("CLIENT_ACCEPTED")
        finally:
            invalid.close()

    def test_link_commands_read_structured_event_link_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    log local0. "last=[LINK::lasthop]/[LINK::lasthop id]/[LINK::lasthop type]/[LINK::lasthop name] next=[LINK::nexthop]/[LINK::nexthop id]/[LINK::nexthop type]/[LINK::nexthop name] qos=[LINK::qos] vlan=[LINK::vlan_id]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "CLIENT_ACCEPTED",
                {
                    "link": {
                        "qos": 5,
                        "vlan_id": 4094,
                        "lasthop_mac": "aa:bb:cc:dd:ee:ff",
                        "lasthop_id": "last-1",
                        "lasthop_type": "router",
                        "lasthop_name": "edge-a",
                        "nexthop_mac": "11:22:33:44:55:66",
                        "nexthop_id": "next-1",
                        "nexthop_type": "router",
                        "nexthop_name": "core-a",
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["link"]["qos"], "5")
            self.assertEqual(result["state"]["link"]["vlan_id"], "4094")
            self.assertTrue(any(
                "last=aa:bb:cc:dd:ee:ff/last-1/router/edge-a" in entry
                and "next=11:22:33:44:55:66/next-1/router/core-a" in entry
                and "qos=5 vlan=4094" in entry
                for entry in result["logs"]
            ))

            default = session.fire_event("CLIENT_ACCEPTED")
            self.assertTrue(any(
                "next=ff:ff:ff:ff:ff:ff///" in entry
                and "qos=0 vlan=0" in entry
                for entry in default["logs"]
            ))
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { LINK::lasthop bogus }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "selector must be id, type, or name"
            ):
                invalid.fire_event("CLIENT_ACCEPTED")
        finally:
            invalid.close()

    def test_legacy_hop_commands_update_shared_link_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    lasthop external AA:BB:CC:DD:EE:FF
    nexthop external 2001:db8::10
    log local0. "last=[LINK::lasthop]/[LINK::lasthop type]/[LINK::lasthop name] next=[LINK::nexthop id]/[LINK::nexthop type]/[LINK::nexthop name]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED")
            link = result["semantic"]["link"]
            self.assertEqual(link["lasthop_mac"], "aa:bb:cc:dd:ee:ff")
            self.assertEqual(link["lasthop_type"], "mac")
            self.assertEqual(link["lasthop_name"], "external")
            self.assertEqual(link["nexthop_id"], "2001:db8::10")
            self.assertEqual(link["nexthop_type"], "ip")
            self.assertEqual(link["nexthop_name"], "external")
            self.assertTrue(any(
                "last=aa:bb:cc:dd:ee:ff/mac/external next=2001:db8::10/ip/external" in entry
                for entry in result["logs"]
            ))
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["lasthop"]["runtime_status"], "semantic-mock")
            self.assertEqual(usage["nexthop"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { lasthop transparent }",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "lasthop requires an IP or MAC address"
            ):
                invalid.fire_event("CLIENT_ACCEPTED")
        finally:
            invalid.close()

    def test_socks_commands_model_request_decision_and_destination(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "SOCKS"],
                "irule": """
when SOCKS_REQUEST {
    set before [SOCKS::destination]
    set before_host [SOCKS::destination host]
    set before_port [SOCKS::destination port]
    SOCKS::destination host internal.example
    SOCKS::destination port 8443
    SOCKS::allowed 0
    log local0. "version=[SOCKS::version] before=$before/$before_host/$before_port after=[SOCKS::destination] allowed=[SOCKS::allowed]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "SOCKS_REQUEST",
                {
                    "socks": {
                        "version": "5",
                        "allowed": 1,
                        "destination_host": "proxy.example",
                        "destination_port": 1080,
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["socks"]["allowed"], "0")
            self.assertEqual(result["state"]["socks"]["destination_host"], "internal.example")
            self.assertEqual(result["state"]["socks"]["destination_port"], "8443")
            self.assertTrue(any(
                "version=5 before=proxy.example:1080/proxy.example/1080 after=internal.example:8443 allowed=0" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "SOCKS"],
                "irule": "when CLIENT_ACCEPTED { SOCKS::version }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "not valid in CLIENT_ACCEPTED"
            ):
                invalid.fire_event("CLIENT_ACCEPTED")
        finally:
            invalid.close()

        malformed = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "SOCKS"],
                "irule": "when SOCKS_REQUEST { SOCKS::destination malformed }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                r"requires HOST:PORT or \[HOST\]:PORT",
            ):
                malformed.fire_event("SOCKS_REQUEST")
        finally:
            malformed.close()

    def test_socks_packet_adapter_decodes_socks5_domain_and_applies_decision(self) -> None:
        domain = b"blocked.example"
        payload = bytes([5, 1, 0, 3, len(domain)]) + domain + (443).to_bytes(2, "big")
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "SOCKS"],
                "irule": """
when SOCKS_REQUEST {
    log local0. "version=[SOCKS::version] destination=[SOCKS::destination]"
    if {[SOCKS::destination host] eq "blocked.example"} { SOCKS::allowed 0 }
}
""",
                "packets": [
                    {
                        "protocol": "socks",
                        "direction": "client_to_server",
                        "payload_hex": payload.hex(),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]
        event = next(item for item in entry["events"] if item["event"] == "SOCKS_REQUEST")
        accepted = next(item for item in entry["events"] if item["event"] == "CLIENT_ACCEPTED")
        self.assertTrue(event["fired"])
        self.assertEqual(accepted["state"]["datagram"]["protocol"], "6")
        self.assertIn("tcp", accepted["state"])
        self.assertEqual(event["state"]["socks"]["version"], "5")
        self.assertEqual(event["state"]["socks"]["destination_host"], "blocked.example")
        self.assertEqual(event["state"]["socks"]["destination_port"], "443")
        self.assertEqual(event["state"]["socks"]["allowed"], "0")
        self.assertTrue(any("version=5 destination=blocked.example:443" in log for log in event["logs"]))
        self.assertEqual(entry["socks"]["command"], "CONNECT")
        self.assertTrue(entry["discarded"])
        self.assertEqual(entry["drop_reason"], "socks")

        no_handler = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "SOCKS"],
                "irule": "when CLIENT_ACCEPTED { log local0. \"accepted\" }",
                "packets": [
                    {
                        "protocol": "socks",
                        "direction": "client_to_server",
                        "payload_hex": payload.hex(),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(no_handler["trace"][0]["socks"]["command"], "CONNECT")
        self.assertEqual(
            no_handler["trace"][0]["socks"]["destination_host"], "blocked.example"
        )
        self.assertEqual(no_handler["trace"][0]["socks"]["allowed"], "1")

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "SOCKS5 domain destination is incomplete"
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "SOCKS"],
                    "irule": "when SOCKS_REQUEST { SOCKS::version }",
                    "packets": [
                        {
                            "protocol": "socks",
                            "direction": "client_to_server",
                            "payload_hex": "0501000304",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "SOCKS request payload must not be empty"
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "SOCKS"],
                    "irule": "when SOCKS_REQUEST { SOCKS::version }",
                    "packets": [
                        {
                            "protocol": "socks",
                            "direction": "client_to_server",
                            "payload_hex": "",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "SOCKS requests must be client_to_server"
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "SOCKS"],
                    "irule": "when SOCKS_REQUEST { SOCKS::version }",
                    "packets": [
                        {
                            "protocol": "socks",
                            "direction": "server_to_client",
                            "payload_hex": payload.hex(),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_socks_packet_adapter_decodes_socks4_and_socks5_address_variants(self) -> None:
        def run_request(payload: bytes) -> dict[str, object]:
            result = self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "SOCKS"],
                    "irule": "when SOCKS_REQUEST { log local0. \"[SOCKS::version] [SOCKS::destination]\" }",
                    "packets": [
                        {
                            "protocol": "socks",
                            "direction": "client_to_server",
                            "payload_hex": payload.hex(),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
            entry = result["trace"][0]
            return next(
                item for item in entry["events"] if item["event"] == "SOCKS_REQUEST"
            )

        socks4 = bytes([4, 1]) + (80).to_bytes(2, "big") + bytes([192, 0, 2, 10]) + b"user\x00"
        socks4_event = run_request(socks4)
        self.assertEqual(socks4_event["state"]["socks"]["version"], "4")
        self.assertEqual(socks4_event["state"]["socks"]["destination_host"], "192.0.2.10")
        self.assertEqual(socks4_event["state"]["socks"]["destination_port"], "80")
        self.assertTrue(any("4 192.0.2.10:80" in log for log in socks4_event["logs"]))

        socks4a = (
            bytes([4, 1])
            + (443).to_bytes(2, "big")
            + bytes([0, 0, 0, 1])
            + b"user\x00socks4a.example\x00"
        )
        socks4a_event = run_request(socks4a)
        self.assertEqual(socks4a_event["state"]["socks"]["destination_host"], "socks4a.example")
        self.assertEqual(socks4a_event["state"]["socks"]["destination_port"], "443")

        ipv6 = ipaddress.ip_address("2001:db8::42").packed
        socks5_event = run_request(bytes([5, 1, 0, 4]) + ipv6 + (8443).to_bytes(2, "big"))
        self.assertEqual(socks5_event["state"]["socks"]["version"], "5")
        self.assertEqual(socks5_event["state"]["socks"]["destination_host"], "2001:db8::42")
        self.assertEqual(socks5_event["state"]["socks"]["destination_port"], "8443")

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
        coverage = report["coverage"]
        self.assertGreater(report["commands"]["target_f5_command_count"], 900)
        self.assertEqual(
            report["commands"]["target_catalog_kind_runtime_status_counts"]["f5-irule"]["generated-stub"],
            0,
        )
        self.assertGreater(
            report["coverage"]["support_command_behavior"]["placeholder_count"],
            400,
        )
        self.assertEqual(coverage["command_catalog"]["status"], "complete")
        self.assertEqual(
            coverage["command_catalog"]["target_count"],
            report["commands"]["target_catalog_count"],
        )
        self.assertEqual(coverage["command_behavior"]["status"], "partial")
        self.assertEqual(
            coverage["command_behavior"]["behavioral_count"],
            coverage["command_behavior"]["target_runtime_status_counts"]["handwritten-mock"]
            + coverage["command_behavior"]["target_runtime_status_counts"]["semantic-mock"],
        )
        self.assertEqual(coverage["event_catalog"]["status"], "complete")
        self.assertEqual(coverage["event_lifecycle"]["status"], "partial")
        self.assertEqual(
            coverage["event_lifecycle"]["target_adapter_count"],
            report["events"]["packet_adapter_count"],
        )
        self.assertNotIn(
            "ASM_RESPONSE_VIOLATION",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "ASM_RESPONSE_LOGIN",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "IN_DOSL7_ATTACK",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "ACCESS2_POLICY_EXPRESSION_EVAL",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "EPI_NA_CHECK_HTTP_REQUEST",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "AVR_CSPM_INJECTION",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "PING_REQUEST_READY",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "PING_RESPONSE_READY",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "ACCESS_SAML_SLO_REQ",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertNotIn(
            "ACCESS_SAML_SLO_RESP",
            coverage["event_lifecycle"]["target_unmapped_events"],
        )
        self.assertEqual(report["commands"]["post_target_count"], 10)
        self.assertEqual(
            report["commands"]["target_catalog_count"],
            report["commands"]["catalog_count"] - 10 - 12,
        )
        self.assertEqual(report["commands"]["unavailable_count"], 12)
        self.assertIn("XML::payload", report["commands"]["unavailable_commands"])
        self.assertIn("JSON::parse", report["commands"]["post_target_commands"])
        self.assertNotIn("IKE_AUTH", report["events"]["unmapped_events"])
        self.assertIn("IKE_AUTH", report["source"]["event_overrides"])
        packet_adapters = {
            item["name"]: item["adapter"]
            for item in report["events"]["packet_adapter_events"]
        }
        self.assertEqual(
            {name: packet_adapters[name] for name in (
                "ACCESS_SESSION_STARTED",
                "ACCESS_SESSION_CLOSED",
                "ACCESS_POLICY_AGENT_EVENT",
                "ACCESS_PER_REQUEST_AGENT_EVENT",
                "ACCESS_POLICY_COMPLETED",
                "ACCESS_ACL_ALLOWED",
                "ACCESS_ACL_DENIED",
                "ACCESS_SAML_AUTHN",
                "ACCESS_SAML_ASSERTION",
                "ACCESS_SAML_SLO_REQ",
                "ACCESS_SAML_SLO_RESP",
                "ACCESS2_POLICY_EXPRESSION_EVAL",
                "EPI_NA_CHECK_HTTP_REQUEST",
                "AVR_CSPM_INJECTION",
                "XML_CONTENT_BASED_ROUTING",
                "IVS_ENTRY_REQUEST",
                "IVS_ENTRY_RESPONSE",
                "IP_GTM",
                "TCP_GTM",
                "UDP_GTM",
                "PING_REQUEST_READY",
                "PING_RESPONSE_READY",
                "BOTDEFENSE_REQUEST",
                "BOTDEFENSE_ACTION",
                "ANTIFRAUD_LOGIN",
                "ANTIFRAUD_ALERT",
                "AUTH_RESULT",
                "AUTH_SUCCESS",
                "AUTH_FAILURE",
                "AUTH_ERROR",
                "AUTH_WANTCREDENTIAL",
                "USER_REQUEST",
                "USER_RESPONSE",
                "NAME_RESOLVED",
            )},
            {
                "ACCESS_SESSION_STARTED": "ACCESS session start from client connection",
                "ACCESS_SESSION_CLOSED": "ACCESS session close from client connection",
                "ACCESS_POLICY_AGENT_EVENT": "ACCESS policy agent lifecycle event",
                "ACCESS_PER_REQUEST_AGENT_EVENT": "ACCESS per-request agent lifecycle event",
                "ACCESS_POLICY_COMPLETED": "ACCESS policy completion after HTTP request",
                "ACCESS_ACL_ALLOWED": "ACCESS allow decision after load-balancer selection",
                "ACCESS_ACL_DENIED": "ACCESS deny decision after load-balancer selection",
                "ACCESS_SAML_AUTHN": "ACCESS SAML authentication fixture after policy",
                "ACCESS_SAML_ASSERTION": "ACCESS SAML assertion fixture after policy",
                "ACCESS_SAML_SLO_REQ": "ACCESS SAML logout request fixture after policy",
                "ACCESS_SAML_SLO_RESP": "ACCESS SAML logout response fixture after policy",
                "ACCESS2_POLICY_EXPRESSION_EVAL": "ACCESS2 policy-expression procedure fixture after policy",
                "EPI_NA_CHECK_HTTP_REQUEST": "Endpoint Inspector special status request",
                "AVR_CSPM_INJECTION": "AVR CSPM response injection opportunity",
                "XML_CONTENT_BASED_ROUTING": "synthetic XML profile match event",
                "IVS_ENTRY_REQUEST": "synthetic internal virtual server request entry",
                "IVS_ENTRY_RESPONSE": "synthetic internal virtual server response entry",
                "IP_GTM": "synthetic legacy GTM IP event injection",
                "TCP_GTM": "synthetic legacy GTM TCP event injection",
                "UDP_GTM": "synthetic legacy GTM UDP event injection",
                "PING_REQUEST_READY": "PingAccess policy request ready before release",
                "PING_RESPONSE_READY": "PingAccess policy response ready for mutation",
                "BOTDEFENSE_REQUEST": "Bot Defense request inspection from HTTP request",
                "BOTDEFENSE_ACTION": "Bot Defense action from HTTP request",
                "ANTIFRAUD_LOGIN": "Anti-Fraud login inspection from HTTP request",
                "ANTIFRAUD_ALERT": "Anti-Fraud alert from HTTP request",
                "AUTH_RESULT": "AUTH result from AUTH::authenticate",
                "AUTH_SUCCESS": "AUTH success continuation from AUTH::authenticate",
                "AUTH_FAILURE": "AUTH failure from AUTH::authenticate",
                "AUTH_ERROR": "AUTH error from AUTH::authenticate",
                "AUTH_WANTCREDENTIAL": "AUTH credential challenge from AUTH::authenticate",
                "USER_REQUEST": "queued TCP::notify request event",
                "USER_RESPONSE": "queued TCP::notify response event",
                "NAME_RESOLVED": "bounded NAME::lookup callback",
            },
        )
        self.assertEqual(
            packet_adapters["ASM_REQUEST_VIOLATION"],
            "ASM request violation inspection",
        )
        self.assertEqual(
            packet_adapters["ASM_REQUEST_DONE"],
            "ASM request inspection completion",
        )
        self.assertEqual(
            packet_adapters["ASM_REQUEST_BLOCKING"],
            "ASM blocking-response hook",
        )
        queue = report["commands"]["implementation_queue"]
        self.assertEqual(queue["candidate_statuses"], ["generated-stub", "no-runtime-handler"])
        queue_buckets = {
            (bucket["namespace"], bucket["runtime_status"]): bucket["count"]
            for bucket in queue["buckets"]
        }
        self.assertNotIn(("AUTH", "generated-stub"), queue_buckets)
        self.assertNotIn(("X509", "generated-stub"), queue_buckets)
        self.assertNotIn(("ADAPT", "generated-stub"), queue_buckets)
        self.assertNotIn(("DATAGRAM", "generated-stub"), queue_buckets)
        self.assertNotIn(("SCTP", "generated-stub"), queue_buckets)
        self.assertNotIn(("DHCP", "generated-stub"), queue_buckets)
        self.assertNotIn(("DHCPV4", "generated-stub"), queue_buckets)
        self.assertNotIn(("DHCPV6", "generated-stub"), queue_buckets)
        self.assertNotIn(("FTP", "generated-stub"), queue_buckets)
        self.assertNotIn(("ICAP", "generated-stub"), queue_buckets)
        self.assertNotIn(("IMAP", "generated-stub"), queue_buckets)
        self.assertNotIn(("POP3", "generated-stub"), queue_buckets)
        self.assertNotIn(("LDAP", "generated-stub"), queue_buckets)
        self.assertNotIn(("SMTPS", "generated-stub"), queue_buckets)
        self.assertNotIn(("NTLM", "generated-stub"), queue_buckets)
        self.assertNotIn(("PROTOCOL_INSPECTION", "generated-stub"), queue_buckets)
        self.assertNotIn(("CLASSIFICATION", "generated-stub"), queue_buckets)
        self.assertNotIn(("CATEGORY", "generated-stub"), queue_buckets)
        self.assertNotIn(("CLASSIFY", "generated-stub"), queue_buckets)
        self.assertNotIn(("FLOWTABLE", "generated-stub"), queue_buckets)
        self.assertNotIn(("L7CHECK", "generated-stub"), queue_buckets)
        self.assertNotIn(("LINK", "generated-stub"), queue_buckets)
        self.assertNotIn(("NAME", "generated-stub"), queue_buckets)
        self.assertNotIn(("RESOLV", "generated-stub"), queue_buckets)
        self.assertNotIn(("SOCKS", "generated-stub"), queue_buckets)
        self.assertNotIn(("SDP", "generated-stub"), queue_buckets)
        self.assertNotIn(("LSN", "generated-stub"), queue_buckets)
        self.assertNotIn(("XLAT", "generated-stub"), queue_buckets)
        self.assertNotIn(("PCP", "generated-stub"), queue_buckets)
        self.assertNotIn(("PSC", "generated-stub"), queue_buckets)
        self.assertNotIn(("PEM", "generated-stub"), queue_buckets)
        self.assertNotIn(("VALIDATE", "generated-stub"), queue_buckets)
        self.assertNotIn(("BWC", "generated-stub"), queue_buckets)
        self.assertNotIn(("AES", "generated-stub"), queue_buckets)
        self.assertNotIn(("IPFIX", "generated-stub"), queue_buckets)
        self.assertNotIn(("CRYPTO", "generated-stub"), queue_buckets)
        self.assertNotIn(("ASN1", "generated-stub"), queue_buckets)
        self.assertNotIn(("ILX", "generated-stub"), queue_buckets)
        self.assertNotIn(("NSH", "generated-stub"), queue_buckets)
        self.assertNotIn(("SIPALG", "generated-stub"), queue_buckets)
        self.assertNotIn(("REST", "generated-stub"), queue_buckets)
        self.assertNotIn(("OFFBOX", "generated-stub"), queue_buckets)
        self.assertNotIn(("TDS", "generated-stub"), queue_buckets)
        self.assertNotIn(("QOE", "generated-stub"), queue_buckets)
        self.assertNotIn(("IKE", "generated-stub"), queue_buckets)
        self.assertNotIn(("XML", "generated-stub"), queue_buckets)
        self.assertEqual(queue["command_count"], 0)
        self.assertEqual(queue["buckets"], [])
        self.assertNotIn(("math", "no-runtime-handler"), queue_buckets)
        self.assertGreaterEqual(report["events"]["catalog_count"], 170)
        self.assertEqual(report["events"]["post_target_count"], 7)
        self.assertEqual(
            report["events"]["target_catalog_count"],
            report["events"]["catalog_count"] - 7 - 6,
        )
        self.assertEqual(report["events"]["unavailable_count"], 6)
        self.assertIn("XML_BEGIN_DOCUMENT", report["events"]["unavailable_events"])
        self.assertIn("JSON_REQUEST", report["events"]["post_target_events"])
        self.assertIn("HTTP_REQUEST", {
            entry["name"] for entry in report["events"]["packet_adapter_events"]
        })
        packet_adapters = {
            entry["name"]: entry["adapter"]
            for entry in report["events"]["packet_adapter_events"]
        }
        self.assertIn("PEM_POLICY", packet_adapters)
        self.assertIn("PEM_SUBS_SESS_CREATED", packet_adapters)
        self.assertIn("PEM_SUBS_SESS_UPDATED", packet_adapters)
        self.assertIn("PEM_SUBS_SESS_DELETED", packet_adapters)
        self.assertEqual(packet_adapters["FIX_MESSAGE"], "structured FIX message event")
        self.assertEqual(
            packet_adapters["PROTOCOL_INSPECTION_MATCH"],
            "protocol inspection match packet",
        )
        self.assertEqual(
            packet_adapters["TAP_REQUEST"],
            "structured TAP security-token event",
        )
        self.assertEqual(
            packet_adapters["HTTP_REQUEST_RELEASE"],
            "HTTP request transaction release phase",
        )
        self.assertEqual(
            packet_adapters["HTTP_RESPONSE_CONTINUE"],
            "raw HTTP 100 Continue response",
        )
        self.assertEqual(
            packet_adapters["IKE_AUTH"],
            "IKEv2 IKE_AUTH exchange",
        )
        self.assertEqual(
            packet_adapters["HTTP_RESPONSE_RELEASE"],
            "HTTP response transaction release phase",
        )
        self.assertEqual(
            packet_adapters["SOCKS_REQUEST"],
            "SOCKS4/SOCKS5 request packet",
        )
        self.assertEqual(
            packet_adapters["HTTP_DISABLED"],
            "HTTP::disable control outcome",
        )
        self.assertEqual(
            packet_adapters["HTTP_CLASS_SELECTED"],
            "supplied HTTP class selection outcome",
        )
        self.assertEqual(
            packet_adapters["HTTP_CLASS_FAILED"],
            "supplied HTTP class selection failure",
        )
        self.assertEqual(
            packet_adapters["HTTP_REJECT"],
            "rule-caused HTTP abort",
        )
        self.assertEqual(
            packet_adapters["HTTP_PROXY_REQUEST"],
            "explicit HTTP proxy request ingress",
        )
        self.assertEqual(
            packet_adapters["HTTP_PROXY_CONNECT"],
            "proxy chaining CONNECT request",
        )
        self.assertEqual(
            packet_adapters["HTTP_PROXY_RESPONSE"],
            "proxy chaining CONNECT response",
        )
        for event_name in (
            "ADAPT_REQUEST_HEADERS",
            "ADAPT_REQUEST_RESULT",
            "ADAPT_RESPONSE_HEADERS",
            "ADAPT_RESPONSE_RESULT",
            "FLOW_INIT",
            "HTTP_REQUEST_DATA",
            "HTTP_REQUEST_SEND",
            "HTTP_RESPONSE_DATA",
            "HTML_TAG_MATCHED",
            "HTML_COMMENT_MATCHED",
            "REWRITE_REQUEST_DONE",
            "REWRITE_RESPONSE_DONE",
            "STREAM_MATCHED",
            "SA_PICKED",
            "SERVER_CONNECTED",
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

    def test_adapt_dynamic_contexts_and_result_event(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP", "REQUESTADAPT", "RESPONSEADAPT"],
                "irule": """
when HTTP_REQUEST {
    ADAPT::enable request false
    set static_ctx [ADAPT::context_static request]
    set request_ctx [ADAPT::context_create request_ctx]
    ADAPT::select $request_ctx /Common/request-ivs
    ADAPT::enable $request_ctx true
    ADAPT::allow $request_ctx http_v1.0 false
    ADAPT::preview_size $request_ctx 128
    ADAPT::service_down_action $request_ctx drop
    ADAPT::timeout $request_ctx 5000
    set response_ctx [ADAPT::context_create response response_ctx]
    ADAPT::select $response_ctx /Common/response-ivs
    log local0. "static=[ADAPT::context_name $static_ctx] request=[ADAPT::context_name $request_ctx] response=[ADAPT::context_name $response_ctx] enabled=[ADAPT::enable $request_ctx] allow=[ADAPT::allow $request_ctx http_v1.0] preview=[ADAPT::preview_size $request_ctx] action=[ADAPT::service_down_action $request_ctx] timeout=[ADAPT::timeout $request_ctx]"
}
when ADAPT_REQUEST_RESULT {
    set current [ADAPT::context_current]
    log local0. "current=[ADAPT::context_name $current] result=[ADAPT::result]"
    ADAPT::result bypass
    ADAPT::context_delete_all
}
""",
                "request": {"uri": "/"},
            },
            allow_irule_file=False,
            allow_requests=True,
        )
        try:
            request_result = session.run_request({"uri": "/"})
            contexts = request_result["semantic"]["adapt"]["contexts"]
            dynamic = [context for context in contexts if context["dynamic"]]
            self.assertEqual(
                [context["name"] for context in dynamic],
                ["request_ctx", "response_ctx"],
            )
            request_context = dynamic[0]
            self.assertFalse(contexts[0]["enabled"])
            self.assertTrue(request_context["enabled"])
            self.assertFalse(request_context["allow_http_v1"])
            self.assertEqual(request_context["preview_size"], 128)
            self.assertEqual(request_context["service_down_action"], "drop")
            self.assertEqual(request_context["timeout"], 5000)
            self.assertTrue(any(
                "static=REQUESTADAPT request=request_ctx response=response_ctx enabled=1 allow=0 preview=128 action=drop timeout=5000" in entry
                for entry in request_result["logs"]
            ))

            reset_result = session.run_request({"uri": "/", "new_connection": True})
            reset_dynamic = [
                context
                for context in reset_result["semantic"]["adapt"]["contexts"]
                if context["dynamic"]
            ]
            self.assertEqual(
                [context["handle"] for context in reset_dynamic],
                ["dynamic:request:1", "dynamic:response:2"],
            )

            adapt_result = session.fire_event("ADAPT_REQUEST_RESULT")
            self.assertTrue(adapt_result["fired"])
            self.assertTrue(any("current=request_ctx result=unknown" in entry for entry in adapt_result["logs"]))
            self.assertEqual(
                [context["handle"] for context in adapt_result["semantic"]["adapt"]["contexts"]],
                ["static:request", "static:response"],
            )
            self.assertEqual(
                adapt_result["semantic"]["adapt"]["current_handle"],
                "static:request",
            )
        finally:
            session.close()

    def test_adapt_request_and_response_lifecycle_uses_ivs_fixture_results(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REQUESTADAPT", "RESPONSEADAPT"],
                "adapt": {
                    "request": {"result": "modified"},
                    "response": {"result": "response"},
                },
                "irule": """
when HTTP_REQUEST {
    log local0. "http-request"
}
when ADAPT_REQUEST_HEADERS {
    log local0. "request-headers=[ADAPT::result]"
    HTTP::header insert X-Adapt-Request headers
}
when ADAPT_REQUEST_RESULT {
    log local0. "request-result=[ADAPT::result]"
    ADAPT::result bypass
}
when HTTP_RESPONSE {
    log local0. "http-response"
}
when ADAPT_RESPONSE_HEADERS {
    log local0. "response-headers=[ADAPT::result]"
    HTTP::header insert X-Adapt-Response headers
}
when ADAPT_RESPONSE_RESULT {
    log local0. "response-result=[ADAPT::result]"
    ADAPT::result close
}
""",
                "request": {"uri": "/", "headers": {"Host": "example.test"}},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["results"][0]["events_fired"]
        self.assertLess(events.index("HTTP_REQUEST"), events.index("ADAPT_REQUEST_HEADERS"))
        self.assertLess(events.index("ADAPT_REQUEST_HEADERS"), events.index("ADAPT_REQUEST_RESULT"))
        self.assertLess(events.index("HTTP_RESPONSE"), events.index("ADAPT_RESPONSE_HEADERS"))
        self.assertLess(events.index("ADAPT_RESPONSE_HEADERS"), events.index("ADAPT_RESPONSE_RESULT"))
        request_result = result["results"][0]
        self.assertEqual(
            request_result["request"]["headers"]["x-adapt-request"],
            "headers",
        )
        self.assertEqual(
            request_result["response"]["headers"]["x-adapt-response"],
            "headers",
        )
        self.assertTrue(any("request-headers=modify" in entry for entry in request_result["logs"]))
        self.assertTrue(any("request-result=modify" in entry for entry in request_result["logs"]))
        self.assertTrue(any("response-headers=respond" in entry for entry in request_result["logs"]))
        self.assertTrue(any("response-result=respond" in entry for entry in request_result["logs"]))
        contexts = request_result["semantic"]["adapt"]["contexts"]
        self.assertEqual(contexts[0]["result"], "bypass")

    def test_adapt_noop_and_error_fixtures_gate_headers_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REQUESTADAPT", "RESPONSEADAPT"],
                "adapt": {
                    "request": {"result": "noop"},
                    "response": {"result": "error"},
                },
                "irule": """
when ADAPT_REQUEST_HEADERS { log local0. request-headers }
when ADAPT_REQUEST_RESULT { log local0. request-result }
when ADAPT_RESPONSE_HEADERS { log local0. response-headers }
when ADAPT_RESPONSE_RESULT { log local0. response-result }
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["results"][0]["events_fired"]
        self.assertNotIn("ADAPT_REQUEST_HEADERS", events)
        self.assertNotIn("ADAPT_REQUEST_RESULT", events)
        self.assertNotIn("ADAPT_RESPONSE_HEADERS", events)
        self.assertIn("ADAPT_RESPONSE_RESULT", events)

    def test_adapt_request_fixture_override_is_scoped_to_one_request(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REQUESTADAPT"],
                "adapt": {"request": {"result": "noop"}},
                "irule": "when ADAPT_REQUEST_RESULT { log local0. adapt-result }",
                "requests": [
                    {"uri": "/modified", "adapt": {"request": {"result": "modified"}}},
                    {"uri": "/noop"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertIn("ADAPT_REQUEST_RESULT", result["results"][0]["events_fired"])
        self.assertNotIn("ADAPT_REQUEST_RESULT", result["results"][1]["events_fired"])

    def test_adapt_context_validation_boundaries(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "adapt.request.result must be one of",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "REQUESTADAPT"],
                    "adapt": {"request": {"result": "not-an-ivs-result"}},
                    "irule": "when HTTP_REQUEST { return }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "no more than 256 bytes"
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "REQUESTADAPT"],
                    "irule": "when HTTP_REQUEST { ADAPT::context_create [string repeat x 257] }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP", "REQUESTADAPT", "RESPONSEADAPT"],
                "irule": """
when HTTP_REQUEST {
    set ::response_ctx [ADAPT::context_create response response_ctx]
    set ::disabled_ctx [ADAPT::context_create disabled_ctx]
    ADAPT::enable $::disabled_ctx false
}
when ADAPT_REQUEST_RESULT {
    set current [ADAPT::context_current]
    set rc [catch {ADAPT::select $::response_ctx /Common/not-current-side} message]
    log local0. "current=[ADAPT::context_name $current] cross_side_rc=$rc"
}
""",
                "request": {"uri": "/"},
            },
            allow_irule_file=False,
            allow_requests=True,
        )
        try:
            session.run_request({"uri": "/"})
            result = session.fire_event("ADAPT_REQUEST_RESULT")
            self.assertTrue(any(
                "current=REQUESTADAPT cross_side_rc=1" in entry
                for entry in result["logs"]
            ))
            self.assertEqual(
                result["semantic"]["adapt"]["current_handle"],
                "static:request",
            )
        finally:
            session.close()

    def test_datagram_header_payload_and_option_queries(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["UDP", "DATAGRAM", "FLOW"],
                "irule": """
when FLOW_INIT {
    if {[IP::protocol] == 17} {
        log local0. "v4=[DATAGRAM::ip tos]/[DATAGRAM::ip ttl]/[DATAGRAM::ip flags] opts=[DATAGRAM::ip option] count=[DATAGRAM::ip option_count]/[DATAGRAM::ip option_count 7] udp=[DATAGRAM::udp payload 2]/[DATAGRAM::udp payload_length] dns=[DATAGRAM::dns id]/[DATAGRAM::dns qr]/[DATAGRAM::dns opcode]/[DATAGRAM::dns qdcount]/[DATAGRAM::dns ancount]/[DATAGRAM::dns nscount]/[DATAGRAM::dns arcount] l2=[DATAGRAM::l2 dest]"
    } else {
        log local0. "v6=[DATAGRAM::ip6 hop_limit]/[DATAGRAM::ip6 option]/[DATAGRAM::ip6 option_count] tcp=[DATAGRAM::tcp flags]/[DATAGRAM::tcp window]/[DATAGRAM::tcp payload]/[DATAGRAM::tcp payload_length] opts=[DATAGRAM::tcp option]/[DATAGRAM::tcp option_count 2]"
    }
}
""",
            },
            allow_irule_file=False,
            allow_requests=True,
        )
        try:
            ipv4 = session.fire_event(
                "FLOW_INIT",
                {
                    "connection": {
                        "protocol": 17,
                        "client_addr": "10.0.0.1",
                        "local_addr": "192.0.2.53",
                        "client_port": 53000,
                        "local_port": 53,
                        "tos": 16,
                        "ttl": 44,
                    },
                    "datagram": {
                        "ip_version": 4,
                        "ip_flags": 2,
                        "ip_options": "{1 foo} {7}",
                        "l2_dest": "aa:bb:cc:dd:ee:ff",
                        "dns_id": 4660,
                        "dns_qr": 0,
                        "dns_opcode": "QUERY",
                        "dns_qdcount": 1,
                        "dns_ancount": 2,
                        "dns_nscount": 3,
                        "dns_arcount": 4,
                        "payload": "hello",
                    },
                },
            )
            self.assertTrue(any(
                "v4=16/44/2" in entry
                and "opts={1 foo} 7" in entry
                and "count=2/1" in entry
                and "udp=he/5" in entry
                and "dns=4660/0/QUERY/1/2/3/4" in entry
                and "l2=aa:bb:cc:dd:ee:ff" in entry
                for entry in ipv4["logs"]
            ))

            ipv6 = session.fire_event(
                "FLOW_INIT",
                {
                    "connection": {
                        "protocol": 6,
                        "client_addr": "2001:db8::1",
                        "local_addr": "2001:db8::53",
                        "client_port": 51000,
                        "local_port": 443,
                    },
                    "datagram": {
                        "ip_version": 6,
                        "ip6_hop_limit": 31,
                        "ip6_options": "{1 alpha} {2 beta} {2 gamma}",
                        "tcp_flags": 18,
                        "tcp_window": 65535,
                        "tcp_options": "{2 mss} {3 ws} {2 sack}",
                        "payload": "world",
                    },
                },
            )
            self.assertTrue(any(
                "v6=31/{1 alpha} {2 beta} {2 gamma}/3" in entry
                and "tcp=18/65535/world/5" in entry
                and "opts={2 mss} {3 ws} {2 sack}/2" in entry
                for entry in ipv6["logs"]
            ))
        finally:
            session.close()

    def test_datagram_packet_metadata_and_protocol_boundaries(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DATAGRAM"],
                "irule": """
when CLIENT_DATA {
    log local0. "udp=[DATAGRAM::udp payload 3]/[DATAGRAM::udp payload_length] dns=[DATAGRAM::dns id] l2=[DATAGRAM::l2 dest]"
}
""",
                "packets": [{
                    "protocol": "udp",
                    "source": {"address": "10.0.0.1", "port": 53000},
                    "destination": {"address": "192.0.2.53", "port": 53},
                    "ttl": 48,
                    "tos": 8,
                    "payload": "abcdef",
                    "datagram": {
                        "ip_flags": 1,
                        "l2_dest": "00:11:22:33:44:55",
                        "dns_id": 99,
                    },
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLIENT_DATA"
        )
        self.assertEqual(event["state"]["datagram"]["ip_flags"], "1")
        self.assertEqual(event["state"]["datagram"]["ip_ttl"], "48")
        self.assertEqual(event["state"]["datagram"]["ip_tos"], "8")
        self.assertEqual(event["state"]["datagram"]["dns_id"], "99")
        self.assertTrue(any(
            "udp=abc/6" in entry
            and "dns=99" in entry
            and "l2=00:11:22:33:44:55" in entry
            for entry in event["logs"]
        ))
        statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("DATAGRAM::")
        }
        self.assertEqual(set(statuses), {
            "DATAGRAM::dns", "DATAGRAM::l2", "DATAGRAM::udp",
        })
        self.assertTrue(all(value == "semantic-mock" for value in statuses.values()))

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires an IPv4 datagram"):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP", "DATAGRAM", "FLOW"],
                    "irule": "when FLOW_INIT { DATAGRAM::ip ttl }",
                    "packets": [{
                        "protocol": "udp",
                        "source": {"address": "2001:db8::1", "port": 53000},
                        "destination": {"address": "2001:db8::53", "port": 53},
                        "payload": "x",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires the DATAGRAM profile"):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP", "FLOW"],
                    "irule": "when FLOW_INIT { DATAGRAM::udp payload_length }",
                    "packets": [{"protocol": "udp", "payload": "x"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_event_packets_inject_catalogued_events_with_validated_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_PROXY_REQUEST {
    log local0. proxy-event
}
""",
                "packets": [
                    {
                        "protocol": "event",
                        "event": "HTTP_PROXY_REQUEST",
                        "state": {
                            "connection": {
                                "client_addr": "192.0.2.10",
                            }
                        },
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        entry = result["trace"][0]
        event = entry["events"][0]
        self.assertEqual(entry["protocol"], "event")
        self.assertEqual(entry["event"], "HTTP_PROXY_REQUEST")
        self.assertEqual(event["event"], "HTTP_PROXY_REQUEST")
        self.assertEqual(event["state"]["connection"]["client_addr"], "192.0.2.10")
        self.assertTrue(any("proxy-event" in log for log in event["logs"]))

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "uppercase iRule event"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_PROXY_REQUEST { log local0. ok }",
                    "packets": [{"protocol": "event", "event": "http_proxy_request"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "unknown iRule event"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_PROXY_REQUEST { log local0. ok }",
                    "packets": [{"protocol": "event", "event": "NOT_A_REAL_EVENT"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "synthetic event packet"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_PROXY_REQUEST { log local0. ok }",
                    "packets": [{
                        "protocol": "event",
                        "event": "HTTP_PROXY_REQUEST",
                        "payload": "must-not-be-ignored",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_sctp_packet_collection_payload_and_response_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SCTP"],
                "irule": """
when CLIENT_ACCEPTED {
    SCTP::collect 4
    SCTP::ppi 3
    log local0. "accepted=[SCTP::client_port]/[SCTP::server_port] mss=[SCTP::mss] ppi=[SCTP::ppi]"
}
when CLIENT_DATA {
    log local0. "data=[SCTP::payload]/[SCTP::payload length]/[SCTP::payload 2]"
    SCTP::payload replace 0 4 PONG
    SCTP::respond reply 0 3
    SCTP::release 0
}
""",
                "packets": [{
                    "protocol": "sctp",
                    "source": {"address": "10.0.0.1", "port": 5000},
                    "destination": {"address": "192.0.2.10", "port": 9899},
                    "payload": "ping",
                    "ppi": 7,
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]
        accepted = next(event for event in entry["events"] if event["event"] == "CLIENT_ACCEPTED")
        data = next(event for event in entry["events"] if event["event"] == "CLIENT_DATA")
        self.assertTrue(any("accepted=5000/9899" in line and "mss=1460" in line and "ppi=3" in line
                            for line in accepted["logs"]))
        self.assertTrue(any("data=ping/4/pi" in line for line in data["logs"]))
        self.assertEqual(data["state"]["connection"]["protocol"], "132")
        self.assertEqual(data["state"]["sctp"]["payload"], "PONG")
        self.assertEqual(data["state"]["sctp"]["ppi"], "7")
        self.assertEqual(data["state"]["sctp"]["released"], "1")
        self.assertEqual(data["state"]["sctp"]["released_length"], "0")
        self.assertEqual(entry["response"], "rep")
        self.assertEqual(result["emitted"][0]["protocol"], "sctp")

    def test_sctp_payload_validation_and_timeout_queries(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SCTP"],
                "irule": """
when CLIENT_ACCEPTED {
    log local0. "ports=[SCTP::local_port]/[SCTP::remote_port]/[SCTP::local_port clientside]/[SCTP::remote_port serverside]"
    log local0. "rto=[SCTP::rto_initial]/[SCTP::rto_max]/[SCTP::rto_min]/[SCTP::sack_timeout]"
}
""",
                "packets": [{
                    "protocol": "sctp",
                    "source": {"address": "10.0.0.1", "port": 5000},
                    "destination": {"address": "192.0.2.10", "port": 9899},
                    "payload_hex": "ff00",
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        accepted = next(event for event in result["trace"][0]["events"] if event["event"] == "CLIENT_ACCEPTED")
        self.assertTrue(any("ports=9899/5000/9899/9899" in line for line in accepted["logs"]))
        self.assertTrue(any("rto=1000/60000/100/200" in line for line in accepted["logs"]))
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "ppi must be an integer"):
            self.adapter.run_scenario(
                {
                    "profiles": ["SCTP"],
                    "irule": "when CLIENT_ACCEPTED { log local0. ok }",
                    "packets": [{"protocol": "sctp", "ppi": 65536}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "xid must be an integer"):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{"protocol": "dhcpv4", "xid": 2**32}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "option IDs must be integers"):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{"protocol": "dhcpv6", "options": {"client-id": "x"}}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_sctp_collection_buffers_partial_payloads(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SCTP"],
                "irule": "when CLIENT_ACCEPTED { SCTP::collect 4 } when CLIENT_DATA { log local0. \"payload=[SCTP::payload]\" }",
                "packets": [
                    {"protocol": "sctp", "payload": "pi"},
                    {"protocol": "sctp", "payload": "ng"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(result["trace"][0]["buffered"])
        self.assertEqual(result["trace"][0]["buffered_bytes"], 2)
        data_events = [
            event
            for packet in result["trace"]
            for event in packet["events"]
            if event["event"] == "CLIENT_DATA"
        ]
        self.assertEqual(len(data_events), 1)
        self.assertTrue(any("payload=ping" in line for line in data_events[0]["logs"]))

    def test_dhcpv4_packet_fields_options_and_reject(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_DATA {
    log local0. "v=[DHCP::version] type=[DHCPv4::type] htype=[DHCPv4::htype] xid=[DHCPv4::xid] ch=[DHCPv4::chaddr] o=[DHCPv4::option 53]"
    DHCPv4::option 12 updated-host
    DHCPv4::reject
}
""",
                "packets": [{
                    "protocol": "dhcpv4",
                    "source": {"address": "0.0.0.0", "port": 68},
                    "destination": {"address": "255.255.255.255", "port": 67},
                    "type": "DISCOVER",
                    "htype": 1,
                    "xid": 42,
                    "chaddr": "00:11:22:33:44:55",
                    "options": {"053": "DISCOVER", "012": "client host"},
                    "payload": "discover",
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        data = next(event for event in result["trace"][0]["events"] if event["event"] == "CLIENT_DATA")
        self.assertTrue(any("v=4 type=DISCOVER htype=1 xid=42 ch=00:11:22:33:44:55 o=DISCOVER" in line
                            for line in data["logs"]))
        self.assertEqual(data["state"]["dhcp"]["version"], "4")
        self.assertIn("12 updated-host", data["state"]["dhcpv4"]["options"])
        self.assertTrue(result["trace"][0]["rejected"])
        self.assertEqual(result["trace"][0]["drop_reason"], "dhcpv4 reject")

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        self.assertEqual(usage["DHCPv4::htype"]["runtime_status"], "semantic-mock")

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet 0 htype must be an integer from 0 to 255",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. [DHCPv4::htype] }",
                    "packets": [{"protocol": "dhcpv4", "htype": 256}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "packet 0 htype must be a non-negative integer",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. [DHCPv4::htype] }",
                    "packets": [{"protocol": "dhcpv4", "htype": True}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_raw_dhcpv4_packets_reach_the_structured_event_adapter(self) -> None:
        request_payload = _dhcpv4_message(
            options=(
                (53, b"\x01"),
                (12, b"client-a"),
                (3, ipaddress.ip_address("192.0.2.1").packed),
                (55, b"\x01\x03\x06"),
            )
        )
        response_payload = _dhcpv4_message(
            opcode=2,
            yiaddr="192.0.2.50",
            siaddr="192.0.2.1",
            options=(
                (53, b"\x02"),
                (54, ipaddress.ip_address("192.0.2.1").packed),
                (51, (3600).to_bytes(4, "big")),
            ),
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_DATA {
    log local0. "client=[DHCP::version]/[DHCPv4::type]/[DHCPv4::xid]/[DHCPv4::chaddr]/[DHCPv4::option 12]/[DHCPv4::option 3]/[DHCPv4::option 55]"
}
when SERVER_DATA {
    log local0. "server=[DHCPv4::type]/[DHCPv4::yiaddr]/[DHCPv4::option 51]"
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "0.0.0.0", "255.255.255.255", 68, 67, request_payload
                        ),
                    },
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.1", "192.0.2.50", 67, 68, response_payload
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request, response = result["trace"]
        self.assertEqual(request["protocol"], "dhcpv4")
        self.assertEqual(response["protocol"], "dhcpv4")
        self.assertEqual(request["payload_hex"], request_payload.hex())
        self.assertEqual(response["payload_hex"], response_payload.hex())
        client_event = next(event for event in request["events"] if event["event"] == "CLIENT_DATA")
        server_event = next(event for event in response["events"] if event["event"] == "SERVER_DATA")
        client_dhcp = client_event["state"]["dhcpv4"]
        server_dhcp = server_event["state"]["dhcpv4"]
        self.assertEqual(client_dhcp["type"], "DISCOVER")
        self.assertEqual(client_dhcp["chaddr"], "00:11:22:33:44:55")
        self.assertEqual(server_dhcp["yiaddr"], "192.0.2.50")
        self.assertTrue(any(
            "client=4/DISCOVER/305419896/00:11:22:33:44:55/client-a/192.0.2.1/1 3 6" in entry
            for entry in client_event["logs"]
        ))
        self.assertTrue(any("server=OFFER/192.0.2.50/3600" in entry for entry in server_event["logs"]))

        capture = _pcap_bytes([
            (
                9,
                10,
                _ethernet_ipv4(
                    _raw_ipv4_udp_hex(
                        "0.0.0.0", "255.255.255.255", 68, 67, request_payload
                    )
                ),
            )
        ])
        replay = self.adapter.run_pcap_scenario(
            {
                "profiles": ["UDP"],
                "irule": "when CLIENT_DATA { log local0. dhcp-pcap }",
            },
            capture,
            tcl_lsp_root=self.tcl_lsp_root,
            direction="client_to_server",
        )
        self.assertEqual(replay["trace"][0]["protocol"], "dhcpv4")
        self.assertIn(
            "CLIENT_DATA",
            [event["event"] for event in replay["trace"][0]["events"]],
        )

    def test_raw_dhcpv6_packets_reach_the_structured_event_adapter(self) -> None:
        request_payload = _dhcpv6_message(
            options=(
                (6, struct.pack("!HH", 1, 23)),
                (23, ipaddress.ip_address("2001:db8::53").packed),
            )
        )
        response_payload = _dhcpv6_message(
            message_type=7,
            transaction_id=b"\x01\x02\x03",
            options=((13, struct.pack("!H", 0) + b"ok"),),
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_DATA {
    log local0. "client=[DHCP::version]/[DHCPv6::msg_type]/[DHCPv6::transaction_id]/[DHCPv6::option 6]/[DHCPv6::option 23]"
}
when SERVER_DATA {
    log local0. "server=[DHCPv6::msg_type]/[DHCPv6::option 13]"
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv6",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv6_udp_hex(
                        "fe80::10", "ff02::1:2", 546, 547, request_payload,
                        traffic_class=0x2E,
                        next_header=0,
                        extension_header=b"\x11\x00" + b"\x00" * 6,
                    ),
                    },
                    {
                        "protocol": "wire",
                        "network": "ipv6",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv6_udp_hex(
                            "fe80::1", "fe80::10", 547, 546, response_payload
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request, response = result["trace"]
        self.assertEqual(request["protocol"], "dhcpv6")
        self.assertEqual(response["protocol"], "dhcpv6")
        client_event = next(event for event in request["events"] if event["event"] == "CLIENT_DATA")
        server_event = next(event for event in response["events"] if event["event"] == "SERVER_DATA")
        self.assertEqual(client_event["state"]["datagram"]["ip_ttl"], "64")
        self.assertEqual(client_event["state"]["datagram"]["ip_tos"], "46")
        self.assertEqual(client_event["state"]["dhcp"]["version"], "6")
        self.assertEqual(client_event["state"]["dhcpv6"]["msg_type"], "SOLICIT")
        self.assertEqual(client_event["state"]["dhcpv6"]["transaction_id"], "010203")
        self.assertTrue(any("client=6/SOLICIT/010203/1 23/2001:db8::53" in entry for entry in client_event["logs"]))
        self.assertTrue(any("server=REPLY/0 ok" in entry for entry in server_event["logs"]))

        capture = _pcap_bytes([
            (
                11,
                12,
                _ethernet_ipv6(
                    _raw_ipv6_udp_hex(
                        "fe80::10", "ff02::1:2", 546, 547, request_payload
                    )
                ),
            )
        ])
        replay = self.adapter.run_pcap_scenario(
            {
                "profiles": ["UDP"],
                "irule": "when CLIENT_DATA { log local0. dhcpv6-pcap }",
            },
            capture,
            tcl_lsp_root=self.tcl_lsp_root,
            direction="client_to_server",
        )
        self.assertEqual(replay["capture"]["ip_packet_count"], 1)
        self.assertEqual(replay["capture"]["ipv6_packet_count"], 1)
        self.assertEqual(replay["trace"][0]["protocol"], "dhcpv6")

    def test_ikev2_packet_adapter_fires_ike_auth_and_supports_nat_t(self) -> None:
        request_payload = _ikev2_message()
        response_payload = _ikev2_message(response=True, payload_types=(36, 46))
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when IKE_AUTH {
    log local0. "ike=[IKE::cert 0]/[IKE::san_dns]"
    IKE::auth_success
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "198.51.100.10", "203.0.113.10", 500, 500, request_payload
                        ),
                    },
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "203.0.113.10", "198.51.100.10", 4500, 4500,
                            b"\x00\x00\x00\x00" + response_payload,
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request, response = result["trace"]
        self.assertEqual(request["protocol"], "ike")
        self.assertEqual(request["ike"]["exchange_type"], "IKE_AUTH")
        self.assertEqual(request["ike"]["payloads"][0]["type"], "IDi")
        self.assertEqual(
            [event["event"] for event in request["events"]],
            ["RULE_INIT", "CLIENT_ACCEPTED", "IKE_AUTH"],
        )
        self.assertTrue(request["events"][-1]["fired"])
        self.assertEqual(response["protocol"], "ike")
        self.assertTrue(response["ike"]["response"])
        self.assertEqual(response["ike"]["payloads"][-1]["type"], "SK")
        self.assertTrue(any("ike=/" in entry for entry in request["events"][-1]["logs"]))
        self.assertEqual(request["events"][-1]["state"]["ike"]["auth_success"], "1")

        structured = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": "when IKE_AUTH { log local0. \"[IKE::cert]/[IKE::san_dns]\" }",
                "packets": [
                    {
                        "protocol": "ike",
                        "source": {"address": "198.51.100.10", "port": 500},
                        "destination": {"address": "203.0.113.10", "port": 500},
                        "ike": {
                            "cert": "CERTIFICATE-DATA",
                            "san_dns": "vpn.example.test",
                            "payloads": ["IDi", "AUTH"],
                        },
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = structured["trace"][0]["events"][-1]
        self.assertTrue(any("CERTIFICATE-DATA/vpn.example.test" in entry for entry in event["logs"]))

        esp_like = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": "when CLIENT_DATA { log local0. esp-udp }",
                "packets": [
                    {
                        "protocol": "wire",
                        "network": "ipv4",
                        "direction": "server_to_client",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "203.0.113.10", "198.51.100.10", 4500, 4500,
                            b"\x01\x02\x03\x04",
                        ),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        esp_entry = esp_like["trace"][0]
        self.assertEqual(esp_entry["protocol"], "udp")
        self.assertEqual(esp_entry["events"][-1]["event"], "SERVER_DATA")

    def test_ikev2_packet_adapter_rejects_invalid_envelopes(self) -> None:
        base = {
            "profiles": ["UDP"],
            "irule": "when IKE_AUTH { }",
            "packets": [
                {
                    "protocol": "wire",
                    "network": "ipv4",
                    "direction": "client_to_server",
                    "raw_hex": "",
                }
            ],
        }
        trailing = bytearray(_ikev2_message(payload_types=(35,)) + b"\x00")
        trailing[24:28] = len(trailing).to_bytes(4, "big")
        for payload, message in (
            (b"\x02", "IKE header is truncated"),
            (_ikev2_message()[:-1], "IKE message length is invalid"),
            (bytes(trailing), "IKE payload chain has trailing bytes"),
        ):
            scenario = dict(base)
            scenario["packets"] = [dict(base["packets"][0], raw_hex=_raw_ipv4_udp_hex(
                "198.51.100.10", "203.0.113.10", 500, 500, payload
            ))]
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_structured_ike_packet_rejects_inconsistent_metadata(self) -> None:
        base = {
            "profiles": ["UDP"],
            "irule": "when IKE_AUTH { }",
            "packets": [
                {
                    "protocol": "ike",
                    "source": {"address": "198.51.100.10", "port": 500},
                    "destination": {"address": "203.0.113.10", "port": 500},
                    "ike": {},
                }
            ],
        }
        invalid_ikes = (
            ({"flags": 0x20, "response": False}, "response disagrees"),
            ({"version": "2.16"}, "version must be an IKEv2 version"),
            ({"payloads": [], "next_payload": "AUTH"}, "next_payload disagrees"),
            ({"payloads": ["NONE"]}, "cannot be NONE"),
        )
        for ike, message in invalid_ikes:
            with self.subTest(message=message):
                scenario = dict(base)
                scenario["packets"] = [dict(base["packets"][0], ike=ike)]
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_raw_dhcpv6_rejects_truncated_message_and_options(self) -> None:
        base = {
            "profiles": ["UDP"],
            "irule": "when CLIENT_DATA { log local0. request }",
        }
        malformed_payloads = (
            (b"\x01\x02", "wire packet 0 DHCPv6 message is truncated"),
            (_dhcpv6_message(options=()) + b"\x00", "wire packet 0 DHCPv6 option header is truncated"),
            (_dhcpv6_message() + b"\x00\x01\x00\x02\x01", "wire packet 0 DHCPv6 option 1 exceeds the message"),
        )
        for payload, message in malformed_payloads:
            with self.subTest(message=message):
                scenario = dict(base)
                scenario["packets"] = [{
                    "protocol": "wire",
                    "network": "ipv6",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv6_udp_hex(
                        "fe80::10", "ff02::1:2", 546, 547, payload
                    ),
                }]
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        fragmented = dict(base)
        fragmented["packets"] = [{
            "protocol": "wire",
            "network": "ipv6",
            "direction": "client_to_server",
            "raw_hex": _raw_ipv6_udp_hex(
                "fe80::10",
                "ff02::1:2",
                546,
                547,
                _dhcpv6_message(),
                next_header=44,
                extension_header=b"\x11\x00\x00\x08\x00\x00\x00\x00",
            ),
        }]
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "raw input contains incomplete IP fragments",
        ):
            self.adapter.run_scenario(fragmented, tcl_lsp_root=self.tcl_lsp_root)

    def test_raw_dhcpv4_rejects_malformed_bootp_and_options(self) -> None:
        base = {
            "profiles": ["UDP"],
            "irule": "when CLIENT_DATA { log local0. request }",
        }

        malformed_payloads = (
            (b"\x01" * 239, "wire packet 0 DHCPv4 message is truncated"),
            (_dhcpv4_message()[:236] + b"\x00\x00\x00\x00", "wire packet 0 DHCPv4 magic cookie is missing"),
            (_dhcpv4_message()[:-1] + b"\x35", "wire packet 0 DHCPv4 option 53 is missing its length"),
            (_dhcpv4_message()[:-1] + b"\x35\x02\x01", "wire packet 0 DHCPv4 option 53 exceeds the message"),
        )
        for payload, message in malformed_payloads:
            with self.subTest(message=message):
                scenario = dict(base)
                scenario["packets"] = [{
                    "protocol": "wire",
                    "network": "ipv4",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_udp_hex(
                        "0.0.0.0", "255.255.255.255", 68, 67, payload
                    ),
                }]
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        invalid_hlen = bytearray(_dhcpv4_message())
        invalid_hlen[2] = 17
        scenario = dict(base)
        scenario["packets"] = [{
            "protocol": "wire",
            "network": "ipv4",
            "direction": "client_to_server",
            "raw_hex": _raw_ipv4_udp_hex(
                "0.0.0.0", "255.255.255.255", 68, 67, bytes(invalid_hlen)
            ),
        }]
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "wire packet 0 DHCPv4 hardware address length exceeds 16",
        ):
            self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_raw_dhcpv4_option_overload_is_decoded_after_primary_options(self) -> None:
        payload = bytearray(
            _dhcpv4_message(options=((53, b"\x01"), (52, b"\x01")))
        )
        overloaded = b"\x0c\x0foverloaded-host\xff"
        payload[108 : 108 + len(overloaded)] = overloaded
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": 'when CLIENT_DATA { log local0. "type=[DHCPv4::option 53] host=[DHCPv4::option 12]" }',
                "packets": [{
                    "protocol": "wire",
                    "network": "ipv4",
                    "direction": "client_to_server",
                    "raw_hex": _raw_ipv4_udp_hex(
                        "0.0.0.0", "255.255.255.255", 68, 67, bytes(payload)
                    ),
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        data_event = next(
            event for event in result["trace"][0]["events"] if event["event"] == "CLIENT_DATA"
        )
        self.assertTrue(any(
            "type=DISCOVER host=overloaded-host" in entry
            for entry in data_event["logs"]
        ))

    def test_dhcp_direct_event_infers_version_and_rejects_duplicate_numeric_options(self) -> None:
        session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["UDP"],
                "irule": 'when CLIENT_DATA { log local0. "v=[DHCP::version]" }',
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event(
                "CLIENT_DATA",
                {"dhcpv6": {"msg_type": "REPLY"}},
            )
        finally:
            session.close()
        self.assertEqual(result["state"]["dhcp"]["version"], "6")
        self.assertTrue(any("v=6" in line for line in result["logs"]))

        session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["UDP"],
                "irule": 'when CLIENT_DATA { log local0. "htype=[DHCPv4::htype]" }',
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("CLIENT_DATA", {"dhcpv4": {"htype": 255}})
        finally:
            session.close()
        self.assertTrue(any("htype=255" in line for line in result["logs"]))
        self.assertEqual(result["state"]["dhcpv4"]["htype"], "255")

        default_result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": 'when CLIENT_DATA { log local0. "htype=[DHCPv4::htype]" }',
                "packets": [
                    {"protocol": "dhcpv4", "htype": 255},
                    {"protocol": "dhcpv4"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        default_data_events = [
            event
            for packet_trace in default_result["trace"]
            for event in packet_trace["events"]
            if event["event"] == "CLIENT_DATA"
        ]
        self.assertTrue(
            any("htype=255" in line for line in default_data_events[0]["logs"])
        )
        self.assertTrue(
            any("htype=1" in line for line in default_data_events[1]["logs"])
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "DHCPv4::htype takes no arguments",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. [DHCPv4::htype 1] }",
                    "packets": [{"protocol": "dhcpv4"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "duplicate option ID 1"):
            self.adapter.run_scenario(
                {
                    "profiles": ["UDP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{
                        "protocol": "dhcpv4",
                        "options": {"1": "one", "01": "duplicate"},
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_dhcpv6_packet_fields_options_and_drop(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_DATA {
    log local0. "v=[DHCP::version] type=[DHCPv6::msg_type] tx=[DHCPv6::transaction_id] opt=[DHCPv6::option 18]"
    DHCPv6::option delete 18
    DHCPv6::drop
}
""",
                "packets": [{
                    "protocol": "dhcpv6",
                    "source": {"address": "fe80::1", "port": 546},
                    "destination": {"address": "ff02::1:2", "port": 547},
                    "msg_type": "SOLICIT",
                    "transaction_id": "010203",
                    "hop_count": 1,
                    "options": {"18": "relay-id", "1": "client-id"},
                    "payload_hex": "01020304",
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        data = next(event for event in result["trace"][0]["events"] if event["event"] == "CLIENT_DATA")
        self.assertTrue(any("v=6 type=SOLICIT tx=010203 opt=relay-id" in line for line in data["logs"]))
        self.assertEqual(data["state"]["dhcp"]["version"], "6")
        self.assertNotIn("18 relay-id", data["state"]["dhcpv6"]["options"])
        self.assertTrue(result["trace"][0]["dropped"])

    def test_packet_server_lifecycle_fires_init_before_connected(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when SERVER_INIT { log local0. init }
when SERVER_CONNECTED { log local0. connected }
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
                        "direction": "server_to_client",
                        "flags": ["SYN", "ACK"],
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        events = [event["event"] for event in result["trace"][1]["events"]]
        self.assertEqual(events[:2], ["SERVER_INIT", "SERVER_CONNECTED"])
        logs = [log for event in result["trace"][1]["events"] for log in event["logs"]]
        self.assertTrue(any("init" in log for log in logs))
        self.assertTrue(any("connected" in log for log in logs))
        self.assertIn("SERVER_INIT", result["fidelity"]["events"])

    def test_udp_server_lifecycle_does_not_claim_tcp_server_init(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when SERVER_INIT { log local0. unexpected-init }
when SERVER_CONNECTED { log local0. connected }
""",
                "packets": [
                    {
                        "protocol": "udp",
                        "direction": "client_to_server",
                        "payload": "request",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                    },
                    {
                        "protocol": "udp",
                        "direction": "server_to_client",
                        "payload": "response",
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        server_events = [event["event"] for event in result["trace"][1]["events"]]
        self.assertEqual(server_events, ["SERVER_CONNECTED", "SERVER_DATA"])
        self.assertFalse(any("unexpected-init" in log for log in result["trace"][1]["events"][0]["logs"]))

    def test_ftp_packet_controls_and_connection_lifecycle(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    FTP::allow_active_mode enable
    FTP::enforce_tls_session_reuse enable
    FTP::ftps_mode require
    FTP::port 5000 5999
}
when CLIENT_DATA {
    log local0. "client mode=[FTP::ftps_mode] active=[FTP::allow_active_mode] reuse=[FTP::enforce_tls_session_reuse]"
}
when SERVER_CONNECTED {
    FTP::port 6000 6099
}
when SERVER_DATA {
    log local0. "server mode=[FTP::ftps_mode]"
}
""",
                "packets": [
                    {
                        "protocol": "ftp",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "198.51.100.20", "port": 21},
                        "type": "command",
                        "command": "USER",
                        "payload": "USER alice\r\n",
                    },
                    {
                        "protocol": "ftp",
                        "direction": "server_to_client",
                        "source": {"address": "198.51.100.20", "port": 21},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "type": "response",
                        "response_code": 331,
                        "payload_hex": "333331204e656564206163636f756e7420666f7220616c6963650d0a",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        client_data = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLIENT_DATA"
        )
        server_data = next(
            event
            for event in result["trace"][1]["events"]
            if event["event"] == "SERVER_DATA"
        )
        self.assertTrue(any("client mode=require active=enable reuse=enable" in line
                            for line in client_data["logs"]))
        self.assertEqual(client_data["state"]["ftp"]["port_first"], "5000")
        self.assertEqual(server_data["state"]["ftp"]["type"], "response")
        self.assertEqual(server_data["state"]["ftp"]["response_code"], "331")
        self.assertEqual(server_data["state"]["ftp"]["port_first"], "6000")
        self.assertEqual(server_data["state"]["ftp"]["port_last"], "6099")

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_DATA { FTP::disable }",
                "packets": [
                    {"protocol": "ftp", "payload": "first"},
                    {"protocol": "ftp", "payload": "second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(disabled["trace"][0]["disabled"])
        self.assertEqual(disabled["trace"][1]["ignored"], "FTP processing is disabled")

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "FIRST must not exceed LAST"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_ACCEPTED { FTP::port 6000 5000 }",
                    "packets": [{"protocol": "ftp", "payload": "noop"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "must use payload or payload_hex"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{
                        "protocol": "ftp",
                        "payload": "text",
                        "payload_hex": "74657874",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_icap_request_response_events_and_headers(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "ICAP"],
                "irule": """
when ICAP_REQUEST {
    log local0. "method=[ICAP::method] uri=[ICAP::uri] host=[ICAP::header value Host] count=[ICAP::header count]"
    ICAP::header replace Host icap.internal
    ICAP::header add X-Trace enabled
    ICAP::uri icap://icap.internal/reqmod
}
when ICAP_RESPONSE {
    log local0. "status=[ICAP::status] trace=[ICAP::header value X-Trace]"
    ICAP::header remove X-Trace
}
""",
                "packets": [
                    {
                        "protocol": "icap",
                        "source": {"address": "192.0.2.10", "port": 41000},
                        "destination": {"address": "198.51.100.20", "port": 1344},
                        "type": "request",
                        "method": "REQMOD",
                        "uri": "icap://icap.example.net/reqmod",
                        "headers": {"Host": "icap.example.net", "Allow": "204"},
                        "payload": "REQMOD body",
                    },
                    {
                        "protocol": "icap",
                        "direction": "server_to_client",
                        "source": {"address": "198.51.100.20", "port": 1344},
                        "destination": {"address": "192.0.2.10", "port": 41000},
                        "type": "response",
                        "status": 204,
                        "headers": {"X-Trace": "enabled", "ISTag": "v1"},
                        "payload_hex": "",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "ICAP_REQUEST"
        )
        response_event = next(
            event
            for event in result["trace"][1]["events"]
            if event["event"] == "ICAP_RESPONSE"
        )
        self.assertTrue(any("method=REQMOD" in line and "count=2" in line
                            for line in request_event["logs"]))
        self.assertEqual(request_event["state"]["icap"]["uri"], "icap://icap.internal/reqmod")
        self.assertIn("X-Trace", request_event["state"]["icap"]["headers"])
        self.assertTrue(any("status=204 trace=enabled" in line for line in response_event["logs"]))
        self.assertNotIn("X-Trace", response_event["state"]["icap"]["headers"])
        self.assertIn("ICAP_REQUEST", result["registered_events"])
        self.assertIn("ICAP_RESPONSE", result["registered_events"])

    def test_starttls_protocol_controls_and_packet_state(self) -> None:
        for protocol, namespace, port in (
            ("imap", "IMAP", 143),
            ("pop3", "POP3", 110),
            ("ldap", "LDAP", 389),
            ("smtps", "SMTPS", 587),
        ):
            result = self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": f"""
when CLIENT_ACCEPTED {{
    {namespace}::activation_mode require
    {namespace}::enable
}}
""",
                    "packets": [
                        {
                            "protocol": protocol,
                            "source": {"address": "192.0.2.10", "port": 40000},
                            "destination": {"address": "198.51.100.20", "port": port},
                            "type": "command",
                            "command": "STARTTLS",
                            "tls_active": False,
                            "payload": "STARTTLS\r\n",
                        },
                        {
                            "protocol": protocol,
                            "direction": "server_to_client",
                            "source": {"address": "198.51.100.20", "port": port},
                            "destination": {"address": "192.0.2.10", "port": 40000},
                            "type": "response",
                            "command": "OK Begin TLS negotiation now",
                            "tls_active": True,
                            "payload": "OK\r\n",
                        },
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
            client_event = next(
                event
                for event in result["trace"][0]["events"]
                if event["event"] == "CLIENT_DATA"
            )
            server_event = next(
                event
                for event in result["trace"][1]["events"]
                if event["event"] == "SERVER_DATA"
            )
            self.assertEqual(client_event["state"][protocol]["activation_mode"], "require")
            self.assertEqual(client_event["state"][protocol]["enabled"], "1")
            self.assertEqual(client_event["state"][protocol]["command"], "STARTTLS")
            self.assertEqual(client_event["state"][protocol]["tls_active"], "0")
            self.assertEqual(client_event["state"][protocol]["payload"], "STARTTLS\r\n")
            self.assertEqual(server_event["state"][protocol]["type"], "response")
            self.assertEqual(server_event["state"][protocol]["tls_active"], "1")
            self.assertEqual(
                server_event["state"][protocol]["command"],
                "OK Begin TLS negotiation now",
            )

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { IMAP::disable }",
                "packets": [
                    {"protocol": "imap", "payload": "first"},
                    {"protocol": "imap", "payload": "second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(disabled["trace"][0]["ignored"], "IMAP processing is disabled")
        self.assertTrue(disabled["trace"][0]["disabled"])
        self.assertEqual(disabled["trace"][1]["ignored"], "IMAP processing is disabled")

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "LDAP::activation_mode is not valid during CLIENT_DATA",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { LDAP::activation_mode allow }",
                    "packets": [{"protocol": "ldap", "payload": "bind"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "POP3::activation_mode requires none, allow, or require",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_ACCEPTED { POP3::activation_mode opportunistic }",
                    "packets": [{"protocol": "pop3", "payload": "+OK"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "IMAP responses must be server_to_client",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{
                        "protocol": "imap",
                        "type": "response",
                        "command": "bad direction",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "LDAP command exceeds 65536 bytes",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{
                        "protocol": "ldap",
                        "command": "x" * 65537,
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "SMTPS payload exceeds 2097152 bytes",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { log local0. ok }",
                    "packets": [{
                        "protocol": "smtps",
                        "payload": "x" * (2 * 1024 * 1024 + 1),
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_ntlm_and_protocol_inspection_packet_controls(self) -> None:
        enabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { NTLM::enable }
""",
                "packets": [
                    {"protocol": "ntlm", "payload_hex": "4e544c4d"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        ntlm_event = next(
            event
            for event in enabled["trace"][0]["events"]
            if event["event"] == "CLIENT_DATA"
        )
        self.assertEqual(ntlm_event["state"]["ntlm"]["enabled"], "1")
        self.assertEqual(ntlm_event["state"]["ntlm"]["payload"], "NTLM")
        self.assertEqual(ntlm_event["state"]["ntlm"]["payload_length"], "4")

        reopened = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { NTLM::enable }",
                "packets": [
                    {"protocol": "ntlm", "payload": "closed", "flags": ["FIN"]},
                    {"protocol": "ntlm", "payload": "fresh"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertIn(
            "CLIENT_CLOSED",
            [event["event"] for event in reopened["trace"][0]["events"]],
        )
        accepted_events = [
            event
            for packet in reopened["trace"]
            for event in packet["events"]
            if event["event"] == "CLIENT_ACCEPTED"
        ]
        self.assertEqual(len(accepted_events), 2)
        self.assertEqual(reopened["trace"][1]["events"][-1]["event"], "CLIENT_DATA")

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { NTLM::disable }",
                "packets": [
                    {"protocol": "ntlm", "payload": "first"},
                    {"protocol": "ntlm", "payload": "second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(disabled["trace"][0]["ignored"], "NTLM processing is disabled")
        self.assertTrue(disabled["trace"][0]["disabled"])
        self.assertEqual(disabled["trace"][1]["ignored"], "NTLM processing is disabled")

        inspection = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "PROTOCOL_INSPECTION"],
                "irule": """
when PROTOCOL_INSPECTION_MATCH {
    log local0. "ids=[PROTOCOL_INSPECTION::id]"
    PROTOCOL_INSPECTION::disable
}
""",
                "packets": [
                    {
                        "protocol": "protocol_inspection",
                        "ids": ["tls handshake", "http"],
                        "matched": True,
                        "payload": "candidate",
                    },
                    {
                        "protocol": "protocol_inspection",
                        "ids": ["later"],
                        "matched": True,
                        "payload": "not inspected",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        match_event = next(
            event
            for event in inspection["trace"][0]["events"]
            if event["event"] == "PROTOCOL_INSPECTION_MATCH"
        )
        self.assertEqual(
            match_event["state"]["protocol_inspection"]["ids"],
            '{"tls handshake" "http"}',
        )
        self.assertTrue(any('ids={"tls handshake" "http"}' in line for line in match_event["logs"]))
        self.assertEqual(inspection["trace"][0]["inspection_ids"], '{"tls handshake" "http"}')
        self.assertTrue(inspection["trace"][0]["disabled"])
        self.assertEqual(
            inspection["trace"][1]["ignored"],
            "protocol inspection is disabled",
        )

        unmatched = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "PROTOCOL_INSPECTION"],
                "irule": "when PROTOCOL_INSPECTION_MATCH { log local0. matched }",
                "packets": [{
                    "protocol": "protocol_inspection",
                    "matched": False,
                    "ids": ["signature"],
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            unmatched["trace"][0]["ignored"],
            "protocol inspection packet did not match",
        )
        self.assertNotIn(
            "PROTOCOL_INSPECTION_MATCH",
            [event["event"] for event in unmatched["trace"][0]["events"]],
        )

        gated = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when PROTOCOL_INSPECTION_MATCH { log local0. matched }",
                "packets": [{"protocol": "protocol_inspection", "matched": True}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            gated["trace"][0]["ignored"],
            "PROTOCOL_INSPECTION profile is not attached",
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "PROTOCOL_INSPECTION packets must be client_to_server",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "PROTOCOL_INSPECTION"],
                    "irule": "when PROTOCOL_INSPECTION_MATCH { return }",
                    "packets": [{
                        "protocol": "protocol_inspection",
                        "direction": "server_to_client",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "PROTOCOL_INSPECTION id exceeds 4096 bytes",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "PROTOCOL_INSPECTION"],
                    "irule": "when PROTOCOL_INSPECTION_MATCH { return }",
                    "packets": [{
                        "protocol": "protocol_inspection",
                        "ids": ["x" * 4097],
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "NTLM payload exceeds 2 MiB",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_DATA { return }",
                    "packets": [{
                        "protocol": "ntlm",
                        "payload": "x" * (2 * 1024 * 1024 + 1),
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_classification_packet_results_and_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLASSIFICATION"],
                "irule": """
when CLIENT_ACCEPTED { CLASSIFICATION::enable }
when CLASSIFICATION_DETECTED {
    log local0. "app=[CLASSIFICATION::app] category=[CLASSIFICATION::category] protocol=[CLASSIFICATION::protocol] result=[CLASSIFICATION::result] urlcat=[CLASSIFICATION::urlcat] user=[CLASSIFICATION::username]"
    CLASSIFICATION::disable
}
""",
                "packets": [
                    {
                        "protocol": "classification",
                        "app": "streaming",
                        "category": "media",
                        "classification_protocol": "https",
                        "result": ["streaming", "media"],
                        "urlcat": "entertainment",
                        "username": "alice",
                        "payload": "classified request",
                    },
                    {
                        "protocol": "classification",
                        "app": "later",
                        "detected": True,
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        detected_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLASSIFICATION_DETECTED"
        )
        classification_state = detected_event["state"]["classification"]
        self.assertEqual(classification_state["app"], "streaming")
        self.assertEqual(classification_state["category"], "media")
        self.assertEqual(classification_state["protocol"], "https")
        self.assertEqual(classification_state["result"], '{"streaming" "media"}')
        self.assertEqual(classification_state["urlcat"], "entertainment")
        self.assertEqual(classification_state["username"], "alice")
        self.assertEqual(classification_state["detected"], "1")
        self.assertEqual(
            result["trace"][0]["classification_result"],
            '{"streaming" "media"}',
        )
        self.assertTrue(result["trace"][0]["disabled"])
        self.assertEqual(result["trace"][1]["ignored"], "classification is disabled")

        undetected = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLASSIFICATION"],
                "irule": "when CLASSIFICATION_DETECTED { return }",
                "packets": [{
                    "protocol": "classification",
                    "detected": False,
                    "app": "not-used",
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            undetected["trace"][0]["ignored"],
            "classification packet was not detected",
        )
        self.assertNotIn(
            "CLASSIFICATION_DETECTED",
            [event["event"] for event in undetected["trace"][0]["events"]],
        )

        gated = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CLASSIFICATION_DETECTED { return }",
                "packets": [{"protocol": "classification"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            gated["trace"][0]["ignored"],
            "CLASSIFICATION profile is not attached",
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CLASSIFICATION packets must be client_to_server unless deferred",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CLASSIFICATION"],
                    "irule": "when CLASSIFICATION_DETECTED { return }",
                    "packets": [{
                        "protocol": "classification",
                        "direction": "server_to_client",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CLASSIFICATION result cannot contain empty strings",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CLASSIFICATION"],
                    "irule": "when CLASSIFICATION_DETECTED { return }",
                    "packets": [{
                        "protocol": "classification",
                        "result": [""],
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_classify_controls_overlay_results_disable_and_defer(self) -> None:
        add_session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["HTTP", "CLASSIFICATION"],
                "irule": """
when HTTP_REQUEST {
    CLASSIFY::application add manual-app
    CLASSIFY::urlcat add manual-urlcat
    CLASSIFY::category add manual-category
    CLASSIFY::username alice auth-context
}
when CLASSIFICATION_DETECTED {
    log local0. "app=[CLASSIFICATION::app] category=[CLASSIFICATION::category] urlcat=[CLASSIFICATION::urlcat] result=[CLASSIFICATION::result] user=[CLASSIFICATION::username]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            add_session.fire_event("HTTP_REQUEST", {})
            detected = add_session.fire_event(
                "CLASSIFICATION_DETECTED",
                {
                    "classification": {
                        "app": "engine-app",
                        "category": "engine-category",
                        "protocol": "https",
                        "result": '"engine-app" "engine-category"',
                        "urlcat": "engine-urlcat",
                    }
                },
            )
            repeated = add_session.fire_event(
                "CLASSIFICATION_DETECTED",
                {"classification": {
                    "app": "later-app",
                    "result": '"later-app"',
                }},
            )
        finally:
            add_session.close()
        classification_state = detected["state"]["classification"]
        self.assertEqual(classification_state["app"], "engine-app")
        self.assertEqual(classification_state["category"], "engine-category")
        self.assertEqual(classification_state["urlcat"], "engine-urlcat")
        self.assertEqual(
            classification_state["result"],
            "engine-app engine-category manual-app manual-urlcat manual-category",
        )
        self.assertEqual(classification_state["username"], "alice")
        self.assertTrue(any("manual-app" in str(log) for log in detected["logs"]))
        self.assertEqual(
            repeated["state"]["classification"]["result"], '"later-app"'
        )

        set_session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["HTTP", "CLASSIFICATION"],
                "irule": """
when HTTP_REQUEST { CLASSIFY::application set forced-app }
when CLASSIFICATION_DETECTED { log local0. "app=[CLASSIFICATION::app] result=[CLASSIFICATION::result]" }
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            set_session.fire_event("HTTP_REQUEST", {})
            forced = set_session.fire_event(
                "CLASSIFICATION_DETECTED",
                {"classification": {
                    "app": "engine-app",
                    "result": '"engine-app" "engine-category"',
                }},
            )
        finally:
            set_session.close()
        self.assertEqual(forced["state"]["classification"]["app"], "forced-app")
        self.assertEqual(forced["state"]["classification"]["result"], "forced-app")

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLASSIFICATION"],
                "irule": "when CLIENT_ACCEPTED { CLASSIFY::disable } when CLASSIFICATION_DETECTED { return }",
                "packets": [{"protocol": "classification"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(disabled["trace"][0]["ignored"], "classification is disabled")
        self.assertTrue(disabled["trace"][0]["disabled"])

        deferred = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "FLOW", "CLASSIFICATION"],
                "irule": "when FLOW_INIT { CLASSIFY::defer } when CLASSIFICATION_DETECTED { log local0. \"deferred=[CLASSIFICATION::result]\" }",
                "packets": [{
                    "protocol": "classification",
                    "direction": "server_to_client",
                    "deferred": True,
                    "result": ["response-app"],
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        deferred_event = next(
            event for event in deferred["trace"][0]["events"]
            if event["event"] == "CLASSIFICATION_DETECTED"
        )
        self.assertTrue(deferred_event["fired"])
        self.assertEqual(
            deferred_event["state"]["classification"]["deferred"], "1"
        )
        self.assertEqual(
            deferred["trace"][0]["classification_result"], '{"response-app"}'
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CLASSIFY::application is not valid during CLASSIFICATION_DETECTED",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CLASSIFICATION"],
                    "irule": "when CLASSIFICATION_DETECTED { CLASSIFY::application add too-late }",
                    "packets": [{"protocol": "classification"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_category_packet_match_lookup_and_filetype(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CATEGORY"],
                "irule": """
when CATEGORY_MATCHED {
    CATEGORY::matchtype match_type
    set result [CATEGORY::result category -display request_default_and_custom]
    set first_category [lindex $result 1]
    set safe [CATEGORY::result safesearch]
    log local0. "type=$match_type result=$result first=$first_category safe=$safe"
}
""",
                "packets": [
                    {
                        "protocol": "category",
                        "url": "https://example.test/watch?q=1",
                        "categories": ["/Common/Media", "Sports & Video"],
                        "safesearch": ["safe_key", "strict"],
                        "matchtype": "custom",
                        "filetype": {"mimetype": "text", "mimesubtype": "html"},
                        "payload": "category payload",
                    },
                    {"protocol": "category", "matched": False},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        matched_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CATEGORY_MATCHED"
        )
        category_state = matched_event["state"]["category"]
        self.assertEqual(
            category_state["categories"], '"/Common/Media" "Sports & Video"'
        )
        self.assertEqual(category_state["safesearch"], '"safe_key" "strict"')
        self.assertEqual(category_state["matchtype"], "custom")
        self.assertEqual(category_state["matched"], "1")
        self.assertEqual(category_state["detected"], "1")
        self.assertEqual(category_state["url"], "https://example.test/watch?q=1")
        self.assertEqual(
            category_state["lookup_url"], "https://example.test/watch?q=1"
        )
        self.assertEqual(category_state["filetype_mimetype"], "text")
        self.assertEqual(category_state["filetype_mimesubtype"], "html")
        self.assertEqual(category_state["analytics"], "disable")
        self.assertEqual(category_state["payload"], "category payload")
        self.assertEqual(
            result["trace"][0]["category_result"], category_state["categories"]
        )
        self.assertEqual(
            result["trace"][0]["safesearch_result"], category_state["safesearch"]
        )
        self.assertTrue(
            any("type=custom" in str(log) and "first=Sports & Video" in str(log)
                and "safe_key" in str(log)
                for log in matched_event["logs"])
        )
        self.assertEqual(result["trace"][1]["ignored"], "category packet did not match")

        request_session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["HTTP", "CATEGORY"],
                "irule": """
when HTTP_REQUEST {
    set lookup [CATEGORY::lookup https://lookup.example.test/path -display custom -ip 192.0.2.10 -custom_cat_match custom-category]
    set safe [CATEGORY::safesearch https://safe.example.test/search]
    CATEGORY::analytics enable
    log local0. "lookup=$lookup safe=$safe"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            request_event = request_session.fire_event(
                "HTTP_REQUEST",
                {"category": {
                    "categories": '"Custom Category"',
                    "safesearch": "safe_key strict",
                }},
            )
        finally:
            request_session.close()
        request_category_state = request_event["state"]["category"]
        self.assertEqual(request_category_state["analytics"], "enable")
        self.assertEqual(
            request_category_state["lookup_url"], "https://safe.example.test/search"
        )
        self.assertTrue(any("lookup=" in str(log) and "Custom Category" in str(log)
                            and "safe=safe_key strict" in str(log)
                            for log in request_event["logs"]))

        filetype_session = self.adapter.EmulatorSession(
            self.tcl_lsp_root,
            {
                "profiles": ["HTTP", "CATEGORY"],
                "irule": """
when HTTP_RESPONSE_DATA {
    CATEGORY::filetype payload -mimetype mime -mimesubtype subtype
    log local0. "mime=$mime subtype=$subtype"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            filetype_event = filetype_session.fire_event(
                "HTTP_RESPONSE_DATA",
                {"category": {
                    "filetype_mimetype": "application",
                    "filetype_mimesubtype": "json",
                }},
            )
        finally:
            filetype_session.close()
        self.assertTrue(any("mime=application subtype=json" in str(log)
                            for log in filetype_event["logs"]))

        gated = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when CATEGORY_MATCHED { return }",
                "packets": [{"protocol": "category"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            gated["trace"][0]["ignored"], "CATEGORY profile is not attached"
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CATEGORY packets must be client_to_server",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CATEGORY"],
                    "irule": "when CATEGORY_MATCHED { return }",
                    "packets": [{
                        "protocol": "category",
                        "direction": "server_to_client",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CATEGORY safesearch cannot contain empty strings",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CATEGORY"],
                    "irule": "when CATEGORY_MATCHED { return }",
                    "packets": [{"protocol": "category", "safesearch": [""]}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "CATEGORY filetype must contain mimetype and/or mimesubtype",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "CATEGORY"],
                    "irule": "when CATEGORY_MATCHED { return }",
                    "packets": [{"protocol": "category", "filetype": {}}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_post_tmos_17_5_features_are_reported_and_rejected(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "introduced after TMOS 17.5"
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": 'when HTTP_REQUEST { JSON::parse "{}" }',
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
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
        self.assertEqual(usage["ASM::status"]["runtime_status"], "semantic-mock")
        warning_codes = {warning["code"] for warning in report["warnings"]}
        self.assertIn("profile-gated-event", warning_codes)

    def test_asm_policy_state_getters_collections_and_actions(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM", "FASTHTTP"],
                "asm": {
                    "policy": "/Common/asm-policy",
                    "client_ip": "203.0.113.9",
                    "fingerprint": "fp-123",
                    "username": "alice",
                    "login_status": "logged_in",
                    "microservice": "*a/login.php",
                    "status": "Blocked",
                    "severity": "Error",
                    "support_id": "SUP-42",
                    "captcha_status": "correct",
                    "captcha_age": 35,
                    "payload": "configured-body",
                    "violations": [
                        {
                            "name": "VIOLATION_ILLEGAL_PARAMETER",
                            "attack_type": "Parameter Tampering",
                            "rating": "Error",
                            "details": {"param_data.param_name": "dGVzdA=="},
                        }
                    ],
                    "signatures": {
                        "ids": ["200000001"],
                        "names": ["Illegal parameter"],
                        "set_names": ["Default"],
                        "staged_ids": ["300000001"],
                        "staged_names": ["Staged"],
                        "staged_set_names": ["StagedSet"],
                    },
                    "threat_campaigns": {
                        "names": ["campaign-a"],
                        "staged_names": ["campaign-b"],
                    },
                },
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  log local0. \"asm ip=[ASM::client_ip] fp=[ASM::fingerprint] user=[ASM::username]\"\n"
                    "  log local0. \"auth=[ASM::is_authenticated] login=[ASM::login_status] micro=[ASM::microservice]\"\n"
                    "  log local0. \"policy=[ASM::policy] status=[ASM::status] severity=[ASM::severity] support=[ASM::support_id]\"\n"
                    "  log local0. \"captcha_status=[ASM::captcha_status] age=[ASM::captcha_age] count=[ASM::violation count]\"\n"
                    "  log local0. \"names=[ASM::violation names] attacks=[ASM::violation attack_types] rating=[ASM::violation rating]\"\n"
                    "  log local0. \"details=[ASM::violation details] signatures=[ASM::signature ids] campaigns=[ASM::threat_campaign names]\"\n"
                    "  log local0. \"vdata=[ASM::violation_data] captcha=[ASM::captcha]\"\n"
                    "  ASM::unblock\n"
                    "  ASM::uncaptcha\n"
                    "  ASM::conviction\n"
                    "  ASM::deception\n"
                    "  ASM::payload replace 0 3 BAD\n"
                    "  ASM::raise CUSTOM_VIOLATION {field value}\n"
                    "  log local0. \"after status=[ASM::status] count=[ASM::violation count] payload=[ASM::payload]\"\n"
                    "}"
                ),
                "request": {"uri": "/login", "body": "bad-body"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(any("ip=203.0.113.9 fp=fp-123 user=alice" in log for log in logs))
        self.assertTrue(any("auth=1 login=logged_in micro=*a/login.php" in log for log in logs))
        self.assertTrue(any("policy=/Common/asm-policy status=Blocked severity=Error support=SUP-42" in log for log in logs))
        self.assertTrue(any("captcha_status=correct age=35 count=1" in log for log in logs))
        self.assertTrue(any("names=VIOLATION_ILLEGAL_PARAMETER" in log for log in logs))
        self.assertTrue(any("captcha=nok asm blocked request" in log for log in logs))
        self.assertTrue(any("after status=Alarm count=2 payload=BAD-body" in log for log in logs))

        asm = result["results"][0]["semantic"]["asm"]
        self.assertEqual(asm["client_ip"], "203.0.113.9")
        self.assertEqual(asm["status"], "Alarm")
        self.assertEqual(asm["payload"], "BAD-body")
        self.assertEqual(asm["signatures"]["ids"], ["200000001"])
        self.assertEqual(asm["threat_campaigns"]["names"], ["campaign-a"])
        self.assertTrue(asm["uncaptcha"])
        self.assertTrue(asm["unblocked"])
        self.assertTrue(asm["conviction"])
        self.assertTrue(asm["deception"])
        self.assertEqual([item["name"] for item in asm["violations"]], [
            "VIOLATION_ILLEGAL_PARAMETER",
            "CUSTOM_VIOLATION",
        ])

    def test_asm_request_and_connection_state_resets(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM", "FASTHTTP"],
                "asm": {"policy": "/Common/default", "status": "Clear", "payload": "seed"},
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  if {[HTTP::uri] eq \"/disable\"} { ASM::disable }\n"
                    "  if {[HTTP::uri] eq \"/enable\"} { ASM::enable /Common/override }\n"
                    "  if {[HTTP::uri] eq \"/raise\"} { ASM::raise REQUEST_VIOLATION }\n"
                    "  log local0. \"uri=[HTTP::uri] enabled=[ASM::status] policy=[ASM::policy] count=[ASM::violation count] payload=[ASM::payload]\"\n"
                    "}"
                ),
                "requests": [
                    {"uri": "/disable"},
                    {"uri": "/enable"},
                    {"uri": "/raise"},
                    {"uri": "/fresh", "new_connection": True},
                    {"uri": "/empty", "body": ""},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        snapshots = [item["semantic"]["asm"] for item in result["results"]]
        self.assertFalse(snapshots[0]["enabled"])
        self.assertEqual(snapshots[0]["policy"], "")
        self.assertTrue(snapshots[1]["enabled"])
        self.assertEqual(snapshots[1]["policy"], "/Common/override")
        self.assertEqual(snapshots[2]["violations"][0]["name"], "REQUEST_VIOLATION")
        self.assertEqual(snapshots[3]["policy"], "/Common/default")
        self.assertEqual(snapshots[3]["violations"], [])
        self.assertEqual(snapshots[3]["payload"], "seed")
        self.assertEqual(snapshots[4]["payload"], "")

    def test_http_access_lifecycle_events_follow_policy_and_connection_state(self) -> None:
        allowed = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {"acl_result": "Allow"},
                "irule": (
                    "when ACCESS_SESSION_STARTED { log local0. started }\n"
                    "when ACCESS_POLICY_AGENT_EVENT { log local0. agent }\n"
                    "when ACCESS_PER_REQUEST_AGENT_EVENT { log local0. perrequest }\n"
                    "when ACCESS_POLICY_COMPLETED { log local0. completed }\n"
                    "when ACCESS_ACL_ALLOWED { log local0. allowed }\n"
                    "when ACCESS_SESSION_CLOSED { log local0. closed }\n"
                    "when HTTP_REQUEST { log local0. request }"
                ),
                "request": {"uri": "/", "close_after": True},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            allowed["results"][0]["events_fired"],
            [
                "CLIENT_ACCEPTED",
                "ACCESS_SESSION_STARTED",
                "ACCESS_POLICY_AGENT_EVENT",
                "HTTP_REQUEST",
                "ACCESS_PER_REQUEST_AGENT_EVENT",
                "ACCESS_POLICY_COMPLETED",
                "LB_SELECTED",
                "ACCESS_ACL_ALLOWED",
                "CLIENT_CLOSED",
                "ACCESS_SESSION_CLOSED",
            ],
        )
        self.assertTrue(any("started" in log for log in allowed["results"][0]["logs"]))

        denied = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {"acl_result": "Reject"},
                "irule": (
                    "when ACCESS_ACL_DENIED { log local0. denied }\n"
                    "when HTTP_REQUEST { log local0. request }"
                ),
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertIn(
            "ACCESS_ACL_DENIED",
            denied["results"][0]["events_fired"],
        )
        self.assertTrue(any("denied" in log for log in denied["results"][0]["logs"]))

    def test_http_asm_request_events_follow_violation_and_blocking_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {
                    "policy": "/Common/waf",
                    "status": "Blocked",
                    "severity": "Critical",
                    "support_id": "support-1",
                    "violations": [
                        {
                            "name": "VIOLATION_ATTACK",
                            "attack_type": "SQL-INJECTION",
                            "rating": "Critical",
                            "details": {"parameter": "id"},
                        }
                    ],
                },
                "irule": (
                    "when ASM_REQUEST_VIOLATION { "
                    "log local0. \"violation=[ASM::violation count]/[ASM::status]\" }\n"
                    "when ASM_REQUEST_DONE { "
                    "log local0. \"done=[ASM::status]/[ASM::support_id]\"; "
                    "ASM::unblock }\n"
                    "when ASM_REQUEST_BLOCKING { log local0. should-not-run }"
                ),
                "request": {"uri": "/blocked", "body": "id=1"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            item["events_fired"],
            ["HTTP_REQUEST", "ASM_REQUEST_VIOLATION", "ASM_REQUEST_DONE"],
        )
        self.assertTrue(any("violation=1/Blocked" in log for log in item["logs"]))
        self.assertTrue(any("done=Blocked/support-1" in log for log in item["logs"]))
        self.assertFalse(any("should-not-run" in log for log in item["logs"]))
        self.assertEqual(item["semantic"]["asm"]["status"], "Alarm")

        clear = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "irule": "when ASM_REQUEST_DONE { log local0. clear }",
                "request": {"uri": "/clear"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            clear["results"][0]["events_fired"],
            ["HTTP_REQUEST", "ASM_REQUEST_DONE"],
        )

    def test_http_asm_response_violation_follows_http_response_and_rewrites_response(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {
                    "policy": "/Common/waf",
                    "support_id": "response-support-1",
                    "response_violations": [
                        {
                            "name": "VIOLATION_RESPONSE_SCRUBBING",
                            "attack_type": "Information Leakage",
                            "rating": "Error",
                            "details": {"response": "secret"},
                        }
                    ],
                },
                "irule": (
                    "when HTTP_RESPONSE { "
                    'log local0. "http=[HTTP::status]" }\n'
                    "when ASM_RESPONSE_VIOLATION { "
                    'log local0. "asm=[ASM::violation count]/[ASM::status]/[ASM::payload]"; '
                    "HTTP::header insert X-ASM-Response seen; "
                    'ASM::payload replace 0 [ASM::payload length] "scrubbed" }'
                ),
                "request": {
                    "uri": "/response",
                    "response_status": 200,
                    "response_headers": {"X-Origin": "yes"},
                    "response_body": "secret",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        events = item["events_fired"]
        self.assertLess(
            events.index("HTTP_RESPONSE"),
            events.index("ASM_RESPONSE_VIOLATION"),
        )
        self.assertEqual(item["response"]["body"], "scrubbed")
        self.assertEqual(item["response"]["headers"]["x-asm-response"], "seen")
        self.assertTrue(
            any("asm=1/Alarm/secret" in entry for entry in item["logs"])
        )
        self.assertEqual(item["semantic"]["asm"]["violations"][0]["name"], "VIOLATION_RESPONSE_SCRUBBING")

        utf8 = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {
                    "response_violations": [{"name": "VIOLATION_UTF8"}],
                },
                "irule": (
                    "when ASM_RESPONSE_VIOLATION { "
                    'log local0. "length=[ASM::payload length]"; '
                    'ASM::payload replace 1 2 "X" }'
                ),
                "request": {"uri": "/utf8", "response_body": "héllo"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        utf8_item = utf8["results"][0]
        self.assertTrue(any("length=6" in entry for entry in utf8_item["logs"]))
        self.assertEqual(utf8_item["response"]["body"], "hXllo")

        for login_status in ("logged_in", "failed"):
            with self.subTest(login_status=login_status):
                login = self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP", "ASM"],
                        "asm": {
                            "username": "alice",
                            "response_login": {
                                "enabled": True,
                                "status": login_status,
                            },
                        },
                        "irule": (
                            "when ASM_RESPONSE_LOGIN { "
                            'log local0. "login=[ASM::username]/[ASM::login_status]"; '
                            "HTTP::header insert X-Login-Status [ASM::login_status] }"
                        ),
                        "request": {
                            "uri": "/login",
                            "response_body": "login-response",
                        },
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
                login_item = login["results"][0]
                self.assertEqual(
                    login_item["events_fired"],
                    ["HTTP_RESPONSE", "ASM_RESPONSE_LOGIN"],
                )
                self.assertTrue(
                    any(
                        f"login=alice/{login_status}" in entry
                        for entry in login_item["logs"]
                    )
                )
                self.assertEqual(
                    login_item["response"]["headers"]["x-login-status"],
                    login_status,
                )

        no_response_violation = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {},
                "irule": "when ASM_RESPONSE_VIOLATION { log local0. unexpected }",
                "request": {"uri": "/clear", "response_body": "clean"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn(
            "ASM_RESPONSE_VIOLATION",
            no_response_violation["results"][0]["events_fired"],
        )

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {
                    "enabled": False,
                    "response_violations": [
                        {"name": "VIOLATION_RESPONSE_SCRUBBING"}
                    ],
                },
                "irule": "when ASM_RESPONSE_VIOLATION { log local0. unexpected }",
                "request": {"uri": "/disabled", "response_body": "clean"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn(
            "ASM_RESPONSE_VIOLATION",
            disabled["results"][0]["events_fired"],
        )

        both_sides = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "asm": {
                    "status": "Blocked",
                    "violations": [{"name": "VIOLATION_REQUEST"}],
                    "response_violations": [{"name": "VIOLATION_RESPONSE"}],
                },
                "irule": (
                    "when ASM_REQUEST_VIOLATION { log local0. request }\n"
                    "when ASM_REQUEST_DONE { log local0. done }\n"
                    "when ASM_RESPONSE_VIOLATION { log local0. response }"
                ),
                "request": {"uri": "/both", "response_body": "body"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        both_events = both_sides["results"][0]["events_fired"]
        self.assertEqual(both_events.count("ASM_REQUEST_VIOLATION"), 1)
        self.assertEqual(both_events.count("ASM_REQUEST_DONE"), 1)
        self.assertEqual(both_events.count("ASM_RESPONSE_VIOLATION"), 1)
        self.assertLess(
            both_events.index("ASM_REQUEST_DONE"),
            both_events.index("ASM_RESPONSE_VIOLATION"),
        )

    def test_asm_input_validation_rejects_unsafe_or_ambiguous_values(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP", "ASM"],
            "irule": "when HTTP_REQUEST { ASM::status }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "asm.enabled must be a boolean"),
            ({"client_ip": "not-an-ip"}, "not a valid IPv4 or IPv6 address"),
            ({"status": []}, "asm.status must be a string without NUL"),
            ({"login_status": {}}, "asm.login_status must be a string without NUL"),
            ({"response_login": []}, "asm.response_login must be an object"),
            (
                {"response_login": {"enabled": "yes"}},
                "asm.response_login.enabled must be a boolean",
            ),
            (
                {"response_login": {"status": "pending"}},
                "asm.response_login.status must be one of: failed, logged_in",
            ),
            (
                {"response_login": {"username": "bad\x00value"}},
                "asm.response_login.username must be a string without NUL",
            ),
            ({"captcha_age": -2}, "asm.captcha_age must be an integer"),
            ({"violations": [{"name": "x", "details": ["bad"]}]}, "details must be an object"),
            ({"response_violations": [{"name": "x", "details": ["bad"]}]}, "details must be an object"),
            ({"signatures": {"ids": ["bad\x00value"]}}, "array of strings without NUL"),
            ({"unknown": True}, "asm unsupported field"),
        )
        for asm, message in invalid_cases:
            scenario = dict(base)
            scenario["asm"] = asm
            with self.subTest(asm=asm):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_botdefense_policy_state_getters_and_overrides(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "BOTDEFENSE"],
                "botdefense": {
                    "action": "allow",
                    "bot_anomalies": ["OAT", "automation"],
                    "bot_categories": ["scraping"],
                    "bot_name": "curl",
                    "bot_signature": "Headless Browser",
                    "bot_signature_category": "Automation",
                    "captcha_age": 42,
                    "captcha_status": "correct",
                    "client_class": "malicious_bot",
                    "client_type": "bot",
                    "cookie_age": 12,
                    "cookie_status": "valid",
                    "cs_allowed": True,
                    "cs_attribute_device_id": True,
                    "cs_possible": True,
                    "device_id": 123,
                    "intent": "credential_stuffing",
                    "micro_service": {"name": "login", "type": "authentication"},
                    "previous_action": "browser_challenge",
                    "previous_request_age": 7,
                    "previous_support_id": "prev-1",
                    "reason": "anomaly",
                    "support_id": "cur-1",
                },
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  log local0. \"action=[BOTDEFENSE::action] anomalies=[BOTDEFENSE::bot_anomalies] categories=[BOTDEFENSE::bot_categories]\"\n"
                    "  log local0. \"bot=[BOTDEFENSE::bot_name] sig=[BOTDEFENSE::bot_signature] sigcat=[BOTDEFENSE::bot_signature_category]\"\n"
                    "  log local0. \"captcha=[BOTDEFENSE::captcha_status] age=[BOTDEFENSE::captcha_age] cookie=[BOTDEFENSE::cookie_status] cage=[BOTDEFENSE::cookie_age]\"\n"
                    "  log local0. \"class=[BOTDEFENSE::client_class] type=[BOTDEFENSE::client_type] device=[BOTDEFENSE::device_id] intent=[BOTDEFENSE::intent]\"\n"
                    "  log local0. \"micro=[BOTDEFENSE::micro_service name]/[BOTDEFENSE::micro_service type] previous=[BOTDEFENSE::previous_action]/[BOTDEFENSE::previous_request_age]/[BOTDEFENSE::previous_support_id]\"\n"
                    "  log local0. \"reason=[BOTDEFENSE::reason] support=[BOTDEFENSE::support_id] possible=[BOTDEFENSE::cs_possible] allowed=[BOTDEFENSE::cs_allowed] attr=[BOTDEFENSE::cs_attribute device_id]\"\n"
                    "  set override [BOTDEFENSE::action block]\n"
                    "  BOTDEFENSE::cs_allowed false\n"
                    "  BOTDEFENSE::cs_attribute device_id false\n"
                    "  BOTDEFENSE::disable\n"
                    "  BOTDEFENSE::enable\n"
                    "  log local0. \"override=$override action=[BOTDEFENSE::action] allowed=[BOTDEFENSE::cs_allowed] attr=[BOTDEFENSE::cs_attribute device_id]\"\n"
                    "}\n"
                    "when BOTDEFENSE_REQUEST { log local0. botdefense-request }\n"
                    "when BOTDEFENSE_ACTION { log local0. botdefense-action }"
                ),
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertIn("BOTDEFENSE_REQUEST", result["results"][0]["events_fired"])
        self.assertIn("BOTDEFENSE_ACTION", result["results"][0]["events_fired"])
        self.assertLess(
            result["results"][0]["events_fired"].index("BOTDEFENSE_REQUEST"),
            result["results"][0]["events_fired"].index("BOTDEFENSE_ACTION"),
        )
        self.assertTrue(any("action=allow" in log for log in logs))
        self.assertTrue(any("bot=curl sig=Headless Browser sigcat=Automation" in log for log in logs))
        self.assertTrue(any("captcha=correct age=42 cookie=valid cage=12" in log for log in logs))
        self.assertTrue(any("class=malicious_bot type=bot device=123 intent=credential_stuffing" in log for log in logs))
        self.assertTrue(any("micro=login/authentication previous=browser_challenge/7/prev-1" in log for log in logs))
        self.assertTrue(any("reason=anomaly support=cur-1 possible=1 allowed=1 attr=1" in log for log in logs))
        self.assertTrue(any("override=ok action=block allowed=0 attr=0" in log for log in logs))
        botdefense = result["results"][0]["semantic"]["botdefense"]
        self.assertTrue(botdefense["enabled"])
        self.assertEqual(botdefense["action"], "block")
        self.assertTrue(botdefense["action_overridden"])
        self.assertFalse(botdefense["cs_allowed"])
        self.assertFalse(botdefense["cs_attribute_device_id"])
        self.assertEqual(botdefense["bot_anomalies"], ["OAT", "automation"])
        self.assertEqual(botdefense["bot_categories"], ["scraping"])
        self.assertEqual(botdefense["micro_service"], {"name": "login", "type": "authentication"})

    def test_botdefense_connection_state_and_input_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "BOTDEFENSE"],
                "botdefense": {"action": "allow"},
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  if {[HTTP::uri] eq \"/disable\"} { BOTDEFENSE::disable }\n"
                    "  if {[HTTP::uri] eq \"/enable\"} { BOTDEFENSE::enable }\n"
                    "  if {[HTTP::uri] eq \"/override\"} { BOTDEFENSE::action block }\n"
                    "  log local0. \"uri=[HTTP::uri] enabled=[BOTDEFENSE::action] overridden=[BOTDEFENSE::action]\"\n"
                    "}"
                ),
                "requests": [
                    {"uri": "/disable"},
                    {"uri": "/enable"},
                    {"uri": "/override"},
                    {"uri": "/fresh", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        snapshots = [item["semantic"]["botdefense"] for item in result["results"]]
        self.assertFalse(snapshots[0]["enabled"])
        self.assertTrue(snapshots[1]["enabled"])
        self.assertEqual(snapshots[2]["action"], "block")
        self.assertTrue(snapshots[2]["action_overridden"])
        self.assertEqual(snapshots[3]["action"], "allow")
        self.assertTrue(snapshots[3]["enabled"])

        base = {
            "profiles": ["TCP", "HTTP", "BOTDEFENSE"],
            "irule": "when HTTP_REQUEST { BOTDEFENSE::action }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "botdefense.enabled must be a boolean"),
            ({"captcha_status": "unknown"}, "botdefense.captcha_status must be one of"),
            ({"client_type": []}, "botdefense.client_type must be a string without NUL"),
            ({"device_id": -1}, "botdefense.device_id must be an integer"),
            ({"micro_service": {"bad": "field"}}, "unsupported field"),
        )
        for botdefense, message in invalid_cases:
            scenario = dict(base)
            scenario["botdefense"] = botdefense
            with self.subTest(botdefense=botdefense):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_antifraud_policy_state_and_automatic_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FASTHTTP", "ANTIFRAUD"],
                "antifraud": {
                    "profile": "/Common/af-profile",
                    "login": True,
                    "alert": True,
                    "client_id": "client-1",
                    "device_id": "device-1",
                    "fingerprint": "fp-1",
                    "geo": "US",
                    "guid": "guid-1",
                    "username": "configured-user",
                    "license_id": "license-7",
                    "result": "failed",
                    "fields": {
                        "alert_type": "credential_stuffing",
                        "alert_score": "42",
                        "alert_username": "alice",
                        "alert_device_id": "device-alert-1",
                    },
                },
                "irule": (
                    "when HTTP_REQUEST { ANTIFRAUD::disable; ANTIFRAUD::enable; log local0. request }\n"
                    "when ANTIFRAUD_LOGIN { "
                    "log local0. \"login=[ANTIFRAUD::username] guid=[ANTIFRAUD::guid] fp=[ANTIFRAUD::fingerprint]\"\n"
                    "ANTIFRAUD::username alias }\n"
                    "when ANTIFRAUD_ALERT { "
                    "log local0. \"alert=[ANTIFRAUD::alert_type] score=[ANTIFRAUD::alert_score] user=[ANTIFRAUD::alert_username]\"\n"
                    "ANTIFRAUD::alert_score 99 }"
                ),
                "request": {"uri": "/login"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            item["events_fired"], ["HTTP_REQUEST", "ANTIFRAUD_LOGIN", "ANTIFRAUD_ALERT"]
        )
        self.assertTrue(any("login=configured-user guid=guid-1 fp=fp-1" in log for log in item["logs"]))
        self.assertTrue(any("alert=credential_stuffing score=42 user=alice" in log for log in item["logs"]))
        antifraud = item["semantic"]["antifraud"]
        self.assertTrue(antifraud["enabled"])
        self.assertEqual(antifraud["profile"], "/Common/af-profile")
        self.assertEqual(antifraud["result"], "failed")
        self.assertEqual(antifraud["username"], "alias")
        self.assertEqual(antifraud["alert"]["alert_score"], "99")
        self.assertEqual(antifraud["alert"]["alert_device_id"], "device-alert-1")
        self.assertEqual(antifraud["alert_license_id"], "f89e256a")

    def test_antifraud_request_overrides_connection_reset_and_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FASTHTTP", "ANTIFRAUD"],
                "antifraud": {"login": False, "alert": False},
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  if {[HTTP::uri] eq \"/alert-off\"} { ANTIFRAUD::disable_alert }\n"
                    "  if {[HTTP::uri] eq \"/disable\"} { ANTIFRAUD::disable }\n"
                    "  if {[HTTP::uri] eq \"/features\"} {\n"
                    "    ANTIFRAUD::disable_app_layer_encryption\n"
                    "    ANTIFRAUD::disable_auto_transactions\n"
                    "    ANTIFRAUD::disable_injection\n"
                    "    ANTIFRAUD::disable_malware\n"
                    "    ANTIFRAUD::disable_phishing\n"
                    "    ANTIFRAUD::enable_log Debug\n"
                    "  }\n"
                    "  log local0. \"request=[HTTP::uri]\"\n"
                    "}\n"
                    "when ANTIFRAUD_LOGIN { log local0. login }\n"
                    "when ANTIFRAUD_ALERT { log local0. alert }"
                ),
                "requests": [
                    {"uri": "/alert-off", "antifraud": {"login": True, "alert": True}},
                    {"uri": "/normal", "antifraud": {"login": True, "alert": True}},
                    {"uri": "/features", "antifraud": {"login": True, "alert": True}},
                    {"uri": "/disable", "antifraud": {"login": True, "alert": True}},
                    {"uri": "/same-connection", "antifraud": {"login": True, "alert": True}},
                    {
                        "uri": "/fresh",
                        "new_connection": True,
                        "antifraud": {"login": True, "alert": True},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, normal, features, disabled, same, fresh = result["results"]
        self.assertEqual(first["events_fired"], ["HTTP_REQUEST", "ANTIFRAUD_LOGIN"])
        self.assertEqual(normal["events_fired"], ["HTTP_REQUEST", "ANTIFRAUD_LOGIN", "ANTIFRAUD_ALERT"])
        self.assertEqual(features["events_fired"], ["HTTP_REQUEST", "ANTIFRAUD_LOGIN", "ANTIFRAUD_ALERT"])
        self.assertEqual(disabled["events_fired"], ["HTTP_REQUEST"])
        self.assertEqual(same["events_fired"], ["HTTP_REQUEST"])
        self.assertEqual(fresh["events_fired"], ["HTTP_REQUEST", "ANTIFRAUD_LOGIN", "ANTIFRAUD_ALERT"])
        self.assertTrue(all(features["semantic"]["antifraud"]["disabled_features"].values()))
        self.assertEqual(features["semantic"]["antifraud"]["log_level"], "Debug")
        self.assertFalse(normal["semantic"]["antifraud"]["alert_disabled"])
        self.assertTrue(disabled["semantic"]["antifraud"]["enabled"] is False)
        self.assertTrue(same["semantic"]["antifraud"]["enabled"] is False)
        self.assertTrue(fresh["semantic"]["antifraud"]["enabled"])
        self.assertFalse(fresh["semantic"]["antifraud"]["disabled_features"]["malware"])

    def test_antifraud_input_validation(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP", "FASTHTTP", "ANTIFRAUD"],
            "irule": "when HTTP_REQUEST { ANTIFRAUD::result }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "antifraud.enabled must be a boolean"),
            ({"result": "unknown"}, "antifraud.result must be one of"),
            ({"fields": {"alert_score": 7}}, "antifraud.fields.alert_score must be a string without NUL"),
            ({"fields": {"not_a_field": "x"}}, "unsupported field"),
        )
        for antifraud, message in invalid_cases:
            scenario = dict(base)
            scenario["antifraud"] = antifraud
            with self.subTest(antifraud=antifraud):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_authentication_session_success_and_response_data(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "AUTH"],
                "auth": {
                    "type": "pam",
                    "service": "default_radius",
                    "ldap_status": "success",
                    "ldap_username": "alice",
                    "response_data": {"user": "alice", "role": "admin"},
                },
                "irule": (
                    "when CLIENT_ACCEPTED { "
                    "set ::auth_id [AUTH::start pam default_radius]; "
                    "AUTH::subscribe $::auth_id; "
                    "AUTH::username_credential $::auth_id alice"
                    "}\n"
                    "when HTTP_REQUEST { "
                    "AUTH::password_credential $::auth_id secret; "
                    "AUTH::authenticate $::auth_id"
                    "}\n"
                    "when AUTH_RESULT { "
                    "log local0. \"result=[AUTH::status $::auth_id] "
                    "data=[AUTH::response_data $::auth_id] "
                    "id=[AUTH::last_event_session_id]\""
                    "}\n"
                    "when AUTH_SUCCESS { "
                    "log local0. \"success=[AUTH::status] "
                    "ldap=[AUTH::ssl_cc_ldap_username $::auth_id] "
                    "prompt=[AUTH::wantcredential_prompt $::auth_id]\""
                    "}"
                ),
                "request": {"uri": "/login"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        events = item["events_fired"]
        self.assertIn("AUTH_RESULT", events)
        self.assertIn("AUTH_SUCCESS", events)
        self.assertLess(events.index("AUTH_RESULT"), events.index("AUTH_SUCCESS"))
        self.assertTrue(any("result=0 data=user alice role admin id=auth-1" in log for log in item["logs"]))
        self.assertTrue(any("success=0 ldap=alice prompt=Password:" in log for log in item["logs"]))
        auth = item["semantic"]["auth"]
        self.assertTrue(auth["enabled"])
        self.assertEqual(auth["session_count"], 1)
        self.assertEqual(auth["last_event_session_id"], "auth-1")
        self.assertEqual(auth["last_event"], "AUTH_SUCCESS")
        self.assertEqual(auth["sessions"], [{
            "id": "auth-1",
            "valid": True,
            "status": 0,
            "in_progress": False,
            "subscribed": True,
            "last_event": "AUTH_SUCCESS",
        }])

    def test_authentication_wantcredential_continuation_and_connection_reset(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "AUTH"],
                "auth": {
                    "result": "wantcredential",
                    "credential_type": "otp",
                    "prompt": "Token:",
                    "prompt_style": "echo_on",
                },
                "irule": (
                    "when CLIENT_ACCEPTED { "
                    "set ::auth_id [AUTH::start pam radius]; "
                    "AUTH::subscribe $::auth_id"
                    "}\n"
                    "when HTTP_REQUEST { AUTH::authenticate $::auth_id }\n"
                    "when AUTH_WANTCREDENTIAL { "
                    "log local0. \"want=[AUTH::wantcredential_type $::auth_id] "
                    "prompt=[AUTH::wantcredential_prompt $::auth_id] "
                    "style=[AUTH::wantcredential_prompt_style $::auth_id]\"; "
                    "AUTH::authenticate_continue $::auth_id 123456"
                    "}\n"
                    "when AUTH_RESULT { log local0. \"status=[AUTH::status]\" }\n"
                    "when AUTH_SUCCESS { log local0. continued }"
                ),
                "requests": [
                    {"uri": "/first"},
                    {"uri": "/fresh", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, fresh = result["results"]
        for item in (first, fresh):
            events = item["events_fired"]
            self.assertIn("AUTH_WANTCREDENTIAL", events)
            self.assertIn("AUTH_RESULT", events)
            self.assertIn("AUTH_SUCCESS", events)
            self.assertLess(events.index("AUTH_WANTCREDENTIAL"), events.index("AUTH_RESULT"))
            self.assertLess(events.index("AUTH_RESULT"), events.index("AUTH_SUCCESS"))
            self.assertTrue(any("want=otp prompt=Token: style=echo_on" in log for log in item["logs"]))
            self.assertTrue(any("status=0" in log for log in item["logs"]))
            self.assertEqual(item["semantic"]["auth"]["sessions"][0]["id"], "auth-1")
            self.assertEqual(item["semantic"]["auth"]["sessions"][0]["status"], 0)

    def test_authentication_failure_error_and_abort_outcomes(self) -> None:
        for configured_result, event_name, status in (
            ("failure", "AUTH_FAILURE", 1),
            ("error", "AUTH_ERROR", -1),
        ):
            with self.subTest(result=configured_result):
                result = self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP", "AUTH"],
                        "auth": {"result": configured_result},
                        "irule": (
                            "when CLIENT_ACCEPTED { set ::auth_id [AUTH::start pam radius] }\n"
                            "when HTTP_REQUEST { AUTH::authenticate $::auth_id }\n"
                            f"when {event_name} {{ log local0. \"status=[AUTH::status $::auth_id]\" }}"
                        ),
                        "request": {"uri": "/login"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
                item = result["results"][0]
                self.assertIn(event_name, item["events_fired"])
                self.assertTrue(any(f"status={status}" in log for log in item["logs"]))
                self.assertEqual(item["semantic"]["auth"]["sessions"][0]["status"], status)

        aborted = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "AUTH"],
                "auth": {"result": "wantcredential"},
                "irule": (
                    "when CLIENT_ACCEPTED { set ::auth_id [AUTH::start pam radius] }\n"
                    "when HTTP_REQUEST { AUTH::authenticate $::auth_id }\n"
                    "when AUTH_WANTCREDENTIAL { AUTH::abort $::auth_id }\n"
                    "when AUTH_FAILURE { log local0. \"aborted=[AUTH::status]\" }"
                ),
                "request": {"uri": "/abort"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        item = aborted["results"][0]
        self.assertIn("AUTH_WANTCREDENTIAL", item["events_fired"])
        self.assertIn("AUTH_FAILURE", item["events_fired"])
        self.assertTrue(any("aborted=1" in log for log in item["logs"]))
        session = item["semantic"]["auth"]["sessions"][0]
        self.assertFalse(session["valid"])
        self.assertEqual(session["status"], 1)
        self.assertEqual(session["last_event"], "AUTH_FAILURE")

    def test_authentication_input_validation(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP", "AUTH"],
            "irule": "when HTTP_REQUEST { AUTH::start pam radius }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "auth.enabled must be a boolean"),
            ({"result": "unknown"}, "auth.result must be one of"),
            ({"prompt_style": "silent"}, "auth.prompt_style must be one of"),
            ({"response_data": ["user", "alice"]}, "auth.response_data must be an object"),
            ({"response_data": {"": "alice"}}, "auth.response_data keys must be non-empty strings"),
            ({1: "invalid-field-name"}, "auth field names must be strings"),
        )
        for auth, message in invalid_cases:
            scenario = dict(base)
            scenario["auth"] = auth
            with self.subTest(auth=auth):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        scenario = dict(base)
        scenario["request"] = {"uri": "/", "antifraud": {"login": "yes"}}
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "request.antifraud.login must be a boolean"
        ):
            self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_aaa_authentication_and_accounting_requests(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "aaa": {"auth_result": "OK", "acct_result": "INPROGRESS"},
                "irule": (
                    "when HTTP_REQUEST {\n"
                    "  set ::auth_request [AAA::auth_send /Common/aaa alice secret]\n"
                    "  set ::acct_request [AAA::acct_send /Common/aaa user-name alice acct-session-id sid]\n"
                    "  log local0. \"auth=[AAA::auth_result $::auth_request] "
                    "acct=[AAA::acct_result $::acct_request]\"\n"
                    "}"
                ),
                "request": {"uri": "/aaa"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertTrue(any("auth=OK acct=INPROGRESS" in log for log in item["logs"]))
        aaa = item["semantic"]["aaa"]
        self.assertTrue(aaa["enabled"])
        self.assertEqual(aaa["request_count"], 2)
        self.assertEqual(aaa["requests"], [
            {
                "id": "aaa-1",
                "kind": "auth",
                "result": "OK",
                "valid": True,
                "virtual_server": "/Common/aaa",
                "username": "alice",
            },
            {
                "id": "aaa-2",
                "kind": "acct",
                "result": "INPROGRESS",
                "valid": True,
                "virtual_server": "/Common/aaa",
                "username": "alice",
            },
        ])
        self.assertNotIn("secret", json.dumps(aaa))

    def test_aaa_result_branches_reset_and_input_validation(self) -> None:
        for configured_result in ("FAIL", "ERROR"):
            with self.subTest(result=configured_result):
                result = self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "aaa": {"auth_result": configured_result},
                        "irule": (
                            "when HTTP_REQUEST { "
                            "set ::request_id [AAA::auth_send /Common/aaa alice]; "
                            "log local0. \"result=[AAA::auth_result $::request_id]\" }"
                        ),
                        "request": {"uri": "/aaa"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
                item = result["results"][0]
                self.assertTrue(any(f"result={configured_result}" in log for log in item["logs"]))

        reset = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "aaa": {"auth_result": "OK"},
                "irule": (
                    "when HTTP_REQUEST { "
                    "set ::request_id [AAA::auth_send /Common/aaa alice]; "
                    "log local0. \"request=$::request_id\" }"
                ),
                "requests": [
                    {"uri": "/same"},
                    {"uri": "/fresh", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("request=aaa-1" in log for log in reset["results"][0]["logs"]))
        self.assertTrue(any("request=aaa-1" in log for log in reset["results"][1]["logs"]))
        self.assertEqual(reset["results"][1]["semantic"]["aaa"]["request_count"], 1)

        base = {
            "profiles": ["TCP", "HTTP"],
            "irule": "when HTTP_REQUEST { AAA::auth_send /Common/aaa alice }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "aaa.enabled must be a boolean"),
            ({"auth_result": "unknown"}, "aaa.auth_result must be one of"),
            ({"acct_result": []}, "aaa.acct_result must be a string without NUL"),
            ({1: "invalid-field-name"}, "aaa field names must be strings"),
        )
        for aaa, message in invalid_cases:
            scenario = dict(base)
            scenario["aaa"] = aaa
            with self.subTest(aaa=aaa):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_access_sessions_policy_acl_and_perflow(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {
                    "acl_result": "Reject",
                    "acl_lookup": ["/Common/web", "/Common/admin"],
                    "acl_matched": ["/Common/admin"],
                    "policy_result": "deny",
                    "policy_agent_id": "logon-agent",
                    "policy_uri": True,
                    "session_data": {
                        "session.logon.last.username": "alice",
                        "session.logon.last.password": "secret",
                    },
                    "perflow": {"perflow.custom": "seed"},
                },
                "irule": (
                    "when CLIENT_ACCEPTED { "
                    "set ::access_sid [ACCESS::session create -flow -timeout 600 -lifetime 3600]; "
                    "ACCESS::flowid test-flow; "
                    "ACCESS::perflow set perflow.custom changed "
                    "}\n"
                    "when HTTP_REQUEST { "
                    "ACCESS::acl eval /Common/admin; "
                    "ACCESS::policy evaluate -sid $::access_sid -profile /Common/access "
                    "session.logon.last.username alice; "
                    "log local0. \"sid=[ACCESS::session sid] "
                    "exists=[ACCESS::session exists -sid $::access_sid] "
                    "allowed=[ACCESS::session exists -sid $::access_sid -state_allow] "
                    "acl=[ACCESS::acl result] "
                    "perflow=[ACCESS::perflow get perflow.custom] "
                    "flow=[ACCESS::flowid] "
                    "policy=[ACCESS::policy result -sid $::access_sid]\" "
                    "}\n"
                    "when ACCESS_SESSION_STARTED { log local0. \"started=[ACCESS::session sid]\" }\n"
                    "when ACCESS_POLICY_COMPLETED { log local0. \"completed=[ACCESS::policy result]\" }"
                ),
                "request": {"uri": "/protected", "close_after": True},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertIn("ACCESS_SESSION_STARTED", item["events_fired"])
        self.assertIn("ACCESS_POLICY_COMPLETED", item["events_fired"])
        self.assertTrue(any("started=sid-1" in log for log in item["logs"]))
        self.assertTrue(any("completed=deny" in log for log in item["logs"]))
        self.assertTrue(any("sid=sid-1 exists=TRUE allowed=FALSE" in log for log in item["logs"]))
        self.assertTrue(any("acl=Reject perflow=changed flow=test-flow policy=deny" in log for log in item["logs"]))
        access = item["semantic"]["access"]
        self.assertEqual(access["session_count"], 1)
        self.assertEqual(access["current_sid"], "sid-1")
        self.assertEqual(access["acl_evaluated"], ["/Common/admin"])
        self.assertEqual(access["perflow"]["perflow.custom"], "changed")
        self.assertEqual(access["sessions"][0]["state"], "deny")
        self.assertEqual(access["sessions"][0]["data"]["session.logon.last.username"], "alice")
        self.assertEqual(access["sessions"][0]["data"]["session.logon.last.password"], "<redacted>")
        self.assertNotIn("secret", json.dumps(item["semantic"]))

    def test_access_ephemeral_auth_respond_and_session_close(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "irule": (
                    "when CLIENT_ACCEPTED { "
                    "set ::access_sid [ACCESS::session create -flow] "
                    "}\n"
                    "when HTTP_REQUEST { "
                    "set ::ephemeral [ACCESS::ephemeral-auth create -user bob -sid $::access_sid]; "
                    "set ::verified [ACCESS::ephemeral-auth verify -user bob "
                    "-password $::ephemeral -protocol http]; "
                    "ACCESS::session data set -sid $::access_sid session.logon.last.password secret; "
                    "ACCESS::saml assertion assertion-value; "
                    "ACCESS::restrict_irule_events disable; "
                    "ACCESS::disable; "
                    "ACCESS::respond 403 content denied; "
                    "ACCESS::session remove -sid $::access_sid; "
                    "log local0. \"verified=$::verified\" "
                    "}\n"
                    "when ACCESS_SESSION_CLOSED { "
                    "log local0. \"closed=[ACCESS::session exists -sid $::access_sid]\" "
                    "}"
                ),
                "request": {"uri": "/ephemeral"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(item["response"]["status"], 403)
        self.assertEqual(item["response"]["body"], "denied")
        self.assertIn("ACCESS_SESSION_STARTED", item["events_fired"])
        self.assertIn("ACCESS_SESSION_CLOSED", item["events_fired"])
        self.assertTrue(any("verified=sid-1" in log for log in item["logs"]))
        self.assertTrue(any("closed=TRUE" in log for log in item["logs"]))
        access = item["semantic"]["access"]
        self.assertEqual(access["session_count"], 0)
        self.assertFalse(access["request_enabled"])
        self.assertFalse(access["restrict_irule_events"])
        self.assertEqual(access["saml"]["assertion"], "assertion-value")
        self.assertNotIn("temporary-password", json.dumps(item))
        self.assertNotIn("secret", json.dumps(item))

    def test_access_input_validation(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP", "ACCESS"],
            "irule": "when HTTP_REQUEST { ACCESS::enable }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "access.enabled must be a boolean"),
            ({"acl_result": "allow"}, "access.acl_result must be one of"),
            ({"policy_result": "permit"}, "access.policy_result must be one of"),
            ({"policy_uri": 1}, "access.policy_uri must be a boolean"),
            ({"acl_lookup": "not-a-list"}, "access.acl_lookup must be an array of strings"),
            ({"session_data": ["key", "value"]}, "access.session_data must be an object"),
            ({"ephemeral_auth_password": ""}, "access.ephemeral_auth_password must not be empty"),
            ({"saml": "not-an-object"}, "access.saml must be an object"),
            ({"saml": {"unknown": "value"}}, r"access.saml unsupported field\(s\): unknown"),
            ({"saml": {"authn": 7}}, "access.saml.authn must be a string without NUL"),
            ({1: "invalid-field-name"}, "access field names must be strings"),
        )
        for access, message in invalid_cases:
            scenario = dict(base)
            scenario["access"] = access
            with self.subTest(access=access):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        request_invalid_cases = (
            ({"acl_result": "deny"}, "request.access.acl_result must be one of"),
            ({"policy_uri": 1}, "request.access.policy_uri must be a boolean"),
            ({"acl_lookup": "not-a-list"}, "request.access.acl_lookup must be an array of strings"),
            ({"unsupported": True}, r"request.access unsupported field\(s\): unsupported"),
        )
        for access, message in request_invalid_cases:
            scenario = dict(base)
            scenario["requests"] = [{"uri": "/", "access": access}]
            scenario.pop("request", None)
            with self.subTest(request_access=access):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_http_access_lifecycle_creates_session_and_emits_ordered_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {
                    "acl_lookup": ["/Common/web"],
                    "acl_matched": ["/Common/web"],
                    "session_data": {"session.logon.last.username": "alice"},
                },
                "irule": (
                    "when HTTP_REQUEST { ACCESS::acl eval /Common/web }\n"
                    "when ACCESS_SESSION_STARTED { log local0. \"started=[ACCESS::session sid]\" }\n"
                    "when ACCESS_POLICY_AGENT_EVENT { log local0. \"agent=[ACCESS::session sid]\" }\n"
                    "when ACCESS_PER_REQUEST_AGENT_EVENT { log local0. \"per-request=[ACCESS::session sid]\" }\n"
                    "when ACCESS_POLICY_COMPLETED { log local0. \"policy=[ACCESS::policy result]\" }\n"
                    "when ACCESS_ACL_ALLOWED { log local0. \"allowed=[ACCESS::session sid]\" }"
                ),
                "request": {"uri": "/protected", "close_after": True},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        lifecycle = [
            event
            for event in item["events_fired"]
            if event
            in {
                "ACCESS_SESSION_STARTED",
                "ACCESS_POLICY_AGENT_EVENT",
                "ACCESS_PER_REQUEST_AGENT_EVENT",
                "ACCESS_POLICY_COMPLETED",
                "ACCESS_ACL_ALLOWED",
                "ACCESS_SESSION_CLOSED",
            }
        ]
        self.assertEqual(
            lifecycle,
            [
                "ACCESS_SESSION_STARTED",
                "ACCESS_POLICY_AGENT_EVENT",
                "ACCESS_PER_REQUEST_AGENT_EVENT",
                "ACCESS_POLICY_COMPLETED",
                "ACCESS_ACL_ALLOWED",
                "ACCESS_SESSION_CLOSED",
            ],
        )
        self.assertTrue(any("started=sid-1" in entry for entry in item["logs"]))
        self.assertTrue(any("agent=sid-1" in entry for entry in item["logs"]))
        self.assertTrue(any("per-request=sid-1" in entry for entry in item["logs"]))
        self.assertTrue(any("policy=allow" in entry for entry in item["logs"]))
        self.assertTrue(any("allowed=sid-1" in entry for entry in item["logs"]))
        self.assertEqual(item["semantic"]["access"]["session_count"], 1)
        self.assertEqual(item["semantic"]["access"]["acl_evaluated"], ["/Common/web"])

    def test_http_access_request_override_emits_acl_denial(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {"acl_result": "Allow"},
                "irule": "when ACCESS_ACL_DENIED { ACCESS::respond 451 content blocked }",
                "requests": [
                    {
                        "uri": "/blocked",
                        "access": {
                            "acl_result": "Reject",
                            "acl_lookup": ["/Common/deny"],
                        },
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertIn("ACCESS_ACL_DENIED", item["events_fired"])
        self.assertEqual(item["response"]["status"], 451)
        self.assertEqual(item["response"]["body"], "blocked")
        self.assertEqual(item["semantic"]["access"]["acl_result"], "Reject")
        self.assertEqual(item["semantic"]["access"]["acl_evaluated"], ["/Common/deny"])

    def test_http_access_agent_events_follow_session_and_keepalive_multiplicity(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "irule": (
                    "when ACCESS_POLICY_AGENT_EVENT { log local0. \"policy-agent\" }\n"
                    "when ACCESS_PER_REQUEST_AGENT_EVENT { log local0. \"per-request\" }\n"
                    "when ACCESS_POLICY_COMPLETED { log local0. \"policy-complete\" }\n"
                    "when ACCESS_ACL_ALLOWED { log local0. \"acl\" }"
                ),
                "requests": [{"uri": "/one"}, {"uri": "/two"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second = result["results"]
        self.assertEqual(
            [event for event in first["events_fired"] if event.startswith("ACCESS_")],
            [
                "ACCESS_SESSION_STARTED",
                "ACCESS_POLICY_AGENT_EVENT",
                "ACCESS_PER_REQUEST_AGENT_EVENT",
                "ACCESS_POLICY_COMPLETED",
                "ACCESS_ACL_ALLOWED",
            ],
        )
        self.assertEqual(
            [event for event in second["events_fired"] if event.startswith("ACCESS_")],
            ["ACCESS_PER_REQUEST_AGENT_EVENT", "ACCESS_ACL_ALLOWED"],
        )
        self.assertEqual(first["semantic"]["access"]["session_count"], 1)
        self.assertEqual(second["semantic"]["access"]["session_count"], 1)
        self.assertEqual(sum("policy-agent" in log for log in first["logs"]), 1)
        self.assertEqual(sum("policy-complete" in log for log in first["logs"]), 1)
        self.assertEqual(sum("per-request" in log for log in first["logs"]), 1)
        self.assertTrue(any("per-request" in log for log in second["logs"]))

    def test_http_access_saml_fixtures_emit_authentication_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {
                    "saml": {
                        "authn": "<AuthnRequest>mock</AuthnRequest>",
                        "assertion": "<Assertion>mock</Assertion>",
                    }
                },
                "irule": (
                    "when ACCESS_SAML_AUTHN { log local0. \"authn=[ACCESS::saml authn]\" }\n"
                    "when ACCESS_SAML_ASSERTION { log local0. \"assertion=[ACCESS::saml assertion]\" }"
                ),
                "request": {"uri": "/sso"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            [event for event in item["events_fired"] if event.startswith("ACCESS_SAML_")],
            ["ACCESS_SAML_AUTHN", "ACCESS_SAML_ASSERTION"],
        )
        self.assertTrue(any("authn=<AuthnRequest>mock</AuthnRequest>" in log for log in item["logs"]))
        self.assertTrue(any("assertion=<Assertion>mock</Assertion>" in log for log in item["logs"]))
        self.assertEqual(
            item["semantic"]["access"]["saml"],
            {
                "authn": "<AuthnRequest>mock</AuthnRequest>",
                "assertion": "<Assertion>mock</Assertion>",
                "slo_req": "",
                "slo_resp": "",
            },
        )

    def test_access_saml_slo_fixtures_are_available_to_direct_events(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["ACCESS"],
                "access": {
                    "saml": {
                        "slo_req": "<LogoutRequest>fixture</LogoutRequest>",
                        "slo_resp": "<LogoutResponse>fixture</LogoutResponse>",
                    }
                },
                "irule": (
                    "when ACCESS_SAML_SLO_REQ { log local0. \"req=[ACCESS::saml slo_req]\" }\n"
                    "when ACCESS_SAML_SLO_RESP { log local0. \"resp=[ACCESS::saml slo_resp]\" }"
                ),
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            request_event = session.fire_event("ACCESS_SAML_SLO_REQ")
            response_event = session.fire_event("ACCESS_SAML_SLO_RESP")
            self.assertTrue(request_event["fired"])
            self.assertTrue(response_event["fired"])
            self.assertTrue(any("req=<LogoutRequest>fixture</LogoutRequest>" in log for log in request_event["logs"]))
            self.assertTrue(any("resp=<LogoutResponse>fixture</LogoutResponse>" in log for log in response_event["logs"]))
        finally:
            session.close()

    def test_http_access_saml_slo_fixtures_emit_logout_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {
                    "saml": {
                        "slo_req": "<LogoutRequest>fixture</LogoutRequest>",
                        "slo_resp": "<LogoutResponse>fixture</LogoutResponse>",
                    }
                },
                "irule": (
                    "when ACCESS_SAML_SLO_REQ { "
                    "set value [ACCESS::saml slo_req]; "
                    "ACCESS::saml slo_req \"${value}|changed\"; "
                    "log local0. \"req=[ACCESS::saml slo_req]\" }\n"
                    "when ACCESS_SAML_SLO_RESP { "
                    "set value [ACCESS::saml slo_resp]; "
                    "ACCESS::saml slo_resp \"${value}|changed\"; "
                    "log local0. \"resp=[ACCESS::saml slo_resp]\" }"
                ),
                "request": {"uri": "/logout"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            [event for event in item["events_fired"] if event.startswith("ACCESS_SAML_")],
            ["ACCESS_SAML_SLO_REQ", "ACCESS_SAML_SLO_RESP"],
        )
        self.assertTrue(any("req=<LogoutRequest>fixture</LogoutRequest>|changed" in log for log in item["logs"]))
        self.assertTrue(any("resp=<LogoutResponse>fixture</LogoutResponse>|changed" in log for log in item["logs"]))
        self.assertEqual(
            item["semantic"]["access"]["saml"],
            {
                "authn": "",
                "assertion": "",
                "slo_req": "<LogoutRequest>fixture</LogoutRequest>|changed",
                "slo_resp": "<LogoutResponse>fixture</LogoutResponse>|changed",
            },
        )

    def test_http_access_saml_events_repeat_for_a_new_session_on_one_connection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access": {"saml": {"authn": "authn-fixture"}},
                "irule": (
                    "when HTTP_REQUEST { "
                    "if {![info exists ::request_count]} { set ::request_count 0 }; "
                    "incr ::request_count; "
                    "if {$::request_count == 2} { ACCESS::session remove; ACCESS::session create -flow }"
                    " }\n"
                    "when ACCESS_SAML_AUTHN { log local0. \"authn=[ACCESS::saml authn]\" }"
                ),
                "requests": [{"uri": "/one"}, {"uri": "/two"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            sum(item["events_fired"].count("ACCESS_SAML_AUTHN") for item in result["results"]),
            2,
        )
        self.assertEqual(
            [item["semantic"]["access"]["current_sid"] for item in result["results"]],
            ["sid-1", "sid-2"],
        )

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

    def test_istats_persist_across_requests_and_support_remove(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set count_key {app counter requests}
    set status_key {app string status}
    set gauge_key {app /service gauge active}
    set missing_string_key {app string missing}
    set missing_counter_key {app counter missing}
    if {[HTTP::path] eq "/remove"} {
        ISTATS::remove $count_key
    } else {
        ISTATS::incr $count_key 1
        ISTATS::set $status_key ready
        ISTATS::set $gauge_key 3
        ISTATS::incr $gauge_key -1
    }
    log local0. "count=[ISTATS::get $count_key] status=[ISTATS::get $status_key] gauge=[ISTATS::get $gauge_key] missing=[ISTATS::get $missing_string_key] zero=[ISTATS::get $missing_counter_key]"
}
""",
                "requests": [
                    {"uri": "/one"},
                    {"uri": "/two"},
                    {"uri": "/remove"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second, removed = result["results"]
        self.assertEqual(first["semantic"]["istats"], {
            "count": 3,
            "values": {
                "app counter requests": "1",
                "app string status": "ready",
                "app /service gauge active": "2",
            },
        })
        self.assertEqual(second["semantic"]["istats"]["values"]["app counter requests"], "2")
        self.assertEqual(removed["semantic"]["istats"], {
            "count": 2,
            "values": {
                "app string status": "ready",
                "app /service gauge active": "2",
            },
        })
        self.assertTrue(any("missing= zero=0" in entry for entry in first["logs"]))
        self.assertTrue(any("count=0 status=ready gauge=2" in entry for entry in removed["logs"]))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("ISTATS::get", "ISTATS::incr", "ISTATS::remove", "ISTATS::set"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "counter value must be non-negative"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": 'when HTTP_REQUEST { ISTATS::incr "app counter bad" -1 }',
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_crypto_hash_sign_verify_and_validate_options(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set digest [CRYPTO::hash -alg sha256 hello]
    set signature [CRYPTO::sign -alg hmac-sha256 -key secret hello]
    set hex_signature [CRYPTO::sign -alg hmac-sha256 -keyhex 736563726574 hello]
    set stream_partial [CRYPTO::hash -alg sha256 -ctx digest_ctx he]
    set stream_middle [CRYPTO::hash -ctx digest_ctx llo]
    set stream_digest [CRYPTO::hash -ctx digest_ctx -final]
    CRYPTO::sign -alg hmac-sha256 -ctx sign_ctx -key secret he
    CRYPTO::sign -ctx sign_ctx llo
    set stream_signature [CRYPTO::sign -ctx sign_ctx -final]
    CRYPTO::verify -alg hmac-sha256 -ctx verify_ctx -key secret he
    CRYPTO::verify -ctx verify_ctx llo
    set stream_valid [CRYPTO::verify -ctx verify_ctx -final -signature $stream_signature]
    log local0. "hash=[b64encode $digest] signature=[b64encode $signature] hex=[b64encode $hex_signature] valid=[CRYPTO::verify -alg hmac-sha256 -key secret -signature $signature hello] invalid=[CRYPTO::verify -alg hmac-sha256 -key secret -signature $signature changed] stream=[b64encode $stream_digest] partial=<$stream_partial><$stream_middle> stream_valid=$stream_valid"
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertTrue(any(
                "hash=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" in entry
                and "signature=iKqz7ejTrflNJquQ07r9SiCDBww7zOnAFO4EpEOEfAs=" in entry
                and "hex=iKqz7ejTrflNJquQ07r9SiCDBww7zOnAFO4EpEOEfAs=" in entry
                and "valid=1 invalid=0" in entry
                and "stream=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" in entry
                and "partial=<><>" in entry
                and "stream_valid=1" in entry
                for entry in result["results"][0]["logs"]
            ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("CRYPTO::hash", "CRYPTO::sign", "CRYPTO::verify"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule, message in (
            ('when HTTP_REQUEST { CRYPTO::sign -alg hmac-sha256 hello }', "requires -key"),
            ('when HTTP_REQUEST { CRYPTO::verify -alg hmac-sha256 -key secret hello }', "requires -signature"),
            ('when HTTP_REQUEST { CRYPTO::hash hello }', "requires -alg"),
            ('when HTTP_REQUEST { CRYPTO::hash -alg sha256 -final hello }', "-final requires -ctx"),
            ('when HTTP_REQUEST { CRYPTO::hash -alg sha256 -key secret hello }', "does not accept a key"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_crypto_encrypt_decrypt_keygen_and_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set keyhex 000102030405060708090a0b0c0d0e0f
    set ivhex 101112131415161718191a1b1c1d1e1f
    set encrypted [CRYPTO::encrypt -alg aes-128-cbc -keyhex $keyhex -ivhex $ivhex "hello crypto"]
    set decrypted [CRYPTO::decrypt -alg aes-128-cbc -keyhex $keyhex -ivhex $ivhex $encrypted]
    set ecb [CRYPTO::encrypt -alg aes-128-ecb -keyhex $keyhex "ecb"]
    set ecb_plain [CRYPTO::decrypt -alg aes-128-ecb -keyhex $keyhex $ecb]
    CRYPTO::encrypt -alg aes-128-cfb -ctx cipher_ctx -keyhex $keyhex -ivhex $ivhex hello
    set streamed [CRYPTO::encrypt -ctx cipher_ctx -final " crypto"]
    set rc4 [CRYPTO::encrypt -alg rc4 -key secret "stream data"]
    set rc4_plain [CRYPTO::decrypt -alg rc4 -key secret $rc4]
    set random_key [CRYPTO::keygen -alg random -len 128]
    set derived_one [CRYPTO::keygen -alg pbkdf2-md5 -len 128 -passphrase pass -salthex 73616c74 -rounds 2]
    set derived_two [CRYPTO::keygen -alg pbkdf2-md5 -len 128 -passphrase pass -salthex 73616c74 -rounds 2]
    set rsa_keys [CRYPTO::keygen -alg rsa -len 1024]
    set rsa_cipher [CRYPTO::encrypt -alg rsa-pub -padding oaep -key [lindex $rsa_keys 0] "rsa message"]
    set rsa_plain [CRYPTO::decrypt -alg rsa-priv -padding oaep -key [lindex $rsa_keys 1] $rsa_cipher]
    log local0. "plain=$decrypted ecb=$ecb_plain stream=[b64encode $streamed] rc4=$rc4_plain random_len=[string length $random_key] derived_equal=[expr {$derived_one eq $derived_two}] rsa=$rsa_plain"
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "plain=hello crypto" in entry
            and "ecb=ecb" in entry
            and "rc4=stream data" in entry
            and "random_len=16" in entry
            and "derived_equal=1" in entry
            and "rsa=rsa message" in entry
            for entry in result["results"][0]["logs"]
        ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("CRYPTO::decrypt", "CRYPTO::encrypt", "CRYPTO::keygen"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule in (
            'when HTTP_REQUEST { CRYPTO::encrypt -alg rc2-mode -key secret hello }',
            'when HTTP_REQUEST { CRYPTO::encrypt -alg aes-128-cwc -key secret hello }',
            'when HTTP_REQUEST { CRYPTO::encrypt -alg aes-128-cbc -key short hello }',
            'when HTTP_REQUEST { CRYPTO::encrypt -alg aes-128-cbc -keyhex 000102030405060708090a0b0c0d0e0f -iv {} hello }',
            'when HTTP_REQUEST { CRYPTO::decrypt -alg rsa-pub -key invalid hello }',
            'when HTTP_REQUEST { CRYPTO::keygen -alg random -len 7 }',
            'when HTTP_REQUEST { CRYPTO::keygen -alg pbkdf2-md5 -len 128 }',
            'when HTTP_REQUEST { CRYPTO::hash -alg sha256 -ctx collision hello; CRYPTO::encrypt -alg rc4 -ctx collision -key secret hello }',
        ):
            with self.subTest(irule=irule), self.assertRaises(self.adapter.EmulatorInputError):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_asn1_element_encode_decode_and_payload_replacement(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set ::state::connection::client_payload [binary format H* 30080201020403686579]
    set root [ASN1::element init BER]
    set version [ASN1::element next $root]
    set message [ASN1::element next $version]
    set decoded [ASN1::decode $root "(ia)" number value]
    set primitive_count [ASN1::decode $version i version_value]
    set optional_encoded [ASN1::encode DER "?ia" "" payload]
    set optional_count [ASN1::decode $optional_encoded "?ia" missing payload_value]
    ASN1::encode replace $root 2 i 3
    set root_after [ASN1::element init DER]
    log local0. "decoded=$decoded number=$number value=$value primitive=$primitive_count/$version_value optional=$optional_count/[info exists missing]/$payload_value tag=[ASN1::element tag $message] size=[ASN1::element size $root] offset=[ASN1::element byte_offset $message] length=[ASN1::element length $root_after] payload=[b64encode [TCP::payload]]"
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "decoded=2 number=2 value=hey" in entry
            and "primitive=1/2" in entry
            and "optional=1/0/payload" in entry
            and "tag=4" in entry
            and "size=10" in entry
            and "offset=5" in entry
            and "length=8" in entry
            and "payload=MAgCAQMEA2hleQ==" in entry
            for entry in result["results"][0]["logs"]
        ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("ASN1::decode", "ASN1::element", "ASN1::encode"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule, message in (
            ('when HTTP_REQUEST { ASN1::encode DER i not-an-integer }', "ASN1 integer value must be an integer"),
            ('when HTTP_REQUEST { set ::state::connection::client_payload {}; ASN1::element init DER }', "ASN1 payload must not be empty"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_ilx_init_call_notify_and_connection_scope(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set handle [ILX::init telemetry plugin]
    set echo [ILX::call $handle echo "hello world"]
    set sum [ILX::call $handle -timeout 25 sum 2 3]
    set queued [ILX::notify $handle event payload]
    log local0. "handle=$handle echo=$echo sum=$sum queued=$queued"
}
""",
                "requests": [{"uri": "/one"}, {"uri": "/two", "close_before": True}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "handle=ilx:1 echo=hello world sum=5 queued=0" in entry
            for entry in result["results"][0]["logs"]
        ))
        self.assertTrue(any(
            "handle=ilx:1 echo=hello world sum=5 queued=0" in entry
            for entry in result["results"][1]["logs"]
        ))
        first_semantic = result["results"][0]["semantic"]["ilx"]
        second_semantic = result["results"][1]["semantic"]["ilx"]
        self.assertEqual(first_semantic["handles"], [{
            "handle": "ilx:1", "plugin": "telemetry", "extension": "plugin",
        }])
        self.assertEqual(first_semantic["calls"][1]["timeout_ms"], 25)
        self.assertEqual(first_semantic["calls"][1]["args"], ["2", "3"])
        self.assertEqual(first_semantic["notifies"][0]["args"], ["payload"])
        self.assertEqual(second_semantic["handles"], [{
            "handle": "ilx:1", "plugin": "telemetry", "extension": "plugin",
        }])

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("ILX::call", "ILX::init", "ILX::notify"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule, message in (
            (
                "when RULE_INIT { set h [ILX::init plugin extension] }",
                "ILX::init is not valid during RULE_INIT",
            ),
            (
                "when HTTP_REQUEST { set h [ILX::init plugin extension]; ILX::call $h -timeout -1 echo x }",
                "ILX::call timeout must be a non-negative integer",
            ),
            (
                "when HTTP_REQUEST { ILX::call ilx:missing echo x }",
                "ILX::call received an invalid ILX handle",
            ),
            (
                "when HTTP_REQUEST { set h [ILX::init plugin extension]; ILX::call $h sum one }",
                "ILX mock sum requires integer arguments",
            ),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_legacy_global_http_ip_and_byte_order_commands(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "ip=[http_client_ip] custom=[http_client_ip X-Real-IP] len=[http_content_len_max 10] cookie=[http_cookie sid] header=[http_header Host:] host=[http_host] method=[http_method] uri=[http_uri] ver=[http_version] proto=[ip_protocol] tos=[ip_tos] ttl=[ip_ttl] addr=[ip_addr 10.0.0.1 equals 10.0.0.0/24] n32=[htonl 16909060] n16=[htons 258] h32=[ntohl 67305985] h16=[ntohs 513]"
}
""",
                "request": {
                    "method": "POST",
                    "uri": "/legacy?q=1",
                    "host": "example.test",
                    "headers": {
                        "X-Forwarded-For": "198.51.100.2, 198.51.100.3",
                        "X-Real-IP": "203.0.113.8",
                        "Content-Length": "20",
                        "Cookie": "sid=abc=def; other=two",
                    },
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "ip=198.51.100.2 custom=203.0.113.8 len=10 cookie=abc=def "
            "header=example.test host=example.test method=POST uri=/legacy?q=1 "
            "ver=1.1 proto=6 tos=0 ttl=64 addr=1 n32=67305985 n16=513 "
            "h32=16909060 h16=258" in entry
            for entry in result["results"][0]["logs"]
        ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "htonl", "htons", "http_client_ip", "http_content_len_max",
            "http_cookie", "http_header", "http_host", "http_method", "http_uri",
            "http_version", "ip_addr", "ip_protocol", "ip_tos", "ip_ttl", "ntohl", "ntohs",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule, message in (
            (
                'when HTTP_REQUEST { set x [http_content_len_max 0]; return }',
                None,
            ),
            (
                'when HTTP_REQUEST { http_content_len_max 10 }',
                "http_content_len_max found an invalid Content-Length",
            ),
            (
                'when HTTP_REQUEST { htonl -1 }',
                "htonl value is outside the unsigned 32-bit range",
            ),
            (
                'when HTTP_REQUEST { htons 65536 }',
                "htons value is outside the unsigned 16-bit range",
            ),
        ):
            with self.subTest(message=message):
                scenario = {
                    "profiles": ["TCP", "HTTP"],
                    "irule": irule,
                    "request": {"uri": "/"},
                }
                if message is None:
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)
                else:
                    scenario["request"]["headers"] = {"Content-Length": "bad"}
                    with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                        self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_nsh_stateful_fields_and_connection_scope(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[NSH::path_id clientside_ingress] == 0} {
        if {[HTTP::uri] eq "/first"} {
            NSH::path_id clientside_ingress 10
        } else {
            NSH::path_id clientside_ingress 20
        }
        NSH::chain serverside_egress chain-a
        NSH::context 1 serverside_egress 1111
        NSH::md1 serverside_egress 1 4 [binary format H* 00ff1020]
        NSH::mocksf
        NSH::service_index serverside_egress 7
    }
    log local0. "path=[NSH::path_id clientside_ingress] service=[NSH::service_index serverside_egress] context=[NSH::context 1 serverside_egress] md1=[b64encode [NSH::md1 serverside_egress 1 4]]"
}
""",
                "requests": [
                    {"uri": "/first"},
                    {"uri": "/same"},
                    {"uri": "/second", "close_before": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = [result["results"][index]["logs"] for index in range(3)]
        self.assertTrue(any("path=10 service=7 context=1111 md1=AP8QIA==" in entry for entry in logs[0]))
        self.assertTrue(any("path=10 service=7 context=1111 md1=AP8QIA==" in entry for entry in logs[1]))
        self.assertTrue(any("path=20 service=7 context=1111 md1=AP8QIA==" in entry for entry in logs[2]))

        first_nsh = result["results"][0]["semantic"]["nsh"]
        second_nsh = result["results"][1]["semantic"]["nsh"]
        third_nsh = result["results"][2]["semantic"]["nsh"]
        for nsh_state, path_id in ((first_nsh, 10), (second_nsh, 10), (third_nsh, 20)):
            self.assertEqual(nsh_state["chains"], [{"direction": "serverside_egress", "chain": "chain-a"}])
            self.assertEqual(nsh_state["contexts"], [{"index": 1, "direction": "serverside_egress", "context": 1111}])
            self.assertEqual(nsh_state["md1"], [{
                "direction": "serverside_egress",
                "offset": 1,
                "length": 4,
                "metadata_base64": "AP8QIA==",
            }])
            self.assertTrue(nsh_state["mocksf"])
            self.assertEqual(nsh_state["path_ids"], [{"direction": "clientside_ingress", "value": path_id}])
            self.assertEqual(nsh_state["service_indices"], [{"direction": "serverside_egress", "value": 7}])

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "NSH::chain", "NSH::context", "NSH::md1", "NSH::mocksf",
            "NSH::path_id", "NSH::service_index",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_nsh_unset_values_and_bounds(self) -> None:
        defaults = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { log local0. \"context=[NSH::context 1 clientside_ingress] md1=[b64encode [NSH::md1 clientside_ingress 0 0]] path=[NSH::path_id clientside_ingress] service=[NSH::service_index clientside_ingress]\" }",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any(
            "context=0 md1= path=0 service=0" in entry
            for entry in defaults["results"][0]["logs"]
        ))

        for irule, message in (
            (
                "when HTTP_REQUEST { NSH::context 1 invalid 2 }",
                "NSH::context direction must be clientside_ingress, clientside_egress, serverside_ingress, or serverside_egress",
            ),
            (
                "when HTTP_REQUEST { NSH::md1 clientside_ingress 0 2 [binary format H* 00] }",
                "NSH::md1 metadata length must equal the requested length",
            ),
            (
                "when HTTP_REQUEST { NSH::path_id clientside_ingress 16777216 }",
                "NSH::path_id value must be an unsigned integer from 0 to 16777215",
            ),
            (
                "when HTTP_REQUEST { NSH::service_index clientside_ingress 256 }",
                "NSH::service_index value must be an unsigned integer from 0 to 255",
            ),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_aes_key_encrypt_decrypt_round_trip_and_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when RULE_INIT {
    set ::aes_key_128 [AES::key 128]
    set ::aes_key_192 [AES::key 192]
    set ::aes_key_256 [AES::key 256]
}
when HTTP_REQUEST {
    set plaintext "hello binary"
    set encrypted_128 [AES::encrypt $::aes_key_128 $plaintext]
    set encrypted_192 [AES::encrypt $::aes_key_192 $plaintext]
    set encrypted_256 [AES::encrypt $::aes_key_256 $plaintext]
    set static_key "AES 128 00112233445566778899aabbccddeeff"
    set passphrase_encrypted [AES::encrypt passphrase $plaintext]
    set binary_data [binary format H* 00010203fffe7f80101112131415161718]
    set binary_cipher [AES::encrypt $static_key $binary_data]
    set binary_plain [AES::decrypt $static_key $binary_cipher]
    log local0. "bits=[lindex $::aes_key_128 1]/[lindex $::aes_key_192 1]/[lindex $::aes_key_256 1] lengths=[string length $encrypted_128]/[string length $encrypted_192]/[string length $encrypted_256] plain=[b64encode [AES::decrypt $::aes_key_128 $encrypted_128]] static=[b64encode [AES::decrypt $static_key [AES::encrypt $static_key $plaintext]]] pass=[b64encode [AES::decrypt passphrase $passphrase_encrypted]] binary_equal=[expr {$binary_plain eq $binary_data}] binary_len=[string length $binary_cipher]"
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertTrue(any(
            "bits=128/192/256" in entry
            and "lengths=16/16/16" in entry
            and "plain=aGVsbG8gYmluYXJ5" in entry
            and "static=aGVsbG8gYmluYXJ5" in entry
            and "pass=aGVsbG8gYmluYXJ5" in entry
            and "binary_equal=1" in entry
            and "binary_len=32" in entry
            for entry in result["results"][0]["logs"]
        ))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("AES::key", "AES::encrypt", "AES::decrypt"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        for irule, message in (
            ("when HTTP_REQUEST { AES::key 64 }", "AES::key size must be 128, 192, or 256"),
            ("when HTTP_REQUEST { AES::encrypt {AES 128 deadbeef} data }", "exactly 32 hexadecimal characters"),
            ("when HTTP_REQUEST { AES::decrypt passphrase short }", "ciphertext length must be a positive multiple of 16"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_ipfix_templates_messages_persist_and_send_across_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when RULE_INIT {
    set static::ipfix_destination ""
    set static::ipfix_template ""
}
when CLIENT_ACCEPTED {
    if {$static::ipfix_destination eq ""} {
        set static::ipfix_destination [IPFIX::destination open -publisher /Common/ipfix_publisher]
    }
    if {$static::ipfix_template eq ""} {
        set static::ipfix_template [IPFIX::template create {sourceIPv4Address action action}]
    }
}
when HTTP_REQUEST {
    set static::ipfix_message [IPFIX::msg create $static::ipfix_template]
    IPFIX::msg set $static::ipfix_message sourceIPv4Address client
    IPFIX::msg set $static::ipfix_message action -pos 0 Request
}
when HTTP_RESPONSE_RELEASE {
    IPFIX::msg set $static::ipfix_message action -pos 1 Response
    IPFIX::destination send $static::ipfix_destination $static::ipfix_message
}
""",
                "requests": [
                    {"uri": "/first", "close_after": True},
                    {"uri": "/second", "close_after": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(len(result["results"]), 2)
        first_ipfix = result["results"][0]["semantic"]["ipfix"]
        second_ipfix = result["results"][1]["semantic"]["ipfix"]
        expected_template = {
            "handle": "template-1",
            "fields": ["sourceIPv4Address", "action", "action"],
        }
        expected_destination = {
            "handle": "destination-1",
            "publisher": "/Common/ipfix_publisher",
            "closed": False,
        }
        expected_fields = [
            {"name": "sourceIPv4Address", "position": 0, "field_position": 0, "set": True, "value": "client"},
            {"name": "action", "position": 1, "field_position": 0, "set": True, "value": "Request"},
            {"name": "action", "position": 2, "field_position": 1, "set": True, "value": "Response"},
        ]
        self.assertEqual(first_ipfix["templates"], [expected_template])
        self.assertEqual(first_ipfix["destinations"], [expected_destination])
        self.assertEqual(first_ipfix["messages"], [
            {"handle": "message-1", "template": "template-1", "fields": expected_fields}
        ])
        self.assertEqual(first_ipfix["sends"], [
            {
                "destination": "destination-1",
                "message": "message-1",
                "template": "template-1",
                "fields": expected_fields,
            }
        ])
        self.assertEqual(second_ipfix["templates"], [expected_template])
        self.assertEqual(second_ipfix["destinations"], [expected_destination])
        self.assertEqual(
            second_ipfix["messages"][0]["handle"], "message-2"
        )
        self.assertEqual(len(second_ipfix["sends"]), 2)
        self.assertEqual(second_ipfix["sends"][1]["message"], "message-2")
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("IPFIX::destination", "IPFIX::msg", "IPFIX::template"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_ipfix_validation_delete_and_closed_destination(self) -> None:
        delete_result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set destination [IPFIX::destination open -publisher /Common/publisher]
    set template [IPFIX::template create {action}]
    set message [IPFIX::msg create $template]
    IPFIX::template delete $template
    IPFIX::msg set $message action retained
    IPFIX::destination send $destination $message
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        ipfix = delete_result["results"][0]["semantic"]["ipfix"]
        self.assertEqual(ipfix["templates"], [])
        self.assertEqual(ipfix["messages"][0]["fields"][0]["value"], "retained")
        self.assertEqual(len(ipfix["sends"]), 1)

        for irule, message in (
            (
                "when HTTP_REQUEST { set t [IPFIX::template create {action action}]; "
                "set m [IPFIX::msg create $t]; IPFIX::msg set $m action value }",
                "requires -pos for a repeated field",
            ),
            (
                "when HTTP_REQUEST { set t [IPFIX::template create {sourceIPv4Address action}]; "
                "set m [IPFIX::msg create $t]; IPFIX::msg set $m action -pos 1 value }",
                "position must identify the requested field",
            ),
            (
                "when HTTP_REQUEST { set d [IPFIX::destination open -publisher /Common/publisher]; "
                "set t [IPFIX::template create {action}]; set m [IPFIX::msg create $t]; "
                "IPFIX::destination close $d; IPFIX::destination send $d $m }",
                "received a closed destination object",
            ),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_oneconnect_controls_persist_until_connection_reset(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ONECONNECT"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::path] eq "/first"} {
        ONECONNECT::detach disable
        ONECONNECT::reuse disable
        ONECONNECT::select persist
        ONECONNECT::label update tenant-a
    }
    log local0. "reuse=[ONECONNECT::reuse] select=[ONECONNECT::select]"
}
""",
                "requests": [
                    {"uri": "/first"},
                    {"uri": "/second"},
                    {"uri": "/new", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second, new_connection = result["results"]
        self.assertEqual(first["semantic"]["oneconnect"], {
            "detach_enabled": False,
            "reuse_enabled": False,
            "select": "persist",
            "label": "tenant-a",
        })
        self.assertEqual(second["semantic"]["oneconnect"], first["semantic"]["oneconnect"])
        self.assertEqual(new_connection["semantic"]["oneconnect"], {
            "detach_enabled": True,
            "reuse_enabled": True,
            "select": "none",
            "label": "",
        })
        self.assertEqual(first["server_connection"], {
            "id": 1,
            "enabled": True,
            "reused": False,
            "reason": "new",
            "state_after_response": "attached",
            "reuse_enabled": False,
            "select": "persist",
            "label": "tenant-a",
        })
        self.assertEqual(second["server_connection"]["id"], 1)
        self.assertEqual(second["server_connection"]["reason"], "attached")
        self.assertEqual(new_connection["server_connection"]["id"], 2)
        self.assertEqual(new_connection["server_connection"]["reason"], "new")
        self.assertTrue(any("reuse=0 select=persist" in entry for entry in first["logs"]))
        self.assertTrue(any("reuse=1 select=none" in entry for entry in new_connection["logs"]))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "ONECONNECT::detach",
            "ONECONNECT::label",
            "ONECONNECT::reuse",
            "ONECONNECT::select",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires a OneConnect profile"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { ONECONNECT::reuse }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        reused = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ONECONNECT"],
                "irule": 'when HTTP_REQUEST { log local0. "reuse=[ONECONNECT::reuse]" }',
                "requests": [{"uri": "/idle-1"}, {"uri": "/idle-2"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_idle, second_idle = reused["results"]
        self.assertEqual(first_idle["server_connection"]["reason"], "new")
        self.assertEqual(first_idle["server_connection"]["state_after_response"], "detached")
        self.assertEqual(second_idle["server_connection"], {
            "id": 1,
            "enabled": True,
            "reused": True,
            "reason": "idle-reuse",
            "state_after_response": "detached",
            "reuse_enabled": True,
            "select": "none",
            "label": "",
        })

        plain = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { }",
                "request": {"uri": "/plain"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertFalse(plain["results"][0]["server_connection"]["enabled"])
        self.assertFalse(plain["results"][0]["server_connection"]["reuse_enabled"])

    def test_crypto_context_lifecycle_and_reuse_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::path] eq "/start"} {
        CRYPTO::hash -alg sha256 -ctx rolling hello
        log local0. "context=started"
    } elseif {[HTTP::path] eq "/finish"} {
        set digest [CRYPTO::hash -ctx rolling -final]
        log local0. "context=finished digest=[b64encode $digest]"
    } else {
        set digest [CRYPTO::hash -alg sha1 -ctx rolling hello]
        set final [CRYPTO::hash -ctx rolling -final]
        log local0. "context=reset digest=[b64encode $final] partial=<$digest>"
    }
}
""",
                "requests": [
                    {"uri": "/start"},
                    {"uri": "/finish"},
                    {"uri": "/reset", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("context=started" in entry for entry in result["results"][0]["logs"]))
        self.assertTrue(any(
            "context=finished digest=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=" in entry
            for entry in result["results"][1]["logs"]
        ))
        self.assertTrue(any(
            "context=reset digest=qvTGHdzF6KLavt4PO0gs2a6pQ00=" in entry
            for entry in result["results"][2]["logs"]
        ))

        invalid_rules = (
            (
                "when HTTP_REQUEST { CRYPTO::hash -alg sha256 -ctx ctx a; CRYPTO::sign -alg hmac-sha256 -ctx ctx -key secret b }",
                "already used for another CRYPTO command",
            ),
            (
                "when HTTP_REQUEST { CRYPTO::hash -alg sha256 -ctx ctx a; CRYPTO::hash -alg sha1 -ctx ctx b }",
                "cannot change the context algorithm",
            ),
            (
                "when HTTP_REQUEST { CRYPTO::sign -alg hmac-sha256 -ctx ctx -key secret a; CRYPTO::sign -ctx ctx -key other b }",
                "cannot change the context key after it starts",
            ),
        )
        for irule, message in invalid_rules:
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_ip_semantics_record_packet_state_and_seeded_lookups(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "ip": {
                    "hops": 3,
                    "intelligence": {"10.0.0.5": ["Proxy", "Scanners"]},
                    "reputation": {"10.0.0.5": ["Scanners", "Cloud Provider Networks"]},
                },
                "irule": """
when CLIENT_ACCEPTED {
    TCP::collect
    log local0. "accepted hops=[IP::hops] stats=[IP::stats] reputation=[IP::reputation [IP::client_addr]] intelligence=[IP::intelligence [IP::client_addr]]"
    IP::idle_timeout 900
}
when CLIENT_DATA {
    IP::ingress_drop_rate [IP::client_addr] 10 30
    IP::ingress_rate_limit 20 100
    log local0. "data pkts=[IP::stats pkts in] bytes=[IP::stats bytes in] age=[IP::stats age] in=[IP::stats in] out=[IP::stats out]"
}
when SERVER_CONNECTED {
    log local0. "server pkts=[IP::stats pkts out] bytes=[IP::stats bytes out]"
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                        "flags": ["SYN"],
                        "hops": 4,
                        "timestamp": 10,
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 443},
                        "flags": ["ACK", "PSH"],
                        "payload": "hello",
                        "hops": 4,
                        "timestamp": 10.25,
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 443},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                        "flags": ["ACK"],
                        "payload": "ok",
                        "timestamp": 10.5,
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        accepted = result["trace"][0]["events"][-1]
        self.assertEqual(accepted["event"], "CLIENT_ACCEPTED")
        self.assertTrue(any("accepted hops=4" in log for log in accepted["logs"]))
        self.assertTrue(any("reputation=Scanners" in log for log in accepted["logs"]))
        self.assertEqual(accepted["semantic"]["ip"]["intelligence"]["10.0.0.5"], [
            "Proxy", "Scanners"
        ])
        self.assertEqual(accepted["semantic"]["ip"]["pkts_in"], 1)
        self.assertEqual(accepted["semantic"]["ip"]["bytes_in"], 0)
        self.assertEqual(accepted["semantic"]["ip"]["hops"], 4)

        data_event = result["trace"][1]["events"][-1]
        self.assertEqual(data_event["event"], "CLIENT_DATA")
        self.assertTrue(any("pkts=2 bytes=5 age=250" in log for log in data_event["logs"]))
        self.assertEqual(data_event["semantic"]["ip"]["drop_rates"], {
            "10.0.0.5": {"rate": 10, "timeout": 30}
        })
        self.assertEqual(data_event["semantic"]["ip"]["global_gray_list_rate"], 20)
        self.assertEqual(data_event["semantic"]["ip"]["global_rate"], 100)
        self.assertEqual(data_event["semantic"]["ip"]["idle_timeout"], 900)

        server_event = result["trace"][2]["events"][-1]
        self.assertEqual(server_event["event"], "SERVER_CONNECTED")
        self.assertTrue(any("server pkts=1 bytes=2" in log for log in server_event["logs"]))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "IP::hops", "IP::idle_timeout", "IP::ingress_drop_rate",
            "IP::ingress_rate_limit", "IP::intelligence", "IP::reputation", "IP::stats",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_ip_semantics_reject_invalid_inputs(self) -> None:
        base = {
            "profiles": ["TCP"],
            "irule": "when CLIENT_ACCEPTED { IP::hops }",
            "packets": [{
                "protocol": "tcp",
                "direction": "client_to_server",
                "flags": ["SYN"],
            }],
        }
        invalid_scenarios = (
            ({"ip": {"hops": 256}}, "ip.hops must be an integer from 0 to 255"),
            ({"ip": {"reputation": {"not-an-ip": ["Botnets"]}}}, "not a valid IPv4 or IPv6"),
            ({"ip": {"reputation": {"10.0.0.5": ["bad}category"]}}}, "Tcl braces"),
        )
        for extra, message in invalid_scenarios:
            scenario = dict(base)
            scenario.update(extra)
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

        for irule, message in (
            ("when CLIENT_ACCEPTED { IP::stats nope }", "unsupported IP::stats selector"),
            ("when CLIENT_ACCEPTED { IP::idle_timeout -1 }", "non-negative integer"),
            ("when CLIENT_ACCEPTED { IP::ingress_rate_limit 1 }", "requires GLOBAL_GRAY_LIST_RATE"),
        ):
            scenario = dict(base)
            scenario["irule"] = irule
            with self.subTest(irule=irule):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_profile_attribute_commands_read_configured_17_5_settings(self) -> None:
        profiles = [
            "TCP",
            "HTTP",
            "ACCESS",
            "ANTIFRAUD",
            "AUTH",
            "AVR",
            "DIAMETER",
            "EXCHANGE",
            "FTP",
            "HTTPCLASS",
            "HTTPCOMPRESSION",
            "ONECONNECT",
            "PERSIST",
            "STREAM",
            "TFTP",
            "VDI",
            "WEBACCELERATION",
            "XML",
        ]
        settings = {
            "ACCESS": {"enabled": True},
            "ANTIFRAUD": {"mode": "strict"},
            "AUTH": {"method": "ldap"},
            "AVR": {"analytics": "enabled"},
            "DIAMETER": {"realm": "example.net"},
            "EXCHANGE": {"version": "2019"},
            "FTP": {"mode": "passive"},
            "HTTPCLASS": {"default": "class-a"},
            "HTTPCOMPRESSION": {"gzip": "enabled"},
            "ONECONNECT": {"reuse": "enabled"},
            "PERSIST": {"timeout": 300},
            "STREAM": {"replacement": "enabled"},
            "TFTP": {"mode": "read"},
            "VDI": {"msrdp_ntlm_auth_name": "corp"},
            "WEBACCELERATION": {"cache": "enabled"},
            "XML": {"validation": "strict"},
        }
        result = self.adapter.run_scenario(
            {
                "profiles": profiles,
                "profile_settings": settings,
                "irule": """
when HTTP_REQUEST {
    log local0. "access=[PROFILE::access enabled] antifraud=[PROFILE::antifraud mode] auth=[PROFILE::auth /Common/auth method] avr=[PROFILE::avr analytics] diameter=[PROFILE::diameter realm] exchange=[PROFILE::exchange version] ftp=[PROFILE::ftp mode] httpclass=[PROFILE::httpclass default] compression=[PROFILE::httpcompression gzip] oneconnect=[PROFILE::oneconnect reuse] persist=[PROFILE::persist instance /Common/persist timeout] stream=[PROFILE::stream replacement] tftp=[PROFILE::tftp mode] vdi=[PROFILE::vdi msrdp_ntlm_auth_name] webacceleration=[PROFILE::webacceleration cache] xml=[PROFILE::xml validation]"
}
""",
                "requests": [{"uri": "/profile-settings"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        entry = result["results"][0]
        self.assertTrue(
            any(
                "access=1 antifraud=strict auth=ldap avr=enabled "
                "diameter=example.net exchange=2019 ftp=passive "
                "httpclass=class-a compression=enabled oneconnect=enabled "
                "persist=300 stream=enabled tftp=read vdi=corp "
                "webacceleration=enabled xml=strict" in log
                for log in entry["logs"]
            )
        )
        expected_settings = {
            profile: {
                attribute: "1" if isinstance(value, bool) and value else
                "0" if isinstance(value, bool) else str(value)
                for attribute, value in attributes.items()
            }
            for profile, attributes in settings.items()
        }
        self.assertEqual(entry["semantic"]["profile_settings"], expected_settings)
        self.assertEqual(
            {
                command["name"]: command["runtime_status"]
                for command in result["fidelity"]["commands"]
                if command["name"].startswith("PROFILE::")
                and command["name"] not in {
                    "PROFILE::clientssl",
                    "PROFILE::exists",
                    "PROFILE::fastL4",
                    "PROFILE::fasthttp",
                    "PROFILE::http",
                    "PROFILE::list",
                    "PROFILE::serverssl",
                    "PROFILE::tcp",
                    "PROFILE::udp",
                }
            },
            {
                f"PROFILE::{name.lower()}": "semantic-mock"
                for name in (
                    "access",
                    "antifraud",
                    "auth",
                    "avr",
                    "diameter",
                    "exchange",
                    "ftp",
                    "httpclass",
                    "httpcompression",
                    "oneconnect",
                    "persist",
                    "stream",
                    "tftp",
                    "vdi",
                    "webacceleration",
                    "xml",
                )
            },
        )

        gated = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "profile_settings": {"FTP": {"mode": "passive"}},
                "irule": "when HTTP_REQUEST { log local0. \"ftp=[PROFILE::ftp mode]\" }",
                "requests": [{"uri": "/gated"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("ftp=" in log for log in gated["results"][0]["logs"]))

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

    def test_semantic_overlay_models_dosl7_policy_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FASTHTTP"],
                "dosl7": {
                    "enabled": True,
                    "health": 7,
                    "profile": "/Common/dos-profile",
                    "mitigated": True,
                    "greylist": {
                        "10.0.0.1": {"rate": 10, "timeout": 60},
                    },
                },
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/disable"} {
        DOSL7::disable
    } elseif {[HTTP::uri] eq "/enable"} {
        DOSL7::enable /Common/override
    } elseif {[HTTP::uri] eq "/slow"} {
        DOSL7::slowdown 30 120
    }
    log local0. "profile=[DOSL7::profile] health=[DOSL7::health] slowed=[DOSL7::is_ip_slowdown] mitigated=[DOSL7::is_mitigated]"
}
""",
                "requests": [
                    {"uri": "/inspect"},
                    {"uri": "/disable"},
                    {"uri": "/enable"},
                    {"uri": "/slow"},
                    {"uri": "/inspect", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        inspect, disabled, enabled, slowed, fresh = result["results"]
        self.assertTrue(any("profile=/Common/dos-profile health=7 slowed=1 mitigated=1" in log for log in inspect["logs"]))
        self.assertTrue(any("profile= health=7 slowed=1 mitigated=1" in log for log in disabled["logs"]))
        self.assertTrue(any("profile=/Common/dos-profile health=7 slowed=1 mitigated=1" in log for log in enabled["logs"]))
        self.assertIn("dosl7 slowdown {{10.0.0.1 30 120}}", slowed["decisions"])
        self.assertTrue(any("profile=/Common/dos-profile health=7 slowed=1 mitigated=1" in log for log in fresh["logs"]))
        self.assertEqual(
            slowed["semantic"]["dosl7"]["greylist"]["10.0.0.1"],
            {"rate": 30, "timeout": 120},
        )
        self.assertFalse(disabled["semantic"]["dosl7"]["enabled"])
        self.assertTrue(enabled["semantic"]["dosl7"]["enabled"])
        self.assertEqual(enabled["semantic"]["dosl7"]["profile_object"], "/Common/override")
        self.assertEqual(fresh["semantic"]["dosl7"]["profile_object"], "")
        self.assertEqual(
            {
                command["name"]: command["runtime_status"]
                for command in result["fidelity"]["commands"]
                if command["name"].startswith("DOSL7::")
            },
            {
                "DOSL7::disable": "semantic-mock",
                "DOSL7::enable": "semantic-mock",
                "DOSL7::health": "semantic-mock",
                "DOSL7::is_ip_slowdown": "semantic-mock",
                "DOSL7::is_mitigated": "semantic-mock",
                "DOSL7::profile": "semantic-mock",
                "DOSL7::slowdown": "semantic-mock",
            },
        )

    def test_dosl7_scenario_validation_rejects_invalid_policy_inputs(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP", "FASTHTTP"],
            "irule": "when HTTP_REQUEST { log local0. ok }",
            "request": {"uri": "/"},
        }
        invalid_cases = (
            ({"enabled": "yes"}, "dosl7.enabled must be a boolean"),
            ({"health": -1}, "dosl7.health must be an integer"),
            ({"greylist": {"10.0.0.1": {"rate": 101, "timeout": 60}}}, "rate must be an integer"),
            ({"greylist": {"10.0.0.1": {"rate": 10, "timeout": -1}}}, "timeout must be an integer"),
            ({"greylist": {"not-an-ip": {"rate": 10, "timeout": 60}}}, "not a valid IPv4 or IPv6 address"),
            ({"attack": []}, "dosl7.attack must be an object"),
            (
                {"attack": {"enabled": "yes"}},
                "dosl7.attack.enabled must be a boolean",
            ),
            (
                {"attack": {"enabled": True}},
                "dosl7.attack.attacker_ip is required when dosl7.attack.enabled is true",
            ),
            (
                {"attack": {"enabled": True, "attacker_ip": "not-an-ip"}},
                "not a valid IPv4 or IPv6 address",
            ),
            ({"unknown": True}, "dosl7 unsupported field"),
        )
        for dosl7, message in invalid_cases:
            scenario = dict(base)
            scenario["dosl7"] = dosl7
            with self.subTest(dosl7=dosl7):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(scenario, tcl_lsp_root=self.tcl_lsp_root)

    def test_dosl7_attack_fixture_emits_in_dosl7_attack(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "dosl7": {
                    "attack": {
                        "enabled": True,
                        "attacker_ip": "203.0.113.44",
                        "mitigation": "Source IP-Based Rate Limiting",
                    }
                },
                "irule": (
                    "when IN_DOSL7_ATTACK { "
                    'log local0. "attacker=$DOSL7_ATTACKER_IP mitigation=$DOSL7_MITIGATION"; '
                    "DOSL7::disable }"
                ),
                "request": {"uri": "/under-attack"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        item = result["results"][0]
        self.assertEqual(item["events_fired"], ["HTTP_REQUEST", "IN_DOSL7_ATTACK"])
        self.assertTrue(
            any(
                "attacker=203.0.113.44 mitigation=Source IP-Based Rate Limiting" in entry
                for entry in item["logs"]
            )
        )
        self.assertFalse(item["semantic"]["dosl7"]["enabled"])

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ASM"],
                "dosl7": {
                    "enabled": False,
                    "attack": {
                        "enabled": True,
                        "attacker_ip": "203.0.113.44",
                        "mitigation": "rate-limit",
                    },
                },
                "irule": "when IN_DOSL7_ATTACK { log local0. unexpected }",
                "request": {"uri": "/clear"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("IN_DOSL7_ATTACK", disabled["results"][0]["events_fired"])

    def test_dosl7_request_mitigation_override_resets_to_policy_default(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FASTHTTP"],
                "dosl7": {"mitigated": True},
                "irule": "when HTTP_REQUEST { log local0. \"mitigated=[DOSL7::is_mitigated]\" }",
                "requests": [
                    {"uri": "/default"},
                    {"uri": "/override", "dosl7": {"mitigated": False}},
                    {"uri": "/default-again"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("mitigated=1" in log for log in result["results"][0]["logs"]))
        self.assertTrue(any("mitigated=0" in log for log in result["results"][1]["logs"]))
        self.assertTrue(any("mitigated=1" in log for log in result["results"][2]["logs"]))
        self.assertTrue(result["results"][0]["semantic"]["dosl7"]["mitigated"])
        self.assertFalse(result["results"][1]["semantic"]["dosl7"]["mitigated"])
        self.assertTrue(result["results"][2]["semantic"]["dosl7"]["mitigated"])

    def test_dosl7_profile_is_gated_without_fasthttp(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "dosl7": {"profile": "/Common/dos-profile"},
                "irule": "when HTTP_REQUEST { log local0. \"profile=[DOSL7::profile]\" }",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("profile=" in log and "/Common/dos-profile" not in log for log in result["results"][0]["logs"]))

    def test_semantic_overlay_models_lb_connection_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:80"]},
                "irule": """
when CLIENT_ACCEPTED {
    LB::context_id context-a
    LB::src_tag source-a
    LB::dst_tag destination-a
    LB::bias 3
    LB::enable_decisionlog
}
when HTTP_REQUEST {
    pool api_pool
    LB::mode roundrobin
    LB::connlimit virtual limit 10 key tenant-a
    LB::connect
    snat automap
    LB::command transparent_port
    LB::prime
    log local0. "mode=[LB::mode] snat=[LB::snat] class=[LB::class] queued=[LB::queue queued] limit=[LB::connlimit virtual]"
}
""",
                "requests": [{"uri": "/health"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        entry = result["results"][0]
        self.assertEqual(
            entry["semantic"]["lb"],
            {
                "bias": "3",
                "class": "",
                "command": "transparent_port",
                "context_id": "context-a",
                "dst_tag": "destination-a",
                "src_tag": "source-a",
                "decisionlog_enabled": "1",
                "connect_requested": "1",
                "prime_requested": "1",
                "connlimits": "virtual {limit 10 key tenant-a}",
                "queue_on": "0",
                "queue_queued": "0",
                "queue_depth": "0",
                "queue_limit_depth": "0",
                "queue_limit_time": "0",
                "queue_age_head": "0",
                "queue_age_max": "0",
                "queue_age_edm": "0",
                "queue_age_ema": "0",
            },
        )
        self.assertEqual(entry["pool"], "api_pool")
        self.assertEqual(entry["node"], "192.0.2.10")
        self.assertTrue(any("mode=roundrobin snat=automap" in log for log in entry["logs"]))
        self.assertTrue(any("queued=0" in log and "limit=limit 10 key tenant-a" in log for log in entry["logs"]))

    def test_semantic_overlay_models_bwc_flow_controls_and_measurement(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when CLIENT_ACCEPTED {
    set ::bwc_session "[IP::remote_addr]:[TCP::remote_port]"
    BWC::policy attach video_policy $::bwc_session
    BWC::color set video_policy streaming
    BWC::mark $::bwc_session tos 33
    log local0. "policy_mark=[set ::state::bwc::mark_tos]"
    BWC::mark $::bwc_session streaming qos 4
    BWC::rate $::bwc_session streaming 200 Mbps
    BWC::pps 77
    BWC::priority tc1 60 tc2 40
    BWC::measure identifier video_measure session $::bwc_session
    BWC::measure start session $::bwc_session
    BWC::debug start
}
when HTTP_REQUEST {
    if {[HTTP::path] eq "/detach"} {
        BWC::color unset video_policy
        BWC::measure stop session $::bwc_session
        BWC::policy detach video_policy $::bwc_session
    }
}
when HTTP_RESPONSE {
    if {[HTTP::path] eq "/measure"} {
        set measured_bytes [BWC::measure get bytes session $::bwc_session]
        set measured_rate [BWC::measure get rate session $::bwc_session]
        log local0. "measure=$measured_rate/$measured_bytes"
    }
}
""",
                "requests": [
                    {"uri": "/measure", "response_body": "hello"},
                    {"uri": "/detach"},
                    {"uri": "/fresh", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        measured, detached, fresh = result["results"]
        bwc = measured["semantic"]["bwc"]
        self.assertTrue(bwc["attached"])
        self.assertEqual(bwc["policy"], "video_policy")
        self.assertEqual(bwc["rate"], {"value": "200 mbps", "category": "streaming"})
        self.assertEqual(bwc["pps"], 77)
        self.assertEqual(
            bwc["color"],
            {"set": True, "policy": "video_policy", "category": "streaming"},
        )
        self.assertEqual(
            bwc["mark"],
            {"scope": "category", "category": "streaming", "tos": "", "qos": "4"},
        )
        self.assertEqual(bwc["priority"], {"tc1": 60, "tc2": 40})
        self.assertEqual(
            bwc["measurement"]["identifier"],
            "video_measure",
        )
        self.assertTrue(bwc["measurement"]["enabled"])
        self.assertGreaterEqual(bwc["measurement"]["bytes"], 5)
        self.assertEqual(
            bwc["measurement"]["rate"],
            bwc["measurement"]["bytes"],
        )
        self.assertTrue(bwc["debug"])
        self.assertTrue(any("policy_mark=33" in log for log in measured["logs"]))
        self.assertTrue(any("measure=" in log for log in measured["logs"]))

        self.assertFalse(detached["semantic"]["bwc"]["attached"])
        self.assertEqual(detached["semantic"]["bwc"]["policy"], "")
        self.assertTrue(fresh["semantic"]["bwc"]["attached"])
        self.assertEqual(fresh["semantic"]["bwc"]["policy"], "video_policy")
        self.assertEqual(
            fresh["semantic"]["bwc"]["rate"],
            {"value": "200 mbps", "category": "streaming"},
        )

        invalid_rules = (
            ("when CLIENT_ACCEPTED { BWC::pps -1 }", "BWC::pps"),
            ("when CLIENT_ACCEPTED { BWC::policy attach p; BWC::mark s qos 8 }", "BWC::mark value"),
            ("when CLIENT_ACCEPTED { BWC::policy attach p; BWC::priority tc1 50 tc1 50 }", "unique"),
            ("when CLIENT_ACCEPTED { BWC::policy attach p; BWC::measure get bytes flow }", "measurement to be started"),
        )
        for irule, message in invalid_rules:
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {"profiles": ["TCP", "HTTP"], "irule": irule, "request": {"uri": "/"}},
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_semantic_overlay_models_connection_scoped_psm_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/disable"} {
        PSM::FTP::disable
        PSM::HTTP::disable
        PSM::SMTP::disable
    } elseif {[HTTP::uri] eq "/enable"} {
        PSM::FTP::enable
        PSM::HTTP::enable
        PSM::SMTP::enable
    }
}
""",
                "requests": [
                    {"uri": "/disable"},
                    {"uri": "/enable"},
                    {"uri": "/fresh", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        disabled, enabled, fresh = result["results"]
        self.assertEqual(
            disabled["semantic"]["psm"],
            {"FTP": False, "HTTP": False, "SMTP": False},
        )
        self.assertEqual(
            enabled["semantic"]["psm"],
            {"FTP": True, "HTTP": True, "SMTP": True},
        )
        self.assertEqual(
            fresh["semantic"]["psm"],
            {"FTP": True, "HTTP": True, "SMTP": True},
        )
        self.assertEqual(
            [decision for decision in disabled["decisions"] if decision.startswith("psm ")],
            [
                "psm ftp disable",
                "psm http disable",
                "psm smtp disable",
            ],
        )
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"].startswith("PSM::")},
            {
                "PSM::FTP::disable": "semantic-mock",
                "PSM::FTP::enable": "semantic-mock",
                "PSM::HTTP::disable": "semantic-mock",
                "PSM::HTTP::enable": "semantic-mock",
                "PSM::SMTP::disable": "semantic-mock",
                "PSM::SMTP::enable": "semantic-mock",
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

    def test_http_packet_lb_failure_drives_fallback_event(self) -> None:
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
    log local0. "packet-failure=[event info]"
    pool fallback_pool
    LB::reselect
}
""",
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "uri": "/health",
                        "lb_failure": "connection_timeout",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.100", "port": 443},
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        entry = result["trace"][0]["http_result"]
        self.assertIn("LB_FAILED", entry["events_fired"])
        self.assertEqual(entry["pool"], "fallback_pool")
        self.assertEqual(entry["node"], "192.0.2.20")
        self.assertEqual(
            entry["lb_failure"],
            {"cause": "connection_timeout", "fired": True, "selected": True},
        )
        self.assertTrue(
            any("packet-failure=connection_timeout" in log for log in entry["logs"])
        )

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "HTTP responses cannot specify lb_failure",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_RESPONSE { }",
                    "packets": [
                        {
                            "protocol": "http",
                            "direction": "server_to_client",
                            "lb_failure": "connection_timeout",
                            "source": {"address": "192.0.2.10", "port": 443},
                            "destination": {"address": "10.0.0.5", "port": 51000},
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http_lb_causal_events_preserve_persistence_and_queue_order(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "primary_pool": ["192.0.2.10:443"],
                    "fallback_pool": ["192.0.2.20:443"],
                },
                "irule": """
when HTTP_REQUEST { pool primary_pool }
when PERSIST_DOWN {
    log local0. "persist=[LB::server]"
    pool fallback_pool
}
when LB_SELECTED { log local0. "selected=[LB::server]" }
when LB_QUEUED {
    log local0. "queued=[LB::queue queued] depth=[LB::queue depth one fallback_pool] limit=[LB::queue limit depth fallback_pool]"
}
""",
                "requests": [
                    {
                        "uri": "/first",
                        "persist_down": {
                            "pool": "primary_pool",
                            "member": "192.0.2.10:443",
                        },
                        "lb_queue": {
                            "queued": True,
                            "depth": 2,
                            "limit_depth": 5,
                            "limit_time": 30,
                            "age_head": 4,
                        },
                    },
                    {"uri": "/second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second = result["results"]
        self.assertEqual(
            first["events_fired"],
            ["HTTP_REQUEST", "PERSIST_DOWN", "LB_SELECTED", "LB_QUEUED"],
        )
        self.assertEqual(first["pool"], "fallback_pool")
        self.assertEqual(first["node"], "192.0.2.20")
        self.assertEqual(
            first["semantic"]["lb_events"],
            {
                "persist_down_pending": "0",
                "persist_down_fired": "1",
                "persist_down_pool": "primary_pool",
                "persist_down_member": "192.0.2.10:443",
                "queue_event_pending": "0",
                "queue_event_fired": "1",
            },
        )
        self.assertTrue(any("queued=1 depth=2 limit=5" in log for log in first["logs"]))
        self.assertNotIn("PERSIST_DOWN", second["events_fired"])
        self.assertNotIn("LB_QUEUED", second["events_fired"])
        self.assertEqual(second["semantic"]["lb_events"]["persist_down_fired"], "0")
        self.assertEqual(second["semantic"]["lb_events"]["queue_event_fired"], "0")

    def test_http_packet_lb_causal_inputs_and_response_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST { pool api_pool }
when PERSIST_DOWN { log local0. persist-event }
when LB_SELECTED { log local0. selected-event }
when LB_QUEUED { log local0. queue-event }
""",
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "uri": "/health",
                        "persist_down": {
                            "pool": "api_pool",
                            "member": "192.0.2.10:443",
                        },
                        "lb_queue": {"queued": True, "depth": 1},
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]["http_result"]
        self.assertEqual(
            entry["events_fired"],
            ["HTTP_REQUEST", "PERSIST_DOWN", "LB_SELECTED", "LB_QUEUED"],
        )
        self.assertEqual(entry["semantic"]["lb"]["queue_depth"], "1")

        for field in ("persist_down", "lb_queue"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError,
                    f"HTTP responses cannot specify {field}",
                ):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "irule": "when HTTP_RESPONSE { }",
                            "packets": [
                                {
                                    "protocol": "http",
                                    "direction": "server_to_client",
                                    field: (
                                        {"member": "192.0.2.10:443"}
                                        if field == "persist_down"
                                        else {"queued": True, "depth": 1}
                                    ),
                                }
                            ],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

    def test_lb_causal_inputs_reject_ambiguous_failure_combinations(self) -> None:
        base = {
            "profiles": ["TCP", "HTTP"],
            "pools": {"api_pool": ["192.0.2.10:443"]},
            "irule": "when HTTP_REQUEST { pool api_pool }",
        }
        with self.subTest("request persistence and explicit failure"):
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "cannot be combined with persist_down",
            ):
                self.adapter.run_scenario(
                    {
                        **base,
                        "request": {
                            "lb_failure": "connection_timeout",
                            "persist_down": {"member": "192.0.2.10:443"},
                        },
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
        with self.subTest("packet queue and explicit failure"):
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "cannot be combined with.*queued lb_queue",
            ):
                self.adapter.run_scenario(
                    {
                        **base,
                        "packets": [
                            {
                                "protocol": "http",
                                "direction": "client_to_server",
                                "lb_failure": "connection_timeout",
                                "lb_queue": {"queued": True, "depth": 1},
                            }
                        ],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
        with self.subTest("queue requires connection limit"):
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "on_connlimit must be true",
            ):
                self.adapter.run_scenario(
                    {
                        **base,
                        "request": {
                            "lb_queue": {
                                "queued": True,
                                "on_connlimit": False,
                                "depth": 1,
                            }
                        },
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_http_causal_events_advance_state_without_registered_handlers(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when HTTP_REQUEST { pool api_pool }
when LB_SELECTED { log local0. selected }
""",
                "request": {
                    "persist_down": {
                        "pool": "api_pool",
                        "member": "192.0.2.10:443",
                    },
                    "lb_queue": {"queued": True, "depth": 1},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertEqual(
            request_result["events_fired"],
            ["HTTP_REQUEST", "PERSIST_DOWN", "LB_SELECTED", "LB_QUEUED"],
        )
        self.assertEqual(request_result["semantic"]["lb_events"]["persist_down_fired"], "1")
        self.assertEqual(request_result["semantic"]["lb_events"]["queue_event_fired"], "1")

    def test_lb_queue_limit_exceeded_fires_lb_failed_after_queue_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "primary_pool": ["192.0.2.10:443"],
                    "fallback_pool": ["192.0.2.20:443"],
                },
                "irule": """
when HTTP_REQUEST { pool primary_pool }
when LB_QUEUED { log local0. "queue-limit=[LB::queue depth one fallback_pool]" }
when LB_FAILED {
    log local0. "queue-failure=[event info]"
    pool fallback_pool
    LB::reselect
}
""",
                "request": {
                    "uri": "/health",
                    "lb_queue": {
                        "queued": True,
                        "depth": 6,
                        "limit_depth": 5,
                    },
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertEqual(
            request_result["events_fired"],
            ["HTTP_REQUEST", "LB_SELECTED", "LB_QUEUED", "LB_FAILED"],
        )
        self.assertEqual(request_result["pool"], "fallback_pool")
        self.assertEqual(request_result["node"], "192.0.2.20")
        self.assertEqual(
            request_result["lb_failure"],
            {"cause": "queue_limit", "fired": True, "selected": True},
        )
        self.assertTrue(any("queue-limit=6" in log for log in request_result["logs"]))
        self.assertTrue(any("queue-failure=queue_limit" in log for log in request_result["logs"]))

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

    def test_http_retry_reset_replaces_only_the_server_connection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ONECONNECT"],
                "pools": {"api_pool": ["192.0.2.10:443"]},
                "irule": """
when CLIENT_ACCEPTED { set ::retry_count 0 }
when HTTP_REQUEST { pool api_pool }
when HTTP_RESPONSE {
    if {[HTTP::status] == 503 && $::retry_count == 0} {
        incr ::retry_count
        HTTP::retry -reset
    }
}
""",
                "request": {
                    "uri": "/reset",
                    "response_status": 503,
                    "response_body": "temporary failure",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request_result = result["results"][0]
        self.assertEqual(request_result["retry"], {"attempts": 1, "exhausted": False})
        self.assertEqual(request_result["server_connection"]["id"], 2)
        self.assertFalse(request_result["server_connection"]["reused"])
        self.assertEqual(request_result["server_connection"]["reason"], "new")
        self.assertEqual(request_result["events_fired"].count("CLIENT_ACCEPTED"), 1)
        self.assertEqual(request_result["events_fired"].count("HTTP_REQUEST"), 2)
        self.assertEqual(request_result["events_fired"].count("HTTP_RESPONSE"), 2)

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

    def test_session_table_survives_connection_reset_and_normalizes_legacy_key_qualifiers(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/seed"} {
        session add uie [list client-key any virtual] session-value
    } elseif {[HTTP::uri] eq "/read"} {
        HTTP::header insert X-Session [session lookup uie client-key]
    } elseif {[HTTP::uri] eq "/delete"} {
        session delete uie [list client-key any virtual]
    }
}
""",
                "requests": [
                    {"uri": "/seed"},
                    {"uri": "/read", "new_connection": True},
                    {"uri": "/delete", "new_connection": True},
                    {"uri": "/read", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        seeded, read, deleted, missing = result["results"]
        self.assertEqual(seeded["semantic"]["session"]["count"], 1)
        self.assertEqual(
            seeded["semantic"]["session"]["records"],
            [{"mode": "uie", "key": "client-key", "data": "session-value", "timeout": 180}],
        )
        self.assertEqual(read["request"]["headers"]["x-session"], "session-value")
        self.assertEqual(deleted["semantic"]["session"]["count"], 0)
        self.assertEqual(missing["request"]["headers"]["x-session"], "")
        self.assertEqual(
            [access["operation"] for access in missing["semantic"]["session"]["accesses"]],
            ["add", "lookup", "delete", "lookup"],
        )
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] == "session"
            },
            {"session": "semantic-mock"},
        )

    def test_session_table_rejects_empty_keys_and_unsupported_modes(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "session key must not be empty"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { session lookup uie \"\" }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "session mode must be"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { session add invalid key value }",
                    "request": {"uri": "/"},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_session_table_supports_each_documented_mode_and_round_trips_values(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    session add simple simple-key "simple value"
    session add source_addr source-key "source\nvalue" 0
    session add sticky sticky-key sticky-value 0
    session add dest_addr dest-key dest-value 0
    session add ssl ssl-key ssl-value 0
    session add uie uie-key uie-value 0
    session add hash hash-key hash-value 0
    session add sip sip-key sip-value 0
    HTTP::header insert X-Session-Modes [list \
        [session lookup simple simple-key] \
        [session lookup source_addr source-key] \
        [session lookup sticky sticky-key] \
        [session lookup dest_addr dest-key] \
        [session lookup ssl ssl-key] \
        [session lookup uie uie-key] \
        [session lookup hash hash-key] \
        [session lookup sip sip-key]]
}
""",
                "request": {"uri": "/"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        session_state = result["results"][0]["semantic"]["session"]
        self.assertEqual(session_state["count"], 8)
        self.assertEqual(
            result["results"][0]["request"]["headers"]["x-session-modes"],
            "{simple value} {source\nvalue} sticky-value dest-value ssl-value uie-value hash-value sip-value",
        )

    def test_sharedvar_binds_connection_variable_and_resets_with_connection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    sharedvar public
    if {[HTTP::uri] eq "/seed"} {
        set public shared-value
    } else {
        HTTP::header insert X-Shared $public
    }
}
""",
                "requests": [
                    {"uri": "/seed"},
                    {"uri": "/read"},
                    {"uri": "/read", "new_connection": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        seeded, same_connection, new_connection = result["results"]
        self.assertEqual(same_connection["request"]["headers"]["x-shared"], "shared-value")
        self.assertEqual(new_connection["request"]["headers"]["x-shared"], "")
        self.assertEqual(
            seeded["semantic"]["sharedvar"]["names"],
            [{"name": "public", "value": "shared-value"}],
        )
        self.assertEqual(
            new_connection["semantic"]["sharedvar"]["names"],
            [{"name": "public", "value": ""}],
        )
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] == "sharedvar"
            },
            {"sharedvar": "semantic-mock"},
        )

    def test_sharedvar_rejects_ambiguous_or_unsafe_variable_names(self) -> None:
        for irule in (
            "when HTTP_REQUEST { sharedvar }",
            "when HTTP_REQUEST { sharedvar public extra }",
            "when HTTP_REQUEST { sharedvar {public name} }",
            "when HTTP_REQUEST { sharedvar 1public }",
        ):
            with self.subTest(irule=irule), self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "sharedvar",
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "requests": [{"uri": "/"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_traffic_intents_are_recorded_and_reset_with_connection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/seed"} {
        clone pool tap_pool member 192.0.2.50 8443
        listen { proto 17 timeout 30 bind tap_vlan 192.0.2.10 4000 server 192.0.2.20 7 allow 10.0.0.1 55000 }
        relate_client { proto 17 clientflow client_vlan 192.0.2.10 4000 10.0.0.1 55000 serverflow server_vlan 192.0.2.20 7 10.0.0.1 55000 }
        relate_server { proto 17 clientflow client_vlan 192.0.2.10 4000 10.0.0.1 55000 serverflow server_vlan 192.0.2.20 7 10.0.0.1 55000 }
        use pool legacy_pool
    }
}
""",
                "requests": [
                    {"uri": "/seed"},
                    {"uri": "/read", "new_connection": True},
                    {"uri": "/seed"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        seeded, new_connection, fresh_connection = result["results"]
        intents = seeded["semantic"]["traffic"]["intents"]
        self.assertEqual(
            [intent["kind"] for intent in intents],
            ["clone", "listen", "relate_client", "relate_server", "use"],
        )
        self.assertEqual(
            intents[0]["data"],
            [
                "target_type", "pool", "target", "tap_pool",
                "member", "192.0.2.50", "port", "8443",
            ],
        )
        self.assertEqual(
            intents[1]["data"],
            [
                "proto", "17", "timeout", "30",
                "bind", "tap_vlan 192.0.2.10 4000",
                "server", "192.0.2.20 7",
                "allow", "10.0.0.1 55000",
            ],
        )
        self.assertEqual(
            intents[2]["data"],
            [
                "proto", "17",
                "clientflow", "client_vlan 192.0.2.10 4000 10.0.0.1 55000",
                "serverflow", "server_vlan 192.0.2.20 7 10.0.0.1 55000",
            ],
        )
        self.assertEqual(
            new_connection["semantic"]["traffic"]["intents"],
            [],
        )
        self.assertEqual(
            [intent["ordinal"] for intent in fresh_connection["semantic"]["traffic"]["intents"]],
            [1, 2, 3, 4, 5],
        )
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] in {
                    "clone", "listen", "relate_client", "relate_server", "use"
                }
            },
            {
                "clone": "semantic-mock",
                "listen": "semantic-mock",
                "relate_client": "semantic-mock",
                "relate_server": "semantic-mock",
                "use": "semantic-mock",
            },
        )

    def test_traffic_intents_reject_malformed_configurations(self) -> None:
        for irule in (
            "when HTTP_REQUEST { clone pool }",
            "when HTTP_REQUEST { clone pool tap_pool member 192.0.2.1 65536 }",
            "when HTTP_REQUEST { listen { proto 6 bind vlan 192.0.2.1 } }",
            "when HTTP_REQUEST { listen { proto 6 proto 17 } }",
            "when HTTP_REQUEST { relate_client { proto 6 clientflow a b c } }",
            "when HTTP_REQUEST { use pool }",
            "when HTTP_REQUEST { use " + " ".join(["x" * 4096] * 5) + " }",
        ):
            with self.subTest(irule=irule), self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "clone|listen|relate_client|use|traffic intent",
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "requests": [{"uri": "/"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_traffic_intents_reset_after_explicit_close(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { use pool tap_pool }",
                "requests": [
                    {"uri": "/", "close_after": True},
                    {"uri": "/"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        closed, after_close = result["results"]
        self.assertEqual(
            [intent["ordinal"] for intent in closed["semantic"]["traffic"]["intents"]],
            [1],
        )
        self.assertEqual(
            [intent["ordinal"] for intent in after_close["semantic"]["traffic"]["intents"]],
            [1],
        )

    def test_legacy_utility_commands_use_bounded_fixtures(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "cpu": {
                    "5 secs": 2.5,
                    "all_seconds": [1, 2, 3],
                },
                "whereis": {
                    "192.0.2.10": {
                        "country": "US",
                        "city": "Ashburn",
                        "latitude": "390431",
                    },
                },
                "pem_dtos": {
                    "012430000000132": "{Apple-iPhone 4 model MC603KS} iOS",
                },
                "irule": """
when HTTP_REQUEST {
    log local0. "cpu=[cpu usage 5 sec] all=[cpu usage all_seconds]"
    log local0. "geo=[whereis 192.0.2.10 country city latitude]"
    log local0. "tac=[pem_dtos tac lookup 012430000000132] imid=[imid]"
}
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event_result = result["results"][0]
        self.assertTrue(any("cpu=2.5 all=1 2 3" in entry for entry in event_result["logs"]))
        self.assertTrue(
            any(
                "geo=US Ashburn 390431" in entry
                for entry in event_result["logs"]
            )
        )
        self.assertTrue(
            any(
                "tac={Apple-iPhone 4 model MC603KS} iOS imid=" in entry
                for entry in event_result["logs"]
            )
        )
        utilities = event_result["semantic"]["utilities"]
        self.assertEqual(
            utilities["cpu"],
            [
                {"interval": "5secs", "value": "2.5"},
                {"interval": "all_seconds", "value": ["1", "2", "3"]},
            ],
        )
        self.assertEqual(
            utilities["whereis"],
            [{
                "address": "192.0.2.10",
                "fields": ["country", "city", "latitude"],
                "values": ["US", "Ashburn", "390431"],
            }],
        )
        self.assertEqual(
            utilities["pem_dtos"],
            [{"input": "012430000000132", "value": "{Apple-iPhone 4 model MC603KS} iOS"}],
        )
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] in {"cpu", "imid", "pem_dtos", "whereis"}
            },
            {
                "cpu": "semantic-mock",
                "imid": "semantic-mock",
                "pem_dtos": "semantic-mock",
                "whereis": "semantic-mock",
            },
        )

    def test_legacy_utility_commands_reject_invalid_inputs(self) -> None:
        invalid_rules = (
            "when HTTP_REQUEST { cpu usage 2 hours }",
            "when HTTP_REQUEST { cpu usage 1sec extra }",
            "when HTTP_REQUEST { whereis 192.0.2.10 not_a_field }",
            "when HTTP_REQUEST { pem_dtos tac query 012430000000132 }",
            "when HTTP_REQUEST { imid unexpected }",
        )
        for irule in invalid_rules:
            with self.subTest(irule=irule), self.assertRaises(
                self.adapter.EmulatorInputError
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "requests": [{"uri": "/"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "whereis"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "whereis": {"192.0.2.10": {1: "US"}},
                    "irule": "when HTTP_REQUEST { log local0. ready }",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "cpu"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "cpu": {"all_seconds": [1, 2]},
                    "irule": "when HTTP_REQUEST { log local0. ready }",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_legacy_diagnostic_commands_are_bounded_and_observable(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set original [LINE::get]
    LINE::set "rewritten line"
    check syntax
    tcpdump -i 0 host 192.0.2.10
    DIAG::test
    log local0. "line=$original/[LINE::get] check=[check]"
}
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event_result = result["results"][0]
        self.assertTrue(
            any("line=/rewritten line check=syntax" in entry for entry in event_result["logs"])
        )
        diagnostics = event_result["semantic"]["diagnostics"]
        self.assertEqual(diagnostics["check"]["level"], "syntax")
        self.assertEqual(
            diagnostics["check"]["accesses"],
            [
                {"level": "syntax", "argument_count": 1},
                {"level": "syntax", "argument_count": 0},
            ],
        )
        self.assertEqual(diagnostics["tcpdump"]["accesses"], [["-i", "0", "host", "192.0.2.10"]])
        self.assertEqual(diagnostics["diag_test"]["access_count"], 1)
        self.assertEqual(
            diagnostics["line"]["accesses"],
            [
                {"operation": "get", "value": ""},
                {"operation": "set", "value": "rewritten line"},
                {"operation": "get", "value": "rewritten line"},
            ],
        )
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"]
                in {"accumulate", "check", "tcpdump", "DIAG::test", "LINE::get", "LINE::set"}
            },
            {
                "check": "semantic-mock",
                "tcpdump": "semantic-mock",
                "DIAG::test": "semantic-mock",
                "LINE::get": "semantic-mock",
                "LINE::set": "semantic-mock",
            },
        )

    def test_accumulate_stops_the_current_handler_and_reports_suspension(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
proc stop_here {} { accumulate }
when HTTP_REQUEST {
    log local0. before
    stop_here
    log local0. after
}
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event_result = result["results"][0]
        self.assertTrue(any("before" in entry for entry in event_result["logs"]))
        self.assertFalse(any("after" in entry for entry in event_result["logs"]))
        self.assertTrue(event_result["semantic"]["diagnostics"]["accumulate"]["pending"])
        self.assertTrue(event_result["semantic"]["diagnostics"]["accumulate"]["invoked"])
        self.assertEqual(event_result["semantic"]["diagnostics"]["accumulate"]["count"], 1)
        self.assertTrue(event_result["suspended"])
        self.assertEqual(event_result["suspension"], "accumulate")

    def test_accumulate_pending_state_clears_on_the_next_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/first"} { accumulate }
    log local0. reached
}
""",
                "requests": [{"uri": "/first"}, {"uri": "/second"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second = result["results"]
        self.assertTrue(first["semantic"]["diagnostics"]["accumulate"]["pending"])
        self.assertTrue(first["suspended"])
        self.assertFalse(any("reached" in entry for entry in first["logs"]))
        self.assertFalse(second["semantic"]["diagnostics"]["accumulate"]["pending"])
        self.assertNotIn("suspended", second)
        self.assertTrue(any("reached" in entry for entry in second["logs"]))

    def test_legacy_diagnostic_commands_reject_unsafe_inputs(self) -> None:
        for irule in (
            "when HTTP_REQUEST { check invalid }",
            "when HTTP_REQUEST { tcpdump [string repeat x 16385] }",
            "when HTTP_REQUEST { DIAG::test unexpected }",
            "when HTTP_REQUEST { LINE::get unexpected }",
            "when HTTP_REQUEST { LINE::set }",
            "when HTTP_REQUEST { accumulate unexpected }",
        ):
            with self.subTest(irule=irule), self.assertRaises(
                self.adapter.EmulatorInputError
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "requests": [{"uri": "/"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_outer_priority_orders_handlers_and_exposes_timing_metadata(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
priority 200
when HTTP_REQUEST { log local0. late }
priority 100
when HTTP_REQUEST { log local0. early }
timing off
when CLIENT_ACCEPTED { log local0. timing-disabled }
""",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            result["event_controls"],
            [
                {"ordinal": 0, "event": "HTTP_REQUEST", "priority": 200, "timing": "on"},
                {"ordinal": 1, "event": "HTTP_REQUEST", "priority": 100, "timing": "on"},
                {"ordinal": 2, "event": "CLIENT_ACCEPTED", "priority": 100, "timing": "off"},
            ],
        )
        request_logs = result["results"][0]["logs"]
        self.assertLess(
            next(index for index, entry in enumerate(request_logs) if "early" in entry),
            next(index for index, entry in enumerate(request_logs) if "late" in entry),
        )
        self.assertTrue(any("timing-disabled" in entry for entry in request_logs))

    def test_outer_priority_and_timing_validate_values(self) -> None:
        for irule, message in (
            ("priority 1001\nwhen HTTP_REQUEST { return }", "priority must be"),
            ("timing sometimes\nwhen HTTP_REQUEST { return }", "timing must be"),
        ):
            with self.subTest(irule=irule), self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                message,
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "requests": [{"uri": "/"}],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_multiple_attached_irules_compose_with_isolated_defaults(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irules": [
                    "priority 100\nwhen HTTP_REQUEST { log local0. first }",
                    {"irule": "when HTTP_REQUEST { log local0. second }"},
                    "priority 50\ntiming off\nwhen HTTP_REQUEST { log local0. third }",
                ],
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            result["event_controls"],
            [
                {"ordinal": 0, "event": "HTTP_REQUEST", "priority": 100, "timing": "on"},
                {"ordinal": 1, "event": "HTTP_REQUEST", "priority": 500, "timing": "on"},
                {"ordinal": 2, "event": "HTTP_REQUEST", "priority": 50, "timing": "off"},
            ],
        )
        logs = result["results"][0]["logs"]
        log_indexes = {
            label: next(index for index, entry in enumerate(logs) if label in entry)
            for label in ("first", "second", "third")
        }
        self.assertLess(log_indexes["third"], log_indexes["first"])
        self.assertLess(log_indexes["first"], log_indexes["second"])

    def test_multiple_attached_irules_validate_shape_and_conflicts(self) -> None:
        for scenario in (
            {"irules": []},
            {"irules": [""]},
            {"irules": [{"unexpected": "field"}]},
            {"irules": [{"irule": "when HTTP_REQUEST {}", "irule_file": "x.tcl"}]},
            {"irule": "when HTTP_REQUEST {}", "irules": ["when HTTP_REQUEST {}"]},
            {"irules": ["when HTTP_REQUEST {}"] * 65},
        ):
            with self.subTest(scenario=scenario), self.assertRaises(
                self.adapter.EmulatorInputError
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "requests": [{"uri": "/"}],
                        **scenario,
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_command_probe_rejects_multiple_attached_rule_fixture(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "command probe scenario cannot provide irules",
        ):
            self.adapter.run_command_probe(
                {
                    "command": "HTTP::host",
                    "event": "HTTP_REQUEST",
                    "scenario": {"irules": ["when HTTP_REQUEST {}"]},
                },
                tcl_lsp_root=self.tcl_lsp_root,
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

    def test_packet_http_lifecycle_covers_collection_rewrite_and_html_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REWRITE", "HTML"],
                "irule": """
when HTTP_REQUEST { HTTP::collect 3 }
when REWRITE_REQUEST_DONE {
    log local0. rewrite-request
    REWRITE::post_process 1
}
when HTTP_REQUEST_DATA {
    log local0. "request-data=[HTTP::payload]"
    HTTP::release
}
when HTTP_REQUEST_SEND { log local0. request-send }
when HTTP_RESPONSE {
    HTTP::collect 2
    HTML::enable
}
when HTML_TAG_MATCHED { log local0. html-tag }
when HTML_COMMENT_MATCHED { log local0. html-comment }
when HTTP_RESPONSE_DATA {
    log local0. "response-data=[HTTP::payload]"
    HTTP::release
}
when REWRITE_RESPONSE_DONE { log local0. rewrite-response }
""",
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "method": "POST",
                        "uri": "/submit",
                        "body": "abc",
                    },
                    {
                        "protocol": "http",
                        "direction": "server_to_client",
                        "status": 200,
                        "response_headers": {
                            "Content-Length": "36",
                            "Content-Type": "text/html",
                        },
                        "response_body": "<html><!--x--><body>ok</body></html>",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        transaction = result["results"][0]
        events = transaction["events_fired"]
        for event in (
            "HTTP_REQUEST_DATA",
            "REWRITE_REQUEST_DONE",
            "HTTP_REQUEST_SEND",
            "HTTP_RESPONSE_DATA",
            "HTML_TAG_MATCHED",
            "HTML_COMMENT_MATCHED",
            "REWRITE_RESPONSE_DONE",
        ):
            self.assertIn(event, events)
        self.assertLess(events.index("HTTP_REQUEST_DATA"), events.index("HTTP_REQUEST_SEND"))
        self.assertTrue(any("request-data=abc" in log for log in transaction["logs"]))
        self.assertTrue(any("html-tag" in log for log in transaction["logs"]))
        self.assertTrue(any("html-comment" in log for log in transaction["logs"]))
        self.assertTrue(any("rewrite-response" in log for log in transaction["logs"]))
        self.assertTrue(any("response-data=<html><!--x--><body>ok</body></html>" in log for log in transaction["logs"]))

    def test_http_lifecycle_fires_rewrite_entry_events_before_http_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REWRITE"],
                "irule": (
                    "when REWRITE_REQUEST { REWRITE::payload replace 0 7 rewritten; log local0. rewrite-request }\n"
                    "when HTTP_REQUEST { log local0. http-request }\n"
                    "when REWRITE_RESPONSE { REWRITE::payload replace 0 8 returned; log local0. rewrite-response }\n"
                    "when HTTP_RESPONSE { log local0. http-response }"
                ),
                "request": {
                    "uri": "/rewrite",
                    "body": "request-body",
                    "response_status": 200,
                    "response_body": "response-body",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        events = result["results"][0]["events_fired"]
        self.assertLess(events.index("REWRITE_REQUEST"), events.index("HTTP_REQUEST"))
        self.assertLess(events.index("REWRITE_RESPONSE"), events.index("HTTP_RESPONSE"))
        self.assertEqual(result["results"][0]["request"]["body"], "rewritten-body")
        self.assertEqual(result["results"][0]["response"]["body"], "returned-body")
        logs = result["results"][0]["logs"]
        self.assertTrue(any("rewrite-request" in log for log in logs))
        self.assertTrue(any("http-request" in log for log in logs))
        self.assertTrue(any("rewrite-response" in log for log in logs))
        self.assertTrue(any("http-response" in log for log in logs))

        rewrite_only = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REWRITE"],
                "irule": (
                    "when REWRITE_REQUEST { REWRITE::payload replace 0 7 rewritten }\n"
                    "when REWRITE_RESPONSE { REWRITE::payload replace 0 8 returned }"
                ),
                "request": {
                    "uri": "/rewrite-only",
                    "body": "request-body",
                    "response_status": 200,
                    "response_body": "response-body",
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        rewrite_only_result = rewrite_only["results"][0]
        rewrite_only_events = rewrite_only_result["events_fired"]
        self.assertIn("REWRITE_REQUEST", rewrite_only_events)
        self.assertIn("REWRITE_RESPONSE", rewrite_only_events)
        self.assertLess(
            rewrite_only_events.index("REWRITE_REQUEST"),
            rewrite_only_events.index("HTTP_REQUEST"),
        )
        self.assertLess(
            rewrite_only_events.index("REWRITE_RESPONSE"),
            rewrite_only_events.index("HTTP_RESPONSE"),
        )
        self.assertEqual(rewrite_only_result["request"]["body"], "rewritten-body")
        self.assertEqual(rewrite_only_result["response"]["body"], "returned-body")

    def test_packet_trace_fires_rule_init_once_across_connections(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when RULE_INIT { log local0. init }
when CLIENT_ACCEPTED { log local0. accepted }
when CLIENT_CLOSED { log local0. closed }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 80},
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["FIN", "ACK"],
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "flags": ["SYN"],
                        "source": {"address": "10.0.0.5", "port": 51001},
                        "destination": {"address": "192.0.2.10", "port": 80},
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
        self.assertEqual(events.count("RULE_INIT"), 1)
        self.assertEqual(events.count("CLIENT_ACCEPTED"), 2)
        self.assertEqual(events.count("CLIENT_CLOSED"), 1)

    def test_packet_trace_models_client_and_server_ssl_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL", "SERVERSSL"],
                "irule": """
when CLIENTSSL_CLIENTHELLO {
    SSL::alpn set h2 http/1.1
    SSL::handshake hold
    SSL::renegotiate disable
    SSL::secure_renegotiation require-strict
    SSL::allow_nonssl 1
    SSL::allow_dynamic_record_sizing 1
    SSL::authenticate always
    SSL::authenticate depth 4
    SSL::maximum_record_size 1200
    SSL::unclean_shutdown enable
    SSL::profile /Common/clientssl_alt
    SSL::session invalidate nodrop
    log local0. "mode=[SSL::mode] alpn=[SSL::alpn] max=[SSL::maximum_record_size] dynamic=[SSL::allow_dynamic_record_sizing] secure=[SSL::is_renegotiation_secure] random=[SSL::clientrandom] ticket=[SSL::sessionticket]"
}
when SERVERSSL_HANDSHAKE {
    SSL::alpn set http/1.1
    SSL::handshake resume
    SSL::renegotiate
    log local0. "mode=[SSL::mode] alpn=[SSL::alpn]"
}
""",
                "packets": [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_hello",
                        "renegotiation_secure": True,
                        "clientrandom": "001122aabbcc",
                        "sessionticket": "ticket-1",
                    },
                    {"protocol": "tls", "direction": "server_to_client", "type": "server_handshake"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        events = [event for packet in result["trace"] for event in packet["events"]]
        client_event = next(event for event in events if event["event"] == "CLIENTSSL_CLIENTHELLO")
        server_event = next(event for event in events if event["event"] == "SERVERSSL_HANDSHAKE")
        client_tls = client_event["state"]["tls_client"]
        server_tls = server_event["state"]["tls_server"]
        self.assertEqual(client_tls["alpn"], "h2 http/1.1")
        self.assertEqual(client_tls["handshake_held"], "1")
        self.assertEqual(client_tls["renegotiation_enabled"], "0")
        self.assertEqual(client_tls["secure_renegotiation"], "2")
        self.assertEqual(client_tls["renegotiation_secure"], "1")
        self.assertEqual(client_tls["allow_nonssl"], "1")
        self.assertEqual(client_tls["dynamic_record_sizing"], "1")
        self.assertEqual(client_tls["authenticate_frequency"], "always")
        self.assertEqual(client_tls["authenticate_depth"], "4")
        self.assertEqual(client_tls["maximum_record_size"], "1200")
        self.assertEqual(client_tls["profile"], "/Common/clientssl_alt")
        self.assertEqual(client_tls["session_invalidated"], "1")
        self.assertEqual(client_tls["session_drop"], "0")
        self.assertEqual(client_tls["unclean_shutdown"], "1")
        self.assertEqual(server_tls["alpn"], "http/1.1")
        self.assertEqual(server_tls["handshake_held"], "0")
        self.assertEqual(server_tls["renegotiation_requested"], "1")
        self.assertTrue(any("mode=1" in entry and "dynamic=1" in entry and "secure=1" in entry and "random=001122aabbcc" in entry and "ticket=ticket-1" in entry for entry in client_event["logs"]))
        self.assertTrue(any("mode=1" in entry for entry in server_event["logs"]))
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]
             if entry["name"].startswith("SSL::")},
            {
                "SSL::alpn": "semantic-mock",
                "SSL::allow_dynamic_record_sizing": "semantic-mock",
                "SSL::allow_nonssl": "semantic-mock",
                "SSL::authenticate": "semantic-mock",
                "SSL::clientrandom": "semantic-mock",
                "SSL::handshake": "semantic-mock",
                "SSL::is_renegotiation_secure": "semantic-mock",
                "SSL::maximum_record_size": "semantic-mock",
                "SSL::mode": "semantic-mock",
                "SSL::profile": "semantic-mock",
                "SSL::renegotiate": "semantic-mock",
                "SSL::secure_renegotiation": "semantic-mock",
                "SSL::session": "semantic-mock",
                "SSL::sessionticket": "semantic-mock",
                "SSL::unclean_shutdown": "semantic-mock",
            },
        )

    def test_tls_packet_adapter_covers_ssl_send_and_passthrough_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL", "SERVERSSL"],
                "irule": (
                    "when CLIENTSSL_PASSTHROUGH { log local0. passthrough }\n"
                    "when CLIENTSSL_SERVERHELLO_SEND { log local0. client-serverhello }\n"
                    "when SERVERSSL_CLIENTHELLO_SEND { log local0. server-clienthello }"
                ),
                "packets": [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "passthrough",
                    },
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "server_hello_send",
                    },
                    {
                        "protocol": "tls",
                        "direction": "server_to_client",
                        "type": "client_hello_send",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        packet_events = [
            event["event"]
            for packet in result["trace"]
            for event in packet["events"]
            if event["event"] in {
                "CLIENTSSL_PASSTHROUGH",
                "CLIENTSSL_SERVERHELLO_SEND",
                "SERVERSSL_CLIENTHELLO_SEND",
            }
        ]
        self.assertEqual(
            packet_events,
            [
                "CLIENTSSL_PASSTHROUGH",
                "CLIENTSSL_SERVERHELLO_SEND",
                "SERVERSSL_CLIENTHELLO_SEND",
            ],
        )
        self.assertTrue(
            any(
                "passthrough" in log
                for packet in result["trace"]
                for event in packet["events"]
                for log in event["logs"]
            )
        )
        self.assertTrue(
            any(
                "client-serverhello" in log
                for packet in result["trace"]
                for event in packet["events"]
                for log in event["logs"]
            )
        )
        self.assertTrue(
            any(
                "server-clienthello" in log
                for packet in result["trace"]
                for event in packet["events"]
                for log in event["logs"]
            )
        )

    def test_ssl_remaining_175_commands_and_plaintext_collection(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL", "SERVERSSL"],
                "irule": """
when CLIENTSSL_HANDSHAKE {
    SSL::c3d extension 1.2.3.4 extension-value
    SSL::c3d cert forged-client-cert
    SSL::c3d subject commonName forged.example
    SSL::cert_constraint 1.2.3.4 constraint-value
    SSL::forward_proxy policy intercept
    SSL::forward_proxy cert response_control mask
    SSL::forward_proxy cert status verified
    SSL::forward_proxy extension 1.2.3.5 proxy-extension
    SSL::forward_proxy verified_handshake enable
    SSL::nextproto http/1.1
    log local0. "c3d=[set ::state::tls::client::c3d_subject_cn] proxy=[SSL::forward_proxy policy] cert=[SSL::forward_proxy cert] control=[SSL::forward_proxy cert response_control] verified=[SSL::forward_proxy verified_handshake] next=[SSL::nextproto] modssl=[SSL::modssl_sessionid_headers initial] secret=[SSL::sessionsecret] tls13=[SSL::tls13_secret client hs]"
    SSL::collect 4
}
when CLIENTSSL_DATA {
    log local0. "client=[SSL::payload] length=[SSL::payload length] first=[SSL::payload 2]"
    SSL::payload replace 0 2 XY
    SSL::release 2
}
when SERVERSSL_HANDSHAKE {
    log local0. "server-tls13=[SSL::tls13_secret server hs]"
    SSL::collect 3
}
when SERVERSSL_DATA {
    log local0. "server=[SSL::payload]"
    SSL::release
}
""",
                "packets": [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "handshake",
                        "session_id": "current-session",
                        "initial_session_id": "initial-session",
                        "forward_proxy_cert": "forged-cert",
                        "session_secret": "master-secret",
                        "tls13_client_hs_secret": "client-hs-secret",
                    },
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_data",
                        "payload": "ab",
                    },
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_data",
                        "payload": "cd",
                    },
                    {
                        "protocol": "tls",
                        "direction": "server_to_client",
                        "type": "server_handshake",
                        "tls13_server_hs_secret": "server-hs-secret",
                    },
                    {
                        "protocol": "tls",
                        "direction": "server_to_client",
                        "type": "server_data",
                        "payload": "xyz",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        client_data = next(
            packet for packet in result["trace"]
            if packet.get("buffered") and packet["direction"] == "client_to_server"
        )
        client_event_packet = next(
            packet for packet in result["trace"]
            if any(event["event"] == "CLIENTSSL_DATA" for event in packet["events"])
        )
        server_data = next(
            packet for packet in result["trace"]
            if any(event["event"] == "SERVERSSL_DATA" for event in packet["events"])
        )
        self.assertTrue(client_data["buffered"])
        client_event = next(
            event for event in client_event_packet["events"]
            if event["event"] == "CLIENTSSL_DATA"
        )
        self.assertTrue(any("client=abcd length=4 first=ab" in entry for entry in client_event["logs"]))
        self.assertEqual(client_event["state"]["tls_client"]["payload"], "cd")
        self.assertEqual(client_event["state"]["tls_client"]["released_length"], "2")
        self.assertTrue(server_data["events"])
        self.assertTrue(any("server=xyz" in entry for entry in server_data["events"][0]["logs"]))
        self.assertEqual(server_data["events"][0]["state"]["tls_server"]["payload"], "")

        handshake = next(
            event for packet in result["trace"] for event in packet["events"]
            if event["event"] == "CLIENTSSL_HANDSHAKE"
        )
        self.assertTrue(any("c3d=forged.example" in entry for entry in handshake["logs"]))
        self.assertTrue(any("proxy=intercept" in entry for entry in handshake["logs"]))
        self.assertTrue(any("cert=forged-cert" in entry for entry in handshake["logs"]))
        self.assertTrue(any("control=mask" in entry for entry in handshake["logs"]))
        self.assertTrue(any("verified=1" in entry for entry in handshake["logs"]))
        self.assertTrue(any("next=http/1.1" in entry for entry in handshake["logs"]))
        self.assertTrue(any("SSLClientSessionId initial-session" in entry for entry in handshake["logs"]))
        self.assertTrue(any("secret=master-secret" in entry and "tls13=client-hs-secret" in entry for entry in handshake["logs"]))
        server_handshake = next(
            event for packet in result["trace"] for event in packet["events"]
            if event["event"] == "SERVERSSL_HANDSHAKE"
        )
        self.assertTrue(any("server-tls13=server-hs-secret" in entry for entry in server_handshake["logs"]))

        ssl_statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("SSL::")
        }
        for command in {
            "SSL::c3d",
            "SSL::cert_constraint",
            "SSL::collect",
            "SSL::forward_proxy",
            "SSL::modssl_sessionid_headers",
            "SSL::nextproto",
            "SSL::payload",
            "SSL::release",
            "SSL::sessionsecret",
            "SSL::tls13_secret",
        }:
            self.assertEqual(ssl_statuses[command], "semantic-mock")

    def test_generic_server_event_uses_server_ssl_state(self) -> None:
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "SERVERSSL"],
                "irule": """
when SERVER_CONNECTED {
    SSL::alpn set h2
    SSL::session invalidate nodrop
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "SERVER_CONNECTED",
                {"tls_server": {"cipher_name": "TLS_AES_256_GCM_SHA384"}},
            )
        finally:
            session.close()

        self.assertTrue(result["fired"])
        self.assertEqual(result["state"]["tls_server"]["alpn"], "h2")
        self.assertEqual(result["state"]["tls_server"]["session_invalidated"], "1")
        self.assertEqual(result["state"]["tls_server"]["session_drop"], "0")

    def test_x509_certificate_inspection_uses_packet_fixture_metadata(self) -> None:
        pem = "-----BEGIN CERTIFICATE-----\nSGVsbG8=\n-----END CERTIFICATE-----"
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTCERT {
    set cert [SSL::cert 0]
    set fields [X509::cert_fields $cert 10 hash issuer serial sigalg subject subpubkey validity versionnum whole]
    log local0. "fields=$fields"
    log local0. "ext=[X509::extensions $cert] hash=[X509::hash $cert] issuer=[X509::issuer $cert] serial=[X509::serial_number $cert] sigalg=[X509::signature_algorithm $cert] type=[X509::subject_public_key_type $cert] bits=[X509::subject_public_key_RSA_bits $cert] key=[X509::subject_public_key $cert] curve=[X509::subject_public_key curve_name $cert] version=[X509::version $cert] before=[X509::not_valid_before $cert] after=[X509::not_valid_after $cert] err=[X509::verify_cert_error_string 10] der=[binary encode hex [X509::pem2der [X509::whole $cert]]]"
}
""",
                "packets": [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_cert",
                        "cert_count": 1,
                        "cert_subject": "CN=client.example.com,O=Example",
                        "cert_issuer": "CN=Example Root",
                        "cert_serial": "01:02:03",
                        "cert_hash": "AA:BB:CC",
                        "cert_extensions": "X509v3 extensions:\n    X509v3 Extended Key Usage: clientAuth",
                        "cert_not_valid_before": "Jan  1 00:00:00 2026 GMT",
                        "cert_not_valid_after": "Jan  1 00:00:00 2027 GMT",
                        "cert_signature_algorithm": "sha256WithRSAEncryption",
                        "cert_public_key": "public-key",
                        "cert_public_key_type": "RSA",
                        "cert_public_key_bits": 2048,
                        "cert_public_key_curve": "",
                        "cert_version": 3,
                        "cert_pem": pem,
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event = next(
            event for packet in result["trace"] for event in packet["events"]
            if event["event"] == "CLIENTSSL_CLIENTCERT"
        )
        self.assertTrue(any("SSL_CLIENT_CERT_HASH AA:BB:CC" in entry for entry in event["logs"]))
        self.assertTrue(any("SSL_CLIENT_I_DN {CN=Example Root}" in entry for entry in event["logs"]))
        self.assertTrue(any("ext=X509v3 extensions:" in entry for entry in event["logs"]))
        self.assertTrue(any("serial=01:02:03" in entry and "type=RSA" in entry and "bits=2048" in entry for entry in event["logs"]))
        self.assertTrue(any("version=3" in entry and "err=certificate has expired" in entry and "der=48656c6c6f" in entry for entry in event["logs"]))

        x509_statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("X509::")
        }
        for command in {
            "X509::cert_fields",
            "X509::extensions",
            "X509::hash",
            "X509::not_valid_after",
            "X509::not_valid_before",
            "X509::pem2der",
            "X509::serial_number",
            "X509::signature_algorithm",
            "X509::subject_public_key",
            "X509::subject_public_key_RSA_bits",
            "X509::subject_public_key_type",
            "X509::verify_cert_error_string",
            "X509::version",
            "X509::whole",
        }:
            self.assertEqual(x509_statuses[command], "semantic-mock")

    def test_x509_certificate_inspection_derives_fields_from_valid_pem(self) -> None:
        pem, der = _valid_client_certificate()
        expected_hash = ":".join(
            f"{byte:02X}"
            for byte in hashlib.md5(der, usedforsecurity=False).digest()
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTCERT {
    set cert [SSL::cert 0]
    log local0. "subject=[X509::subject $cert] cn=[X509::subject $cert commonName] issuer=[X509::issuer $cert] hash=[X509::hash $cert] serial=[X509::serial_number $cert] sig=[X509::signature_algorithm $cert] type=[X509::subject_public_key_type $cert] bits=[X509::subject_public_key bits $cert] rsa_bits=[X509::subject_public_key_RSA_bits $cert] version=[X509::version $cert] before=[X509::not_valid_before $cert] after=[X509::not_valid_after $cert] ext=[X509::extensions $cert] der=[string length [X509::pem2der [X509::whole $cert]]]"
}
""",
                "packets": [{
                    "protocol": "tls",
                    "direction": "client_to_server",
                    "type": "client_cert",
                    "cert_pem": pem,
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event = next(
            item
            for item in result["trace"][0]["events"]
            if item["event"] == "CLIENTSSL_CLIENTCERT"
        )
        self.assertTrue(event["fired"])
        self.assertTrue(any("subject=C=US,O=Example Org,CN=client.example.com" in entry for entry in event["logs"]))
        self.assertTrue(any("cn=client.example.com issuer=C=US,O=Example Root,CN=Example Root CA" in entry for entry in event["logs"]))
        self.assertTrue(any(f"hash={expected_hash}" in entry for entry in event["logs"]))
        self.assertTrue(any("serial=10203 sig=sha256WithRSAEncryption type=RSA bits=2048 rsa_bits=2048 version=3" in entry for entry in event["logs"]))
        self.assertTrue(any("before=Jan  1 00:00:00 2026 GMT after=Jan  1 00:00:00 2027 GMT" in entry for entry in event["logs"]))
        self.assertTrue(any("X509v3 extensions:" in entry and "X509v3 Subject Alternative Name:" in entry for entry in event["logs"]))
        self.assertTrue(any(f"der={len(der)}" in entry for entry in event["logs"]))

        normalised = self.adapter._normalise_packets([{
            "protocol": "tls",
            "direction": "client_to_server",
            "type": "client_cert",
            "cert_der": der.hex(),
        }])[0]
        self.assertEqual(normalised["cert_count"], 1)
        self.assertEqual(normalised["cert_subject"], "C=US,O=Example Org,CN=client.example.com")
        self.assertEqual(normalised["cert_hash"], expected_hash)
        self.assertEqual(normalised["cert_version"], 3)

    def test_raw_tls_certificate_record_populates_x509_state(self) -> None:
        _, der = _valid_client_certificate()
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTCERT {
    set cert [SSL::cert 0]
    log local0. "count=[SSL::cert count] cn=[X509::subject $cert commonName] hash=[X509::hash $cert]"
}
""",
                "packets": [{
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "network": "ipv4",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "192.0.2.20",
                        "192.0.2.10",
                        51000,
                        443,
                        0x10,
                        _tls_certificate_payload(der, der),
                    ),
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event = next(
            item
            for item in result["trace"][0]["events"]
            if item["event"] == "CLIENTSSL_CLIENTCERT"
        )
        expected_hash = ":".join(
            f"{byte:02X}"
            for byte in hashlib.md5(der, usedforsecurity=False).digest()
        )
        self.assertTrue(event["fired"])
        self.assertTrue(any("count=2 cn=client.example.com" in entry for entry in event["logs"]))
        self.assertTrue(any(f"hash={expected_hash}" in entry for entry in event["logs"]))

    def test_raw_tls13_certificate_record_populates_x509_state(self) -> None:
        _, der = _valid_client_certificate()
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTCERT {
    set cert [SSL::cert 0]
    log local0. "count=[SSL::cert count] cn=[X509::subject $cert commonName]"
}
""",
                "packets": [{
                    "protocol": "wire",
                    "direction": "client_to_server",
                    "network": "ipv4",
                    "raw_hex": _raw_ipv4_tcp_hex(
                        "192.0.2.20",
                        "192.0.2.10",
                        51000,
                        443,
                        0x10,
                        _tls_certificate_payload(der, der, tls13=True),
                    ),
                }],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event = next(
            item
            for item in result["trace"][0]["events"]
            if item["event"] == "CLIENTSSL_CLIENTCERT"
        )
        self.assertTrue(event["fired"])
        self.assertTrue(any("count=2 cn=client.example.com" in entry for entry in event["logs"]))

    def test_raw_tls_certificate_handshake_reassembles_across_tcp_segments(self) -> None:
        _, der = _valid_client_certificate()
        payload = _tls_certificate_payload(der, der)
        split_at = 13
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTCERT {
    set cert [SSL::cert 0]
    log local0. "count=[SSL::cert count] cn=[X509::subject $cert commonName]"
}
""",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "network": "ipv4",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.20",
                            "192.0.2.10",
                            51000,
                            443,
                            0x10,
                            payload[:split_at],
                            sequence=1000,
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "network": "ipv4",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.20",
                            "192.0.2.10",
                            51000,
                            443,
                            0x10,
                            payload[split_at:],
                            sequence=1000 + split_at,
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        events = [
            event
            for entry in result["trace"]
            for event in entry["events"]
            if event["event"] == "CLIENTSSL_CLIENTCERT"
        ]
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["fired"])
        self.assertTrue(any("count=2 cn=client.example.com" in entry for entry in events[0]["logs"]))

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
        server_init = result["trace"][2]["events"][0]
        server_connected = result["trace"][2]["events"][1]
        server_event = result["trace"][2]["events"][2]
        self.assertEqual(client_event["event"], "CLIENT_DATA")
        self.assertTrue(
            any("client=client-data length=11 offset=11" in entry for entry in client_event["logs"])
        )
        self.assertIn("tcp payload_replace", str(client_event["decisions"]))
        self.assertEqual(server_event["event"], "SERVER_DATA")
        self.assertEqual(server_init["event"], "SERVER_INIT")
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
    WS::payload_processing disable
    WS::payload_ivs /Common/mqtt_ivs
    log local0. "payload-processing=[set ::state::websocket::payload_processing] ivs=[set ::state::websocket::payload_ivs]"
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
                "payload-processing=disable ivs=/Common/mqtt_ivs" in entry
                for entry in request_event["logs"]
            )
        )
        self.assertEqual(request_event["state"]["websocket"]["payload_processing"], "disable")
        self.assertEqual(request_event["state"]["websocket"]["payload_ivs"], "/Common/mqtt_ivs")
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("WS::payload_ivs", "WS::payload_processing"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")
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

    def test_packet_trace_drives_rtsp_events_headers_collection_and_response(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "RTSP"],
                "irule": """
when RTSP_REQUEST {
    log local0. "request=[RTSP::method] [RTSP::uri] [RTSP::version] source=[RTSP::msg_source] cseq=[RTSP::header value CSeq]"
    RTSP::header replace Transport RTP/AVP/TCP
    RTSP::collect 4
}
when RTSP_REQUEST_DATA {
    log local0. "request-data=[RTSP::payload] length=[RTSP::payload length]"
    RTSP::payload replace 0 4 PONG
    RTSP::release
}
when RTSP_RESPONSE {
    log local0. "response=[RTSP::status] [RTSP::header value Content-Type]"
    RTSP::header insert [list X-Test yes]
    RTSP::collect
}
when RTSP_RESPONSE_DATA {
    log local0. "response-data=[RTSP::payload]"
    RTSP::release
}
""",
                "packets": [
                    {
                        "protocol": "rtsp",
                        "type": "request",
                        "direction": "client_to_server",
                        "method": "DESCRIBE",
                        "uri": "rtsp://media.example/live",
                        "headers": {
                            "CSeq": "1",
                            "Transport": "RTP/AVP;unicast",
                        },
                        "payload": "ping",
                    },
                    {
                        "protocol": "rtsp",
                        "type": "response",
                        "direction": "server_to_client",
                        "status": 200,
                        "phrase": "OK",
                        "response_headers": {
                            "CSeq": "1",
                            "Content-Type": "application/sdp",
                        },
                        "payload": "sdp",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            [event["event"] for packet in result["trace"] for event in packet["events"]],
            [
                "RULE_INIT",
                "CLIENT_ACCEPTED",
                "RTSP_REQUEST",
                "RTSP_REQUEST_DATA",
                "RTSP_RESPONSE",
                "RTSP_RESPONSE_DATA",
            ],
        )
        request_event = result["trace"][0]["events"][2]
        request_data = result["trace"][0]["events"][3]
        response_event = result["trace"][1]["events"][0]
        self.assertTrue(any("DESCRIBE rtsp://media.example/live RTSP/1.0" in log for log in request_event["logs"]))
        self.assertTrue(any("request-data=ping length=4" in log for log in request_data["logs"]))
        self.assertEqual(result["trace"][0]["payload_after"], "PONG")
        self.assertIn("Transport", request_event["state"]["rtsp"]["headers"])
        self.assertTrue(any("response=200 application/sdp" in log for log in response_event["logs"]))
        self.assertIn("X-Test", response_event["state"]["rtsp"]["headers"])
        self.assertTrue(result["trace"][0]["released"])
        self.assertTrue(result["trace"][1]["released"])

        response = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "RTSP"],
                "irule": 'when RTSP_REQUEST { RTSP::respond 401 Unauthorized "X-Reason: denied\\r\\n\\r\\nblocked" }',
                "packets": [
                    {
                        "protocol": "rtsp",
                        "type": "request",
                        "direction": "client_to_server",
                        "method": "OPTIONS",
                        "uri": "*",
                        "headers": {"CSeq": "8"},
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        response_entry = response["trace"][0]
        self.assertEqual(response_entry["events"][-1]["event"], "RTSP_REQUEST")
        self.assertEqual(response_entry["response"]["status"], 401)
        self.assertEqual(
            response_entry["response"]["headers"],
            [["X-Reason", "denied"], ["CSeq", "8"]],
        )
        self.assertEqual(response_entry["response"]["body"], "blocked")
        self.assertEqual(response["emitted"][0]["protocol"], "rtsp")

    def test_cache_profile_replays_hits_and_exposes_cache_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "CACHE"],
                "irule": """
when HTTP_REQUEST {
    CACHE::userkey tenant-a
    CACHE::accept_encoding gzip
    CACHE::uri /canonical-asset.js
    CACHE::useragent cache-test-agent
    CACHE::priority 5
}
when CACHE_REQUEST {
    log local0. "lookup age=[CACHE::age] hits=[CACHE::hits] fresh=[CACHE::fresh]"
}
when CACHE_RESPONSE {
    if {[CACHE::header exists content-type]} {
        log local0. "hit payload=[CACHE::payload] headers=[CACHE::headers] type=[CACHE::header value CONTENT-TYPE]"
    }
    CACHE::header replace X-Cache HIT
    CACHE::header insert X-Temporary remove-me
    CACHE::header remove X-Temporary
    log local0. "cache-header=[CACHE::header value x-cache] exists=[CACHE::header exists X-CACHE HIT] removed=[CACHE::header exists X-Temporary] trace=[CACHE::trace 1]"
}
when CACHE_UPDATE {
    log local0. "update stats=[CACHE::statskey] uri=[CACHE::uri] ua=[CACHE::useragent] encoding=[CACHE::accept_encoding] priority=[CACHE::priority]"
}
""",
                "requests": [
                    {
                        "method": "GET",
                        "host": "cache.example",
                        "uri": "/asset.js",
                        "response_headers": {"Content-Type": "application/javascript"},
                        "response_body": "console.log(1)",
                    },
                    {
                        "method": "GET",
                        "host": "cache.example",
                        "uri": "/asset.js",
                        "response_status": 503,
                        "response_body": "origin-unavailable",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first, second = result["results"]
        self.assertEqual(first["response"]["body"], "console.log(1)")
        self.assertEqual(second["response"]["body"], "console.log(1)")
        self.assertEqual(second["response"]["headers"]["x-cache"], "HIT")
        self.assertIn("CACHE_REQUEST", first["events_fired"])
        self.assertIn("CACHE_UPDATE", first["events_fired"])
        self.assertIn("CACHE_RESPONSE", second["events_fired"])
        self.assertNotIn("HTTP_RESPONSE", second["events_fired"])
        self.assertTrue(any("lookup age=1 hits=1 fresh=1" in log for log in second["logs"]))
        self.assertTrue(any("type=application/javascript" in log for log in second["logs"]))
        self.assertTrue(any("cache-header=HIT exists=1 removed=0" in log for log in second["logs"]))
        self.assertEqual(first["semantic"]["cache"]["uri"], "/canonical-asset.js")
        self.assertEqual(first["semantic"]["cache"]["useragent"], "cache-test-agent")
        self.assertEqual(first["semantic"]["cache"]["accept_encoding"], "gzip")
        self.assertEqual(first["semantic"]["cache"]["priority"], "5")
        self.assertEqual(second["semantic"]["cache"]["object_count"], "1")

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "CACHE"],
                "irule": "when HTTP_REQUEST { CACHE::disable }",
                "requests": [
                    {
                        "uri": "/private",
                        "response_body": "private",
                    },
                    {
                        "uri": "/private",
                        "response_body": "private-again",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn("CACHE_RESPONSE", disabled["results"][1]["events_fired"])
        self.assertEqual(disabled["results"][1]["response"]["body"], "private-again")
        self.assertEqual(disabled["results"][0]["semantic"]["cache"]["disabled"], "1")

        revalidated = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "CACHE"],
                "irule": """
when CACHE_REQUEST {
    if {[CACHE::hits] > 1} { CACHE::expire }
}
when CACHE_RESPONSE { }
when CACHE_UPDATE { }
""",
                "requests": [
                    {"uri": "/revalidate", "response_body": "version-1"},
                    {"uri": "/revalidate", "response_body": "origin-not-used"},
                    {"uri": "/revalidate", "response_body": "version-2"},
                    {"uri": "/revalidate", "response_body": "origin-not-used-again"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            [entry["response"]["body"] for entry in revalidated["results"]],
            ["version-1", "version-1", "version-2", "version-2"],
        )
        self.assertIn("CACHE_RESPONSE", revalidated["results"][1]["events_fired"])
        self.assertNotIn("CACHE_RESPONSE", revalidated["results"][2]["events_fired"])
        self.assertIn("CACHE_UPDATE", revalidated["results"][2]["events_fired"])
        self.assertIn("CACHE_RESPONSE", revalidated["results"][3]["events_fired"])

        forced_post = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "CACHE"],
                "irule": """
when HTTP_REQUEST { CACHE::enable }
when CACHE_RESPONSE { }
when CACHE_UPDATE { }
""",
                "requests": [
                    {"method": "POST", "uri": "/forced", "response_body": "post-1"},
                    {"method": "POST", "uri": "/forced", "response_body": "origin-not-used"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(forced_post["results"][1]["response"]["body"], "post-1")
        self.assertIn("CACHE_RESPONSE", forced_post["results"][1]["events_fired"])
        self.assertEqual(forced_post["results"][1]["semantic"]["cache"]["forced"], "1")

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
        server_init = result["trace"][2]["events"][0]
        server_connected = result["trace"][2]["events"][1]
        server_event = result["trace"][2]["events"][2]
        self.assertEqual(client_event["event"], "CLIENT_DATA")
        self.assertEqual(server_init["event"], "SERVER_INIT")
        self.assertEqual(server_connected["event"], "SERVER_CONNECTED")
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
            ["MQTT_CLIENT_INGRESS", "MQTT_CLIENT_DATA", "MQTT_SERVER_EGRESS"],
        )
        self.assertTrue(
            any("client=sensor-1 type=PUBLISH topic=sensors/temp" in entry for entry in publish_events[0]["logs"])
        )
        self.assertTrue(
            any("payload=abc length=3" in entry for entry in publish_events[1]["logs"])
        )
        self.assertEqual(publish_events[1]["state"]["mqtt"]["payload"], "xyz")
        self.assertEqual(publish_events[2]["forwarded"]["to"], "server")
        self.assertEqual(publish_events[2]["forwarded"]["packet"]["payload"], "xyz")
        self.assertTrue(connack_events[-1]["fired"])
        self.assertTrue(any("server=CONNACK code=0" in entry for entry in connack_events[-1]["logs"]))
        self.assertEqual(
            [event["event"] for event in connack_events],
            ["MQTT_SERVER_INGRESS"],
        )
        self.assertTrue(result["trace"][2]["dropped"])
        self.assertEqual(result["trace"][2]["drop_reason"], "message")
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("MQTT::collect", "MQTT::payload", "MQTT::release", "MQTT::drop"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_mqtt_server_ingress_drives_client_egress_forwarding(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MQTT"],
                "irule": (
                    "when MQTT_SERVER_INGRESS { log local0. \"incoming=[MQTT::type]\" }\n"
                    "when MQTT_CLIENT_EGRESS { log local0. \"outgoing=[MQTT::type]\" }"
                ),
                "packets": [
                    {
                        "protocol": "mqtt",
                        "type": "CONNACK",
                        "direction": "server_to_client",
                        "return_code": 0,
                        "session_present": True,
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        message_events = [
            event
            for event in result["trace"][0]["events"]
            if event["event"] in {"MQTT_SERVER_INGRESS", "MQTT_CLIENT_EGRESS"}
        ]
        self.assertEqual(
            [event["event"] for event in message_events],
            ["MQTT_SERVER_INGRESS", "MQTT_CLIENT_EGRESS"],
        )
        self.assertEqual(message_events[0]["forwarded"]["to"], "client")
        self.assertEqual(message_events[1]["forwarded"]["to"], "client")
        self.assertEqual(message_events[1]["forwarded"]["packet"]["type"], "CONNACK")
        self.assertTrue(any("outgoing=CONNACK" in log for log in message_events[1]["logs"]))

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

    def test_mqtt_message_mutation_response_and_insert_emissions(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MQTT"],
                "irule": """
when MQTT_CLIENT_INGRESS {
    if {[MQTT::type] eq "CONNECT"} {
        MQTT::will topic /devices/will
        MQTT::will message offline
        MQTT::will qos 1
        MQTT::will retain 1
        MQTT::insert after type PINGREQ
        MQTT::respond type CONNACK return_code 5
    }
    if {[MQTT::type] eq "PUBLISH"} {
        MQTT::replace type PUBLISH topic rewritten payload changed qos 1 packet_id 7 dup 1 retain 1
    }
    if {[MQTT::type] eq "SUBSCRIBE"} {
        MQTT::replace type SUBSCRIBE packet_id 9 topic_list {{devices/# 1} {alerts 0}}
    }
}
""",
                "packets": [
                    {
                        "protocol": "mqtt",
                        "type": "CONNECT",
                        "direction": "client_to_server",
                        "client_id": "device-1",
                        "username": "alice",
                        "password": "secret",
                    },
                    {
                        "protocol": "mqtt",
                        "type": "PUBLISH",
                        "direction": "client_to_server",
                        "topic": "devices/input",
                        "payload": "online",
                        "qos": 0,
                    },
                    {
                        "protocol": "mqtt",
                        "type": "SUBSCRIBE",
                        "direction": "client_to_server",
                        "packet_id": 2,
                        "topic_list": [["devices/#", 0]],
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        connect_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "MQTT_CLIENT_INGRESS"
        )
        self.assertEqual(connect_event["event"], "MQTT_CLIENT_INGRESS")
        self.assertEqual(connect_event["forwarded"]["to"], "server")
        self.assertEqual(connect_event["forwarded"]["packet"]["will_flag"], "1")
        self.assertEqual(connect_event["forwarded"]["packet"]["will_qos"], "1")
        self.assertEqual(connect_event["forwarded"]["packet"]["will_retain"], "1")
        self.assertEqual(connect_event["forwarded"]["packet"]["username_flag"], "1")
        self.assertEqual(connect_event["forwarded"]["packet"]["password_flag"], "1")
        self.assertEqual(connect_event["emissions"][0]["kind"], "insert")
        self.assertEqual(connect_event["emissions"][0]["position"], "after")
        self.assertEqual(connect_event["emissions"][0]["to"], "server")
        self.assertEqual(connect_event["emissions"][0]["packet"]["type"], "PINGREQ")
        self.assertEqual(connect_event["emissions"][1]["kind"], "response")
        self.assertEqual(connect_event["emissions"][1]["to"], "client")
        self.assertEqual(connect_event["emissions"][1]["packet"]["return_code"], "5")
        connect_egress = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "MQTT_SERVER_EGRESS"
        )
        self.assertEqual(connect_egress["event"], "MQTT_SERVER_EGRESS")
        self.assertEqual(connect_egress["forwarded"]["to"], "server")
        self.assertEqual(connect_egress["forwarded"]["packet"]["will_topic"], "/devices/will")

        publish_event = result["trace"][1]["events"][0]
        self.assertEqual(publish_event["forwarded"]["packet"]["topic"], "rewritten")
        self.assertEqual(publish_event["forwarded"]["packet"]["payload"], "changed")
        self.assertEqual(publish_event["forwarded"]["packet"]["qos"], "1")
        self.assertEqual(publish_event["forwarded"]["packet"]["packet_id"], "7")
        self.assertEqual(publish_event["forwarded"]["packet"]["dup"], "1")
        self.assertEqual(publish_event["forwarded"]["packet"]["retain"], "1")
        publish_egress = result["trace"][1]["events"][1]
        self.assertEqual(publish_egress["event"], "MQTT_SERVER_EGRESS")
        self.assertEqual(publish_egress["forwarded"]["packet"]["topic"], "rewritten")
        self.assertEqual(publish_egress["forwarded"]["packet"]["payload"], "changed")

        subscribe_event = result["trace"][2]["events"][0]
        self.assertEqual(
            subscribe_event["forwarded"]["packet"]["topic_list"],
            [["devices/#", "1"], ["alerts", "0"]],
        )
        self.assertEqual(subscribe_event["forwarded"]["packet"]["packet_id"], "9")
        self.assertEqual(result["trace"][2]["events"][1]["event"], "MQTT_SERVER_EGRESS")

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("MQTT::insert", "MQTT::replace", "MQTT::respond", "MQTT::will"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_mqtt_message_commands_reject_invalid_shapes_and_events(self) -> None:
        for irule, message in (
            (
                "when MQTT_CLIENT_INGRESS { MQTT::replace type PUBLISH topic x payload y qos 1 }",
                "packet_id",
            ),
            (
                "when MQTT_CLIENT_INGRESS { MQTT::will topic x }",
                "only for CONNECT",
            ),
        ):
            with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                self.adapter.run_scenario(
                    {
                        "profiles": ["MQTT"],
                        "irule": irule,
                        "packets": [
                            {
                                "protocol": "mqtt",
                                "type": "PUBLISH" if "will" in irule else "CONNECT",
                                "direction": "client_to_server",
                                "client_id": "device-1",
                                "topic": "x",
                                "payload": "y",
                                "qos": 0,
                            }
                        ],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_sip_structured_lifecycle_headers_payload_and_response_rewrite(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": """
when SIP_REQUEST {
    log local0. "method=[SIP::method] uri=[SIP::uri] call=[SIP::call_id] from=[SIP::from]"
    SIP::header replace X-Test changed
    SIP::payload insert 5 "!"
    SIP::persist [SIP::call_id]
}
when SIP_REQUEST_SEND {
    log local0. "names=[SIP::header names] payload=[SIP::payload] key=[SIP::persist]"
}
when SIP_REQUEST_DONE { log local0. "done=[SIP::route_status]" }
when SIP_RESPONSE {
    log local0. "code=[SIP::response code] via=[SIP::via proto 0]"
    SIP::response rewrite 202 Accepted
}
when SIP_RESPONSE_SEND { log local0. "sent=[SIP::response code]" }
when SIP_RESPONSE_DONE { log local0. response-done }
""",
                "packets": [
                    {
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "INVITE",
                        "uri": "sip:bob@example.com",
                        "headers": {
                            "Via": "SIP/2.0/UDP proxy.example.com;branch=z9",
                            "From": "<sip:alice@example.com>;tag=1",
                            "To": "<sip:bob@example.com>",
                            "Call-ID": "call-123",
                            "CSeq": "1 INVITE",
                        },
                        "payload": "hello",
                    },
                    {
                        "protocol": "sip",
                        "direction": "server_to_client",
                        "type": "response",
                        "status": 200,
                        "phrase": "OK",
                        "headers": {
                            "Via": "SIP/2.0/UDP proxy.example.com;branch=z9",
                            "From": "<sip:alice@example.com>;tag=1",
                            "To": "<sip:bob@example.com>;tag=2",
                            "Call-ID": "call-123",
                            "CSeq": "1 INVITE",
                        },
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_events = result["trace"][0]["events"]
        self.assertEqual(
            [event["event"] for event in request_events[-3:]],
            ["SIP_REQUEST", "SIP_REQUEST_SEND", "SIP_REQUEST_DONE"],
        )
        self.assertTrue(any("call=call-123" in log for log in request_events[-3]["logs"]))
        self.assertTrue(any("X-Test" in log and "hello!" in log for log in request_events[-2]["logs"]))
        self.assertIn("X-Test: changed", request_events[-1]["state"]["sip"]["message"])
        self.assertIn("hello!", request_events[-1]["state"]["sip"]["message"])
        response_events = result["trace"][1]["events"]
        self.assertEqual(
            [event["event"] for event in response_events],
            ["SIP_RESPONSE", "SIP_RESPONSE_SEND", "SIP_RESPONSE_DONE"],
        )
        self.assertTrue(any("via=UDP" in log for log in response_events[0]["logs"]))
        self.assertEqual(response_events[-1]["state"]["sip"]["status"], "202")

    def test_sip_sdp_payload_is_parsed_mutated_and_reencoded(self) -> None:
        body = (
            "v=0\r\n"
            "o=- 2890844526 2890842807 IN IP4 198.51.100.10\r\n"
            "s=Original session\r\n"
            "x=vendor-extension\r\n"
            "t=0 0\r\n"
            "m=audio 5004 RTP/AVP 0 96\r\n"
            "c=IN IP4 198.51.100.10\r\n"
            "b=AS:64\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": """
when SIP_REQUEST {
    log local0. "sid=[SDP::session_id] name=[SDP::field s] media=[SDP::media count] codec=[SDP::media attr 0 0]"
    SDP::field s 0 "Rewritten session"
    SDP::field o 0 "- 3000000000 2890842807 IN IP4 198.51.100.10"
    SDP::media port 0 6000/2
    SDP::media conn 0 "IN IP4 203.0.113.20"
}
when SIP_REQUEST_SEND {
    log local0. "sid=[SDP::session_id] name=[SDP::field s] port=[SDP::media port 0]"
}
""",
                "packets": [
                    {
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "INVITE",
                        "uri": "sip:bob@example.com",
                        "headers": {
                            "Content-Type": "application/sdp; charset=utf-8",
                            "Call-ID": "sdp-call-1",
                        },
                        "payload": body,
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]
        events = entry["events"]
        sip_events = [event for event in events if event["event"].startswith("SIP_")]
        self.assertEqual(
            [event["event"] for event in sip_events],
            ["SIP_REQUEST", "SIP_REQUEST_SEND", "SIP_REQUEST_DONE"],
        )
        self.assertTrue(any("sid=2890844526" in log for log in sip_events[0]["logs"]))
        self.assertTrue(any("media=1" in log and "codec=rtpmap:0 PCMU/8000" in log for log in sip_events[0]["logs"]))
        self.assertTrue(any("sid=3000000000 name=Rewritten session port=6000/2" in log for log in sip_events[1]["logs"]))
        self.assertEqual(sip_events[0]["state"]["sdp"]["session_id"], "3000000000")
        self.assertIn("Rewritten session", entry["payload_after"])
        self.assertIn("o=- 3000000000 2890842807", entry["payload_after"])
        self.assertIn("x=vendor-extension", entry["payload_after"])
        self.assertIn("b=AS:64", entry["payload_after"])
        self.assertIn("m=audio 6000/2 RTP/AVP 0 96", entry["payload_after"])
        self.assertIn("c=IN IP4 203.0.113.20", entry["payload_after"])
        self.assertIn(
            f"Content-Length: {len(entry['payload_after'].encode('utf-8'))}",
            entry["message_after"],
        )
        self.assertEqual(entry["wire_hex"], entry["message_after"].encode("utf-8").hex())

    def test_sip_payload_mutation_does_not_get_overwritten_by_stale_sdp_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": "when SIP_REQUEST { SIP::payload insert 0 X }",
                "packets": [
                    {
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "INVITE",
                        "uri": "sip:bob@example.com",
                        "headers": {"Content-Type": "application/sdp"},
                        "payload": "v=0\r\ns=opaque\r\n",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]
        self.assertTrue(entry["payload_after"].startswith("Xv=0\r\ns=opaque\r\n"))
        self.assertNotIn("m=", entry["payload_after"])
        sip_events = [event for event in entry["events"] if event["event"].startswith("SIP_")]
        self.assertNotIn("sdp", sip_events[-1]["state"])

    def test_sipalg_connection_and_message_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": """
when SIP_REQUEST {
    log local0. "before=[SIPALG::hairpin]/[SIPALG::hairpin_default]/[SIPALG::nonregister_subscriber_listener]"
    SIPALG::hairpin enable
    SIPALG::hairpin_default disable
    SIPALG::nonregister_subscriber_listener 1
    log local0. "after=[SIPALG::hairpin]/[SIPALG::hairpin_default]/[SIPALG::nonregister_subscriber_listener]"
}
""",
                "packets": [
                    {
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "INVITE",
                        "uri": "sip:bob@example.com",
                    },
                    {
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "BYE",
                        "uri": "sip:bob@example.com",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_event = next(
            event for event in result["trace"][0]["events"]
            if event["event"] == "SIP_REQUEST"
        )
        second_event = next(
            event for event in result["trace"][1]["events"]
            if event["event"] == "SIP_REQUEST"
        )
        self.assertTrue(any("before=detect/detect/0" in log for log in first_event["logs"]))
        self.assertTrue(any("after=enable/disable/1" in log for log in first_event["logs"]))
        self.assertTrue(any("before=disable/disable/1" in log for log in second_event["logs"]))
        self.assertTrue(any("after=enable/disable/1" in log for log in second_event["logs"]))
        self.assertEqual(first_event["semantic"]["sipalg"], {
            "hairpin": "enable",
            "hairpin_default": "disable",
            "nonregister_subscriber_listener": True,
        })
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "SIPALG::hairpin",
            "SIPALG::hairpin_default",
            "SIPALG::nonregister_subscriber_listener",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "SIPALG::hairpin accepts detect, disable, or enable",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["SIP"],
                    "irule": "when SIP_REQUEST { SIPALG::hairpin invalid }",
                    "packets": [{
                        "protocol": "sip",
                        "direction": "client_to_server",
                        "type": "request",
                        "method": "OPTIONS",
                        "uri": "sip:example.com",
                    }],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_feature_control_commands_and_connection_scope(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/first"} {
        DEMANGLE::enable
        DEMANGLE::disable
        ISESSION::deduplication disable
        PLUGIN::disable
        PLUGIN::enable ASM
        PLUGIN::disable WAM
    }
    log local0. "controls-set"
}
""",
                "requests": [
                    {"uri": "/first"},
                    {"uri": "/second"},
                    {"uri": "/third", "close_before": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first = result["results"][0]["semantic"]["feature_controls"]
        second = result["results"][1]["semantic"]["feature_controls"]
        third = result["results"][2]["semantic"]["feature_controls"]
        self.assertFalse(first["demangle_enabled"])
        self.assertFalse(first["isession_deduplication_enabled"])
        self.assertTrue(first["plugin_all_disabled"])
        self.assertEqual(first["plugin_states"], {"ASM": True, "WAM": False})
        self.assertEqual(second, first)
        self.assertEqual(third["demangle_enabled"], True)
        self.assertEqual(third["isession_deduplication_enabled"], True)
        self.assertEqual(third["plugin_states"], {})
        self.assertTrue(any("controls-set" in entry for entry in result["results"][0]["logs"]))

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in (
            "DEMANGLE::disable",
            "DEMANGLE::enable",
            "ISESSION::deduplication",
            "PLUGIN::disable",
            "PLUGIN::enable",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        ivs_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["IVS_ENTRY"],
                "irule": """
when IVS_ENTRY_REQUEST {
    IVS_ENTRY::result modified
    log local0. "ivs=[IVS_ENTRY::result]"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            ivs_result = ivs_session.fire_event("IVS_ENTRY_REQUEST")
            self.assertTrue(any("ivs=modified" in entry for entry in ivs_result["logs"]))
            self.assertEqual(
                ivs_result["semantic"]["feature_controls"]["ivs_entry_result"],
                "modified",
            )
            self.assertEqual(
                ivs_result["semantic"]["feature_controls"]["ivs_entry_results"],
                [{"event": "IVS_ENTRY_REQUEST", "result": "modified"}],
            )
        finally:
            ivs_session.close()

        for irule, message in (
            (
                "when HTTP_REQUEST { ISESSION::deduplication maybe }",
                "ISESSION::deduplication requires enable or disable",
            ),
            (
                "when HTTP_REQUEST { PLUGIN::enable }",
                "PLUGIN::enable requires a plugin name",
            ),
            (
                "when HTTP_REQUEST { IVS_ENTRY::result noop }",
                "IVS_ENTRY::result is not valid during HTTP_REQUEST",
            ),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_rest_send_records_bounded_local_request_without_network_io(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/send"} {
        set rest_body {{"operation":"QUERY"}}
        REST::send -method post /shared/rpm-tasks $rest_body
    }
}
""",
                "requests": [
                    {"uri": "/send"},
                    {"uri": "/other"},
                    {"uri": "/send", "close_before": True},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first = result["results"][0]["semantic"]["rest"]
        second = result["results"][1]["semantic"]["rest"]
        third = result["results"][2]["semantic"]["rest"]
        expected_request = {
            "method": "POST",
            "uri": "/shared/rpm-tasks",
            "body": '{"operation":"QUERY"}',
        }
        self.assertEqual(first["request_count"], 1)
        self.assertEqual(first["last"], expected_request)
        self.assertEqual(first["requests"], [expected_request])
        self.assertEqual(second, first)
        self.assertEqual(third["request_count"], 1)
        self.assertEqual(third["last"], expected_request)
        self.assertTrue(
            any(entry.startswith("rest send ") for entry in result["results"][0]["decisions"])
        )

        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        self.assertEqual(usage["REST::send"]["runtime_status"], "semantic-mock")

        for irule, message in (
            (
                "when HTTP_REQUEST { REST::send GET /shared/rpm-tasks }",
                "REST::send syntax is",
            ),
            (
                'when HTTP_REQUEST { REST::send -method "BAD METHOD" /shared/rpm-tasks }',
                "REST::send method must be a valid HTTP token",
            ),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "irule": irule,
                        "request": {"uri": "/"},
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_offbox_request_records_bounded_local_request_without_network_io(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    OFFBOX::request /Common/offbox::ip_reputation 203.0.113.10 cache 203.0.113.10 blocking 250
    OFFBOX::request /Common/offbox::health ping
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST")
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["OFFBOX::request"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        self.assertEqual(result["semantic"]["offbox"]["request_count"], 2)
        self.assertEqual(
            result["semantic"]["offbox"]["last"],
            {
                "service": "/Common/offbox::health",
                "payload": "ping",
                "cache_key": "",
                "blocking": False,
                "timeout": 0,
            },
        )
        self.assertEqual(
            result["semantic"]["offbox"]["requests"][0],
            {
                "service": "/Common/offbox::ip_reputation",
                "payload": "203.0.113.10",
                "cache_key": "203.0.113.10",
                "blocking": True,
                "timeout": 250,
                "result": "not-executed",
            },
        )
        self.assertTrue(any(entry.startswith("offbox request ") for entry in result["decisions"]))

        for irule, message in (
            (
                "when HTTP_REQUEST { OFFBOX::request svc payload cache }",
                "OFFBOX::request cache requires a key",
            ),
            (
                "when HTTP_REQUEST { OFFBOX::request svc payload blocking -1 }",
                "OFFBOX::request timeout must be a non-negative integer",
            ),
            (
                "when HTTP_REQUEST { OFFBOX::request svc payload async }",
                "OFFBOX::request options must be cache KEY and/or blocking TIMEOUT",
            ),
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": irule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                invalid.close()

    def test_tds_message_and_session_commands_model_direct_events(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TDS"],
                "irule": """
when TDS_REQUEST {
    log local0. "msg=[TDS::msg type]/[TDS::msg length]/[TDS::msg procid]/[TDS::msg procname]/[TDS::msg sqltext]/[TDS::msg xacttype]/[TDS::msg xactid]/[TDS::msg is_read] session=[TDS::session username]/[TDS::session dbname]/[TDS::session loginoption]/[TDS::session version]"
    TDS::msg request_type write
    log local0. "request_type=[TDS::msg request_type]"
}
when TDS_RESPONSE {
    log local0. "response=[TDS::msg type] session=[TDS::session username] request_type=[TDS::msg request_type]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            request = session.fire_event(
                "TDS_REQUEST",
                {
                    "tds": {
                        "type": 4,
                        "length": 128,
                        "procid": 7,
                        "procname": "sp_executesql",
                        "sqltext": "select 1",
                        "xacttype": 2,
                        "xactid": 9,
                        "is_read": True,
                        "request_type": "read",
                        "username": "alice",
                        "dbname": "app",
                        "loginoption": "integrated",
                        "version": "7.4",
                    }
                },
            )
            response = session.fire_event(
                "TDS_RESPONSE",
                {"tds": {"type": 5, "length": 32}},
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["TDS::msg"]["runtime_status"], "semantic-mock")
            self.assertEqual(usage["TDS::session"]["runtime_status"], "semantic-mock")
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "invalid TDS type state"
            ):
                session.fire_event("TDS_REQUEST", {"tds": {"type": -1}})
        finally:
            session.close()

        self.assertTrue(
            any(
                "msg=4/128/7/sp_executesql/select 1/2/9/1 session=alice/app/integrated/7.4"
                in entry
                for entry in request["logs"]
            )
        )
        self.assertTrue(any("request_type=write" in entry for entry in request["logs"]))
        self.assertTrue(
            any("response=5 session=alice request_type=read" in entry for entry in response["logs"])
        )
        self.assertEqual(
            request["semantic"]["tds"],
            {
                "message": {
                    "type": 4,
                    "length": 128,
                    "procid": 7,
                    "procname": "sp_executesql",
                    "sqltext": "select 1",
                    "xacttype": 2,
                    "xactid": 9,
                    "is_read": True,
                    "request_type": "write",
                },
                "session": {
                    "username": "alice",
                    "dbname": "app",
                    "loginoption": "integrated",
                    "version": "7.4",
                },
            },
        )
        self.assertEqual(
            response["semantic"]["tds"]["session"]["username"], "alice"
        )

    def test_tds_structured_packets_drive_request_and_response_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "TDS"],
                "irule": """
when TDS_REQUEST {
    TDS::msg request_type write
    log local0. "request=[TDS::msg type]/[TDS::msg procname]/[TDS::msg request_type] session=[TDS::session username]/[TDS::session dbname]"
}
when TDS_RESPONSE {
    log local0. "response=[TDS::msg type]/[TDS::msg length] session=[TDS::session username]/[TDS::session dbname]"
}
""",
                "packets": [
                    {
                        "protocol": "tds",
                        "direction": "client_to_server",
                        "type": 4,
                        "length": 128,
                        "procid": 7,
                        "procname": "sp_executesql",
                        "sqltext": "select 1",
                        "xacttype": 2,
                        "xactid": 9,
                        "is_read": True,
                        "username": "alice",
                        "dbname": "app",
                        "loginoption": "integrated",
                        "version": "7.4",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 1433},
                    },
                    {
                        "protocol": "tds",
                        "direction": "server_to_client",
                        "type": 5,
                        "length": 32,
                        "username": "alice",
                        "dbname": "app",
                        "loginoption": "integrated",
                        "version": "7.4",
                        "source": {"address": "192.0.2.10", "port": 1433},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request_events = result["trace"][0]["events"]
        response_events = result["trace"][1]["events"]
        self.assertEqual(request_events[-1]["event"], "TDS_REQUEST")
        self.assertEqual(request_events[-1]["state"]["tds"]["request_type"], "write")
        self.assertTrue(
            any("request=4/sp_executesql/write" in log for log in request_events[-1]["logs"])
        )
        self.assertEqual(
            [event["event"] for event in response_events],
            ["SERVER_INIT", "SERVER_CONNECTED", "TDS_RESPONSE"],
        )
        self.assertTrue(any("response=5/32" in log for log in response_events[-1]["logs"]))
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "TDS request_type must be read or write",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "TDS"],
                    "irule": "when TDS_REQUEST { }",
                    "packets": [
                        {
                            "protocol": "tds",
                            "request_type": "query",
                            "source": {"address": "10.0.0.5", "port": 51000},
                            "destination": {"address": "192.0.2.10", "port": 1433},
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_ike_auth_commands_model_certificate_and_san_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["IPSEC"],
                "irule": """
when IKE_AUTH {
    log local0. "cert=[IKE::cert 0] dns=[IKE::san_dns] email=[IKE::san_email] subject=[IKE::subjectAltName]"
    if {[IKE::san_dns] eq "vpn.example.test"} {
        IKE::auth_success
    }
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event(
                "IKE_AUTH",
                {
                    "ike": {
                        "cert": "CERTIFICATE-DATA",
                        "san_dirname": "ou=VPN,o=Example",
                        "san_dns": "vpn.example.test",
                        "san_ediparty": "",
                        "san_email": "vpn@example.test",
                        "san_ipadd": "192.0.2.10",
                        "san_othername": "",
                        "san_rid": "",
                        "san_uri": "https://vpn.example.test",
                        "san_x400": "",
                        "subjectAltName": "DNS:vpn.example.test,email:vpn@example.test",
                    }
                },
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command in (
                "IKE::auth_success",
                "IKE::cert",
                "IKE::san_dns",
                "IKE::subjectAltName",
            ):
                self.assertEqual(usage[command]["runtime_status"], "semantic-mock")
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "event state ike is only valid during IKE_AUTH",
            ):
                session.fire_event(
                    "CLIENT_ACCEPTED", {"ike": {"cert": "unexpected"}}
                )
        finally:
            session.close()

        self.assertTrue(
            any(
                "cert=CERTIFICATE-DATA dns=vpn.example.test email=vpn@example.test"
                in entry
                for entry in result["logs"]
            )
        )
        self.assertIn("ike auth_success 1", result["decisions"])
        self.assertEqual(result["state"]["ike"]["auth_success"], "1")
        self.assertEqual(result["state"]["ike"]["cert"], "CERTIFICATE-DATA")
        self.assertEqual(
            result["state"]["ike"]["subjectAltName"],
            "DNS:vpn.example.test,email:vpn@example.test",
        )

    def test_access2_proc_exposes_current_policy_expression_procedure(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["ACCESS"],
                "irule": """
when ACCESS2_POLICY_EXPRESSION_EVAL {
    log local0. "proc=[ACCESS2::access2_proc]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event(
                "ACCESS2_POLICY_EXPRESSION_EVAL",
                {"access2": {"proc": "::policy::evaluate_request"}},
            )
            usage = {
                entry["name"]: entry for entry in session.fidelity["commands"]
            }
            self.assertEqual(
                usage["ACCESS2::access2_proc"]["runtime_status"],
                "semantic-mock",
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["access2"]["proc"], "::policy::evaluate_request")
            self.assertEqual(result["semantic"]["access2"], {"proc": "::policy::evaluate_request"})
            self.assertTrue(
                any("proc=::policy::evaluate_request" in entry for entry in result["logs"])
            )

            reset = session.fire_event("ACCESS2_POLICY_EXPRESSION_EVAL")
            self.assertEqual(reset["semantic"]["access2"], {"proc": ""})
            for bad_state, message in (
                ({"access2": {"proc": 7}}, "event state access2.proc must be a string"),
                ({"access2": {"proc": "bad\x00proc"}}, "must not contain NUL bytes"),
                ({"access2": {"proc": "x" * 4097}}, "exceeds 4096 UTF-8 bytes"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    session.fire_event("ACCESS2_POLICY_EXPRESSION_EVAL", bad_state)
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["ACCESS"],
                "irule": "when ACCESS2_POLICY_EXPRESSION_EVAL { ACCESS2::access2_proc unexpected }",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "ACCESS2::access2_proc takes no arguments",
            ):
                invalid.fire_event("ACCESS2_POLICY_EXPRESSION_EVAL")
        finally:
            invalid.close()

        event_only = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["ACCESS", "HTTP"],
                "irule": "when HTTP_REQUEST { ACCESS2::access2_proc }",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "ACCESS2::access2_proc is not valid during HTTP_REQUEST",
            ):
                event_only.fire_event("HTTP_REQUEST")
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "event state access2 is only valid during ACCESS2_POLICY_EXPRESSION_EVAL",
            ):
                event_only.fire_event(
                    "HTTP_REQUEST", {"access2": {"proc": "unexpected"}}
                )
        finally:
            event_only.close()

    def test_http_access2_fixture_emits_policy_expression_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "access2": {"proc": "::policy::evaluate_request"},
                "irule": (
                    "when ACCESS2_POLICY_EXPRESSION_EVAL { "
                    "log local0. \"proc=[ACCESS2::access2_proc]\" }"
                ),
                "request": {"uri": "/policy"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            item["events_fired"],
            [
                "CLIENT_ACCEPTED",
                "ACCESS_SESSION_STARTED",
                "HTTP_REQUEST",
                "ACCESS_POLICY_COMPLETED",
                "ACCESS2_POLICY_EXPRESSION_EVAL",
            ],
        )
        self.assertTrue(any("proc=::policy::evaluate_request" in log for log in item["logs"]))
        self.assertEqual(
            item["semantic"]["access2"],
            {"proc": "::policy::evaluate_request"},
        )

    def test_epi_na_special_http_paths_emit_internal_event(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "ACCESS"],
                "irule": (
                    "when EPI_NA_CHECK_HTTP_REQUEST { "
                    "log local0. \"epi=[HTTP::path]\" }\n"
                    "when HTTP_REQUEST { log local0. \"request=[HTTP::path]\" }"
                ),
                "requests": [
                    {"uri": "/my.status.eps?client=one"},
                    {"uri": "/normal"},
                    {"uri": "/my.status.na"},
                    {"uri": "/my.report.na"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(
            [
                item["request"]["uri"]
                for item in result["results"]
                if "EPI_NA_CHECK_HTTP_REQUEST" in item["events_fired"]
            ],
            [
                "/my.status.eps?client=one",
                "/my.status.na",
                "/my.report.na",
            ],
        )
        self.assertEqual(
            [
                item["events_fired"].count("EPI_NA_CHECK_HTTP_REQUEST")
                for item in result["results"]
            ],
            [1, 0, 1, 1],
        )
        self.assertEqual(
            result["results"][0]["events_fired"],
            ["HTTP_REQUEST", "EPI_NA_CHECK_HTTP_REQUEST"],
        )
        self.assertTrue(any("epi=/my.status.eps" in log for log in result["results"][0]["logs"]))
        self.assertTrue(any("request=/normal" in log for log in result["results"][1]["logs"]))

    def test_pingaccess_ready_events_mutate_http_request_and_response(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "ping": {"request_ready": True, "response_ready": True},
                "irule": (
                    "when PING_REQUEST_READY { "
                    "HTTP::header insert X-Ping-Request ready; "
                    "log local0. \"ping-request=[HTTP::header X-Ping-Request]\" }\n"
                    "when PING_RESPONSE_READY { "
                    "HTTP::header insert X-Ping-Response ready; "
                    "log local0. \"ping-response=[HTTP::header X-Ping-Response]\" }"
                ),
                "request": {
                    "uri": "/ping",
                    "response_status": 204,
                    "response_headers": {"X-Origin": "yes"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertEqual(
            item["events_fired"],
            ["HTTP_REQUEST", "PING_REQUEST_READY", "HTTP_RESPONSE", "PING_RESPONSE_READY"],
        )
        self.assertTrue(any("ping-request=ready" in log for log in item["logs"]))
        self.assertTrue(any("ping-response=ready" in log for log in item["logs"]))
        self.assertEqual(item["request"]["headers"]["x-ping-request"], "ready")
        self.assertEqual(item["response"]["headers"]["x-ping-response"], "ready")

    def test_pingaccess_fixture_defaults_to_disabled(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "ping": {"request_ready": True},
                "irule": (
                    "when PING_REQUEST_READY { log local0. request-ready }\n"
                    "when PING_RESPONSE_READY { log local0. response-ready }"
                ),
                "request": {"uri": "/ping"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        item = result["results"][0]
        self.assertIn("PING_REQUEST_READY", item["events_fired"])
        self.assertNotIn("PING_RESPONSE_READY", item["events_fired"])
        self.assertTrue(any("request-ready" in log for log in item["logs"]))
        self.assertFalse(any("response-ready" in log for log in item["logs"]))

    def test_pingaccess_ready_events_reset_once_per_request(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "ping": {"request_ready": True, "response_ready": True},
                "irule": (
                    "when PING_REQUEST_READY { log local0. request-ready }\n"
                    "when PING_RESPONSE_READY { log local0. response-ready }"
                ),
                "requests": [{"uri": "/one"}, {"uri": "/two"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(len(result["results"]), 2)
        for item in result["results"]:
            self.assertEqual(item["events_fired"].count("PING_REQUEST_READY"), 1)
            self.assertEqual(item["events_fired"].count("PING_RESPONSE_READY"), 1)
            self.assertTrue(any("request-ready" in log for log in item["logs"]))
            self.assertTrue(any("response-ready" in log for log in item["logs"]))

    def test_pingaccess_fixture_validation_rejects_ambiguous_inputs(self) -> None:
        for invalid_ping in (
            True,
            {"request_ready": 1},
            {"response_ready": "true"},
            {"unexpected": True},
        ):
            with self.subTest(invalid_ping=invalid_ping):
                with self.assertRaises(self.adapter.EmulatorInputError):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "ping": invalid_ping,
                            "irule": "when HTTP_REQUEST { log local0. ok }",
                            "request": {"uri": "/ping"},
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

    def test_am_commands_model_acceleration_metadata_and_disable_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "am=[AM::age]/[AM::application]/[AM::cache]/[AM::expires]/[AM::media_playlist]/[AM::policy_node]"
    AM::disable
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event(
                "HTTP_REQUEST",
                {
                    "am": {
                        "age": 37,
                        "application": "/Common/video-app",
                        "cache": "hit",
                        "expires": 3600,
                        "media_playlist": "playlist-1",
                        "policy_node": "node-7",
                    }
                },
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command in (
                "AM::age",
                "AM::application",
                "AM::cache",
                "AM::disable",
                "AM::expires",
                "AM::media_playlist",
                "AM::policy_node",
            ):
                self.assertEqual(usage[command]["runtime_status"], "semantic-mock")
            self.assertTrue(
                any("am=37//Common/video-app/hit/3600/playlist-1/node-7" in entry for entry in result["logs"])
            )
            self.assertEqual(
                result["semantic"]["am"],
                {
                    "age": "37",
                    "application": "/Common/video-app",
                    "cache": "hit",
                    "disabled": True,
                    "expires": "3600",
                    "media_playlist": "playlist-1",
                    "policy_node": "node-7",
                },
            )

            persisted = session.fire_event("HTTP_RESPONSE")
            self.assertEqual(persisted["semantic"]["am"]["disabled"], True)

            reset = session.fire_event("CLIENT_ACCEPTED")
            self.assertEqual(
                reset["semantic"]["am"],
                {
                    "age": "0",
                    "application": "",
                    "cache": "",
                    "disabled": False,
                    "expires": "",
                    "media_playlist": "",
                    "policy_node": "",
                },
            )
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["HTTP"], "irule": "when HTTP_REQUEST { AM::age invalid }"},
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "AM::age takes no arguments"
            ):
                invalid.fire_event("HTTP_REQUEST")
        finally:
            invalid.close()

    def test_call_dispatches_defined_tcl_procedures_and_preserves_errors(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
proc join_words {left right} { return "$left:$right" }
when HTTP_REQUEST {
    set result [call -debug join_words left right]
    log local0. "result=$result"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST")
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["call"]["runtime_status"], "semantic-mock")
            self.assertTrue(any("result=left:right" in entry for entry in result["logs"]))
            self.assertIn("call debug {::join_words {left right}}", result["decisions"])
            self.assertIn("call invoke {::join_words 2}", result["decisions"])
        finally:
            session.close()

        error_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
proc fail_proc {} { error "boom" }
when HTTP_REQUEST { call fail_proc }
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(self.adapter.EmulatorInputError, "boom"):
                error_session.fire_event("HTTP_REQUEST")
        finally:
            error_session.close()

        for irule, message in (
            (
                "when HTTP_REQUEST { call missing_proc }",
                "call procedure missing_proc is not defined",
            ),
            (
                "when HTTP_REQUEST { call }",
                "call requires a procedure name",
            ),
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": irule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                invalid.close()

    def test_fasthash_returns_repeatable_bounded_hashes(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    set value [fasthash "hello"]
    set repeat [fasthash "hello"]
    set empty [fasthash ""]
    set binary [fasthash [binary format H* 006162]]
    log local0. "value=$value repeat=$repeat empty=$empty binary=$binary"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST")
            message = next(entry for entry in result["logs"] if "value=" in entry)
            match = re.search(
                r"value=(\d+) repeat=(\d+) empty=(\d+) binary=(\d+)", message
            )
            self.assertIsNotNone(match)
            values = [int(value) for value in match.groups()]
            self.assertEqual(values[0], values[1])
            self.assertTrue(all(0 <= value <= (1 << 63) - 1 for value in values))
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["fasthash"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        for invalid_rule in (
            "when HTTP_REQUEST { fasthash }",
            "when HTTP_REQUEST { fasthash one two }",
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": invalid_rule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, "fasthash requires one value"
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                invalid.close()

    def test_rmd160_returns_binary_digest_for_one_value(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "digest=[binary encode hex [rmd160 abc]]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST")
            self.assertTrue(
                any(
                    "digest=8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" in entry
                    for entry in result["logs"]
                )
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["rmd160"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        for invalid_rule in (
            "when HTTP_REQUEST { rmd160 }",
            "when HTTP_REQUEST { rmd160 one two }",
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": invalid_rule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, "ripemd160 requires one value"
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                invalid.close()

    def test_md4_returns_legacy_binary_digest_for_one_value(self) -> None:
        for value, expected in (
            (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
            (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
            (
                b"message digest",
                "d9130a8164549fe818874806e1c7014b",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                b"1234567890" * 8,
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ):
            self.assertEqual(self.adapter._md4_digest(value).hex(), expected)

        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "digest=[binary encode hex [md4 abc]]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST")
            self.assertTrue(
                any(
                    "digest=a448017aaf21d8525fc10ae87aa6729d" in entry
                    for entry in result["logs"]
                )
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["md4"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        for invalid_rule in (
            "when HTTP_REQUEST { md4 }",
            "when HTTP_REQUEST { md4 one two }",
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": invalid_rule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, "md4 requires one value"
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                invalid.close()

    def test_vlan_id_reads_packet_vlan_state_through_legacy_global(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": "when HTTP_REQUEST { log local0. \"vlan=[vlan_id]\" }",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = session.fire_event("HTTP_REQUEST", {"link": {"vlan_id": 4094}})
            self.assertTrue(any("vlan=4094" in entry for entry in result["logs"]))
            self.assertTrue(
                any("toplevel vlan_id 4094" in entry for entry in result["decisions"])
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["vlan_id"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["HTTP"], "irule": "when HTTP_REQUEST { vlan_id 1 }"},
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "vlan_id takes no arguments"
            ):
                invalid.fire_event("HTTP_REQUEST")
        finally:
            invalid.close()

    def test_traffic_group_reads_caller_supplied_connection_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": "when HTTP_REQUEST { log local0. \"tg=[traffic_group]\" }",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            empty_result = session.fire_event("HTTP_REQUEST")
            self.assertTrue(any("tg= " in entry for entry in empty_result["logs"]))
            result = session.fire_event(
                "HTTP_REQUEST",
                {"traffic_group": {"name": "/Common/traffic-group-2"}},
            )
            self.assertTrue(
                any("tg=/Common/traffic-group-2" in entry for entry in result["logs"])
            )
            self.assertTrue(
                any(
                    "toplevel traffic_group /Common/traffic-group-2" in entry
                    for entry in result["decisions"]
                )
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["traffic_group"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["HTTP"], "irule": "when HTTP_REQUEST { traffic_group 1 }"},
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "traffic_group takes no arguments"
            ):
                invalid.fire_event("HTTP_REQUEST")
        finally:
            invalid.close()

    def test_ip_list_utilities_normalize_order_and_filter_xff_headers(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": """
when HTTP_REQUEST {
    set candidates {192.0.2.10 {2001:0DB8::1, 192.0.2.10 invalid 0.0.0.0} 127.0.0.1}
    set ordered [uniq_ordered_ip_list {*}$candidates]
    set sorted [uniq_sorted_ip_list {*}$candidates]
    set xff_ordered [xff_uniq_ordered_ip_list]
    set xff_sorted [xff_list]
    set custom [xff_uniq_sorted_ip_list X-Real-IP]
    log local0. "ordered=[join $ordered |] sorted=[join $sorted |] xff_ordered=[join $xff_ordered |] xff_sorted=[join $xff_sorted |] custom=[join $custom |] empty=[llength [uniq_sorted_ip_list]]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            result = session.run_request(
                {
                    "uri": "/",
                    "headers": {
                        "X-Forwarded-For": (
                            "127.0.0.1, 192.0.2.10, 2001:0db8::1, "
                            "192.0.2.10, 0.0.0.0"
                        ),
                        "X-Real-IP": "2001:0DB8::2, 203.0.113.4, 203.0.113.4",
                    },
                }
            )
            message = next(entry for entry in result["logs"] if "ordered=" in entry)
            self.assertIn(
                "ordered=192.0.2.10|2001:db8::1|0.0.0.0|127.0.0.1",
                message,
            )
            self.assertIn(
                "sorted=0.0.0.0|127.0.0.1|192.0.2.10|2001:db8::1",
                message,
            )
            self.assertIn("xff_ordered=192.0.2.10|2001:db8::1", message)
            self.assertIn("xff_sorted=192.0.2.10|2001:db8::1", message)
            self.assertIn("custom=203.0.113.4|2001:db8::2", message)
            self.assertIn("empty=0", message)
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command_name in (
                "uniq_ordered_ip_list",
                "uniq_sorted_ip_list",
                "xff_list",
                "xff_uniq_ordered_ip_list",
                "xff_uniq_sorted_ip_list",
            ):
                self.assertEqual(usage[command_name]["runtime_status"], "semantic-mock")
        finally:
            session.close()

    def test_ip_list_utilities_reject_invalid_shape_and_excessive_candidates(self) -> None:
        invalid_rules = (
            (
                "when HTTP_REQUEST { xff_list X-Forwarded-For X-Real-IP }",
                "xff_list accepts an optional header name",
            ),
            (
                "when HTTP_REQUEST { xff_list {} }",
                "xff_list header name must be non-empty",
            ),
            (
                "when HTTP_REQUEST { uniq_sorted_ip_list [lrepeat 257 192.0.2.1] }",
                "IP list cannot contain more than 256 candidates",
            ),
        )
        for irule, message in invalid_rules:
            session = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": irule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    session.fire_event("HTTP_REQUEST")
            finally:
                session.close()

        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["TCP"], "irule": "when CLIENT_ACCEPTED { xff_list }"},
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "xff_list requires the HTTP profile"
            ):
                session.fire_event("CLIENT_ACCEPTED")
        finally:
            session.close()

    def test_sideband_connect_send_peek_recv_and_close_use_deterministic_fixtures(self) -> None:
        response = "HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n"
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP"],
                "sideband": {"10.0.0.10:80": {"response": response}},
                "irule": """
when HTTP_REQUEST {
    set conn [connect -protocol TCP -timeout 100 -idle 30 -status connect_status 10.0.0.10:80]
    set sent [send -timeout 1000 -status send_status $conn "GET / HTTP/1.0\r\n\r\n"]
    set peeked [recv -peek -status peek_status 5 $conn]
    set line [recv -eol -status line_status $conn]
    set remainder [recv -status recv_status $conn]
    close $conn close_status
    log local0. "statuses=$connect_status/$send_status/$peek_status/$line_status/$recv_status/$close_status sent=$sent peek=[string length $peeked] line=[string length $line] remainder=[string length $remainder]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            result = session.run_request({"uri": "/"})
            self.assertTrue(
                any(
                    "statuses=connected/sent/received/received/received/closed" in entry
                    and f"sent={len('GET / HTTP/1.0\r\n\r\n')}" in entry
                    and "peek=5" in entry
                    for entry in result["logs"]
                )
            )
            sideband = result["semantic"]["sideband"]
            self.assertEqual(sideband["next_id"], 1)
            self.assertEqual(len(sideband["connections"]), 1)
            connection = sideband["connections"][0]
            self.assertEqual(connection["handle"], "sideband:1")
            self.assertEqual(connection["destination"], "10.0.0.10:80")
            self.assertEqual(connection["protocol"], 6)
            self.assertTrue(connection["closed"])
            self.assertEqual(connection["sent_bytes"], len("GET / HTTP/1.0\r\n\r\n"))
            self.assertEqual(connection["received_bytes"], len(response))
            self.assertEqual(connection["buffered_bytes"], 0)
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command_name in ("connect", "send", "recv", "close"):
                self.assertEqual(usage[command_name]["runtime_status"], "semantic-mock")
        finally:
            session.close()

    def test_ifile_commands_use_bounded_scenario_fixtures(self) -> None:
        binary = base64.b64encode(b"\x00\xff\x01").decode("ascii")
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "ifiles": {
                    "/Common/index.html": {
                        "content": "hello",
                        "last_updated_by": "alice",
                        "last_update_time": "2026-08-29T12:00:00Z",
                        "revision": 3,
                        "checksum": "fixture-checksum",
                    },
                    "/Common/blob.bin": {"content_base64": binary},
                },
                "irule": """
when HTTP_REQUEST {
    array set attrs [ifile attributes /Common/index.html]
    set names [ifile listall]
    set body [ifile get /Common/index.html]
    log local0. "names=$names body=$body size=[ifile size /Common/index.html] user=$attrs(last_updated_by) time=$attrs(last_update_time) revision=[ifile revision /Common/index.html] checksum=[ifile checksum /Common/index.html] binary=[string length [ifile get /Common/blob.bin]]"
    HTTP::respond 200 content $body
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            result = session.run_request({"uri": "/"})
            self.assertIn("HTTP_REQUEST", result["events_fired"])
            self.assertEqual(result["response"]["body"], "hello")
            self.assertTrue(
                any(
                    "names=/Common/blob.bin /Common/index.html body=hello size=5" in entry
                    and "user=alice" in entry
                    and "revision=3" in entry
                    and "checksum=fixture-checksum" in entry
                    and "binary=3" in entry
                    for entry in result["logs"]
                )
            )
            self.assertEqual(
                result["semantic"]["ifile"]["names"],
                ["/Common/blob.bin", "/Common/index.html"],
            )
            accesses = result["semantic"]["ifile"]["accesses"]
            self.assertEqual(accesses[0], {"operation": "attributes", "name": "/Common/index.html"})
            self.assertEqual(accesses[-1], {"operation": "get", "name": "/Common/blob.bin"})
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["ifile"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

    def test_ifile_fixture_validation_is_strict_and_does_not_read_host_paths(self) -> None:
        normalise = self.adapter._normalise_ifiles
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "valid base64"):
            normalise({"/Common/bad": {"content_base64": "not base64"}})
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "only one of content"):
            normalise({"/Common/bad": {"content": "x", "content_base64": "eA=="}})
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "unsupported field"):
            normalise({"/Common/bad": {"host_path": "/etc/passwd"}})
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "64 MiB|67108864"):
            normalise(
                {
                    f"/Common/file-{index}": {"content": "x" * (1024 * 1024)}
                    for index in range(65)
                }
            )
        self.assertEqual(
            normalise({"/etc/passwd": "fixture"})["/etc/passwd"]["revision"],
            "1",
        )

    def test_urlcat_queries_use_deterministic_scenario_fixtures(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "urlcat": {
                    "queries": {
                        "example.test/path": ["Malware", "Phishing"],
                    },
                    "blind_queries": {"deadbeef": "Business"},
                },
                "irule": """
when HTTP_REQUEST {
    set direct [urlcatquery example.test/path]
    set blind [urlcatblindquery deadbeef]
    set missing [urlcatquery unknown.test]
    log local0. "direct=$direct blind=$blind missing=$missing"
    HTTP::respond 200 content "$direct|$blind|$missing"
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            result = session.run_request({"uri": "/"})
            self.assertEqual(
                result["response"]["body"],
                "Malware Phishing|Business|Unknown",
            )
            self.assertTrue(
                any(
                    "direct=Malware Phishing blind=Business missing=Unknown" in entry
                    for entry in result["logs"]
                )
            )
            self.assertEqual(
                result["semantic"]["urlcat"]["default"],
                ["Unknown"],
            )
            self.assertEqual(result["semantic"]["urlcat"]["query_count"], 1)
            self.assertEqual(result["semantic"]["urlcat"]["blind_query_count"], 1)
            self.assertEqual(
                result["semantic"]["urlcat"]["accesses"],
                [
                    {"kind": "queries", "input": "example.test/path"},
                    {"kind": "blind_queries", "input": "deadbeef"},
                    {"kind": "queries", "input": "unknown.test"},
                ],
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            self.assertEqual(usage["urlcatquery"]["runtime_status"], "semantic-mock")
            self.assertEqual(usage["urlcatblindquery"]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        ipv6_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "irule": "when HTTP_REQUEST { urlcatquery 2001:db8::1 }",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "urlcatquery does not support IPv6 addresses",
            ):
                ipv6_session.run_request({"uri": "/"})
        finally:
            ipv6_session.close()

    def test_urlcat_fixture_validation_is_bounded(self) -> None:
        normalise = self.adapter._normalise_urlcat
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "1 to 64"):
            normalise({"default": []})
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "lookup keys"):
            normalise({"queries": {"\x00bad": "Unknown"}})
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "64 categories"):
            normalise({"default": [f"category-{index}" for index in range(65)]})

    def test_sideband_connect_failure_and_lifecycle_validation_are_deterministic(self) -> None:
        failed = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "sideband": {
                    "unreachable.example:443": {"connect_status": "unreachable"}
                },
                "irule": """
when HTTP_REQUEST {
    set conn [connect -status status unreachable.example:443]
    log local0. "conn=$conn status=$status"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = failed.fire_event("HTTP_REQUEST")
            self.assertTrue(any("conn= status=unreachable" in entry for entry in result["logs"]))
            self.assertEqual(result["semantic"]["sideband"]["connections"], [])
        finally:
            failed.close()

        for irule, message in (
            (
                "when HTTP_REQUEST { send sideband:99 data }",
                "send references an unknown sideband connection",
            ),
            (
                "when HTTP_REQUEST { connect -unknown x }",
                "unsupported connect option -unknown",
            ),
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["HTTP"], "irule": irule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    invalid.fire_event("HTTP_REQUEST")
            finally:
                    invalid.close()

        output_session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["HTTP"],
                "sideband": {"empty.example:80": ""},
                "irule": """
when HTTP_REQUEST {
    set conn [connect empty.example:80]
    set count [recv -timeout 25 $conn received]
    set status [recv -timeout 25 -status receive_status $conn]
    close $conn
    log local0. "count=$count received=<$received> status=$receive_status result=<$status>"
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            result = output_session.fire_event("HTTP_REQUEST")
            self.assertTrue(
                any(
                    "count=0 received=<> status=timeout result=<>" in entry
                    for entry in result["logs"]
                )
            )
        finally:
            output_session.close()

    def test_legacy_connection_controls_update_visible_routing_state(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    set qos_before [link_qos]
    set qos_after [link_qos 5]
    translate address disable
    set address_state [translate address]
    set port_state [translate port]
    rateclass premium
    forward
    redirect to https://example.com/login
    log local0. "qos=$qos_before/$qos_after translation=$address_state/$port_state"
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            result = session.run_request({"uri": "/"})
            self.assertTrue(
                any("qos=0/5 translation=0/1" in entry for entry in result["logs"])
            )
            legacy = result["semantic"]["legacy"]
            self.assertTrue(legacy["forwarded"])
            self.assertEqual(legacy["rateclass"], "premium")
            self.assertFalse(legacy["translate_address_enabled"])
            self.assertTrue(legacy["translate_port_enabled"])
            self.assertTrue(legacy["translate_service_enabled"])
            self.assertEqual(legacy["link_qos"], 5)
            self.assertEqual(result["response"]["status"], 302)
            self.assertEqual(result["response"]["headers"]["location"], "https://example.com/login")
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command_name in ("forward", "link_qos", "rateclass", "redirect", "translate"):
                self.assertEqual(usage[command_name]["runtime_status"], "semantic-mock")
        finally:
            session.close()

    def test_legacy_connection_controls_reset_on_new_connection(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::path] eq "/first"} {
        link_qos 5
        translate address disable
        rateclass premium
        forward
    }
    log local0. "forwarded=[expr {[translate address] == 0}] qos=[link_qos] rate=[translate service]"
}
""",
            },
            allow_irule_file=True,
            allow_requests=True,
            allow_packets=False,
        )
        try:
            first = session.run_request({"uri": "/first"})
            self.assertTrue(first["semantic"]["legacy"]["forwarded"])
            self.assertEqual(first["semantic"]["legacy"]["link_qos"], 5)
            self.assertFalse(first["semantic"]["legacy"]["translate_address_enabled"])

            second = session.run_request({"uri": "/second", "new_connection": True})
            legacy = second["semantic"]["legacy"]
            self.assertFalse(legacy["forwarded"])
            self.assertEqual(legacy["rateclass"], "")
            self.assertTrue(legacy["translate_address_enabled"])
            self.assertTrue(legacy["translate_port_enabled"])
            self.assertTrue(legacy["translate_service_enabled"])
            self.assertEqual(legacy["link_qos"], 0)
            self.assertTrue(any("forwarded=0 qos=0 rate=1" in entry for entry in second["logs"]))
        finally:
            session.close()

    def test_qoe_commands_model_video_metrics_and_connection_control(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["QOE"],
                "irule": """
when QOE_PARSE_DONE {
    log local0. "video=[QOE::video width]/[QOE::video height]/[QOE::video duration]/[QOE::video available]/[QOE::video framerate]/[QOE::video nominal_bitrate]/[QOE::video average_bitrate]/[QOE::video mos]"
    QOE::disable
}
when CLIENT_CLOSED {
    log local0. "available=[QOE::video available]"
    QOE::enable
}
""",
            },
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            parsed = session.fire_event(
                "QOE_PARSE_DONE",
                {
                    "qoe": {
                        "width": 1920,
                        "height": 1080,
                        "duration": "00:01:30",
                        "available": True,
                        "framerate": "59.94",
                        "nominal_bitrate": 8000000,
                        "average_bitrate": 6500000,
                        "mos": "4.7",
                    }
                },
            )
            closed = session.fire_event(
                "CLIENT_CLOSED",
                {"qoe": {"available": False}},
            )
            usage = {entry["name"]: entry for entry in session.fidelity["commands"]}
            for command in ("QOE::disable", "QOE::enable", "QOE::video"):
                self.assertEqual(usage[command]["runtime_status"], "semantic-mock")
        finally:
            session.close()

        self.assertTrue(
            any(
                "video=1920/1080/00:01:30/1/59.94/8000000/6500000/4.7" in entry
                for entry in parsed["logs"]
            )
        )
        self.assertTrue(any("available=0" in entry for entry in closed["logs"]))
        self.assertEqual(parsed["semantic"]["qoe"]["enabled"], False)
        self.assertEqual(parsed["semantic"]["qoe"]["video"]["available"], "1")
        self.assertEqual(closed["semantic"]["qoe"]["enabled"], True)
        self.assertEqual(closed["semantic"]["qoe"]["video"]["available"], "0")

        fresh = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {"profiles": ["QOE"], "irule": "when QOE_PARSE_DONE { QOE::disable }"},
            allow_irule_file=True,
            allow_requests=False,
            allow_packets=False,
        )
        try:
            reset = fresh.fire_event("QOE_PARSE_DONE")
        finally:
            fresh.close()
        self.assertEqual(reset["semantic"]["qoe"]["enabled"], False)

    def test_qoe_packet_adapter_emits_parse_event_and_honors_disable(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["QOE"],
                "irule": """
when QOE_PARSE_DONE {
    log local0. "video=[QOE::video width]/[QOE::video height]/[QOE::video mos]"
    QOE::disable
}
""",
                "packets": [
                    {
                        "protocol": "qoe",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.20", "port": 443},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "qoe": {
                            "width": 1920,
                            "height": 1080,
                            "duration": "00:01:30",
                            "framerate": "59.94",
                            "nominal_bitrate": 8000000,
                            "average_bitrate": 6500000,
                            "mos": "4.7",
                        },
                    },
                    {
                        "protocol": "qoe",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.20", "port": 443},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "qoe": {"available": False},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "QOE_PARSE_DONE"
        )
        self.assertEqual(first_event["state"]["qoe"]["width"], "1920")
        self.assertEqual(first_event["state"]["qoe"]["available"], "1")
        self.assertTrue(
            any("video=1920/1080/4.7" in log for log in first_event["logs"])
        )
        self.assertEqual(result["trace"][1]["ignored"], "QOE processing is disabled")
        self.assertTrue(result["trace"][1]["disabled"])

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "QOE packets must be server_to_client",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["QOE"],
                    "irule": "when QOE_PARSE_DONE { return }",
                    "packets": [
                        {
                            "protocol": "qoe",
                            "direction": "client_to_server",
                            "qoe": {"width": 1},
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        for irule, event, message in (
            (
                "when QOE_PARSE_DONE { QOE::video bitrate }",
                "QOE_PARSE_DONE",
                "QOE::video field is invalid",
            ),
            (
                "when QOE_PARSE_DONE { QOE::video width height }",
                "QOE_PARSE_DONE",
                "QOE::video requires width",
            ),
            (
                "when CLIENT_ACCEPTED { QOE::video width }",
                "CLIENT_ACCEPTED",
                "QOE::video is not valid during CLIENT_ACCEPTED",
            ),
        ):
            invalid = self.adapter.EmulatorSession(
                self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
                {"profiles": ["QOE"], "irule": irule},
                allow_irule_file=True,
                allow_requests=False,
                allow_packets=False,
            )
            try:
                with self.subTest(message=message), self.assertRaisesRegex(
                    self.adapter.EmulatorInputError, message
                ):
                    invalid.fire_event(event)
            finally:
                invalid.close()

    def test_l7check_packet_adapter_preserves_protocol_across_directions(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "L7CHECK"],
                "irule": """
when L7CHECK_CLIENT_DATA {
    log local0. "client-before=[L7CHECK::protocol get]"
    L7CHECK::protocol set https
}
when L7CHECK_SERVER_DATA {
    log local0. "server=[L7CHECK::protocol get]"
}
""",
                "packets": [
                    {
                        "protocol": "l7check",
                        "direction": "client_to_server",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "192.0.2.20", "port": 443},
                        "l7_protocol": "http",
                        "payload": "GET / HTTP/1.1\r\n\r\n",
                    },
                    {
                        "protocol": "l7check",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.20", "port": 443},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "payload_hex": "485454502f312e3120323030204f4b0d0a0d0a",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        client_event = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "L7CHECK_CLIENT_DATA"
        )
        server_event = next(
            event
            for event in result["trace"][1]["events"]
            if event["event"] == "L7CHECK_SERVER_DATA"
        )
        self.assertTrue(client_event["fired"])
        self.assertTrue(server_event["fired"])
        self.assertEqual(client_event["state"]["l7check"]["protocol"], "https")
        self.assertEqual(server_event["state"]["l7check"]["protocol"], "https")
        self.assertEqual(server_event["state"]["datagram"]["payload_length"], "19")
        self.assertTrue(any("client-before=http" in log for log in client_event["logs"]))
        self.assertTrue(any("server=https" in log for log in server_event["logs"]))
        self.assertEqual(result["trace"][0]["l7_protocol"], "https")
        self.assertEqual(result["trace"][1]["l7_protocol"], "https")

        without_profile = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": "when L7CHECK_CLIENT_DATA { return }",
                "packets": [{"protocol": "l7check", "payload": "probe"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        gated_event = next(
            event
            for event in without_profile["trace"][0]["events"]
            if event["event"] == "L7CHECK_CLIENT_DATA"
        )
        self.assertFalse(gated_event["fired"])
        self.assertEqual(
            without_profile["trace"][0]["ignored"],
            "L7CHECK profile is not attached",
        )

        invalid_packets = [
            (
                {
                    "protocol": "l7check",
                    "l7_protocol": {"name": "http"},
                },
                "packet 0 l7_protocol must be a string",
            ),
            (
                {
                    "protocol": "l7check",
                    "l7_protocol": "http\x00",
                },
                "packet 0 l7_protocol cannot contain NUL bytes",
            ),
            (
                {
                    "protocol": "l7check",
                    "payload": "probe",
                    "payload_hex": "70726f6265",
                },
                "L7CHECK packets must use payload or payload_hex, not both",
            ),
        ]
        for packet, message in invalid_packets:
            with self.subTest(message=message), self.assertRaisesRegex(
                self.adapter.EmulatorInputError, message
            ):
                self.adapter.run_scenario(
                    {
                        "profiles": ["TCP", "L7CHECK"],
                        "irule": "when L7CHECK_CLIENT_DATA { return }",
                        "packets": [packet],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )

    def test_sdp_commands_model_fields_media_and_session_id(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["SIP"],
                "irule": """
when SIP_REQUEST {
    log local0. "sid=[SDP::session_id] version=[SDP::field v] origin=[SDP::field origin] count=[SDP::media count] type=[SDP::media type 0] port=[SDP::media port 0] transport=[SDP::media transport 0] attr=[SDP::media attr 0 1]"
    SDP::field connection 0 "IN IP4 198.51.100.10"
    SDP::media port 0 5004/2
    SDP::media conn 0 "IN IP4 198.51.100.20"
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event(
                "SIP_REQUEST",
                {
                    "sdp": {
                        "session_id": "2890844526",
                        "fields": (
                            "version 0 "
                            "origin {alice 2890844526 2890842807 IN IP4 host.example} "
                            "connection {IN IP4 203.0.113.1} "
                            "attribute sendrecv attribute tool:demo"
                        ),
                        "media": (
                            "{type audio port 49170/2 transport RTP/AVP "
                            "conn {IN IP4 203.0.113.1} "
                            "attrs {rtpmap:0\\ PCMU/8000 sendrecv}}"
                        ),
                    }
                },
            )
            self.assertTrue(result["fired"])
            self.assertEqual(result["state"]["sdp"]["session_id"], "2890844526")
            self.assertIn("198.51.100.10", result["state"]["sdp"]["fields"])
            self.assertIn("5004/2", result["state"]["sdp"]["media"])
            self.assertIn("198.51.100.20", result["state"]["sdp"]["media"])
            self.assertTrue(any(
                "sid=2890844526 version=0 origin=alice 2890844526 2890842807 IN IP4 host.example"
                in entry
                and "count=1 type=audio port=49170/2 transport=RTP/AVP attr=sendrecv" in entry
                for entry in result["logs"]
            ))
        finally:
            session.close()

        invalid = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["SIP"],
                "irule": "when SIP_REQUEST { SDP::media type 1 }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError, "index is outside the media list"
            ):
                invalid.fire_event("SIP_REQUEST")
        finally:
            invalid.close()

    def test_sip_raw_tcp_and_udp_messages_drive_request_events(self) -> None:
        raw_message = (
            b"OPTIONS sip:server@example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/TCP client.example.com;branch=z9\r\n"
            b"Call-ID: raw-1\r\nContent-Length: 4\r\n\r\nping"
        )
        tcp_packets = [
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "raw_hex": _raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 5060, 5060, 0x02, sequence=5000
                ),
            },
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "raw_hex": _raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 5060, 5060, 0x18,
                    raw_message[:40], sequence=5001,
                ),
            },
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "raw_hex": _raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 5060, 5060, 0x18,
                    raw_message[40:], sequence=5041,
                ),
            },
        ]
        udp_message = (
            b"REGISTER sip:example.com SIP/2.0\r\n"
            b"Via: SIP/2.0/UDP client.example.com\r\n"
            b"Call-ID: udp-1\r\nContent-Length: 0\r\n\r\n"
        )
        udp_packets = [
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "raw_hex": _raw_ipv4_udp_hex(
                    "10.0.0.5", "192.0.2.10", 5060, 5060, udp_message
                ),
            }
        ]
        rule = "when SIP_REQUEST { log local0. \"[SIP::method] [SIP::call_id] [SIP::payload]\" }"
        tcp_result = self.adapter.run_scenario(
            {"profiles": ["SIP"], "irule": rule, "packets": tcp_packets},
            tcl_lsp_root=self.tcl_lsp_root,
        )
        tcp_entries = [entry for entry in tcp_result["trace"] if entry["protocol"] == "sip"]
        self.assertEqual(len(tcp_entries), 1)
        self.assertTrue(any("OPTIONS raw-1 ping" in log for log in tcp_entries[0]["events"][-1]["logs"]))
        udp_result = self.adapter.run_scenario(
            {"profiles": ["SIP"], "irule": rule, "packets": udp_packets},
            tcl_lsp_root=self.tcl_lsp_root,
        )
        udp_entry = udp_result["trace"][0]
        self.assertEqual(udp_entry["protocol"], "sip")
        self.assertEqual(udp_entry["transport"], "udp")
        self.assertEqual(udp_entry["events"][-1]["state"]["connection"]["protocol"], "17")
        self.assertTrue(any("REGISTER udp-1" in log for log in udp_entry["events"][-1]["logs"]))

    def test_sip_respond_and_discard_stop_the_forward_lifecycle(self) -> None:
        response = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": "when SIP_REQUEST { SIP::respond 403 Forbidden X-Reason blocked }",
                "packets": [
                    {
                        "protocol": "sip",
                        "type": "request",
                        "method": "INVITE",
                        "uri": "sip:bob@example.com",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = response["trace"][0]
        self.assertEqual([event["event"] for event in entry["events"][-1:]], ["SIP_REQUEST"])
        self.assertTrue(entry["responded"])
        self.assertEqual(
            entry["response"],
            {
                "status": 403,
                "phrase": "Forbidden",
                "headers": [["X-Reason", "blocked"]],
            },
        )
        discarded = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": "when SIP_REQUEST { SIP::discard }",
                "packets": [
                    {
                        "protocol": "sip",
                        "type": "request",
                        "method": "BYE",
                        "uri": "sip:bob@example.com",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        discarded_entry = discarded["trace"][0]
        self.assertTrue(discarded_entry["discarded"])
        self.assertEqual(discarded_entry["drop_reason"], "message")

    def test_sip_compact_headers_insert_order_and_message_state_reset(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["SIP"],
                "irule": """
when SIP_REQUEST {
    log local0. "call=[SIP::call_id] via=[SIP::via proto 0]"
    SIP::header insert Via "SIP/2.0/UDP inserted.example.com"
}
when SIP_REQUEST_SEND { log local0. "message=[SIP::message]" }
""",
                "packets": [
                    {
                        "protocol": "sip",
                        "type": "request",
                        "method": "OPTIONS",
                        "uri": "sip:example.com",
                        "headers": [
                            ["v", "SIP/2.0/UDP compact.example.com"],
                            ["i", "compact-call"],
                        ],
                    },
                    {
                        "protocol": "sip",
                        "type": "request",
                        "method": "BYE",
                        "uri": "sip:example.com",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first_events = result["trace"][0]["events"]
        second_events = result["trace"][1]["events"]
        self.assertTrue(any("call=compact-call via=UDP" in log for log in first_events[-3]["logs"]))
        first_message = first_events[-2]["logs"]
        self.assertTrue(any("Via: SIP/2.0/UDP inserted.example.com" in log for log in first_message))
        self.assertTrue(any("v: SIP/2.0/UDP compact.example.com" in log for log in first_message))
        self.assertTrue(any("call= via=" in log for log in second_events[-3]["logs"]))

    def test_sip_rejects_non_decimal_or_duplicate_content_length(self) -> None:
        for content_length in ("1_0", "+1"):
            with self.assertRaises(self.adapter.EmulatorInputError):
                self.adapter.run_scenario(
                    {
                        "profiles": ["SIP"],
                        "irule": "when SIP_REQUEST { log local0. ok }",
                        "packets": [
                            {
                                "protocol": "sip",
                                "type": "request",
                                "message": (
                                    "OPTIONS sip:example.com SIP/2.0\\r\\n"
                                    f"Content-Length: {content_length}\\r\\n\\r\\n"
                                ),
                            }
                        ],
                    },
                    tcl_lsp_root=self.tcl_lsp_root,
                )
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter.run_scenario(
                {
                    "profiles": ["SIP"],
                    "irule": "when SIP_REQUEST { log local0. ok }",
                    "packets": [
                        {
                            "protocol": "sip",
                            "type": "request",
                            "message": (
                                "OPTIONS sip:example.com SIP/2.0\\r\\n"
                                "Content-Length: 0\\r\\n"
                                "l: 0\\r\\n\\r\\n"
                            ),
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_diameter_structured_messages_expose_headers_avps_and_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "DIAMETER"],
                "irule": """
when DIAMETER_INGRESS {
    log local0. "command=[DIAMETER::command] app=[DIAMETER::header application_id] host=[DIAMETER::host origin] realm=[DIAMETER::realm origin] result=[DIAMETER::result] count=[DIAMETER::avp count 264]"
    DIAMETER::header pflag 1
    DIAMETER::avp replace 264 edited.example.com
}
""",
                "packets": [
                    {
                        "protocol": "diameter",
                        "direction": "client_to_server",
                        "type": "request",
                        "command_code": 272,
                        "application_id": 4,
                        "hop_by_hop_id": 0x10203040,
                        "end_to_end_id": 0x50607080,
                        "avps": [
                            {"code": 263, "data": "session-1"},
                            {"code": 264, "data": "origin.example.com"},
                            {"code": 296, "data": "example.com"},
                            {"code": 268, "type": "unsigned32", "data": "2001"},
                        ],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        entry = result["trace"][0]
        diameter_event = next(
            event for event in entry["events"] if event["event"] == "DIAMETER_INGRESS"
        )
        self.assertTrue(diameter_event["fired"])
        self.assertTrue(
            any(
                "command=272 app=4 host=origin.example.com realm=example.com result=2001 count=1"
                in log
                for log in diameter_event["logs"]
            )
        )
        self.assertEqual(diameter_event["state"]["diameter"]["pflag"], "1")
        message_hex = diameter_event["state"]["diameter"]["message_hex"]
        self.assertIn(b"edited.example.com", bytes.fromhex(message_hex))
        self.assertNotIn(b"origin.example.com", bytes.fromhex(message_hex))

    def test_diameter_raw_tcp_reassembly_handles_split_and_coalesced_messages(self) -> None:
        first = self.adapter._diameter_encode_message(
            {
                "type": "request",
                "command_code": 272,
                "application_id": 4,
                "hop_by_hop_id": 1,
                "end_to_end_id": 2,
                "avps": [{"code": 263, "data": "first"}],
                "_diameter_avps": [{"code": 263, "data": "first"}],
            }
        )
        second = self.adapter._diameter_encode_message(
            {
                "type": "response",
                "command_code": 272,
                "application_id": 4,
                "hop_by_hop_id": 3,
                "end_to_end_id": 4,
                "avps": [{"code": 268, "type": "unsigned32", "data": "2001"}],
                "_diameter_avps": [
                    {
                        "code": 268,
                        "type": "unsigned32",
                        "data": "2001",
                        "_data": (2001).to_bytes(4, "big"),
                    }
                ],
            }
        )
        combined = first + second
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "DIAMETER"],
                "irule": "when DIAMETER_INGRESS { log local0. \"command=[DIAMETER::command] length=[DIAMETER::length]\" }\nwhen DIAMETER_EGRESS { log local0. egress }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 3868, 3868, 0x02, sequence=1000
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 3868, 3868, 0x18,
                            combined[:17], sequence=1001
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "10.0.0.5", "192.0.2.10", 3868, 3868, 0x18,
                            combined[17:], sequence=1018
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertTrue(result["trace"][1]["buffered"])
        diameter_entries = [entry for entry in result["trace"] if entry["protocol"] == "diameter"]
        self.assertEqual(len(diameter_entries), 2)
        self.assertEqual(
            [event["event"] for event in diameter_entries[0]["events"] if event["fired"]],
            ["DIAMETER_INGRESS"],
        )
        self.assertEqual(
            [event["event"] for event in diameter_entries[1]["events"] if event["fired"]],
            ["DIAMETER_INGRESS"],
        )
        self.assertIn("command=272 length=36", " ".join(diameter_entries[0]["events"][-1]["logs"]))

    def test_diameter_response_drop_retransmission_and_wire_validation(self) -> None:
        response = self.adapter.run_scenario(
            {
                "profiles": ["DIAMETER"],
                "irule": "when DIAMETER_INGRESS { DIAMETER::respond 1 0 0 0 0 }",
                "packets": [
                    {
                        "protocol": "diameter",
                        "type": "request",
                        "command_code": 280,
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(response["trace"][0]["responded"])
        self.assertEqual(response["trace"][0]["response"]["arguments"], ["1", "0", "0", "0", "0"])

        dropped = self.adapter.run_scenario(
            {
                "profiles": ["DIAMETER"],
                "irule": "when DIAMETER_INGRESS { DIAMETER::drop }",
                "packets": [{"protocol": "diameter", "command_code": 280}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(dropped["trace"][0]["dropped"])
        self.assertEqual(dropped["trace"][0]["drop_reason"], "message")

        retransmitted = self.adapter.run_scenario(
            {
                "profiles": ["DIAMETER"],
                "irule": """
when DIAMETER_INGRESS { DIAMETER::header pflag 1 }
when DIAMETER_RETRANSMISSION { log local0. "retransmit=[DIAMETER::is_retransmission] pflag=[DIAMETER::header pflag]" }
""",
                "packets": [{"protocol": "diameter", "tflag": True, "command_code": 280}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        retransmission_event = next(
            event for event in retransmitted["trace"][0]["events"]
            if event["event"] == "DIAMETER_RETRANSMISSION"
        )
        self.assertTrue(
            any("retransmit=1 pflag=1" in log for log in retransmission_event["logs"])
        )

        invalid = bytearray.fromhex("0100001c80000110000000000000000000000000")
        invalid.extend(bytes.fromhex("0000010c00000000"))
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "AVP length"):
            self.adapter.run_scenario(
                {
                    "profiles": ["DIAMETER"],
                    "irule": "when DIAMETER_INGRESS { log local0. invalid }",
                    "packets": [{"protocol": "diameter", "message_hex": invalid.hex()}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_radius_structured_messages_expose_codes_attributes_and_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "RADIUS"],
                "irule": """
when RADIUS_AAA_AUTH_REQUEST {
    log local0. "code=[RADIUS::code] id=[RADIUS::id] user=[RADIUS::avp User-Name string] ip=[RADIUS::avp 4 ip4]"
    RADIUS::avp replace User-Name alice
    RADIUS::rtdom 7
    RADIUS::subscriber subscriber-1
}
""",
                "packets": [
                    {
                        "protocol": "radius",
                        "direction": "client_to_server",
                        "code": 1,
                        "id": 9,
                        "avps": [
                            {"code": "User-Name", "data": "bob"},
                            {"code": "NAS-IP-Address", "type": "ip4", "data": "192.0.2.20"},
                            {"code": 26, "vendor_id": 10415, "vendor_type": 1, "data": "imsi-1"},
                        ],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        event = next(
            event for event in result["trace"][0]["events"]
            if event["event"] == "RADIUS_AAA_AUTH_REQUEST"
        )
        self.assertTrue(event["fired"])
        self.assertTrue(any("code=1 id=9 user=bob ip=192.0.2.20" in log for log in event["logs"]))
        self.assertEqual(event["state"]["radius"]["rtdom"], "7")
        self.assertEqual(event["state"]["radius"]["subscriber"], "subscriber-1")
        self.assertIn(b"alice", bytes.fromhex(event["state"]["radius"]["message_hex"]))
        self.assertNotIn(b"bob", bytes.fromhex(event["state"]["radius"]["message_hex"]))

    def test_radius_raw_udp_replay_decodes_auth_and_accounting_events(self) -> None:
        auth = self.adapter._radius_encode_message(
            {
                "code": 1,
                "id": 3,
                "authenticator_hex": "11" * 16,
                "_radius_avps": [
                    {"code": 1, "type": "string", "data": "alice", "_data": b"alice"}
                ],
            }
        )
        acct = self.adapter._radius_encode_message(
            {
                "code": 4,
                "id": 4,
                "authenticator_hex": "22" * 16,
                "_radius_avps": [
                    {"code": 40, "type": "integer", "data": "1", "_data": (1).to_bytes(4, "big")}
                ],
            }
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "RADIUS_AAA"],
                "irule": "when RADIUS_AAA_AUTH_REQUEST { log local0. auth }\nwhen RADIUS_AAA_ACCT_REQUEST { log local0. acct }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex("10.0.0.5", "192.0.2.10", 51000, 1812, auth),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex("10.0.0.5", "192.0.2.10", 51000, 1813, acct),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["trace"][0]["protocol"], "radius")
        self.assertEqual(result["trace"][0]["events"][-1]["event"], "RADIUS_AAA_AUTH_REQUEST")
        self.assertEqual(result["trace"][1]["events"][-1]["event"], "RADIUS_AAA_ACCT_REQUEST")
        self.assertTrue(any("auth" in log for log in result["trace"][0]["events"][-1]["logs"]))
        self.assertTrue(any("acct" in log for log in result["trace"][1]["events"][-1]["logs"]))

    def test_radius_response_events_vendor_attributes_and_validation(self) -> None:
        response = self.adapter.run_scenario(
            {
                "profiles": ["RADIUS"],
                "irule": "when RADIUS_AAA_AUTH_RESPONSE { log local0. \"response code=[RADIUS::code] id=[RADIUS::id]\" }",
                "packets": [
                    {
                        "protocol": "radius",
                        "direction": "server_to_client",
                        "code": 2,
                        "id": 9,
                        "avps": [{"code": "Reply-Message", "data": "welcome"}],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = response["trace"][0]["events"][-1]
        self.assertEqual(event["event"], "RADIUS_AAA_AUTH_RESPONSE")
        self.assertTrue(any("response code=2 id=9" in log for log in event["logs"]))

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "vendor fields"):
            self.adapter.run_scenario(
                {
                    "profiles": ["RADIUS"],
                    "irule": "when RADIUS_AAA_AUTH_REQUEST { log local0. invalid }",
                    "packets": [{"protocol": "radius", "avps": [{"code": 1, "vendor_id": 7, "data": "x"}]}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

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

    def test_http_stream_decoder_honors_head_and_connect_response_framing(self) -> None:
        head_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n"
            b"X-Mode: head\r\n\r\n"
        )
        decoded_head = self.adapter._decode_http_payload(
            head_response,
            "server_to_client",
            request_method=" head ",
        )
        self.assertIsNotNone(decoded_head)
        assert decoded_head is not None
        head_message, head_consumed = decoded_head
        self.assertEqual(head_message["response_body"], "")
        self.assertEqual(head_consumed, len(head_response))

        connect_response = (
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Content-Length: 999\r\n\r\n"
        )
        decoded_connect = self.adapter._decode_http_payload(
            connect_response,
            "server_to_client",
            request_method="CONNECT",
        )
        self.assertIsNotNone(decoded_connect)
        assert decoded_connect is not None
        connect_message, connect_consumed = decoded_connect
        self.assertEqual(connect_message["response_body"], "")
        self.assertEqual(connect_consumed, len(connect_response))

        incomplete_get_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nno"
        )
        self.assertIsNone(
            self.adapter._decode_http_payload(
                incomplete_get_response,
                "server_to_client",
                request_method="GET",
            )
        )

    def test_raw_http_response_framing_uses_pending_head_request(self) -> None:
        request = b"HEAD /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": 'when HTTP_RESPONSE { log local0. "status=[HTTP::status]" }',
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
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["request"]["method"], "HEAD")
        self.assertEqual(result["results"][0]["response"]["status"], 200)
        self.assertEqual(result["results"][0]["response"]["body"], "")

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

    def test_dns_rr_objects_can_be_created_inserted_and_inspected(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": """
when DNS_REQUEST {
    set rr [DNS::rr "[DNS::question name]. 30 IN A 192.0.2.10"]
    DNS::answer clear
    DNS::answer insert $rr
    DNS::header aa 1
    log local0. "[DNS::name $rr] [DNS::type $rr] [DNS::class $rr] [DNS::ttl $rr] [DNS::rdata $rr] [DNS::header aa]"
    DNS::return
}
when DNS_RESPONSE { DNS::drop }
""",
                "packets": [
                    {
                        "protocol": "dns",
                        "direction": "client_to_server",
                        "qname": "example.com",
                        "qtype": "A",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][0]
        self.assertTrue(event["fired"])
        self.assertTrue(event["state"]["dns"]["response_sent"] in {"1", "true"})
        self.assertTrue(result["trace"][0]["dropped"])
        self.assertEqual(event["state"]["dns"]["ancount"], "1")
        self.assertIn("example.com. A IN 30 192.0.2.10", event["state"]["dns"]["answers"])
        self.assertIn("example.com. A IN 30 192.0.2.10 1", event["logs"][0])
        self.assertTrue(event["state"]["dns"]["message_hex"])
        self.assertEqual(result["trace"][0]["events"][1]["event"], "DNS_RESPONSE")

    def test_dns_tsig_exists_and_remove_are_connection_safe(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": """
when DNS_REQUEST {
    log local0. "before=[DNS::tsig exists]"
    if {[DNS::question name] eq "signed.example.com"} { DNS::tsig remove }
    log local0. "after=[DNS::tsig exists]"
}
""",
                "packets": [
                    {
                        "protocol": "dns",
                        "direction": "client_to_server",
                        "qname": "signed.example.com",
                        "qtype": "A",
                        "tsig_present": True,
                    },
                    {
                        "protocol": "dns",
                        "direction": "client_to_server",
                        "qname": "unsigned.example.com",
                        "qtype": "A",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][0]
        unsigned_event = result["trace"][1]["events"][0]
        self.assertTrue(any("before=1" in entry for entry in event["logs"]))
        self.assertTrue(any("after=0" in entry for entry in event["logs"]))
        self.assertEqual(event["state"]["dns"]["tsig_present"], "0")
        self.assertTrue(any("before=0" in entry for entry in unsigned_event["logs"]))
        self.assertEqual(unsigned_event["state"]["dns"]["tsig_present"], "0")
        self.assertTrue(any("tsig_remove" in entry for entry in event["decisions"]))
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"] == "DNS::tsig"
            },
            {"DNS::tsig": "semantic-mock"},
        )

    def test_raw_dns_response_decodes_compressed_answer_records(self) -> None:
        qname = b"\x07example\x03com\x00"
        dns_payload = (
            struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
            + qname
            + struct.pack("!HH", 1, 1)
            + b"\xc0\x0c"
            + struct.pack("!HHIH4s", 1, 1, 60, 4, b"\xc0\x00\x02\x0a")
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": "when DNS_RESPONSE { set rr [lindex [DNS::answer] 0]; log local0. \"[DNS::name $rr] [DNS::type $rr] [DNS::rdata $rr] [DNS::ttl $rr] [DNS::header ancount]\" }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.53", "10.0.0.5", 53, 53000, dns_payload
                        ),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][0]
        self.assertEqual(event["event"], "DNS_RESPONSE")
        self.assertTrue(event["fired"])
        self.assertEqual(event["state"]["dns"]["ancount"], "1")
        self.assertIn("example.com A 192.0.2.10 60 1", event["logs"][0])
        self.assertEqual(
            int(event["state"]["dns"]["message_length"]),
            len(bytes.fromhex(event["state"]["dns"]["message_hex"])),
        )

    def test_dns_response_rr_mutation_scrape_and_drop_are_stateful(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": """
when DNS_RESPONSE {
    set rr [lindex [DNS::answer] 0]
    DNS::ttl $rr 10
    DNS::answer insert [DNS::rr "alias.example.com. 20 IN CNAME example.com."]
    log local0. "[DNS::scrape ALL type ttl qnamelen rdatalen]"
    DNS::answer remove $rr
    DNS::drop
}
""",
                "packets": [
                    {
                        "protocol": "dns",
                        "direction": "server_to_client",
                        "qname": "example.com",
                        "qtype": "A",
                        "answers": [
                            {
                                "name": "example.com.",
                                "type": "A",
                                "class": "IN",
                                "ttl": 60,
                                "rdata": "192.0.2.10",
                            }
                        ],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        packet = result["trace"][0]
        event = packet["events"][0]
        self.assertTrue(event["fired"])
        self.assertTrue(packet["dropped"])
        self.assertEqual(event["state"]["dns"]["ancount"], "1")
        self.assertIn("alias.example.com. CNAME IN 20 example.com.", event["state"]["dns"]["answers"])
        self.assertIn("A 10 12 10", event["logs"][0])
        self.assertIn("CNAME 20 18 12", event["logs"][0])

    def test_dns_structured_input_supports_edns0_and_wideip_membership(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP", "DNS"],
                "irule": """
when DNS_REQUEST {
    log local0. "[DNS::edns0 exists] [DNS::edns0 do] [DNS::edns0 sz] [DNS::edns0 subnet address] [DNS::is_wideip [DNS::question name]]"
}
""",
                "packets": [
                    {
                        "protocol": "dns",
                        "qname": "www.example.com.",
                        "edns0": {
                            "exists": True,
                            "do": True,
                            "sz": 1232,
                            "subnet_address": "192.0.2.0",
                            "subnet_source": 24,
                            "subnet_scope": 0,
                        },
                        "wideips": ["www.example.com"],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][0]
        self.assertIn("1 1 1232 192.0.2.0 0", event["logs"][0])

    def test_dns_input_rejects_invalid_resource_record_ttl(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "ttl"):
            self.adapter._normalise_packets(
                [
                    {
                        "protocol": "dns",
                        "qname": "example.com",
                        "answers": [
                            {
                                "name": "example.com.",
                                "type": "A",
                                "class": "IN",
                                "ttl": -1,
                                "rdata": "192.0.2.10",
                            }
                        ],
                    }
                ]
            )

    def test_resolver_lookup_returns_dnsmsg_objects(self) -> None:
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    set message [RESOLVER::name_lookup /Common/r1 www.example.com A]
    set rr [lindex [DNSMSG::section $message answer] 0]
    log local0. "[DNSMSG::header $message qr] [DNSMSG::header $message rcode] [DNSMSG::record $rr owner] [DNSMSG::record $rr type] [DNSMSG::record $rr rdata] [llength [RESOLVER::summarize $message]]"
}
""",
                "resolvers": {
                    "/Common/r1": [
                        {
                            "name": "www.example.com.",
                            "type": "A",
                            "class": "IN",
                            "ttl": 120,
                            "rdata": "192.0.2.20",
                        }
                    ]
                },
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED")
        finally:
            session.close()
        self.assertTrue(result["fired"])
        self.assertIn("1 0 www.example.com. A 192.0.2.20 1", result["logs"][0])

    def test_legacy_name_and_resolv_lookups_use_deterministic_records(self) -> None:
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "NAME"],
                "irule": """
when CLIENT_ACCEPTED {
    set inline [RESOLV::lookup @/Common/r1 -a www.example.com]
    NAME::lookup @/Common/r1 www.example.com
    log local0. "inline=$inline"
}
when NAME_RESOLVED {
    log local0. "addresses=[NAME::response] first=[NAME::response address 0]"
}
""",
                "resolvers": {
                    "/Common/r1": [
                        {
                            "name": "www.example.com.",
                            "type": "A",
                            "class": "IN",
                            "ttl": 120,
                            "rdata": "192.0.2.20",
                        },
                        {
                            "name": "www.example.com.",
                            "type": "A",
                            "class": "IN",
                            "ttl": 120,
                            "rdata": "192.0.2.21",
                        },
                    ]
                },
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            result = session.fire_event("CLIENT_ACCEPTED")
        finally:
            session.close()
        self.assertTrue(result["fired"])
        self.assertTrue(any("inline=192.0.2.20 192.0.2.21" in entry for entry in result["logs"]))
        self.assertTrue(any(
            "addresses=192.0.2.20 192.0.2.21 first=192.0.2.20" in entry
            for entry in result["logs"]
        ))
        inline_index = next(
            index for index, entry in enumerate(result["logs"])
            if "inline=192.0.2.20 192.0.2.21" in entry
        )
        response_index = next(
            index for index, entry in enumerate(result["logs"])
            if "addresses=192.0.2.20 192.0.2.21 first=192.0.2.20" in entry
        )
        self.assertLess(inline_index, response_index)

        reverse = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "NAME"],
                "irule": """
when CLIENT_ACCEPTED { NAME::lookup @/Common/r1 192.0.2.20 }
when NAME_RESOLVED {
    log local0. "ptr=[NAME::response] name=[NAME::response name]"
}
""",
                "resolvers": {
                    "/Common/r1": [
                        {
                            "name": "20.2.0.192.in-addr.arpa.",
                            "type": "PTR",
                            "class": "IN",
                            "ttl": 120,
                            "rdata": "host.example.com.",
                        }
                    ]
                },
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            reverse_result = reverse.fire_event("CLIENT_ACCEPTED")
        finally:
            reverse.close()
        self.assertTrue(any(
            "ptr=host.example.com. name=host.example.com." in entry
            for entry in reverse_result["logs"]
        ))

        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError,
            "received unknown record type option -bogus",
        ):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when CLIENT_ACCEPTED { RESOLV::lookup -bogus example.com }",
                    "resolvers": {"/Common/r1": []},
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_name_resolution_callback_loop_is_bounded(self) -> None:
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "NAME"],
                "irule": """
when CLIENT_ACCEPTED { NAME::lookup @/Common/r1 www.example.com }
when NAME_RESOLVED { NAME::lookup @/Common/r1 www.example.com }
""",
                "resolvers": {
                    "/Common/r1": [
                        {
                            "name": "www.example.com.",
                            "type": "A",
                            "class": "IN",
                            "ttl": 60,
                            "rdata": "192.0.2.20",
                        }
                    ]
                },
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "exceeded the 32-event NAME_RESOLVED dispatch limit",
            ):
                session.fire_event("CLIENT_ACCEPTED")
        finally:
            session.close()

    def test_route_metrics_lookup_domain_and_clear(self) -> None:
        destination = "192.0.2.10"
        gateway = "192.0.2.1"
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "route": {
                    "domain": "7",
                    "metrics": [
                        {
                            "destination": destination,
                            "gateway": gateway,
                            "age": 12,
                            "expiration": 300,
                            "mtu": 1500,
                            "rtt": 3200,
                            "rttvar": 400,
                            "cwnd": 14600,
                            "bandwidth": 3650,
                        }
                    ],
                },
                "irule": f"""
when CLIENT_ACCEPTED {{
    log local0. "before=[ROUTE::domain] [ROUTE::age {destination} {gateway}] [ROUTE::expiration {destination} {gateway}] [ROUTE::mtu {destination} {gateway}] [ROUTE::rtt {destination} {gateway}] [ROUTE::rttvar {destination} {gateway}] [ROUTE::cwnd {destination} {gateway}] [ROUTE::bandwidth {destination} {gateway}]"
    ROUTE::clear {destination} {gateway}
    log local0. "after=[ROUTE::rtt {destination} {gateway}] cleared=[set ::state::route::cleared]"
}}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            first = session.fire_event("CLIENT_ACCEPTED")
            second = session.fire_event("CLIENT_ACCEPTED")
            fidelity = session.fidelity
        finally:
            session.close()

        self.assertTrue(first["fired"])
        self.assertTrue(any("before=7 12 300 1500 3200 400 14600 3650" in log for log in first["logs"]))
        self.assertTrue(any("after=0 cleared=1" in log for log in first["logs"]))
        self.assertTrue(any("before=7 0 0 0 0 0 0 0" in log for log in second["logs"]))
        self.assertEqual(first["state"]["route"]["cleared"], "1")
        self.assertEqual(first["state"]["route"]["rtt"], "0")
        self.assertEqual(second["state"]["route"]["destination"], destination)
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in fidelity["commands"]
                if entry["name"].startswith("ROUTE::")
            },
            {
                "ROUTE::age": "semantic-mock",
                "ROUTE::bandwidth": "semantic-mock",
                "ROUTE::clear": "semantic-mock",
                "ROUTE::cwnd": "semantic-mock",
                "ROUTE::domain": "semantic-mock",
                "ROUTE::expiration": "semantic-mock",
                "ROUTE::mtu": "semantic-mock",
                "ROUTE::rtt": "semantic-mock",
                "ROUTE::rttvar": "semantic-mock",
            },
        )

    def test_route_metrics_reject_duplicate_entries_and_invalid_values(self) -> None:
        base = {
            "profiles": ["TCP"],
            "irule": "when CLIENT_ACCEPTED { log local0. [ROUTE::domain] }",
        }
        invalid_routes = (
            (
                {"domain": "0", "metrics": [{"destination": "192.0.2.1"}, {"destination": "192.0.2.1"}]},
                "duplicate destination/gateway",
            ),
            (
                {"domain": "0", "metrics": [{"destination": "192.0.2.1", "rtt": -1}]},
                "non-negative integer",
            ),
        )
        for route, message in invalid_routes:
            with self.subTest(route=route):
                scenario = dict(base, route=route)
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.EmulatorSession(
                        Path(self.tcl_lsp_root),
                        scenario,
                        allow_irule_file=False,
                        allow_requests=False,
                    )

    def test_http_proxy_controls_resolution_and_proxy_chaining(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "http_proxy": {
                    "enabled": True,
                    "uri_rewrite": True,
                    "resolved": True,
                    "addr": "192.0.2.44",
                    "port": 3128,
                    "rtdom": 7,
                    "iptuple": "192.0.2.44%7:3128",
                    "chain": {
                        "enabled": True,
                        "host": "proxy.internal",
                        "port": 8080,
                    },
                },
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::request_num] == 1} {
        log local0. "before=[list [HTTP::proxy] [HTTP::proxy exists] [HTTP::proxy addr] [HTTP::proxy port] [HTTP::proxy rtdom] [HTTP::proxy iptuple] [HTTP::proxy chain] [HTTP::proxy chain host] [HTTP::proxy chain port]]"
        HTTP::proxy disable
        HTTP::proxy uri-rewrite disable
        HTTP::proxy chain disable
        HTTP::proxy chain host next-proxy.internal
        HTTP::proxy chain port 8081
        HTTP::proxy chain retry
        log local0. "after=[list [HTTP::proxy] [set ::itest::semantic::http_proxy_uri_rewrite] [HTTP::proxy chain] [HTTP::proxy chain host] [HTTP::proxy chain port] [set ::itest::semantic::http_proxy_chain_retry_requested]]"
    }
}
""",
                "requests": [{"host": "example.com", "uri": "/one"}, {"uri": "/two"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first, second = result["results"]
        self.assertTrue(any("before=1 1 192.0.2.44 3128 7 192.0.2.44%7:3128 1 proxy.internal 8080" in entry for entry in first["logs"]))
        self.assertTrue(any("after=0 0 0 next-proxy.internal 8081 1" in entry for entry in first["logs"]))
        self.assertEqual(
            first["semantic"]["http_proxy"],
            {
                "enabled": False,
                "uri_rewrite": False,
                "resolved": True,
                "addr": "192.0.2.44",
                "port": 3128,
                "rtdom": 7,
                "iptuple": "192.0.2.44%7:3128",
                "chain_enabled": False,
                "chain_host": "next-proxy.internal",
                "chain_port": 8081,
                "chain_retry_requested": True,
                "chain_response": None,
                "chain_response_index": 0,
                "chain_retry_count": 0,
                "chain_failed": False,
            },
        )
        self.assertEqual(second["semantic"]["http_proxy"]["enabled"], True)
        self.assertEqual(second["semantic"]["http_proxy"]["uri_rewrite"], True)
        self.assertEqual(second["semantic"]["http_proxy"]["chain_host"], "proxy.internal")
        self.assertFalse(second["semantic"]["http_proxy"]["chain_retry_requested"])
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        self.assertEqual(usage["HTTP::proxy"]["runtime_status"], "semantic-mock")

    def test_http_proxy_unresolved_destination_and_input_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "http_proxy": {
                    "resolved": False,
                    "addr": "192.0.2.44",
                    "port": 3128,
                    "rtdom": 7,
                },
                "irule": "when HTTP_REQUEST { log local0. \"exists=[HTTP::proxy exists] addr=[HTTP::proxy addr] port=[HTTP::proxy port] rtdom=[HTTP::proxy rtdom] tuple=[HTTP::proxy iptuple]\" }",
                "request": {"host": "unresolved.example.com"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event_log = result["results"][0]["logs"]
        self.assertTrue(any("exists=0 addr= port= rtdom= tuple=" in entry for entry in event_log))

        invalid_values = (
            ({"chain": {"port": 65536}}, "chain.port"),
            ({"port": -1}, "http_proxy.port"),
            ({"enabled": "yes"}, "http_proxy.enabled"),
        )
        for proxy, message in invalid_values:
            with self.subTest(proxy=proxy):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.EmulatorSession(
                        Path(self.tcl_lsp_root),
                        {
                            "profiles": ["TCP", "HTTP"],
                            "http_proxy": proxy,
                            "irule": "when HTTP_REQUEST { log local0. ok }",
                        },
                        allow_irule_file=False,
                        allow_requests=False,
                    )

    def test_rewrite_events_modify_request_and_response_payloads(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "REWRITE"],
                "irule": """
when REWRITE_REQUEST_DONE {
    log local0. "request=[REWRITE::payload] length=[REWRITE::payload length] first=[REWRITE::payload 2] window=[REWRITE::payload 1 2] post=[REWRITE::post_process]"
    REWRITE::disable
    REWRITE::enable
    REWRITE::payload replace 0 4 pong!
    REWRITE::post_process 1
}
when REWRITE_RESPONSE_DONE {
    log local0. "response=[REWRITE::payload] length=[REWRITE::payload length]"
    REWRITE::payload replace 0 5 world
}
""",
                "request": {
                    "host": "rewrite.example.com",
                    "body": "ping",
                    "headers": {"Content-Length": "4"},
                    "response_body": "hello",
                    "response_headers": {"Content-Length": "5"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertIn("REWRITE_REQUEST_DONE", request_result["events_fired"])
        self.assertIn("REWRITE_RESPONSE_DONE", request_result["events_fired"])
        self.assertEqual(request_result["request"]["body"], "pong!")
        self.assertEqual(request_result["response"]["body"], "world")
        self.assertEqual(request_result["request"]["headers"]["content-length"], "5")
        self.assertEqual(request_result["response"]["headers"]["content-length"], "5")
        self.assertEqual(
            request_result["semantic"]["rewrite"],
            {
                "enabled": True,
                "post_process": True,
                "payload_side": "response",
                "payload_replaced": True,
                "request_payload_length": 5,
                "response_payload_length": 5,
            },
        )
        self.assertTrue(any("request=ping length=4 first=pi window=in post=0" in entry for entry in request_result["logs"]))
        self.assertTrue(any("response=hello length=5" in entry for entry in request_result["logs"]))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("REWRITE::disable", "REWRITE::enable", "REWRITE::payload", "REWRITE::post_process"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_html_filter_fires_token_events_and_applies_bounded_mutations(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "HTML"],
                "irule": """
when HTTP_RESPONSE {
    HTML::enable
    log local0. "encoded=[HTML::encode {<x>&\"'}]"
}
when HTML_TAG_MATCHED {
    if {[HTML::tag name] eq "html"} {
        HTML::disable
        HTML::enable
    }
    if {[HTML::tag name] eq "title"} {
        HTML::tag prepend {<!--title-start-->}
        HTML::tag append {<!--title-end-->}
    }
    if {[string trimleft [HTML::tag name] /] eq "p"} {
        HTML::tag remove
    }
    if {[HTML::tag name] eq "br"} {
        HTML::tag append {<!--br-marker-->}
    }
}
when HTML_COMMENT_MATCHED {
    if {[HTML::comment] eq {<!--remove-->}} {
        HTML::comment remove
    }
}
""",
                "request": {
                    "host": "html.example.com",
                    "response_body": "<html><title>Hi</title><!--remove--><p>x</p><br/></html>",
                    "response_headers": {"Content-Length": "52"},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertIn("HTML_TAG_MATCHED", request_result["events_fired"])
        self.assertIn("HTML_COMMENT_MATCHED", request_result["events_fired"])
        self.assertEqual(
            request_result["response"]["body"],
            "<html><!--title-start--><title><!--title-end-->Hi</title>x<br/><!--br-marker--></html>",
        )
        self.assertEqual(
            request_result["response"]["headers"]["content-length"],
            str(len(request_result["response"]["body"].encode("utf-8"))),
        )
        self.assertEqual(request_result["semantic"]["html"]["token_count"], 8)
        self.assertTrue(request_result["semantic"]["html"]["mutated"])
        self.assertTrue(any("encoded=&lt;x&gt;&amp;&quot;&#39;" in entry for entry in request_result["logs"]))
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("HTML::comment", "HTML::disable", "HTML::enable", "HTML::encode", "HTML::tag"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_http_compression_controls_transform_response_and_decode_before_response(self) -> None:
        compressed = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_RESPONSE {
    if {[HTTP::uri] eq "/gzip"} {
        COMPRESS::disable response
        COMPRESS::gzip response level 9
        COMPRESS::gzip response memory_level 9
        COMPRESS::gzip response window_size 15
        COMPRESS::buffer_size response 4096
        COMPRESS::method response prefer gzip
        COMPRESS::nodelay response
        COMPRESS::enable response
    }
}
""",
                "requests": [
                    {
                        "uri": "/gzip",
                        "host": "compress.example.com",
                        "response_body": "payload that should be gzip encoded",
                        "response_headers": {"Content-Length": "36"},
                    },
                    {
                        "uri": "/plain",
                        "host": "compress.example.com",
                        "response_body": "keep alive remains plain",
                        "response_headers": {"Content-Length": "24"},
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        compressed_result = compressed["results"][0]
        compressed_body = compressed_result["response"]["body"].encode("latin-1")
        self.assertEqual(zlib.decompress(compressed_body, 31), b"payload that should be gzip encoded")
        self.assertEqual(compressed_result["response"]["headers"]["content-encoding"], "gzip")
        self.assertEqual(
            compressed_result["response"]["headers"]["content-length"],
            str(len(compressed_body)),
        )
        compression = compressed_result["semantic"]["compression"]
        self.assertTrue(compression["compress_applied"])
        self.assertEqual(compression["compress_applied_side"], "response")
        self.assertEqual(compression["compress_response_gzip_level"], 9)
        self.assertEqual(compression["compress_response_buffer_size"], 4096)
        self.assertTrue(compression["compress_response_nodelay"])
        plain_result = compressed["results"][1]
        self.assertEqual(plain_result["response"]["body"], "keep alive remains plain")
        self.assertNotIn("content-encoding", plain_result["response"]["headers"])
        self.assertFalse(plain_result["semantic"]["compression"]["compress_applied"])

        encoded = base64.b64encode(zlib.compress(b"decoded response", 9, wbits=31)).decode("ascii")
        decompressed = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": f"""
when HTTP_RESPONSE {{
    DECOMPRESS::disable response
    DECOMPRESS::enable response
    HTTP::header replace Content-Encoding gzip
    HTTP::respond 200 content [binary decode base64 {{{encoded}}}]
}}
""",
                "request": {"host": "decompress.example.com"},
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        decompressed_result = decompressed["results"][0]
        self.assertEqual(decompressed_result["response"]["body"], "decoded response")
        self.assertNotIn("content-encoding", decompressed_result["response"]["headers"])
        self.assertTrue(decompressed_result["semantic"]["compression"]["decompress_applied"])
        self.assertEqual(
            decompressed_result["semantic"]["compression"]["decompress_applied_side"],
            "response",
        )
        usage = {
            entry["name"]: entry
            for entry in compressed["fidelity"]["commands"] + decompressed["fidelity"]["commands"]
        }
        for command in (
            "COMPRESS::buffer_size", "COMPRESS::disable", "COMPRESS::enable",
            "COMPRESS::gzip", "COMPRESS::method", "COMPRESS::nodelay",
            "DECOMPRESS::disable", "DECOMPRESS::enable",
        ):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

    def test_httplog_enable_disable_emits_request_and_response_audit_records(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/logged"} {
        HTTPLOG::enable
    } else {
        HTTPLOG::disable
    }
}
""",
                "requests": [
                    {
                        "uri": "/logged",
                        "host": "log.example.com",
                        "headers": {"X-Request": "one"},
                        "body": "abc",
                        "response_status": 201,
                        "response_headers": {
                            "Content-Type": "text/plain",
                            "Content-Length": "5",
                        },
                        "response_body": "hello",
                    },
                    {
                        "uri": "/plain",
                        "host": "log.example.com",
                        "body": "xy",
                        "response_body": "no audit",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        logged, plain = result["results"]
        self.assertEqual(
            logged["http_log"],
            [
                {
                    "phase": "request",
                    "method": "GET",
                    "uri": "/logged",
                    "host": "log.example.com",
                    "status": None,
                    "bytes": 3,
                    "headers": {
                        "host": "log.example.com",
                        "x-request": "one",
                    },
                },
                {
                    "phase": "response",
                    "method": "GET",
                    "uri": "/logged",
                    "host": "log.example.com",
                    "status": 201,
                    "bytes": 5,
                    "headers": {
                        "content-type": "text/plain",
                        "content-length": "5",
                    },
                },
            ],
        )
        self.assertEqual(plain["http_log"], [])
        self.assertFalse(plain["semantic"]["http_log"]["enabled"])
        self.assertTrue(logged["semantic"]["http_log"]["enabled"])
        usage = {entry["name"]: entry for entry in result["fidelity"]["commands"]}
        for command in ("HTTPLOG::disable", "HTTPLOG::enable"):
            self.assertEqual(usage[command]["runtime_status"], "semantic-mock")

        inherited = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when CLIENT_ACCEPTED { HTTPLOG::enable }",
                "requests": [
                    {"uri": "/first", "host": "keep.example.com", "response_body": "one"},
                    {"uri": "/second", "host": "keep.example.com", "response_body": "two"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        for request_result, uri, body in zip(
            inherited["results"], ("/first", "/second"), ("one", "two")
        ):
            self.assertEqual(len(request_result["http_log"]), 2)
            self.assertEqual(request_result["http_log"][0]["uri"], uri)
            self.assertEqual(request_result["http_log"][1]["uri"], uri)
            self.assertEqual(request_result["http_log"][1]["bytes"], len(body))

    def test_tls_semantics_expose_sni_cipher_and_peer_certificate(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "CLIENTSSL"],
                "irule": """
when CLIENTSSL_CLIENTHELLO {
    set cert [SSL::cert 0]
    log local0. "[SSL::sni name] [SSL::sni required] [SSL::cipher name] [SSL::cipher bits] [SSL::sessionid] [SSL::cert count] [X509::subject $cert commonName] [X509::issuer $cert]"
    SSL::disable clientside
}
""",
                "packets": [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_hello",
                        "sni": "secure.example.com",
                        "sni_required": True,
                        "cipher_name": "TLS_AES_128_GCM_SHA256",
                        "cipher_bits": 128,
                        "cipher_version": "TLSv1.3",
                        "session_id": "abc123",
                        "cert_count": 1,
                        "cert_subject": "CN=client.example.com,O=Example",
                        "cert_issuer": "CN=Example Root CA",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = next(
            item
            for item in result["trace"][0]["events"]
            if item["event"] == "CLIENTSSL_CLIENTHELLO"
        )
        self.assertTrue(event["fired"])
        self.assertIn(
            "secure.example.com 1 TLS_AES_128_GCM_SHA256 128 abc123 1 client.example.com CN=Example Root CA",
            event["logs"][0],
        )
        self.assertEqual(event["state"]["tls_client"]["disabled"], "1")

    def test_tls_input_rejects_invalid_sni_required_value(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "sni_required"):
            self.adapter._normalise_packets(
                [
                    {
                        "protocol": "tls",
                        "direction": "client_to_server",
                        "type": "client_hello",
                        "sni_required": "sometimes",
                    }
                ]
            )

    def test_http2_metadata_drives_commands_and_mutation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    log local0. "[HTTP2::active] [HTTP2::version] [HTTP2::requests] [HTTP2::concurrency] [HTTP2::header :authority] [HTTP2::stream id]"
    HTTP2::header replace :path /rewritten
    HTTP2::stream priority 42
}
""",
                "request": {
                    "method": "GET",
                    "uri": "/original",
                    "host": "api.example.com",
                    "http2": {
                        "active": True,
                        "version": 2,
                        "stream_id": 3,
                        "stream_priority": 8,
                        "concurrency": 2,
                        "requests": 4,
                        "pseudo_headers": {
                            ":authority": "h2.example.com",
                            ":method": "GET",
                            ":path": "/original",
                            ":scheme": "https",
                        },
                    },
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request_result = result["results"][0]
        self.assertTrue(any("1 2 4 2 h2.example.com 3" in entry for entry in request_result["logs"]))
        self.assertEqual(request_result["http2"]["stream_priority"], "42")
        self.assertEqual(request_result["http2"]["pseudo_headers"][":path"], "/rewritten")
        self.assertEqual(request_result["http2"]["pseudo_headers"][":authority"], "h2.example.com")
        self.assertTrue(any("header_replace" in entry for entry in request_result["decisions"]))

    def test_stream_match_state_and_connection_controls(self) -> None:
        session = self.adapter.EmulatorSession(
            Path(self.tcl_lsp_root),
            {
                "profiles": ["TCP", "STREAM"],
                "irule": """
when STREAM_MATCHED {
    if {[STREAM::match] eq "first"} {
        STREAM::encoding utf-8
        STREAM::expression {foo bar}
        STREAM::max_matchsize 2048
        STREAM::replace rewritten
        STREAM::disable
        log local0. "first=[STREAM::match] replacement=[set ::state::stream::replacement] disabled=[set ::state::stream::disabled]"
        STREAM::enable
    } elseif {[STREAM::match] eq "clear"} {
        STREAM::replace
    } else {
        log local0. "match=[STREAM::match] replacement=[set ::state::stream::replacement]"
    }
}
""",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            first = session.fire_event("STREAM_MATCHED", {"stream": {"match": "first"}})
            second = session.fire_event("STREAM_MATCHED", {"stream": {"match": "second"}})
            no_state = session.fire_event("STREAM_MATCHED")
            cleared = session.fire_event("STREAM_MATCHED", {"stream": {"match": "clear"}})
        finally:
            session.close()

        self.assertTrue(first["fired"])
        self.assertTrue(second["fired"])
        self.assertTrue(no_state["fired"])
        self.assertTrue(cleared["fired"])
        self.assertEqual(first["state"]["stream"]["encoding"], "utf-8")
        self.assertEqual(first["state"]["stream"]["expression"], "foo bar")
        self.assertEqual(first["state"]["stream"]["max_matchsize"], "2048")
        self.assertEqual(first["state"]["stream"]["replacement"], "rewritten")
        self.assertEqual(first["state"]["stream"]["replacement_requested"], "1")
        self.assertEqual(first["state"]["stream"]["replaced"], "1")
        self.assertEqual(first["state"]["stream"]["disabled"], "0")
        self.assertEqual(first["state"]["stream"]["enabled"], "1")
        self.assertEqual(second["state"]["stream"]["replacement"], "")
        self.assertEqual(second["state"]["stream"]["replacement_requested"], "0")
        self.assertEqual(cleared["state"]["stream"]["replacement_requested"], "0")
        self.assertTrue(any("first=first replacement=rewritten disabled=1" in log for log in first["logs"]))
        self.assertTrue(any("match=second replacement=" in log for log in second["logs"]))
        self.assertTrue(any("match= replacement=" in log for log in no_state["logs"]))

        stream_statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in session.fidelity["commands"]
            if entry["name"].startswith("STREAM::")
        }
        self.assertEqual(
            set(stream_statuses.values()),
            {"semantic-mock"},
        )

    def test_stream_connection_settings_reset_after_close(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "STREAM"],
                "irule": """
when HTTP_REQUEST {
    if {[HTTP::uri] eq "/first"} {
        STREAM::encoding utf-8
        STREAM::disable
    }
    log local0. "[HTTP::uri] [set ::state::stream::encoding] [set ::state::stream::disabled]"
}
""",
                "requests": [
                    {"uri": "/first", "close_after": True},
                    {"uri": "/second"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        first_logs = result["results"][0]["logs"]
        second_logs = result["results"][1]["logs"]
        self.assertTrue(any("/first utf-8 1" in log for log in first_logs))
        self.assertTrue(any("/second ascii 0" in log for log in second_logs))

    def test_stream_profile_matches_tcp_payload_and_handles_split_matches(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "STREAM"],
                "irule": """
when CLIENT_ACCEPTED { STREAM::expression @secret@redacted@ }
when STREAM_MATCHED {
    log local0. "match=[STREAM::match]"
    STREAM::replace redacted
}
""",
                "packets": [{"protocol": "tcp", "payload": "prefix secret suffix"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        entry = result["trace"][0]
        self.assertIn("STREAM_MATCHED", [event["event"] for event in entry["events"]])
        self.assertEqual(entry["stream_match"], "secret")
        self.assertEqual(entry["payload_after"], "prefix redacted suffix")
        stream_event = next(
            event for event in entry["events"] if event["event"] == "STREAM_MATCHED"
        )
        self.assertEqual(stream_event["state"]["stream"]["match"], "secret")
        self.assertEqual(stream_event["state"]["stream"]["replacement"], "redacted")

        split = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "STREAM"],
                "irule": """
when CLIENT_ACCEPTED { STREAM::expression @secret@redacted@ }
when STREAM_MATCHED { STREAM::replace redacted }
""",
                "packets": [
                    {"protocol": "tcp", "payload": "sec"},
                    {"protocol": "tcp", "payload": "ret"},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            [event["event"] for event in split["trace"][0]["events"]],
            ["RULE_INIT", "CLIENT_ACCEPTED"],
        )
        self.assertEqual(split["trace"][1]["stream_match"], "secret")
        self.assertTrue(split["trace"][1]["stream_replacement_deferred"])

        disabled = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "STREAM"],
                "irule": """
when CLIENT_ACCEPTED { STREAM::expression @secret@redacted@; STREAM::disable }
when STREAM_MATCHED { log local0. should-not-run }
""",
                "packets": [{"protocol": "tcp", "payload": "secret"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertNotIn(
            "STREAM_MATCHED",
            [event["event"] for event in disabled["trace"][0]["events"]],
        )

    def test_stream_max_matchsize_rejects_non_positive_values(self) -> None:
        for value in ("0", "-1"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, "positive integer"):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP", "STREAM"],
                            "irule": f"when HTTP_REQUEST {{ STREAM::max_matchsize {value} }}",
                            "requests": [{"uri": "/invalid"}],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

    def test_http2_push_records_promise_and_inline_response_metadata(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST {
    HTTP2::push /static/app.js -priority 16 -content "console.log('pushed');" -noserver host example.com -- :status 200 content-type application/javascript
}
""",
                "request": {
                    "uri": "/index.html",
                    "http2": {"active": True, "version": 2, "stream_id": 1},
                },
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        request_result = result["results"][0]
        self.assertEqual(request_result["http2"]["push_count"], 1)
        self.assertEqual(
            request_result["http2"]["pushes"],
            [{
                "id": 1,
                "uri": "/static/app.js",
                "priority": 16,
                "content": "console.log('pushed');",
                "ifile": "",
                "noserver": True,
                "nohost": False,
                "request_headers": {"host": "example.com"},
                "response_headers": {":status": "200", "content-type": "application/javascript"},
            }],
        )
        self.assertTrue(any("push" in entry for entry in request_result["decisions"]))
        self.assertEqual(
            {entry["name"]: entry["runtime_status"] for entry in result["fidelity"]["commands"]},
            {"HTTP2::push": "semantic-mock"},
        )

    def test_http2_metadata_rejects_invalid_shape_and_bounds(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "pseudo_headers"):
            self.adapter._normalise_packets(
                [
                    {
                        "protocol": "http",
                        "http2": {"pseudo_headers": {":Path": "/bad"}},
                    }
                ]
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "stream_priority"):
            self.adapter._normalise_packets(
                [
                    {
                        "protocol": "http",
                        "http2": {"stream_priority": 256},
                    }
                ]
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "version"):
            self.adapter._normalise_packets(
                [
                    {
                        "protocol": "http",
                        "http2": {"version": 1},
                    }
                ]
            )

    def test_http2_wire_frames_decode_hpack_and_drive_http_lifecycle(self) -> None:
        request_block = Encoder().encode(
            [
                (":method", "POST"),
                (":path", "/submit"),
                (":scheme", "https"),
                (":authority", "api.example.com"),
                ("x-request", "one"),
            ]
        )
        response_block = Encoder().encode(
            [(":status", "201"), ("x-response", "created")]
        )
        split_at = max(1, len(request_block) // 2)
        packets = [
            {
                "protocol": "http2",
                "direction": "client_to_server",
                "payload_hex": (
                    HTTP2_CLIENT_PREFACE
                    + _http2_frame(0x4, 0x0, 0)
                    + _http2_frame(0x1, 0x0, 1, request_block[:split_at])
                ).hex(),
            },
            {
                "protocol": "http2",
                "direction": "client_to_server",
                "payload_hex": (
                    _http2_frame(0x9, 0x4, 1, request_block[split_at:])
                    + _http2_frame(0x0, 0x1, 1, b"request-body")
                ).hex(),
            },
            {
                "protocol": "http2",
                "direction": "server_to_client",
                "payload_hex": _http2_frame(0x1, 0x4, 1, response_block).hex(),
            },
            {
                "protocol": "http2",
                "direction": "server_to_client",
                "payload_hex": _http2_frame(0x0, 0x1, 1, b"created-body").hex(),
            },
        ]
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { log local0. "request=[HTTP2::header :authority] [HTTP::payload]" }
when HTTP_RESPONSE { log local0. "response=[HTTP::status] [HTTP::payload]" }
""",
                "packets": packets,
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 1)
        transaction = result["results"][0]
        self.assertEqual(transaction["request"]["method"], "POST")
        self.assertEqual(transaction["request"]["body"], "request-body")
        self.assertEqual(transaction["request"]["headers"]["x-request"], "one")
        self.assertEqual(transaction["response"]["status"], 201)
        self.assertEqual(transaction["response"]["body"], "created-body")
        self.assertTrue(any("request=api.example.com request-body" in log for log in transaction["logs"]))
        self.assertTrue(any("response=201 created-body" in log for log in transaction["logs"]))
        self.assertEqual(result["trace"][0]["http2_frames"][0]["frame_type"], "SETTINGS")
        self.assertTrue(result["trace"][1]["http2_frames"][0]["continued"])

    def test_tcp_payload_hex_detects_split_http2_prior_knowledge(self) -> None:
        request_block = Encoder().encode(
            [
                (":method", "GET"),
                (":path", "/raw-tcp"),
                (":scheme", "https"),
                (":authority", "raw.example.com"),
            ]
        )
        response_block = Encoder().encode([(':status', '204')])
        client_bytes = (
            HTTP2_CLIENT_PREFACE
            + _http2_frame(0x4, 0x0, 0)
            + _http2_frame(0x1, 0x4, 1, request_block)
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": 'when HTTP_REQUEST { log local0. "raw=[HTTP2::header :authority]" }',
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload_hex": client_bytes[:7].hex(),
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "payload_hex": (
                            client_bytes[7:]
                            + _http2_frame(0x0, 0x1, 1, b"")
                        ).hex(),
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "payload_hex": _http2_frame(0x1, 0x5, 1, response_block).hex(),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["request"]["uri"], "/raw-tcp")
        self.assertTrue(any("raw=raw.example.com" in log for log in result["results"][0]["logs"]))
        self.assertEqual(result["trace"][0]["protocol"], "tcp")
        self.assertTrue(result["trace"][0]["buffered"])
        self.assertEqual(result["trace"][1]["protocol"], "http2")
        self.assertEqual(result["trace"][1]["http2_frames"][0]["frame_type"], "SETTINGS")
        self.assertEqual(result["trace"][2]["protocol"], "http2")

    def test_tcp_payload_hex_rejects_text_payload_ambiguity(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "payload or payload_hex"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_ACCEPTED { return }",
                    "packets": [
                        {
                            "protocol": "tcp",
                            "payload": "text",
                            "payload_hex": "74657874",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http2_stream_trailers_and_informational_responses(self) -> None:
        request_headers = Encoder().encode(
            [(':method', 'POST'), (':path', '/trailers'), (':scheme', 'https')]
        )
        request_trailers = Encoder().encode([('x-request-trailer', 'complete')])
        informational = Encoder().encode([(':status', '103'), ('link', '</style.css>')])
        response_headers = Encoder().encode([(':status', '200'), ('content-type', 'text/plain')])
        response_trailers = Encoder().encode([('x-response-trailer', 'complete')])
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { log local0. trailers=[HTTP::path] }",
                "packets": [
                    {
                        "protocol": "http2",
                        "direction": "client_to_server",
                        "payload_hex": (
                            HTTP2_CLIENT_PREFACE
                            + _http2_frame(0x4, 0x0, 0)
                            + _http2_frame(0x1, 0x4, 1, request_headers)
                            + _http2_frame(0x0, 0x0, 1, b"request")
                            + _http2_frame(0x1, 0x5, 1, request_trailers)
                        ).hex(),
                    },
                    {
                        "protocol": "http2",
                        "direction": "server_to_client",
                        "payload_hex": (
                            _http2_frame(0x4, 0x0, 0)
                            + _http2_frame(0x1, 0x4, 1, informational)
                            + _http2_frame(0x1, 0x4, 1, response_headers)
                            + _http2_frame(0x0, 0x0, 1, b"response")
                            + _http2_frame(0x1, 0x5, 1, response_trailers)
                        ).hex(),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        transaction = result["results"][0]
        self.assertEqual(transaction["request"]["trailers"]["x-request-trailer"], "complete")
        self.assertEqual(transaction["response"]["trailers"]["x-response-trailer"], "complete")
        self.assertEqual(transaction["response"]["informational"][0]["status"], 103)
        self.assertTrue(any("trailers=/trailers" in log for log in transaction["logs"]))

    def test_http2_control_frames_are_decoded_and_bounded(self) -> None:
        settings = (5).to_bytes(2, "big") + (16384).to_bytes(4, "big")
        decoder = Http2ConnectionDecoder()
        events = decoder.feed(
            HTTP2_CLIENT_PREFACE
            + _http2_frame(0x4, 0x0, 0, settings)
            + _http2_frame(0x6, 0x1, 0, b"12345678")
            + _http2_frame(0x8, 0x0, 1, (7).to_bytes(4, "big"))
            + _http2_frame(0x7, 0x0, 0, (1).to_bytes(4, "big") + (0).to_bytes(4, "big") + b"debug"),
            "client_to_server",
        )
        self.assertEqual(events[0]["settings"]["5"], 16384)
        self.assertTrue(events[1]["ack"])
        self.assertEqual(events[2]["increment"], 7)
        self.assertEqual(events[3]["last_stream_id"], 1)
        with self.assertRaisesRegex(ValueError, "RST_STREAM"):
            decoder.feed(
                _http2_frame(0x3, 0x0, 1, b"\x00\x00\x00"),
                "client_to_server",
            )

        decoder = Http2ConnectionDecoder()
        decoder.feed(
            _http2_frame(0x4, 0x0, 0, (5).to_bytes(2, "big") + (16384).to_bytes(4, "big")),
            "client_to_server",
        )
        with self.assertRaisesRegex(ValueError, "frame exceeds"):
            decoder.feed(
                _http2_frame(0x0, 0x0, 1, b"x" * 16385),
                "server_to_client",
            )

    def test_http2_interleaves_multiple_streams_without_crossing_state(self) -> None:
        client_encoder = Encoder()
        server_encoder = Encoder()
        request_one = client_encoder.encode(
            [(':method', 'GET'), (':path', '/one'), (':scheme', 'https')]
        )
        request_two = client_encoder.encode(
            [(':method', 'GET'), (':path', '/two'), (':scheme', 'https')]
        )
        response_one = server_encoder.encode([(':status', '200')])
        response_two = server_encoder.encode([(':status', '201')])
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { log local0. [HTTP::path] }",
                "packets": [
                    {
                        "protocol": "http2",
                        "direction": "client_to_server",
                        "payload_hex": (
                            HTTP2_CLIENT_PREFACE
                            + _http2_frame(0x4, 0x0, 0)
                            + _http2_frame(0x1, 0x5, 1, request_one)
                            + _http2_frame(0x1, 0x5, 3, request_two)
                        ).hex(),
                    },
                    {
                        "protocol": "http2",
                        "direction": "server_to_client",
                        "payload_hex": (
                            _http2_frame(0x1, 0x5, 3, response_two)
                            + _http2_frame(0x1, 0x5, 1, response_one)
                        ).hex(),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            [(item["request"]["uri"], item["response"]["status"]) for item in result["results"]],
            [('/two', 201), ('/one', 200)],
        )
        self.assertTrue(any("/two" in log for log in result["results"][0]["logs"]))
        self.assertTrue(any("/one" in log for log in result["results"][1]["logs"]))

    def test_http2_wire_frames_reject_oversized_frame_headers(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "frame exceeds"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { return }",
                    "packets": [
                        {
                            "protocol": "http2",
                            "direction": "client_to_server",
                            "payload_hex": "100001000000000000",
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_http2_wire_decoder_enforces_frame_invariants(self) -> None:
        request_block = Encoder().encode(
            [(":method", "GET"), (":path", "/"), (":scheme", "https")]
        )
        priority_payload = (0).to_bytes(4, "big") + bytes([42]) + request_block
        decoder = Http2ConnectionDecoder()
        events = decoder.feed(
            HTTP2_CLIENT_PREFACE + _http2_frame(0x1, 0x24, 1, priority_payload),
            "client_to_server",
        )
        self.assertEqual(events[0]["priority"], 42)

        decoder = Http2ConnectionDecoder()
        duplicate_headers = Encoder().encode([("x-duplicate", "one"), ("x-duplicate", "two")])
        events = decoder.feed(
            HTTP2_CLIENT_PREFACE + _http2_frame(0x1, 0x5, 1, duplicate_headers),
            "client_to_server",
        )
        self.assertEqual(events[0]["headers"]["x-duplicate"], "one,two")
        self.assertEqual(len(events[0]["header_list"]), 2)

        decoder = Http2ConnectionDecoder()
        invalid_name_block = b"\x00\x08bad name\x01x"
        with self.assertRaisesRegex(ValueError, "valid token"):
            decoder.feed(
                HTTP2_CLIENT_PREFACE + _http2_frame(0x1, 0x5, 1, invalid_name_block),
                "client_to_server",
            )

        decoder = Http2ConnectionDecoder()
        with self.assertRaisesRegex(ValueError, "CONTINUATION"):
            decoder.feed(
                HTTP2_CLIENT_PREFACE
                + _http2_frame(0x1, 0x0, 1, request_block[:1])
                + _http2_frame(0x0, 0x0, 1, b"bad"),
                "client_to_server",
            )

        for frame_type, stream_id, payload, message in (
            (0x0, 0, b"data", "DATA frame requires a stream"),
            (0x1, 0, request_block, "HEADERS frame requires a stream"),
        ):
            decoder = Http2ConnectionDecoder()
            with self.assertRaisesRegex(ValueError, message):
                decoder.feed(
                    HTTP2_CLIENT_PREFACE + _http2_frame(frame_type, 0x4, stream_id, payload),
                    "client_to_server",
                )

        decoder = Http2ConnectionDecoder()
        with self.assertRaisesRegex(ValueError, "SETTINGS"):
            decoder.feed(
                HTTP2_CLIENT_PREFACE + _http2_frame(0x4, 0x1, 0, b"\x00\x01\x00\x00\x00\x00"),
                "client_to_server",
            )

        decoder = Http2ConnectionDecoder()
        with self.assertRaisesRegex(ValueError, "invalid HTTP/2 DATA flags"):
            decoder.feed(
                HTTP2_CLIENT_PREFACE + _http2_frame(0x0, 0x4, 1, b"data"),
                "client_to_server",
            )

    def test_http2_metadata_survives_structured_packet_request_flow(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { HTTP2::header replace :path /packet-path }",
                "packets": [
                    {
                        "protocol": "http",
                        "direction": "client_to_server",
                        "method": "GET",
                        "uri": "/original",
                        "host": "packet.example.com",
                        "http2": {
                            "active": True,
                            "version": 2,
                            "stream_id": 5,
                            "pseudo_headers": {
                                ":authority": "packet.example.com",
                                ":method": "GET",
                                ":path": "/original",
                                ":scheme": "https",
                            },
                        },
                    },
                    {
                        "protocol": "http",
                        "direction": "server_to_client",
                        "status": 200,
                        "response_body": "ok",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(result["results"][0]["http2"]["stream_id"], "5")
        self.assertEqual(result["results"][0]["http2"]["pseudo_headers"][":path"], "/packet-path")

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

    def test_raw_wire_rejects_incomplete_fragment_set(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "packet 0 must be an object"):
            self.adapter._normalise_packets(["not-a-packet"])

        raw = bytearray.fromhex(
            _raw_ipv4_tcp_hex("10.0.0.5", "192.0.2.10", 51000, 443, 0x02)
        )
        raw[6:8] = (0x2000).to_bytes(2, "big")  # IPv4 more-fragments flag
        with self.assertRaises(self.adapter.EmulatorInputError):
            self.adapter._normalise_packets(
                [{"protocol": "wire", "direction": "client_to_server", "raw_hex": raw.hex()}]
            )

    def test_raw_wire_reassembles_out_of_order_ipv4_tcp_fragments(self) -> None:
        request_payload = b"GET /fragmented HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        request_ip = bytes.fromhex(
            _raw_ipv4_tcp_hex(
                "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                request_payload, sequence=1001,
            )
        )
        request_transport = request_ip[20:]
        fragments = [
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "network": "ipv4",
                "raw_hex": _raw_ipv4_fragment_hex(
                    "10.0.0.5", "192.0.2.10", 0x4242, 24,
                    request_transport[24:], more_fragments=False, protocol=6,
                ),
            },
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "network": "ipv4",
                "raw_hex": _raw_ipv4_fragment_hex(
                    "10.0.0.5", "192.0.2.10", 0x4242, 0,
                    request_transport[:24], more_fragments=True, protocol=6,
                ),
            },
            {
                "protocol": "wire",
                "direction": "server_to_client",
                "network": "ipv4",
                "raw_hex": _raw_ipv4_tcp_hex(
                    "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                    response_payload, sequence=2000,
                ),
            },
        ]
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api_pool }",
                "pools": {"api_pool": ["10.0.0.10:80"]},
                "packets": fragments,
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        self.assertEqual(result["trace"][0]["protocol"], "http")
        self.assertEqual(result["trace"][0]["index"], 0)
        self.assertEqual(result["results"][0]["request"]["uri"], "/fragmented")
        self.assertEqual(result["results"][0]["response"]["body"], "ok")

    def test_raw_wire_reassembles_ipv6_udp_fragments_and_rejects_overlap(self) -> None:
        udp_payload = b"fragmented-udp!"
        udp = struct.pack("!HHHH", 53000, 5353, 8 + len(udp_payload), 0) + udp_payload
        packets = [
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "network": "ipv6",
                "raw_hex": _raw_ipv6_fragment_hex(
                    "2001:db8::5", "2001:db8::53", 0xABCDEF01, 16,
                    udp[16:], more_fragments=False, next_header=17,
                ),
            },
            {
                "protocol": "wire",
                "direction": "client_to_server",
                "network": "ipv6",
                "raw_hex": _raw_ipv6_fragment_hex(
                    "2001:db8::5", "2001:db8::53", 0xABCDEF01, 0,
                    udp[:16], more_fragments=True, next_header=17,
                ),
            },
        ]
        normalised = self.adapter._normalise_packets(packets)
        self.assertEqual(len(normalised), 1)
        self.assertEqual(normalised[0]["protocol"], "udp")
        self.assertEqual(normalised[0]["payload"], "fragmented-udp!")

        overlap = dict(packets[1])
        overlap["raw_hex"] = _raw_ipv6_fragment_hex(
            "2001:db8::5", "2001:db8::53", 0xABCDEF01, 8,
            udp[8:24], more_fragments=False, next_header=17,
        )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "overlaps"):
            self.adapter._normalise_packets([packets[1], overlap, packets[0]])

        reserved = dict(packets[1])
        reserved_raw = bytearray.fromhex(reserved["raw_hex"])
        reserved_raw[42:44] = (0x0002).to_bytes(2, "big")
        reserved["raw_hex"] = reserved_raw.hex()
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "reserved"):
            self.adapter._normalise_packets([reserved])

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

    def test_pcapng_replay_decodes_ethernet_and_interface_timestamps(self) -> None:
        request_payload = b"GET /pcapng HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        response_payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        capture = _pcapng_bytes(
            [
                (1, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 51000, 443, 0x02, sequence=1000
                ))),
                (1, 500_000, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "10.0.0.5", "192.0.2.10", 51000, 443, 0x18,
                    request_payload, sequence=1001
                ))),
                (2, 125_000, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                    "192.0.2.10", "10.0.0.5", 443, 51000, 0x18,
                    response_payload, sequence=2000
                ))),
            ]
        )
        result = self.adapter.run_pcap_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { log local0. pcapng }",
            },
            capture,
            tcl_lsp_root=self.tcl_lsp_root,
            direction="auto",
            client_addr="10.0.0.5",
            server_addr="192.0.2.10",
        )
        self.assertEqual(result["capture"]["format"], "pcapng")
        self.assertEqual(result["capture"]["record_count"], 3)
        self.assertEqual(result["capture"]["interface_count"], 1)
        self.assertEqual(result["capture"]["timestamp_resolution"], "microseconds")
        self.assertEqual(result["trace"][1]["timestamp"], 1.5)
        self.assertEqual(result["trace"][2]["timestamp"], 2.125)
        self.assertEqual(result["results"][0]["request"]["uri"], "/pcapng")
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

        pcapng = _pcapng_bytes(
            [(1, 0, _ethernet_ipv4(_raw_ipv4_tcp_hex(
                "10.0.0.5", "192.0.2.10", 51000, 443, 0x02
            )))]
        )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "block length"):
            self.adapter._pcap_packets(
                pcapng[:-1],
                direction="client_to_server",
                client_addr=None,
                server_addr=None,
            )
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "unknown interface"):
            bad_interface = bytearray(pcapng)
            # Enhanced Packet Block interface ID is the first word of its body.
            packet_offset = len(_pcapng_block(
                0x0A0D0D0A,
                struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
            )) + len(_pcapng_block(
                0x00000001,
                struct.pack("<HHI", 1, 0, 65535)
                + struct.pack("<HHB", 9, 1, 6)
                + b"\x00" * 3
                + struct.pack("<HH", 0, 0),
            ))
            bad_interface[packet_offset + 8 : packet_offset + 12] = (1).to_bytes(4, "little")
            self.adapter._pcap_packets(
                bytes(bad_interface),
                direction="client_to_server",
                client_addr=None,
                server_addr=None,
            )

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

    def test_live_http_data_plane_runs_persistent_real_client_requests(self) -> None:
        scenario = {
            "profiles": ["TCP", "HTTP"],
            "irule": """
when HTTP_REQUEST {
    HTTP::header insert X-Rule-Path [HTTP::path]
    if {[HTTP::uri] eq "/blocked"} {
        HTTP::respond 403 content denied
    }
}
when HTTP_RESPONSE {
    HTTP::header insert X-Request-Number [HTTP::request_num]
}
""",
            "live_origin": {
                "status": 200,
                "headers": {"X-Origin": "fixture"},
                "body": "origin-body",
            },
        }
        server, manager = self.adapter._data_plane_server(
            Path(self.tcl_lsp_root), "127.0.0.1", 0, scenario
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        try:
            connection.request("GET", "/one", headers={"Host": "live.example"})
            first = connection.getresponse()
            self.assertEqual(first.status, 200)
            self.assertEqual(first.read(), b"origin-body")
            self.assertEqual(first.getheader("X-Origin"), "fixture")
            self.assertEqual(first.getheader("X-Request-Number"), "1")

            connection.request("GET", "/two", headers={"Host": "live.example"})
            second = connection.getresponse()
            self.assertEqual(second.status, 200)
            self.assertEqual(second.read(), b"origin-body")
            self.assertEqual(second.getheader("X-Request-Number"), "2")

            connection.request("HEAD", "/two", headers={"Host": "live.example"})
            head = connection.getresponse()
            self.assertEqual(head.status, 200)
            self.assertEqual(head.read(), b"")
            self.assertEqual(head.getheader("Content-Length"), str(len(b"origin-body")))

            connection.request("GET", "/blocked", headers={"Host": "live.example"})
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            self.assertEqual(blocked.read(), b"denied")
        finally:
            connection.close()
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
            manager.close_all()

    def test_live_http_data_plane_validates_origin_and_request_limits(self) -> None:
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "unsupported live_origin field"
        ):
            self.adapter._data_plane_server(
                Path(self.tcl_lsp_root),
                "127.0.0.1",
                0,
                {"irule": "", "live_origin": {"unexpected": True}},
            )
        with self.assertRaisesRegex(
            self.adapter.EmulatorInputError, "live_origin.status"
        ):
            self.adapter._data_plane_server(
                Path(self.tcl_lsp_root),
                "127.0.0.1",
                0,
                {"irule": "", "live_origin": {"status": 700}},
            )
        with self.assertRaisesRegex(
            self.adapter.EmulatorResourceError, "live_origin.body exceeds"
        ):
            self.adapter._data_plane_server(
                Path(self.tcl_lsp_root),
                "127.0.0.1",
                0,
                {
                    "irule": "",
                    "live_origin": {
                        "body": "x" * (2 * 1024 * 1024 + 1),
                    },
                },
            )

    def test_http_api_exposes_runtime_registration_probe(self) -> None:
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_port}/v1/probes?namespace=AAA&limit=2"
            ) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["chunk"]["total"], 4)
            self.assertEqual(payload["chunk"]["count"], 2)
            self.assertEqual(payload["summary"]["registered_count"], 2)
            self.assertTrue(all(command["registered"] for command in payload["commands"]))
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_http_api_exposes_command_workbench(self) -> None:
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/command-probes",
                data=json.dumps(
                    {
                        "command": "HTTP::host",
                        "event": "HTTP_REQUEST",
                        "profiles": ["TCP", "HTTP"],
                        "request": {"host": "api.example.com", "uri": "/api"},
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
            self.assertEqual(payload["command"], "HTTP::host")
            self.assertEqual(payload["execution"]["value"], "api.example.com")
            self.assertEqual(payload["execution"]["event"]["fired"], True)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_http_api_runs_behavior_pack(self) -> None:
        pack = json.loads(
            (ROOT / "examples" / "behavior-packs" / "http-core-17.5.json")
            .read_text(encoding="utf-8")
        )
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/behavior-packs",
                data=json.dumps(pack).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
            self.assertEqual(payload["status"], "passed")
            self.assertEqual(payload["summary"]["passed"], 9)

            stateful = json.loads(
                (ROOT / "examples" / "behavior-packs" / "stateful-17.5.json")
                .read_text(encoding="utf-8")
            )
            stateful_request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/behavior-packs",
                data=json.dumps(stateful).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(stateful_request) as response:
                self.assertEqual(response.status, 200)
                stateful_payload = json.loads(response.read())
            self.assertEqual(stateful_payload["status"], "passed")
            self.assertEqual(stateful_payload["summary"]["passed"], 2)

            udp_pack = json.loads(
                (ROOT / "examples" / "behavior-packs" / "udp-datagram-17.5.json")
                .read_text(encoding="utf-8")
            )
            udp_request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/behavior-packs",
                data=json.dumps(udp_pack).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(udp_request) as response:
                self.assertEqual(response.status, 200)
                udp_payload = json.loads(response.read())
            self.assertEqual(udp_payload["status"], "passed")
            self.assertEqual(udp_payload["summary"]["passed"], 15)

            sip_pack = json.loads(
                (ROOT / "examples" / "behavior-packs" / "sip-17.5.json")
                .read_text(encoding="utf-8")
            )
            sip_request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/behavior-packs",
                data=json.dumps(sip_pack).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(sip_request) as response:
                self.assertEqual(response.status, 200)
                sip_payload = json.loads(response.read())
            self.assertEqual(sip_payload["status"], "passed")
            self.assertEqual(sip_payload["summary"]["passed"], 41)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_http_api_runs_differential_vectors(self) -> None:
        pack = json.loads(
            (ROOT / "examples" / "golden-vectors" / "http-17.5.json")
            .read_text(encoding="utf-8")
        )
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/differential-vectors",
                data=json.dumps(pack).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
            self.assertEqual(payload["status"], "passed")
            self.assertEqual(payload["summary"]["passed"], 3)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_http_api_imports_external_observations(self) -> None:
        observation_pack = {
            "name": "http-capture",
            "source": "bigip-vlab-17.5.4",
            "provenance": {"capture_id": "http-001"},
            "observations": [
                {
                    "id": "host",
                    "operation": "command_probe",
                    "input": {
                        "command": "HTTP::host",
                        "event": "HTTP_REQUEST",
                        "request": {"host": "api.example.com"},
                    },
                    "output": {"value": "api.example.com"},
                    "comparisons": [
                        {
                            "label": "host",
                            "actual_path": ["execution", "value"],
                            "reference_path": ["value"],
                        }
                    ],
                }
            ],
        }
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/differential-vectors/import",
                data=json.dumps(observation_pack).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["summary"]["executed"], False)
            self.assertEqual(payload["pack"]["vectors"][0]["id"], "host")
            self.assertEqual(payload["pack"]["provenance"]["capture_id"], "http-001")
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

    def test_cli_runs_golden_vector_path_form(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ADAPTER_PATH),
                "--golden-vectors",
                str(ROOT / "examples" / "golden-vectors" / "http-17.5.json"),
                "--tcl-lsp-root",
                self.tcl_lsp_root,
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["summary"]["vector_count"], 3)

    def test_cli_imports_observation_pack_path_form(self) -> None:
        observation_pack = {
            "name": "cli-observation",
            "source": "bigip-vlab-17.5.4",
            "observations": [
                {
                    "id": "host",
                    "operation": "command_probe",
                    "input": {
                        "command": "HTTP::host",
                        "event": "HTTP_REQUEST",
                        "request": {"host": "cli.example.com"},
                    },
                    "output": {"value": "cli.example.com"},
                    "comparisons": [
                        {
                            "label": "host",
                            "actual_path": ["execution", "value"],
                            "reference_path": ["value"],
                        }
                    ],
                }
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as observation_file:
            json.dump(observation_pack, observation_file)
            observation_file.flush()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER_PATH),
                    "--import-observations",
                    observation_file.name,
                    "--tcl-lsp-root",
                    self.tcl_lsp_root,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["summary"]["executed"], False)
        self.assertEqual(payload["pack"]["vectors"][0]["id"], "host")

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

    def test_http_api_accepts_lb_causal_request_inputs(self) -> None:
        server = self.adapter.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.adapter._http_handler(Path(self.tcl_lsp_root))
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/v1/simulations",
                data=json.dumps(
                    {
                        "profiles": ["TCP", "HTTP"],
                        "pools": {"api_pool": ["192.0.2.10:443"]},
                        "irule": "when HTTP_REQUEST { pool api_pool } when PERSIST_DOWN { log local0. persist } when LB_QUEUED { log local0. queued }",
                        "request": {
                            "persist_down": {
                                "pool": "api_pool",
                                "member": "192.0.2.10:443",
                            },
                            "lb_queue": {"queued": True, "depth": 1},
                        },
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request) as response:
                self.assertEqual(response.status, 200)
                payload = json.loads(response.read())
                self.assertEqual(
                    payload["results"][0]["events_fired"],
                    ["HTTP_REQUEST", "PERSIST_DOWN", "LB_SELECTED", "LB_QUEUED"],
                )
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
        self.assertIn("irule_catalog", tool_names)
        self.assertIn("irule_probe", tool_names)
        self.assertIn("irule_command_probe", tool_names)
        self.assertIn("irule_behavior_pack", tool_names)
        self.assertIn("irule_differential_vectors", tool_names)
        self.assertIn("irule_import_observations", tool_names)
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
            causal = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_simulate",
                        "arguments": {
                            "scenario": {
                                "profiles": ["TCP", "HTTP"],
                                "pools": {"api_pool": ["192.0.2.10:443"]},
                                "irule": "when HTTP_REQUEST { pool api_pool } when LB_QUEUED { log local0. queued }",
                                "request": {
                                    "lb_queue": {"queued": True, "depth": 1}
                                },
                            }
                        },
                    },
                }
            )
            self.assertEqual(
                causal["result"]["structuredContent"]["results"][0]["events_fired"],
                ["HTTP_REQUEST", "LB_SELECTED", "LB_QUEUED"],
            )
            filtered = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_capabilities",
                        "arguments": {
                            "namespace": "AUTH",
                            "runtime_status": "semantic-mock",
                            "offset": 0,
                            "limit": 1,
                        },
                    },
                }
            )
            filtered_payload = filtered["result"]["structuredContent"]
            self.assertEqual(filtered_payload["chunk"]["total"], 18)
            self.assertEqual(filtered_payload["commands"][0]["name"], "AUTH::abort")

            probed = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_probe",
                        "arguments": {"namespace": "AAA", "limit": 2},
                    },
                }
            )
            probed_payload = probed["result"]["structuredContent"]
            self.assertEqual(probed_payload["summary"]["registered_count"], 2)
            self.assertTrue(all(command["registered"] for command in probed_payload["commands"]))

            command_probe = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 11,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_command_probe",
                        "arguments": {
                            "command": "HTTP::host",
                            "event": "HTTP_REQUEST",
                            "request": {"host": "mcp.example.com"},
                        },
                    },
                }
            )
            command_probe_payload = command_probe["result"]["structuredContent"]
            self.assertEqual(
                command_probe_payload["execution"]["value"], "mcp.example.com"
            )

            behavior_pack = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 12,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_behavior_pack",
                        "arguments": {
                            "pack": json.loads(
                                (ROOT / "examples" / "behavior-packs" / "http-core-17.5.json")
                                .read_text(encoding="utf-8")
                            )
                        },
                    },
                }
            )
            behavior_payload = behavior_pack["result"]["structuredContent"]
            self.assertEqual(behavior_payload["status"], "passed")
            self.assertEqual(behavior_payload["summary"]["case_count"], 9)

            golden_vectors = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_differential_vectors",
                        "arguments": {
                            "pack": json.loads(
                                (ROOT / "examples" / "golden-vectors" / "http-17.5.json")
                                .read_text(encoding="utf-8")
                            )
                        },
                    },
                }
            )
            golden_payload = golden_vectors["result"]["structuredContent"]
            self.assertEqual(golden_payload["status"], "passed")
            self.assertEqual(golden_payload["summary"]["vector_count"], 3)

            imported_observations = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_import_observations",
                        "arguments": {
                            "pack": {
                                "name": "mcp-observation",
                                "source": "bigip-vlab-17.5.4",
                                "observations": [
                                    {
                                        "id": "host",
                                        "operation": "command_probe",
                                        "input": {
                                            "command": "HTTP::host",
                                            "event": "HTTP_REQUEST",
                                            "request": {"host": "mcp.example.com"},
                                        },
                                        "output": {"value": "mcp.example.com"},
                                        "comparisons": [
                                            {
                                                "label": "host",
                                                "actual_path": ["execution", "value"],
                                                "reference_path": ["value"],
                                            }
                                        ],
                                    }
                                ],
                            }
                        },
                    },
                }
            )
            imported_payload = imported_observations["result"]["structuredContent"]
            self.assertEqual(imported_payload["status"], "ok")
            self.assertEqual(imported_payload["summary"]["executed"], False)
            self.assertEqual(imported_payload["pack"]["vectors"][0]["id"], "host")

            udp_behavior_pack = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 13,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_behavior_pack",
                        "arguments": {
                            "pack": json.loads(
                                (ROOT / "examples" / "behavior-packs" / "udp-datagram-17.5.json")
                                .read_text(encoding="utf-8")
                            )
                        },
                    },
                }
            )
            udp_behavior_payload = udp_behavior_pack["result"]["structuredContent"]
            self.assertEqual(udp_behavior_payload["status"], "passed")
            self.assertEqual(udp_behavior_payload["summary"]["case_count"], 15)

            sip_behavior_pack = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 14,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_behavior_pack",
                        "arguments": {
                            "pack": json.loads(
                                (ROOT / "examples" / "behavior-packs" / "sip-17.5.json")
                                .read_text(encoding="utf-8")
                            )
                        },
                    },
                }
            )
            sip_behavior_payload = sip_behavior_pack["result"]["structuredContent"]
            self.assertEqual(sip_behavior_payload["status"], "passed")
            self.assertEqual(sip_behavior_payload["summary"]["case_count"], 41)

            catalog_response = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "irule_catalog",
                        "arguments": {"chunk_size": 1000},
                    },
                }
            )
            catalog_payload = catalog_response["result"]["structuredContent"]
            self.assertEqual(catalog_payload["chunking"]["chunk_count"], 2)
            self.assertEqual(
                sum(chunk["count"] for chunk in catalog_payload["chunks"]),
                catalog_payload["summary"]["command_count"],
            )

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

    def test_persistent_session_keeps_interleaved_flow_contexts_across_calls(self) -> None:
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        session_id = manager.create(
            {
                "profiles": ["TCP", "HTTP"],
                "pools": {
                    "a_pool": ["10.0.0.10:80"],
                    "b_pool": ["10.0.0.11:80"],
                },
                "irule": (
                    'when HTTP_REQUEST { if {[HTTP::host] eq "a.example"} '
                    '{ pool a_pool } else { pool b_pool } }'
                ),
            }
        )
        try:
            first = manager.execute(
                session_id,
                lambda session: session.run_packet_trace(
                    [
                        {
                            "protocol": "http",
                            "flow_id": "flow-a",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.1", "port": 50001},
                            "destination": {"address": "192.0.2.10", "port": 80},
                            "host": "a.example",
                            "uri": "/a",
                        },
                        {
                            "protocol": "http",
                            "flow_id": "flow-b",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.2", "port": 50002},
                            "destination": {"address": "192.0.2.10", "port": 80},
                            "host": "b.example",
                            "uri": "/b",
                        },
                    ]
                ),
            )
            second = manager.execute(
                session_id,
                lambda session: session.run_packet_trace(
                    [
                        {
                            "protocol": "http",
                            "flow_id": "flow-a",
                            "direction": "server_to_client",
                            "source": {"address": "192.0.2.10", "port": 80},
                            "destination": {"address": "10.0.0.1", "port": 50001},
                            "status": 200,
                            "response_body": "a-response",
                        },
                        {
                            "protocol": "http",
                            "flow_id": "flow-b",
                            "direction": "server_to_client",
                            "source": {"address": "192.0.2.10", "port": 80},
                            "destination": {"address": "10.0.0.2", "port": 50002},
                            "status": 200,
                            "response_body": "b-response",
                        },
                    ]
                ),
            )
        finally:
            manager.close(session_id)

        self.assertEqual(first["flow_mode"], "isolated")
        self.assertEqual(first["results"], [])
        self.assertEqual([item["pool"] for item in second["results"]], ["a_pool", "b_pool"])
        self.assertEqual(
            [item["response"]["body"] for item in second["results"]],
            ["a-response", "b-response"],
        )

    def test_persistent_session_routes_events_by_flow_id(self) -> None:
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        session_id = manager.create(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when CLIENT_ACCEPTED { log local0. accepted }",
            }
        )
        packets = [
            {
                "protocol": "http",
                "flow_id": "flow-a",
                "direction": "client_to_server",
                "source": {"address": "10.0.0.1", "port": 50001},
                "destination": {"address": "192.0.2.10", "port": 80},
                "host": "a.example",
                "uri": "/a",
            },
            {
                "protocol": "http",
                "flow_id": "flow-b",
                "direction": "client_to_server",
                "source": {"address": "10.0.0.2", "port": 50002},
                "destination": {"address": "192.0.2.10", "port": 80},
                "host": "b.example",
                "uri": "/b",
            },
        ]
        try:
            manager.execute(session_id, lambda session: session.run_packet_trace(packets))
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "session event requires flow_id",
            ):
                manager.execute(
                    session_id,
                    lambda session: session.fire_event("CLIENT_ACCEPTED", {}),
                )
            routed = manager.execute(
                session_id,
                lambda session: session.fire_event(
                    "CLIENT_ACCEPTED", {}, "flow-a"
                ),
            )
        finally:
            manager.close(session_id)

        self.assertTrue(routed["fired"])

    def test_persistent_session_rejects_unscoped_events_with_base_and_child(self) -> None:
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        session_id = manager.create(
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { log local0. accepted }",
            }
        )
        try:
            manager.execute(
                session_id,
                lambda session: session.run_packet_trace(
                    [
                        {
                            "protocol": "tcp",
                            "flow_id": "base-flow",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.1", "port": 50001},
                            "destination": {"address": "192.0.2.10", "port": 443},
                        }
                    ]
                ),
            )
            manager.execute(
                session_id,
                lambda session: session.fire_event(
                    "CLIENT_ACCEPTED", {}, "child-flow"
                ),
            )
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "session event requires flow_id",
            ):
                manager.execute(
                    session_id,
                    lambda session: session.fire_event("CLIENT_ACCEPTED", {}),
                )
        finally:
            manager.close(session_id)

    def test_persistent_request_and_event_share_explicit_flow_context(self) -> None:
        manager = self.adapter.SessionManager(Path(self.tcl_lsp_root), idle_timeout=60)
        session_id = manager.create(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": (
                    'when HTTP_REQUEST { set ::flow_marker [HTTP::host] } '
                    'when CLIENT_DATA { log local0. "marker=$::flow_marker" }'
                ),
            }
        )
        try:
            manager.execute(
                session_id,
                lambda session: session.run_request(
                    {"host": "a.example", "uri": "/a"}, "flow-a"
                ),
            )
            manager.execute(
                session_id,
                lambda session: session.run_request(
                    {"host": "b.example", "uri": "/b"}, "flow-b"
                ),
            )
            with self.assertRaisesRegex(
                self.adapter.EmulatorInputError,
                "session request requires flow_id",
            ):
                manager.execute(
                    session_id,
                    lambda session: session.run_request({"uri": "/unscoped"}),
                )
            event = manager.execute(
                session_id,
                lambda session: session.fire_event("CLIENT_DATA", {}, "flow-a"),
            )
            flow_metadata = manager.metadata(session_id, "flow-a")
        finally:
            manager.close(session_id)

        self.assertTrue(event["fired"])
        self.assertTrue(any("marker=a.example" in entry for entry in event["logs"]))
        self.assertEqual(flow_metadata["request_count"], 1)

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
            with urllib.request.urlopen(
                f"http://127.0.0.1:{server.server_port}/"
            ) as workbench_response:
                workbench = workbench_response.read().decode("utf-8")
                self.assertEqual(workbench_response.status, 200)
                self.assertIn("TMOS 17.5 iRule workbench", workbench)
                self.assertIn("/v1/sessions", workbench)

            status, conformance = request_json("/v1/conformance")
            self.assertEqual(status, 200)
            self.assertGreaterEqual(conformance["commands"]["catalog_count"], 1400)
            self.assertGreater(conformance["events"]["packet_adapter_count"], 0)

            status, catalog = request_json("/v1/catalog?chunk_size=1000")
            self.assertEqual(status, 200)
            self.assertEqual(catalog["chunking"], {"chunk_size": 1000, "chunk_count": 2})
            self.assertEqual(
                sum(chunk["count"] for chunk in catalog["chunks"]),
                catalog["summary"]["command_count"],
            )
            self.assertEqual(
                [chunk["offset"] for chunk in catalog["chunks"]], [0, 1000]
            )

            status, created = request_json("/v1/sessions", "POST", config)
            session_id = created["session_id"]
            self.assertEqual(status, 201)
            self.assertEqual(created["request_count"], 0)

            status, first = request_json(
                f"/v1/sessions/{session_id}/requests",
                "POST",
                {
                    "flow_id": "http-flow",
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

    def test_mr_structured_message_routes_and_exposes_message_state(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MR"],
                "irule": """
when MR_INGRESS {
    log local0. "proto=[MESSAGE::proto] type=[MESSAGE::type] kind=[MESSAGE::field value kind]"
    MR::peer peer-a
    MR::message route config tcp_tc host 192.0.2.10:5060
}
""",
                "packets": [
                    {
                        "protocol": "mr",
                        "proto": "generic",
                        "type": "request",
                        "fields": {"kind": "ping", "src": "client-a"},
                        "payload": "hello",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertEqual(event["event"], "MR_INGRESS")
        self.assertTrue(event["fired"])
        self.assertTrue(any("proto=GENERIC type=request kind=ping" in log for log in event["logs"]))
        self.assertEqual(event["state"]["message"]["fields"], '"kind" "ping" "src" "client-a"')
        self.assertEqual(event["state"]["mr"]["peer"], "peer-a")
        self.assertEqual(event["state"]["mr"]["route_status"], "routed")
        self.assertEqual(result["trace"][0]["proto"], "generic")

    def test_mr_collect_fires_data_event_and_preserves_payload_bytes(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MR"],
                "irule": "when MR_INGRESS { MR::collect 3 }\nwhen MR_DATA { log local0. \"data=[MR::payload] len=[MR::payload length]\" }",
                "packets": [
                    {
                        "protocol": "mr",
                        "payload_hex": "0001020304",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["trace"][0]["events"]
        self.assertEqual([event["event"] for event in events[-2:]], ["MR_INGRESS", "MR_DATA"])
        self.assertEqual(events[-1]["state"]["mr"]["payload_length"], "5")
        self.assertTrue(any("len=5" in log for log in events[-1]["logs"]))

    def test_mr_egress_and_route_failure_events_are_stateful(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MR"],
                "irule": "when MR_EGRESS { log local0. egress }\nwhen MR_FAILED { MR::retry; log local0. \"retry=[MR::message retry_count]\" }",
                "packets": [
                    {
                        "protocol": "mr",
                        "direction": "server_to_client",
                        "route_status": "failed",
                        "payload": "response",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["trace"][0]["events"]
        self.assertEqual([event["event"] for event in events[-2:]], ["MR_EGRESS", "MR_FAILED"])
        self.assertEqual(events[-1]["state"]["mr"]["retry_count"], "1")
        self.assertTrue(any("retry=1" in log for log in events[-1]["logs"]))

    def test_mr_payload_mutation_uses_utf8_byte_length_and_validates_return_status(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["MR"],
                "irule": "when MR_INGRESS { GENERICMESSAGE::message data \"π\"; log local0. \"len=[GENERICMESSAGE::message length]\" }",
                "packets": [{"protocol": "mr", "payload": "old"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertEqual(event["state"]["mr"]["payload_length"], "2")
        self.assertTrue(any("len=2" in log for log in event["logs"]))

        returned = self.adapter.run_scenario(
            {
                "profiles": ["MR"],
                "irule": "when MR_INGRESS { MR::return no_route_found }",
                "packets": [{"protocol": "mr", "payload": "x"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            returned["trace"][0]["events"][-1]["state"]["mr"]["route_status"],
            "no_route_found",
        )

    def test_gtp_v2_signalling_exposes_headers_and_information_elements(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": """
when GTP_SIGNALLING_INGRESS {
    log local0. "version=[GTP::header version] type=[GTP::header type] teid=[GTP::header teid] cause=[GTP::ie get value cause:0] count=[GTP::ie count -type cause] list=[GTP::ie get list -type cause]"
    GTP::header sequence set 12
}
""",
                "packets": [
                    {
                        "protocol": "gtp",
                        "version": 2,
                        "type": 32,
                        "teid": 0x12345678,
                        "sequence": 7,
                        "ies": [{"type": 2, "instance": 0, "data_hex": "01"}],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertEqual(event["event"], "GTP_SIGNALLING_INGRESS")
        self.assertTrue(event["fired"])
        self.assertTrue(
            any(
                "version=2 type=32 teid=305419896 cause=01 count=1 list=2:0" in entry
                for entry in event["logs"]
            )
        )
        self.assertEqual(event["state"]["gtp"]["sequence"], "12")
        self.assertEqual(
            event["state"]["gtp"]["message_hex"],
            "4820000d1234567800000c000200010001",
        )

    def test_gtp_v1_signalling_preserves_optional_header_fields(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": "when GTP_SIGNALLING_INGRESS { log local0. \"version=[GTP::header version] teid=[GTP::header teid] sequence=[GTP::header sequence] npdu=[GTP::header npdu] cause=[GTP::ie get value cause:0]\" }",
                "packets": [
                    {
                        "protocol": "gtp",
                        "version": 1,
                        "type": 16,
                        "teid": 9,
                        "sequence": 3,
                        "npdu": 4,
                        "ies": [{"type": 2, "data_hex": "01"}],
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertTrue(
            any(
                "version=1 teid=9 sequence=3 npdu=4 cause=01" in entry
                for entry in event["logs"]
            )
        )
        self.assertEqual(event["state"]["gtp"]["version"], "1")

    def test_gtp_u_payload_mutation_discard_and_tunnel_introspection(self) -> None:
        tunneled_ip = bytes.fromhex(
            _raw_ipv4_tcp_hex(
                "192.0.2.1",
                "198.51.100.2",
                1234,
                5678,
                0x18,
            )
        )
        result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": """
when GTP_GPDU_INGRESS {
    log local0. "is=[GTP::tunnel is_ip] version=[GTP::tunnel ip_version] proto=[GTP::tunnel ip_proto] src=[GTP::tunnel tcp_src_port] dst=[GTP::tunnel tcp_dst_port]"
    GTP::payload replace 0 4 TEST
    GTP::discard
}
""",
                "packets": [
                    {
                        "protocol": "gtp",
                        "version": 2,
                        "type": 255,
                        "teid": 1,
                        "sequence": 1,
                        "payload_hex": tunneled_ip.hex(),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertTrue(
            any("is=1 version=4 proto=6 src=1234 dst=5678" in entry for entry in event["logs"])
        )
        self.assertEqual(event["state"]["gtp"]["payload_hex"][:8], "54455354")
        self.assertEqual(event["state"]["gtp"]["payload_length"], str(len(tunneled_ip)))
        self.assertTrue(result["trace"][0]["discarded"])

    def test_gtp_udp_and_gtp_prime_tcp_adapters_route_to_distinct_events(self) -> None:
        message = bytes.fromhex(
            _gtp_v2_hex(32, teid=7, sequence=3, body=b"\x02\x00\x01\x00\x01")
        )
        udp_result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": "when GTP_SIGNALLING_INGRESS { log local0. udp }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_udp_hex(
                            "192.0.2.1", "198.51.100.2", 40000, 2123, message
                        ),
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertEqual(
            udp_result["trace"][0]["events"][-1]["event"], "GTP_SIGNALLING_INGRESS"
        )

        first = message[:5]
        second = message[5:]
        tcp_result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": "when GTP_PRIME_INGRESS { log local0. prime }",
                "packets": [
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.1", "198.51.100.2", 40000, 3386, 0x18, first,
                            sequence=1000,
                        ),
                    },
                    {
                        "protocol": "wire",
                        "direction": "client_to_server",
                        "raw_hex": _raw_ipv4_tcp_hex(
                            "192.0.2.1", "198.51.100.2", 40000, 3386, 0x18, second,
                            sequence=1000 + len(first),
                        ),
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        trace = tcp_result["trace"]
        self.assertTrue(trace[0]["buffered"])
        self.assertEqual(trace[1]["events"][-1]["event"], "GTP_PRIME_INGRESS")

    def test_gtp_type_alias_must_not_disagree(self) -> None:
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "type and message_type"):
            self.adapter.run_scenario(
                {
                    "profiles": ["GTP"],
                    "irule": "when GTP_SIGNALLING_INGRESS { return }",
                    "packets": [{"protocol": "gtp", "type": 32, "message_type": 33}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_gtp_payload_infers_g_pdu_type_when_type_is_omitted(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["GTP"],
                "irule": "when GTP_GPDU_INGRESS { log local0. [GTP::header type] }",
                "packets": [
                    {
                        "protocol": "GTP",
                        "version": 2,
                        "payload_hex": "64656661756c7420626f6479",
                    }
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        event = result["trace"][0]["events"][-1]
        self.assertEqual(event["event"], "GTP_GPDU_INGRESS")
        self.assertTrue(event["fired"])
        self.assertEqual(event["state"]["gtp"]["type"], "255")

    def test_generic_udp_events_model_payload_ports_and_flow_controls(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_ACCEPTED {
    UDP::hold
    UDP::max_buf_pkts 5
    UDP::max_rate 1000
    UDP::sendbuffer 4096
    UDP::debug_queue enable
    set unused [UDP::unused_port 192.0.2.10 9999 10.0.0.5]
    log local0. "mss=[UDP::mss] unused=$unused"
}
when CLIENT_DATA {
    log local0. "p=[UDP::payload] len=[UDP::payload length] ports=[UDP::client_port]:[UDP::server_port] local=[UDP::local_port] remote=[UDP::remote_port]"
    UDP::payload replace 0 4 PONG
    UDP::release
    UDP::respond reply
}
when SERVER_DATA {
    if {[UDP::payload] contains "drop"} { UDP::drop }
}
""",
                "packets": [
                    {
                        "protocol": "udp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 9999},
                        "payload": "ping",
                    },
                    {
                        "protocol": "udp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.10", "port": 9999},
                        "destination": {"address": "10.0.0.5", "port": 51000},
                        "payload": "drop",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )

        accepted = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLIENT_ACCEPTED"
        )
        client_data = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLIENT_DATA"
        )
        server_data = next(
            event
            for event in result["trace"][1]["events"]
            if event["event"] == "SERVER_DATA"
        )
        self.assertEqual(accepted["state"]["udp"]["held"], "1")
        self.assertEqual(accepted["state"]["udp"]["max_buf_pkts"], "5")
        self.assertTrue(any("mss=1460 unused=40000" in log for log in accepted["logs"]))
        self.assertEqual(client_data["state"]["udp"]["payload"], "PONG")
        self.assertEqual(client_data["state"]["udp"]["payload_length"], "4")
        self.assertEqual(client_data["state"]["udp"]["released"], "1")
        self.assertEqual(client_data["state"]["udp"]["responded"], "1")
        self.assertEqual(result["trace"][0]["payload_after"], "PONG")
        self.assertEqual(result["trace"][0]["response"], "reply")
        self.assertTrue(result["trace"][1]["dropped"])
        self.assertEqual(server_data["state"]["udp"]["dropped"], "1")
        self.assertEqual(result["emitted"][0]["payload"], "reply")
        self.assertEqual(
            {
                entry["name"]: entry["runtime_status"]
                for entry in result["fidelity"]["commands"]
                if entry["name"].startswith("UDP::")
            },
            {
                "UDP::client_port": "semantic-mock",
                "UDP::debug_queue": "semantic-mock",
                "UDP::drop": "semantic-mock",
                "UDP::hold": "semantic-mock",
                "UDP::local_port": "semantic-mock",
                "UDP::max_buf_pkts": "semantic-mock",
                "UDP::max_rate": "semantic-mock",
                "UDP::mss": "semantic-mock",
                "UDP::payload": "semantic-mock",
                "UDP::release": "semantic-mock",
                "UDP::remote_port": "semantic-mock",
                "UDP::respond": "semantic-mock",
                "UDP::sendbuffer": "semantic-mock",
                "UDP::server_port": "semantic-mock",
                "UDP::unused_port": "semantic-mock",
            },
        )

    def test_generic_udp_drop_on_accept_stops_datagram_dispatch(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["UDP"],
                "irule": """
when CLIENT_ACCEPTED { UDP::drop }
when CLIENT_DATA { log local0. "must-not-fire" }
""",
                "packets": [{"protocol": "udp", "payload": "blocked"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        events = result["trace"][0]["events"]
        self.assertNotIn("CLIENT_DATA", [event["event"] for event in events])
        self.assertTrue(result["trace"][0]["dropped"])
        self.assertEqual(result["trace"][0]["drop_reason"], "udp")
        self.assertFalse(any("must-not-fire" in log for event in events for log in event["logs"]))

    def test_tcp_transport_controls_persist_into_later_data_events(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    TCP::nagle disable
    TCP::keepalive 60
    TCP::idletime 120
    TCP::sendbuf 100000
    TCP::recvwnd 200000
    TCP::setmss 1200
    TCP::pacing enable
    TCP::push_flag auto
    TCP::proxybuffer 10000 2000
    TCP::congestion cubic
    TCP::collect 1
}
when CLIENT_DATA {
    log local0. "mss=[TCP::mss] nagle=[TCP::naglemode]/[TCP::naglestate] keepalive=[TCP::keepalive] sendbuf=[TCP::sendbuf] recvwnd=[TCP::recvwnd] pacing=[TCP::pacing] push=[TCP::push_flag] high=[TCP::proxybufferhigh] low=[TCP::proxybufferlow] congestion=[TCP::congestion]"
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 9999},
                        "flags": ["SYN"],
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 9999},
                        "flags": ["ACK"],
                        "payload": "x",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        accepted = result["trace"][0]["events"][-1]
        data = result["trace"][1]["events"][-1]
        self.assertEqual(accepted["state"]["connection"]["mss"], "1200")
        self.assertEqual(accepted["state"]["tcp"]["idletime"], "120")
        self.assertEqual(accepted["state"]["tcp"]["proxybuffer_high"], "10000")
        self.assertEqual(accepted["state"]["tcp"]["proxybuffer_low"], "2000")
        self.assertEqual(data["state"]["connection"]["mss"], "1200")
        self.assertEqual(data["state"]["tcp"]["sendbuf"], "100000")
        self.assertEqual(data["state"]["tcp"]["recvwnd"], "200000")
        self.assertTrue(any("mss=1200" in log and "nagle=disable/disabled" in log for log in data["logs"]))
        self.assertTrue(any("pacing=1" in log and "push=auto" in log for log in data["logs"]))
        self.assertTrue(any("high=10000" in log and "low=2000" in log for log in data["logs"]))
        self.assertTrue(any("congestion=cubic" in log for log in data["logs"]))
        expected = {
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
            "TCP::recvwnd",
            "TCP::sendbuf",
            "TCP::setmss",
        }
        tcp_statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("TCP::")
        }
        self.assertTrue(expected.issubset(tcp_statuses))
        self.assertTrue(all(tcp_statuses[name] == "semantic-mock" for name in expected))

    def test_tcp_17_5_tuning_commands_are_semantic_and_inspectable(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    TCP::abc disable
    TCP::analytics key api
    TCP::autowin disable
    TCP::delayed_ack disable
    TCP::dsack disable
    TCP::earlyrxmit disable
    TCP::ecn disable
    TCP::enhanced_loss_recovery disable
    TCP::limxmit disable
    TCP::lossfilter 150 10
    set ::burst [TCP::lossfilterburst]
    set ::rate [TCP::lossfilterrate]
    set ::rcv_scale [TCP::rcv_scale]
    set ::snd_scale [TCP::snd_scale]
    set ::ssthresh [TCP::snd_ssthresh]
    set ::rexmt [TCP::rexmt_thresh 100]
    TCP::rt_metrics_timeout 300
    set ::port [TCP::unused_port 192.0.2.20 80 10.0.0.5 55000]
    set ::port2 [TCP::unused_port 192.0.2.20 80 10.0.0.5]
    TCP::collect 1
}
when CLIENT_DATA {
    log local0. "abc=[set ::state::tcp::abc] analytics=[set ::state::tcp::analytics]/[set ::state::tcp::analytics_key] autowin=[set ::state::tcp::autowin] earlyrxmit=[set ::state::tcp::earlyrxmit] ecn=[set ::state::tcp::ecn] loss=[set ::burst]/[set ::rate] rcv=[set ::rcv_scale] snd=[set ::snd_scale] ssthresh=[set ::ssthresh] rexmt=[set ::rexmt] port=[set ::port]/[set ::port2]"
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 9999},
                        "flags": ["SYN"],
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "10.0.0.5", "port": 51000},
                        "destination": {"address": "192.0.2.10", "port": 9999},
                        "flags": ["ACK"],
                        "payload": "x",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        accepted = result["trace"][0]["events"][-1]
        data = result["trace"][1]["events"][-1]
        tcp = accepted["state"]["tcp"]
        self.assertEqual(tcp["abc"], "disable")
        self.assertEqual(tcp["analytics"], "enable")
        self.assertEqual(tcp["analytics_key"], "api")
        self.assertEqual(tcp["autowin"], "disable")
        self.assertEqual(tcp["delayed_ack"], "disable")
        self.assertEqual(tcp["dsack"], "disable")
        self.assertEqual(tcp["earlyrxmit"], "disable")
        self.assertEqual(tcp["ecn"], "disable")
        self.assertEqual(tcp["enhanced_loss_recovery"], "disable")
        self.assertEqual(tcp["limxmit"], "disable")
        self.assertEqual(tcp["lossfilter_rate"], "150")
        self.assertEqual(tcp["lossfilter_burst"], "10")
        self.assertEqual(tcp["rt_metrics_timeout"], "300")
        self.assertTrue(any("analytics=enable/api" in log and "port=55000/49152" in log for log in data["logs"]))
        expected = {
            "TCP::abc", "TCP::analytics", "TCP::autowin", "TCP::delayed_ack",
            "TCP::dsack", "TCP::earlyrxmit", "TCP::ecn",
            "TCP::enhanced_loss_recovery", "TCP::limxmit", "TCP::lossfilter",
            "TCP::lossfilterburst", "TCP::lossfilterrate", "TCP::rcv_scale",
            "TCP::rexmt_thresh", "TCP::rt_metrics_timeout", "TCP::snd_scale",
            "TCP::snd_ssthresh", "TCP::unused_port",
        }
        statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"] in expected
        }
        self.assertEqual(set(statuses), expected)
        self.assertTrue(all(value == "semantic-mock" for value in statuses.values()))
        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "integer from 3 to 255"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP"],
                    "irule": "when CLIENT_ACCEPTED { TCP::rexmt_thresh 2 }",
                    "packets": [
                        {
                            "protocol": "tcp",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.5", "port": 51000},
                            "destination": {"address": "192.0.2.10", "port": 9999},
                            "flags": ["SYN"],
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_flow_handles_track_connection_state_and_related_flows(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FLOW"],
                "pools": {"app": ["192.0.2.20:80"]},
                "irule": """
when CLIENT_ACCEPTED {
    set ::client_flow [FLOW::this]
    set ::server_flow [FLOW::peer $::client_flow]
    FLOW::priority clientside 2
    FLOW::idle_timeout $::client_flow 42
    log local0. "client=$::client_flow peer=$::server_flow"
}
when SERVER_CONNECTED {
    FLOW::priority serverside 4
    log local0. "server=[FLOW::this] priority=[FLOW::priority]"
}
when HTTP_REQUEST { pool app }
""",
                "requests": [{"uri": "/health"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request = result["results"][0]
        flow = request["semantic"]["flow"]
        self.assertEqual(flow["flow_count"], 2)
        self.assertEqual(flow["current_side"], "server")
        self.assertEqual(flow["current_handle"], "flow-server-0")
        by_handle = {entry["handle"]: entry for entry in flow["flows"]}
        self.assertEqual(by_handle["flow-client-0"]["peer"], "flow-server-0")
        self.assertEqual(by_handle["flow-client-0"]["timeout"], 42)
        self.assertEqual(by_handle["flow-client-0"]["priority"], 2)
        self.assertEqual(by_handle["flow-server-0"]["priority"], 4)
        self.assertTrue(any("client=flow-client-0 peer=flow-server-0" in log for log in request["logs"]))
        self.assertTrue(any("server=flow-server-0 priority=4" in log for log in request["logs"]))
        statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("FLOW::")
        }
        self.assertEqual(set(statuses), {
            "FLOW::idle_timeout", "FLOW::peer", "FLOW::priority", "FLOW::this",
        })
        self.assertTrue(all(value == "semantic-mock" for value in statuses.values()))

    def test_flow_related_creation_refresh_and_validation(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP", "FLOW"],
                "pools": {"app": ["192.0.2.20:80"]},
                "irule": """
when SERVER_CONNECTED {
    set ::related [FLOW::create_related -hairpin {
        proto 17
        clientflow -local-ip 10.0.0.10 -local-port 5000 10.0.0.11 6000 vlan-a
        serverflow 10.0.0.12 7000 vlan-b
        inherit-vs /Common/app
    }]
    set ::related_peer [FLOW::peer $::related]
    FLOW::idle_timeout $::related 9
    FLOW::priority $::related 6
    set ::before [FLOW::idle_duration $::related]
    FLOW::refresh $::related
    set ::after [FLOW::idle_duration $::related]
    log local0. "related=$::related peer=$::related_peer before=$::before after=$::after"
}
when HTTP_REQUEST { pool app }
""",
                "requests": [{"uri": "/health"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        request = result["results"][0]
        flow = request["semantic"]["flow"]
        self.assertEqual(flow["flow_count"], 4)
        related = next(entry for entry in flow["flows"] if entry["handle"] == "flow-related-1-client")
        related_peer = next(entry for entry in flow["flows"] if entry["handle"] == "flow-related-1-server")
        self.assertEqual(related["peer"], "flow-related-1-server")
        self.assertEqual(related["protocol"], 17)
        self.assertEqual(related["local_addr"], "10.0.0.10")
        self.assertEqual(related["local_port"], "5000")
        self.assertEqual(related["remote_addr"], "10.0.0.11")
        self.assertTrue(related["hairpin"])
        self.assertEqual(related["timeout"], 9)
        self.assertEqual(related["priority"], 6)
        self.assertEqual(related_peer["remote_port"], "7000")
        self.assertTrue(any("before=0 after=0" in log for log in request["logs"]))

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "integer from 0 to 7"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "FLOW"],
                    "irule": "when CLIENT_ACCEPTED { FLOW::priority 8 }",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires the FLOW profile"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when CLIENT_ACCEPTED { FLOW::this }",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "integer from 0 to 7"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "FLOW"],
                    "irule": "when CLIENT_ACCEPTED { FLOW::priority 8 }",
                    "packets": [
                        {
                            "protocol": "tcp",
                            "direction": "client_to_server",
                            "source": {"address": "10.0.0.5", "port": 51000},
                            "destination": {"address": "192.0.2.10", "port": 443},
                            "flags": ["SYN"],
                        }
                    ],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "requires one proto value"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "FLOW"],
                    "pools": {"app": ["192.0.2.20:80"]},
                    "irule": """
when SERVER_CONNECTED {
    FLOW::create_related {proto 6 proto 17 clientflow 10.0.0.1 1000 vlan-a serverflow 10.0.0.2 2000 vlan-b}
}
when HTTP_REQUEST { pool app }
""",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "not valid in CLIENT_CLOSED"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP", "FLOW"],
                    "pools": {"app": ["192.0.2.20:80"]},
                    "irule": """
when HTTP_REQUEST { pool app }
when HTTP_RESPONSE { HTTP::close }
when CLIENT_CLOSED { FLOW::priority 8 }
""",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_flowtable_counts_and_limits_use_deterministic_scopes(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "flowtable": {
                    "count": {
                        "global": 42,
                        "virtual": {"/Common/app": 7, "default": 8},
                        "route_domain": {"0": 9, "default": 10},
                    },
                    "limit": {
                        "virtual": {"/Common/app": 100, "default": 101},
                        "route_domain": {"0": 1000, "default": 1001},
                    },
                },
                "irule": """
when HTTP_REQUEST {
    set global [FLOWTABLE::count]
    set virtual [FLOWTABLE::count virtual /Common/app]
    set current_virtual [FLOWTABLE::count virtual]
    set route [FLOWTABLE::count route_domain 0]
    set current_route [FLOWTABLE::count route_domain]
    set virtual_limit [FLOWTABLE::limit virtual /Common/app]
    set current_virtual_limit [FLOWTABLE::limit virtual]
    set route_limit [FLOWTABLE::limit route_domain 0]
    set current_route_limit [FLOWTABLE::limit route_domain]
    log local0. "global=$global virtual=$virtual current_virtual=$current_virtual route=$route current_route=$current_route virtual_limit=$virtual_limit current_virtual_limit=$current_virtual_limit route_limit=$route_limit current_route_limit=$current_route_limit"
}
""",
                "requests": [{"uri": "/health"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        logs = result["results"][0]["logs"]
        self.assertTrue(any(
            "global=42 virtual=7 current_virtual=8 route=9 current_route=10 "
            "virtual_limit=100 current_virtual_limit=101 route_limit=1000 "
            "current_route_limit=1001" in entry
            for entry in logs
        ))
        statuses = {
            entry["name"]: entry["runtime_status"]
            for entry in result["fidelity"]["commands"]
            if entry["name"].startswith("FLOWTABLE::")
        }
        self.assertEqual(set(statuses), {"FLOWTABLE::count", "FLOWTABLE::limit"})
        self.assertTrue(all(value == "semantic-mock" for value in statuses.values()))

    def test_flowtable_missing_values_and_invalid_configuration_are_bounded(self) -> None:
        missing = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "flowtable": {"count": {"global": 1}},
                "irule": "when HTTP_REQUEST { log local0. \"count=[FLOWTABLE::count virtual /Common/missing] limit=[FLOWTABLE::limit route_domain 99]\" }",
                "requests": [{"uri": "/"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        self.assertTrue(any("count=0 limit=0" in entry for entry in missing["results"][0]["logs"]))

        invalid_scenarios = (
            ({"count": {"global": True}}, "flowtable.count.global"),
            ({"count": {"virtual": {"/Common/app": -1}}}, "flowtable.virtual./Common/app"),
            ({"limit": {"virtual": []}}, "flowtable.virtual must be an object"),
            ({"count": {"unexpected": {}}}, "flowtable.count unsupported field"),
            ({1: {}}, "flowtable unsupported field"),
        )
        for flowtable, message in invalid_scenarios:
            with self.subTest(flowtable=flowtable):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "flowtable": flowtable,
                            "irule": "when HTTP_REQUEST { return }",
                            "requests": [{"uri": "/"}],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

        with self.assertRaisesRegex(self.adapter.EmulatorInputError, "scope must be virtual or route_domain"):
            self.adapter.run_scenario(
                {
                    "profiles": ["TCP", "HTTP"],
                    "irule": "when HTTP_REQUEST { FLOWTABLE::count pool /Common/app }",
                    "requests": [{"uri": "/"}],
                },
                tcl_lsp_root=self.tcl_lsp_root,
            )

    def test_backend_fixture_skips_down_member_and_runs_before_http_response(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": """
when HTTP_REQUEST { pool api }
when HTTP_RESPONSE {
    log local0. "status=[HTTP::status] body=[HTTP::payload] backend=[HTTP::header value X-Backend]"
}
""",
                "pools": {"api": ["10.0.0.1:80", "10.0.0.2:80"]},
                "backends": {
                    "10.0.0.1:80": {"state": "down"},
                    "10.0.0.2:80": {
                        "state": "up",
                        "responses": [{
                            "match": {"path": "/health"},
                            "status": 200,
                            "headers": {"X-Backend": "healthy-two"},
                            "body": "healthy",
                        }],
                    },
                },
                "requests": [{"uri": "/health"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        result_item = result["results"][0]
        self.assertEqual(result_item["node"], "10.0.0.2")
        self.assertEqual(result_item["response"]["status"], 200)
        self.assertEqual(result_item["response"]["body"], "healthy")
        self.assertEqual(result_item["response"]["headers"]["x-backend"], "healthy-two")
        self.assertEqual(result_item["semantic"]["backend"], {
            "active": True,
            "member": "10.0.0.2:80",
            "state": "up",
            "matched": True,
            "match_index": 0,
            "status": 200,
        })
        self.assertTrue(any(
            "status=200 body=healthy backend=healthy-two" in entry
            for entry in result_item["logs"]
        ))

    def test_backend_fixture_matches_in_order_and_respects_explicit_response_overrides(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api }",
                "pools": {"api": ["10.0.0.3:80"]},
                "backends": {
                    "10.0.0.3:80": {
                        "responses": [
                            {"match": {"path": "/health"}, "status": 204, "body": "first"},
                            {"status": 418, "body": "default"},
                        ],
                    },
                },
                "requests": [
                    {"uri": "/health"},
                    {"uri": "/other", "response_status": 202},
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        first, second = result["results"]
        self.assertEqual(first["response"]["status"], 204)
        self.assertEqual(first["response"]["body"], "first")
        self.assertEqual(first["semantic"]["backend"]["match_index"], 0)
        self.assertEqual(second["response"]["status"], 202)
        self.assertEqual(second["response"]["body"], "default")
        self.assertEqual(second["semantic"]["backend"]["match_index"], 1)
        self.assertEqual(second["semantic"]["backend"]["status"], 202)

    def test_round_robin_pool_mode_rotates_across_keepalive_requests(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api }",
                "pools": {"api": ["10.0.0.1:80", "10.0.0.2:80"]},
                "pool_modes": {"api": "round_robin"},
                "backends": {
                    "10.0.0.1:80": {
                        "responses": [{"status": 200, "body": "one"}],
                    },
                    "10.0.0.2:80": {
                        "responses": [{"status": 200, "body": "two"}],
                    },
                },
                "requests": [{"uri": "/one"}, {"uri": "/two"}, {"uri": "/three"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        results = result["results"]
        self.assertEqual([item["node"] for item in results], ["10.0.0.1", "10.0.0.2", "10.0.0.1"])
        self.assertEqual([item["response"]["body"] for item in results], ["one", "two", "one"])
        self.assertEqual(
            [item["semantic"]["pool_selection"][0] for item in results],
            [
                {"pool": "api", "mode": "round_robin", "next_index": 1},
                {"pool": "api", "mode": "round_robin", "next_index": 0},
                {"pool": "api", "mode": "round_robin", "next_index": 1},
            ],
        )

    def test_round_robin_pool_mode_skips_down_members(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP", "HTTP"],
                "irule": "when HTTP_REQUEST { pool api }",
                "pools": {
                    "api": [
                        "10.0.0.1:80",
                        "10.0.0.2:80",
                        "10.0.0.3:80",
                    ]
                },
                "pool_modes": {"api": "round_robin"},
                "backends": {
                    "10.0.0.1:80": {"state": "down"},
                    "10.0.0.2:80": {
                        "responses": [{"status": 200, "body": "two"}],
                    },
                    "10.0.0.3:80": {
                        "responses": [{"status": 200, "body": "three"}],
                    },
                },
                "requests": [{"uri": "/one"}, {"uri": "/two"}, {"uri": "/three"}],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        results = result["results"]
        self.assertEqual(
            [item["node"] for item in results],
            ["10.0.0.2", "10.0.0.3", "10.0.0.2"],
        )
        self.assertEqual(
            [item["response"]["body"] for item in results],
            ["two", "three", "two"],
        )
        self.assertEqual(
            [item["semantic"]["pool_selection"][0]["next_index"] for item in results],
            [2, 0, 2],
        )

    def test_backend_fixture_validation_rejects_ambiguous_or_unsafe_definitions(self) -> None:
        invalid = (
            ({"10.0.0.1:80": {"state": "unknown"}}, "state must be one of"),
            ({"10.0.0.1:80": {"unexpected": True}}, "unsupported field"),
            ({"10.0.0.1:80": {"responses": [{"body": "a"}, {"body": "b"}]}}, "only one default"),
            ({"10.0.0.1:80": {"responses": [{"headers": {"X": "bad\nvalue"}}]}}, "must not contain newlines"),
            ({"10.0.0.1:80": {"responses": [{"headers": {"X": "a", "x": "b"}}]}}, "duplicate name"),
        )
        for backends, message in invalid:
            with self.subTest(backends=backends):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "irule": "when HTTP_REQUEST { return }",
                            "pools": {"api": ["10.0.0.1:80"]},
                            "backends": backends,
                            "requests": [{"uri": "/"}],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

        for pool_modes, message in (
            ({"api": "least_connections"}, "must be one of"),
            ({"api": 1}, "must be a string"),
            ({"missing": "round_robin"}, "unknown pool"),
        ):
            with self.subTest(pool_modes=pool_modes):
                with self.assertRaisesRegex(self.adapter.EmulatorInputError, message):
                    self.adapter.run_scenario(
                        {
                            "profiles": ["TCP", "HTTP"],
                            "irule": "when HTTP_REQUEST { return }",
                            "pools": {"api": ["10.0.0.1:80"]},
                            "pool_modes": pool_modes,
                            "requests": [{"uri": "/"}],
                        },
                        tcl_lsp_root=self.tcl_lsp_root,
                    )

    def test_tcp_notify_dispatches_user_events_after_current_handler(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED {
    TCP::collect
}
when CLIENT_DATA {
    log local0. before
    TCP::release
    TCP::notify request
    log local0. after
}
when USER_REQUEST {
    log local0. user-request
    TCP::notify response
}
when USER_RESPONSE {
    log local0. user-response
}
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "192.0.2.20", "port": 443},
                        "payload": "request-data",
                    },
                    {
                        "protocol": "tcp",
                        "direction": "server_to_client",
                        "source": {"address": "192.0.2.20", "port": 443},
                        "destination": {"address": "192.0.2.10", "port": 40000},
                        "payload": "response-data",
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        client_entry = result["trace"][0]
        client_data = next(
            event
            for event in client_entry["events"]
            if event["event"] == "CLIENT_DATA"
        )
        self.assertEqual(client_data["events_fired"], ["CLIENT_DATA"])
        self.assertEqual(client_data["notifications"], [])

        server_entry = result["trace"][1]
        server_connected = next(
            event
            for event in server_entry["events"]
            if event["event"] == "SERVER_CONNECTED"
        )
        self.assertEqual(
            server_connected["events_fired"],
            ["SERVER_CONNECTED", "USER_REQUEST", "USER_RESPONSE"],
        )
        self.assertEqual(
            [notification["event"] for notification in server_connected["notifications"]],
            ["USER_REQUEST", "USER_RESPONSE"],
        )
        user_request, user_response = server_connected["notifications"]
        self.assertTrue(any("after" in log for log in client_data["logs"]))
        self.assertTrue(any("user-request" in log for log in user_request["logs"]))
        self.assertTrue(any("user-response" in log for log in user_response["logs"]))

    def test_tcp_notify_queue_is_discarded_when_packet_connection_closes(self) -> None:
        result = self.adapter.run_scenario(
            {
                "profiles": ["TCP"],
                "irule": """
when CLIENT_ACCEPTED { TCP::collect }
when CLIENT_DATA { TCP::release; TCP::notify request }
when USER_REQUEST { log local0. should-not-run }
""",
                "packets": [
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "192.0.2.20", "port": 443},
                        "payload": "request-data",
                    },
                    {
                        "protocol": "tcp",
                        "direction": "client_to_server",
                        "source": {"address": "192.0.2.10", "port": 40000},
                        "destination": {"address": "192.0.2.20", "port": 443},
                        "flags": ["FIN"],
                    },
                ],
            },
            tcl_lsp_root=self.tcl_lsp_root,
        )
        client_data = next(
            event
            for event in result["trace"][0]["events"]
            if event["event"] == "CLIENT_DATA"
        )
        self.assertEqual(client_data["notifications"], [])
        self.assertNotIn("should-not-run", str(result))

    def test_tcp_notify_rejects_wrong_side_and_event_context(self) -> None:
        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_DATA { TCP::notify response }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(self.adapter.EmulatorInputError, "not valid on the client side"):
                session.fire_event("CLIENT_DATA", {"connection": {"client_payload": "x"}})
        finally:
            session.close()

        session = self.adapter.EmulatorSession(
            self.adapter._find_tcl_lsp_root(self.tcl_lsp_root),
            {
                "profiles": ["TCP"],
                "irule": "when CLIENT_ACCEPTED { TCP::notify request }",
            },
            allow_irule_file=False,
            allow_requests=False,
        )
        try:
            with self.assertRaisesRegex(self.adapter.EmulatorInputError, "not valid in CLIENT_ACCEPTED"):
                session.fire_event("CLIENT_ACCEPTED", {})
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
