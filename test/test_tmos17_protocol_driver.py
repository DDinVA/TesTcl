from __future__ import annotations

import base64
import importlib.util
import json
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "tools" / "tmos17-protocol-driver.py"
SPEC = importlib.util.spec_from_file_location("tmos17_protocol_driver", DRIVER_PATH)
assert SPEC is not None and SPEC.loader is not None
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)


def test_dns_query_is_bounded_and_encodes_question() -> None:
    payload = driver.build_dns_query({"qname": "example.com", "qtype": "AAAA"})
    transaction_id, flags, qdcount, _, _, _ = struct.unpack(">HHHHHH", payload[:12])
    assert transaction_id == 0x1705
    assert flags == 0x0100
    assert qdcount == 1
    assert payload.endswith(b"\x07example\x03com\x00\x00\x1c\x00\x01")


def test_mqtt_driver_builds_connect_then_publish() -> None:
    payload = driver.build_mqtt_connect_publish(
        {"client_id": "client-1", "topic": "f5/test", "payload": "ping"}
    )
    assert payload.startswith(b"\x10")
    assert b"\x00\x04MQTT" in payload
    assert b"\x00\x07f5/testping" in payload
    encoded_payload = base64.b64encode(b"\x00mqtt").decode("ascii")
    encoded = driver.build_mqtt_connect_publish(
        {"topic": "f5/test", "payload_base64": encoded_payload}
    )
    assert encoded.endswith(b"\x00\x07f5/test\x00mqtt")


def test_sip_driver_rejects_header_injection_and_adds_content_length() -> None:
    payload = driver.build_sip_message(
        {"method": "OPTIONS", "uri": "sip:test@example.com", "body": "hello"},
        "SIP_REQUEST",
    )
    assert payload.endswith(b"Content-Length: 5\r\n\r\nhello")
    with pytest.raises(driver.DriverError, match="line breaks"):
        driver.build_sip_message(
            {"headers": {"X-Test": "ok\r\nInjected: yes"}}, "SIP_REQUEST"
        )
    with pytest.raises(driver.DriverError, match="line breaks"):
        driver.build_sip_message({"uri": "sip:ok\nInjected"}, "SIP_REQUEST")


def test_pcp_driver_builds_map_request_and_options() -> None:
    payload = driver.build_pcp_request(
        {
            "pcp": {
                "opcode": "map",
                "lifetime": 3600,
                "protocol": "tcp",
                "client_addr": "192.0.2.10",
                "internal_port": 22,
                "suggested_ext_port": 40000,
                "suggested_ext_addr": "0.0.0.0",
                "third_party": True,
                "third_party_int_addr": "192.0.2.11",
                "prefer_failure": True,
            }
        }
    )
    assert payload[:4] == b"\x02\x01\x00\x00"
    assert len(payload) == 84
    assert payload[24:36] == b"\x00" * 12
    assert payload[36] == 6
    assert payload[-24:-20] == b"\x01\x00\x00\x10"
    assert payload[-20:-4] == b"\x00" * 10 + b"\xff\xff\xc0\x00\x02\x0b"
    assert payload[-4:] == b"\x02\x00\x00\x00"


def test_pcp_driver_rejects_invalid_nested_fields() -> None:
    with pytest.raises(driver.DriverError, match="field names"):
        driver.build_pcp_request({"pcp": {1: "invalid"}})
    with pytest.raises(driver.DriverError, match="unsupported field"):
        driver.build_pcp_request({"pcp": {"unknown": 1}})
    with pytest.raises(driver.DriverError, match="third_party_int_addr"):
        driver.build_pcp_request({"pcp": {"third_party_int_addr": "192.0.2.11"}})
    with pytest.raises(driver.DriverError, match="third_party"):
        driver.build_pcp_request({"pcp": {"third_party": 0}})


def test_radius_driver_builds_auth_request_with_typed_attributes() -> None:
    payload = driver.build_radius_request(
        {
            "radius": {
                "code": "Access-Request",
                "id": 3,
                "authenticator_hex": "11" * 16,
                "avps": [
                    {"code": "User-Name", "data": "alice"},
                    {"code": "NAS-IP-Address", "type": "ip4", "data": "192.0.2.20"},
                ],
            }
        },
        "RADIUS_AAA_AUTH_REQUEST",
    )
    assert payload[:4] == b"\x01\x03\x00\x21"
    assert payload[4:20] == b"\x11" * 16
    assert payload[20:] == b"\x01\x07alice\x04\x06\xc0\x00\x02\x14"


def test_radius_driver_rejects_event_code_mismatch_and_bad_attributes() -> None:
    with pytest.raises(driver.DriverError, match="requires Access-Request"):
        driver.build_radius_request(
            {"radius": {"code": 4}}, "RADIUS_AAA_AUTH_REQUEST"
        )
    with pytest.raises(driver.DriverError, match="exactly one data source"):
        driver.build_radius_request(
            {"radius": {"avps": [{"code": 1}]}}, "RADIUS_AAA_AUTH_REQUEST"
        )
    with pytest.raises(driver.DriverError, match="255-byte limit"):
        driver.build_radius_request(
            {
                "radius": {
                    "avps": [
                        {
                            "code": 26,
                            "vendor_id": 10415,
                            "vendor_type": 1,
                            "data": "x" * 248,
                        }
                    ]
                }
            },
            "RADIUS_AAA_AUTH_REQUEST",
        )


def test_dns_driver_requires_boolean_recursion_flag() -> None:
    with pytest.raises(driver.DriverError, match="recursion_desired"):
        driver.build_dns_query({"qname": "example.com", "recursion_desired": "yes"})


def test_driver_rejects_unencodable_unicode() -> None:
    with pytest.raises(driver.DriverError, match="Unicode"):
        driver.build_dns_query({"qname": "bad\ud800.example"})


def test_raw_driver_payload_uses_base64_and_explicit_destination() -> None:
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "GENERIC_DATA",
            "traffic_url": "http://unused.example/",
            "request": {
                "destination": "udp://192.0.2.10:9999",
                "payload_base64": base64.b64encode(b"\x00raw").decode("ascii"),
                "timeout": 3,
            },
        }
    )
    assert endpoint == driver.Endpoint("udp", "192.0.2.10", 9999)
    assert payload == b"\x00raw"
    assert timeout == 3.0


def test_send_payload_uses_udp_without_waiting_for_response() -> None:
    fake_socket = MagicMock()
    fake_socket.__enter__.return_value = fake_socket
    with patch.object(
        driver.socket,
        "getaddrinfo",
        return_value=[(driver.socket.AF_INET, driver.socket.SOCK_DGRAM, 0, "", ("192.0.2.10", 53))],
    ), patch.object(driver.socket, "socket", return_value=fake_socket) as socket_factory:
        driver.send_payload(driver.Endpoint("udp", "192.0.2.10", 53), b"dns", 2.0)
    socket_factory.assert_called_once()
    fake_socket.settimeout.assert_called_once_with(2.0)
    fake_socket.sendto.assert_called_once_with(b"dns", ("192.0.2.10", 53))


def test_read_request_rejects_non_finite_json() -> None:
    class _Stream:
        def read(self, _: int) -> bytes:
            return json.dumps({"value": float("nan")}).encode("utf-8")

    with pytest.raises(driver.DriverError, match="non-finite"):
        driver.read_request(_Stream())
