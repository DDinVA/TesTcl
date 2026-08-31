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


def test_http_driver_builds_structured_request_and_body() -> None:
    payload = driver.build_http_request(
        {
            "method": "POST",
            "uri": "/api/test?mode=1",
            "host": "example.test",
            "headers": {"X-Request-ID": "abc"},
            "body": "hello",
        }
    )
    assert payload == (
        b"POST /api/test?mode=1 HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"X-Request-ID: abc\r\n"
        b"Content-Length: 5\r\n"
        b"Connection: close\r\n\r\nhello"
    )
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "HTTP_REQUEST",
            "traffic_url": "tcp://192.0.2.20:8080",
            "request": {"method": "GET", "uri": "/health", "host": "vip.test"},
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 8080)
    assert payload.startswith(b"GET /health HTTP/1.1\r\nHost: vip.test\r\n")
    assert timeout == 10.0


def test_http_driver_rejects_header_injection_and_conflicting_body_sources() -> None:
    with pytest.raises(driver.DriverError, match="line breaks"):
        driver.build_http_request({"headers": {"X-Test": "ok\r\nInjected: yes"}})
    with pytest.raises(driver.DriverError, match="repeated"):
        driver.build_http_request({"headers": {"Host": "one", "host": "two"}})
    with pytest.raises(driver.DriverError, match="body, payload, or payload_base64"):
        driver.build_http_request(
            {"body": "hello", "payload_base64": base64.b64encode(b"world").decode("ascii")}
        )
    with pytest.raises(driver.DriverError, match="ASCII"):
        driver.build_http_request({"uri": "/café"})
    with pytest.raises(driver.DriverError, match="header names"):
        driver.build_http_request({"headers": {"X Bad": "value"}})
    with pytest.raises(driver.DriverError, match="at most 128"):
        driver.build_http_request(
            {"headers": {f"X-{index}": "value" for index in range(128)}}
        )


def test_websocket_driver_builds_upgrade_and_masked_client_frame() -> None:
    payload = driver.build_websocket_request(
        {
            "websocket": {
                "uri": "/socket",
                "host": "example.test",
                "sec_websocket_key": "dGhlIHNhbXBsZSBub25jZQ==",
                "frame_type": "text",
                "payload": "hello",
                "mask_hex": "01020304",
            }
        },
        "WS_CLIENT_FRAME",
    )
    assert payload.startswith(
        b"GET /socket HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    assert payload.endswith(b"\x81\x85\x01\x02\x03\x04igohn")
    endpoint, handshake, timeout = driver.build_payload(
        {
            "event": "WS_REQUEST",
            "traffic_url": "tcp://192.0.2.20:8080",
            "request": {"websocket": {"uri": "/socket"}},
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 8080)
    assert handshake.endswith(b"Sec-WebSocket-Version: 13\r\n\r\n")
    assert timeout == 10.0


def test_websocket_driver_rejects_invalid_mask_and_control_frame() -> None:
    with pytest.raises(driver.DriverError, match="mask_hex"):
        driver.build_websocket_request(
            {"websocket": {"mask_hex": "bad", "payload": "x"}},
            "WS_CLIENT_FRAME",
        )
    with pytest.raises(driver.DriverError, match="control frames"):
        driver.build_websocket_request(
            {
                "websocket": {
                    "frame_type": "ping",
                    "fin": False,
                    "payload": "x",
                }
            },
            "WS_CLIENT_FRAME",
        )


def test_rtsp_driver_builds_structured_request_and_payload() -> None:
    payload = driver.build_rtsp_message(
        {
            "method": "DESCRIBE",
            "uri": "rtsp://media.example/live",
            "headers": {"CSeq": "7", "Accept": "application/sdp"},
            "body": "ping",
        },
        "RTSP_REQUEST",
    )
    assert payload == (
        b"DESCRIBE rtsp://media.example/live RTSP/1.0\r\n"
        b"CSeq: 7\r\n"
        b"Accept: application/sdp\r\n"
        b"Content-Length: 4\r\n\r\nping"
    )
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "RTSP_REQUEST",
            "traffic_url": "tcp://192.0.2.20:8554",
            "request": {
                "method": "OPTIONS",
                "uri": "rtsp://media.example/live",
                "headers": {"CSeq": "2"},
            },
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 8554)
    assert payload.startswith(b"OPTIONS rtsp://media.example/live RTSP/1.0\r\n")
    assert timeout == 10.0


def test_rtsp_driver_rejects_injection_and_ambiguous_sources() -> None:
    with pytest.raises(driver.DriverError, match="line breaks"):
        driver.build_rtsp_message(
            {"headers": {"CSeq": "1\r\nInjected: yes"}}, "RTSP_REQUEST"
        )
    with pytest.raises(driver.DriverError, match="exactly one"):
        driver.build_rtsp_message(
            {"body": "body", "payload_base64": base64.b64encode(b"payload").decode()},
            "RTSP_REQUEST",
        )
    with pytest.raises(driver.DriverError, match="ASCII bytes"):
        driver.build_rtsp_message(
            {"headers": {"X-Test": "café"}}, "RTSP_REQUEST"
        )
    with pytest.raises(driver.DriverError, match="supports RTSP_REQUEST"):
        driver.build_rtsp_message({}, "RTSP_RESPONSE")


def test_rtsp_driver_normalises_raw_message_line_endings() -> None:
    payload = driver.build_rtsp_message(
        {"message": "OPTIONS rtsp://media.example/live RTSP/1.0\nCSeq: 3\n\n"},
        "RTSP_REQUEST",
    )
    assert payload == b"OPTIONS rtsp://media.example/live RTSP/1.0\r\nCSeq: 3\r\n\r\n"


def test_fix_driver_builds_framed_tags_and_accepts_raw_bytes() -> None:
    payload = driver.build_fix_message(
        {
            "fix": {
                "begin_string": "FIX.4.4",
                "tags": {
                    "35": "D",
                    "49": "CLIENT",
                    "56": "TARGET",
                    "11": "ORDER-1",
                    "55": "AAPL",
                },
            }
        },
        "CLIENT_DATA",
    )
    assert payload == (
        b"8=FIX.4.4\x019=44\x0135=D\x0149=CLIENT\x0156=TARGET\x0111=ORDER-1\x0155=AAPL\x0110=004\x01"
    )
    raw = base64.b64encode(payload).decode("ascii")
    assert driver.build_fix_message(
        {"fix": {"message_base64": raw}}, "SERVER_DATA"
    ) == payload
    endpoint, generated, timeout = driver.build_payload(
        {
            "event": "FIX_MESSAGE",
            "traffic_url": "tcp://192.0.2.20:9876",
            "request": {
                "fix": {"tags": {"35": "0", "49": "CLIENT", "56": "TARGET"}}
            },
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 9876)
    assert generated.startswith(b"8=FIX.4.4\x019=")
    assert timeout == 10.0


def test_fix_driver_rejects_ambiguous_or_unsafe_fields() -> None:
    with pytest.raises(driver.DriverError, match="mutually exclusive"):
        driver.build_fix_message(
            {"fix": {"message_hex": "00", "message_base64": "AA=="}},
            "CLIENT_DATA",
        )
    with pytest.raises(driver.DriverError, match="message type"):
        driver.build_fix_message(
            {"fix": {"tags": {"49": "CLIENT", "56": "TARGET"}}},
            "CLIENT_DATA",
        )
    with pytest.raises(driver.DriverError, match="SOH"):
        driver.build_fix_message(
            {"fix": {"tags": {"35": "D", "58": "bad\x01value"}}},
            "CLIENT_DATA",
        )
    with pytest.raises(driver.DriverError, match="reserved"):
        driver.build_fix_message(
            {"fix": {"tags": {"8": "FIX.4.4", "35": "D"}}},
            "CLIENT_DATA",
        )


def test_ftp_driver_builds_command_response_and_multiline_reply() -> None:
    command = driver.build_ftp_message(
        {"ftp": {"command": "USER alice"}}, "CLIENT_DATA"
    )
    assert command == b"USER alice\r\n"
    response = driver.build_ftp_message(
        {"ftp": {"response_code": 220, "lines": ["welcome", "ready"]}},
        "SERVER_DATA",
    )
    assert response == b"220-welcome\r\n220 ready\r\n"
    assert driver.build_ftp_message(
        {"ftp": {"response_code": 220, "lines": ["welcome"]}},
        "SERVER_DATA",
    ) == b"220 welcome\r\n"
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "CLIENT_DATA",
            "traffic_url": "tcp://192.0.2.20:2121",
            "request": {"ftp": {"command": "NOOP"}},
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 2121)
    assert payload == b"NOOP\r\n"
    assert timeout == 10.0


def test_ftp_driver_rejects_wrong_direction_and_line_injection() -> None:
    with pytest.raises(driver.DriverError, match="SERVER_DATA requires"):
        driver.build_ftp_message(
            {"ftp": {"command": "USER alice"}}, "SERVER_DATA"
        )
    with pytest.raises(driver.DriverError, match="line breaks"):
        driver.build_ftp_message(
            {"ftp": {"command": "USER alice\r\nNOOP"}}, "CLIENT_DATA"
        )
    with pytest.raises(driver.DriverError, match="response_code"):
        driver.build_ftp_message(
            {"ftp": {"response_code": 99, "text": "bad"}}, "SERVER_DATA"
        )
    with pytest.raises(driver.DriverError, match="must not be blank"):
        driver.build_ftp_message({"ftp": {"command": " "}}, "CLIENT_DATA")
    with pytest.raises(driver.DriverError, match="cannot include response"):
        driver.build_ftp_message(
            {"ftp": {"command": "NOOP", "text": "ignored"}}, "CLIENT_DATA"
        )
    with pytest.raises(driver.DriverError, match="valid UTF-8"):
        driver.build_ftp_message(
            {"ftp": {"response_code": 550, "text": "bad\ud800"}}, "SERVER_DATA"
        )
    with pytest.raises(driver.DriverError, match="line exceeding"):
        driver.build_ftp_message(
            {"ftp": {"message": "X" * 65537}}, "CLIENT_DATA"
        )


def test_ldap_driver_builds_bind_search_and_response_messages() -> None:
    bind = driver.build_ldap_message(
        {"ldap": {"operation": "bindRequest", "message_id": 7, "dn": "cn=alice", "password": "secret"}},
        "CLIENT_DATA",
    )
    assert bind == bytes.fromhex("301a020107a0150201030408636e3d616c6963658006736563726574")
    search = driver.build_ldap_message(
        {"ldap": {"operation": "searchRequest", "message_id": 8, "dn": "dc=example,dc=test", "scope": 2}},
        "CLIENT_DATA",
    )
    assert search == bytes.fromhex("3037020108a332041264633d6578616d706c652c64633d746573740a01020a0100020100020100010100870b6f626a656374436c6173733000")
    response = driver.build_ldap_message(
        {"ldap": {"operation": "bindResponse", "message_id": 7, "result_code": 49, "diagnostic": "invalid credentials"}},
        "SERVER_DATA",
    )
    assert response == bytes.fromhex("301f020107a11a0a013104000413696e76616c69642063726564656e7469616c73")
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "CLIENT_DATA",
            "traffic_url": "tcp://192.0.2.20:1389",
            "request": {"ldap": {"operation": "unbindRequest", "message_id": 9}},
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 1389)
    assert payload == bytes.fromhex("30050201094200")
    assert timeout == 10.0


def test_ldap_driver_rejects_invalid_direction_and_raw_message() -> None:
    with pytest.raises(driver.DriverError, match="operation must be one of"):
        driver.build_ldap_message(
            {"ldap": {"operation": "bindRequest"}}, "SERVER_DATA"
        )
    with pytest.raises(driver.DriverError, match="protocol operation is truncated"):
        driver.build_ldap_message(
            {"ldap": {"message_hex": "3003020101"}}, "CLIENT_DATA"
        )
    with pytest.raises(driver.DriverError, match="cannot be combined"):
        driver.build_ldap_message(
            {"ldap": {"message_hex": "3003020101", "message_id": 1}}, "CLIENT_DATA"
        )
    with pytest.raises(driver.DriverError, match="at most 2147483647"):
        driver.build_ldap_message(
            {"ldap": {"message_hex": "300702050080000000"}}, "CLIENT_DATA"
        )
    with pytest.raises(driver.DriverError, match="invalid protocol operation direction"):
        driver.build_ldap_message(
            {"ldap": {"message_hex": "301f020107a11a0a013104000413696e76616c69642063726564656e7469616c73"}},
            "CLIENT_DATA",
        )


def test_starttls_driver_builds_imap_and_pop3_control_lines() -> None:
    imap = driver.build_starttls_message(
        {"starttls": {"protocol": "imap", "command": "A001 STARTTLS"}},
        "CLIENT_DATA",
    )
    assert imap == b"A001 STARTTLS\r\n"
    pop3 = driver.build_starttls_message(
        {"starttls": {"protocol": "pop3", "message": "+OK Begin TLS"}},
        "SERVER_DATA",
    )
    assert pop3 == b"+OK Begin TLS\r\n"
    endpoint, payload, timeout = driver.build_payload(
        {
            "event": "CLIENT_DATA",
            "traffic_url": "tcp://192.0.2.20:1110",
            "request": {
                "starttls": {"protocol": "pop3", "command": "STLS"}
            },
        }
    )
    assert endpoint == driver.Endpoint("tcp", "192.0.2.20", 1110)
    assert payload == b"STLS\r\n"
    assert timeout == 10.0


def test_starttls_driver_rejects_wrong_direction_and_invalid_command() -> None:
    with pytest.raises(driver.DriverError, match="SERVER_DATA requires"):
        driver.build_starttls_message(
            {"starttls": {"protocol": "imap", "command": "A001 NOOP"}},
            "SERVER_DATA",
        )
    with pytest.raises(driver.DriverError, match="not recognized"):
        driver.build_starttls_message(
            {"starttls": {"protocol": "pop3", "command": "BOGUS"}},
            "CLIENT_DATA",
        )


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
