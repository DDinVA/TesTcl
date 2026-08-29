"""Bounded HTTP/2 frame and HPACK decoding for the TesTcl packet adapter."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

try:
    from hpack import Decoder
    from hpack.exceptions import HPACKDecodingError
except ImportError:  # pragma: no cover - exercised only in incomplete installs
    Decoder = None  # type: ignore[assignment,misc]

    class HPACKDecodingError(Exception):
        """Fallback error type when the optional dependency is absent."""


HTTP2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_MAX_FRAME_PAYLOAD = 1 << 20
HTTP2_MAX_HEADER_BLOCK = 1 << 20
HTTP2_MAX_HEADERS = 128
HTTP2_MAX_HEADER_VALUE_BYTES = 1 << 20

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20
_HEADER_NAME_RE = re.compile(r"[a-z0-9!#$%&'*+\-.^_`|~]+\Z")


class Http2DecodeError(ValueError):
    """Raised for malformed or unsupported bounded HTTP/2 input."""


@dataclass(frozen=True)
class Http2Frame:
    direction: str
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


@dataclass
class _HeaderContinuation:
    stream_id: int
    fragments: bytearray
    end_stream: bool
    priority: int


def _u24(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def _u31(raw: bytes) -> int:
    return int.from_bytes(raw, "big") & 0x7FFF_FFFF


def _unpad(payload: bytes, flags: int) -> bytes:
    if not flags & FLAG_PADDED:
        return payload
    if not payload:
        raise Http2DecodeError("padded HTTP/2 frame is missing a pad length")
    pad_length = payload[0]
    if pad_length >= len(payload):
        raise Http2DecodeError("HTTP/2 padding exceeds frame payload")
    return payload[1 : len(payload) - pad_length]


def _validate_header_pairs(decoded: list[tuple[str, str]]) -> list[tuple[str, str]]:
    if len(decoded) > HTTP2_MAX_HEADERS:
        raise Http2DecodeError("HTTP/2 header block exceeds the header-count limit")
    result: list[tuple[str, str]] = []
    seen_pseudo: set[str] = set()
    regular_seen = False
    for name, value in decoded:
        if not isinstance(name, str) or not isinstance(value, str):
            raise Http2DecodeError("HPACK produced a non-text header")
        if not name or name != name.lower():
            raise Http2DecodeError("HTTP/2 header names must be lowercase")
        name_without_pseudo = name[1:] if name.startswith(":") else name
        if _HEADER_NAME_RE.fullmatch(name_without_pseudo) is None:
            raise Http2DecodeError("HTTP/2 header names must contain valid token characters")
        if len(value.encode("utf-8")) > HTTP2_MAX_HEADER_VALUE_BYTES:
            raise Http2DecodeError("HTTP/2 header value exceeds the size limit")
        is_pseudo = name.startswith(":")
        if is_pseudo:
            if regular_seen:
                raise Http2DecodeError("HTTP/2 pseudo-headers must precede regular headers")
            if name in seen_pseudo:
                raise Http2DecodeError(f"duplicate HTTP/2 pseudo-header: {name}")
            seen_pseudo.add(name)
        else:
            regular_seen = True
        result.append((name, value))
    return result


class Http2ConnectionDecoder:
    """Decode complete HTTP/2 frames across arbitrary packet boundaries."""

    def __init__(self) -> None:
        if Decoder is None:
            raise Http2DecodeError(
                "HTTP/2 wire decoding requires hpack; install requirements-emulator.txt"
            )
        self._buffers: dict[str, bytearray] = {
            "client_to_server": bytearray(),
            "server_to_client": bytearray(),
        }
        self._decoders = {
            "client_to_server": Decoder(max_header_list_size=HTTP2_MAX_HEADER_BLOCK),
            "server_to_client": Decoder(max_header_list_size=HTTP2_MAX_HEADER_BLOCK),
        }
        self._continuations: dict[str, _HeaderContinuation | None] = {
            "client_to_server": None,
            "server_to_client": None,
        }
        self._preface_seen = False

    def reset(self) -> None:
        self.__init__()

    def _decode_headers(
        self,
        direction: str,
        stream_id: int,
        block: bytes,
        end_stream: bool,
        priority: int,
    ) -> dict[str, Any]:
        if len(block) > HTTP2_MAX_HEADER_BLOCK:
            raise Http2DecodeError("HTTP/2 header block exceeds the size limit")
        try:
            decoded = self._decoders[direction].decode(block)
        except (HPACKDecodingError, ValueError) as exc:
            raise Http2DecodeError(f"invalid HPACK header block: {exc}") from exc
        pairs = _validate_header_pairs(decoded)
        pseudo_headers = {name: value for name, value in pairs if name.startswith(":")}
        regular_headers: dict[str, str] = {}
        for name, value in pairs:
            if name.startswith(":"):
                continue
            if name in regular_headers:
                regular_headers[name] = f"{regular_headers[name]},{value}"
            else:
                regular_headers[name] = value
        return {
            "kind": "headers",
            "direction": direction,
            "frame_type": "HEADERS",
            "stream_id": stream_id,
            "headers": regular_headers,
            "header_list": [[name, value] for name, value in pairs],
            "pseudo_headers": pseudo_headers,
            "end_stream": end_stream,
            "priority": priority,
        }

    def _frame_event(self, frame: Http2Frame) -> dict[str, Any] | None:
        pending = self._continuations[frame.direction]
        if pending is not None and frame.frame_type != FRAME_CONTINUATION:
            raise Http2DecodeError("HTTP/2 CONTINUATION must be the next frame")
        frame_names = {
            FRAME_DATA: "DATA",
            FRAME_HEADERS: "HEADERS",
            FRAME_PRIORITY: "PRIORITY",
            FRAME_RST_STREAM: "RST_STREAM",
            FRAME_SETTINGS: "SETTINGS",
            FRAME_PUSH_PROMISE: "PUSH_PROMISE",
            FRAME_PING: "PING",
            FRAME_GOAWAY: "GOAWAY",
            FRAME_WINDOW_UPDATE: "WINDOW_UPDATE",
            FRAME_CONTINUATION: "CONTINUATION",
        }
        name = frame_names.get(frame.frame_type, f"UNKNOWN_{frame.frame_type}")
        if frame.frame_type == FRAME_HEADERS:
            if frame.stream_id == 0:
                raise Http2DecodeError("HTTP/2 HEADERS frame requires a stream")
            payload = _unpad(frame.payload, frame.flags)
            priority = 0
            if frame.flags & FLAG_PRIORITY:
                if len(payload) < 5:
                    raise Http2DecodeError("HTTP/2 HEADERS priority field is truncated")
                priority = payload[4]
                payload = payload[5:]
            if frame.flags & FLAG_END_HEADERS:
                return self._decode_headers(
                    frame.direction,
                    frame.stream_id,
                    payload,
                    bool(frame.flags & FLAG_END_STREAM),
                    priority,
                )
            continuation = self._continuations[frame.direction]
            if continuation is not None:
                raise Http2DecodeError("HTTP/2 header continuation is already pending")
            if len(payload) > HTTP2_MAX_HEADER_BLOCK:
                raise Http2DecodeError("HTTP/2 header block exceeds the size limit")
            self._continuations[frame.direction] = _HeaderContinuation(
                frame.stream_id,
                bytearray(payload),
                bool(frame.flags & FLAG_END_STREAM),
                priority,
            )
            return None
        if frame.frame_type == FRAME_CONTINUATION:
            if frame.stream_id == 0:
                raise Http2DecodeError("HTTP/2 CONTINUATION frame requires a stream")
            continuation = self._continuations[frame.direction]
            if continuation is None or continuation.stream_id != frame.stream_id:
                raise Http2DecodeError("unexpected HTTP/2 CONTINUATION frame")
            continuation.fragments.extend(frame.payload)
            if len(continuation.fragments) > HTTP2_MAX_HEADER_BLOCK:
                raise Http2DecodeError("HTTP/2 header block exceeds the size limit")
            if not frame.flags & FLAG_END_HEADERS:
                return None
            pending = self._continuations[frame.direction]
            self._continuations[frame.direction] = None
            assert pending is not None
            event = self._decode_headers(
                frame.direction,
                pending.stream_id,
                bytes(pending.fragments),
                pending.end_stream,
                pending.priority,
            )
            event["frame_type"] = "HEADERS"
            event["continued"] = True
            return event
        if frame.frame_type == FRAME_DATA:
            if frame.stream_id == 0:
                raise Http2DecodeError("HTTP/2 DATA frame requires a stream")
            data = _unpad(frame.payload, frame.flags)
            return {
                "kind": "data",
                "direction": frame.direction,
                "frame_type": name,
                "stream_id": frame.stream_id,
                "data": data,
                "end_stream": bool(frame.flags & FLAG_END_STREAM),
            }
        if frame.frame_type == FRAME_SETTINGS:
            if frame.stream_id != 0 or len(frame.payload) % 6 or (
                frame.flags & 0x1 and frame.payload
            ):
                raise Http2DecodeError("invalid HTTP/2 SETTINGS frame")
            settings = {
                str(int.from_bytes(frame.payload[index : index + 2], "big")): int.from_bytes(
                    frame.payload[index + 2 : index + 6], "big"
                )
                for index in range(0, len(frame.payload), 6)
            }
            return {
                "kind": "control",
                "direction": frame.direction,
                "frame_type": name,
                "stream_id": 0,
                "settings": settings,
            }
        if frame.frame_type == FRAME_PRIORITY:
            if frame.stream_id == 0 or len(frame.payload) != 5:
                raise Http2DecodeError("invalid HTTP/2 PRIORITY frame")
            return {
                "kind": "control",
                "direction": frame.direction,
                "frame_type": name,
                "stream_id": frame.stream_id,
                "priority": int.from_bytes(frame.payload, "big") & 0x7FFF_FFFF,
            }
        return {
            "kind": "control",
            "direction": frame.direction,
            "frame_type": name,
            "stream_id": frame.stream_id,
            "payload_hex": frame.payload.hex(),
            "end_stream": bool(frame.flags & FLAG_END_STREAM),
        }

    def feed(self, payload: bytes, direction: str) -> list[dict[str, Any]]:
        if direction not in self._buffers:
            raise Http2DecodeError(f"unsupported HTTP/2 direction: {direction}")
        if not isinstance(payload, (bytes, bytearray)):
            raise Http2DecodeError("HTTP/2 payload must be bytes")
        buffer = self._buffers[direction]
        buffer.extend(payload)
        if direction == "client_to_server" and not self._preface_seen:
            if bytes(buffer).startswith(HTTP2_CLIENT_PREFACE):
                del buffer[: len(HTTP2_CLIENT_PREFACE)]
                self._preface_seen = True
            elif len(buffer) < len(HTTP2_CLIENT_PREFACE) and HTTP2_CLIENT_PREFACE.startswith(buffer):
                return []
            else:
                self._preface_seen = True
        events: list[dict[str, Any]] = []
        while len(buffer) >= 9:
            length = _u24(bytes(buffer[:3]))
            if length > HTTP2_MAX_FRAME_PAYLOAD:
                raise Http2DecodeError("HTTP/2 frame exceeds the payload limit")
            total = 9 + length
            if len(buffer) < total:
                break
            frame_type = buffer[3]
            flags = buffer[4]
            stream_id = _u31(bytes(buffer[5:9]))
            payload_bytes = bytes(buffer[9:total])
            del buffer[:total]
            frame = Http2Frame(direction, frame_type, flags, stream_id, payload_bytes)
            event = self._frame_event(frame)
            if event is not None:
                events.append(event)
        if len(buffer) > HTTP2_MAX_FRAME_PAYLOAD + 9:
            raise Http2DecodeError("incomplete HTTP/2 frame exceeds the payload limit")
        return events
