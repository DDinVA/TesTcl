#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18096}
data_port=${TESTCL_DATA_PORT:-18097}
scenario="$repo_root/examples/scenarios/live-websocket-17.5.json"
python_bin="$repo_root/.venv/bin/python"
log_file=$(mktemp -t testcl-live-websocket.XXXXXX)
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$log_file"
}
trap cleanup EXIT

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi

TCL_LSP_ROOT=${TCL_LSP_ROOT:-/tmp/tcl-lsp} \
  "$repo_root/scripts/emulate-irule.sh" \
  --serve \
  --host 127.0.0.1 \
  --port "$api_port" \
  --data-plane-host 127.0.0.1 \
  --data-plane-port "$data_port" \
  --data-plane-scenario "$scenario" \
  >"$log_file" 2>&1 &
server_pid=$!

ready=0
for _ in {1..50}; do
  if curl --silent --fail "http://127.0.0.1:$api_port/healthz" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  echo "emulator did not become ready" >&2
  sed -n '1,120p' "$log_file" >&2
  exit 1
fi

echo "WebSocket response:"
"$python_bin" - "$data_port" <<'PY'
import socket
import sys


def frame(opcode: int, payload: bytes) -> bytes:
    mask = bytes.fromhex("01020304")
    if len(payload) >= 126:
        raise ValueError("smoke payload must be shorter than 126 bytes")
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return bytes((0x80 | opcode, 0x80 | len(payload))) + mask + masked


def receive_exact(client: socket.socket, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = client.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("server closed during WebSocket frame")
        payload.extend(chunk)
    return bytes(payload)


def receive_frame(client: socket.socket) -> tuple[int, bytes]:
    header = receive_exact(client, 2)
    first, second = header
    if second & 0x80:
        raise RuntimeError("server WebSocket frame must not be masked")
    length = second & 0x7F
    if length == 126:
        extended = receive_exact(client, 2)
        length = int.from_bytes(extended, "big")
    elif length == 127:
        extended = receive_exact(client, 8)
        length = int.from_bytes(extended, "big")
    return first & 0x0F, receive_exact(client, length)


with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2) as client:
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    client.sendall(
        (
            "GET /socket HTTP/1.1\r\n"
            "Host: live.example\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
    )
    handshake = bytearray()
    while b"\r\n\r\n" not in handshake:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError("server closed during WebSocket handshake")
        handshake.extend(chunk)
    if not handshake.startswith(b"HTTP/1.1 101 Switching Protocols"):
        raise RuntimeError(f"unexpected WebSocket handshake: {handshake!r}")
    if b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" not in handshake:
        raise RuntimeError("WebSocket accept key was not validated")

    client.sendall(frame(0x1, b"hello"))
    opcode, payload = receive_frame(client)
    if opcode != 0x1 or payload != b"world":
        raise RuntimeError(f"unexpected WebSocket response: opcode={opcode} payload={payload!r}")
    print(payload.decode("ascii"))

    client.sendall(frame(0x8, (1000).to_bytes(2, "big")))
PY

echo "Captured WebSocket observations:"
curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=20" \
  | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
print(json.dumps({
    "profile": payload.get("profile"),
    "count": payload.get("count"),
    "protocols": [item.get("protocol") for item in payload.get("observations", [])],
    "phases": [item.get("phase") for item in payload.get("observations", [])],
}, indent=2))
observations = payload.get("observations", [])
if not any(item.get("protocol") == "websocket" for item in observations):
    raise SystemExit("no WebSocket observation was captured")
'
