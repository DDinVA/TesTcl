#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18098}
data_port=${TESTCL_DATA_PORT:-18099}
scenario="$repo_root/examples/scenarios/live-sip-tcp-17.5.json"
python_bin="$repo_root/.venv/bin/python"
log_file=$(mktemp -t testcl-live-sip-tcp.XXXXXX)
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

echo "SIP/TCP response:"
"$python_bin" - "$data_port" <<'PY'
import socket
import sys

request = (
    b"OPTIONS sip:service.example.com SIP/2.0\r\n"
    b"Via: SIP/2.0/TCP client.example.com;branch=z9\r\n"
    b"From: <sip:alice@example.com>;tag=1\r\n"
    b"To: <sip:service.example.com>\r\n"
    b"Call-ID: smoke-tcp-options\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n\r\n"
)
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2) as client:
    client.settimeout(2)
    midpoint = 37
    client.sendall(request[:midpoint])
    client.sendall(request[midpoint:])
    response_buffer = bytearray()
    while b"\r\n\r\n" not in response_buffer:
        chunk = client.recv(4096)
        if not chunk:
            break
        response_buffer.extend(chunk)
        if len(response_buffer) > 1 << 20:
            raise SystemExit("SIP response exceeded the smoke-test limit")
    response = bytes(response_buffer)
    if not response.startswith(b"SIP/2.0 200 OK\r\n"):
        raise SystemExit(f"unexpected SIP response: {response!r}")
    print(response.decode("utf-8"))
PY

echo "Captured SIP/TCP observations:"
curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=10" \
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
'
