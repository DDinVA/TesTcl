#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18086}
data_port=${TESTCL_DATA_PORT:-18087}
scenario="$repo_root/examples/scenarios/live-dns-17.5.json"
python_bin="$repo_root/.venv/bin/python"
log_file=$(mktemp -t testcl-live-dns.XXXXXX)
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

echo "DNS response:"
"$python_bin" - "$data_port" <<'PY'
import socket
import struct
import sys

qname = b"\x07example\x03com\x00"
query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
query += qname + struct.pack("!HH", 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(2)
    client.sendto(query, ("127.0.0.1", int(sys.argv[1])))
    response, _ = client.recvfrom(65535)

response_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
    "!HHHHHH", response[:12]
)
assert response_id == 0x1234
assert flags & 0x8000
assert flags & 0x0400
assert (qdcount, ancount, nscount, arcount) == (1, 1, 0, 0)
assert b"\xc0\x00\x02\x0a" in response
print({"id": hex(response_id), "authoritative": True, "answers": ancount})
PY

echo "Captured DNS observations:"
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
