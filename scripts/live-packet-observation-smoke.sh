#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18092}
data_port=${TESTCL_DATA_PORT:-18093}
scenario="$repo_root/examples/scenarios/live-tcp-17.5.json"
python_bin="$repo_root/.venv/bin/python"
log_file=$(mktemp -t testcl-live-packet-observation.XXXXXX)
capture_request=$(mktemp -t testcl-live-packet-capture-request.XXXXXX)
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$log_file" "$capture_request"
}
trap cleanup EXIT

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
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

echo "TCP response bytes:"
"$python_bin" - "$data_port" <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2) as client:
    for payload in (b"one", b"two"):
        client.sendall(payload)
        response = bytearray()
        while len(response) < len(payload):
            chunk = client.recv(len(payload) - len(response))
            if not chunk:
                raise SystemExit("emulator closed before the echo completed")
            response.extend(chunk)
        if response != payload:
            raise SystemExit(f"unexpected response: {response!r}")
        print(response.decode("ascii"))
PY

echo "Captured TCP observations:"
observations=$(curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=20")
printf '%s\n' "$observations" | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
print(json.dumps({
    "profile": payload.get("profile"),
    "count": payload.get("count"),
    "observations": [
        {
            "observation_id": item.get("observation_id"),
            "phase": item.get("phase"),
            "direction": item.get("direction"),
            "trace_packets": len(item.get("result", {}).get("trace", [])),
        }
        for item in payload.get("observations", [])
    ],
}, indent=2))
'

"$python_bin" - "$scenario" "$capture_request" <<'PY'
import json
import sys
from pathlib import Path

scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
Path(sys.argv[2]).write_text(
    json.dumps({"scenario": scenario}, separators=(",", ":")),
    encoding="utf-8",
)
PY

echo "Capture-plan export:"
curl --silent --show-error --fail \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-binary "@$capture_request" \
  "http://127.0.0.1:$api_port/v1/live-observations/capture-plan" \
  | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
plan = payload["plan"]
print(json.dumps({
    "status": payload.get("status"),
    "observation_count": payload["summary"].get("observation_count"),
    "reference_output_included": payload["summary"].get("reference_output_included"),
    "packets": [
        {
            "id": item.get("id"),
            "packet_count": len(item.get("input", {}).get("packets", [])),
            "payload_hex": [
                packet.get("payload_hex")
                for packet in item.get("input", {}).get("packets", [])
            ],
        }
        for item in plan.get("observations", [])
    ],
}, indent=2))
'
