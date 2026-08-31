#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18090}
data_port=${TESTCL_DATA_PORT:-18091}
scenario="$repo_root/examples/scenarios/live-http-17.5.json"
log_file=$(mktemp -t testcl-live-observation.XXXXXX)
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$log_file"
}
trap cleanup EXIT

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

echo "HTTP response:"
curl --silent --show-error --include \
  -H 'Host: live.example' \
  "http://127.0.0.1:$data_port/health"
echo
echo "Captured live observations:"
observations=$(curl --silent --show-error \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=10")
printf '%s\n' "$observations" | "$repo_root/.venv/bin/python" -c '
import json
import sys

payload = json.load(sys.stdin)
print(json.dumps({
    "profile": payload.get("profile"),
    "count": payload.get("count"),
    "observations": [
        {
            "observation_id": item.get("observation_id"),
            "protocol": item.get("protocol"),
            "phase": item.get("phase"),
            "direction": item.get("direction"),
            "session_id": item.get("session_id"),
            "request_uri": item.get("result", {}).get("request", {}).get("uri"),
            "response_status": item.get("result", {}).get("response", {}).get("status"),
        }
        for item in payload.get("observations", [])
    ],
}, indent=2))
'
echo
