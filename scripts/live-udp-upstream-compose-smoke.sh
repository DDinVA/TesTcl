#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"
project_name="testcl-udp-smoke-$$"
api_port=${TESTCL_UDP_API_PORT:-8081}
data_port=${TESTCL_UDP_DATA_PORT:-18082}
export TESTCL_UDP_API_PORT="$api_port" TESTCL_UDP_DATA_PORT="$data_port"
compose=(docker compose -p "$project_name" --profile udp)

cleanup() {
  "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "This smoke test requires Docker Compose v2" >&2
  exit 2
fi
if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi

cd "$repo_root"
"${compose[@]}" up --build --detach udp-backend emulator-udp

ready=0
for _ in {1..60}; do
  if curl --silent --fail "http://127.0.0.1:$api_port/healthz" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" != 1 ]]; then
  "${compose[@]}" logs >&2
  echo "UDP Compose workbench did not become ready" >&2
  exit 1
fi

echo "UDP upstream response:"
set +e
"$python_bin" - "$data_port" <<'PY'
import socket
import sys
import time

deadline = time.monotonic() + 30
last_error = RuntimeError("no UDP response attempt completed")
while time.monotonic() < deadline:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(b"hello", ("127.0.0.1", int(sys.argv[1])))
            response, _ = client.recvfrom(65535)
        if response == b"reply:query":
            print(response.decode("ascii"))
            break
        last_error = RuntimeError(f"unexpected UDP response: {response!r}")
    except OSError as exc:
        last_error = exc
    time.sleep(0.5)
else:
    raise SystemExit(f"UDP upstream smoke failed: {last_error!r}")
PY
udp_status=$?
set -e
if [[ "$udp_status" -ne 0 ]]; then
  echo "Compose service state after UDP smoke failure:" >&2
  "${compose[@]}" ps >&2 || true
  echo "Compose logs after UDP smoke failure:" >&2
  "${compose[@]}" logs --no-color >&2 || true
  exit "$udp_status"
fi

echo "Captured UDP upstream phases:"
curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=10" \
  | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
phases = [item.get("phase") for item in payload.get("observations", [])]
pairs = [phases[index:index + 2] for index in range(0, len(phases), 2)]
if not pairs or any(pair != ["datagram", "upstream_data"] for pair in pairs):
    raise SystemExit(f"unexpected observation phases: {phases!r}")
print(json.dumps({"profile": payload.get("profile"), "phases": pairs[-1]}, indent=2))
'
