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
"$python_bin" - "$data_port" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.settimeout(3)
    client.sendto(b"hello", ("127.0.0.1", int(sys.argv[1])))
    response, _ = client.recvfrom(65535)
    if response != b"reply:query":
        raise SystemExit(f"unexpected UDP response: {response!r}")
    print(response.decode("ascii"))
PY

echo "Captured UDP upstream phases:"
curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=10" \
  | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
phases = [item.get("phase") for item in payload.get("observations", [])]
if phases != ["datagram", "upstream_data"]:
    raise SystemExit(f"unexpected observation phases: {phases!r}")
print(json.dumps({"profile": payload.get("profile"), "phases": phases}, indent=2))
'
