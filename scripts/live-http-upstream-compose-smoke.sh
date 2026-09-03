#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin="$repo_root/.venv/bin/python"

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required for the HTTP upstream smoke test" >&2
  exit 2
fi
if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for the HTTP upstream smoke test" >&2
  exit 2
fi

api_port=${TESTCL_HTTP_API_PORT:-8082}
data_port=${TESTCL_HTTP_DATA_PORT:-18084}
project_name="testcl-http-smoke-$$"
temp_dir=$(mktemp -d -t testcl-http-upstream.XXXXXX)
headers_file="$temp_dir/headers.txt"
body_file="$temp_dir/body.json"
observations_file="$temp_dir/observations.json"

cleanup() {
  docker compose -p "$project_name" --profile http down --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temp_dir"
}
trap cleanup EXIT

docker compose -p "$project_name" --profile http up --build --detach \
  http-backend emulator-http

for attempt in $(seq 1 30); do
  if curl --fail --silent --show-error --max-time 3 \
    "http://127.0.0.1:$api_port/healthz" >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" -eq 30 ]]; then
    docker compose -p "$project_name" --profile http logs
    exit 1
  fi
  sleep 1
done

curl --fail --silent --show-error --max-time 5 \
  -D "$headers_file" -o "$body_file" \
  "http://127.0.0.1:$data_port/compose?probe=17.5"

"$python_bin" - "$body_file" <<'PY'
import json
import sys
from pathlib import Path

body = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "method": "GET",
    "path": "/compose?probe=17.5",
    "x_from_rule": "live-upstream",
    "body": "",
}
if body != expected:
    raise SystemExit(f"unexpected backend request: {body!r}")
print("HTTP backend request:")
print(json.dumps(body, sort_keys=True))
PY

grep -Eiq '^X-Processed:[[:space:]]*by-irule[[:space:]]*$' "$headers_file"
echo "HTTP response mutation: X-Processed: by-irule"

curl --fail --silent --show-error \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=10" >"$observations_file"

"$python_bin" - "$observations_file" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if payload.get("profile") != "tmos-17.5":
    raise SystemExit("observations returned the wrong profile")
phases = [item.get("phase") for item in payload.get("observations", [])]
if phases != ["transaction"]:
    raise SystemExit(f"unexpected HTTP observation phases: {phases!r}")
transaction = payload["observations"][0].get("result")
if not isinstance(transaction, dict):
    raise SystemExit("HTTP transaction observation is not an object")
headers = transaction.get("response", {}).get("headers", {})
if not isinstance(headers, dict):
    raise SystemExit("HTTP transaction response headers are not an object")
processed = next(
    (value for name, value in headers.items() if str(name).lower() == "x-processed"),
    None,
)
if processed != "by-irule":
    raise SystemExit("HTTP transaction did not retain the response mutation")
print("HTTP live observation phase: transaction")
PY
