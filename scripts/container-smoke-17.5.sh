#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image_name=${TESTCL_IMAGE:-testcl-irule-emulator:local}
container_name="testcl-irule-smoke-$$"
tcl_lsp_commit=${TCL_LSP_COMMIT:-cad24955f16953c2443902efd83d9f7f95d9b648}
build_image=1

usage() {
  cat >&2 <<'EOF'
usage: scripts/container-smoke-17.5.sh [--no-build]

Build (unless --no-build is supplied) and exercise the local TMOS 17.5
emulator container through its API, catalog evaluator, and HTTP data plane.
Set TESTCL_IMAGE to choose the image tag and TCL_LSP_COMMIT to override the
pinned tcl-lsp commit used during an image build.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      build_image=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for the container smoke test" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for the container smoke test" >&2
  exit 2
fi

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$build_image" -eq 1 ]]; then
  docker build \
    --build-arg "TCL_LSP_COMMIT=$tcl_lsp_commit" \
    -f "$repo_root/Dockerfile.emulator" \
    -t "$image_name" \
    "$repo_root"
fi

docker run --detach --name "$container_name" \
  --publish 127.0.0.1::8080/tcp \
  --publish 127.0.0.1::18080/tcp \
  "$image_name" \
  --serve --host 0.0.0.0 --port 8080 \
  --data-plane-scenario /opt/testcl/examples/scenarios/live-http-17.5.json \
  --data-plane-host 0.0.0.0 --data-plane-port 18080 \
  >/dev/null

api_mapping="$(docker port "$container_name" 8080/tcp | head -n 1)"
data_mapping="$(docker port "$container_name" 18080/tcp | head -n 1)"
api_port=${api_mapping##*:}
data_port=${data_mapping##*:}
if [[ -z "$api_mapping" || -z "$data_mapping" || "$api_port" == "$api_mapping" || "$data_port" == "$data_mapping" ]]; then
  echo "could not determine published container ports" >&2
  docker logs "$container_name" >&2 || true
  exit 1
fi

retry_curl() {
  local output_path="$1"
  local attempt
  shift
  for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error "$@" >"$output_path"; then
      return 0
    fi
    if [[ "$attempt" -lt 30 ]]; then
      sleep 1
    fi
  done
  docker logs "$container_name" >&2 || true
  return 1
}

health_file=$(mktemp -t testcl-container-health.XXXXXX)
workbench_file=$(mktemp -t testcl-container-workbench.XXXXXX)
capability_file=$(mktemp -t testcl-container-capability.XXXXXX)
evaluation_file=$(mktemp -t testcl-container-evaluation.XXXXXX)
data_file=$(mktemp -t testcl-container-data.XXXXXX)
cleanup_files() {
  rm -f "$health_file" "$workbench_file" "$capability_file" "$evaluation_file" "$data_file"
}
trap 'cleanup_files; cleanup' EXIT

retry_curl "$health_file" "http://127.0.0.1:$api_port/healthz"
grep -F 'tmos-17.5' "$health_file" >/dev/null
retry_curl "$workbench_file" "http://127.0.0.1:$api_port/"
grep -F 'TesTcl · TMOS 17.5 iRule workbench' "$workbench_file" >/dev/null
grep -F 'Evaluate local chunk' "$workbench_file" >/dev/null
retry_curl "$capability_file" \
  "http://127.0.0.1:$api_port/v1/capabilities?namespace=HTTP&target_status=available-in-tmos-17.5&limit=2"
if [[ ! -s "$capability_file" ]]; then
  echo "capability endpoint returned an empty response" >&2
  docker logs "$container_name" >&2 || true
  exit 1
fi

request_file=$(mktemp -t testcl-container-request.XXXXXX)
cleanup_request() {
  rm -f "$request_file"
}
trap 'cleanup_request; cleanup_files; cleanup' EXIT
docker run --rm --interactive --entrypoint python --network container:"$container_name" "$image_name" \
  -c 'import json,sys; chunk=json.load(open(sys.argv[1])); print(json.dumps({"chunk": chunk, "mode": "both", "variants": 1}))' \
  /dev/stdin <"$capability_file" >"$request_file"
retry_curl "$evaluation_file" -X POST \
  -H 'Content-Type: application/json' \
  --data-binary "@$request_file" \
  "http://127.0.0.1:$api_port/v1/catalog-chunk-evaluate"
grep -F '"status":"ok"' "$evaluation_file" >/dev/null
grep -F '"target_command_count":2' "$evaluation_file" >/dev/null

retry_curl "$data_file" "http://127.0.0.1:$data_port/health"
grep -F 'hello from the modeled origin' "$data_file" >/dev/null

printf '%s\n' "container smoke passed: image=$image_name api_port=$api_port data_port=$data_port"
