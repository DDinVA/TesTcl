#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
api_port=${TESTCL_API_PORT:-18098}
data_port=${TESTCL_DATA_PORT:-18099}
python_bin="$repo_root/.venv/bin/python"
temporary_directory=$(mktemp -d -t testcl-live-http2.XXXXXX)
scenario="$temporary_directory/scenario.json"
log_file="$temporary_directory/emulator.log"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$temporary_directory"
}
trap cleanup EXIT

if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "TesTcl requires a uv-managed Python 3.13+ environment at $python_bin" >&2
  echo "Create it with: uv sync --python 3.13" >&2
  exit 2
fi

"$python_bin" - "$temporary_directory" "$scenario" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

directory = Path(sys.argv[1])
certificate_path = directory / "server.pem"
key_path = directory / "server.key"
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.now(timezone.utc)
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(hours=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    .sign(key, hashes.SHA256())
)
certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
key_path.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
scenario = {
    "profiles": ["TCP", "HTTP"],
    "irule": (
        "when HTTP_REQUEST { HTTP::header insert X-Rule-Path [HTTP::path] } "
        "when HTTP_RESPONSE { HTTP::header insert X-Emulator-Rule http2 }"
    ),
    "live_origin": {
        "status": 200,
        "headers": {"Content-Type": "text/plain"},
        "body": "hello from the modeled HTTP/2 origin",
    },
    "live_data_plane": {
        "protocol": "http2",
        "tls": {"certfile": str(certificate_path), "keyfile": str(key_path)},
    },
}
Path(sys.argv[2]).write_text(json.dumps(scenario), encoding="utf-8")
PY

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

echo "HTTP/2 response:"
PYTHONPATH="$repo_root" "$python_bin" - "$data_port" <<'PY'
import socket
import ssl
import sys

from hpack import Encoder

from tools.http2_wire import HTTP2_CLIENT_PREFACE, Http2ConnectionDecoder


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def receive_events(client: ssl.SSLSocket) -> list[dict[str, object]]:
    decoder = Http2ConnectionDecoder()
    events: list[dict[str, object]] = []
    client.settimeout(2)
    while not any(
        event.get("kind") == "data" and event.get("end_stream")
        for event in events
    ):
        payload = client.recv(65535)
        if not payload:
            raise RuntimeError("HTTP/2 server closed before response completion")
        events.extend(decoder.feed(payload, "server_to_client"))
    return events


context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.set_alpn_protocols(["h2"])
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2) as raw_client:
    with context.wrap_socket(raw_client, server_hostname="localhost") as client:
        if client.selected_alpn_protocol() != "h2":
            raise RuntimeError("TLS ALPN did not negotiate h2")
        headers = Encoder().encode(
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "live.example"),
                (":path", "/h2"),
            ]
        )
        client.sendall(
            HTTP2_CLIENT_PREFACE
            + frame(0x4, 0, 0)
            + frame(0x1, 0x5, 1, headers)
        )
        events = receive_events(client)

response_headers = next(event for event in events if event.get("kind") == "headers")
body = b"".join(
    event["data"]
    for event in events
    if event.get("kind") == "data" and isinstance(event.get("data"), bytes)
)
status = response_headers.get("pseudo_headers", {}).get(":status")
response_fields = response_headers.get("headers", {})
if status != "200":
    raise RuntimeError(f"unexpected HTTP/2 status: {status!r}")
if response_fields.get("x-emulator-rule") != "http2":
    raise RuntimeError("HTTP/2 response did not contain the iRule header mutation")
if body != b"hello from the modeled HTTP/2 origin":
    raise RuntimeError(f"unexpected HTTP/2 body: {body!r}")
print(f"status={status} x-emulator-rule={response_fields['x-emulator-rule']}")
print(body.decode("utf-8"))
PY

echo "Captured HTTP/2 observations:"
curl --silent --show-error --fail \
  "http://127.0.0.1:$api_port/v1/live-observations?limit=20" \
  | "$python_bin" -c '
import json
import sys

payload = json.load(sys.stdin)
observations = payload.get("observations", [])
print(json.dumps({
    "profile": payload.get("profile"),
    "count": payload.get("count"),
    "protocols": [item.get("protocol") for item in observations],
    "phases": [item.get("phase") for item in observations],
}, indent=2))
if not any(item.get("protocol") == "http2" for item in observations):
    raise SystemExit("no HTTP/2 observation was captured")
'
