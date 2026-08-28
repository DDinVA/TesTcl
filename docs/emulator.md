# BIG-IP 17.5 iRule emulator

TesTcl now has a thin adapter for the iRule simulation framework in
[`tcl-lsp`](https://github.com/bitwisecook/tcl-lsp). The adapter exposes a
stable JSON scenario interface while leaving the original Tcl test library
unchanged.

This is a behavioral emulator, not a BIG-IP TMM or vLab. It runs the iRule in
a real Tcl interpreter and supplies TMM-like event orchestration, protocol
state, pools, data groups, decision logs, and safety restrictions. It does not
forward production traffic or reproduce every internal TMM implementation
detail.

## Run locally

Point the adapter at a checkout of `tcl-lsp`:

```sh
export TCL_LSP_ROOT=/path/to/tcl-lsp
./scripts/emulate-irule.sh <<'JSON'
{
  "tmos_version": "17.5",
  "irule": "when HTTP_REQUEST { if {[HTTP::host] eq \"api.example.com\"} { pool api_pool } }",
  "pools": {"api_pool": ["10.0.0.1:80"]},
  "requests": [
    {"host": "api.example.com", "uri": "/health"},
    {"host": "api.example.com", "uri": "/v1/users"}
  ]
}
JSON
```

The second request uses the same connection, exercising the framework's
keep-alive lifecycle. Set `close_before`, `close_after`, or `new_connection`
on a request to control connection boundaries. `irule_file` may be used in
place of `irule` for local files.

The response contains `schema_version`, the fixed `tmos-17.5` `profile`,
`registered_events`, and one result per request. Each result includes the
selected pool/node, response commitment, connection state, decisions, logs,
and any events reported by the upstream framework.

## HTTP API

Run a localhost-only service over the same contract:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh --serve --port 8080
curl http://127.0.0.1:8080/healthz
curl 'http://127.0.0.1:8080/v1/capabilities?offset=0&limit=100'
curl -X POST -H 'Content-Type: application/json' \
  --data-binary @test/fixtures/emulator_http.json \
  http://127.0.0.1:8080/v1/simulations
```

The service exposes `GET /healthz`, `GET /v1/capabilities`, and
`POST /v1/simulations`. It also supports persistent sessions through
`POST /v1/sessions`, `GET /v1/sessions/{session_id}`,
`POST /v1/sessions/{session_id}/requests`, and
`DELETE /v1/sessions/{session_id}`. It binds to `127.0.0.1` by default, caps
JSON request bodies at 2 MiB, and does not expose arbitrary Tcl evaluation.
The HTTP API accepts inline `irule` text only; use the CLI's `irule_file` field
when a rule must be loaded from a local file.

For connection-aware testing, use the persistent session endpoints:
`POST /v1/sessions` creates a session from an iRule, profiles, pools, and data
groups; `POST /v1/sessions/{session_id}/requests` runs one request on that
session; `GET /v1/sessions/{session_id}` returns lifecycle metadata; and
`POST /v1/sessions/{session_id}/events` injects a catalogued event with
structured protocol state; `DELETE /v1/sessions/{session_id}` closes it. The
Tcl interpreter is kept on a dedicated worker thread per session, so HTTP
handler threads can safely make successive calls. Sessions expire after 30
minutes of inactivity and the default service permits 32 concurrent sessions.
The service has no authentication layer; keep the default loopback binding or
put an authenticated proxy in front of any non-local deployment.

```sh
SESSION=$(curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"irule":"when HTTP_REQUEST { pool api_pool }", "pools":{"api_pool":["10.0.0.1:80"]}}' \
  http://127.0.0.1:8080/v1/sessions | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"uri":"/health"}' \
  "http://127.0.0.1:8080/v1/sessions/${SESSION}/requests"
curl -sS -X DELETE "http://127.0.0.1:8080/v1/sessions/${SESSION}"
```

Event sessions can use non-HTTP profiles. For example, a DNS request can be
driven without a packet generator:

```sh
DNS_SESSION=$(curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"profiles":["UDP","DNS"],"irule":"when DNS_REQUEST { log local0. dns-request }"}' \
  http://127.0.0.1:8080/v1/sessions | python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"event":"DNS_REQUEST","state":{"dns":{"qname":"example.com","qtype":"A"}}}' \
  "http://127.0.0.1:8080/v1/sessions/${DNS_SESSION}/events"
curl -sS -X DELETE "http://127.0.0.1:8080/v1/sessions/${DNS_SESSION}"
```

Requests may include a string `body`, plus `response_headers` and
`response_body` to model the upstream response. The returned result includes
the final request/response headers and bodies after the iRule runs. For
example:

```json
{
  "irule": "when HTTP_REQUEST { if {[HTTP::payload] eq \"ping\"} { pool api_pool } } when HTTP_RESPONSE { HTTP::header replace X-Result ok }",
  "pools": {"api_pool": ["10.0.0.1:80"]},
  "request": {
    "body": "ping",
    "response_headers": {"Content-Type": "text/plain"},
    "response_body": "pong"
  }
}
```

## Inspect the complete capability catalog

The adapter can emit the entire `tcl-lsp` F5 iRules registry in bounded
chunks. The catalog currently reports command names, subcommands, protocol
requirements, and whether the runtime has a handwritten mock, generated stub,
or no handler. It also includes event lifecycle metadata and profile metadata.

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capabilities --offset 0 --limit 100
```

Use the returned `chunk.has_more` and advance `offset` by `chunk.count` until
all commands are consumed. This is a registry/capability view, not a claim
that generated stubs reproduce production TMM semantics; the distinction is
explicit in `runtime_status`.

## Container

Build and run the pinned 17.5 image:

```sh
docker build -f Dockerfile.emulator -t testcl-irule-emulator:17.5 .
docker run --rm -i testcl-irule-emulator:17.5 <<'JSON'
{"irule":"when HTTP_REQUEST { pool api_pool }","pools":{"api_pool":["10.0.0.1:80"]}}
JSON
```

The image uses Python only as the bridge and `python3-tk` for the required
in-process Tcl interpreter; it does not install the full language-server
dependency set.
The upstream dependency is AGPL-3.0-or-later. See [`THIRD_PARTY.md`](../THIRD_PARTY.md)
before redistributing the image.

To publish the HTTP API from a container, bind it to the container interface
and publish the port explicitly:

```sh
docker run --rm --publish 8080:8080 testcl-irule-emulator:17.5 \
  --serve --host 0.0.0.0 --port 8080
```

## Current boundary

The current slice is focused on HTTP/TCP request simulation with persistent
connection sessions. The next slices should add UDP/DNS and TLS scenario
inputs, richer protocol state, capability-aware execution warnings, and an MCP
facade over the same JSON contract. The emulator profile remains fixed at
`tmos-17.5`.
