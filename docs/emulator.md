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

Create the repo-local uv environment once, then point the adapter at a checkout
of `tcl-lsp`:

```sh
uv venv --python 3.13 .venv
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
and any events reported by the upstream framework. It also includes a
`fidelity` report showing statically detected command/event usage and warnings
when a recognized command is backed by a generated stub, has no runtime
handler, or is gated by the attached profiles.
The adapter-owned semantic-mock status identifies commands with behavior
implemented against the scenario state. Semantic state is returned under
`result.semantic`, including STATS counters, captured HSL messages, and
LB node/pool status changes, plus live session-table entries. Persistence records created with `persist add`
remain available across requests on the same connection/session; `persist
lookup`, `persist delete`, and `LB::persist` can inspect, remove, and restore
those records. Table entries support subtables, add/set/replace/incr/append,
key listing, delete-all, and lifetime/timeout expiry. Positive persistence
timeouts expire records using the emulator clock, while timeout `0` means no
expiry.

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

The service exposes `GET /healthz`, `GET /v1/capabilities`,
`GET /v1/conformance`, `POST /v1/simulations`, and
`POST /v1/simulations/pcap`. It also supports persistent sessions through
`POST /v1/sessions`, `GET /v1/sessions/{session_id}`,
`POST /v1/sessions/{session_id}/requests`,
`POST /v1/sessions/{session_id}/packets`, and
`DELETE /v1/sessions/{session_id}`. It binds to `127.0.0.1` by default, caps
JSON request bodies at 2 MiB, and does not expose arbitrary Tcl evaluation.
The HTTP API accepts inline `irule` text only; use the CLI's `irule_file` field
when a rule must be loaded from a local file.

Raw classic PCAP replay is available at `POST /v1/simulations/pcap`. The
request contains an inline `scenario` and a base64-encoded `pcap_base64` value:

```json
{
  "scenario": {
    "profiles": ["TCP", "HTTP"],
    "irule": "when HTTP_REQUEST { pool api_pool }",
    "pools": {"api_pool": ["10.0.0.1:80"]}
  },
  "pcap_base64": "<base64 classic-pcap bytes>",
  "direction": "auto",
  "client_addr": "10.0.0.5",
  "server_addr": "192.0.2.10"
}
```

The endpoint accepts classic PCAP with Ethernet (including VLAN tags) or raw
IPv4 link layers, and preserves each record timestamp in the returned packet
trace. `direction` defaults to `client_to_server`; `auto` requires both
endpoint addresses and skips packets that do not match either direction. The
capture is bounded to 16 MiB, 1,000 records, and 2 MiB per packet. pcapng and
IPv4 fragments are not supported yet. TCP sequence numbers are honored for
bounded out-of-order reassembly and retransmission de-duplication.

For connection-aware testing, use the persistent session endpoints:
`POST /v1/sessions` creates a session from an iRule, profiles, pools, and data
groups; `POST /v1/sessions/{session_id}/requests` runs one request on that
session; `GET /v1/sessions/{session_id}` returns lifecycle metadata; and
`POST /v1/sessions/{session_id}/events` injects a catalogued event with
structured protocol state. `POST /v1/sessions/{session_id}/packets` replays a
structured packet trace; `DELETE /v1/sessions/{session_id}` closes it. The
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

## MCP stdio facade

The same adapter can be launched as a dependency-light MCP server. It speaks
newline-delimited JSON-RPC on stdin/stdout, keeps protocol output off stdout,
and delegates every tool call to the existing emulator and session manager:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh --mcp
docker run --rm -i testcl-irule-emulator:17.5 --mcp
```

After the normal MCP `initialize` and `notifications/initialized` exchange,
clients can discover these tools with `tools/list`:

- `irule_simulate` runs a bounded one-shot scenario.
- `irule_pcap_replay` replays a base64-encoded classic PCAP through the same
  packet and Tcl event adapters.
- `irule_capabilities` returns a chunk of the complete 17.5 catalog.
- `irule_conformance` reports static catalog/runtime and packet-adapter coverage.
- `irule_session_create`, `irule_session_inspect`, `irule_session_request`,
  `irule_session_trace`, `irule_session_event`, and `irule_session_close` manage
  persistent sessions.

Tool failures are returned as MCP tool results with `isError: true`; malformed
JSON-RPC requests and unknown methods use protocol-level errors. The facade
does not expose arbitrary Tcl evaluation or local `irule_file` loading.

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
requirements, and whether the runtime has a handwritten mock, an adapter-owned
semantic mock, a generated stub, or no handler. It also includes event
lifecycle metadata and profile metadata.

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capabilities --offset 0 --limit 100
```

Use the returned `chunk.has_more` and advance `offset` by `chunk.count` until
all commands are consumed. This is a registry/capability view, not a claim
that generated stubs reproduce production TMM semantics; the distinction is
explicit in `runtime_status`. The same distinction is included in each
simulation/session `fidelity.warnings` report, so callers can fail closed or
ask for a higher-fidelity test when needed.

## Structured packet traces

One-shot scenarios may use `packets` instead of `request`/`requests`. A trace
is a bounded sequence of structured packet records. TCP SYN/FIN/RST, TCP
payloads, TLS handshake/data records, HTTP
request/response pairs, and DNS request/response messages are translated into
the same Tcl events and state layers used by the HTTP API. Generic UDP payloads
are reported as unmapped because there is no protocol-specific event to infer.
For raw captures, use `protocol: "wire"`, `network: "ipv4"`, and an IPv4
packet in `raw_hex`; the current decoder rejects fragmented IPv4 packets and
performs bounded sequence-aware TCP application reassembly across records and
persistent session calls, including out-of-order segments and duplicate
retransmissions. Classic PCAP file/HTTP/MCP ingestion is supported separately;
pcapng and IPv4 fragment handling remain outside this slice.

```json
{
  "profiles": ["TCP", "CLIENTSSL", "HTTP"],
  "irule": "when HTTP_REQUEST { pool api_pool }",
  "pools": {"api_pool": ["10.0.0.1:80"]},
  "packets": [
    {
      "protocol": "tcp",
      "direction": "client_to_server",
      "flags": ["SYN"],
      "source": {"address": "10.0.0.5", "port": 51000},
      "destination": {"address": "192.0.2.10", "port": 443}
    },
    {
      "protocol": "tls",
      "type": "client_hello",
      "direction": "client_to_server",
      "sni": "api.example.com"
    },
    {
      "protocol": "http",
      "direction": "client_to_server",
      "method": "GET",
      "uri": "/health",
      "host": "api.example.com"
    },
    {
      "protocol": "http",
      "direction": "server_to_client",
      "status": 200,
      "response_body": "ok"
    }
  ]
}
```

The response includes a per-packet `trace`, translated event results, and
HTTP transaction results. Persistent sessions accept the same packet array at
`POST /v1/sessions/{session_id}/packets`, or through the MCP
`irule_session_trace` tool.

For a classic PCAP file, keep the iRule scenario in a JSON file and replay it
through the CLI:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --scenario scenario.json --pcap traffic.pcap --pcap-direction auto \
  --client-addr 10.0.0.5 --server-addr 192.0.2.10
```

The CLI is the only file-loading surface. HTTP and MCP callers provide PCAP
bytes as base64 and cannot load arbitrary local paths.

Use the static conformance report to see what the pinned 17.5 registry knows
about and which events currently have packet adapters:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh --conformance
curl http://127.0.0.1:8080/v1/conformance
```

## Container

Build and run the pinned 17.5 image:

```sh
docker build -f Dockerfile.emulator -t testcl-irule-emulator:17.5 .
docker run --rm -i testcl-irule-emulator:17.5 <<'JSON'
{"irule":"when HTTP_REQUEST { pool api_pool }","pools":{"api_pool":["10.0.0.1:80"]}}
JSON
```

The image uses Python 3.13 only as the bridge and `tk` for the required
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

The current slice supports HTTP/TCP request simulation, structured packet
traces, classic PCAP replay, sequence-aware persistent connection sessions,
structured DNS/TLS event injection, catalog conformance reporting, an MCP
facade over the same JSON contract, and an adapter-owned semantic overlay for
selected HSL, HTTP, IP, LB, PROFILE, STATS, URI, persistence, table, and
HTTP cookie commands. The semantic overlay also models data-group `class`
matching, lookup, enumeration, connection-scoped search iterators, and
request/response cookie mutations. TCP payload access is directional for
client/server data events and supports byte-length, replacement, collection,
offset, release, and response bookkeeping. `TCP::collect` gates data events
until the requested length and skip window is available, consumes one
collection window, and preserves partial buffers across calls on a persistent
session. The
emulator profile remains fixed at
`tmos-17.5`.
