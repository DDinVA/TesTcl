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
uv sync --python 3.13
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
Connection endpoint getters (`client_addr`, `client_port`, `local_addr`,
`local_port`, `remote_addr`, `remote_port`, `server_addr`, and `server_port`)
read the configured connection endpoints; server getters switch to the
selected pool member after `pool` or `LB::reselect` establishes one.
Generic UDP packet traces fire `CLIENT_ACCEPTED`, `CLIENT_DATA`,
`SERVER_CONNECTED`, and `SERVER_DATA` as applicable. `UDP::payload` is mutable
by wire-byte offset, and the adapter records UDP drop, hold/release, respond,
port, buffer, rate, and debug-queue controls in the event trace. This is a
bounded datagram model: it does not implement TMM queue scheduling, NAT, or a
real upstream UDP socket.
TCP packet traces also expose a bounded transport-control state layer. Rules
can inspect or set Nagle mode, keepalive, idle timeout, send/receive buffers,
MSS, pacing, PUSH mode, congestion label, and proxy-buffer thresholds; those
values persist across packet events in the emulated connection.
RTSP packet traces use the RTSP profile and expose structured request/response
events, case-insensitive header lookup and mutation, byte-oriented payload
collection/replacement, release, metadata getters, and deterministic
`RTSP::respond` emissions. The packet interface is structured rather than a
full RTSP wire parser or media-session implementation.
The load-balancing layer also models the high-value `LB::` connection controls:
mode and bias overrides, SNAT inspection, context and source/destination tags,
connection-limit records, queue queries, decision-log enablement, and bounded
server-connect/prime requests. These controls update semantic state and
decision output, and pool selection still uses the configured deterministic
members. The emulator does not open real sideband connections, implement
kernel connection limits, or run a production queue scheduler.
Profile attribute commands can be backed by a scenario-level
`profile_settings` object. Keys are profile names such as `AUTH`, `PERSIST`,
or `HTTPCOMPRESSION`, and values are attribute/value maps; attributes are
returned only when the corresponding profile is attached. This provides a
deterministic way to exercise profile-aware rules without requiring a BIG-IP
configuration export.
The `DOSL7` policy surface can be seeded with a scenario-level `dosl7` object:

```json
{
  "profiles": ["TCP", "HTTP", "FASTHTTP"],
  "dosl7": {
    "enabled": true,
    "health": 7,
    "profile": "/Common/dos-profile",
    "mitigated": false,
    "greylist": {
      "10.0.0.1": {"rate": 30, "timeout": 60}
    }
  },
  "irule": "when HTTP_REQUEST { if {[DOSL7::is_ip_slowdown]} { log local0. slowed } }"
}
```

This models all seven TMOS 17.5 `DOSL7::` commands. `DOSL7::enable` and
`DOSL7::disable` change the current connection's enforcement state;
`DOSL7::health`, `DOSL7::profile`, and `DOSL7::is_mitigated` read the seeded
policy inputs; and `DOSL7::slowdown RATE TIMEOUT` adds the current client IP to
the session greylist. The configured greylist survives a new connection while
the enable/disable override does not. The model records timeout values but does
not advance a wall clock or run a real L7 DoS detection/mitigation engine. An
HTTP request may include `"dosl7": {"mitigated": true}` or `false` to override
the seeded mitigation result for that transaction; the override is reused for
an internal `HTTP::retry` and the next request returns to the scenario default.
The `ASM` policy surface can be seeded with deterministic WAF inputs:

```json
{
  "profiles": ["TCP", "HTTP", "ASM", "FASTHTTP"],
  "asm": {
    "enabled": true,
    "policy": "/Common/asm-policy",
    "status": "Blocked",
    "severity": "Error",
    "support_id": "SUP-42",
    "violations": [
      {
        "name": "VIOLATION_ILLEGAL_PARAMETER",
        "attack_type": "Parameter Tampering",
        "rating": "Error",
        "details": {"param_data.param_name": "dGVzdA=="}
      }
    ],
    "signatures": {"ids": ["200000001"]},
    "threat_campaigns": {"names": ["campaign-a"]}
  },
  "irule": "when HTTP_REQUEST { log local0. \"[ASM::status] [ASM::violation count]\" }"
}
```

This models all 25 catalogued TMOS 17.5 `ASM::` commands. Getters expose the
seeded policy, identity, login, CAPTCHA, signature, campaign, violation, and
payload values. `ASM::enable`, `ASM::disable`, `ASM::raise`, `ASM::unblock`,
`ASM::uncaptcha`, `ASM::conviction`, `ASM::deception`, and payload replacement
update the current request state and appear in decisions or semantic output.
Request body data replaces the seeded payload for that transaction. Policy
inputs reset between requests; connection-scoped enable/disable and policy
overrides reset at a new connection. This is a deterministic policy model,
not a WAF inspection, signature-matching, CAPTCHA service, or attack-detection
engine.
With the `CACHE` or `WEBACCELERATION` profile, HTTP requests also use a
deterministic per-session cache model. The adapter derives a cache key from the
user key, host, URI, accepted encoding, and user agent; cache hits expose
`CACHE_REQUEST` and `CACHE_RESPONSE`, while origin responses can populate the
cache through `CACHE_UPDATE`. The `CACHE::header` surface supports
case-insensitive value, existence, insertion, replacement, and removal, and
the emulator exposes payload, hit/age/freshness, priority, expiry, trace, and
enable/disable controls. This is a bounded behavioral model: it does not
implement TMM cache eviction policy, wall-clock freshness, disk storage, or a
live Web Accelerator service.

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

Raw classic PCAP or pcapng replay is available at `POST /v1/simulations/pcap`.
The request contains an inline `scenario` and a base64-encoded `pcap_base64`
value:

```json
{
  "scenario": {
    "profiles": ["TCP", "HTTP"],
    "irule": "when HTTP_REQUEST { pool api_pool }",
    "pools": {"api_pool": ["10.0.0.1:80"]}
  },
  "pcap_base64": "<base64 pcap or pcapng bytes>",
  "direction": "auto",
  "client_addr": "10.0.0.5",
  "server_addr": "192.0.2.10"
}
```

The endpoint accepts classic PCAP or pcapng with Ethernet (including VLAN
tags) or raw IPv4 link layers, and preserves each record timestamp in the
returned packet trace. The pcapng reader supports Section Header, Interface
Description, Enhanced Packet, and Simple Packet Blocks with bounded interface
and timestamp-resolution metadata. `direction` defaults to
`client_to_server`; `auto` requires both endpoint addresses and skips packets
that do not match either direction. The capture is bounded to 16 MiB, 1,000
records, and 2 MiB per packet. IPv4 fragments are not supported yet. TCP sequence numbers are honored for
bounded out-of-order reassembly and retransmission de-duplication. HTTP
request and response payloads honor `Content-Length` and chunked transfer
framing, including partial bodies split across TCP packets and response
trailers. Coalesced messages are emitted in order, while an incomplete next
message remains buffered in the connection stream.

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
  http://127.0.0.1:8080/v1/sessions | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
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
- `irule_pcap_replay` replays a base64-encoded classic PCAP or pcapng capture through the same
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
  http://127.0.0.1:8080/v1/sessions | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')
curl -sS -X POST -H 'Content-Type: application/json' \
  --data '{"event":"DNS_REQUEST","state":{"dns":{"qname":"example.com","qtype":"A"}}}' \
  "http://127.0.0.1:8080/v1/sessions/${DNS_SESSION}/events"
curl -sS -X DELETE "http://127.0.0.1:8080/v1/sessions/${DNS_SESSION}"
```

Requests may include a string `body`, plus `response_headers` and
`response_body` to model the upstream response. They may also include
`lb_failure` with one of `no_member`, `unreachable`, `queue_limit`, or
`connection_timeout`; this injects a bounded load-balancer failure before the
serverside flow and fires `LB_FAILED`, allowing the rule to inspect
`event info` and recover with a fallback pool or `LB::reselect`. A configured
pool with no available members automatically produces the `no_member` cause.
When `HTTP::retry` is called from `HTTP_RESPONSE` or `HTTP_RESPONSE_DATA`, the
adapter replays the transaction on the persistent session. An empty argument
replays the original request; a URI or well-formed raw HTTP request can replace
the method, URI, headers, host, and body. Retries are bounded to eight replay
attempts and are reported in the result as `retry.attempts` and
`retry.exhausted`.
The returned result includes the final request/response headers and bodies
after the iRule runs. For
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
lifecycle metadata and profile metadata. Each command and event also has a
`target_status`; the pinned upstream registry is intentionally broader than
17.5, so entries introduced after TMOS 17.5 remain visible for catalog
completeness but are marked `introduced-after-tmos-17.5`.

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capabilities --offset 0 --limit 100
```

Use the returned `chunk.has_more` and advance `offset` by `chunk.count` until
all commands are consumed. This is a registry/capability view, not a claim
that generated stubs reproduce production TMM semantics; the distinction is
explicit in `runtime_status`. The conformance report separately exposes the
17.5-compatible count and the post-target entries. Scenarios using a known
post-17.5 command or event are rejected rather than executed against a stub.
The same distinction is included in each simulation/session
`fidelity.warnings` report, so callers can fail closed or ask for a
higher-fidelity test when needed.

## Structured packet traces

One-shot scenarios may use `packets` instead of `request`/`requests`. A trace
is a bounded sequence of structured packet records. TCP SYN/FIN/RST, TCP
payloads, TLS handshake/data records, HTTP
request/response pairs, WebSocket upgrade/frame packets, DNS request/response
messages, and SIP request/response messages are translated into the same Tcl events and state
layers used by the HTTP API. Generic UDP payloads are reported as unmapped
because there is no protocol-specific event to infer. WebSocket support is a
structured packet adapter: it models the HTTP upgrade and the eight WebSocket
frame/data events, and the raw TCP/PCAP path decodes RFC 6455 frames after a
successful upgrade. Compressed frames using unsupported RSV extensions are
rejected; IPv4 fragment handling remains outside this slice.
HTTP/2 wire packets use `protocol: "http2"` and a lossless `payload_hex`
field. Binary TCP captures can instead use `protocol: "tcp"` with
`payload_hex`; the adapter recognizes a client HTTP/2 prior-knowledge preface
even when that preface is split across TCP segments, then routes both TCP
directions through the same decoder. The decoder accepts frame boundaries
split across packets, HEADERS plus CONTINUATION blocks, per-direction HPACK
dynamic tables, DATA frames, SETTINGS, PRIORITY, and other control frames.
Decoded request and response streams are joined by stream ID and then pass
through the existing HTTP iRule lifecycle, including `HTTP2::*` state. Later
HEADERS blocks are modeled as request/response trailers, and one or more
informational responses are retained on the completed response. SETTINGS,
RST_STREAM, PING, GOAWAY, and WINDOW_UPDATE metadata remains visible in the
packet trace and stream-associated control frames are included in the result.
Frame payloads are capped at 1 MiB, header blocks at 1 MiB, and header count at
128; malformed padding, stream-zero data/header frames, invalid continuation
order, uppercase or invalid-token headers, duplicate pseudo-headers, and
invalid HPACK fail closed.
This is still a bounded transaction adapter, not a full HTTP/2 endpoint: it
does not implement live flow-control negotiation, server push emission, or
HTTP/2 detection inside encrypted TLS payloads or arbitrary TCP streams that
do not begin with the prior-knowledge preface.

```json
{
  "profiles": ["TCP", "HTTP"],
  "irule": "when HTTP_REQUEST { if {[HTTP2::active]} { log local0. [HTTP2::header :authority] } }",
  "packets": [{
    "protocol": "http2",
    "direction": "client_to_server",
    "payload_hex": "<HTTP/2 preface and frame bytes in hexadecimal>"
  }]
}
```
MQTT support is pinned to the 17.5-era MQTT 3.1.1 event model: structured
`CONNECT`, `CONNACK`, `PUBLISH`, subscription, acknowledgement, ping, and
disconnect packets can drive `MQTT_CLIENT_INGRESS`/`MQTT_SERVER_INGRESS`, while
`MQTT::collect` on a `PUBLISH` drives the corresponding `*_DATA` event with the
collected payload. Raw MQTT-over-TCP payloads are decoded after bounded TCP
reassembly, including messages split across segments and multiple messages in
one segment. `MQTT::payload`, `MQTT::drop`, `MQTT::release`, and the common
MQTT field getters/setters are semantic mocks; `MQTT::replace`, `respond`,
`insert`, and `will` remain explicitly reported as generated-stub catalog
entries. See the F5 [`MQTT`](https://clouddocs.f5.com/api/irules/MQTT.html),
[`MQTT::collect`](https://clouddocs.f5.com/api/irules/MQTT__collect.html), and
[`MQTT::payload`](https://clouddocs.f5.com/api/irules/MQTT__payload.html)
references for the production command/event contract.
SIP support is pinned to the 17.5 SIP message-event model. A structured SIP
packet uses `protocol: "sip"`, `type: "request"` or `type: "response"`, and
request/response-specific start-line fields. The adapter emits the ingress,
send, and done events for each direction:
`SIP_REQUEST`, `SIP_REQUEST_SEND`, `SIP_REQUEST_DONE`, `SIP_RESPONSE`,
`SIP_RESPONSE_SEND`, and `SIP_RESPONSE_DONE`. Raw SIP over TCP is recognized
after TCP reassembly and framed using `Content-Length`, including split and
coalesced messages; raw SIP over UDP accepts one complete datagram. Header
names are case-insensitive and compact aliases such as `v` and `i` are
handled. The semantic overlay covers SIP header/payload access and mutation,
request/response fields, Via/Route helpers, `SIP::respond`, `SIP::discard`,
and message-level `SIP::persist` settings. The latter does not yet implement
the BIG-IP Message Routing Framework route table or persistence store. See the
F5 [`SIP`](https://clouddocs.f5.com/api/irules/SIP.html),
[`SIP::header`](https://clouddocs.f5.com/api/irules/SIP__header.html),
[`SIP::payload`](https://clouddocs.f5.com/api/irules/SIP__payload.html),
[`SIP::respond`](https://clouddocs.f5.com/api/irules/SIP__respond.html), and
[`SIP::persist`](https://clouddocs.f5.com/api/irules/SIP__persist.html)
references for the production command/event contract.
Diameter support is pinned to the 17.5 catalog. Structured
`protocol: "diameter"` packets and raw Diameter-over-TCP packets drive
`DIAMETER_INGRESS` or `DIAMETER_EGRESS`; a packet with the retransmit flag also
drives `DIAMETER_RETRANSMISSION`. The codec validates the version, 24-bit
message length, AVP padding, vendor AVPs, request/proxiable/error/retransmit
flags, command/application identifiers, and hop-by-hop/end-to-end identifiers.
AVPs can be supplied as UTF-8, hexadecimal, base64, or 32/64-bit unsigned
values. The semantic overlay covers the catalogued Diameter header, AVP,
payload, host/realm, result, session, routing-status, persistence,
respond/drop/disconnect, retransmission, retry, and dynamic-route controls.
Header and AVP mutations rebuild the modeled wire message, and raw TCP
reassembly handles split and coalesced Diameter messages. This is a bounded
message/router model: it does not implement a live Diameter peer, realm/route
table, capability exchange, transport timers, or production persistence
storage. For example:

```json
{
  "profiles": ["TCP", "DIAMETER"],
  "irule": "when DIAMETER_INGRESS { if {[DIAMETER::result] == 5001} { DIAMETER::drop } }",
  "packets": [{
    "protocol": "diameter",
    "type": "request",
    "command_code": 272,
    "application_id": 4,
    "avps": [
      {"code": 263, "data": "session-1"},
      {"code": 268, "type": "unsigned32", "data": "2720"}
    ]
  }]
}
```
See the F5 [`DIAMETER`](https://clouddocs.f5.com/api/irules/DIAMETER.html),
[`DIAMETER::avp`](https://clouddocs.f5.com/api/irules/DIAMETER__avp.html), and
[`DIAMETER::header`](https://clouddocs.f5.com/api/irules/DIAMETER__header.html)
references for the production command/event contract.
Message Routing Framework support is also pinned to the 17.5 catalog.
Structured `protocol: "mr"` packets model generic-message ingress and egress
over TCP, with `MR_DATA` emitted when an ingress rule requests payload
collection and `MR_FAILED` available for an explicitly failed route. The
semantic overlay exposes `MESSAGE::proto`, `MESSAGE::type`,
`MESSAGE::field`, `GENERICMESSAGE::message`, `GENERICMESSAGE::peer`,
`GENERICMESSAGE::route`, and the core `MR::` state controls for collection,
routing, retry, return, streaming, and stored variables. This is a bounded
message-router model: it does not open real peer connections, implement a
production route table, or reproduce TMM connection selection and retry
timers.

```json
{
  "profiles": ["MR"],
  "irule": "when MR_INGRESS { if {[MESSAGE::type] eq \"request\"} { MR::message route config tcp_tc host 192.0.2.10:5060 } }",
  "packets": [{
    "protocol": "mr",
    "proto": "generic",
    "type": "request",
    "fields": {"kind": "health-check"},
    "payload": "ping"
  }]
}
```
See the F5 [`MR::message`](https://clouddocs.f5.com/api/irules/MR__message.html),
[`MR::collect`](https://clouddocs.f5.com/api/irules/MR__collect.html), and
[`MESSAGE::field`](https://clouddocs.f5.com/api/irules/MESSAGE__field.html)
references for the production command/event contract.
RADIUS support is pinned to the 17.5 AAA event model. Structured
`protocol: "radius"` packets and raw UDP packets on ports 1812/1813 drive
`RADIUS_AAA_AUTH_REQUEST`, `RADIUS_AAA_AUTH_RESPONSE`,
`RADIUS_AAA_ACCT_REQUEST`, or `RADIUS_AAA_ACCT_RESPONSE` based on direction
and RADIUS code. The codec validates the 20-byte header, message length,
attribute lengths, standard attributes, and Vendor-Specific attributes (type
26). `RADIUS::avp` supports named or numeric attributes, string/octet,
integer, integer64, and IP address values, including indexed vendor
attributes; `RADIUS::code`, `RADIUS::id`, `RADIUS::rtdom`, and
`RADIUS::subscriber` expose deterministic message/session state. This is a
bounded packet model and does not perform shared-secret authentication,
password hiding, live AAA, or RADIUS retransmission timers. See the F5
[`RADIUS`](https://clouddocs.f5.com/api/irules/RADIUS.html) and
[`RADIUS::avp`](https://clouddocs.f5.com/api/irules/RADIUS__avp.html)
references for the production command/event contract.
GTP support is pinned to the TMOS 17.5 catalog. Structured `protocol: "gtp"`
packets model GTPv1 or GTPv2 signaling and G-PDU messages. A GTP packet with
`type: 255` is treated as a G-PDU and exposes its payload; other messages may
carry bounded typed IEs using `type`, `instance`, and one of `data`,
`data_hex`, or `data_base64`. UDP packets on port 2123 or 2152 are decoded as
GTP-C/GTP-U, while TCP packets on port 3386 are decoded as GTP-Prime after
sequence-aware reassembly. The adapter emits `GTP_SIGNALLING_INGRESS` or
`GTP_SIGNALLING_EGRESS`, `GTP_GPDU_INGRESS` or `GTP_GPDU_EGRESS`, and
`GTP_PRIME_INGRESS` or `GTP_PRIME_EGRESS` according to the message and
direction.

For structured packets, supplying `payload` or `payload_hex` without `type`
infers G-PDU (`type: 255`); packets without a payload retain the signaling
default (`type: 1`).

The semantic overlay implements `GTP::header`, `GTP::ie`, `GTP::length`,
`GTP::message`, `GTP::payload`, `GTP::discard`, `GTP::respond`,
`GTP::forward`, `GTP::clone`, `GTP::new`, `GTP::parse`, and `GTP::tunnel`.
Header and G-PDU payload mutations rebuild the modeled wire message. The
`GTP::tunnel` accessors return the inner IP version/protocol, addresses, and
TCP/UDP ports when the payload is a complete IPv4/IPv6 datagram. Message
objects, GTP extension-header registries, 3GPP IE value decoding, tunnel
session state, live peer connections, and timer-driven retransmission are
outside this deterministic boundary.

```json
{
  "profiles": ["GTP"],
  "irule": "when GTP_SIGNALLING_INGRESS { if {[GTP::ie exists cause:0]} { GTP::header sequence set 12 } }",
  "packets": [{
    "protocol": "gtp",
    "version": 2,
    "type": 32,
    "teid": 305419896,
    "sequence": 7,
    "ies": [{"type": 2, "instance": 0, "data_hex": "01"}]
  }]
}
```

See the F5 [`GTP::header`](https://clouddocs.f5.com/api/irules/GTP__header.html),
[`GTP::ie`](https://clouddocs.f5.com/api/irules/GTP__ie.html), and
[`GTP::tunnel`](https://clouddocs.f5.com/api/irules/GTP__tunnel.html)
references for the production command/event contract.

DNS traces expose the question, header fields, and answer, authority, and
additional resource-record sections. Structured records may be supplied as
objects with `name`, `type`, `class`, `ttl`, and `rdata`, or as standard DNS
text such as `example.com. 60 IN A 192.0.2.10`. Within `DNS_REQUEST` and
`DNS_RESPONSE`, the emulator supports RR-object iteration and mutation with
`DNS::answer`, `DNS::authority`, `DNS::additional`, `DNS::rr`, `DNS::name`,
`DNS::type`, `DNS::class`, `DNS::ttl`, and `DNS::rdata`; header inspection and
mutation with `DNS::header`; bounded `DNS::scrape`; EDNS0 controls; and
`DNS::drop`, `DNS::disable`, `DNS::enable`, `DNS::last_act`, `DNS::return`,
`DNS::ptype`, and `DNS::len`. `DNS::return` from a request produces a bounded
follow-up `DNS_RESPONSE` event carrying the mutated message state. `DNS::query`
filters the supplied deterministic RR sections as a DNS-Express-shaped test
fixture, while recursive resolution, DNSSEC, TSIG, compression-preserving
re-encoding, and live nameserver behavior remain outside the boundary.

Resolver-backed rules can use the same deterministic records through
`RESOLVER::name_lookup`, `DNSMSG::header`, `DNSMSG::section`,
`DNSMSG::record`, and `RESOLVER::summarize`. Add a `resolvers` object to the
scenario; each resolver name maps to an RR array. Lookups never access the
network and return only records whose owner name and type match the query.

```json
{
  "profiles": ["TCP"],
  "resolvers": {
    "/Common/r1": [{
      "name": "www.example.com.",
      "type": "A",
      "class": "IN",
      "ttl": 120,
      "rdata": "192.0.2.20"
    }]
  },
  "irule": "when CLIENT_ACCEPTED { set m [RESOLVER::name_lookup /Common/r1 www.example.com A]; set rr [lindex [DNSMSG::section $m answer] 0]; log local0. [DNSMSG::record $rr rdata] }"
}
```

```json
{
  "profiles": ["UDP", "DNS"],
  "irule": "when DNS_REQUEST { set rr [DNS::rr \"[DNS::question name]. 30 IN A 192.0.2.10\"]; DNS::answer clear; DNS::answer insert $rr; DNS::header aa 1; DNS::return }",
  "packets": [{
    "protocol": "dns",
    "qname": "example.com",
    "qtype": "A"
  }]
}
```

For raw IPv4/UDP DNS, the decoder handles compressed names and common A,
AAAA, CNAME, NS, PTR, MX, SRV, and TXT resource records. See the F5
[`DNS::answer`](https://clouddocs.f5.com/api/irules/DNS__answer.html),
[`DNS::rr`](https://clouddocs.f5.com/api/irules/DNS__rr.html),
[`DNS::header`](https://clouddocs.f5.com/api/irules/DNS__header.html), and
[`DNS::scrape`](https://clouddocs.f5.com/api/irules/DNS__scrape.html)
references for the production command contract.

TLS packet state also drives the common SSL inspection path. In
`CLIENTSSL_*` and `SERVERSSL_*` events, the semantic overlay supports
`SSL::sni`, `SSL::cipher`, `SSL::sessionid`, `SSL::cert`,
`SSL::verify_result`, and side-specific `SSL::disable`/`SSL::enable`.
Certificate handles can be inspected with `X509::subject` and
`X509::issuer`. Certificate and cipher values are deterministic packet input;
the emulator does not perform a TLS handshake, certificate validation, key
exchange, or cryptographic renegotiation.

```json
{
  "profiles": ["TCP", "CLIENTSSL"],
  "irule": "when CLIENTSSL_CLIENTHELLO { set cert [SSL::cert 0]; log local0. \"[SSL::sni name] [SSL::cipher name] [X509::subject $cert commonName]\" }",
  "packets": [{
    "protocol": "tls",
    "direction": "client_to_server",
    "type": "client_hello",
    "sni": "secure.example.com",
    "cipher_name": "TLS_AES_128_GCM_SHA256",
    "cipher_bits": 128,
    "cert_count": 1,
    "cert_subject": "CN=client.example.com,O=Example"
  }]
}
```

HTTP/2 metadata can be attached to a structured HTTP transaction with an
`http2` object. This drives the reusable `tcl-lsp` pseudo-header and stream
handlers plus semantic `HTTP2::active`, `HTTP2::version`,
`HTTP2::requests`, `HTTP2::concurrency`, `HTTP2::enable`, `HTTP2::disable`,
and `HTTP2::disconnect` behavior. Header names are validated as lowercase
HTTP/2 pseudo-headers, stream IDs are bounded to 31 bits, and priorities to
8 bits. The current slice models decoded transaction state; it does not parse
HTTP/2 frames, implement HPACK, multiplex live streams, or emit
`HTTP2::push` responses.

```json
{
  "profiles": ["TCP", "HTTP"],
  "irule": "when HTTP_REQUEST { if {[HTTP2::active] && [HTTP2::header :authority] contains \"api\"} { HTTP2::stream priority 32 } }",
  "request": {
    "method": "GET",
    "uri": "/health",
    "host": "api.example.com",
    "http2": {
      "active": true,
      "version": 2,
      "stream_id": 3,
      "concurrency": 2,
      "requests": 4,
      "pseudo_headers": {
        ":authority": "api.example.com",
        ":method": "GET",
        ":path": "/health",
        ":scheme": "https"
      }
    }
  }
}
```

For raw captures, use `protocol: "wire"`, `network: "ipv4"`, and an IPv4
packet in `raw_hex`; the current decoder rejects fragmented IPv4 packets and
performs bounded sequence-aware TCP application reassembly across records and
persistent session calls, including out-of-order segments and duplicate
retransmissions. Classic PCAP and pcapng file/HTTP/MCP ingestion is supported
separately; IPv4 fragment handling remains outside this slice.

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
HTTP transaction results. TCP responses and graceful FIN requests emitted by
`TCP::respond`/`TCP::close` are exposed both on the event as `emissions` and in
the top-level `emitted` array, with their modeled egress direction. Data
emissions include byte length; FIN emissions include `control: "FIN"`. Persistent sessions accept the
same packet array at
`POST /v1/sessions/{session_id}/packets`, or through the MCP
`irule_session_trace` tool.

HTTP data events are only produced by the high-level request flow after
`HTTP::collect` has armed the corresponding request or response body and the
requested byte threshold is available. `HTTP::release` is modeled in the data
events: it clears the active collection window and is reported as
`http_release: true` in the transaction result. Explicit event injection
remains available through the event API for lower-level tests. The
`HTTP_REQUEST_RELEASE` and `HTTP_RESPONSE_RELEASE` events follow their
respective data events, and body commands such as `HTTP::payload` and
`HTTP::collect` are rejected in those release contexts.

Raw packet replay also preserves interim HTTP responses: a `100 Continue`
frame fires `HTTP_RESPONSE_CONTINUE` without completing the pending request,
so a later final response supplies the transaction result. Other non-final
1xx frames remain interim in the packet trace.

WebSocket packets use `protocol: "websocket"`. Upgrade requests require
`type: "request"`, `direction: "client_to_server"`, and `headers`; upgrade
responses use `type: "response"`, `direction: "server_to_client"`, and
`response_headers`. Frame packets use `type: "frame"`, `frame_type` (`text`,
`binary`, `continuation`, `close`, `ping`, or `pong`), optional `fin`, `masked`,
and `mask`, plus an optional text `payload`. A valid request followed by a 101
response enables `WS_REQUEST`/`WS_RESPONSE`; subsequent frames drive
`WS_CLIENT_FRAME` or `WS_SERVER_FRAME`, optional collected data events, and the
corresponding frame-done event. `WS::payload` offsets and lengths are modeled
as wire-byte counts, including UTF-8 payloads. Incomplete upgrades, disabled
WebSocket processing, and frames before a completed handshake are reported as
ignored trace entries. Raw TCP frames are reassembled across packets, including
partial frames, coalesced frames, client masking, and fragmented messages.
`WS::frame drop` and `WS::message drop` suppress the
corresponding collected data event and mark the packet as dropped. `WS::release`
clears the collection window; incoming frame payloads are bounded by the same
2 MiB stream limit as TCP reassembly. Control frames are not added to a data
collection window.
`WS::disconnect` records its close code and reason as a decision and emits a
modeled CLOSE frame result for both endpoints with the RFC 6455 close payload
bytes in `payload_hex`. The result is intentionally an egress model rather than
a claim that the adapter is a complete TMM connection teardown.

For a classic PCAP or pcapng file, keep the iRule scenario in a JSON file and replay it
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
traces, classic PCAP and pcapng replay, sequence-aware persistent connection sessions,
structured DNS/TLS/SIP/RADIUS event injection, catalog conformance reporting, an MCP
facade over the same JSON contract, and an adapter-owned semantic overlay for
selected HSL, HTTP, IP, LB, PROFILE, STATS, URI, persistence, table, TCP, and
HTTP cookie commands, PSM FTP/HTTP/SMTP protocol controls, SSL inspection and
control state, plus SIP request/response message adaptation and common global string, base64, data-group, and pool
health and pool inventory functions, URI decoding, dotted-domain extraction, CRC32,
and binary-compatible MD5/SHA1/SHA256/SHA384/SHA512 digests. The DOSL7 policy
surface is modeled through deterministic scenario inputs, connection controls,
health/profile queries, mitigation flags, and source-IP greylist state.
It also models multimap lookup through `llookup`. The semantic overlay also models data-group `class`
matching, lookup, enumeration, connection-scoped search iterators, and
request/response cookie mutations. TCP payload access is directional for
client/server data events and supports byte-length, replacement, collection,
offset, release, and response bookkeeping. `TCP::collect` gates data events
until the requested length and skip window is available; the no-argument form
continues to fire for each received packet until `TCP::release`, while explicit
lengths consume one collection window. Partial buffers are preserved across
calls on a persistent session. `peer`, `clientside`, and `serverside` execute
nested command blocks under the corresponding connection context. The
`HTTP::retry` overlay preserves the final request/response state while exposing
the replay count and exhaustion status; transport-level socket reset behavior
from `HTTP::retry -reset` is not separately simulated yet. The
`HTTP::is_keepalive` and `HTTP::header is_keepalive` paths derive their result
from the active side's `Connection` header and HTTP version. Redirect detection
matches the documented 301, 302, 303, 305, and 307 responses only when a
`Location` header is present. The `HTTP::request_num` overlay counts logical
requests on the current persistent connection, does not increment for an
internal `HTTP::retry` replay, and resets when the adapter starts a new
connection. `HTTP::close` performs the corresponding emulated connection
teardown, including `CLIENT_CLOSED`, before the next request can start a new
connection. `LB::server` reports the selected pool/member tuple and supports
the common `pool`, `addr`, `port`, `priority`, and `ratio` selectors; direct
`node` overrides intentionally report the pool without claiming a pool member.
`HTTP::request` and `HTTP::response` reconstruct raw header blocks with request
or status lines and terminal CRLFs; request/response payloads remain separate
through the payload collection APIs. `HTTP_RESPONSE_CONTINUE` is emitted for
raw `100 Continue` responses while the pending HTTP transaction remains open.
`HTTP::redirect` commits a 302 response with a `Location` header and clears
the response body; `HTTP::has_responded` reports that commitment to later
rule logic. The emulator profile remains fixed at `tmos-17.5`.
