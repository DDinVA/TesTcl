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

## Real-client HTTP data plane

For an end-to-end smoke test, run the optional data plane against a scenario
file. It accepts real HTTP/1.x clients, keeps one emulator session per TCP
connection, and returns the modeled response produced by the iRule and the
deterministic `live_origin` fixture:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --data-plane --host 127.0.0.1 --port 18080 \
  --scenario examples/scenarios/live-http-17.5.json
curl -i http://127.0.0.1:18080/health
```

The fixture uses `live_origin` with optional `status`, `headers`, and `body`
fields. Actual request fields are supplied by the client; origin fields are
defaults that the iRule may inspect or replace with `HTTP::respond` or
`HTTP::redirect`. Request bodies are limited to 2 MiB, chunked request bodies
are rejected explicitly, and response hop-by-hop headers are normalized by the
listener. This is a deterministic HTTP data-plane adapter, not a kernel TCP
stack or full live proxy. It can terminate bounded HTTPS with a configured
certificate and key, and can connect to an HTTPS upstream with explicit
certificate verification settings. HTTP/1.1 uses TLS 1.2 or newer when enabled.

For a real TLS client using HTTP/2, set `live_data_plane.protocol` to `http2`.
The listener advertises ALPN `h2`, decodes the client preface plus bounded
HEADERS/DATA frames with HPACK, and runs the same staged `HTTP_REQUEST`,
optional body collection, origin, and `HTTP_RESPONSE` lifecycle. It can use
either the deterministic `live_origin` fixture or a configured TLS h2 upstream;
cleartext prior-knowledge mode is rejected. The h2 upstream path sends the
iRule-mutated request over a fresh bounded TLS connection, requires ALPN `h2`,
decodes HPACK response headers and DATA, and feeds connection failures through
`LB_FAILED` and the mapped-member fallback scheduler. The listener caps each
connection at 2 MiB and 128 concurrent request streams; TLS session resumption
and BIG-IP SSL profile semantics remain outside this adapter. The checked-in
[`live-http2-17.5.json`](../examples/scenarios/live-http2-17.5.json) scenario
shows the certificate paths expected when running the container with mounted
secrets.

To exercise a real HTTP backend, replace `live_origin` with
`live_data_plane.upstream`. The direct `{host, port}` form sends the
iRule-mutated request to one backend. The pool form uses the same mapped target
and bounded scheduler model as raw TCP; `HTTP_REQUEST` runs before the backend
request is sent, and `HTTP_RESPONSE` plus response-body collection run after the
backend reply is received. For `protocol: "http2"`, the upstream must include
TLS settings and negotiate ALPN `h2`; for HTTP/1.1, an upstream TLS block is
optional and negotiates `http/1.1`. Backend response bodies are capped at 2 MiB
and hop-by-hop headers are not forwarded through the adapter. The checked-in
[`live-http-upstream-17.5.json`](../examples/scenarios/live-http-upstream-17.5.json)
scenario is a minimal example.

When a real HTTP upstream connection fails, the adapter fires `LB_FAILED` with
`unreachable` or `connection_timeout` as the bounded `event info` cause. A
rule can select another mapped pool/member with `pool` and `LB::reselect`, or
commit a local response with `HTTP::respond`; failed mapped members are also
placed in the live scheduler's temporary cooldown. Omit `upstream.pool` when
an `LB_FAILED` handler is allowed to move between pools, because specifying it
intentionally restricts resolution to that one pool.

To expose the same listener over HTTPS, add `live_data_plane.tls` with local
certificate material. Paths are read by the local CLI/container process, so a
container deployment should mount them explicitly:

```json
{
  "live_data_plane": {
    "protocol": "http",
    "tls": {
      "certfile": "/run/secrets/testcl/server.pem",
      "keyfile": "/run/secrets/testcl/server.key"
    }
  }
}
```

`client_auth` may be `none` (the default), `optional`, or `required`; the
last two modes also require `cafile`. A mapped or direct HTTP upstream may
set `tls.verify` (default `true`), `tls.cafile`, and an optional client
`certfile`/`keyfile` pair. Set `verify` to `false` only for an intentionally
insecure local fixture. The live listener reports `https://...` when TLS is
enabled. Actual SSL certificate fields are not automatically injected into
iRule `SSL::cert` state; use the packet-level TLS adapters or explicit
scenario state for those semantics.

## Real-client WebSocket data plane

Set `live_data_plane.protocol` to `websocket` to accept a real RFC 6455 client:

```json
{
  "profiles": ["TCP", "HTTP", "WS"],
  "irule": "when WS_CLIENT_FRAME { WS::collect frame } when WS_CLIENT_DATA { WS::payload replace 0 5 world }",
  "live_data_plane": {"protocol": "websocket", "read_timeout": 1.0}
}
```

The listener validates the HTTP/1.1 upgrade and client masking, runs the
persistent `WS_REQUEST`/`WS_RESPONSE` and frame/data/done lifecycle, echoes
text/binary/continuation frames after iRule payload mutation, answers pings
with pongs, and honors `WS::frame drop`, `WS::message drop`, and close
emissions. It enforces bounded headers, frames, control-frame rules, and
fragmentation ordering. This first live slice uses a deterministic local peer;
with `live_data_plane.upstream` it can instead complete a real upstream
WebSocket upgrade and bridge frames in both directions. Direct `{host, port}`
and pool-mapped `targets` forms are supported; pool selection follows the
`WS_REQUEST` iRule lifecycle. A failed mapped member is cooled down, fires
`LB_FAILED`, and can be replaced by an iRule-selected pool plus
`LB::reselect`; the live scheduler will not retry an already attempted member.
Upstream TLS is optional for `ws://` fixtures and uses the
same explicit verification settings as HTTP/1.1 when configured. TLS
termination is available with the same `live_data_plane.tls` block described
above. The checked-in [`live-websocket-upstream-17.5.json`](../examples/scenarios/live-websocket-upstream-17.5.json)
shows the pool-mapped upstream shape.

For raw TCP clients, add an explicit `live_data_plane` object to the scenario:

```json
{
  "profiles": ["TCP"],
  "irule": "when CLIENT_ACCEPTED { TCP::collect } when CLIENT_DATA { TCP::respond [TCP::payload]; TCP::release; TCP::collect }",
  "live_data_plane": {"protocol": "tcp", "read_timeout": 1.0}
}
```

Run the included echo fixture with a normal TCP client:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --data-plane --host 127.0.0.1 --port 18081 \
  --scenario examples/scenarios/live-tcp-17.5.json
printf 'hello from tcp\n' | nc -N 127.0.0.1 18081
```

The raw listener creates one persistent emulator session per TCP connection,
feeds each bounded read through the normal TCP packet adapter, and forwards
server-directed `TCP::respond` data. Wire reads enter the packet adapter as
`payload_hex`, so `TCP::payload`, byte lengths, offsets, replacements, and
binary Tcl operations see the original bytes. JSON results retain readable
payload text and add `payload_hex` when a value is not losslessly representable
as UTF-8. EOF, timeout, `TCP::close`, and the 2 MiB connection read limit
terminate the stream. With an explicit upstream target, ordinary TCP bytes and
`TCP::release` output cross a bounded client-to-backend-to-client bridge;
`SERVER_INIT` and `SERVER_CONNECTED` are fired when the backend socket opens,
and server-side `TCP::respond` output is sent to that backend. The upstream
target is opt-in and supports only a hostname/address, port, and connect
timeout in its direct form. For pool-aware testing, use upstream.pool plus a
targets map keyed by the member names in pools; the iRule must select that pool
(for example, pool app_pool) and the selected member must have a target mapping.
Set the scenario's `pool_modes` entry to `round_robin` to rotate mapped members
across separate real client connections. A failed target is quarantined for
`upstream.failure_cooldown` seconds (one second by default), and the handler
tries the remaining eligible members. This is still not a kernel TCP stack, TLS
endpoint, or full database peer. Protocol-specific TDS, FTP, LDAP, and similar
parsers are exercised through the packet/API drivers.

For example, a raw TCP scenario can bridge to a local test service with:

```json
{
  "profiles": ["TCP"],
  "pools": {"app_pool": ["backend-a:19000"]},
  "pool_modes": {"app_pool": "round_robin"},
  "irule": "when CLIENT_ACCEPTED { pool app_pool; TCP::collect } when CLIENT_DATA { TCP::release; TCP::collect } when SERVER_DATA { TCP::release; TCP::collect }",
  "live_data_plane": {
    "protocol": "tcp",
    "read_timeout": 1.0,
    "upstream": {
      "pool": "app_pool",
      "targets": {
        "backend-a:19000": {"host": "127.0.0.1", "port": 19000}
      },
      "connect_timeout": 2.0,
      "failure_cooldown": 1.0
    }
  }
}
```

The bridge is deliberately bounded to `max_read_bytes` per direction (2 MiB
by default), does not interpret the backend protocol, and closes the stream
when no eligible backend can be connected or after an idle timeout. Its shared
live scheduler is intentionally limited to configured target maps, one
round-robin cursor per pool, and temporary failure cooldowns; it does not claim
to reproduce all TMM scheduling, monitor, or BIG-IP networking internals.

The API and data plane can run together by starting the normal API with
`--serve --data-plane-scenario PATH`; the API remains on `--host/--port`, while
the data plane defaults to `127.0.0.1:18080` and can be changed with
`--data-plane-host` and `--data-plane-port`.

In combined mode, the API also retains a bounded, in-memory observation stream
from real-client data-plane traffic. `GET /v1/live-observations?limit=50`
returns the most recent transaction, stream, frame, TCP data, or HTTP/2 wire
results with
their protocol, phase, direction, and emulator session ID. Use
`DELETE /v1/live-observations` between test cases. The stream is intentionally
not persisted and is diagnostic emulator output, not independent TMOS/vLab
evidence. A ready-to-run smoke test is available at
[`scripts/live-observation-smoke.sh`](../scripts/live-observation-smoke.sh).
For a raw TCP byte-to-replay-plan check, use
[`scripts/live-packet-observation-smoke.sh`](../scripts/live-packet-observation-smoke.sh).
To turn captured live inputs into an external-reference plan, POST a scenario
and optional observation IDs to `/v1/live-observations/capture-plan`; the
response is a plan without outputs. HTTP transactions become one request
scenario per observation. TCP and WebSocket packet observations are grouped by
live session, preserving connection/frame order. HTTP/2 wire observations
retain the decrypted application bytes exactly as received, including arbitrary
preface/frame chunking, and export as `protocol: "http2"` packets. The exporter copies only
replay inputs, so trace indexes, events, forwarding decisions, and modeled
outputs are excluded. Fill the plan's records from BIG-IP/vLab, then
send the plan and records to `/v1/observations/assemble` before running
`/v1/differential-vectors`.

For the HTTP smoke test, the capture-plan request can be generated from the
same scenario file after the real request has completed:

```sh
curl -sS -X POST -H 'Content-Type: application/json' \
  --data "{\"scenario\":$(<examples/scenarios/live-http-17.5.json)}" \
  http://127.0.0.1:18090/v1/live-observations/capture-plan
```

The returned plan is intentionally not proof of TMOS behavior. It is the
portable replay input that an external collector can pair with its observed
output.

### Promote a completed capture batch

`tools/tmos17-capture-runner.py` stores collector output as resumable NDJSON.
Once every plan has been collected, promote the complete batch into one
golden-vector pack per plan:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp \
uv run --python 3.13 python tools/tmos17-capture-assemble.py \
  --manifest /tmp/tmos-17.5-batch/manifest.json \
  --records /tmp/tmos-17.5-batch/records.ndjson \
  --output-dir /tmp/tmos-17.5-packs \
  --verify
```

The output directory is created atomically and must not already exist. Packs
remain bounded to the same 256-vector limit as the capture plans. `--verify`
replays each pack through the local emulator and writes a report under
`reports/`; a failed comparison leaves the pack and report available for
inspection while returning a failing status. This is the handoff from external
TMOS/vLab observations to checked-in differential contracts. The tool performs
no device I/O.

## Command workbench

Use the command workbench to exercise one target-valid F5 command from the
pinned TMOS 17.5 catalog without writing a temporary iRule. The workbench
generates a single event wrapper, quotes every argument as one Tcl word, runs
it through the normal event lifecycle, and returns the command value together
with event observations. It accepts F5 iRule commands only; Tcl core and
Tcllib entries remain available through normal scenario execution.

The HTTP and MCP surfaces accept this request shape. `request` supplies a
structured HTTP transaction for `HTTP_REQUEST` or `HTTP_RESPONSE`; use
`state` for other catalogued events. `scenario` is optional and may contain
fixture configuration such as profiles, pools, data groups, or semantic
subsystem inputs, but may not contain an iRule, request list, packet list, or
local file reference.

```json
{
  "command": "HTTP::header",
  "args": ["value", "X-Experiment"],
  "event": "HTTP_REQUEST",
  "profiles": ["TCP", "HTTP"],
  "request": {
    "method": "GET",
    "uri": "/health",
    "host": "api.example.com",
    "headers": {"X-Experiment": "enabled"}
  }
}
```

Run it from the CLI:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --command-probe <<'JSON'
{"command":"HTTP::host","event":"HTTP_REQUEST","request":{"host":"api.example.com"}}
JSON
```

The same operation is available as `POST /v1/command-probes` and the MCP tool
`irule_command_probe`. A successful command returns `execution.status` of
`ok`, the Tcl return code, text and base64 forms of the value, byte length,
and the event result. A Tcl command error is reported as
`execution.status: "error"`; a missing required profile is reported as
`profile-gated`. The workbench is bounded to 64 scalar arguments, 16 KiB per
argument, and 64 KiB total argument data, and it never exposes arbitrary Tcl
evaluation.

### Catalog behavior packs

Behavior packs turn catalog entries into checked-in, reproducible contracts.
Each case contains an `id`, exactly one operation, and an `expect` object.
`probe` operations exercise one catalog command with the bounded command
workbench. `scenario` operations run an inline iRule against a bounded request
or packet sequence and assert exact values through JSON paths. Scenario packs
accept inline `irule` source only; they cannot read a local `irule_file`.
Probe expectations support exact `status`, `value`, `value_base64`,
`value_bytes`, `tcl_return_code`, and `event_fired` values, plus an
`error_contains` substring assertion. Scenario expectations contain one to 64
bounded `{path, equals}` assertions. Packs are limited to 256 cases; every
case is normalized before execution, and a malformed case prevents the pack
from running.

The repository includes
[`examples/behavior-packs/http-core-17.5.json`](../examples/behavior-packs/http-core-17.5.json),
which covers HTTP getters, headers, cookies, payloads, profile gating, and a
negative argument contract:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/http-core-17.5.json
```

The command exits non-zero when a case fails and prints every mismatch without
discarding the passing cases. The same runner is available as
`POST /v1/behavior-packs` and the MCP tool `irule_behavior_pack`. The checked-in
packs cover AAA, ACCESS, ADAPT, AES, AM, ASN1, AUTH, AVR, BWC, CACHE, CATEGORY, COMPRESS, CONNECTOR, CRYPTO, DATAGRAM, DHCPv4, DHCPv6, DNSMSG, DOSL7, ECA, FLOW, FTP, GTP, HSL, HTML, HTTP, HTTP/2, IKE, IMAP, IPFIX, ISTATS, LDAP, LINK, LSN, NSH, ONECONNECT, POLICY, PCP, PEM, PLUGIN, POP3, PSM, RADIUS, RESOLVER, REST, REWRITE, SMTPS, STATS, TAP, DNS, TCP, TLS/SSL, VALIDATE, X509, UDP/datagram, WebSocket, XLAT, RTSP, SCTP,
SIP/SDP/SIPALG, load-balancing, URI, stream filtering, route metrics, TMM CMP
topology, FLOWTABLE queries, classification lifecycle, profile introspection,
Message Routing controls, HTTP edge controls, MQTT protocol controls, and stateful
session/table contracts for
the pinned 17.5 profile. The integration pack exercises ILX extension calls,
request-scoped PLUGIN toggles, and network-free OFFBOX request recording. The
protocol pack exercises L7CHECK, SOCKS, ICAP, RTSP, UDP, QOE, NTLM,
PROTOCOL_INSPECTION, and TDS event state. The legacy pack exercises HTTP
logging, feature controls, diagnostics, message routing, deterministic name
resolution, DHCP versioning, HA/DS-Lite/BIGPROTO state, and response
decompression. The remaining-target pack closes the three remaining modeled
F5 17.5 commands: ACCESS2 procedure lookup, BIGTCP flow release, and NTLM
disable. The
SIP pack exercises all 16 catalogued `SIP::`
commands, nine SDP accessors, and three SIPALG controls across command probes
and request/response packet lifecycles. The HTTP/2 pack exercises active
transaction metadata, pseudo-header access/mutation, stream controls, and
push-promise construction. A catalog chunk plus its behavior pack is a
portable implementation checkpoint for adding higher-fidelity semantic mocks.

To measure how much of the F5 catalog those contracts actually exercise, use
the behavior-coverage report:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-coverage
```

The CLI reads the deterministic JSON files in `examples/behavior-packs` (or a
directory supplied with `--behavior-pack-dir`). The report includes both
direct `probe` commands and commands discovered inside `scenario` iRules,
along with pack/case/event provenance and an `add-behavior-vector` queue for
available TMOS 17.5 F5 commands that are not covered. The denominator excludes
Tcl support entries and post-17.5 commands. With the checked-in packs, the
current report covers 894 of 989 target F5 commands (90.39%). This is test-input
coverage, not a semantic-fidelity score.

Run the HTTP/2 behavior pack directly to verify the local contract:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/http2-17.5.json
```

Run the AAA behavior pack to verify request/result correlation and disabled
service handling:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/aaa-17.5.json
```

Run the ACCESS controls behavior pack to verify session and policy state,
per-flow data, SAML values, ephemeral authentication, OAuth signing, identity
lookups, request controls, and ACCESS responses:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/access-controls-17.5.json
```

Run the ADAPT controls behavior pack to verify dynamic request contexts,
enablement, IVS selection, preview and timeout controls, result overrides, and
context cleanup:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/adapt-controls-17.5.json
```

Run the AM controls behavior pack to verify acceleration metadata accessors and
connection-scoped disable state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/am-controls-17.5.json
```

Run the CRYPTO controls behavior pack to verify deterministic hashing, HMAC
signing and verification, AES round trips, and PBKDF2 key generation:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/crypto-controls-17.5.json
```

Run the COMPRESS controls behavior pack to verify response gzip policy,
compression settings, transformation, and keep-alive reset behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/compress-controls-17.5.json
```

Run the ECA controls behavior pack to verify external-content authentication
configuration, allowed-request fields, and denied-request state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/eca-controls-17.5.json
```

Run the DOSL7 controls behavior pack to verify policy inspection, enable/disable
overrides, slowdown state, and connection reset:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/dosl7-controls-17.5.json
```

Run the FLOW controls behavior pack to verify primary and related-flow handles,
timeouts, priorities, and refresh behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/flow-controls-17.5.json
```

Run the NSH controls behavior pack to verify network-service-header path,
service, context, metadata, and connection-scope state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/nsh-controls-17.5.json
```

Run the PSM controls behavior pack to verify protocol-security-module enable,
disable, and connection-reset behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/psm-controls-17.5.json
```

Run the GTP controls behavior pack to verify v2 signalling headers and
information elements, message reconstruction, G-PDU tunnel introspection,
payload mutation, response, forwarding, and discard behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/gtp-controls-17.5.json
```

Run the SCTP controls behavior pack to verify packet collection, PPI, payload
mutation, port and timer accessors, response emission, and release behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/sctp-controls-17.5.json
```

Run the IKE controls behavior pack to verify the bounded IKE_AUTH certificate
and subjectAltName accessors, plus the authentication-success action:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ike-controls-17.5.json
```

Run the PSC controls behavior pack to verify subscriber identity, collection
mutation, custom attributes, and lease-time state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/psc-controls-17.5.json
```

Run the DHCPv6 controls behavior pack to verify client header and option
accessors, option deletion, client drops, and server offer rejection:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/dhcpv6-controls-17.5.json
```

Run the BWC controls behavior pack to verify policy attachment, bandwidth and
packet controls, marking, measurement, and connection-boundary reset:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/bwc-controls-17.5.json
```

Run the LSN controls behavior pack to verify translation address/port and pool
selection, disable controls, persistence mode, and mapping-entry state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/lsn-controls-17.5.json
```

Run the WebSocket controls behavior pack to verify upgrade metadata, payload
processing, frame collection/release, message dropping, and close emission:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ws-controls-17.5.json
```

Run the XLAT controls behavior pack to verify source-translation accessors,
listener lifetime, and endpoint reservation state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/xlat-controls-17.5.json
```

Run the PCP controls behavior pack to verify request/response field accessors
and deterministic request rejection:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/pcp-controls-17.5.json
```

Run the AUTH controls behavior pack to verify authentication sessions,
credential challenges and continuation, certificate credentials, LDAP fields,
response data, and abort behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/auth-controls-17.5.json
```

Run the CACHE controls behavior pack to verify cache keys, hit replay,
response-header mutation, expiration, and enable/disable behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/cache-controls-17.5.json
```

Run the X509 controls behavior pack to verify client-certificate metadata,
validity, issuer/subject fields, PEM conversion, and public-key accessors:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/x509-controls-17.5.json
```

Run the DHCPv4 controls behavior pack to verify BOOTP header fields, option
mutation, client discovery drop, and server offer rejection:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/dhcpv4-controls-17.5.json
```

Run the CATEGORY behavior pack to verify categorization controls, match results,
safe-search, and response file-type outputs:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/category-17.5.json
```

Run the route-metric behavior pack to verify deterministic lookup and clear
semantics across successive requests:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/route-17.5.json
```

Run the TMM behavior pack to verify deterministic CMP topology values:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/tmm-17.5.json
```

Run the FLOWTABLE behavior pack to verify bounded count and limit queries:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/flowtable-17.5.json
```

Run the classification behavior pack to verify detection fields and
classification controls:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/classification-17.5.json
```

Run the PROFILE behavior pack to verify profile existence, enablement, and
profile-setting command dispatch:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/profile-17.5.json
```

Run the MR behavior pack to verify Message Routing Framework state controls:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/mr-17.5.json
```

Run the HTTP edge behavior pack to verify HTTP lifecycle controls, raw message
accessors, proxy state, and response helpers:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/http-edge-17.5.json
```

Run the MQTT behavior pack to verify protocol fields, payload controls, message
operations, and CONNECT will state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/mqtt-17.5.json
```

Run the TCP controls behavior pack to verify transport tuning persists from
`CLIENT_ACCEPTED` into `CLIENT_DATA` and that loss/recovery settings are
inspectable:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/tcp-controls-17.5.json
```

Run the SSL controls behavior pack to verify client/server handshake controls,
forward-proxy state, and staged TLS payload collection:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ssl-controls-17.5.json
```

Run the ANTIFRAUD controls behavior pack to verify deterministic login/alert
fields, policy toggles, logging, and connection-reset semantics:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/antifraud-controls-17.5.json
```

Run the ASM controls behavior pack to verify deterministic WAF policy fields,
violation/signature state, payload rewriting, and connection-reset semantics:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/asm-controls-17.5.json
```

Run the Bot Defense controls behavior pack to verify deterministic bot
classification fields, action overrides, policy controls, and connection-reset
semantics:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/botdefense-controls-17.5.json
```

Run the DIAMETER controls behavior pack to verify packet lifecycle events,
header and AVP mutation, routing/retransmission controls, and message drop or
response behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/diameter-controls-17.5.json
```

Run the IP controls behavior pack to verify packet statistics, endpoint and
header introspection, intelligence/reputation lookups, rate controls, and
address comparison:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ip-controls-17.5.json
```

Run the load-balancing controls behavior pack to verify deterministic member
selection, pool and node state, connection controls, failure fallback, queue
events, persistence, and server introspection:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/lb-controls-17.5.json
```

Run the TCP introspection behavior pack to verify connection ports, transport
metrics, TCP options, notifications, and lifecycle actions:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/tcp-introspection-17.5.json
```

Run the DNS controls behavior pack to verify RR accessors, EDNS state,
resolver queries, and DNS request controls:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/dns-controls-17.5.json
```

Run the SSL lifecycle controls behavior pack to verify client/server
enablement, disablement, and handshake responses:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ssl-lifecycle-controls-17.5.json
```

Run the RADIUS controls behavior pack to verify structured AAA packet decoding,
attribute mutation, and deterministic session metadata:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/radius-controls-17.5.json
```

Run the STATS controls behavior pack to verify persistent counters and bounded
minimum/maximum updates across requests:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/stats-controls-17.5.json
```

Run the DATAGRAM controls behavior pack to verify IPv4/UDP and IPv6/TCP packet
accessors, collection, and emitted response data:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/datagram-controls-17.5.json
```

Run the PEM controls behavior pack to verify subscriber/session database
creation, policy updates, flow state, and lifecycle events:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/pem-controls-17.5.json
```

Run the TAP controls behavior pack to verify decision action and score updates,
configuration lookup, and insight submission state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/tap-controls-17.5.json
```

Run the ISTATS controls behavior pack to verify persistent counters, gauge
updates, string values, and measure removal across requests:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/istats-controls-17.5.json
```

Run the LINK controls behavior pack to verify last-hop/next-hop identity,
quality-of-service, and VLAN metadata queries:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/link-controls-17.5.json
```

Run the ONECONNECT controls behavior pack to verify reuse, selection, labels,
and connection-reset behavior across HTTP requests:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/oneconnect-controls-17.5.json
```

Run the POLICY controls behavior pack to verify policy control/target
introspection and active, matched, unmatched, and executed-rule state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/policy-controls-17.5.json
```

Run the REWRITE controls behavior pack to verify request/response payload
replacement, byte lengths, content-length updates, and post-processing:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/rewrite-controls-17.5.json
```

Run the CONNECTOR controls behavior pack to verify connector profile state,
enable/disable, and client/server remapping:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/connector-controls-17.5.json
```

Run the plugin controls behavior pack to verify WAM, VDI, and WEBSSO request
controls and selected SSO state:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/plugin-controls-17.5.json
```

Run the AVR controls behavior pack to verify connection enablement, logging,
and CSPM injection disablement across structured events:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/avr-controls-17.5.json
```

Run the STARTTLS controls behavior pack to verify enable/disable handling for
FTP, IMAP, LDAP, POP3, and SMTPS protocol profiles:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/starttls-controls-17.5.json
```

Run the resolver/DNSMSG behavior pack to verify deterministic resolver lookup,
DNS message handles, sections, headers, and resource records:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/resolver-dnsmsg-controls-17.5.json
```

Run the IPFIX behavior pack to verify template creation, message fields,
destination handles, and response-release sends:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/ipfix-controls-17.5.json
```

Run the crypto/data behavior pack to verify ACL decisions, AES round trips,
and binary-safe ASN1 element encoding and decoding:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/crypto-data-controls-17.5.json
```

Run the integration controls behavior pack to verify external-boundary
semantics without contacting a plugin or network service:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/integration-controls-17.5.json
```

Run the protocol controls behavior pack to verify stateful event behavior for
L7CHECK, SOCKS, ICAP, RTSP, UDP, QOE, NTLM, protocol inspection, and TDS:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/protocol-controls-17.5.json
```

Run the legacy controls behavior pack to verify diagnostics, feature controls,
message routing, deterministic name resolution, and decompression:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/legacy-controls-17.5.json
```

Run the remaining-target behavior pack to verify ACCESS2, BIGTCP, and NTLM
control behavior:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/remaining-target-controls-17.5.json
```

Run the utility controls behavior pack to verify bounded HSL sends, local REST
request recording, and protocol-signature validation:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/utility-controls-17.5.json
```

For service clients, submit the packs as one bounded JSON request to
`POST /v1/behavior-coverage`:

```json
{"packs":[{"name":"http-core-17.5","cases":["..."]}]}
```

The same operation is exposed as the `irule_behavior_coverage` MCP tool. It is
read-only: it analyzes pack inputs and catalog metadata without running the
cases; use `irule_behavior_pack` or `irule_differential_vectors` to execute
them.

To turn that uncovered queue into an executable external-reference work unit,
generate a bounded candidate chunk:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-candidates --namespace HTTP --offset 0 --limit 16 --variants 8 \
> behavior-candidates-http-000.json
```

To validate only the external portion before using a BIG-IP or vLab, extract
the plan and run the collector in its default dry-run mode. This performs no
device mutation:

```sh
jq '.capture_plan' behavior-candidates-http-000.json \
  > behavior-capture-plan-http-000.json
uv run --python 3.13 python tools/tmos17-collector.py \
  --plan behavior-capture-plan-http-000.json
```

Each candidate contains a registry-derived argument hypothesis, a target-valid
event/profile fixture, a protocol starter request when one is available, and a
reference-free `capture_plan`. The plan can be passed to the existing
`tools/tmos17-collector.py` workflow; it never fabricates expected TMOS output.
The candidate's `input` may also contain a generic emulator-only fixture (for
example, a bounded pool/member state for `LB::*` commands); that fixture stays
available for the local sweep, while the generated `capture_plan` removes it so
the plan remains valid at the external collector boundary.
The `--variants 8` option places all bounded registry-derived argument forms
in the capture plan; reduce either `--limit` or `--variants` when the resulting
plan would exceed the 256-observation capture limit. The default is one primary
argument form per command.

To materialize the entire selected catalog as collector-ready files, use the
batch builder. It chooses the largest safe chunk automatically, validates every
plan through the external collector contract, and writes a manifest describing
which observations can use the built-in HTTP/RULE_INIT driver versus which
require `--trigger-command`:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp uv run --python 3.13 \
  python tools/tmos17-capture-batch.py \
  --output-dir /tmp/tmos-17.5-capture-batch \
  --variants 1
```

For richer argument coverage, `--variants 8` automatically reduces the
command chunk size so every plan remains within the 256-observation collector
limit:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp uv run --python 3.13 \
  python tools/tmos17-capture-batch.py \
  --output-dir /tmp/tmos-17.5-capture-batch-v8 \
  --namespace HTTP \
  --variants 8
```

Each `plan-*.json` is independently usable with
`tools/tmos17-collector.py`; `manifest.json` is the resumable index. Commands
blocked by the collector safety policy (for example, Tcl evaluation or process
commands that also have F5 documentation) are retained in
`blocked-catalog.json` instead of being injected into a device rule. The
manifest counts those entries separately so the selected catalog remains
auditable. The tool uses a staging directory and refuses to overwrite an
existing output directory. Building and validating plans never connects to or
mutates a device.

The manifest also includes the bundled protocol driver's capability report and
fixture preflight. `buildable` means the driver can construct a specialized
protocol stimulus without opening a socket; `raw-fallback` means it can send a
bounded payload but cannot claim event-specific framing or lifecycle parity.
Use the driver report directly with:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp uv run --python 3.13 \
  python tools/tmos17-protocol-driver.py --capabilities
```

To preflight or execute a whole batch, use the resumable runner. It is
read-only by default and validates every plan again. It records one checkpoint
per completed plan, so an interrupted external capture can resume without
replaying completed plans:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp uv run --python 3.13 \
  python tools/tmos17-capture-runner.py \
  --manifest /tmp/tmos-17.5-capture-batch/manifest.json
```

Execution requires all three device coordinates plus both explicit mutation
acknowledgements. Credentials remain in `BIGIP_USERNAME` and
`BIGIP_PASSWORD`; the runner never places them in process arguments:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp uv run --python 3.13 \
  python tools/tmos17-capture-runner.py \
  --manifest /tmp/tmos-17.5-capture-batch/manifest.json \
  --execute --allow-device-write \
  --records /tmp/tmos-17.5-observations.ndjson \
  --bigip-url https://bigip.example \
  --virtual /Common/test-vs \
  --traffic-url http://vip.example/health \
  --trigger-command /path/to/tmos17-protocol-driver.py
```

The state file defaults beside the manifest as `capture-state.json`. A plan is
marked `collected-partial` when `--allow-partial` skips unsupported events; it
will be retried automatically if a later run supplies a trigger driver.

Candidates are chunked over the uncovered-command queue, with a maximum of 64
commands per request. The argument hypotheses are intentionally reviewable:
they start from the pinned tcl-lsp synopsis metadata and use bounded TMOS-safe
type hints where a synopsis only names a type such as `BOOL_VALUE`; each
candidate records its argument source. They may still need a command-specific
fixture or protocol driver before collection. A small set of modeled lifecycle
commands also carries explicit safe event hints (for example,
`HTTP::release` in `HTTP_REQUEST_DATA` and `HTTP::retry` in `HTTP_RESPONSE`)
so generated sweeps do not confuse an invalid event fixture with a semantic
failure. When a command explicitly requires `FASTHTTP` but its selected event
is driven by the reusable HTTP lifecycle, the local fixture may include both
profiles; this is an execution fixture, not a claim that a production virtual
server should attach incompatible profiles. Use
`GET /v1/behavior-candidates` for the checked-in packs or `POST
/v1/behavior-candidates` with `{"packs":[...]}` for custom packs. The same
operation is exposed as `irule_behavior_candidates` in MCP.

To evaluate those hypotheses against the local emulator, run a bounded sweep:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-sweep --namespace HTTP --offset 0 --limit 16 --variants 8
```

The sweep executes each generated input and returns compact per-command
execution evidence, including `ok`, `argument-required`, `runtime-error`, or
`profile-gated` results. It is a local diagnostic and does not claim TMOS
parity. By default it runs the primary argument hypothesis; `--variants 8`
runs every bounded registry-derived argument form and reports each result. Use
`GET /v1/behavior-sweep` for checked-in packs or `POST
/v1/behavior-sweep` with `{"packs":[...]}` for custom packs; MCP exposes the
same operation as `irule_behavior_sweep`.

### TMOS 17.5 differential vectors

Behavior packs assert values authored inside the emulator project. Differential
vectors add an independent reference observation, so a captured result from a
TMOS 17.5 device or vLab can be compared with the emulator without requiring
the reference system to expose the emulator's JSON schema. A vector pack is
bounded to 256 vectors and 2 MiB, and each vector contains:

* `input`: one `scenario`, `command_probe`, or `pcap` operation;
* `reference`: `{ "source": "...", "output": { ... } }`, copied from the
  independent TMOS observation; and
* `comparisons`: explicit `{ "actual_path": [...], "reference_path": [...],
  "label": "..." }` mappings.

The paths are arrays of object keys and non-negative array indexes. They are
not expressions and are never evaluated as Tcl or JSONPath. This makes it
possible to compare a BIG-IP field such as `status` with the corresponding
emulator field even when the surrounding result documents differ. Missing
paths and execution errors fail only that vector, while pack validation is
atomic before execution begins.

The result also includes bounded `analysis` data: total comparison counts,
execution-error counts, the first 32 vector IDs with execution errors, and
mismatch groups keyed by operation and comparison label. This makes a large
capture pack useful for prioritizing fidelity work without replacing the
per-vector evidence.

Run the checked-in contract fixture locally:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --golden-vectors examples/golden-vectors/http-17.5.json
```

The repository also includes
[`examples/golden-vectors/http-streaming-17.5.json`](../examples/golden-vectors/http-streaming-17.5.json),
which exercises split `Content-Length` bodies, chunked response bodies, and
coalesced/pipelined HTTP/1.x messages. Its provenance explicitly identifies it
as a checked-in adapter contract (`live_device: false`); replace the reference
outputs with independently captured TMOS 17.5 observations when a device or
vLab collector is available.

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --golden-vectors examples/golden-vectors/http-streaming-17.5.json
```

The same operation is available as `POST /v1/differential-vectors` and the MCP
tool `irule_differential_vectors`. The checked-in fixture demonstrates the
schema and deterministic adapter contract; it is not presented as a capture
from a live BIG-IP. To add a real differential vector, preserve the scenario
input, replace `reference.output` with the captured TMOS 17.5 observation, and
map only fields whose semantics are intended to be compared. The runner never
connects to a device and never silently regenerates reference output from the
emulator.

### Importing external TMOS observations

Use the observation importer as the handoff between a BIG-IP/vLab collector and
the differential runner. It accepts external output without executing the
emulator, validates the same TMOS 17.5 operation and comparison contracts, and
returns a canonical golden-vector pack with bounded scalar provenance:

```json
{
  "schema_version": 1,
  "profile": "tmos-17.5",
  "name": "http-capture",
  "source": "bigip-vlab-17.5.4",
  "provenance": {
    "collector": "tmsh-observe-v1",
    "build": "17.5.4",
    "capture_id": "capture-001"
  },
  "observations": [
    {
      "id": "http-host",
      "operation": "command_probe",
      "input": {
        "command": "HTTP::host",
        "event": "HTTP_REQUEST",
        "request": {"host": "api.example.com"}
      },
      "output": {"value": "api.example.com"},
      "comparisons": [
        {
          "label": "host",
          "actual_path": ["execution", "value"],
          "reference_path": ["value"]
        }
      ]
    }
  ]
}
```

The CLI form is:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --import-observations observations.json
```

The same operation is available as `POST
/v1/differential-vectors/import` and the MCP tool
`irule_import_observations`. The response contains `pack`, which can be passed
unchanged to `--golden-vectors`, `POST /v1/differential-vectors`, or
`irule_differential_vectors`. Importing never fabricates reference output from
the emulator; it only normalizes and validates collector-supplied output.

### Assemble a capture from a collector stream

For a repeatable capture run, keep the test inputs in a capture plan and send
the observed outputs as newline-delimited JSON. A plan contains the same
`id`, `operation`, `input`, and comparison mappings used by an observation, but
does not contain `output`. Each collector record contains exactly:

```json
{"id":"http-host","output":{"value":"api.example.com"}}
```

The plan must identify a TMOS 17.5 build and a collector/capture ID. The
assembler requires exactly one record for every plan case, restores plan order,
validates each operation against the pinned 17.5 catalog, and adds both an
aggregate `records_sha256` and per-record digests to the result. It is an
assembly boundary only: it does not connect to BIG-IP, execute Tcl, or invent
missing reference values.

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --assemble-observations \
  --capture-plan examples/observations/http-17.5.capture-plan.json \
  --capture-records collector-output.ndjson > observations.json

TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --golden-vectors observations.json
```

The HTTP equivalent is `POST /v1/observations/assemble` with a JSON body of
`{"plan": {...}, "records": [...]}`. The MCP equivalent is
`irule_assemble_observations`. Both expose the same bounded, non-executing
contract. The example records in the repository are placeholders and are not
live-device evidence.

The scenario-capable stateful pack can be run directly with:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/stateful-17.5.json
```

For a stateful data-plane fixture, keep the simple `pools` member-array format
and add `backends` keyed by the same `address:port` member values. A backend
can be `up`, `down`, or `disabled`; down and disabled members are excluded from
pool selection. Its ordered `responses` list matches exact `method`, `uri`,
`path`, `host`, or `pool` fields, with one optional response lacking `match` as
the default. The selected response is installed before `HTTP_RESPONSE`, so an
iRule can inspect or rewrite the fixture just as it would an upstream reply.
Explicit request `response_status`, `response_headers`, and `response_body`
fields override only their corresponding fixture fields.

```json
{
  "pools": {
    "api_pool": ["10.0.0.10:80", "10.0.0.11:80"]
  },
  "backends": {
    "10.0.0.10:80": {"state": "down"},
    "10.0.0.11:80": {
      "state": "up",
      "responses": [
        {
          "match": {"method": "GET", "path": "/health"},
          "status": 200,
          "headers": {"X-Backend": "api-2"},
          "body": "healthy"
        },
        {"status": 503, "body": "no route"}
      ]
    }
  }
}
```

Each result exposes the applied fixture under
`result.semantic.backend` (`active`, selected `member`, health `state`, match
status/index, and applied status). Fixtures are bounded and deterministic;
they do not open sockets or perform live health checks.

Set `pool_modes` to opt a pool into deterministic rotation across requests on
the same emulator session. `first` preserves the legacy behavior and is the
default; `round_robin` advances a per-pool cursor after each successful member
selection and skips members whose backend fixture is down or disabled.

```json
{
  "pool_modes": {"api_pool": "round_robin"}
}
```

The current cursor is visible in `result.semantic.pool_selection` as
`next_index`. It is session-scoped, so repeated requests can exercise
keep-alive distribution while a new emulator session starts from index zero.

`TCP::notify request` and `TCP::notify response` queue the corresponding
`USER_REQUEST` or `USER_RESPONSE` event after the current handler returns.
Queued notifications are returned in dispatch order under an event's
`notifications` array, including notifications raised by a user-event handler,
and are bounded to 32 dispatches per event chain. `TCP::notify eom` records a
message boundary marker without creating a user event; no real message-based
load-balancing socket or asynchronous scheduler is created.

During packet replay, request/response notifications remain pending until the
modeled serverside connection reaches `SERVER_CONNECTED`; this prevents a
client packet from making a serverside user event appear before a serverside
connection exists. The pending queue is bounded to 1024 entries and is cleared
when the packet connection closes. Direct `EmulatorSession.fire_event()` calls
remain synchronous synthetic event injection and dispatch queued notifications
immediately.

HTTP requests can model load-balancer causality with bounded per-request inputs.
`persist_down` supplies the persistence target (`member` is required and `pool`
is optional); it causes `PERSIST_DOWN` before `LB_SELECTED`. `lb_queue` supplies
the queue observation fields `queued`, `on_connlimit`, `depth`, `limit_depth`,
`limit_time`, `age_head`, `age_max`, `age_edm`, and `age_ema`; when `queued` is
true, `LB_QUEUED` fires after `LB_SELECTED` and before server initialization.
When `queued` is true and a positive `limit_depth` is exceeded, the emulator
then fires `LB_FAILED` with the bounded cause `queue_limit`, allowing a rule to
exercise fallback selection. This is a deterministic causal transition, not a
real connection-limit queue.
The two inputs are accepted on client-side structured HTTP packets as well as
JSON requests, and are rejected on server-side response packets. They model a
bounded condition supplied by the test scenario; they do not create a real
connection-limit queue or persistence database. An explicit `lb_failure` input
cannot be combined with `persist_down` or a queued `lb_queue` condition.

```json
{
  "requests": [{
    "uri": "/health",
    "persist_down": {
      "pool": "primary_pool",
      "member": "10.0.0.10:443"
    },
    "lb_queue": {
      "queued": true,
      "depth": 2,
      "limit_depth": 5,
      "limit_time": 30,
      "age_head": 4
    }
  }]
}
```
Rule declarations honor the TMOS 17.5 [`priority`](https://clouddocs.f5.com/api/irules/priority.html)
and [`timing`](https://clouddocs.f5.com/api/irules/timing.html) controls. Outer-scope
directives apply to subsequent `when` blocks; per-event attributes override
them. Lower priorities run first and equal-priority handlers retain source
order. Timing is represented as event metadata (`on`/`off`) and does not invent
wall-clock performance data. Effective controls are returned in the
top-level `event_controls` array and in persistent-session metadata.
Scenarios may also provide `irules`, a bounded array of inline source strings
or `{ "irule": "..." }` objects. The sources are treated as multiple iRules
attached to one virtual server: handlers share the normal priority ordering,
and equal-priority handlers retain the array order. Each source starts with
priority `500` and timing `on`, so outer-scope directives from one attached
iRule cannot leak into the next; a source may override either value in its own
top-level declarations. `irule`, `irule_file`, and `irules` are mutually
exclusive. The array is limited to 64 sources; this is composition of Tcl
handlers, not a claim that the emulator creates a live virtual-server object.
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
The [TMOS 17.5 `session` command](https://clouddocs.f5.com/api/irules/session.html)
is modeled separately as a global key/value table for the lifetime of one
emulator session. `session add`, `session lookup`, and `session delete` support
the documented `simple`, `source_addr`, `sticky`, `dest_addr`, `ssl`, `uie`,
`hash`, and `sip` modes. The legacy `any virtual`, `service`, and `pool`
qualifiers are accepted and normalized to their first key element, matching
BIG-IP 10+ behavior. Adds default to a 180-second timeout; lookups touch a
record and restart its timeout, while timeout `0` disables expiry. The table
is bounded to 1,024 records, 1 MiB per value, and 16 MiB total value data.
Session records survive emulated connection teardown but are isolated from
other emulator sessions and do not select a pool member.
The [TMOS 17.5 `sharedvar` command](https://clouddocs.f5.com/api/irules/sharedvar.html)
binds a declared Tcl identifier to the current connection's shared-variable
store. A later handler can call `sharedvar` for the same name and observe
updates made by an earlier handler or event; the binding is cleared when the
emulated client connection is reset. This supports VIP-to-VIP-style rule
logic within one interpreter, but does not create a second virtual server or
claim to emulate cross-TMM/shared-memory scheduling.
The traffic-intent controls [`clone`](https://clouddocs.f5.com/api/irules/clone.html),
[`listen`](https://clouddocs.f5.com/api/irules/listen.html),
[`relate_client`](https://clouddocs.f5.com/api/irules/relate_client.html),
[`relate_server`](https://clouddocs.f5.com/api/irules/relate_server.html), and
[`use`](https://clouddocs.f5.com/api/irules/use.html) are modeled as validated,
connection-scoped intent records. Each event result exposes them under
`result.semantic.traffic.intents` with a monotonically increasing ordinal,
command kind, and normalized argument data. Records are bounded to 256 per
connection and reset on connection rollover or close. They describe the
iRule-visible request to clone, listen, relate, or select a resource; the
emulator does not open sockets, create a second virtual server, or forward
live traffic as a consequence.
The legacy diagnostic controls are bounded and observable. [`check`](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_rule_command_check.html)
accepts `none`, `syntax`, `config`, or `strict` and retains the selected level;
[`tcpdump`](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_rule_command_tcpdump.html)
records its arguments without starting a host capture; [`DIAG::test`](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_rule_command_DIAG_test.html)
records an invocation; and [`LINE::get`](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_rule_command_LINE_get.html)
and [`LINE::set`](https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/ltm/ltm_rule_command_LINE_set.html)
read and update the current stream line. Their access history is exposed under
`result.semantic.diagnostics` with bounded arguments and records. The legacy
[`accumulate`](https://clouddocs.f5.com/api/irules/accumulate.html) command
stops the current handler and marks the result as `suspended`; it does not
buffer or replay live packets, so a caller must model any subsequent data event
explicitly.
Several legacy lookup commands use caller-supplied deterministic fixtures.
The [`cpu`](https://clouddocs.f5.com/api/irules/cpu.html) command accepts the
documented `usage` intervals, returns zero-valued telemetry by default, and
can be seeded with a scenario-level `cpu` object such as
`{"5secs": 2.5, "all_seconds": [1, 2, 3]}`. The [`whereis`](https://clouddocs.f5.com/api/irules/whereis.html)
command accepts up to eight documented fields and reads exact-address records
from a scenario-level `whereis` object; missing records return empty strings
or the documented numeric/unknown defaults. The [`pem_dtos`](https://clouddocs.f5.com/api/irules/pem_dtos.html)
command reads exact `tac lookup` inputs from a scenario-level `pem_dtos`
object. Query history for these commands is exposed under
`result.semantic.utilities` and resets with the emulated connection. No
external CPU, geolocation, or TAC database is contacted. The legacy
[`imid`](https://clouddocs.f5.com/api/irules/imid.html) command accepts no
arguments and returns the empty string, matching the reference behavior
documented for its currently nonfunctional implementation.
The legacy global helpers `http_client_ip`, `http_content_len_max`,
`http_cookie`, `http_header`, `http_host`, `http_method`, `http_uri`,
`http_version`, `ip_addr`, `ip_protocol`, `ip_tos`, `ip_ttl`, `htonl`, `htons`,
`ntohl`, and `ntohs` are also semantic. They read the existing HTTP/connection state,
validate bounded inputs, and avoid maintaining a parallel compatibility state
store. `http_client_ip` honors an optional forwarded-address header name;
`http_content_len_max` defaults to a 1024-byte cap.
Connection endpoint getters (`client_addr`, `client_port`, `local_addr`,
`local_port`, `remote_addr`, `remote_port`, `server_addr`, and `server_port`)
read the configured connection endpoints; server getters switch to the
selected pool member after `pool` or `LB::reselect` establishes one.
The top-level sideband commands `connect`, `send`, `recv`, and `close` use
deterministic, scenario-supplied fixtures rather than opening external
sockets. Configure a destination with a response shorthand or an explicit
connection result:

```json
{
  "sideband": {
    "10.0.0.10:80": {
      "response": "HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n"
    },
    "unreachable.example:443": {
      "connect_status": "unreachable"
    }
  }
}
```

`connect` returns a connection-scoped handle and supports the documented
`-protocol`, `-myaddr`, `-myport`, `-timeout`, `-idle`, `-tos`, and `-status`
options. `send` records byte counts and supports `-timeout` and `-status`.
`recv` returns fixture bytes, or writes them to a variable, and supports
bounded byte counts plus `-eol`, `-peek`, `-timeout`, and `-status`; `close`
marks the handle closed. Connection status, sent/received byte counts, and
remaining buffered bytes are returned in `result.semantic.sideband`. Fixtures
are capped at 32 destinations and 1 MiB per response, and sideband operations
are intentionally connection-scoped and repeatable. This models iRule
control flow and failure handling, not DNS, TLS, upstream protocol parsing,
socket timing, or real network I/O.
The TMOS 17.5 `ifile` command is backed by bounded scenario fixtures rather
than host files. A fixture can be a text shorthand or an object with
`content`/`content_base64` plus optional `last_updated_by`, `last_update_time`,
`revision`, and `checksum` metadata:

```json
{
  "ifiles": {
    "/Common/maintenance.html": {
      "content": "<h1>Maintenance</h1>",
      "last_updated_by": "test-fixture",
      "revision": 2
    },
    "/Common/logo.bin": {"content_base64": "AAEC"}
  }
}
```

Rules may use `ifile get`, `listall`, `attributes`, `size`,
`last_updated_by`, `last_update_time`, `revision`, and `checksum`. Text
content defaults to a SHA-256 hexadecimal checksum; binary fixtures use
decoded byte sizes. The emulator accepts at most 128 fixtures and 32 MiB per
fixture, 64 MiB in total, records recent accesses under
`result.semantic.ifile`, and never opens or resolves a host filesystem path.
The legacy top-level connection controls `forward`, `translate`, `rateclass`,
and `link_qos` are also modeled against the current connection state. `forward`
records strict forwarding intent, `translate address|port|service` supports
bounded enable/disable state and reads, `rateclass` stores the selected class,
and `link_qos` reads or sets a QoS level from 0 through 7. The legacy
`redirect to HOST_URI` form uses the same HTTP 302/Location response model as
`HTTP::redirect`. Their current values are returned under
`result.semantic.legacy`. These controls expose decisions and state for rule testing;
they do not change real routing, QoS scheduling, or packet forwarding.
Generic UDP packet traces fire `CLIENT_ACCEPTED`, `CLIENT_DATA`,
`SERVER_CONNECTED`, and `SERVER_DATA` as applicable. `UDP::payload` is mutable
by wire-byte offset, and the adapter records UDP drop, hold/release, respond,
port, buffer, rate, and debug-queue controls in the event trace. This is a
bounded datagram model: it does not implement TMM queue scheduling, NAT, or a
real upstream UDP socket.
Structured packet traces may also contain a synthetic `{"protocol":"event"}`
record with an uppercase catalogued `event` and validated `state` object. This
is useful for replaying profile- or subsystem-specific event sequences that do
not have a wire decoder yet; it invokes the same Tcl event runner and returns
the same logs, decisions, state, and fidelity data. Synthetic event records do
not create sockets, advance packet metrics, or implicitly open or close a
connection; use the TCP/UDP/protocol packet forms when those lifecycle effects
matter.
The six TMOS 17.5 `DATAGRAM::*` readers are semantic as well. `DATAGRAM::ip`,
`DATAGRAM::ip6`, `DATAGRAM::tcp`, `DATAGRAM::udp`, `DATAGRAM::dns`, and
`DATAGRAM::l2` expose validated IPv4/IPv6, TCP/UDP, DNS, and Layer-2 metadata
in `FLOW_INIT` or data events where the catalog permits them. Packet records
may provide a `datagram` object with header flags, options, payload metadata,
DNS fields, and an L2 destination; direct event calls may provide the same
fields under the `datagram` state layer. The packet adapter emits `FLOW_INIT`
when a `FLOW` profile is attached. This is deterministic header inspection,
not a kernel parser, live flow engine, or packet mutation path.
TCP packet traces also expose a bounded transport-control state layer. Rules
can inspect or set Appropriate Byte Counting, analytics, automatic window
tuning, delayed ACK, D-SACK, early retransmit, ECN, enhanced loss recovery,
limited transmit, loss filters, window scales, retransmission and metrics
timeouts, Nagle mode, keepalive, idle timeout, send/receive buffers, MSS,
pacing, PUSH mode, congestion label, proxy-buffer thresholds, and a
deterministic unused-port allocator; those values persist across packet
events in the emulated connection. This is transport-control state, not a
kernel TCP implementation or wire-level congestion/retransmission simulator.
When the first server-to-client packet opens the server side of a structured
TCP or TCP-based protocol trace, the adapter emits `SERVER_INIT` followed by
`SERVER_CONNECTED` once per connection. Both events receive the packet's
connection state; later server-side packets go directly to their protocol data
event. This models the observable event ordering documented for server-side
flow setup, not a real SYN/retransmission timer or upstream socket. UDP and
SCTP traces retain `SERVER_CONNECTED` without claiming the TCP-only
`SERVER_INIT` event.
Structured SCTP packet traces expose `CLIENT_ACCEPTED`, `CLIENT_DATA`,
`SERVER_CONNECTED`, and `SERVER_DATA` when the `SCTP` profile is attached.
The 14-command SCTP slice models client/server/local/remote ports, MSS, PPI,
RTO and SACK timeout readers, bounded collection buffering, byte-oriented
payload reads/replacement, release, and response emission. Supply SCTP packets
with `protocol: "sctp"`, endpoints, and either `payload` or `payload_hex`.
This is a deterministic iRule-facing transport model: it does not implement a
kernel SCTP association, chunk parsing, multihoming, retransmission, or
congestion control.
Structured DHCPv4 and DHCPv6 packet traces expose the shared
`DHCP::version` reader plus the version-specific header and option commands.
Use `protocol: "dhcpv4"` or `protocol: "dhcpv6"` with structured fields and
an optional `options` object. DHCPv4 exposes the hardware type through
`DHCPv4::htype` (default `1`, Ethernet) alongside the other header readers.
`DHCPv4::option` supports lookup/set while
`DHCPv6::option` also supports delete; drop and reject actions are returned in
the trace. The adapter fires the normal client/server data path and preserves
option mutations as deterministic state. Raw IPv4/UDP packets on ports 67/68
are decoded into the same DHCPv4 path, including the BOOTP fixed header,
DHCP message type, bounded common option values, and RFC option-overload areas.
Malformed headers, cookies, option lengths, and hardware-address lengths are
rejected. The adapter does not allocate leases, negotiate a DHCP exchange, or
emit real ICMP rejection packets.
Structured FTP packet traces expose the TCP control-channel path through
`CLIENT_ACCEPTED`, `CLIENT_DATA`, `SERVER_CONNECTED`, and `SERVER_DATA`. The
six TMOS 17.5 `FTP::*` commands model active-mode enablement, FTP handler
enable/disable, FTPS mode, TLS session-reuse enforcement, and passive-port
range selection. Packet inputs may provide a control message type, command,
response code, TLS flags, and text or hexadecimal payload; the adapter keeps
the controls connection-scoped and records disabled processing in the trace.
When the `FTP` profile is attached, raw TCP streams on port 21 (or streams
whose prefix is a recognized FTP command/response) are reassembled into
bounded command lines and single- or multi-line server responses before the
FTP events fire. Partial lines and response terminators may span packets.
The adapter does not open a data-channel socket, negotiate TLS, or allocate
real passive ports.
Structured IMAP, POP3, and LDAP packet traces use the ordinary TCP lifecycle
(`CLIENT_ACCEPTED`, `CLIENT_DATA`, `SERVER_CONNECTED`, and `SERVER_DATA`) and
expose their TMOS 17.5 STARTTLS controls. `IMAP::activation_mode`,
`POP3::activation_mode`, and `LDAP::activation_mode` accept `none`, `allow`, or
`require`; each namespace also models its `enable` and `disable` command.
Protocol-control state persists for the emulated connection, while packet
inputs can seed the message type, command text, TLS-active flag, and payload.
When the matching `IMAP`, `POP3`, `LDAP`, or `SMTPS` profile is attached, raw TCP
control lines are reassembled from packet fragments and dispatched as
`CLIENT_DATA`/`SERVER_DATA`; IMAP tags and continuation markers, POP3
`+OK`/`-ERR`, and SMTP three-digit replies are recognized. LDAP BER
`LDAPMessage` frames are reassembled by their definite-length outer sequence;
common bind, search, unbind, extended, and result operations expose their
operation name, message ID, DN, result code, diagnostic text, and bounded wire
hex. The bundled protocol driver can generate the corresponding control
messages. LDAP indefinite-length BER and high-tag-number encodings are
rejected explicitly. None of these adapters negotiates TLS or enforces
STARTTLS policy against a live peer.
Structured ICAP packet traces dispatch `ICAP_REQUEST` and `ICAP_RESPONSE` when
the `ICAP` profile is attached. The four TMOS 17.5 `ICAP::*` commands expose
request method and URI, response status, and case-insensitive ICAP header
lookup, enumeration, insertion, replacement, removal, and replacement of
the complete header block. Header and URI mutations are retained in the event
trace. Raw ICAP/1.0 control messages on port 1344 (or streams with an ICAP
prefix) are also reassembled across TCP packets, including coalesced messages,
`null-body` framing, and bounded ICAP chunked encapsulated bodies. The raw
adapter exposes the full ICAP wire message through `ICAP::payload`; it does not
run an ICAP server, interpret the encapsulated HTTP semantics, or require an
LTM/PEM license.
Structured `ntlm` packet traces use the TCP lifecycle and model the
connection-scoped `NTLM::enable` and `NTLM::disable` controls. They expose
bounded payload bytes and enablement state, but do not parse NTLM messages or
perform authentication negotiation. Structured `protocol_inspection` traces
require the `PROTOCOL_INSPECTION` profile and dispatch
`PROTOCOL_INSPECTION_MATCH`; supplied match IDs, match status, payload bytes,
`PROTOCOL_INSPECTION::id`, and `PROTOCOL_INSPECTION::disable` are modeled with
bounded deterministic state. The adapter does not implement the BIG-IP
signature/inspection engine.
With the `STREAM` profile attached, TCP packet traces also evaluate the
connection-sticky `STREAM::expression` form `@match@replacement@` and dispatch
`STREAM_MATCHED` for the first bounded match in each packet. `STREAM::replace`
mutates matches contained in the current packet; a match completed across TCP
packets is reported with deferred replacement because the earlier bytes have
already been emitted in the trace. This is a deterministic stream filter
model, not a full TMM stream parser.
Structured `classification` packet traces dispatch
`CLASSIFICATION_DETECTED` for client-side TCP traffic when the
`CLASSIFICATION` profile is attached. The eight TMOS 17.5
`CLASSIFICATION::*` commands expose supplied application, category, protocol,
URL-category, username, and result-token fields, plus connection-scoped
enable/disable controls. Result tokens and payloads are bounded; no DPI,
classification database, or PEM policy engine is executed.
The six TMOS 17.5 `CLASSIFY::*` controls integrate with that same state:
application, category, and URL-category `set`/`add` commands overlay the next
supplied classification result, `CLASSIFY::username` assigns flow metadata,
`CLASSIFY::disable` suppresses detection, and `CLASSIFY::defer` may be used in
`HTTP_REQUEST` before an explicitly marked server-side classification packet.
This is deterministic classification control state; it does not run a PEM
classifier or infer results from payloads.
The legacy `urlcatquery` and `urlcatblindquery` commands use exact-match
scenario fixtures under `urlcat.queries` and `urlcat.blind_queries`. Missing
inputs return the configured default, which is `Unknown` by default; lookup
results are returned as Tcl lists and recent lookups are visible under
`result.semantic.urlcat`. These commands do not contact the licensed URL
categorization database, and literal IPv6 inputs are rejected to match the
documented 17.5 behavior.
Structured `category` packet traces dispatch `CATEGORY_MATCHED` for
client-to-server TCP traffic when the `CATEGORY` profile is attached and the
scenario marks a match. The six TMOS 17.5 `CATEGORY::*` commands are modeled:
`CATEGORY::lookup` and `CATEGORY::safesearch` return bounded scenario-supplied
lists, `CATEGORY::result` and `CATEGORY::matchtype` expose the cached match,
`CATEGORY::filetype` writes supplied MIME values to caller variables, and
`CATEGORY::analytics` records the per-request enable/disable decision. Lookup
options and command event restrictions are validated, while no live URL
categorization or SWG engine is contacted.
The ROUTE layer accepts scenario-seeded route-domain and congestion-metric
entries. `ROUTE::age`, `ROUTE::bandwidth`, `ROUTE::cwnd`, `ROUTE::expiration`,
`ROUTE::mtu`, `ROUTE::rtt`, and `ROUTE::rttvar` read deterministic entries, and
`ROUTE::clear` removes a matching destination/gateway entry for the rest of
the session. This models rule-visible cache decisions, not live route
discovery, metric aging, or multi-TMM cache synchronization.

The HTTP proxy layer accepts deterministic explicit-proxy resolution and proxy
chaining inputs. It models all of the documented `HTTP::proxy` forms: proxy
enable/disable, URI-rewrite enable/disable, `addr`, `port`, `rtdom`, `exists`,
`iptuple`, and the `chain` enable/disable, host, port, and retry controls.
Proxy state is reset to the scenario defaults at the start of each HTTP
transaction, so a rule can safely test per-request decisions on a keep-alive
connection. A resolved proxy can be seeded like this:

```json
{
  "http_proxy": {
    "resolved": true,
    "addr": "192.0.2.44",
    "port": 3128,
    "rtdom": 7,
    "iptuple": "192.0.2.44%7:3128",
    "chain": {
      "enabled": true,
      "host": "proxy.internal",
      "port": 8080
    }
  }
}
```

If `iptuple` is omitted for a resolved proxy, the adapter returns the
deterministic Tcl list `{address port route-domain}`. If `resolved` is false,
`HTTP::proxy exists` returns `0` and the destination getters return empty
values. `HTTP::proxy chain retry` records intent in semantic state; the
adapter does not perform DNS, URI rewriting on forwarded bytes, or live
downstream sockets. A bounded chained-proxy response can be supplied under
`http_proxy.chain.response`:

```json
{
  "http_proxy": {
    "chain": {
      "enabled": true,
      "host": "proxy.internal",
      "port": 8080,
      "response": {
        "status": 407,
        "headers": {"Proxy-Authenticate": "Basic realm=proxy"},
        "body": "authentication required"
      }
    }
  }
}
```

The single `response` form is a compatibility fixture: it fires one
`HTTP_PROXY_RESPONSE` event and records `HTTP::proxy chain retry` without
inventing a second response. For deterministic negotiation tests, use the
`responses` array to provide the ordered proxy responses instead:

```json
{
  "http_proxy": {
    "chain": {
      "responses": [
        {"status": 407, "headers": {"Proxy-Authenticate": "Basic realm=proxy"}},
        {"status": 200, "headers": {"X-Proxy": "ready"}, "body": "tunnel-ready"}
      ]
    }
  }
}
```

With `responses`, the adapter advances only when the response handler calls
`HTTP::proxy chain retry`, and permits at most one retry per request. A
successful next response allows `HTTP_REQUEST` to run; an unretried or
exhausted non-200 response closes the emulated connection and marks
`http_proxy.chain_failed`. The semantic snapshot also exposes
`chain_response_index` and `chain_retry_count`. The response handler can
inspect `HTTP::status`, `HTTP::response`, `HTTP::header`, and
`HTTP::payload`; this remains a deterministic event/replay model rather than
live downstream negotiation.
When the `HTTP_PROXY_CONNECT` profile is attached and the proxy remains
enabled, the high-level HTTP lifecycle fires `HTTP_PROXY_REQUEST` before the
chain events and `HTTP_REQUEST`; URI and proxy-control mutations made by the
proxy handler are visible to the normal request handler. Disabling the proxy
or chain suppresses the downstream events.

The REWRITE layer is available when the `REWRITE` profile is attached. The
high-level HTTP flow fires `REWRITE_REQUEST_DONE` after request processing. A
rule may use `REWRITE::payload` to read or replace request content and call
`REWRITE::post_process 1` to enable the later `REWRITE_RESPONSE_DONE` event;
that event can inspect or replace response content. Payload lengths and
replacement offsets are byte-based, and an existing `Content-Length` header is
updated after replacement. `REWRITE::enable` and `REWRITE::disable` model the
connection-level passthrough switch. This is a deterministic iRule event and
payload model, not the full URL/file rewrite plugin or a live APM policy.

The HTML profile adds a bounded response-body filter. A rule enables it during
`HTTP_RESPONSE`, after which the adapter scans comments and tags in order and
fires `HTML_COMMENT_MATCHED` or `HTML_TAG_MATCHED`. `HTML::comment` and
`HTML::tag` can query, prepend, append, or remove the current token;
`HTML::encode` returns escaped text. The parser intentionally handles complete
`<!-- ... -->` comments and simple `< ... >` tags only; it is not a browser,
DOM parser, JavaScript engine, or compression-aware HTML filter.

`HTTP::disable` is modeled as a request-level transition to HTTP passthrough.
The adapter fires `HTTP_DISABLED` after the request handler, preserves the
optional `discard` flag, and exposes deterministic `HTTP::passthrough_reason`
values (`iRule` and numeric value `1`). The state is reset before each
keep-alive request; this does not emulate the full HTTP filter or malformed
wire-request recovery path.

HTTP class-selection outcomes can be supplied on a high-level request or
structured HTTP packet with an `http_class` object. Its `result` is `selected`
or `failed`; `name`, `asm`, and `wa` seed the values visible to
`HTTP::class`, and the corresponding `HTTP_CLASS_SELECTED` or
`HTTP_CLASS_FAILED` event runs before `HTTP_REQUEST`. This is a bounded event
input, not a class database or the deprecated HTTP classification engine.

When a rule calls `reject` during `HTTP_REQUEST`, the adapter fires
`HTTP_REJECT`, exposes deterministic `HTTP::reject_reason` values (`iRule` and
numeric value `1`), marks the result as rejected, and closes the emulated
client connection. The bounded post-abort state retains the reject reason for
the `HTTP_REJECT` handler; malformed-wire and other filter-generated reject
causes are outside this slice.

The HTTP compression slice models `COMPRESS::buffer_size`,
`COMPRESS::disable`, `COMPRESS::enable`, `COMPRESS::gzip`,
`COMPRESS::method`, `COMPRESS::nodelay`, `DECOMPRESS::disable`, and
`DECOMPRESS::enable`. It supports deterministic gzip and deflate transforms
through the in-process Python standard library codec. Response decompression
is applied before `HTTP_RESPONSE` when already enabled, or after the current
handler when the rule enables it there; response compression is applied after
HTML and REWRITE response mutations. Request-side transforms use the same
ordering around `HTTP_REQUEST`. Existing `Content-Encoding` is not
double-compressed, and decompression removes it after a successful transform.
The adapter records buffer and no-delay controls but does not emulate
streaming flush boundaries, Accept-Encoding negotiation, chunk scheduling, or
compression CPU/memory timing.

The HTTPLOG layer models `HTTPLOG::enable` and `HTTPLOG::disable` as a
connection-scoped toggle with a structured, deterministic audit stream. When
enabled, the result contains `http_log` records for the request and response;
each record includes `phase`, `method`, `uri`, `host`, `status`, `bytes`, and
`headers`. Request records use `status: null`, while response records contain
the numeric response status. Records reflect the final adapter-visible headers
and byte length, including mutations performed by the modeled response
pipeline. The records reset for each transaction, while the enablement persists
across keep-alive requests until `HTTPLOG::disable` or connection close. This is
intentionally an observable emulator output: it does not
create a BIG-IP request-logging profile, send syslog, or contact an external
logging service.

The ISTATS layer provides `ISTATS::get`, `ISTATS::incr`, `ISTATS::remove`, and
`ISTATS::set` over arbitrary string keys. Values persist for the lifetime of
the emulator session, across connections and keep-alive requests, and are
returned under `semantic.istats.values` with a `count`. Missing keys read as
`0`; increments require an integer, permit negative values for gauge keys, and
only operate on numeric values. Missing string keys read as an empty value;
other missing keys read as `0`. This models the rule-visible state and
deterministic aggregate view, but not multi-TMM aggregation, tmsh
synchronization, or a live BIG-IP iStats database.

The CRYPTO layer provides one-shot and bounded context-streaming
`CRYPTO::hash`, `CRYPTO::sign`, and `CRYPTO::verify` operations. New contexts
require an explicit `-alg`; later chunks can reuse the context name without
repeating the algorithm or key, and `-final` returns the binary result and
releases the context. Hashes use the standard digest names supported by the
TMOS 17.5 catalog, while signing and verification use the corresponding
`hmac-*` names. Results are binary Tcl values, so `b64encode` is useful when a
rule logs or stores them. The adapter validates algorithm, key, signature, and
data options, supports `-keyhex`, bounds accumulated context data at 16 MiB,
and clears contexts at connection boundaries.

`CRYPTO::encrypt`, `CRYPTO::decrypt`, and `CRYPTO::keygen` extend the same
binary-safe semantic layer. The portable backend implements AES
`cbc`/`cfb`/`ecb`/`ofb`, Blowfish, DES variants, IDEA, RC4, and RSA
public/private encryption. RSA supports the documented `pkcs` default and
`oaep` padding; CBC/ECB block operations use PKCS#7-style padding and
stream-like modes remain unpadded. Omitted IVs are deterministic zero IVs.
`CRYPTO::keygen` supports bounded random, PBKDF2-MD5, and RSA key generation,
returning binary keys or a public/private PEM list as appropriate. Contexts
buffer at most 16 MiB and are released by `-final` or connection reset.

RC2 and AES CWC are retained as catalog entries but return an explicit
unsupported-backend error. PBKDF2 uses an emulator default of 1,000 rounds
when omitted; verify derived-key compatibility against a live TMOS 17.5
device before using it as an interoperability vector. The implementation is
intended for rule behavior testing, not as a replacement for transport
security or production cryptography.

The AES layer provides binary-safe `AES::key`, `AES::encrypt`, and
`AES::decrypt` operations. `AES::key` returns the F5-shaped `AES <bits> <hex>`
format for 128, 192, or 256 bits; encryption and decryption accept those
formatted keys as well as non-empty passphrases. The portable emulator model
uses AES-ECB with PKCS-style padding and bounds each input at 16 MiB. Because
the public F5 reference does not define the passphrase KDF or publish a
ciphertext vector, use formatted keys when interoperability with a live
BIG-IP matters; live-device golden-vector validation remains separate from
the deterministic in-process round-trip test.

The IPFIX layer models `IPFIX::template create|delete`,
`IPFIX::msg create|set|delete`, and `IPFIX::destination open|close|send` as
deterministic objects. Templates and destinations persist for the emulator
session, while messages can be populated across multiple events on one
connection; repeated template elements use the documented zero-based
`-pos` occurrence index. Sent records are retained in a bounded
`semantic.ipfix.sends` history for inspection. The adapter does not open a
real log publisher, encode IPFIX wire records, or transmit UDP traffic.

The ASN.1 layer provides binary-safe BER/DER `ASN1::element`, `ASN1::encode`,
and `ASN1::decode` behavior. It supports opaque element handles, tree
navigation, tag/size/offset/length inspection, optional fields, sequences,
sets, octet and bit strings, booleans, enumerations, integers, and payload
`insert`/`replace` operations. Decode assigns values into the calling Tcl
scope, and parsed payloads are capped at 16 MiB. This portable model accepts
constructed BER indefinite lengths but emits definite-length encodings; it
does not attempt complete schema validation or emulate TMM scheduling.

The ILX layer models `ILX::init`, `ILX::call`, and `ILX::notify` at the
extension boundary. Handles are connection-scoped and the adapter exposes
their plugin/extension targets, synchronous call history, and asynchronous
notification history under `semantic.ilx`. `ILX::call` defaults to a 3000 ms
timeout and accepts an explicit non-negative timeout; `ILX::notify` returns
`0`. Offline calls implement deterministic `echo` and integer `sum` methods,
with unknown methods returning an empty string. Histories are capped at 1024
entries. This does not launch an iRulesLX Node.js worker or attempt to model
extension process scheduling, IPC, or network failures.

The NSH layer models the six TMOS 17.5 `NSH::*` commands as connection-scoped
state. `NSH::chain` stores a direction-specific chain name; `NSH::context`,
`NSH::path_id`, and `NSH::service_index` provide bounded unsigned field
access; `NSH::md1` stores binary-safe metadata; and `NSH::mocksf` records the
mock-service-function option. The resulting state is available under
`semantic.nsh`, and unset context, path, and service values read as `0` while
unset metadata reads as an empty value. Metadata is bounded to 16 MiB by the
portable adapter. This is a rule-behavior model: it does not perform NSH
encapsulation, service-function forwarding, or wire-level packet mutation.

The ADAPT layer models the 17.5 request/response static and dynamic context
surface. `ADAPT::context_create` returns deterministic opaque handles whose
attributes inherit from the static context; the remaining ADAPT commands can
inspect or update enable/allow, internal-virtual selection, preview size,
service-down action, timeout, and result state. Direct `ADAPT_REQUEST_*` and
`ADAPT_RESPONSE_*` events select the first enabled dynamic context on their
side, or the static context when none is enabled; the complete context list is
returned under
`semantic.adapt`. Contexts reset at connection boundaries. This is a
rule-visible adaptation model only: it does not run an ICAP service, internal
virtual server, or content transformation. HTTP scenarios can seed the
deterministic IVS outcome with a top-level `adapt` object, or override it for
one request:

```json
{
  "adapt": {
    "request": {"result": "modified"},
    "response": {"result": "response"}
  }
}
```

The accepted outcomes are `noop`, `modified`, `response`, and `error` (the
aliases `modify`, `respond`, and `no-op` are accepted). A modified or direct
response emits the corresponding `ADAPT_*_HEADERS` event followed by
`ADAPT_*_RESULT`; a noop emits neither event, while an error emits only the
result event. The request-side lifecycle runs after `HTTP_REQUEST` and before
the serverside path; the response-side lifecycle runs after `HTTP_RESPONSE`
and before remaining clientside response processing. This follows the F5
descriptions for [`ADAPT_REQUEST_HEADERS`](https://clouddocs.f5.com/api/irules/ADAPT_REQUEST_HEADERS.html),
[`ADAPT_REQUEST_RESULT`](https://clouddocs.f5.com/api/irules/ADAPT_REQUEST_RESULT.html),
[`ADAPT_RESPONSE_HEADERS`](https://clouddocs.f5.com/api/irules/ADAPT_RESPONSE_HEADERS.html),
and [`ADAPT_RESPONSE_RESULT`](https://clouddocs.f5.com/api/irules/ADAPT_RESPONSE_RESULT.html).

The ONECONNECT layer models the four TMOS 17.5 rule controls
`ONECONNECT::detach`, `ONECONNECT::label`, `ONECONNECT::reuse`, and
`ONECONNECT::select`. Their state is visible under `semantic.oneconnect` and
persists across keep-alive requests, while a `new_connection` request restores
the defaults. This exposes the behavior an iRule can observe without claiming
to reproduce BIG-IP's shared idle server-connection pool or scheduling.
Each result also includes `server_connection`, which reports whether the
OneConnect profile is enabled, the deterministic connection identity, and
whether the request opened, stayed attached to, or reused that session's
server-side connection.

```json
{
  "route": {
    "domain": "7",
    "metrics": [{
      "destination": "192.0.2.10",
      "gateway": "192.0.2.1",
      "age": 12,
      "expiration": 300,
      "mtu": 1500,
      "rtt": 3200,
      "rttvar": 400,
      "cwnd": 14600,
      "bandwidth": 3650
    }]
  }
}
```

The IP layer models the seven TMOS 17.5 commands `IP::hops`,
`IP::idle_timeout`, `IP::ingress_drop_rate`, `IP::ingress_rate_limit`,
`IP::intelligence`, `IP::reputation`, and `IP::stats`. `IP::hops` reads a
deterministic scenario value or per-packet override; `IP::idle_timeout` reads
or updates connection state; the ingress rate commands record bounded control
values; and `IP::stats` reports directional packet/byte counters plus a
deterministic connection age in milliseconds. Scenario data can seed
`ip.intelligence` and `ip.reputation` maps for repeatable rules:

```json
{
  "ip": {
    "hops": 3,
    "intelligence": {"10.0.0.5": ["Proxy", "Scanners"]},
    "reputation": {"10.0.0.5": ["Scanners"]}
  }
}
```

Structured packet traces count UTF-8 payload bytes; raw IPv4 packets count
their IPv4 total length. This is deterministic test data, not a live IP
Intelligence/Reputation database or packet-rate enforcement engine. See the
F5 [`IP::hops`](https://clouddocs.f5.com/api/irules/IP__hops.html),
[`IP::idle_timeout`](https://clouddocs.f5.com/api/irules/IP__idle_timeout.html),
[`IP::ingress_drop_rate`](https://clouddocs.f5.com/api/irules/IP__ingress_drop_rate.html),
[`IP::ingress_rate_limit`](https://clouddocs.f5.com/api/irules/IP__ingress_rate_limit.html),
[`IP::intelligence`](https://clouddocs.f5.com/api/irules/IP__intelligence.html),
[`IP::reputation`](https://clouddocs.f5.com/api/irules/IP__reputation.html), and
[`IP::stats`](https://clouddocs.f5.com/api/irules/IP__stats.html) references.
RTSP packet traces use the RTSP profile and expose structured request/response
events, case-insensitive header lookup and mutation, byte-oriented payload
collection/replacement, release, metadata getters, and deterministic
`RTSP::respond` emissions. Raw control messages support bounded RTSP/1.0
headers and Content-Length bodies, including TCP split/coalescing;
interleaved RTP/RTCP and media-session negotiation are not emulated.
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
    },
    "attack": {
      "enabled": true,
      "attacker_ip": "203.0.113.44",
      "mitigation": "Source IP-Based Rate Limiting"
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
An enabled `dosl7.attack` fixture emits `IN_DOSL7_ATTACK` during the request
lifecycle and exposes the documented `$DOSL7_ATTACKER_IP` and
`$DOSL7_MITIGATION` event variables. This is an explicit deterministic attack
fixture; it does not infer attacks from traffic or run a mitigation engine.
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
    "response_violations": [
      {
        "name": "VIOLATION_RESPONSE_SCRUBBING",
        "attack_type": "Information Leakage",
        "rating": "Error",
        "details": {"response": "secret"}
      }
    ],
    "response_login": {
      "enabled": true,
      "status": "logged_in",
      "username": "alice"
    },
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
engine. A non-empty `response_violations` fixture emits
`ASM_RESPONSE_VIOLATION` after `HTTP_RESPONSE` and any collected response-data
event; response-side `ASM::violation` and `ASM::payload` state are available
to the handler, and `ASM::payload replace` updates the modeled response body.
An enabled `response_login` fixture emits `ASM_RESPONSE_LOGIN` after the
response transaction and sets the response-side `ASM::login_status` and
`ASM::username` values for the handler. Login and response-violation fixtures
are independent and, when both are present, login is emitted first.
With the `ASM` profile attached, an enabled HTTP request also runs the bounded
ASM request lifecycle: `ASM_REQUEST_VIOLATION` is emitted when seeded or
rule-created violations exist, followed by `ASM_REQUEST_DONE`; the
`ASM_REQUEST_BLOCKING` hook is emitted only if the request is still `Blocked`
after the done handlers. This lets a rule use `ASM::unblock` to suppress the
blocking hook, and the result's `semantic.asm` snapshot includes the final
handler mutations. The lifecycle is fixture-driven and does not implement WAF
inspection, production enforcement, or automatic finding detection.
The `BOTDEFENSE` policy surface can be seeded with deterministic client and
decision results:

```json
{
  "profiles": ["TCP", "HTTP", "BOTDEFENSE"],
  "botdefense": {
    "action": "block",
    "client_type": "bot",
    "client_class": "malicious_bot",
    "bot_name": "example-bot",
    "bot_anomalies": ["automation"],
    "bot_categories": ["scraping"],
    "support_id": "BD-42"
  },
  "irule": "when HTTP_REQUEST { log local0. \"[BOTDEFENSE::action] [BOTDEFENSE::client_type]\" }"
}
```

This models all 25 catalogued TMOS 17.5 `BOTDEFENSE::` commands. It exposes
client classification, bot metadata, CAPTCHA and cookie state, device ID,
micro-service and previous-request fields, support/reason values, and
client-side challenge controls. `BOTDEFENSE::action` supports deterministic
per-request overrides; `BOTDEFENSE::enable` and `BOTDEFENSE::disable` are
connection-scoped. The model does not run Bot Defense detection, browser
challenges, CAPTCHA verification, cookie cryptography, or machine-learning
classification. The two Bot Defense events are available through the existing
event/session interface when the `BOTDEFENSE` profile is attached.
The `ANTIFRAUD` policy surface can be seeded with deterministic transaction and
alert context:

```json
{
  "profiles": ["TCP", "HTTP", "FASTHTTP", "ANTIFRAUD"],
  "antifraud": {
    "profile": "/Common/antifraud-profile",
    "login": true,
    "alert": true,
    "client_id": "client-1",
    "device_id": "device-1",
    "fingerprint": "fp-1",
    "geo": "US",
    "guid": "guid-1",
    "username": "configured-user",
    "result": "failed",
    "license_id": "license-7",
    "fields": {
      "alert_type": "credential_stuffing",
      "alert_score": "42",
      "alert_username": "alice"
    }
  },
  "irule": "when ANTIFRAUD_ALERT { log local0. [ANTIFRAUD::alert_type] }"
}
```

This models all 39 catalogued TMOS 17.5 `ANTIFRAUD::` commands. The adapter
exposes login context, alert fields, result and identity getters, deterministic
license-id hashing, enable/disable controls, alert suppression, logging level,
and the five FASTHTTP feature-disable commands. When the profile is attached,
an HTTP request with `login` or `alert` enabled emits `ANTIFRAUD_LOGIN` and
`ANTIFRAUD_ALERT` after `HTTP_REQUEST`; rules can disable the alert or plugin
before those automatic events. A request may override only the two event
triggers with `"antifraud": {"login": true, "alert": false}`. Request fields
reset between transactions, while plugin enable/disable state resets at a new
connection. This is a deterministic policy/context model: it does not perform
fraud scoring, device fingerprinting, bot detection, alert delivery, or a live
Anti-Fraud service.

### AUTH authentication sessions

With the `AUTH` profile attached, the emulator provides a deterministic
authentication-session model for all 18 catalogued TMOS 17.5 `AUTH::`
commands and the `AUTH_ERROR`, `AUTH_FAILURE`, `AUTH_RESULT`, `AUTH_SUCCESS`,
and `AUTH_WANTCREDENTIAL` events. A rule can create a session in
`CLIENT_ACCEPTED`, set username, password, certificate, or issuer credentials,
subscribe to result data, and call `AUTH::authenticate` from an HTTP event.
The scenario-level `auth.result` selects `success`, `failure`, `error`, or
`wantcredential`; the last option emits `AUTH_WANTCREDENTIAL` and allows a
handler to continue with `AUTH::authenticate_continue`.

```json
{
  "profiles": ["TCP", "HTTP", "AUTH"],
  "auth": {
    "result": "success",
    "ldap_username": "alice",
    "response_data": {"user": "alice", "role": "admin"}
  },
  "irule": "when CLIENT_ACCEPTED { set ::auth_id [AUTH::start pam radius]; AUTH::subscribe $::auth_id }\nwhen HTTP_REQUEST { AUTH::username_credential $::auth_id alice; AUTH::password_credential $::auth_id secret; AUTH::authenticate $::auth_id }\nwhen AUTH_SUCCESS { log local0. [AUTH::status $::auth_id] }",
  "request": {"uri": "/login"}
}
```

Session IDs are deterministic within a connection (`auth-1`, `auth-2`, and so
on), session state resets when a new connection starts, and response data is
available only to subscribed sessions. This is an offline protocol model: it
does not contact PAM, RADIUS, LDAP, certificates, or any external identity
provider, and it does not claim to reproduce asynchronous AAA timing.

### AAA internal virtual-server requests

The `AAA::` family is modeled as deterministic internal virtual-server
requests. `AAA::auth_send` accepts a virtual server, username, and optional
password; `AAA::acct_send` accepts a virtual server followed by key/value
accounting attributes. Both return connection-scoped request IDs (`aaa-1`,
`aaa-2`, and so on), which can be queried with the matching result command.
Configure `aaa.auth_result` and `aaa.acct_result` as `OK`, `FAIL`,
`INPROGRESS`, or `ERROR` to exercise each result path.

The semantic snapshot records request kind, result, validity, virtual server,
and username, but deliberately never records the password. Requests and IDs
reset on a new connection. This is an offline IVS model: it does not contact a
real AAA virtual server, transmit credentials, implement asynchronous
completion, or perform authentication/accounting policy.

### ACCESS sessions and policy

With the `ACCESS` profile attached, the emulator provides a deterministic
APM-style session and policy model for all 15 catalogued TMOS 17.5 `ACCESS::`
commands. `ACCESS::session create -flow` creates a connection-scoped session
with a deterministic ID, `ACCESS::session data` reads or writes session
variables, and `ACCESS::policy evaluate` applies the configured policy result
and emits `ACCESS_POLICY_COMPLETED`. Session creation and removal emit
`ACCESS_SESSION_STARTED` and `ACCESS_SESSION_CLOSED`, respectively.

Scenario configuration can seed ACL results and lists, policy result and
profile metadata, session data, per-flow variables, flow ID, SAML values, and
the deterministic ephemeral-auth password prefix:

```json
{
  "profiles": ["TCP", "HTTP", "ACCESS"],
  "access": {
    "acl_result": "Allow",
    "policy_result": "allow",
    "session_data": {"session.logon.last.username": "alice"},
    "perflow": {"perflow.custom": "example"},
    "saml": {
      "authn": "<AuthnRequest>fixture</AuthnRequest>",
      "assertion": "<Assertion>fixture</Assertion>"
    }
  },
  "irule": "when CLIENT_ACCEPTED { set ::sid [ACCESS::session create -flow] }\nwhen HTTP_REQUEST { ACCESS::policy evaluate -sid $::sid -profile /Common/access; log local0. [ACCESS::policy result -sid $::sid] }",
  "request": {"uri": "/protected"}
}
```

When the HTTP request runner is used and the rule contains ACCESS commands or
ACCESS event handlers, it also models the surrounding lifecycle. A connection
gets one deterministic session and emits `ACCESS_SESSION_STARTED`; the first
request completes the policy before load balancing; and each request evaluates
the configured ACL after `LB_SELECTED`, emitting either
`ACCESS_ACL_ALLOWED` or `ACCESS_ACL_DENIED`. `close_after` removes an
automatically created session and emits `ACCESS_SESSION_CLOSED`. A request can
override the ACL and policy fixture without changing the scenario defaults:

```json
{
  "uri": "/admin",
  "access": {
    "acl_result": "Reject",
    "acl_lookup": ["/Common/admin"]
  }
}
```

Policy `deny` and ACL `Reject` produce a deterministic 403 response unless an
iRule handler commits a different response with `ACCESS::respond`; policy
`redirect` produces a deterministic 302. Policy completion is once per
session, while ACL evaluation is per request, including keep-alive requests.
Configured `access.saml.authn` and `access.saml.assertion` payloads trigger
their corresponding events after an allowed policy completes. Configured
`access.saml.slo_req` and `access.saml.slo_resp` payloads likewise trigger
`ACCESS_SAML_SLO_REQ` and `ACCESS_SAML_SLO_RESP` after the allowed policy
completes. All four payloads can be read or updated through `ACCESS::saml`
inside their corresponding event handlers. The SAML values are fixtures; the
adapter does not parse, validate, send, or receive SAML messages.

`ACCESS::disable`, `ACCESS::enable`, `ACCESS::respond`, ACL evaluation,
per-flow mutation, SAML getters/setters, OAuth signing placeholders, and
ephemeral-auth create/verify are represented as deterministic test behavior.
Session snapshots redact values whose keys look like passwords, secrets, or
tokens. This remains a fixture-driven model: it does not execute a real APM
policy graph, contact external authentication services, perform SAML/OAuth
cryptography, or reproduce production session expiry.

### ACCESS2 policy-expression procedure

With the `ACCESS` profile attached, the direct event API supports
`ACCESS2_POLICY_EXPRESSION_EVAL`. Supply the currently selected policy
procedure as `state.access2.proc`; `ACCESS2::access2_proc` returns that value
without invoking it. For HTTP request simulations, set the optional top-level
`access2.proc` fixture to emit the event once after an allowed policy completes.
The value is event-scoped for direct injection and is connection/session-scoped
for the automatic fixture gate, so this adapter does not execute hidden APM
policy expressions or reproduce the policy engine:

```json
{
  "profiles": ["ACCESS"],
  "irule": "when ACCESS2_POLICY_EXPRESSION_EVAL { log local0. [ACCESS2::access2_proc] }"
}
```

An automatic HTTP example is:

```json
{
  "profiles": ["TCP", "HTTP", "ACCESS"],
  "access2": {"proc": "::policy::evaluate_request"},
  "irule": "when ACCESS2_POLICY_EXPRESSION_EVAL { log local0. [ACCESS2::access2_proc] }",
  "request": {"uri": "/policy"}
}
```

### Endpoint Inspector / Network Access status requests

With the `ACCESS` profile attached, an HTTP request whose path is exactly
`/my.status.eps`, `/my.status.na`, or `/my.report.na` emits
`EPI_NA_CHECK_HTTP_REQUEST` after the normal `HTTP_REQUEST` handler. Query
strings do not change the path match. This models the internal event trigger
documented by F5; it does not implement Endpoint Inspector or Network Access
status processing.

### PingAccess policy-server ready hooks

The optional top-level `ping` fixture exposes the two TMOS 17.5 PingAccess
HTTP lifecycle points without opening a policy-server connection:

```json
{
  "profiles": ["TCP", "HTTP"],
  "ping": {"request_ready": true, "response_ready": true},
  "irule": "when PING_REQUEST_READY { HTTP::header insert X-Ping-Request ready }\nwhen PING_RESPONSE_READY { HTTP::header insert X-Ping-Response ready }",
  "request": {"uri": "/ping"}
}
```

`PING_REQUEST_READY` fires once after the modeled `HTTP_REQUEST` handler and
represents the point before the PingAccess policy request is released.
`PING_RESPONSE_READY` fires once after the modeled `HTTP_RESPONSE` handler and
allows response-header mutation. Each flag defaults to `false`, and both
flags reset for every request transaction. See the F5
[`PING_REQUEST_READY`](https://clouddocs.f5.com/api/irules/PING_REQUEST_READY.html)
and
[`PING_RESPONSE_READY`](https://clouddocs.f5.com/api/irules/PING_RESPONSE_READY.html)
references; this adapter models their iRule-visible control points, not a
PingAccess service or network exchange.

### `call` procedure dispatch

The global `call ?-debug? proc_name ?arg ...?` command invokes a procedure
declared at the top level of the iRule. The emulator resolves the procedure
through Tcl's command namespace, invokes it with list-safe argument handling,
and preserves Tcl return/error codes. `-debug` records the resolved procedure
and argument list in the decision trace. Undefined procedures, an omitted
procedure name, NUL-containing names, and names longer than 4096 characters
are rejected. This models procedure dispatch; it does not execute arbitrary
top-level Tcl beyond installing `proc` declarations. See the F5 [`call` command
reference](https://clouddocs.f5.com/api/irules/call.html).

### `fasthash`

`fasthash` accepts exactly one string and returns a non-negative integer below
2^63. The adapter uses Python's standard-library Blake2b implementation to
provide repeatable off-box results; F5 does not guarantee the same `fasthash`
value across BIG-IP versions or reboots, so callers must not treat this as a
bit-compatible TMM hash.

### `vlan_id`

The legacy global `vlan_id` command is modeled as a no-argument getter over
the event's `link.vlan_id` packet state. It shares the value with
`LINK::vlan_id`, allowing older rules to be exercised without maintaining a
separate VLAN model. See the F5 [`vlan_id` reference](https://clouddocs.f5.com/api/irules/vlan_id.html).

### `traffic_group`

The legacy global `traffic_group` command is modeled as a no-argument getter
over the caller-supplied `traffic_group.name` event-state value. It returns an
empty string when no value is provided and does not invent traffic-group
membership or inspect live BIG-IP configuration. See the F5 [`traffic_group`
reference](https://clouddocs.f5.com/api/irules/traffic_group.html).

### IP-list utilities

The curated global helpers `uniq_ordered_ip_list`, `uniq_sorted_ip_list`,
`xff_list`, `xff_uniq_ordered_ip_list`, and `xff_uniq_sorted_ip_list` are
available for rules that need bounded client-address normalization. Arguments
may contain comma- or whitespace-separated IPv4 and IPv6 values. Invalid
values are discarded, valid values are canonicalized, and duplicates are
removed. The ordered variants retain first-seen order; sorted variants use a
deterministic numeric order with IPv4 values before IPv6 values.

The `xff_*` variants read all values of `X-Forwarded-For` by default, or all
values of one optional header name. They discard loopback and unspecified
addresses before deduplication; `xff_list` is the sorted XFF form. The
helpers accept at most 256 candidate addresses per call and do not resolve
hostnames or model BIG-IP's trust policy for forwarded headers. These helpers
are curated `tcl-lsp` community utilities rather than native TMM primitives.

### `rmd160`

`rmd160` accepts exactly one value and returns the binary RIPEMD-160 digest,
so it can be consumed by Tcl binary commands such as `binary encode hex` or
`binary scan`. The digest is computed by the bounded Python standard-library
bridge and is available in any event context supported by the catalog.

### `md4`

`md4` accepts exactly one value and returns the binary legacy MD4 digest. The
adapter includes a self-contained implementation because MD4 is not exposed
by Python 3.13's OpenSSL-backed `hashlib` on the supported runtime. It exists
for compatibility with older iRules; it should not be used for new security
designs.

### AM acceleration metadata

The seven catalogued `AM::*` commands are available with deterministic
caller-supplied metadata. `AM::age`, `AM::application`, `AM::cache`,
`AM::expires`, `AM::media_playlist`, and `AM::policy_node` are modeled as
no-argument reads from the `am` event-state layer; `AM::disable` records a
connection-scoped disable decision. Since the public command pages and the
pinned registry do not define richer argument or value semantics, this layer
does not execute Application Acceleration Manager policy, cache behavior, or
media transformation:

```json
{
  "profiles": ["HTTP"],
  "irule": "when HTTP_REQUEST { log local0. [AM::application]; AM::disable }",
  "request": {"uri": "/video.m3u8"}
}
```

### FLOW connection handles

With the `FLOW` profile attached, the emulator models the seven catalogued
TMOS 17.5 `FLOW::*` commands using deterministic synthetic handles. The base
connection exposes `flow-client-0` and `flow-server-0`; `FLOW::this` selects
the side associated with the current flow event and `FLOW::peer` resolves its
counterpart. Priority (0 through 7), idle timeout, last-used time, endpoint
fields, and related-flow metadata are returned under `semantic.flow`.

`FLOW::create_related` validates the documented `proto`, `clientflow`,
`serverflow`, `inherit-vs`, `-hairpin`, and `-translation-loose` forms and
returns a paired synthetic client handle. The emulator's virtual clock
advances one logical second for each FLOW-relevant lifecycle event, so
`FLOW::idle_duration` and `FLOW::refresh` are repeatable without wall-clock
dependence. Related handles are state records only: the adapter does not
open sockets, inject packets, perform source translation, or create a live
TMM connection.

### ACL decision state

The emulator models `ACL::action` in `FLOW_INIT` and `ACL::eval` in
`CLIENT_ACCEPTED` using deterministic state. `ACL::action` accepts
`default`, `drop`, `reset`, `allow`, and `allow-final`; its getter returns the
documented numeric action code (`0` through `4`). `ACL::eval` returns `0` after
L4 evaluation, or returns `1` for `-l7` when the supplied state says an L7 ACL
was encountered. In the latter case no action is applied.

Supply the decision inputs through the event API:

```json
{
  "event": "CLIENT_ACCEPTED",
  "state": {
    "acl": {
      "action": "drop",
      "l7_present": 1
    }
  }
}
```

The resulting `acl` state exposes `evaluated`, `l7_aborted`, and
`applied_action` for assertions and downstream tooling. This is an AFM-style
decision model only; it does not evaluate configured ACL rules, enforce a
drop/reset on a real connection, or reproduce AFM policy-chain behavior.

### LSN translation state

The emulator models the eight catalogued `LSN::*` controls as deterministic
connection state. Address, port, pool, disable, inbound filtering, persistence
mode, persistence mappings, and inbound mappings are available from the event
API. For example:

```tcl
when CLIENT_ACCEPTED {
    LSN::address 198.51.100.10
    LSN::port 45000
    LSN::pool /Common/lsn_pool
    LSN::persistence address-port 60
    LSN::persistence-entry create 10.0.0.1:50000 198.51.100.10:45000
    LSN::inbound-entry create /Common/lsn_pool 120 \
        10.0.0.1:50000 198.51.100.10:45000 tcp
}
```

`LSN::persistence-entry get CLIENT[:PORT]` returns the mapped translation
endpoint, while `delete` removes it. `LSN::inbound-entry get TRANSLATION
PROTOCOL` returns a two-item `{client route-domain}` list; `create` and
`delete` manage the corresponding mapping. IPv6 endpoints with ports use
`[HOST]:PORT`. The state records are bounded and reset with the connection;
they do not allocate from a live CGNAT pool, translate packets, replicate
mappings, or enforce wall-clock expiry.

### XLAT source-translation state

The emulator also models the seven catalogued `XLAT::*` commands as a
deterministic overlay. Supply source-translation values in an event state and
inspect them from `SA_PICKED`:

```json
{
  "event": "SA_PICKED",
  "state": {
    "xlat": {
      "src_addr": "198.51.100.30",
      "src_port": 41000,
      "src_config": "SNAT /Common/snat",
      "src_nat_valid_range": "{198.51.100.30 40000 45000}"
    }
  }
}
```

`XLAT::listen LIFETIME { ... }` accepts the documented `proto`, `bind`,
`server`, `allow`, and `inherit-vs` subcommands and returns a deterministic
listener handle. `XLAT::listen_lifetime` reads or updates that handle.
`XLAT::src_endpoint_reservation create` returns a `{translation-address
translation-port}` pair; `get` and `update_lifetime` inspect or update the
reservation. The source-NAT range value is a Tcl list of `{address start-port
end-port}` entries. These records do not open sockets, reserve real ports,
translate packets, or reproduce live LSN/CGNAT allocation and expiry.

### PCP request/response state

With the `PCP` profile attached, the event API accepts a bounded `pcp` state
layer for `PCP_REQUEST` and `PCP_RESPONSE`. The overlay implements the
documented read-only field accessors and `PCP::reject`:

```json
{
  "event": "PCP_REQUEST",
  "state": {
    "pcp": {
      "version": 2,
      "opcode": "map",
      "lifetime": 3600,
      "protocol": "tcp",
      "internal_port": 443,
      "client_addr": "192.0.2.10",
      "suggested_ext_port": 40000,
      "suggested_ext_addr": "198.51.100.10"
    }
  }
}
```

Map-only fields return `NA` on announce or peer operations, matching the
documented command behavior. `PCP::reject RESULT_CODE` records a deterministic
rejection for a request and validates the result code from 0 through 255.

Packet traces can use `protocol: "pcp"` with the same nested `pcp` object. A
client-to-server packet fires `PCP_REQUEST`; a server-to-client packet fires
`PCP_RESPONSE`. The adapter validates bounded numeric/address fields, derives a
missing client address from the packet endpoint, and reports `PCP::reject` in
the packet result. Raw IPv4/UDP packets on port 5351 are decoded into this same
adapter shape, including bounded MAP/PEER/ANNOUNCE headers and the
THIRD_PARTY and PREFER_FAILURE options. It is still a deterministic inspection
adapter: it does not perform proxying, allocate mappings, or emulate NAT.

### PSC subscriber/session state

With the `PSC` profile attached, the event API accepts a bounded `psc` state layer
for subscriber/session-oriented rules. The overlay covers all eleven TMOS 17.5
`PSC::*` catalog commands: scalar subscriber identity fields, AAA reporting
interval, custom attributes, IP addresses, policies, and per-address lease times.
The command contracts are based on the [PSC::attr](https://clouddocs.f5.com/api/irules/PSC__attr.html),
[PSC::ip_address](https://clouddocs.f5.com/api/irules/PSC__ip_address.html),
[PSC::policy](https://clouddocs.f5.com/api/irules/PSC__policy.html), and
[PSC::subscriber_id](https://clouddocs.f5.com/api/irules/PSC-subscriber-id.html)
references.

`PSC::attr`, `PSC::ip_address`, and `PSC::policy` support their documented
get/set/remove forms, including `add` and `remove`; IP addresses accept IPv4,
IPv6, and optional route-domain suffixes such as `%10`. State is capped at 256
entries per collection and 64 KiB per supplied PSC state layer. Values reset at
connection teardown. This is deterministic test state: it does not connect to a
live PEM/PSC session database, AAA system, policy engine, or mobile network.

### PEM flow and subscriber-session state

With the `PEM` profile attached, the emulator models the five TMOS 17.5 PEM
commands over deterministic connection-scoped state. `PEM::enable` and
`PEM::disable` toggle enforcement for the current flow; `PEM::flow transactional
disable` and `PEM::flow eval` record flow controls and evaluation requests.
`PEM::session` and `PEM::subscriber` provide bounded in-memory session/subscriber
records with identity fields, provisioning state, custom attributes, policies,
and IP bindings. Both expanded Tcl arguments and braced Tcl lists are accepted
for policy and IP collections. The command contracts follow the [PEM::flow](https://clouddocs.f5.com/api/irules/PEM__flow.html),
[PEM::session](https://clouddocs.f5.com/api/irules/PEM__session.html), and
[PEM::subscriber](https://clouddocs.f5.com/api/irules/PEM__subscriber.html)
references.

The direct event API also supports `PEM_POLICY`, `PEM_SUBS_SESS_CREATED`,
`PEM_SUBS_SESS_UPDATED`, and `PEM_SUBS_SESS_DELETED` with caller-supplied PEM
event fields. Records are limited to 256 sessions, 256 subscribers, 256
attributes, 256 policies, and 256 IP bindings per record. This is an emulator
of rule-visible state and lifecycle signals; it does not run the PEM policy
engine, Gx/AAA provisioning, or a live PEM Session DB.

### CONNECTOR chain controls

With the `CONNECTOR` profile attached, `CONNECTOR::disable` and
`CONNECTOR::enable` toggle the deterministic connector-chain state, while
`CONNECTOR::profile` returns the profile name supplied in the event state.
`CONNECTOR::remap` accepts the documented `client_addr`, `client_port`,
`server_addr`, and `server_port` targets, validates IP addresses and ports,
and records up to 256 remaps for inspection. The command contracts follow
the [CONNECTOR::disable](https://clouddocs.f5.com/api/irules/CONNECTOR__disable.html),
[CONNECTOR::enable](https://clouddocs.f5.com/api/irules/CONNECTOR__enable.html),
[CONNECTOR::profile](https://clouddocs.f5.com/api/irules/CONNECTOR__profile.html),
and [CONNECTOR::remap](https://clouddocs.f5.com/api/irules/CONNECTOR__remap.html)
references.

The direct event API supports `CONNECTOR_OPEN` with caller-supplied connector
fields. Connector state is reset at connection teardown. This models the
rule-visible control and remap state; it does not create connector sockets,
resolve DNS, establish an upstream chain, or perform live traffic remapping.

### TMM CMP topology

The emulator exposes deterministic, scenario-supplied values for all five
TMOS 17.5 `TMM::cmp_*` commands: active TMM count, current group, group list,
primary group, and current unit. All five commands take no arguments. The
defaults model a single non-chassis TMM (`cmp_count=1`, group/unit/primary
group `0`, and `cmp_groups={0}`); callers can override them with a `tmm` event
state layer. `cmp_groups` accepts either a Tcl list string such as `0 1` or a
JSON array of non-negative integers. This is topology metadata for deterministic
rule testing, not a scheduler or multi-TMM execution model. See the F5
[TMM command family](https://clouddocs.f5.com/api/irules/TMM.html) reference.

### LTM policy matching state

`POLICY::controls`, `POLICY::targets`, `POLICY::names`, and `POLICY::rules`
are available in `HTTP_REQUEST` and `HTTP_RESPONSE`. Supply a `policy` event
state layer to model enabled controls/targets, active/matched/unmatched policy
names, and a mapping from policy names to executed rule names. These fields
accept JSON arrays (and `rules` accepts a JSON object whose values are arrays),
or Tcl-list strings at the low-level event boundary. Lists are bounded at 256
entries. This provides deterministic visibility into a simulated policy
decision; it does not evaluate LTM policy conditions or execute policy actions.
See the F5 [POLICY namespace](https://clouddocs.f5.com/api/irules/POLICY.html)
reference.

### WAM and VDI plugin controls

`WAM::disable` and `WAM::enable` model connection-scoped Web Accelerator
processing. `VDI::disable` and `VDI::enable` model the VDI flow toggle; VDI
commands are accepted at `CLIENT_ACCEPTED` or with a `FASTHTTP` profile, while
WAM commands require an `HTTP` profile. All four commands take no arguments,
record a decision, and reset to enabled at connection teardown. These controls
do not execute WAM/VDI plugin processing or emulate the underlying acceleration
engines. See the F5 [WAM::disable](https://clouddocs.f5.com/api/irules/WAM__disable.html),
[WAM::enable](https://clouddocs.f5.com/api/irules/WAM__enable.html),
[VDI::disable](https://clouddocs.f5.com/api/irules/VDI__disable.html), and
[VDI::enable](https://clouddocs.f5.com/api/irules/VDI__enable.html) references.

### WEBSSO request controls

`WEBSSO::disable`, `WEBSSO::enable`, and `WEBSSO::select` model the APM SSO
decision for the current HTTP request. The state is reset at the beginning of
`HTTP_REQUEST` and remains visible through `HTTP_REQUEST_DATA` and
`ACCESS_ACL_ALLOWED`; `websso.selected` records the selected SSO object.
These commands require an `HTTP` or `ACCESS` profile and reject unrelated
events. They model request-visible control state, not SSO token generation or
an APM backend:

```json
{
  "event": "HTTP_REQUEST",
  "state": {
    "websso": {
      "enabled": true,
      "selected": ""
    }
  }
}
```

See the F5 [`WEBSSO::disable`](https://clouddocs.f5.com/api/irules/WEBSSO__disable.html),
[`WEBSSO::enable`](https://clouddocs.f5.com/api/irules/WEBSSO__enable.html), and
[`WEBSSO::select`](https://clouddocs.f5.com/api/irules/WEBSSO__select.html)
references.

### TAP security-token state

The direct event API supports `TAP_REQUEST` with deterministic TAP state. The
emulator models `TAP::action` and `TAP::score` get/set behavior,
`TAP::insight_requested`, application/entity lookup through `TAP::config`, and
`TAP::insight` set/send accumulation. Configure `tap.config` as an object of
application objects and `tap.insight` as a key/value object; values are bounded
to 256 entries. An insight send returns the configured deterministic token and
clears the accumulated insight. This models rule-visible token decisions and
submission state; it does not contact or reproduce the external TAP service.
See the F5 [TAP namespace](https://clouddocs.f5.com/api/irules/TAP.html)
reference.

### HA active/standby state

`HA::status active|standby` compares the requested role with
`event state.ha.status`, which defaults to `active`. This supports rules that
avoid sideband or HSL work on a standby unit:

```json
{
  "event": "CLIENT_ACCEPTED",
  "state": {"ha": {"status": "standby"}}
}
```

The semantic mock validates both roles and returns Tcl boolean values (`1` or
`0`). See the F5 [`HA::status`](https://clouddocs.f5.com/api/irules/HA__status.html)
reference.

### DS-Lite and BIGPROTO controls

`DSLITE::remote_addr` reads the scenario connection's `remote_addr`. The
`BIGPROTO::enable_fix_reset` setter accepts Tcl boolean values and exposes its
canonical state as `bigproto.enable_fix_reset`, allowing FIX-flow rules to
exercise the reset decision without ePVA hardware:

```json
{
  "event": "CLIENT_ACCEPTED",
  "state": {
    "connection": {"remote_addr": "192.0.2.55"},
    "bigproto": {"enable_fix_reset": false}
  }
}
```

See the F5 [`DSLITE::remote_addr`](https://clouddocs.f5.com/api/irules/DSLITE__remote_addr.html)
and [`BIGPROTO::enable_fix_reset`](https://clouddocs.f5.com/api/irules/BIGPROTO__enable_fix_reset.html)
references.

### BIGTCP flow release

`BIGTCP::release_flow` marks the current connection as
`bigtcp.released=1`. Subsequent data and protocol events are
returned with `reason: "bigtcp_passthrough"` without executing their iRule
handlers; connection lifecycle events remain available so a scenario can be
closed cleanly. The command is accepted in `CLIENT_ACCEPTED`,
`SERVER_ACCEPTED`, and `SERVER_CONNECTED` to support the documented flow
migration patterns. This models the control-plane transition, not ePVA
offload or wire-speed forwarding. See the F5
[`BIGTCP::release_flow`](https://clouddocs.f5.com/api/irules/BIGTCP__release_flow.html)
reference.

### ECA / NTLM authentication controls

The ECA overlay models `ECA::enable`, `ECA::disable`, and `ECA::select` as
connection-scoped controls, and exposes injected identity fields through
`ECA::username`, `ECA::domainname`, `ECA::client_machine_name`, and
`ECA::status`. Scenarios can fire `ECA_REQUEST_ALLOWED` or
`ECA_REQUEST_DENIED` with an `eca` state object to exercise authentication
result handlers without requiring a real domain controller or NTLM exchange.
The state resets on a new `CLIENT_ACCEPTED` connection. This is a deterministic
authentication-result model, not an implementation of NTLM cryptography.

### AVR controls

The AVR overlay models the connection-scoped `AVR::enable` and `AVR::disable`
switches, `AVR::log` as a recorded statistics request, and
`AVR::disable_cspm_injection` during `AVR_CSPM_INJECTION` or `HTTP_RESPONSE`.
The `avr` state layer exposes `enabled`, `cspm_injection_enabled`, and
`log_requested`; it does not generate AVR analytics or JavaScript payloads.
Set the optional top-level `avr.cspm_injection` fixture to `true` to emit
`AVR_CSPM_INJECTION` once after the modeled `HTTP_RESPONSE` handler. The event
is a response mutation point; `AVR::disable_cspm_injection` records the
iRule-visible opt-out, but the emulator does not synthesize or insert CSPM
JavaScript:

```json
{
  "profiles": ["TCP", "HTTP", "AVR"],
  "avr": {"cspm_injection": true},
  "irule": "when AVR_CSPM_INJECTION { AVR::disable_cspm_injection }",
  "request": {"uri": "/analytics", "response_body": "origin-body"}
}
```

The fixture defaults to `false` and resets for each request transaction. See
the F5 [`AVR_CSPM_INJECTION`](https://clouddocs.f5.com/api/irules/AVR_CSPM_INJECTION.html)
reference for the production event description.

### XML profile match events

`XML_CONTENT_BASED_ROUTING` is available as a synthetic event packet when the
`XML` profile is attached. Supply the documented `XML_count`,
`XML_queries(index)`, and `XML_values(index)` inputs through bounded `xml`
event state; the emulator installs them as iRule-visible globals before the
handler runs. Queries and values can be JSON arrays (or Tcl-list strings), and
their lengths must exactly match `count`:

```json
{
  "profiles": ["TCP", "XML"],
  "irule": "when XML_CONTENT_BASED_ROUTING { log local0. $XML_queries(0)=$XML_values(0) }",
  "packets": [{
    "protocol": "event",
    "event": "XML_CONTENT_BASED_ROUTING",
    "state": {
      "xml": {
        "count": 1,
        "queries": ["FinanceObject"],
        "values": ["Invoice"]
      }
    }
  }]
}
```

This is a deterministic profile-match injection point for rule testing. It
does not parse XML wire payloads, evaluate XML profile match expressions, or
implement the deprecated XML parser event family. See the F5
[`XML_CONTENT_BASED_ROUTING`](https://clouddocs.f5.com/api/irules/XML_CONTENT_BASED_ROUTING.html)
reference.

### Internal virtual server entry events

`IVS_ENTRY_REQUEST` and `IVS_ENTRY_RESPONSE` can be injected as synchronous
events when the `IVS_ENTRY` profile is attached. `IVS_ENTRY::result` supports
the bounded `noop`, `modified`, and `response` outcomes and records the
request/response entry history under `semantic.feature_controls`. This is a
deterministic internal-virtual-server handoff fixture; it does not create a
second virtual server, open an internal connection, or run an adaptation
service. See the F5
[`IVS_ENTRY_REQUEST`](https://clouddocs.f5.com/api/irules/IVS_ENTRY_REQUEST.html)
and
[`IVS_ENTRY_RESPONSE`](https://clouddocs.f5.com/api/irules/IVS_ENTRY_RESPONSE.html)
references.

### Legacy GTM event injection

The pinned registry retains `IP_GTM`, `TCP_GTM`, and `UDP_GTM` as compatibility
event names even though the current F5 master event list documents GTM DNS
events rather than these legacy names. They can be fired synchronously as
synthetic event packets, using the normal `connection` or `datagram` state
layers for rule-visible protocol values. This exercises handler dispatch and
command behavior only; it does not emulate GTM wide-IP selection, DNS
resolution, or a second GTM dataplane:

```json
{
  "profiles": ["TCP"],
  "irule": "when TCP_GTM { log local0. [TCP::client_port] }",
  "packets": [{
    "protocol": "event",
    "event": "TCP_GTM",
    "state": {"connection": {"client_port": 41000}}
  }]
}
```

### BWC flow controls

The BWC overlay models the complete TMOS 17.5 command family as deterministic
flow state. `BWC::policy attach` and `BWC::policy detach` manage the attached
policy and optional session identifier; `BWC::rate`, `BWC::pps`,
`BWC::color`, `BWC::mark`, and `BWC::priority` record the corresponding
per-flow controls. `BWC::measure` supports start/stop, identifiers, and
`get rate|bytes`; because the emulator has no scheduler or wall-clock traffic
shaper, the reported rate is a deterministic bytes-per-second sample based on
the visible event payload. `BWC::debug start|stop` is recorded as a diagnostic
toggle. Control state resets at connection boundaries and is exposed under
`semantic.bwc`. The adapter does not implement TMM bandwidth enforcement,
queue scheduling, dynamic policy lookup, or external log publishers. See the
F5 [`BWC::policy`](https://clouddocs.f5.com/api/irules/BWC__policy.html),
[`BWC::measure`](https://clouddocs.f5.com/api/irules/BWC__measure.html), and
[`BWC::mark`](https://clouddocs.f5.com/api/irules/BWC__mark.html) references.

### FIX tag state

The direct `FIX_MESSAGE` adapter accepts a `fix.tags` object and exposes it to
`FIX::tag get <tag>`. Missing tags return an empty string, and tags are reset
when the next FIX message event begins. `FIX::tag map set SENDER DATA_GROUP`
and `FIX::tag map delete` maintain a persistent, bounded sender-to-data-group
mapping that can be configured from `RULE_INIT` or another event:

```json
{
  "event": "FIX_MESSAGE",
  "state": {
    "fix": {
      "tags": {"49": "client1", "35": "A", "56": "TARGET"},
      "tag_maps": {"client1": "/Common/fix_tag_map"}
    }
  }
}
```

Tag retrieval is restricted to `FIX_HEADER` and `FIX_MESSAGE`; map mutation is available in any
event.

Packet replay accepts a structured `protocol: "fix"` packet with the same
`fix.tags` and optional `fix.tag_maps` objects. It emits `FIX_HEADER` followed
by `FIX_MESSAGE` for each packet, preserving tag values across both handlers:

```json
{
  "protocol": "fix",
  "direction": "client_to_server",
  "fix": {
    "tags": {"35": "D", "49": "client1", "56": "TARGET", "11": "order-1"}
  }
}
```

Raw FIX/TCP captures are also decoded when the `FIX` profile is attached. The
decoder reassembles split and coalesced messages, validates tags 8/9/10,
`BodyLength`, and the modulo-256 `CheckSum`, then feeds the resulting tag map
through the same `FIX_HEADER` and `FIX_MESSAGE` handlers. Use `payload_hex` when
the capture contains SOH (`0x01`) delimiters:

```json
{
  "protocol": "tcp",
  "direction": "client_to_server",
  "source": {"address": "192.0.2.10", "port": 51000},
  "destination": {"address": "192.0.2.20", "port": 9876},
  "payload_hex": "383d4649582e342e3401393d..."
}
```

The raw decoder is intentionally bounded and exposes tags as the existing map
state: repeating tags retain their final value. It does not implement FIX
session negotiation, a data dictionary, repeating-group structure, or a live
counterparty. The bundled protocol driver can generate a valid framed message
from `request.fix.tags`, or send independently prepared `message_hex`/
`message_base64` bytes to a collector. See the F5
[`FIX::tag`](https://clouddocs.f5.com/api/irules/FIX__tag.html) reference.

### FLOWTABLE query inputs

The TMOS 17.5 `FLOWTABLE::count` and `FLOWTABLE::limit` commands use bounded,
scenario-provided data so rules can test branching and logging without a live
TMM. For example:

```json
{
  "flowtable": {
    "count": {
      "global": 42,
      "virtual": {"/Common/app": 7, "default": 8},
      "route_domain": {"0": 9}
    },
    "limit": {
      "virtual": {"/Common/app": 100},
      "route_domain": {"0": 1000}
    }
  }
}
```

`FLOWTABLE::count` accepts no arguments for the global count, or
`virtual [NAME]` and `route_domain [NAME]`. `FLOWTABLE::limit` accepts
`virtual [NAME]` and `route_domain [NAME]`. An omitted name looks up the
`default` key; an absent entry returns `0`. This is intentionally a query
model: it does not create or age flows, replicate state between TMMs, or
enforce limits against traffic.

### Payload protocol validation

`VALIDATE::protocol APPLICATION PAYLOAD` returns `1` for a bounded signature
match and `0` for a non-match. The current deterministic model recognizes
common HTTP/1.x and HTTP/2 prefaces, TLS records, SSH banners, FTP greetings
or commands, and SMTP greetings or commands. Other classifier names are
conservative non-matches; no external inspection or licensed APM/AFM/PEM
classification is performed.

### L7 check and link metadata

`L7CHECK::protocol set VALUE` and `L7CHECK::protocol get` are available in
`L7CHECK_CLIENT_DATA`, `L7CHECK_SERVER_DATA`, and `CONNECTOR_OPEN` when the
session has the `L7CHECK` or `CONNECTOR` profile. The value persists across
events in one connection and is reset when a new client connection starts.

Packet replay can emit the two data events from structured `l7check` packets:

```json
{
  "protocol": "l7check",
  "direction": "client_to_server",
  "l7_protocol": "http",
  "payload": "GET / HTTP/1.1\r\n\r\n"
}
```

Each packet emits `L7CHECK_CLIENT_DATA` or `L7CHECK_SERVER_DATA` according to
its direction. `l7_protocol` is optional; when supplied it seeds
`L7CHECK::protocol`, while a value changed by the iRule persists into later
packets in the same connection. The adapter supplies the payload and label; it
does not classify arbitrary bytes or reproduce the BIG-IP L7 check engine.

The link commands read a caller-supplied `link` event-state layer:

```json
{
  "event": "CLIENT_ACCEPTED",
  "state": {
    "link": {
      "qos": 5,
      "vlan_id": 4094,
      "lasthop_mac": "aa:bb:cc:dd:ee:ff",
      "lasthop_id": "last-1",
      "lasthop_type": "router",
      "lasthop_name": "edge-a",
      "nexthop_mac": "11:22:33:44:55:66",
      "nexthop_id": "next-1",
      "nexthop_type": "router",
      "nexthop_name": "core-a"
    }
  }
}
```

`LINK::lasthop` and `LINK::nexthop` return the MAC address by default, or the
`id`, `type`, or `name` selector when supplied. `LINK::qos` and
`LINK::vlan_id` return the corresponding values. If no link state is supplied,
QoS and VLAN return `0`, last-hop fields are empty, and next-hop MAC returns
`ff:ff:ff:ff:ff:ff`, matching the documented pre-server-connection behavior.
The legacy `lasthop` and `nexthop` setters update the same link state. MAC
targets populate the MAC field; IP targets are retained as unresolved intent in
the `id` field, and an optional VLAN is retained in the `name` field. This is
structured metadata, not a live NIC, ARP, VLAN, routing, or QoS model.

### SOCKS request state

`SOCKS::version`, `SOCKS::allowed`, and `SOCKS::destination` are available in
`SOCKS_REQUEST` with the `SOCKS` profile. Supply the request state through the
event API:

```json
{
  "event": "SOCKS_REQUEST",
  "state": {
    "socks": {
      "version": "5",
      "allowed": 1,
      "destination_host": "proxy.example",
      "destination_port": 1080
    }
  }
}
```

`SOCKS::allowed` reads or sets `0`/`1`. `SOCKS::destination` reads or updates
the combined `HOST:PORT`, or reads/updates `host` and `port` independently;
IPv6 hosts use `[HOST]:PORT`. The model records the decision and destination
but does not implement a SOCKS handshake, proxy socket, or live connection.
Packet traces may use `protocol: "socks"` with a `payload_hex` request body.
The adapter decodes one SOCKS4/SOCKS4a or SOCKS5 request and supplies its
version and destination to the same event:

```json
{
  "protocol": "socks",
  "direction": "client_to_server",
  "payload_hex": "050100030f626c6f636b65642e6578616d706c6501bb"
}
```

SOCKS5 IPv4, IPv6, and domain destinations are supported; SOCKS4a domain
requests are supported as well. Malformed or unsupported request bytes are
rejected as packet input, and the emulator does not synthesize a SOCKS reply
or open a proxy connection. The packet result includes the decoded command,
destination, and final `allowed` decision.

### SDP state

`SDP::field`, `SDP::media`, and `SDP::session_id` are available during SIP
message events when the `SIP` profile is attached. Supply a bounded structured
SDP overlay through the event API, or provide a SIP packet with a
`Content-Type: application/sdp` body and let the adapter derive the overlay.
`fields` is a Tcl list of repeated field/value pairs; `media` is a Tcl list
whose entries are dictionaries with `type`, `port`, `transport`, `conn`, and
`attrs` keys:

```json
{
  "event": "SIP_REQUEST",
  "state": {
    "sdp": {
      "session_id": "2890844526",
      "fields": "version 0 origin {alice 2890844526 2890842807 IN IP4 host.example} connection {IN IP4 203.0.113.1} attribute sendrecv",
      "media": "{type audio port 49170/2 transport RTP/AVP conn {IN IP4 203.0.113.1} attrs {rtpmap:0\\ PCMU/8000 sendrecv}}"
    }
  }
}
```

`SDP::field name` reads the first matching field and
`SDP::field name index value` rewrites an existing occurrence. `SDP::media`
supports `count`, indexed media dictionaries, `attr`, `type`, `port`,
`transport`, and `conn`; media ports accept `PORT` or `PORT/COUNT` and are
bounded to the 0–65535 port range. `SDP::session_id` returns the session ID
from the `o=` field when raw SDP is parsed, or the supplied identifier for a
structured overlay. For raw SDP packets, bounded field/connection mutations
are serialized back into the SIP body and `Content-Length` is recomputed;
unknown SDP lines are retained. Bodies over 64 KiB, malformed SDP, and
non-UTF-8 SDP remain opaque rather than being partially parsed. The adapter
does not implement full RFC 4566 validation or media negotiation.

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
`GET /v1/probes`, `GET /v1/catalog-smoke`, `GET /v1/behavior-candidates`,
`GET /v1/behavior-sweep`,
`GET /v1/conformance`, `POST /v1/simulations`, `POST /v1/analyze`,
`POST /v1/command-probes`, `POST /v1/behavior-packs`,
`POST /v1/behavior-coverage`, `POST /v1/behavior-candidates`,
`POST /v1/behavior-sweep`, and
`POST /v1/simulations/pcap`. It also supports persistent sessions through
`POST /v1/sessions`, `GET /v1/sessions/{session_id}`,
`POST /v1/sessions/{session_id}/requests`,
`POST /v1/sessions/{session_id}/packets`, and
`DELETE /v1/sessions/{session_id}`. Combined API/data-plane mode additionally
provides `GET` and `DELETE /v1/live-observations`, plus
`POST /v1/live-observations/capture-plan`. It binds to `127.0.0.1` by default, caps
JSON request bodies at 2 MiB, and does not expose arbitrary Tcl evaluation.
The HTTP API accepts inline `irule` text only; use the CLI's `irule_file` field
when a rule must be loaded from a local file.
`GET /` (also available as `/workbench`) serves a dependency-free browser
workbench for the same localhost API. It creates persistent sessions, sends
high-level requests, injects events, replays packet arrays, and searches the
full catalog. The page is served from the repository and makes no external
network requests.

### One-command container stack

Docker Compose provides a portable evaluation stack with the API on port 8080
and the deterministic real-client HTTP data plane on port 18080. It builds the
same Python 3.13 image used by CI and pins the tcl-lsp checkout unless
`TCL_LSP_COMMIT` is overridden:

```sh
docker compose up --build -d
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:18080/health
curl -i http://127.0.0.1:18080/health
docker compose down
```

The Compose service uses the checked-in
[`live-http-17.5.json`](../examples/scenarios/live-http-17.5.json) fixture, so
the data-plane response is deterministic. The image healthcheck only tests API
readiness; it does not claim that the modeled listener reproduces a live BIG-IP
or that the scenario has independent TMOS observation evidence.

The conformance response includes a machine-readable `coverage` matrix. It
separates complete catalog ingestion from partial command behavior and event
lifecycle coverage, and reports target-only behavioral, placeholder, unhandled,
and unmapped counts. These are inventory dimensions, not a fidelity score:
generated stubs are recognized commands, not claims of BIG-IP semantics. The
registry also contains Tcl language/runtime support entries used while parsing
or executing iRules. Use `commands.catalog_kind_counts` and the separate
`coverage.f5_command_behavior` / `coverage.support_command_behavior` sections
to distinguish the F5 iRule surface from those support entries; `when` is
classified as an iRule language construct rather than a runtime command.

`GET /v1/probes` provides live registration evidence for one bounded catalog
chunk. It accepts the same `offset`, `limit`, `namespace`, `runtime_status`,
and `target_status` filters as `/v1/capabilities`:

```sh
curl -sS 'http://127.0.0.1:8080/v1/probes?namespace=HTTP&limit=25'
```

Each returned command includes `registered` and `resolved_handler`. The probe
checks the running framework's `::itest::_command_map`, which is the dispatch
table used by Tcl's `unknown` handler; it does not execute command bodies and
does not turn registration into a claim of TMM semantic parity. This makes it
safe to inventory getters, setters, and protocol-dependent commands while
building implementation slices from the complete catalog.

For an executable, bounded next step, `--catalog-smoke` runs a zero-argument
probe for each safe command in one catalog chunk. The default target filter is
`available-in-tmos-17.5`, the default CLI chunk is 16, and the hard maximum is
32 commands per invocation:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --catalog-smoke --namespace HTTP --limit 16
```

The same report is available from
`GET /v1/catalog-smoke?namespace=HTTP&limit=16` and the
`irule_catalog_smoke` MCP tool. Each row records the generated event/profile
fixture and classifies the result as `ok`, `argument-required`,
`profile-gated`, `runtime-error`, `fixture-error`, `unregistered`, or
`skipped-unsafe`. `ok` means the generated fixture completed in this emulator;
it is deliberately not a TMOS semantic-parity score. `argument-required` is a
useful queue for the next pass, where a human or collector supplies
command-specific arguments from the catalog synopsis and captures a TMOS 17.5
golden vector.

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
records, and 2 MiB per packet. IPv4 and IPv6 fragments are reassembled within
bounded fragment sets before transport decoding. TCP sequence numbers are honored for
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

### Read-only iRule preflight

`POST /v1/analyze` runs the pinned Tcl-LSP analyser in the `f5-irules` dialect
and adds TesTcl's static TMOS 17.5 compatibility findings. It never creates a
Tcl interpreter and never executes the submitted rule. The request accepts an
inline `irule`, optional attached `profiles`, and optional `include_fidelity`
(default `true`):

```json
{
  "irule": "when HTTP_REQUEST priority 500 { HTTP::header replace X-Test yes }",
  "profiles": ["TCP", "HTTP"],
  "include_fidelity": true
}
```

The response contains zero-based LSP ranges in `diagnostics`. Entries with
`source: "tcl-lsp"` are parser/analyser findings; entries with
`source: "testcl"` and `category: "compatibility"` are TMOS 17.5 target and
profile checks and may not have a source range. `valid` is false when any
reported diagnostic has error severity. Source size, line count, line length,
and diagnostic count are bounded to keep the endpoint suitable for an
interactive workbench or an AI tool.

The HTTP lifecycle also exposes the modeled ACCESS session, policy-agent,
per-request-agent, policy-completion, ACL, and session-close events, plus the
profile-gated Bot Defense and Anti-Fraud request events. These transitions use
bounded scenario fixtures and existing deterministic policy state; they are
not claims of live policy evaluation or production security-service behavior.
The `AUTH_RESULT`, `AUTH_SUCCESS`, `AUTH_FAILURE`, `AUTH_ERROR`, and
`AUTH_WANTCREDENTIAL` events are likewise available when a rule drives the
fixture-backed `AUTH::authenticate` flow; they model the command-driven
authentication state machine, not a live authentication backend.

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
- `irule_analyze` performs read-only Tcl-LSP and TMOS 17.5 compatibility preflight on one inline iRule.
- `irule_pcap_replay` replays a base64-encoded classic PCAP or pcapng capture through the same
  packet and Tcl event adapters.
- `irule_capabilities` returns a chunk of the complete 17.5 catalog.
- `irule_capture_campaign` returns a chunk of catalog-derived external
  reference work units, defaulting to commands available in TMOS 17.5.
- `irule_probe` verifies live command registration for a bounded catalog chunk
  without executing catalog commands.
- `irule_catalog_smoke` executes safe zero-argument probes for a bounded
  target catalog chunk and classifies behavior without claiming TMOS parity.
- `irule_behavior_coverage` maps supplied behavior packs to the available F5
  catalog and returns the uncovered implementation queue.
- `irule_behavior_candidates` turns that queue into a bounded, reference-free
  command-probe capture plan with registry-derived argument hypotheses.
- `irule_behavior_sweep` executes a bounded candidate chunk locally and reports
  compact runtime evidence without presenting it as TMOS observation data.
- `irule_conformance` reports static catalog/runtime and packet-adapter coverage.
- `irule_session_create`, `irule_session_inspect`, `irule_session_request`,
  `irule_session_trace`, `irule_session_event`, and `irule_session_close` manage
  persistent sessions.
- `irule_assemble_observations` combines a capture plan with externally
  collected TMOS 17.5 records without executing the emulator.

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
`retry.exhausted`. With `-reset`, the replay receives a fresh deterministic
server-side connection identity while the client-side connection, iRule
variables, and request retry budget remain intact. This models the documented
server-side reset boundary without opening a real upstream socket.
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
Entries that F5 documents as unavailable in this release are marked
`unavailable-in-tmos-17.5`; both non-available statuses are rejected during
scenario validation.

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

The capability response can be narrowed into deterministic implementation
work slices without changing the catalog order:

```sh
# First five AUTH commands with semantic emulator coverage
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capabilities --namespace AUTH --runtime-status semantic-mock \
  --offset 0 --limit 5

# All commands known to be newer than the target release
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capabilities --target-status introduced-after-tmos-17.5 \
  --offset 0 --limit 100
```

Use `--target-status unavailable-in-tmos-17.5` to inspect catalog entries
retained for reference but not runnable against the target profile. For TMOS
17.5 this includes the legacy XML command family; F5 documents those XML
commands and events as unavailable beginning in v10, except for
`XML_CONTENT_BASED_ROUTING`.

The same filters are available through `GET /v1/capabilities` and the
`irule_capabilities` MCP tool as `namespace`, `runtime_status`, and
`target_status`. `summary.filtered_command_count` and `chunk.total` describe
the filtered view, while the unfiltered summary counts remain available for
the complete registry. Each command includes its catalog synopsis, return
description, and source reference so a worker can build a semantic mock from
the bounded slice without rereading the registry checkout.
`GET /v1/conformance` and `irule_conformance` additionally return
`commands.implementation_queue`, grouped by F5 namespace and current runtime
status. Use that compact queue to choose a work family, then consume that
family through the filtered capability chunks.

For consumers that want one reproducible ingest operation, `--catalog` walks
the capability pages and emits a manifest containing every filtered command
inside deterministic chunks, plus the shared event and profile catalogs:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --catalog --limit 250 > catalog-17.5.json
```

The same manifest is available from `GET /v1/catalog?chunk_size=250` and the
`irule_catalog` MCP tool. A catalog consumer can persist each `chunks[*]`
entry, use its offsets as stable work checkpoints, and dispatch only commands
whose `target_status` is available and whose `runtime_status` is not yet
semantic. This makes catalog ingestion a repeatable input to the semantic-mock
implementation queue rather than a manually copied list.

For independent TMOS 17.5 behavior collection, generate a catalog-derived
reference campaign instead of copying command names by hand:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capture-campaign --offset 0 --limit 100 > campaign-000.json
```

The default campaign includes only F5 iRule entries marked
`available-in-tmos-17.5` (currently the target F5 command surface, not the
broader Tcl core/tcllib catalog). Each case carries its catalog namespace,
runtime and target status, safety/purity flags, documentation, and event
requirements. A collector uses those fields to choose valid event/profile/argument fixtures,
then emits `{ "id": "...", "output": {...} }` records for the matching
capture plan. Advance by `campaign.chunk.count` while `has_more` is true; use
`--namespace`, `--runtime-status`, or `--target-status` to split work among
collectors. The campaign is a work queue, not reference evidence, and does not
pretend that a generated probe is valid for every command.

The same view is available from `GET /v1/capture-campaign` and the
`irule_capture_campaign` MCP tool.

To turn one campaign chunk into an assembly-ready plan, use the capture-plan
template mode:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capture-plan-template --offset 0 --limit 100 \
  --capture-source bigip-vlab-17.5.4 \
  --capture-collector my-collector \
  --tmos-build 17.5.4 \
  --capture-id run-001 > capture-plan-000.json
```

The generated plan contains one `command_probe` observation per runnable
catalog command, a target-valid event/profile shell, and a status comparison.
By default its empty `args` array preserves the conservative legacy template:
command arguments and fixture values must be selected by the collector or
operator from the catalog synopsis. Set `--variants 2` through `--variants 8`
to add bounded, registry-derived argument hypotheses to each command (the
plan remains capped at 256 observations). These hypotheses are useful starter
inputs, not a claim that every generated form is valid for every device build.
HTTP/1.1, WebSocket-over-HTTP/1.1, DNS, MQTT, SIP, PCP,
and RADIUS event templates also include a small
starter `request` fixture for the bundled protocol driver; replace its
destination and values for the target environment. Replace the placeholder
provenance when using the defaults. The plan contains no reference output and
therefore is not evidence until a real BIG-IP or vLab collector produces
matching records.

The HTTP equivalent is `GET /v1/capture-plan-template`; it accepts the same
pagination and filtering parameters as the campaign endpoint plus
`source`, `collector`, `tmos_build`, `capture_id`, `name`, and `variants`. The
MCP equivalent is `irule_capture_plan_template` and accepts the same
`variants` bound.

### Optional BIG-IP observation collector

The repository includes a separate, standard-library collector at
`tools/tmos17-collector.py` and `scripts/collect-tmos17.sh`. It is dry-run by
default and does not need BIG-IP credentials for plan inspection:

```sh
./scripts/collect-tmos17.sh --plan capture-plan-000.json
```

For an explicit live run, set `BIGIP_USERNAME` and `BIGIP_PASSWORD`, then
provide an existing virtual server and a URL that reaches it:

```sh
BIGIP_USERNAME=admin BIGIP_PASSWORD='…' \
  ./scripts/collect-tmos17.sh \
  --plan capture-plan-000.json \
  --execute --allow-device-write \
  --bigip-url https://bigip.example \
  --virtual /Common/irule-test-vs \
  --traffic-url http://198.18.0.1:18080 \
  > records.ndjson
```

The collector creates one temporary diagnostic iRule per case, attaches it to
the selected virtual, drives `HTTP_REQUEST` cases (and observes `RULE_INIT`),
reads a structured `/var/log/ltm` record through iControl REST, and restores
the virtual before deleting the temporary rule. Both `--execute` and
`--allow-device-write` are required. TLS verification is enabled by default;
`--insecure` is an explicit opt-out.

For events that require a protocol-specific stimulus, pass an executable
protocol driver:

```sh
BIGIP_USERNAME=admin BIGIP_PASSWORD='…' \
  ./scripts/collect-tmos17.sh \
  --plan mqtt-capture-plan.json \
  --execute --allow-device-write \
  --bigip-url https://bigip.example \
  --virtual /Common/irule-test-vs \
  --traffic-url http://198.18.0.1:18080 \
  --trigger-command /opt/drivers/mqtt-driver \
  > records.ndjson
```

The collector invokes the driver once per non-`HTTP_REQUEST`/non-`RULE_INIT`
case with no shell. It writes one UTF-8 JSON object to the driver's stdin and
requires exit status zero; stdout and stderr are discarded. The object contains
`profile`, `case`, `event`, `command`, `args`, `profiles`, `traffic_url`, and
the selected `virtual`; it also includes the plan's optional `request` object
when one is present. The driver is
responsible for producing the protocol traffic that reaches that virtual;
the collector remains responsible for iRule isolation, log correlation,
observation polling, and cleanup. Driver execution is bounded by
`--trigger-timeout` (1–300 seconds, default 60). A driver may be a compiled
binary, shell-free wrapper, or another executable; if it needs arguments,
provide a purpose-built wrapper executable rather than a shell command line.

Without a driver, plans containing events outside the built-in HTTP/RULE_INIT
subset are rejected before any device mutation. `--allow-partial` may instead
skip those cases. Partial output must be paired with a matching subset plan
before assembly.

The repository includes a dependency-light starter driver at
`tools/tmos17-protocol-driver.py`, with the local `uv`-enforcing wrapper
`scripts/tmos17-protocol-driver.sh`. It supports DNS queries, MQTT 3.1.1
CONNECT plus PUBLISH traffic, generated or raw SIP messages, structured RTSP
requests, raw or structured ICAP/1.0 requests/responses, raw or structured TDS
packet messages, FTP control-channel commands/responses, LDAP BER messages, and
generic raw UDP/TCP payloads, plus IMAP/POP3/SMTPS control lines. Protocol
fixtures belong in the plan's optional `request` object. HTTP/2 `HTTP_REQUEST`
fixtures additionally include an `http2` object; the driver emits the client
prior-knowledge preface, SETTINGS, and HPACK-encoded HEADERS/DATA frames. Use
`http://` or `tcp://` destinations for cleartext h2c, or `https://` for TLS
with ALPN `h2`; certificate verification remains enabled. For example, an
HTTP/2 case can use:

```json
{
  "id": "http2-active-example",
  "operation": "command_probe",
  "input": {
    "command": "HTTP2::active",
    "args": [],
    "event": "HTTP_REQUEST",
    "profiles": ["TCP", "HTTP"],
    "request": {
      "method": "GET",
      "uri": "/testcl/command",
      "host": "vip.example.test",
      "http2": {
        "active": true,
        "version": 2,
        "stream_id": 3,
        "pseudo_headers": {
          ":authority": "vip.example.test",
          ":method": "GET",
          ":path": "/testcl/command",
          ":scheme": "https"
        }
      }
    },
    "comparisons": [{
      "label": "status",
      "actual_path": ["execution", "status"],
      "reference_path": ["status"]
    }]
  }
}
```

Set the destination with the collector's `--traffic-url` (for example,
`https://198.18.0.10:443`) and use the protocol-driver trigger shown above;
the request fixture is intentionally limited to transaction fields so the
capture plan remains portable between BIG-IP/vLab targets.

The driver validates and transmits the fixture but does not implement a full
HTTP/2 client or wait for a complete response. A DNS case can use:

For `RTSP_REQUEST_DATA`, the collector adds a short `RTSP_REQUEST` primer that
requests collection before invoking the target data event. The driver sends
the structured RTSP request and optional UTF-8 body; it does not emulate an
RTSP server response.

```json
{
  "id": "dns-request-example",
  "operation": "command_probe",
  "input": {
    "command": "DNS::question",
    "args": [],
    "event": "DNS_REQUEST",
    "profiles": ["UDP", "DNS"],
    "request": {
      "destination": "udp://198.18.0.53:53",
      "qname": "example.com",
      "qtype": "A"
    }
  },
  "comparisons": [{
    "label": "status",
    "actual_path": ["execution", "status"],
    "reference_path": ["status"]
  }]
}
```

For generic protocol events, provide `request.destination` as `udp://` or
`tcp://` and either `payload_base64` or a UTF-8 `payload`. The driver does not
wait for or synthesize a response; it only produces the stimulus needed to
reach the virtual and returns non-zero when validation or transmission fails.
For FTP control traffic, use `event: "CLIENT_DATA"` with
`request.ftp.command`, or `event: "SERVER_DATA"` with
`request.ftp.response_code` and `request.ftp.text`/`lines`; the default
destination port is 21. The driver adds CRLF framing and can emit bounded
multiline replies.
For IMAP, POP3, or SMTPS control traffic, use the same data events with
`request.starttls.protocol` and either `request.starttls.command` for client
traffic or a raw `request.starttls.message` for server traffic. The default
ports are 143, 110, and 465 respectively.
For LDAP control traffic, use the same data events with
`request.ldap.operation` (for example `bindRequest`, `searchRequest`, or
`bindResponse`) and its structured fields, or provide `message_hex`/
`message_base64` for an independently prepared BER message. The default
destination port is 389.
For FIX control traffic, use `event: "FIX_MESSAGE"` or a client/server data
event with `request.fix.tags` to generate a checksummed message; use
`request.fix.message_hex` or `request.fix.message_base64` to send prepared raw
bytes. The default destination port is 9876.
In a local checkout, use `--trigger-command ./scripts/tmos17-protocol-driver.sh`;
in the emulator image, use
`--trigger-command /opt/testcl/tools/tmos17-protocol-driver.py`.

The same bounded HTTP, DNS, MQTT, SIP, RTSP, PCP, and RADIUS request fixtures
can be replayed through the local differential path with `--golden-vectors` or the command-workbench
API. The adapter converts those request objects into deterministic protocol
packets before firing the catalogued event, so command results can be compared
with an assembled observation pack. Generic raw UDP/TCP request fixtures remain
collector-only for now; local replay rejects them explicitly instead of
silently treating arbitrary bytes as a protocol event.

## Structured packet traces

One-shot scenarios may use `packets` instead of `request`/`requests`. A trace
is a bounded sequence of structured packet records. TCP SYN/FIN/RST, TCP
payloads, TLS handshake/data records, HTTP
request/response pairs, WebSocket upgrade/frame packets, DNS request/response
messages, and SIP request/response messages are translated into the same Tcl events and state
layers used by the HTTP API. Structured HTTP packet traces also honor
`http_proxy.chain.responses`, so a bounded proxy `407`/retry/`200` negotiation
can be exercised without changing the packet input format. Generic UDP payloads are reported as unmapped
because there is no protocol-specific event to infer. WebSocket support is a
structured packet adapter: it models the HTTP upgrade and the eight WebSocket
frame/data events, and the raw TCP/PCAP path decodes RFC 6455 frames after a
successful upgrade. Compressed frames using unsupported RSV extensions are
rejected; raw IPv4 and IPv6 fragments are reassembled within bounded resource
limits before protocol decoding.

Packet records may optionally include a `flow_id` string of at most 128 UTF-8
bytes. Without one, the adapter derives a direction-independent flow identity
from transport family plus the client/server endpoint pair (the endpoints are
swapped for server-to-client packets). An explicit `flow_id` is authoritative
and requests that packets carrying that ID share one isolated context. When a
trace contains interleaved flows, each flow is replayed in its own Tcl context
and the resulting trace, emissions, and HTTP results are merged by the original
packet index. Replay is bounded to 64
flows. Sequential connection traces retain one Tcl context so `RULE_INIT` and
scenario-wide globals preserve their existing behavior. Isolation prevents
pending requests, connection-scoped state, and stream buffers from leaking
between interleaved flows, but it intentionally does not claim TMM-wide shared
Tcl globals across those isolated contexts.
Synthetic `{"protocol":"event"}` records must carry `flow_id` when they are
combined with another flow; otherwise there is no safe target connection for
the event. `RULE_INIT` therefore runs once per isolated flow in a multi-flow
trace.

Persistent sessions created through the HTTP `/v1/sessions` or MCP session
tools retain these packet-flow contexts between trace calls. For example, an
HTTP request may be sent in one `/packets` call and its response in a later
call; use the same explicit `flow_id` on both calls when endpoint metadata is
not available. Persistent flow contexts are retired after FIN/RST and are
bounded by the same 64-flow limit.
The persistent request API accepts an optional `flow_id` field in its request
object, and the MCP request tool accepts the same field as a tool argument.
Requests, packet traces, and injected events carrying the same explicit ID use
the same Tcl context. An unscoped request follows the same routing rule as an
unscoped event: it uses the base context or sole retained flow, and is rejected
when multiple flow contexts are active.
Persistent session event injection may also provide the same `flow_id`; an
event without one is routed to the base context before flow multiplexing, to
the sole retained flow when exactly one exists, and is rejected when multiple
flow contexts exist.
The WebSocket payload-processing controls are also modeled: `WS::payload_ivs`
records the selected internal virtual server and `WS::payload_processing` tracks
whether payload protocol processing is enabled or disabled. These are
connection-scoped decisions returned in WebSocket event state; the emulator
does not execute an IVS or a payload protocol inspection engine.
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

`STREAM_MATCHED` can be fired directly with a structured `stream.match` value.
The TMOS 17.5 `STREAM::*` surface then models connection-scoped enable/disable,
encoding, expression, and maximum-match-size settings, plus the current
one-shot replacement request. The resulting stream state and decisions are
returned with the event. This slice does not scan raw TCP payloads for stream
matches, schedule partial matches across packets, tear down an over-limit
connection, or mutate forwarded wire bytes; callers provide the match that
would have been found by a production stream filter.

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
disconnect packets can drive client/server ingress and egress events. A
client-to-server packet fires `MQTT_CLIENT_INGRESS` and then
`MQTT_SERVER_EGRESS`; a server-to-client packet fires
`MQTT_SERVER_INGRESS` and then `MQTT_CLIENT_EGRESS`. `MQTT::drop` suppresses
the corresponding egress event. `MQTT::collect` on a `PUBLISH` drives the
corresponding `*_DATA` event with the collected payload. Raw MQTT-over-TCP
payloads are decoded after bounded TCP
reassembly, including messages split across segments and multiple messages in
one segment. `MQTT::payload`, `MQTT::drop`, `MQTT::release`, and the common
MQTT field getters/setters are semantic mocks. `MQTT::will` mutates CONNECT
will fields; `MQTT::replace` rebuilds the current message; and `MQTT::respond`
and `MQTT::insert` expose ordered, encoded wire emissions in each event result.
The message commands validate the documented CONNECT, CONNACK, PUBLISH,
subscription, acknowledgement, ping, and disconnect forms. Forwarded and
emitted packets are deterministic adapter outputs, not live MQTT socket
traffic. See the F5 [`MQTT`](https://clouddocs.f5.com/api/irules/MQTT.html),
[`MQTT::collect`](https://clouddocs.f5.com/api/irules/MQTT__collect.html), and
[`MQTT::payload`](https://clouddocs.f5.com/api/irules/MQTT__payload.html),
[`MQTT::insert`](https://clouddocs.f5.com/api/irules/MQTT__insert.html),
[`MQTT::replace`](https://clouddocs.f5.com/api/irules/MQTT__replace.html),
[`MQTT::respond`](https://clouddocs.f5.com/api/irules/MQTT__respond.html), and
[`MQTT::will`](https://clouddocs.f5.com/api/irules/MQTT__will.html)
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
The SIPALG controls `SIPALG::hairpin`, `SIPALG::hairpin_default`, and
`SIPALG::nonregister_subscriber_listener` are modeled on the same structured
SIP lifecycle. Hairpin mode is message-scoped and supports `detect`, `enable`,
and `disable`; the default hairpin mode and nonregistered-subscriber listener
flag are connection-scoped. Their current values are included in each packet
event's semantic state under `semantic.sipalg`. The emulator records these
rule-visible controls but does not implement SIP ALG address translation,
hairpin routing, or ephemeral listener creation. See the F5
[`SIPALG::hairpin`](https://clouddocs.f5.com/api/irules/SIPALG__hairpin.html),
[`SIPALG::hairpin_default`](https://clouddocs.f5.com/api/irules/SIPALG__hairpin_default.html),
and [`SIPALG::nonregister_subscriber_listener`](https://clouddocs.f5.com/api/irules/SIPALG__nonregister_subscriber_listener.html)
references for the command contract.

The emulator also models the legacy connection controls
`DEMANGLE::enable`/`DEMANGLE::disable`,
`ISESSION::deduplication enable|disable`,
`PLUGIN::enable <plugin>`, and `PLUGIN::disable [<plugin>]`. Their current
state is exposed under `semantic.feature_controls`, and
`IVS_ENTRY::result noop|modified|response` records a bounded result history
when fired during `IVS_ENTRY_REQUEST`, `IVS_ENTRY_RESPONSE`, `ICAP_REQUEST`,
or `ICAP_RESPONSE`. These controls preserve iRule-visible state only: the
emulator does not implement the underlying demangler, iSession compression or
deduplication engine, plugin pipeline, or an internal virtual-server transport.
The command contracts are documented by F5 for
[`ISESSION::deduplication`](https://clouddocs.f5.com/api/irules/ISESSION__deduplication.html),
[`IVS_ENTRY::result`](https://clouddocs.f5.com/api/irules/IVS_ENTRY__result.html),
[`PLUGIN::enable`](https://clouddocs.f5.com/api/irules/PLUGIN__enable.html), and
[`PLUGIN::disable`](https://clouddocs.f5.com/api/irules/PLUGIN__disable.html).

`REST::send -method METHOD URI ?BODY?` is modeled as a bounded local-request
ledger. The emulator records the normalized method, URI, body, and request
history under `semantic.rest`; it does not contact a BIG-IP REST endpoint or
make outbound network calls. This matches the iRule contract that the request
is sent to the local REST framework and its response is not available to the
rule. See the F5 [`REST::send` reference](https://clouddocs.f5.com/api/irules/REST__send.html).
The TDS surface is available through direct events and structured packet traces
for `TDS_REQUEST` and `TDS_RESPONSE`. Supply a `tds` object containing the
message fields (`type`, `length`, `procid`, `procname`, `sqltext`, `xacttype`,
`xactid`, `is_read`, and `request_type`) and session fields (`username`,
`dbname`, `loginoption`, and `version`). `TDS::msg` exposes the current event's
message; its `request_type` setter records the rule's read/write override.
`TDS::session` reads connection-scoped session metadata, which persists across
the two event types, while message fields reset at each event boundary. The
resulting state is returned under `semantic.tds` for direct events and in the
structured trace event state for packets. Structured packets use the same
bounded event model and TCP lifecycle as other protocol adapters. Raw TDS packet
messages on port 1433 are also reassembled across TCP fragments and coalesced
messages; SQL Batch type 1 bodies are decoded as UTF-16LE and classified as
read/write requests. The emulator does not synthesize a database peer, parse
RPC parameters or result tokens, or negotiate a TDS session. See the F5
[`TDS::msg`](https://clouddocs.f5.com/api/irules/TDS__msg.html) and
[`TDS::session`](https://clouddocs.f5.com/api/irules/TDS__session.html)
references for the production command contract.
The IKE surface is available through the direct `IKE_AUTH` event API and the
packet adapter.
Supply an `ike` object with the certificate and subjectAltName values, then
use `IKE::cert` (optionally with index `0`), the SAN accessors, and
`IKE::auth_success` from the rule. The event result exposes the supplied
certificate/SAN state and whether the rule accepted authentication under
`state.ike`. This is a certificate-authentication decision model only: it
does not perform IKE negotiation, X.509 parsing, or ESP/IPsec processing.
Packet replay accepts `protocol: "ike"` with a structured `ike` object or
`payload_hex`. Raw `protocol: "wire"` IPv4/IPv6 UDP packets on ports 500 and
4500 are decoded as IKEv2; port 4500 requires the four-byte non-ESP marker.
The adapter validates the IKE header length and generic payload chain, fires
`IKE_AUTH` for exchange type 35, and leaves encrypted `SK` payload contents
opaque. For example:

```json
{
  "protocol": "ike",
  "direction": "client_to_server",
  "source": {"address": "198.51.100.10", "port": 500},
  "destination": {"address": "203.0.113.10", "port": 500},
  "ike": {"exchange_type": "IKE_AUTH", "message_id": 1, "payloads": ["IDi", "AUTH"]}
}
```
The pinned tcl-lsp registry does not currently list `IKE_AUTH`, so the
emulator reports it as a documented TMOS 17.5 event compatibility override in
the catalog metadata. See the F5 [`IKE` reference](https://clouddocs.f5.com/api/irules/IKE.html)
and [`IKE_AUTH` event reference](https://clouddocs.f5.com/api/irules/IKE_AUTH.html).
The QOE surface is available through direct `QOE_PARSE_DONE` and
`CLIENT_CLOSED` events. Supply a `qoe` object with video measurements such as
`width`, `height`, `duration`, `available`, `framerate`, `nominal_bitrate`,
`average_bitrate`, and `mos`; `QOE::video` exposes those values only in its
documented event contexts. `QOE::enable` and `QOE::disable` update a
connection-scoped control flag, returned under `semantic.qoe`. This is a
deterministic metric/control model: it does not parse media, calculate MOS,
or reproduce a live QOE engine. See the F5
[`QOE::video`](https://clouddocs.f5.com/api/irules/QOE__video.html) reference.

Packet replay can represent the same parser completion with a structured
server-to-client packet:

```json
{
  "protocol": "qoe",
  "direction": "server_to_client",
  "source": {"address": "192.0.2.20", "port": 443},
  "destination": {"address": "192.0.2.10", "port": 40000},
  "qoe": {
    "width": 1920,
    "height": 1080,
    "duration": "00:01:30",
    "framerate": "59.94",
    "nominal_bitrate": 8000000,
    "average_bitrate": 6500000,
    "mos": "4.7"
  }
}
```

The adapter emits `QOE_PARSE_DONE` after the serverside connection is
established, defaults an omitted `available` value to `1`, and honors
connection-scoped `QOE::disable` on subsequent packets. It supplies the
measurements; it does not parse MP4/FLV bytes or calculate MOS.
`OFFBOX::request SERVICE PAYLOAD ?cache KEY? ?blocking ?TIMEOUT??` is modeled
as a bounded local request ledger. It validates the documented option forms,
records service, payload, cache, blocking, and timeout fields under
`semantic.offbox`, and deliberately performs no outbound network I/O. The
ledger records `result: "not-executed"` so an iRule test cannot mistake the
portable emulator for a live off-box service. See the F5
[`OFFBOX::request`](https://clouddocs.f5.com/api/irules/OFFBOX__request.html)
reference.
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

The deprecated `RESOLV::lookup` command uses the same records for inline
address, reverse, TXT, MX, NAPTR, and SRV queries. It accepts the documented
resolver selector (`@/Common/r1`), address-family selector (`inet` or
`inet6`), and record-type flags (`-a`, `-aaaa`, `-ptr`, `-txt`, `-mx`,
`-naptr`, and `-srv`), returning a Tcl list of matching `rdata` values.
`NAME::lookup` provides the older asynchronous-style interface: it stores the
bounded result and queues `NAME_RESOLVED` after the current event returns when
that event is registered. `NAME::response`, `NAME::response address [INDEX]`, and
`NAME::response name` expose the corresponding result to that handler. This
keeps legacy rules testable without contacting DNS or pretending to provide a
wall-clock asynchronous resolver.

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

`DNS::tsig exists` and `DNS::tsig remove` provide a deterministic TSIG
presence/removal state for structured DNS messages. The adapter records the
message-level mutation but does not calculate or validate TSIG MACs.

TLS packet state also drives the common SSL inspection path. In
`CLIENTSSL_*` and `SERVERSSL_*` events, the semantic overlay supports
`SSL::sni`, `SSL::cipher`, `SSL::sessionid`, `SSL::cert`,
`SSL::verify_result`, and side-specific `SSL::disable`/`SSL::enable`. The
remaining high-value 17.5 SSL controls are modeled as deterministic state:
client-cert-on-demand (`SSL::c3d`), certificate constraints, forward-proxy
policy/certificate controls, session-ID headers, ALPN/next-protocol, session
secrets, TLS 1.3 secret inspection, and bounded plaintext collection through
`SSL::collect`, `SSL::payload`, and `SSL::release`. Certificate handles can be
inspected with `X509::subject` and `X509::issuer`.

For structured TLS packet traces, `SSL::collect` holds a `CLIENTSSL_DATA` or
`SERVERSSL_DATA` event until the requested plaintext length is available.
`SSL::payload` can inspect or replace the collected bytes, and `SSL::release`
returns a bounded prefix to the modeled stream. The adapter intentionally
accepts structured plaintext rather than decrypting TLS records. Certificate,
secret, and cipher values are deterministic packet input; the emulator does
not perform a TLS handshake, certificate-chain validation, key exchange, or
cryptographic renegotiation. For raw TCP/PCAP TLS Certificate handshake
records, the adapter extracts the first certificate's DER bytes and feeds them
into the same X.509 inspection path; encrypted application records remain
opaque.

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

Additional SSL state can be supplied on the TLS packet when a rule needs to
exercise those inspection paths, for example `initial_session_id`,
`nextproto`, `session_secret`, `tls13_client_hs_secret`, `c3d_cert`,
`forward_proxy_cert`, and `forward_proxy_cert_status`. Values are test
fixtures, not material extracted from a live TLS connection.

Certificate inspection supports both deterministic fixtures and real
certificate bytes. A TLS packet can provide individual fields such as
`cert_subject`, `cert_issuer`, `cert_serial`, `cert_hash`, `cert_extensions`,
validity dates, signature algorithm, public-key metadata, and `cert_version`.
Alternatively, provide a valid PEM certificate in `cert_pem` or hexadecimal
DER in `cert_der`; the adapter parses it and derives those fields, including
the MD5 fingerprint, extension summary, public-key type/size/curve, version,
and canonical PEM. Byte-backed fields take precedence when parsing succeeds,
while individual metadata fields remain a fallback for synthetic or
intentionally malformed fixtures. `SSL::cert 0` returns a stable certificate
handle for the current side, which can be passed to the complete X.509
inspection surface, including `X509::cert_fields`, `X509::extensions`,
`X509::hash`, `X509::pem2der`, public-key queries,
`X509::verify_cert_error_string`, and `X509::whole`. The adapter validates
certificate encoding and handles but does not validate chains or perform
cryptographic signature verification.

The packet adapter also covers the target-valid TLS lifecycle events
`CLIENTSSL_PASSTHROUGH`, `CLIENTSSL_SERVERHELLO_SEND`, and
`SERVERSSL_CLIENTHELLO_SEND`. Use `type: "passthrough"` on a client-side TLS
packet for the first event, `type: "server_hello_send"` for the second, or
`type: "client_hello_send"` on a server-side TLS packet for the third. These
are event fixtures only: they do not negotiate TLS, synthesize handshake
records, or change the SSL profile.

HTTP/2 metadata can be attached to a structured HTTP transaction with an
`http2` object. This drives the reusable `tcl-lsp` pseudo-header and stream
handlers plus semantic `HTTP2::active`, `HTTP2::version`,
`HTTP2::requests`, `HTTP2::concurrency`, `HTTP2::enable`, `HTTP2::disable`,
and `HTTP2::disconnect` behavior. `HTTP2::push` records a bounded
PUSH_PROMISE intent with its URI, priority, request/response headers, inline
content or iFile reference, and `-noserver`/`-nohost` flags. Header names are
validated as lowercase HTTP/2 pseudo-headers, stream IDs are bounded to 31
bits, and priorities to 8 bits. The current slice models decoded transaction
state and push decisions; it does not parse HTTP/2 frames, implement HPACK,
multiplex live streams, contact an origin, or emit pushed frames.

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

For raw captures, use `protocol: "wire"`, `network: "ipv4"` or `"ipv6"`, and
the corresponding IP packet in `raw_hex`. The decoder reassembles complete
IPv4 and IPv6 fragment sets within bounded limits, rejects incomplete or
malformed fragment sets, skips bounded IPv6 extension headers, and performs
bounded sequence-aware TCP application reassembly across records and persistent
session calls, including out-of-order segments and duplicate retransmissions.
Classic PCAP and pcapng file/HTTP/MCP ingestion supports Ethernet or raw IPv4
and IPv6 frames, including bounded IPv4/IPv6 fragment reassembly. RTSP control
messages on the RTSP profile are decoded from raw TCP streams, including
split/coalesced RTSP/1.0 headers and bounded Content-Length bodies. Interleaved
RTP/RTCP media frames and full media-session negotiation remain outside this
slice.

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

NTLM packet scenarios may include an `eca` object with bounded identity/status
fields and `eca_result` set to `allowed` or `denied`. When `eca.enabled` is
true, the packet adapter emits the corresponding `ECA_REQUEST_ALLOWED` or
`ECA_REQUEST_DENIED` event. This injects an authentication outcome for
deterministic testing; it does not perform an NTLM exchange or contact a
domain controller.

HTTP data events are only produced by the high-level request flow after
`HTTP::collect` has armed the corresponding request or response body and the
requested byte threshold is available. `HTTP::release` is modeled in the data
events: it clears the active collection window and is reported as
`http_release: true` in the transaction result. Explicit event injection
remains available through the event API for lower-level tests. The
`HTTP_REQUEST_RELEASE` and `HTTP_RESPONSE_RELEASE` events follow their
respective data events, and body commands such as `HTTP::payload` and
`HTTP::collect` are rejected in those release contexts.

Raw HTTP/1.x replay applies request-aware response framing. Responses to
`HEAD` requests and successful `CONNECT` responses are treated as header-only
messages even when they advertise a `Content-Length`; their following bytes
remain available to the stream decoder rather than being consumed as an HTTP
body. This keeps persistent `HEAD` traffic and CONNECT tunnel handshakes from
being mistaken for incomplete or oversized response bodies.

Raw packet replay also preserves interim HTTP responses: a `100 Continue`
frame fires `HTTP_RESPONSE_CONTINUE` without completing the pending request,
so a later final response supplies the transaction result. Other non-final
1xx frames remain interim in the packet trace.

When raw HTTP/1.x packets carry an explicit decimal `Content-Length` or
`Transfer-Encoding: chunked`, the adapter can stage the request and response
lifecycles at wire boundaries. A header packet runs `HTTP_REQUEST`; subsequent
body bytes are held until the declared length, or the terminating chunk and
trailers, are available, then `HTTP_REQUEST_DATA` and
`HTTP_REQUEST_RELEASE` run according to the rule's collection calls. The same
behavior applies to `HTTP_RESPONSE`, `HTTP_RESPONSE_DATA`, and
`HTTP_RESPONSE_RELEASE`. Chunk extensions are accepted and trailer fields are
validated but are not exposed as application payload. Staged state survives
persistent session trace calls, so a TCP segment split is not treated as a new
transaction. If a staged message shares a TCP segment with the next HTTP
message, the adapter defers that tail until the current transaction completes,
then replays one message at a time; this preserves request/response ordering
for bounded HTTP/1.x pipelining and also survives persistent trace calls. Other
response bodies without a usable framing boundary continue through the
complete-message decoder and are not staged by this path.

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

For a single local smoke report, run the checked-in behavior packs, golden
vectors, catalog conformance checks, and representative HTTP, DNS, MQTT, SIP,
PCP, and RADIUS probes:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/evaluate-local.sh
```

The script requires the repository's uv-managed `.venv` with Python 3.13 or
newer. Its `evidence` value is `local-emulator-contracts`: passing means the
current local contracts agree, not that behavior has been independently
observed on TMOS 17.5 or in a vLab.

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
the replay count and exhaustion status. `HTTP::retry -reset` allocates a fresh
deterministic server-side connection identity for the replay while retaining
the client-side connection and iRule variables; it does not open a real
upstream socket. The
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
