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
The legacy global helpers `http_client_ip`, `http_content_len_max`,
`http_cookie`, `http_header`, `http_host`, `http_method`, `http_uri`,
`http_version`, `ip_protocol`, `ip_tos`, `ip_ttl`, `htonl`, `htons`, `ntohl`,
and `ntohs` are also semantic. They read the existing HTTP/connection state,
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
option mutations as deterministic state. It does not parse raw DHCP wire
formats, allocate leases, or emit real ICMP rejection packets.
Structured FTP packet traces expose the TCP control-channel path through
`CLIENT_ACCEPTED`, `CLIENT_DATA`, `SERVER_CONNECTED`, and `SERVER_DATA`. The
six TMOS 17.5 `FTP::*` commands model active-mode enablement, FTP handler
enable/disable, FTPS mode, TLS session-reuse enforcement, and passive-port
range selection. Packet inputs may provide a control message type, command,
response code, TLS flags, and text or hexadecimal payload; the adapter keeps
the controls connection-scoped and records disabled processing in the trace.
It does not parse FTP commands, open a data-channel socket, negotiate TLS, or
allocate real passive ports.
Structured IMAP, POP3, and LDAP packet traces use the ordinary TCP lifecycle
(`CLIENT_ACCEPTED`, `CLIENT_DATA`, `SERVER_CONNECTED`, and `SERVER_DATA`) and
expose their TMOS 17.5 STARTTLS controls. `IMAP::activation_mode`,
`POP3::activation_mode`, and `LDAP::activation_mode` accept `none`, `allow`, or
`require`; each namespace also models its `enable` and `disable` command.
Protocol-control state persists for the emulated connection, while packet
inputs can seed the message type, command text, TLS-active flag, and payload.
The adapter does not parse IMAP, POP3, LDAP, or SMTPS wire messages, negotiate
TLS, or enforce STARTTLS policy against a live peer.
Structured ICAP packet traces dispatch `ICAP_REQUEST` and `ICAP_RESPONSE` when
the `ICAP` profile is attached. The four TMOS 17.5 `ICAP::*` commands expose
request method and URI, response status, and case-insensitive ICAP header
lookup, enumeration, insertion, replacement, removal, and replacement of
the complete header block. Header and URI mutations are retained in the event
trace. This is a deterministic adaptation-message model; it does not run an
ICAP server, parse encapsulated HTTP bodies, or require an LTM/PEM license.
Structured `ntlm` packet traces use the TCP lifecycle and model the
connection-scoped `NTLM::enable` and `NTLM::disable` controls. They expose
bounded payload bytes and enablement state, but do not parse NTLM messages or
perform authentication negotiation. Structured `protocol_inspection` traces
require the `PROTOCOL_INSPECTION` profile and dispatch
`PROTOCOL_INSPECTION_MATCH`; supplied match IDs, match status, payload bytes,
`PROTOCOL_INSPECTION::id`, and `PROTOCOL_INSPECTION::disable` are modeled with
bounded deterministic state. The adapter does not implement the BIG-IP
signature/inspection engine.
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
`FLOW_INIT` before an explicitly marked server-side classification packet.
This is deterministic classification control state; it does not run a PEM
classifier or infer results from payloads.
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
adapter does not perform DNS, proxy CONNECT negotiation, URI rewriting on
forwarded bytes, or live downstream proxy chaining.

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
virtual server, or content transformation.

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
    "perflow": {"perflow.custom": "example"}
  },
  "irule": "when CLIENT_ACCEPTED { set ::sid [ACCESS::session create -flow] }\nwhen HTTP_REQUEST { ACCESS::policy evaluate -sid $::sid -profile /Common/access; log local0. [ACCESS::policy result -sid $::sid] }",
  "request": {"uri": "/protected"}
}
```

`ACCESS::disable`, `ACCESS::enable`, `ACCESS::respond`, ACL evaluation,
per-flow mutation, SAML getters/setters, OAuth signing placeholders, and
ephemeral-auth create/verify are represented as deterministic test behavior.
Session snapshots redact values whose keys look like passwords, secrets, or
tokens. This does not run APM policy evaluation, ACL enforcement, SAML/OAuth
cryptography, external authentication, or production session expiry.

### ACCESS2 policy-expression procedure

With the `ACCESS` profile attached, the direct event API supports
`ACCESS2_POLICY_EXPRESSION_EVAL`. Supply the currently selected policy
procedure as `state.access2.proc`; `ACCESS2::access2_proc` returns that value
without invoking it. The value is event-scoped and is cleared before the next
policy-expression event, so this adapter does not execute hidden APM policy
expressions or reproduce the policy engine:

```json
{
  "profiles": ["ACCESS"],
  "irule": "when ACCESS2_POLICY_EXPRESSION_EVAL { log local0. [ACCESS2::access2_proc] }"
}
```

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
rejection for a request and validates the result code from 0 through 255. This
slice does not parse PCP wire payloads, perform proxying, allocate mappings, or
emit a packet-level PCP adapter; those remain separate emulator work.

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

Tag retrieval is restricted to `FIX_MESSAGE`; map mutation is available in any
event. This models rule-visible FIX metadata and mapping state, not a complete
FIX wire parser or data-group evaluator. See the F5
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

### SDP state

`SDP::field`, `SDP::media`, and `SDP::session_id` are available during SIP
message events when the `SIP` profile is attached. Supply a bounded structured
SDP overlay through the event API. `fields` is a Tcl list of repeated
field/value pairs; `media` is a Tcl list whose entries are dictionaries with
`type`, `port`, `transport`, `conn`, and `attrs` keys:

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
bounded to the 0–65535 port range. `SDP::session_id` returns the supplied
session identifier. This overlay is intentionally separate from the SIP
payload: it does not yet parse raw SDP bodies or rewrite the serialized SIP
message.

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
disconnect packets can drive `MQTT_CLIENT_INGRESS`/`MQTT_SERVER_INGRESS`, while
`MQTT::collect` on a `PUBLISH` drives the corresponding `*_DATA` event with the
collected payload. Raw MQTT-over-TCP payloads are decoded after bounded TCP
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
The TDS surface is available through the direct event API for
`TDS_REQUEST` and `TDS_RESPONSE`. Supply a `tds` object containing the message
fields (`type`, `length`, `procid`, `procname`, `sqltext`, `xacttype`, `xactid`,
`is_read`, and `request_type`) and session fields (`username`, `dbname`,
`loginoption`, and `version`). `TDS::msg` exposes the current event's message;
its `request_type` setter records the rule's read/write override. `TDS::session`
reads connection-scoped session metadata, which persists across the two event
types, while message fields reset at each event boundary. The resulting state
is returned under `semantic.tds`. This is intentionally a direct-event model:
the emulator does not yet decode or synthesize TDS wire packets. See the F5
[`TDS::msg`](https://clouddocs.f5.com/api/irules/TDS__msg.html) and
[`TDS::session`](https://clouddocs.f5.com/api/irules/TDS__session.html)
references for the production command contract.
The IKE surface is also available through the direct `IKE_AUTH` event API.
Supply an `ike` object with the certificate and subjectAltName values, then
use `IKE::cert` (optionally with index `0`), the SAN accessors, and
`IKE::auth_success` from the rule. The event result exposes the supplied
certificate/SAN state and whether the rule accepted authentication under
`state.ike`. This is a certificate-authentication decision model only: it
does not perform IKE negotiation, X.509 parsing, or IPsec packet processing.
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
not perform a TLS handshake, certificate validation, key exchange, or
cryptographic renegotiation.

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

Certificate inspection uses the same deterministic fixture model. A TLS
packet can provide `cert_subject`, `cert_issuer`, `cert_serial`,
`cert_hash`, `cert_extensions`, validity dates, signature algorithm, public
key metadata, `cert_version`, and `cert_pem`/`cert_der`. `SSL::cert 0` then
returns a stable certificate handle for the current side, which can be passed
to the complete X.509 inspection surface, including `X509::cert_fields`,
`X509::extensions`, `X509::hash`, `X509::pem2der`, public-key queries,
`X509::verify_cert_error_string`, and `X509::whole`. The adapter validates
handles and PEM structure but does not validate certificate chains or perform
cryptographic verification.

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
