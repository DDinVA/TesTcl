# F5 compatibility scope

TesTcl is a local iRule test harness. It is not a BIG-IP/TMM emulator, so a
passing test means that the iRule behaved correctly against the mocks and
expectations configured by the test. It does not prove that the rule will
deploy or behave identically on a particular BIG-IP release.

The event validator is kept separate from mock coverage. `event` accepts the
current F5 event catalog, including events introduced after the original
TesTcl release, while commands that do not yet have a built-in mock still need
an explicit `on` expectation. This avoids rejecting a syntactically valid
modern event while avoiding the stronger and unsafe claim that every F5
subsystem is emulated.

The catalog is based on F5's [Master List of iRule Events](https://clouddocs.f5.com/api/irules/Events.html), supplemented with
`ASM_RESPONSE_LOGIN` documented as introduced in BIG-IP LTM 17.0.0. Review the
F5 version-specific change pages when adding commands or changing command
semantics:

- [BIG-IP Commands and Events by Version](https://clouddocs.f5.com/api/irules/BIGIP_Commands_by_Version.html)
- [BIG-IP LTM v17.0.0 changes](https://clouddocs.f5.com/api/irules/BIGIP_LTM_v17_0_0.html)
- [HTTP::version reference](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_rule_command_HTTP_version.html)
- [Disabled Tcl Commands](https://clouddocs.f5.com/api/irules/DisabledTclCommands.html)

The next compatibility layer should be generated or reviewed from those
references rather than maintained as an unqualified list of mocked commands.

The legacy global HTTP and IP compatibility commands are modeled as
read-oriented views over the same request and connection state as their modern
counterparts. `http_client_ip` selects the first address from
`X-Forwarded-For` (or a caller-specified header) and falls back to the modeled
client address; `http_content_len_max` validates and caps Content-Length;
`http_cookie`, `http_header`, `http_host`, `http_method`, `http_uri`, and
`http_version` read request metadata. The legacy `ip_addr` comparison uses the
same bounded IPv4/IPv6 comparison engine as `IP::addr`. `ip_protocol`,
`ip_tos`, and `ip_ttl` read connection metadata, while `htonl`/`ntohl` and `htons`/`ntohs` perform
bounded unsigned byte-order conversion. These retain the old command surface
without introducing a second source of HTTP/IP state.

The top-level sideband commands `connect`, `send`, `recv`, and `close` are
implemented as deterministic fixture-backed controls. A scenario may provide
successful response bytes or an explicit connection failure such as
`unreachable`, `refused`, or `timeout`; no external socket is opened. Handles
are scoped to the emulated connection, and semantic output reports lifecycle
state plus sent, received, and buffered byte counts. The model validates the
documented options and status-variable forms, including `recv -peek` and
`recv -eol`, but does not claim to reproduce DNS, TLS, socket scheduling,
upstream protocol behavior, or real sideband timing.
The TMOS 17.5 `ifile` command is also fixture-backed. Scenario `ifiles` entries
support text or base64 content and the documented `get`, `listall`,
`attributes`, `size`, `last_updated_by`, `last_update_time`, `revision`, and
`checksum` operations. Fixtures are bounded at 128 entries, 32 MiB each, and
64 MiB in total; the adapter records recent accesses and never reads the host
filesystem.
The TMOS 17.5 [`session`](https://clouddocs.f5.com/api/irules/session.html)
command uses a separate global key/value table within the emulator process.
Its add/lookup/delete operations cover all documented persistence modes,
normalize legacy association qualifiers, apply the 180-second default timeout,
and refresh the timeout on lookup. Records survive connection resets and are
bounded to 1,024 entries, 1 MiB per value, and 16 MiB of total value data.
Persistent sessions created by the same `SessionManager` from the same
canonical scenario share these records, while different scenarios and
separately managed listeners remain isolated. Records are still ephemeral and
are not a shared BIG-IP persistence database or a cross-process store.
The TMOS 17.5 [`priority`](https://clouddocs.f5.com/api/irules/priority.html)
directive is applied to subsequent `when` blocks, while per-event priorities
override the current outer value. Handlers execute in ascending priority and
preserve source order for ties. The [`timing`](https://clouddocs.f5.com/api/irules/timing.html)
directive is retained as normalized `on`/`off` metadata; because this emulator
does not measure TMM execution time, it has no synthetic performance meaning.
The TMOS 17.5 [`sharedvar`](https://clouddocs.f5.com/api/irules/sharedvar.html)
command binds valid Tcl identifiers to connection-scoped shared storage, so
handlers can exchange values across events and connection sides represented
by the emulator. The binding resets with the emulated client connection; the
adapter does not instantiate a second VIP, cross-TMM shared memory, or live
virtual-to-virtual forwarding path.
The traffic-intent controls [`clone`](https://clouddocs.f5.com/api/irules/clone.html),
[`listen`](https://clouddocs.f5.com/api/irules/listen.html),
[`relate_client`](https://clouddocs.f5.com/api/irules/relate_client.html),
[`relate_server`](https://clouddocs.f5.com/api/irules/relate_server.html), and
[`use`](https://clouddocs.f5.com/api/irules/use.html) validate their documented
argument shapes and emit deterministic connection-scoped intent records in
`semantic.traffic.intents`. The records preserve source order, are bounded to
256 per connection, and are cleared at connection reset. This is an explicit
control-flow and observability model: no listener, clone socket, related flow,
second virtual server, or live forwarding path is created.
The legacy diagnostic controls are modeled as bounded test observability:
`check` retains the documented validation level; `tcpdump` records arguments
without invoking a host capture; `DIAG::test` records no-argument probes; and
`LINE::get`/`LINE::set` read or update the current stream line. Accesses appear
under `semantic.diagnostics`. The legacy `accumulate` command preserves Tcl's
handler-stop behavior and reports `suspended: true` with
`suspension: "accumulate"`; it does not replay buffered network data or create
an asynchronous packet source.
Legacy lookup compatibility is fixture-backed: `cpu usage` accepts the
documented interval spellings and returns zero unless a scenario-level `cpu`
map supplies values; `whereis` resolves exact addresses and requested fields
from a scenario-level fixture map; and `pem_dtos tac lookup IMEI` resolves
exact inputs from a scenario-level `pem_dtos` map. Their bounded query
histories appear under `semantic.utilities` and reset with the emulated
connection. No external TMM telemetry, geolocation database, or TAC database
is contacted. `imid` accepts no arguments and returns an empty string, which
matches the current F5 reference note that the function does not work.
The executable checkpoint `global-legacy-controls-17.5.json` exercises these
compatibility paths alongside the digest, HTTP-reader, connection, IP-list,
iFile, pool, link, redirect, shared-variable, and RADIUS controls. Its passing
result is local emulator evidence only; it is not independent TMOS/vLab
evidence.
The related legacy connection controls are deterministic as well: `forward`
records strict-forwarding intent, `translate` tracks address/port/service
translation toggles, `rateclass` records the selected rate class, and
`link_qos` reads or sets the modeled QoS value. `redirect to HOST_URI` maps to
the existing HTTP 302 response path. These outputs describe iRule-visible
decisions only and are not a claim of live routing, QoS, or packet behavior.

The executable `stateful-global-controls-17.5.json` checkpoint extends this
coverage with deterministic sideband lifecycle state, traffic-intent ordering,
datagroup and URL categorization fixtures, top-level `proc`/`priority`/`timing`
handling, and connection-control outcomes. It validates emulator contracts only;
it does not open real sideband sockets or claim independent TMOS/vLab evidence.

The optional TMOS 17.5 emulator exposes the pinned `tcl-lsp` registry in
bounded chunks and reports static command-handler and packet-event coverage
through its conformance endpoint. Structured packet traces currently cover
The optional real-client data plane also accepts `protocol: "sip"` for bounded
SIP-over-UDP request parsing and `SIP::respond` response serialization.
TCP, TLS, HTTP, generic UDP, SCTP, DNS, SIP over TCP or UDP, Diameter over TCP, RADIUS over UDP, GTP over UDP or GTP-Prime over TCP, Message Routing Framework messages over TCP, and raw IPv4 or IPv6 transport records. HTTP requests and client-side structured HTTP packets accept bounded `persist_down` and `lb_queue` inputs for causally exercising `PERSIST_DOWN` and `LB_QUEUED`; the adapter places those events around `LB_SELECTED`, emits `LB_FAILED` with `queue_limit` when a positive queue depth limit is exceeded, and rejects the inputs on server-side response packets. HTTP packet traces also expose the collected request/response data events, request-send phase, request/response rewrite completion, HTML tag/comment matching, and server lifecycle events when the corresponding profile or rule condition is present. They also accept a bounded client-side `lb_failure` cause for exercising `LB_FAILED` fallback and `LB::reselect`; explicit failure cannot be combined with the other causal inputs. HTTP request lifecycles with the `ACCESS` profile expose the deterministic session-start, policy-agent, per-request-agent, policy-completion, ACL-allow, ACL-deny, and session-close events when their modeled transitions occur. `BOTDEFENSE_REQUEST`, `BOTDEFENSE_ACTION`, `ANTIFRAUD_LOGIN`, and `ANTIFRAUD_ALERT` are likewise exposed when their existing HTTP request fixtures trigger them. These are profile-gated lifecycle adapters over seeded policy state, not production ACCESS, Bot Defense, or Anti-Fraud engines. Raw IPv4 and IPv6
fragments are reassembled with bounded set-count and payload-size checks before
transport decoding; incomplete and overlapping sets are rejected. Classic PCAP
and bounded pcapng ingestion are supported, and TCP stream reassembly includes
bounded gap, overlap, and retransmission de-duplication handling. Diameter
validates and
re-encodes bounded RFC 6733-style headers and AVPs, then exposes the 17.5
Diameter ingress, egress, and retransmission events. Its routing, retry,
retransmission, persistence, and capability-exchange commands are modeled as
deterministic test state rather than a complete Diameter peer or TMM
route/persistence implementation.
The conformance response also includes a coverage matrix that keeps complete
catalog ingestion distinct from partial command behavior and event lifecycle
coverage; it is an inventory report, not a fidelity score.
Structured traces also accept a synthetic `event` record containing a
catalogued event name and the same validated state layers accepted by the
session-event API. This provides deterministic coverage for event sequences
without a wire decoder, but intentionally has no implicit connection, socket,
or packet-metric side effects.
The TMOS 17.5 `PSM::FTP::*`, `PSM::HTTP::*`, and `PSM::SMTP::*` enable/disable
commands are modeled as connection-scoped protocol controls and appear in
semantic state and decision output; they do not run a real Protocol Security
Module inspection engine.
The TMOS 17.5 `STREAM::*` commands are available on a direct
`STREAM_MATCHED` event with a caller-supplied match. Encoding, expression,
maximum match size, connection enable/disable, and one-shot replacement intent
are deterministic state; the adapter does not scan/reassemble raw stream
matches, enforce the production buffer/connection lifecycle, or rewrite wire
payloads.
For structured TCP and TCP-based protocol traces, the first server-side packet
emits `SERVER_INIT` before `SERVER_CONNECTED`; both are emitted once per
emulated server connection. UDP and SCTP traces retain `SERVER_CONNECTED`
without claiming the TCP-only `SERVER_INIT` event. The adapter does not
synthesize server SYN retransmits, connection timers, or an upstream socket.
The WebSocket payload-processing controls `WS::payload_ivs` and
`WS::payload_processing` are modeled as connection-scoped state on the existing
structured WebSocket upgrade/frame adapter. They record the requested IVS and
enable/disable decision, but do not execute an IVS or a payload protocol
inspection engine.
Generic UDP traces expose datagram payload bytes, client/server/local/remote
ports, and the `CLIENT_DATA`/`SERVER_DATA` path. The UDP semantic layer models
payload replacement, drop, hold/release, response emission, and bounded buffer,
rate, send-buffer, debug-queue, MSS, and unused-port controls. It does not run
TMM queue scheduling, NAT, connection tracking, or a live upstream UDP socket.
The six TMOS 17.5 `DATAGRAM::*` readers are also modeled. They expose validated
IPv4/IPv6 header values, TCP/UDP payload and header metadata, DNS header fields,
and Layer-2 destination values from a direct event state layer or a packet's
optional `datagram` object. The adapter dispatches `FLOW_INIT` for packet
connections carrying a `FLOW` profile, and keeps command event/protocol
restrictions explicit. This is deterministic header inspection; it does not
replace a kernel network stack or mutate captured packets.
The PCP packet adapter accepts structured PCP request/response records and raw
IPv4/UDP datagrams on port 5351. Raw MAP, PEER, and ANNOUNCE common and
opcode-specific fields are decoded into the same `PCP_REQUEST` and
`PCP_RESPONSE` event path, including the `THIRD_PARTY` and `PREFER_FAILURE`
request options. The adapter validates datagram and option bounds but does not
allocate mappings, perform NAT, or emulate a live PCP server.
The TCP semantic layer additionally models documented connection tuning
controls including Appropriate Byte Counting, analytics state and key,
automatic window tuning, delayed ACK, D-SACK, early retransmit, ECN, enhanced
loss recovery, limited transmit, loss filters, window scales, retransmission
threshold, metrics timeout, Nagle mode/state, keepalive, idle timeout, send
and receive buffers, MSS changes, pacing, PUSH mode, congestion label, and
proxy-buffer thresholds. `TCP::unused_port` allocates deterministic ephemeral
ports for a validated tuple. These are deterministic state and inspection
values; the adapter does not implement a kernel TCP stack, congestion-control
algorithm, retransmission timers, or wire-level pacing.
The SCTP packet adapter models the 17.5 `SCTP::*` surface for endpoint ports,
MSS, PPI, timeout readers, bounded collection, byte-oriented payload mutation,
release, and direct response emission. It dispatches the SCTP client/server
accept, connect, and data event path for structured packets. It does not parse
SCTP chunks or emulate associations, multihoming, retransmission, SACK, or
congestion-control behavior.
The DHCP adapter models the 17.5 `DHCP::version`, `DHCPv4::*`, and `DHCPv6::*`
surfaces for structured client/server data events, DHCP header readers
(including `DHCPv4::htype`), option lookup/mutation, and drop/reject decisions.
DHCPv6 option deletion is modeled explicitly. Raw IPv4/UDP DHCPv4 packets on
ports 67/68 and raw IPv6/UDP DHCPv6 packets on ports 546/547 are decoded into
their respective state paths, including BOOTP/DHCPv6 headers, message types,
bounded common options, and DHCPv4 option-overload areas. It does not run a
lease allocator or send real ICMP rejection traffic.
The FTP adapter models the six 17.5 `FTP::*` controls for structured TCP
control-channel traces, including active-mode permission, FTP handler state,
FTPS activation mode, TLS session-reuse enforcement, and passive-port range
selection. It dispatches the client-accepted, client-data, server-connected,
and server-data path and preserves those controls across messages on one
connection. Raw port-21 control streams are reassembled into bounded command
and single- or multi-line response messages. It does not negotiate TLS, create
a data channel, or allocate live passive ports.
The IMAP, POP3, LDAP, and SMTPS adapters model their TMOS 17.5 STARTTLS control
commands over TCP lifecycle traces. Activation modes (`none`, `allow`, and
`require`) and protocol-handler enable/disable state persist per connection,
with bounded payload snapshots. IMAP, POP3, and SMTPS raw control lines are
reassembled from TCP fragments. LDAP additionally decodes definite-length BER
`LDAPMessage` frames for common bind, search, unbind, extended, and result
operations, exposing the operation, message ID, DN, result code, diagnostic
text, and wire bytes. These adapters do not negotiate TLS or enforce STARTTLS
against a real peer; LDAP indefinite-length and high-tag-number BER are
rejected.
The ICAP adapter models the four 17.5 `ICAP::*` commands and dispatches
`ICAP_REQUEST`/`ICAP_RESPONSE` for structured messages with an `ICAP` profile.
It supports method, URI, status, and case-insensitive header reads and
mutations, including complete header replacement. It does not implement an
ICAP server or encapsulated HTTP semantics, but raw ICAP/1.0 control messages
on port 1344 are reassembled across TCP fragments and coalesced messages.
`null-body` framing and bounded ICAP chunked encapsulated bodies are decoded;
the complete raw message remains available through `ICAP::payload`. License
and control-plane behavior are not emulated.
The NTLM adapter models the connection-scoped `NTLM::enable` and
`NTLM::disable` controls on bounded structured TCP payloads; it does not parse
NTLM messages or negotiate authentication. The protocol-inspection adapter
requires the `PROTOCOL_INSPECTION` profile, dispatches
`PROTOCOL_INSPECTION_MATCH`, and models supplied match IDs, match status,
payload bytes, `PROTOCOL_INSPECTION::id`, and `PROTOCOL_INSPECTION::disable`.
It does not provide a Protocol Inspection signature engine or infer matches
from raw traffic.
The STREAM profile also evaluates bounded `@match@replacement@` expressions
against TCP packet payloads and dispatches `STREAM_MATCHED`; replacements that
span packet boundaries are reported without rewriting the already-emitted
prior packet. This does not implement the full TMM stream filter.
The classification adapter models the eight TMOS 17.5 `CLASSIFICATION::*`
commands on structured client-side TCP records and dispatches
`CLASSIFICATION_DETECTED` when the `CLASSIFICATION` profile is attached.
Supplied application, category, protocol, URL-category, username, and
result-token values are readable in the event; enable/disable state persists
for the connection. It does not run a DPI classifier, classification
database, or PEM policy engine.
The six TMOS 17.5 `CLASSIFY::*` controls are also modeled: application,
category, and URL-category `set`/`add` operations overlay supplied
classification results; `CLASSIFY::username` assigns flow metadata;
`CLASSIFY::disable` suppresses detection; and `CLASSIFY::defer` records a
`FLOW_INIT` deferral that permits an explicitly marked server-side result.
HTTP-only controls and `FLOW_INIT` restrictions are validated, and all
classification values remain deterministic scenario state rather than a live
PEM classification database.
The legacy `urlcatquery` and `urlcatblindquery` commands use exact-match
scenario fixtures and return a bounded Tcl-list result, defaulting to
`Unknown`. They reject literal IPv6 inputs and never contact an external URL
categorization database; recent accesses are exposed in semantic output.
The CATEGORY adapter models the six TMOS 17.5 `CATEGORY::*` commands and
dispatches `CATEGORY_MATCHED` for supplied client-side TCP matches. Lookup,
safe-search, cached-result, match-type, filetype, and per-request analytics
state are bounded and deterministic; lookup options and documented command
event restrictions are checked. It does not contact a URL categorization/SWG
service or reproduce the licensed category engine.
The TMOS 17.5 `ROUTE::*` surface uses scenario-seeded route-domain and
congestion-metric entries. Metric getters return deterministic values and
`ROUTE::clear` removes a matching entry for the session; connection lifecycle
state is reset independently. No live route discovery, metric aging, or
multi-TMM cache synchronization is performed.
The TMOS 17.5 `HTTP::proxy` surface uses scenario-seeded explicit-proxy
resolution and chaining state. It models proxy enable/disable, URI rewriting,
`exists`, destination getters, chain enable/disable, chain host/port updates,
and one-request chain retry intent. Each HTTP transaction starts from the
scenario defaults, while changes made within that transaction remain visible
to later HTTP proxy events. Destination getters return empty values until the
seeded resolution is marked present. The adapter does not perform DNS, proxy
CONNECT negotiation, URI rewriting on forwarded bytes, or live downstream
proxy chaining.
The TMOS 17.5 REWRITE surface models `REWRITE::enable`, `REWRITE::disable`,
`REWRITE::payload`, and `REWRITE::post_process`. With the `REWRITE` profile,
the high-level HTTP lifecycle exposes `REWRITE_REQUEST` and
`REWRITE_RESPONSE` before their corresponding HTTP events, followed by
`REWRITE_REQUEST_DONE` and conditionally `REWRITE_RESPONSE_DONE`; payload
reads and replacements use byte offsets and update an existing
`Content-Length` header. It does not implement the full REWRITE
profile/plugin, APM policy processing, or URL/file rewrite tables.

The MQTT 3.1.1 packet adapter dispatches target-valid ingress and egress
events: client-to-server messages flow through `MQTT_CLIENT_INGRESS` and
`MQTT_SERVER_EGRESS`, while server-to-client messages flow through
`MQTT_SERVER_INGRESS` and `MQTT_CLIENT_EGRESS`. Ingress/data drops suppress
the modeled egress event; delivery events expose deterministic forwarded
message state but do not open message-routing sockets.
The HTTP control path also captures `HTTP::disable` and fires `HTTP_DISABLED`
after a request handler, including a bounded `discard` flag and deterministic
`HTTP::passthrough_reason` values. The control state is reset between
keep-alive requests and does not model malformed-wire recovery or the full HTTP
filter.
High-level requests and structured HTTP packets may also carry a bounded
`http_class` outcome (`selected` or `failed`, with class name and ASM/WA flags);
the matching `HTTP_CLASS_SELECTED` or `HTTP_CLASS_FAILED` event fires before
`HTTP_REQUEST`. This supplies event-visible selector state, not a class
database or the deprecated classification engine.
Rule-caused `reject` calls in `HTTP_REQUEST` fire `HTTP_REJECT`, expose the
deterministic `HTTP::reject_reason` values `iRule` and `1`, mark the request as
rejected, and close the emulated client connection. The post-abort model is
intentionally bounded to the reason accessor; malformed-wire and other
filter-generated reject causes are not simulated.
With the `HTTP_PROXY_CONNECT` profile, an enabled proxy request fires
`HTTP_PROXY_REQUEST` before `HTTP_REQUEST`, and mutations to `HTTP::uri` or
`HTTP::proxy` carry into the normal request handler. An optional
`http_proxy.chain.response` fixture supplies one deterministic status, headers,
and body for the downstream chain response. For ordered negotiation, the
`http_proxy.chain.responses` array supplies the response sequence. Registered
`HTTP_PROXY_CONNECT` and `HTTP_PROXY_RESPONSE` handlers fire between
`HTTP_PROXY_REQUEST` and `HTTP_REQUEST`; an explicit sequence advances only
when the response handler calls `HTTP::proxy chain retry`, with one retry
allowed per request. A successful response continues to `HTTP_REQUEST`, while
an unretried or exhausted non-200 response closes the emulated connection and
sets `chain_failed` in the semantic HTTP proxy state. The adapter never opens a
downstream socket or claims to replay live proxy negotiation. Disabling either
layer suppresses the downstream events.
The TMOS 17.5 HTML surface models `HTML::comment`, `HTML::disable`,
`HTML::enable`, `HTML::encode`, and `HTML::tag`. With the HTML profile and
`HTML::enable` in `HTTP_RESPONSE`, the adapter scans the uncompressed response
body and exposes ordered tag/comment match events with deterministic token
mutations. It does not implement a DOM, script execution, compression
decoding, or the full TMM HTML filter.
The TMOS 17.5 compression surface models `COMPRESS::buffer_size`,
`COMPRESS::disable`, `COMPRESS::enable`, `COMPRESS::gzip`, `COMPRESS::method`,
`COMPRESS::nodelay`, `DECOMPRESS::disable`, and `DECOMPRESS::enable`, including
bounded gzip/deflate transforms and content-encoding/length updates. It does
not implement content negotiation, streaming flush behavior, or compression
resource timing.
The TMOS 17.5 `HTTPLOG::enable` and `HTTPLOG::disable` commands control a
deterministic connection-scoped audit stream. Enabled transactions expose
structured request and response records containing phase, method, URI, host,
status, byte length, and headers; records are reset between transactions while
the toggle persists across keep-alive requests. The adapter does not connect to
a BIG-IP request-logging profile, syslog destination, or external logging sink.
The TMOS 17.5 `ISTATS::get`, `ISTATS::incr`, `ISTATS::remove`, and `ISTATS::set`
commands use a session-global key/value store, allowing counters, gauges, and
strings to persist across connections and requests. `ISTATS::incr` requires an
integer, permits negative values for gauge keys, and rejects non-numeric or
string values. Missing string keys read as an empty value and other missing
keys read as zero. The adapter does not aggregate values across emulator
processes or expose a live control-plane iStats database.

The TMOS 17.5 `CRYPTO::hash`, `CRYPTO::sign`, and `CRYPTO::verify` commands
have one-shot and bounded context-streaming semantic support. New contexts
require an explicit `-alg`; subsequent chunks may reuse the context name, and
`-final` returns the binary result and releases the context. Hashes cover `md5`,
`ripemd160`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`; signing and
verification cover the corresponding HMAC algorithms. Binary results are
preserved, including `-keyhex` inputs. Context data is capped at 16 MiB and
cleared at connection boundaries.

The remaining TMOS 17.5 CRYPTO commands, `CRYPTO::encrypt`,
`CRYPTO::decrypt`, and `CRYPTO::keygen`, are also semantic mocks. Symmetric
coverage includes AES CBC/CFB/ECB/OFB, Blowfish, DES/2-key DES/3-key DES,
IDEA, and variable-length RC4; RSA public/private operations support PKCS#1
v1.5 and OAEP padding. Block CBC/ECB operations use PKCS#7-style padding,
while stream-like modes do not add padding. Missing IVs use a deterministic
zero IV so test vectors are reproducible. Contexts are connection-scoped and
are evaluated on `-final`. `CRYPTO::keygen` supports bounded random,
PBKDF2-MD5, and RSA generation; RSA returns a public/private PEM list.

The catalog also names RC2 and AES CWC mode, but the portable Python backend
does not provide those primitives. The emulator fails explicitly for those
algorithms rather than substituting a non-equivalent cipher. PBKDF2 defaults
to 1,000 rounds when `-rounds` is omitted, an emulator compatibility choice
that should be checked against a live 17.5 device before relying on derived
key bytes. Standard algorithm interoperability and live-device golden vectors
remain separate validation work.

The TMOS 17.5 `AES::key`, `AES::encrypt`, and `AES::decrypt` commands are
implemented as a binary-safe semantic layer. `AES::key` returns the documented
`AES <bits> <hex>` key shape for 128-, 192-, and 256-bit keys; encrypt/decrypt
support formatted keys and deterministic passphrase handling with bounded
16-MiB inputs. The adapter uses AES-ECB with PKCS-style padding for portable
round trips. F5's public reference does not specify the passphrase KDF or a
ciphertext test vector, so formatted keys are the interoperability path and
live-device ciphertext compatibility remains a validation item. Generated
keys are random per emulator session and are never included in semantic
snapshots.

The TMOS 17.5 IPFIX surface is modeled as deterministic object state for
`IPFIX::template`, `IPFIX::msg`, and `IPFIX::destination`. Templates and
destinations persist for the emulator session; messages are connection-scoped
and may be filled across multiple events. Repeated template elements honor the
documented zero-based `-pos` occurrence index, and destination sends are
captured in a bounded semantic history. The adapter does not connect to a
configured log publisher, serialize IPFIX datagrams, or transmit telemetry.

The TMOS 17.5 ASN.1 surface is modeled by `ASN1::element`, `ASN1::encode`,
and `ASN1::decode`. Element handles retain parsed BER/DER TLV trees and
support `init`, `next`, `tag`, `size`, `byte_offset`, and `length`. Encode and
decode support octet strings, bit strings, booleans, enumerations, integers,
optional components, sequences, sets, and iterative length/tag/skip fields.
`ASN1::encode insert|replace` updates the modeled client TCP payload using
element-relative offsets. The parser is bounded at 16 MiB; encoded output is
definite-length, while BER decoding also accepts constructed indefinite
lengths. This is a portable rule-behavior model, not a claim of complete
ASN.1 schema validation or full TMM payload scheduling.

The TMOS 17.5 ILX surface is modeled by `ILX::init`, `ILX::call`, and
`ILX::notify`. Initialization rejects `RULE_INIT`, creates connection-scoped
opaque handles, and records the plugin/extension target. Calls honor the
documented optional timeout (default 3000 ms), and notifies return `0` while
recording the queued message. The offline boundary provides deterministic
`echo` and integer `sum` methods; unknown methods return an empty result.
Handles, calls, and notifications are exposed under `semantic.ilx` with
bounded 1024-entry histories. No Node.js extension worker or networked ILX
runtime is started by the emulator.

The SIPALG controls `SIPALG::hairpin`, `SIPALG::hairpin_default`, and
`SIPALG::nonregister_subscriber_listener` are modeled on structured SIP
messages. Hairpin mode is message-scoped; its default mode and the
nonregistered-subscriber listener flag are connection-scoped. The values are
exposed under `semantic.sipalg`. This records the iRule controls without
implementing SIP ALG address translation, hairpin routing, or ephemeral
listener creation.

The SIP `SIP::persist` model also includes a bounded emulator-owned persistence
table shared across packet-flow contexts. A structured packet may provide
`route_target` as the fixture's selected route; `use`, `replace`, `bypass`,
`ignore`, and `reset` then produce observable cross-flow routing decisions.
`timeout`, `bidirectional`, and `direction` are honored, with packet timestamps
or deterministic logical ticks driving expiry. The table is limited to 1,024
entries and is neither durable nor shared with external emulator processes; the
BIG-IP Message Routing Framework route table and production TMM scheduler
remain outside the model.

`SIP::route` and `SIP::record-route` support both numeric header-line lookup
and the TMOS `top` selector. `top` returns the first comma-separated route
element while respecting angle-bracketed URIs and quoted parameters; this is
header parsing only and does not create a Message Routing Framework route.

The legacy connection controls `DEMANGLE::enable`, `DEMANGLE::disable`,
`ISESSION::deduplication`, `PLUGIN::enable`, and `PLUGIN::disable` are modeled
as bounded connection state under `semantic.feature_controls`. The emulator
does not perform URL demangling, iSession deduplication, or plugin processing;
it records the rule-visible toggles and validates their documented argument
forms.

`REST::send` is also a semantic mock. It validates the documented
`-method METHOD URI ?BODY?` form and records bounded local-request state under
`semantic.rest`; it never performs outbound network I/O or exposes a response.

The TDS command surface is modeled for direct and structured-packet
`TDS_REQUEST` and `TDS_RESPONSE` events. `TDS::msg` provides the event message
fields and the read/write `request_type` override; `TDS::session` provides
connection-scoped username, database, login-option, and version metadata.
Message state resets between TDS events while session metadata persists.
Structured packets use bounded caller-supplied fields and TCP lifecycle
ordering. Raw TDS packet messages on port 1433 are reassembled across TCP
fragments and coalesced messages; SQL Batch (type 1) bodies are decoded as
UTF-16LE and classified as read/write requests. Login, RPC parameter, result
token, database-peer, and session-negotiation behavior remain out of scope.

The IKE namespace is implemented for direct `IKE_AUTH` events and the bounded
packet adapter. It models certificate retrieval, SAN getters, and the
`IKE::auth_success` decision against caller-supplied certificate/SAN state.
Raw IKEv2 UDP envelopes on ports 500 and 4500 (including the NAT-T non-ESP
marker) expose the header and generic payload chain and fire `IKE_AUTH` for
exchange type 35; encrypted payload contents remain opaque. It does not
negotiate IKE, parse X.509 certificates, or process ESP/IPsec traffic.
`IKE_AUTH` is included as a transparent 17.5 event compatibility override
because it is documented by F5 but absent from the pinned tcl-lsp event
registry.

The three catalogued TMOS 17.5 `QOE::*` commands are modeled for direct
`QOE_PARSE_DONE` and `CLIENT_CLOSED` events. `QOE::video` reads caller-supplied
video measurements, while `QOE::enable` and `QOE::disable` update a
connection-scoped enable flag exposed under `semantic.qoe`. The model does not
parse media, calculate quality scores, or emulate a live QOE engine.

`OFFBOX::request` is modeled as a bounded, connection-scoped request ledger.
The emulator validates service/payload/options and records each request under
`semantic.offbox`, but never contacts an off-box service. Entries are marked
`not-executed` to make that boundary explicit.

The legacy XML command family is intentionally not implemented for the
TMOS 17.5 target. F5 documents those commands and XML events as unavailable
beginning in v10, except for `XML_CONTENT_BASED_ROUTING`; the catalog retains
the entries with `target_status: unavailable-in-tmos-17.5` for reference.

The six catalogued TMOS 17.5 `NSH::*` commands are modeled as connection-
scoped rule state. `NSH::chain` records a direction-specific chain name;
`NSH::context`, `NSH::path_id`, and `NSH::service_index` validate and retain
their unsigned header fields; `NSH::md1` stores binary-safe metadata by
direction, offset, and length; and `NSH::mocksf` records the mock-service-
function switch. The state is exposed under `semantic.nsh` and resets at a
connection boundary. This does not encapsulate packets, forward traffic
through a service-function chain, or emulate an NSH-aware TMM data path.

The complete TMOS 17.5 `BWC::` family is represented by deterministic
connection-scoped flow state. Policy attachment, category assignment, rate and
PPS overrides, TOS/QoS marks, priority weights, debug state, and measurement
start/stop/identifier/get operations are validated and exposed in
`semantic.bwc`. Measurement values are bounded samples from event-visible
payload bytes; the adapter does not enforce bandwidth, schedule queues, query
live BWC policy configuration, or publish external measurement logs.

The TMOS 17.5 `ADAPT::*` commands model request/response static and dynamic
contexts. Context handles inherit deterministic static attributes, support
enable/allow, internal-virtual selection, preview size, service-down action,
timeout, and result updates, and are visible in `semantic.adapt`. Direct
`ADAPT_REQUEST_*` and `ADAPT_RESPONSE_*` events select the first enabled
dynamic context on their side, or the static context when none is enabled.
HTTP scenarios can seed request and response IVS outcomes with the `adapt`
fixture. `modified` and `response` emit headers then result events, `noop`
emits neither, and `error` emits only the result event. Contexts reset at
connection boundaries; the adapter does not run an ICAP service, internal
virtual server, or real content transformation.

The TMOS 17.5 `ONECONNECT::detach`, `ONECONNECT::label`,
`ONECONNECT::reuse`, and `ONECONNECT::select` commands model the rule-visible
connection controls. Detach/reuse flags, selection mode, and the connection
label persist across keep-alive requests and reset when the emulator starts a
new connection. The adapter does not simulate a shared multi-client idle
server-connection pool or perform real load-balancer connection scheduling.
Each HTTP result also exposes a deterministic `server_connection` record with
an identity, an `enabled` profile flag, reuse reason, post-response attachment
state, selection mode, and label. The record models one emulator session's
single idle slot; it is not a multi-client pool or real load-balancer
connection scheduler. `HTTP::retry -reset` replaces that server-side identity
for the replay while preserving the client-side connection and iRule state.

The IP semantic layer models the seven TMOS 17.5 commands `IP::hops`,
`IP::idle_timeout`, `IP::ingress_drop_rate`, `IP::ingress_rate_limit`,
`IP::intelligence`, `IP::reputation`, and `IP::stats`. Path hops, directional
packet/byte counters, connection age, timeout changes, and ingress controls
are deterministic connection state. Intelligence and reputation lookups are
scenario-seeded maps; no licensed external database, DNS lookup, or live
blacklist enforcement is performed. Structured packet byte counts use UTF-8
payload length, while raw IPv4 adapters use the IPv4 total length.
RTSP packet traces expose the four RTSP request/response events and the
catalogued `RTSP::` surface for structured or raw-TCP header lookup/mutation,
payload collection and replacement, release, metadata getters, and
deterministic response emission. Raw RTSP/1.0 control messages support bounded
TCP split/coalescing and Content-Length bodies when the RTSP profile is
attached. The emulator does not implement media transport, session
negotiation, or interleaved RTP/RTCP.
The LB control layer models `LB::bias`, `LB::class`, `LB::command`,
`LB::connect`, `LB::connlimit`, `LB::context_id`, `LB::dst_tag`,
`LB::enable_decisionlog`, `LB::mode`, `LB::prime`, `LB::queue`, `LB::snat`,
and `LB::src_tag` as deterministic connection and pool-selection state.
`LB::connect` and `LB::prime` can select a configured pool member, while
connection limits and queue values are inspectable records rather than a live
TMM scheduler or kernel connection-control implementation.
The profile-attribute commands `PROFILE::access`, `PROFILE::antifraud`,
`PROFILE::auth`, `PROFILE::avr`, `PROFILE::diameter`, `PROFILE::exchange`,
`PROFILE::ftp`, `PROFILE::httpclass`, `PROFILE::httpcompression`,
`PROFILE::oneconnect`, `PROFILE::persist`, `PROFILE::stream`, `PROFILE::tftp`,
`PROFILE::vdi`, `PROFILE::webacceleration`, and `PROFILE::xml` read scalar
values supplied by the scenario's `profile_settings` object. They return an
empty value for unattached or unspecified profiles; they do not load live
BIG-IP profile objects or infer undocumented defaults.
The TMOS 17.5 `DOSL7::disable`, `DOSL7::enable`, `DOSL7::health`,
`DOSL7::is_ip_slowdown`, `DOSL7::is_mitigated`, `DOSL7::profile`, and
`DOSL7::slowdown` commands use the scenario's deterministic `dosl7` policy
inputs. Enable/disable is connection-scoped, while seeded and rule-created
greylist entries remain available to later connections in the same session.
An HTTP request can override the seeded `is_mitigated` result for one
transaction, including across an internal `HTTP::retry`. The adapter records
rate and timeout values but does not implement wall-clock expiry, traffic-rate
measurement, or the ASM/DOS inspection and mitigation engines.
An enabled `dosl7.attack` fixture emits `IN_DOSL7_ATTACK` during the HTTP
request lifecycle and exposes `$DOSL7_ATTACKER_IP` and `$DOSL7_MITIGATION` to
the handler. The event is fixture-driven; no DoS detector or mitigation engine
is implemented.
The TMOS 17.5 `ASM::` surface is represented by a deterministic scenario-level
policy model covering all 25 catalogued commands. It can seed policy identity,
client identity, login/CAPTCHA state, payload, request and response violations,
signatures, threat campaigns, and status/severity values; rule actions such as enable/disable,
raise, unblock, uncaptcha, conviction, deception, and payload replacement are
recorded in request semantic state. Request inputs reset between transactions,
while connection overrides reset when a new connection begins. The model does
not perform WAF signature matching, request inspection, CAPTCHA validation,
threat-campaign detection, or production ASM enforcement.
When the `ASM` profile is attached and remains enabled for an HTTP request, the
adapter emits `ASM_REQUEST_VIOLATION` when the bounded fixture has violations,
then `ASM_REQUEST_DONE`, and finally `ASM_REQUEST_BLOCKING` only when violations
remain blocked after the `ASM_REQUEST_DONE` handlers run. An `ASM::unblock`
action therefore suppresses the blocking hook, and the returned semantic
snapshot reflects mutations made by those handlers. A non-empty
`response_violations` fixture emits `ASM_RESPONSE_VIOLATION` after the response
transaction and exposes response-side `ASM::violation` and `ASM::payload`
state; `ASM::payload replace` updates the modeled response body. An enabled
`response_login` fixture emits `ASM_RESPONSE_LOGIN` after the response
transaction and sets response-side `ASM::login_status` and `ASM::username`.
This is a
deterministic request/response lifecycle for rule testing; it does not add a
WAF inspection engine, blocking response generator, or automatic finding
detector.
The TMOS 17.5 `BOTDEFENSE::` surface is represented by a deterministic policy
model covering all 25 catalogued commands. Scenario inputs can seed action,
client and bot classification, anomalies/categories, CAPTCHA/cookie state,
device and micro-service metadata, previous-request fields, and support or
reason values. Action and client-side challenge overrides are recorded in
semantic state, while enable/disable is connection-scoped. The model does not
perform Bot Defense detection, browser challenges, CAPTCHA validation, cookie
cryptography, or ML classification; `BOTDEFENSE_REQUEST` and
`BOTDEFENSE_ACTION` remain explicit profile-gated events rather than claims of
a production Bot Defense pipeline.
The TMOS 17.5 `ANTIFRAUD::` surface is represented by a deterministic policy
model covering all 39 catalogued commands. Scenario inputs can seed login
identity, transaction result, alert fields, and license identity. With the
`ANTIFRAUD` profile attached, configured login and alert triggers cause the
adapter to emit `ANTIFRAUD_LOGIN` and `ANTIFRAUD_ALERT` after `HTTP_REQUEST`;
rules can suppress the alert or disable the plugin first. Request context resets
between transactions, while plugin enable/disable state resets on a new
connection. This does not implement fraud scoring, fingerprinting, device
intelligence, alert delivery, or a production Anti-Fraud service.
The TMOS 17.5 `AUTH::` surface is represented by deterministic authentication
sessions covering all 18 catalogued commands and the five AUTH events.
Sessions can be started, supplied with credentials, subscribed to result data,
completed with success/failure/error outcomes, or continued after an
`AUTH_WANTCREDENTIAL` prompt. Session state is connection-scoped and IDs are
deterministic; the scenario can seed prompt metadata, LDAP fields, and result
data. This does not contact PAM, RADIUS, LDAP, certificates, or an external
identity provider, and does not model production asynchronous authentication
timing.
The four TMOS 17.5 `AAA::` commands are represented by deterministic internal
virtual-server requests. Authentication and accounting sends return
connection-scoped request IDs and expose configurable `OK`, `FAIL`,
`INPROGRESS`, or `ERROR` results through their matching result commands. The
model keeps request metadata for inspection but never stores the supplied
password and does not contact an AAA virtual server or reproduce asynchronous
completion.
The 15 catalogued TMOS 17.5 `ACCESS::` commands are represented by a
deterministic APM-style session and policy model. Session creation, policy
evaluation, and removal can emit `ACCESS_SESSION_STARTED`,
`ACCESS_POLICY_COMPLETED`, and `ACCESS_SESSION_CLOSED`; session data, per-flow
variables, ACL lookups/results, policy metadata, SAML values, request
enable/disable, and response commitment are inspectable in the semantic
snapshot. Password-like session keys are redacted there. Ephemeral-auth and
OAuth operations use deterministic placeholders and do not perform external
authentication or cryptographic signing. The HTTP request runner additionally
models the 17.5 session-start, policy-completion, per-request ACL outcome, and
session-close boundaries, with request-level ACL/policy fixture overrides.
Configured SAML authentication and assertion fixtures drive their corresponding
HTTP policy events. SLO request/response fixtures drive
`ACCESS_SAML_SLO_REQ`/`ACCESS_SAML_SLO_RESP` after an allowed policy completes;
the `ACCESS::saml` values remain deterministic payload fixtures rather than a
real SAML exchange. See the F5 [`ACCESS_SAML_SLO_REQ`](https://clouddocs.f5.com/api/irules/ACCESS_SAML_SLO_REQ.html)
and [`ACCESS_SAML_SLO_RESP`](https://clouddocs.f5.com/api/irules/ACCESS_SAML_SLO_RESP.html)
event references.
This does not execute an APM policy graph, expire sessions against wall-clock
time, or reproduce SAML/OAuth/AAA network behavior.
The TMOS 17.5 `ACCESS2::access2_proc` command is also modeled for
`ACCESS2_POLICY_EXPRESSION_EVAL`: direct event state supplies the selected
procedure name and the command returns it without invoking hidden policy code.
HTTP request simulations may instead supply `access2.proc`, which emits the
event once after an allowed policy completes. Direct-event values are reset at
each event boundary; automatic fixture delivery is gated once per ACCESS
session. This remains a fixture-driven observation point, not an APM policy
engine.
The `EPI_NA_CHECK_HTTP_REQUEST` event is emitted for the three documented
Endpoint Inspector/Network Access status paths when an ACCESS profile is
attached; the event is not a status-report processor. See the F5
[`EPI_NA_CHECK_HTTP_REQUEST`](https://clouddocs.f5.com/api/irules/EPI_NA_CHECK_HTTP_REQUEST.html)
reference.
The optional `ping` fixture exposes the TMOS 17.5
[`PING_REQUEST_READY`](https://clouddocs.f5.com/api/irules/PING_REQUEST_READY.html)
and
[`PING_RESPONSE_READY`](https://clouddocs.f5.com/api/irules/PING_RESPONSE_READY.html)
events once per modeled HTTP transaction. They are deterministic HTTP
mutation points after the corresponding base request/response handler; no
PingAccess policy-server connection is opened, and the fixture flags default
to disabled and reset for each request.
The optional `avr.cspm_injection` fixture similarly exposes
[`AVR_CSPM_INJECTION`](https://clouddocs.f5.com/api/irules/AVR_CSPM_INJECTION.html)
once after `HTTP_RESPONSE` when an AVR profile is attached. It provides the
response mutation point and records `AVR::disable_cspm_injection`, but does not
generate CSPM JavaScript or emulate AVR analytics.
The `XML_CONTENT_BASED_ROUTING` event is available through a synthetic event
packet with an attached XML profile. Its bounded `xml` state installs the
documented `XML_count`, `XML_queries(index)`, and `XML_values(index)` globals;
the count and both list lengths must match. This models the rule-visible
profile-match callback, not XML parsing, profile expression evaluation, or
wire-triggered XML event discovery. See the F5
[`XML_CONTENT_BASED_ROUTING`](https://clouddocs.f5.com/api/irules/XML_CONTENT_BASED_ROUTING.html)
reference.
The IVS event pair is available through synthetic event injection when the
`IVS_ENTRY` profile is attached. `IVS_ENTRY::result` is modeled for the
documented `noop`, `modified`, and `response` outcomes with bounded history;
the emulator does not instantiate a second virtual server or execute a real
internal handoff. See the F5
[`IVS_ENTRY_REQUEST`](https://clouddocs.f5.com/api/irules/IVS_ENTRY_REQUEST.html)
and
[`IVS_ENTRY_RESPONSE`](https://clouddocs.f5.com/api/irules/IVS_ENTRY_RESPONSE.html)
references.
The pinned registry also retains `IP_GTM`, `TCP_GTM`, and `UDP_GTM` as
compatibility event names. They are supported as synthetic event injections
with ordinary protocol state, but no GTM wide-IP selection or DNS dataplane is
created. The current F5 master event list groups GTM behavior around
`DNS_REQUEST`, `DNS_RESPONSE`, and load-balancing events; these legacy names
should therefore be treated as dispatch-compatibility hooks rather than a
claim of full GTM emulation. See the F5
[master event list](https://clouddocs.f5.com/api/irules/Events.html).
The global `call` command is modeled for top-level iRule `proc` declarations,
including optional `-debug`, list-safe argument dispatch, and propagation of
Tcl procedure return/error codes. It does not evaluate arbitrary top-level
Tcl. See the F5 [`call` command reference](https://clouddocs.f5.com/api/irules/call.html).
The global `fasthash` command is modeled with one string argument and a
deterministic non-negative 63-bit result. It is suitable for repeatable
off-box tests, but is not expected to match BIG-IP's implementation-specific
hash values.
The legacy global `vlan_id` command is modeled as a no-argument getter over
the same packet VLAN state exposed by `LINK::vlan_id`; it does not parse live
Ethernet frames.
The legacy global `traffic_group` command is modeled as a no-argument getter
over caller-supplied `traffic_group.name` event state. It returns an empty
string when no value is supplied and does not model BIG-IP traffic-group
configuration or failover behavior.
The curated global helpers `uniq_ordered_ip_list`, `uniq_sorted_ip_list`,
`xff_list`, `xff_uniq_ordered_ip_list`, and `xff_uniq_sorted_ip_list` provide
bounded IPv4/IPv6 normalization, deduplication, and deterministic ordering.
The `xff_*` helpers read repeated values from `X-Forwarded-For` or an
optional caller-selected header and remove loopback and unspecified addresses;
they do not resolve hostnames, apply a trusted-proxy policy, or reproduce a
live TMM header-processing pipeline. Each call is capped at 256 candidates.
These are curated community utilities from the pinned `tcl-lsp` registry, not
native BIG-IP primitives.
The global `rmd160` command is modeled as a one-value binary RIPEMD-160 digest
using the existing bounded digest bridge. It does not add BIG-IP-specific
digest behavior beyond the documented hash operation.
The global `md4` command is also modeled as a one-value binary legacy digest,
with standard test vectors covered by the adapter suite. It is provided for
compatibility only and is not a recommendation for security-sensitive use.
The seven catalogued `AM::*` commands are represented by a deterministic
acceleration-metadata layer: the six no-argument readers return caller-supplied
metadata and `AM::disable` records connection-scoped disable state. The
adapter does not execute Application Acceleration Manager policy, cache
population, or media transformation because those behaviors are not defined
by the pinned command contract.
The TMOS 17.5 `ACL::action` and `ACL::eval` commands are represented by a
deterministic ACL decision state. `ACL::action` supports the documented
`default`, `drop`, `reset`, `allow`, and `allow-final` actions in `FLOW_INIT`;
`ACL::eval` supports L4 evaluation and the `-l7` early-return behavior in
`CLIENT_ACCEPTED`. The model records evaluation and applied-action state but
does not enforce AFM policy, terminate sockets, or evaluate a live ACL chain.
The eight catalogued TMOS 17.5 `LSN::*` commands are represented by a
deterministic connection-scoped translation state. Address, port, pool,
disable, inbound filtering, persistence mode, persistence entries, and
inbound entries can be set, queried, and removed with bounded endpoint and
timeout validation. The model does not allocate from a live CGNAT pool,
translate packets, replicate mappings, or enforce idle expiry.
The seven catalogued TMOS 17.5 `FLOW::*` commands are represented by paired
synthetic client/server handles. `FLOW::this`, `FLOW::peer`, priority, idle
timeout, idle duration, refresh, and validated related-flow creation update a
deterministic connection snapshot; a virtual event clock avoids wall-clock
flakiness. This does not create sockets, perform source translation, schedule
packets, or reproduce live TMM flow state.
The two catalogued TMOS 17.5 `FLOWTABLE::` commands are represented by
scenario-seeded counters and limits. A scenario may provide `flowtable.count`
with `global`, `virtual`, and `route_domain` maps, plus `flowtable.limit` with
`virtual` and `route_domain` maps. Missing entries return zero; when a scope
name is omitted, the deterministic lookup key is `default`. This models the
query and validation surface, not live flow creation, multi-TMM replication,
aging, or enforcement of a configured limit.
`VALIDATE::protocol` performs bounded, deterministic payload signature checks
for common HTTP, TLS, SSH, FTP, and SMTP forms and returns a boolean result;
unknown application classifiers return false. It does not perform licensed
APM/AFM/PEM classification, deep packet inspection, or external lookups.
`L7CHECK::protocol` supports the documented `set VALUE` and `get` forms during
`L7CHECK_CLIENT_DATA`, `L7CHECK_SERVER_DATA`, and `CONNECTOR_OPEN`. The value
is connection-scoped and can be supplied or inspected through the structured
event-state API. Packet replay accepts `protocol: "l7check"` with an optional
`l7_protocol` label and payload, emitting the corresponding client/server data
event for each packet. The adapter does not classify arbitrary payload bytes.
The four `LINK::*` commands (`lasthop`, `nexthop`, `qos`, and
`vlan_id`) read deterministic link metadata from that same API; a next-hop MAC
defaults to the documented broadcast value until the caller supplies one.
The legacy `lasthop` and `nexthop` setters update that shared metadata and
retain unresolved IP targets as intent rather than performing ARP or route
resolution.
This models iRule-visible state and command validation, not live Ethernet,
ARP, VLAN, route, QoS, or TMM forwarding behavior.
The `protocol: "fix"` packet adapter emits `FIX_HEADER` and then `FIX_MESSAGE`
from caller-supplied parsed FIX tags. Raw TCP traffic is also decoded when the
FIX profile is attached: bounded stream reassembly validates FIX tags 8/9/10,
`BodyLength`, and `CheckSum` before exposing the tag map to both events. Raw
repeating tags are represented by their final value, and the adapter does not
implement FIX session negotiation, data dictionaries, or repeating-group
structure. Direct FIX events and tag-map mutation remain available through the
event-state API.
The TMOS 17.5 `SOCKS::allowed`, `SOCKS::destination`, and `SOCKS::version`
commands are modeled on a structured `SOCKS_REQUEST` state. They support
version inspection, allow/reject decisions, host and port getters/setters,
and bounded `HOST:PORT` parsing. Structured `socks` packet records can also
decode one SOCKS4, SOCKS4a, or SOCKS5 request and dispatch `SOCKS_REQUEST`,
including IPv4, IPv6, and domain destinations. The adapter records the
resulting allow/reject outcome but does not implement a SOCKS handshake, proxy
socket, response encoder, or live destination connection.
The TMOS 17.5 `SDP::field`, `SDP::media`, and `SDP::session_id` commands are
modeled on structured SDP state attached to SIP message events. They support
indexed session-field access, media count/type/port/transport/connection and
attribute reads, bounded port/connection rewrites, and session-ID lookup.
SIP packets whose `Content-Type` is `application/sdp` now populate that state
from bounded UTF-8 SDP bodies and re-encode the supported mutations while
preserving unmodeled SDP lines. Bodies larger than the SDP state limit,
malformed bodies, and non-UTF-8 bodies remain opaque SIP payloads; this is not
a complete RFC 4566 parser or media negotiation engine.
The `CACHE` and `WEBACCELERATION` profiles add a deterministic per-session
HTTP cache model covering all 17 catalogued `CACHE::` commands and the
`CACHE_REQUEST`, `CACHE_RESPONSE`, and `CACHE_UPDATE` events. Cache keys,
headers, payloads, hits, age, freshness, expiry, priorities, and forced or
disabled storage are represented in semantic state; `CACHE::header` matching
is case-insensitive. This does not claim full TMM cache fidelity: eviction,
wall-clock freshness, disk persistence, cache policies, and live Web
Accelerator behavior remain outside the emulator.
RADIUS packet handling validates standard and Vendor-Specific attributes and
exposes the four TMOS 17.5 AAA request/response events. It intentionally does
not implement shared-secret cryptography, password obfuscation, live AAA
servers, or timer-driven retransmission.
Message Routing Framework packets expose generic message fields, ingress and
egress events, bounded payload collection, route state, retries, and the
`MESSAGE::`, `GENERICMESSAGE::`, and core `MR::` command families. Peer
connections, production route selection, and timer-driven retries remain
outside this deterministic model.
DNS packet state includes the question, header flags/codes, and bounded answer,
authority, and additional RR sections. The DNS semantic layer supports opaque
RR objects, section insert/remove/clear operations, RR field mutation,
`DNS::header`, `DNS::scrape`, EDNS0 controls, `DNS::return`, and packet drop or
disable actions. Structured records are deterministic test data; the emulator
does not run DNS-Express, recursive resolution, DNSSEC signing, or a live
nameserver. `RESOLVER::name_lookup` and the `DNSMSG::*` commands can consume
scenario-supplied resolver records without making network requests.
The deprecated `RESOLV::lookup` command performs a deterministic inline query
against the same configured records, returning matching `rdata` values for
`-a`, `-aaaa`, `-ptr`, `-txt`, `-mx`, `-naptr`, and `-srv` lookups. The
deprecated `NAME::lookup` command stores an asynchronous-style result and
queues `NAME_RESOLVED` after the current event returns when that event is
registered; `NAME::response` exposes the address list or reverse-lookup name
there. These legacy commands do not contact a nameserver, model retry timers,
or implement a real asynchronous event loop.
`DNS::tsig exists` and `DNS::tsig remove` expose and clear deterministic TSIG
presence state; the adapter does not calculate or validate TSIG signatures.
TLS packet state supports common SNI, cipher, session, certificate, X509
subject/issuer, verification-result, and SSL enable/disable inspection paths;
the remaining high-value TMOS 17.5 SSL paths include client-cert-on-demand,
certificate constraints, forward-proxy controls, session-ID headers, ALPN,
session-secret/TLS 1.3 secret inspection, and bounded plaintext collection,
payload mutation, and release. Structured TLS data is deterministic fixture
input; the adapter does not perform a real TLS handshake, decrypt encrypted
records, validate certificates, or expose cryptographic key material from a
live connection. The complete catalogued X509 inspection surface now consumes
packet-supplied certificate metadata and supports deterministic PEM-to-DER
conversion, ModSSL field-list generation, extension inspection, validity and
public-key queries, and verification-error descriptions. When `cert_pem` is a
valid PEM certificate, or `cert_der` is valid hexadecimal DER, the adapter
parses the certificate and derives the subject, issuer, serial, MD5
fingerprint, extensions, validity dates, signature algorithm, public-key
metadata, version, and canonical PEM. Individual metadata fields remain
supported as a fallback for synthetic or intentionally malformed fixtures.
The parser validates certificate encoding but does not validate certificate
chains or perform cryptographic signature verification.
The SSL control layer also models ALPN, SSL mode, handshake hold/resume,
renegotiation and secure-renegotiation policy/inspection, non-SSL allowance,
dynamic record sizing, maximum record size, profile selection, session
invalidation, and unclean-shutdown policy as deterministic connection state.
It does not emit cryptographic renegotiation or switch a live TLS profile.
Structured TLS packet traces also dispatch the target-valid
`CLIENTSSL_PASSTHROUGH`, `CLIENTSSL_SERVERHELLO_SEND`, and
`SERVERSSL_CLIENTHELLO_SEND` lifecycle events. They are deterministic event
fixtures and do not implement TLS negotiation or encrypted-record processing.
HTTP/2 structured transaction metadata supports pseudo-header lookup and
mutation, stream ID and priority state, active/version/request/concurrency
queries, enable/disable, disconnect decisions, and deterministic
`HTTP2::push` PUSH_PROMISE records through the `HTTP2::*` surface. Push records
retain URI, priority, headers, inline content/iFile references, and suppression
flags; they do not contact an origin or emit live HTTP/2 frames. The adapter
does not parse HTTP/2 frames, implement HPACK, or multiplex live streams.
The packet adapter now also accepts explicit `protocol: "http2"` payloads and
binary TCP `payload_hex` captures. It recognizes a split HTTP/2 prior-knowledge
client preface, decodes bounded frames and HPACK blocks across packet
boundaries, joins request/response DATA and HEADERS by stream ID, and retains
trailers, informational responses, and bounded control-frame metadata. It does
not inspect encrypted TLS payloads, implement a full flow-control scheduler,
or emit server-push streams.
GTP packets expose bounded GTPv1 and GTPv2 header/IE state, G-PDU payloads,
GTP signaling/G-PDU/Prime ingress and egress events, and the catalogued
`GTP::` command family. GTP-C and GTP-U use UDP ports 2123 and 2152; GTP-Prime
uses TCP port 3386 with sequence-aware reassembly. `GTP::tunnel` provides
deterministic IPv4/IPv6 and TCP/UDP header inspection for G-PDU payloads.
This is not a complete 3GPP peer, extension-header registry, TEID/session
manager, or retransmission engine; unsupported protocol details remain visible
as bounded raw message state rather than being guessed.

The upstream registry is broader than the target release. Capability entries
carry `target_status`, and the conformance response reports both the full
registry count and the count available in TMOS 17.5. Known 21.0-only JSON and
SSE commands/events are retained for catalog visibility but are marked
`introduced-after-tmos-17.5` and rejected by the emulator.
The CLI `--catalog`, HTTP `/v1/catalog`, and MCP `irule_catalog` surfaces can
materialize the complete filtered command catalog as deterministic bounded
chunks for downstream semantic-emulation workers.
