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

The optional TMOS 17.5 emulator exposes the pinned `tcl-lsp` registry in
bounded chunks and reports static command-handler and packet-event coverage
through its conformance endpoint. Structured packet traces currently cover
TCP, TLS, HTTP, generic UDP, SCTP, DNS, SIP over TCP or UDP, Diameter over TCP, RADIUS over UDP, GTP over UDP or GTP-Prime over TCP, Message Routing Framework messages over TCP, and raw IPv4 transport records. Fragmented IPv4
packets remain outside the current boundary. Classic PCAP and bounded pcapng
ingestion are supported, and TCP stream reassembly includes bounded gap,
overlap, and retransmission de-duplication handling. Diameter validates and
re-encodes bounded RFC 6733-style headers and AVPs, then exposes the 17.5
Diameter ingress, egress, and retransmission events. Its routing, retry,
retransmission, persistence, and capability-exchange commands are modeled as
deterministic test state rather than a complete Diameter peer or TMM
route/persistence implementation.
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
surfaces for structured client/server data events, DHCP header readers, option
lookup/mutation, and drop/reject decisions. DHCPv6 option deletion is modeled
explicitly. It does not parse raw DHCP messages, run a lease allocator, or
send real ICMP rejection traffic.
The FTP adapter models the six 17.5 `FTP::*` controls for structured TCP
control-channel traces, including active-mode permission, FTP handler state,
FTPS activation mode, TLS session-reuse enforcement, and passive-port range
selection. It dispatches the client-accepted, client-data, server-connected,
and server-data path and preserves those controls across messages on one
connection. It does not parse FTP commands, negotiate TLS, create a data
channel, or allocate live passive ports.
The IMAP, POP3, LDAP, and SMTPS adapters model their TMOS 17.5 STARTTLS control
commands over structured TCP lifecycle traces. Activation modes (`none`,
`allow`, and `require`) and protocol-handler enable/disable state persist per
connection, with bounded command text, TLS-active metadata, and payload
snapshots. They intentionally do not parse the protocol wire formats,
negotiate TLS, or enforce STARTTLS against a real peer.
The ICAP adapter models the four 17.5 `ICAP::*` commands and dispatches
`ICAP_REQUEST`/`ICAP_RESPONSE` for structured messages with an `ICAP` profile.
It supports method, URI, status, and case-insensitive header reads and
mutations, including complete header replacement. It does not implement an
ICAP server, encapsulated HTTP-body parsing, or license/control-plane behavior.
The NTLM adapter models the connection-scoped `NTLM::enable` and
`NTLM::disable` controls on bounded structured TCP payloads; it does not parse
NTLM messages or negotiate authentication. The protocol-inspection adapter
requires the `PROTOCOL_INSPECTION` profile, dispatches
`PROTOCOL_INSPECTION_MATCH`, and models supplied match IDs, match status,
payload bytes, `PROTOCOL_INSPECTION::id`, and `PROTOCOL_INSPECTION::disable`.
It does not provide a Protocol Inspection signature engine or infer matches
from raw traffic.
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
the high-level HTTP lifecycle exposes `REWRITE_REQUEST_DONE` and conditionally
`REWRITE_RESPONSE_DONE`; payload reads and replacements use byte offsets and
update an existing `Content-Length` header. It does not implement the full
REWRITE profile/plugin, APM policy processing, or URL/file rewrite tables.
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
Contexts reset at connection boundaries;
the adapter does not run an ICAP service, internal virtual server, or real
content transformation.

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
connection scheduler.

The IP semantic layer models the seven TMOS 17.5 commands `IP::hops`,
`IP::idle_timeout`, `IP::ingress_drop_rate`, `IP::ingress_rate_limit`,
`IP::intelligence`, `IP::reputation`, and `IP::stats`. Path hops, directional
packet/byte counters, connection age, timeout changes, and ingress controls
are deterministic connection state. Intelligence and reputation lookups are
scenario-seeded maps; no licensed external database, DNS lookup, or live
blacklist enforcement is performed. Structured packet byte counts use UTF-8
payload length, while raw IPv4 adapters use the IPv4 total length.
RTSP packet traces expose the four RTSP request/response events and the
catalogued `RTSP::` surface for structured header lookup/mutation, payload
collection and replacement, release, metadata getters, and deterministic
response emission. RTSP currently requires structured packets and the RTSP
profile; it does not parse raw RTSP wire messages or implement media transport,
session negotiation, or interleaved RTP.
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
The TMOS 17.5 `ASM::` surface is represented by a deterministic scenario-level
policy model covering all 25 catalogued commands. It can seed policy identity,
client identity, login/CAPTCHA state, payload, violations, signatures, threat
campaigns, and status/severity values; rule actions such as enable/disable,
raise, unblock, uncaptcha, conviction, deception, and payload replacement are
recorded in request semantic state. Request inputs reset between transactions,
while connection overrides reset when a new connection begins. The model does
not perform WAF signature matching, request inspection, CAPTCHA validation,
threat-campaign detection, or production ASM enforcement.
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
authentication or cryptographic signing. The model does not execute an APM
policy graph, enforce production ACLs, expire sessions against wall-clock
time, or reproduce SAML/OAuth/AAA network behavior.
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
event-state API. The four `LINK::*` commands (`lasthop`, `nexthop`, `qos`, and
`vlan_id`) read deterministic link metadata from that same API; a next-hop MAC
defaults to the documented broadcast value until the caller supplies one.
This models iRule-visible state and command validation, not live Ethernet,
ARP, VLAN, route, QoS, or TMM forwarding behavior.
The TMOS 17.5 `SOCKS::allowed`, `SOCKS::destination`, and `SOCKS::version`
commands are modeled on a structured `SOCKS_REQUEST` state. They support
version inspection, allow/reject decisions, host and port getters/setters,
and bounded `HOST:PORT` parsing; they do not implement a SOCKS handshake,
proxy socket, or live destination connection.
The TMOS 17.5 `SDP::field`, `SDP::media`, and `SDP::session_id` commands are
modeled on structured SDP state attached to SIP message events. They support
indexed session-field access, media count/type/port/transport/connection and
attribute reads, bounded port/connection rewrites, and session-ID lookup. The
slice does not yet parse SDP from raw SIP payloads or re-encode the SIP body.
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
public-key queries, and verification-error descriptions. It validates opaque
certificate handles and PEM structure; it does not validate certificate
chains or perform cryptographic verification.
The SSL control layer also models ALPN, SSL mode, handshake hold/resume,
renegotiation and secure-renegotiation policy/inspection, non-SSL allowance,
dynamic record sizing, maximum record size, profile selection, session
invalidation, and unclean-shutdown policy as deterministic connection state.
It does not emit cryptographic renegotiation or switch a live TLS profile.
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
