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
TCP, TLS, HTTP, generic UDP, DNS, SIP over TCP or UDP, Diameter over TCP, RADIUS over UDP, GTP over UDP or GTP-Prime over TCP, Message Routing Framework messages over TCP, and raw IPv4 transport records. Fragmented IPv4
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
Generic UDP traces expose datagram payload bytes, client/server/local/remote
ports, and the `CLIENT_DATA`/`SERVER_DATA` path. The UDP semantic layer models
payload replacement, drop, hold/release, response emission, and bounded buffer,
rate, send-buffer, debug-queue, MSS, and unused-port controls. It does not run
TMM queue scheduling, NAT, connection tracking, or a live upstream UDP socket.
The TCP semantic layer additionally models documented connection tuning
controls including Nagle mode/state, keepalive, idle timeout, send and receive
buffers, MSS changes, pacing, PUSH mode, congestion label, and proxy-buffer
thresholds. These are deterministic state and inspection values; the adapter
does not implement a kernel TCP stack, congestion-control algorithm,
retransmission timers, or wire-level pacing.
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
TLS packet state supports common SNI, cipher, session, certificate, X509
subject/issuer, verification-result, and SSL enable/disable inspection paths;
it does not perform a real TLS handshake or certificate cryptography.
The SSL control layer also models ALPN, SSL mode, handshake hold/resume,
renegotiation and secure-renegotiation policy/inspection, non-SSL allowance,
dynamic record sizing, maximum record size, profile selection, session
invalidation, and unclean-shutdown policy as deterministic connection state.
It does not emit cryptographic renegotiation or switch a live TLS profile.
HTTP/2 structured transaction metadata supports pseudo-header lookup and
mutation, stream ID and priority state, active/version/request/concurrency
queries, enable/disable, and disconnect decisions through the `HTTP2::*`
surface. It does not parse HTTP/2 frames, implement HPACK or live stream
multiplexing, or model `HTTP2::push` response emission.
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
