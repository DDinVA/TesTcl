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
TCP, TLS, HTTP, UDP/DNS, SIP over TCP or UDP, and raw IPv4 transport records. Fragmented IPv4
packets and pcapng file ingestion remain outside the current boundary. Classic
PCAP ingestion is supported, and TCP stream reassembly includes bounded gap,
overlap, and retransmission de-duplication handling.

The upstream registry is broader than the target release. Capability entries
carry `target_status`, and the conformance response reports both the full
registry count and the count available in TMOS 17.5. Known 21.0-only JSON and
SSE commands/events are retained for catalog visibility but are marked
`introduced-after-tmos-17.5` and rejected by the emulator.
