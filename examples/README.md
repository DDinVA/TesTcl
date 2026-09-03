This folder contains examples demonstrating how to write your TesTcl tests

The examples used are identical to the ones found on [testcl.com](http://testcl.com)

The `observations/` directory contains a TMOS 17.5 external-observation
template. For larger captures, `http-17.5.capture-plan.json` separates the
portable test inputs and comparison paths from the output collected on a
BIG-IP or vLab. Feed one JSON object per line through the assembler:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --assemble-observations \
  --capture-plan examples/observations/http-17.5.capture-plan.json \
  --capture-records examples/observations/http-17.5.records.ndjson
```

The checked-in records file is only a shape example and deliberately contains
a placeholder value. Replace it with records emitted by an independent
TMOS 17.5 collector. The assembler requires exactly one record for every plan
case, preserves plan order, adds a digest of the supplied records, and never
executes the emulator to generate reference output. The assembled result can
then be passed to `--golden-vectors` or `POST /v1/differential-vectors`.

To generate a plan for a catalog chunk, use `--capture-plan-template`. It
chooses a target-valid event/profile shell for each F5 iRule command; the
collector still supplies command-specific arguments and fixture values:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --capture-plan-template --offset 0 --limit 100 \
  --tmos-build 17.5.4 --capture-id run-001 > capture-plan-000.json
```

The optional BIG-IP collector can inspect that plan without touching a device:

```sh
./scripts/collect-tmos17.sh --plan capture-plan-000.json
```

Live execution is deliberately explicit and requires `BIGIP_USERNAME`,
`BIGIP_PASSWORD`, `--execute`, and `--allow-device-write`; see
[`docs/emulator.md`](../docs/emulator.md) for the virtual-server and traffic
requirements.

For DNS, SIP, MQTT, and other protocol-specific cases, add
`--trigger-command /path/to/driver`. The collector invokes that executable
once per case with a JSON request on stdin containing the TMOS profile, case
ID, event, command, arguments, profiles, traffic URL, and selected virtual.
The driver must return zero and generate traffic to the virtual; it is invoked
without a shell. The collector discards both driver output streams and keeps
ownership of temporary iRule cleanup and structured observation output. Without
a driver, unsupported events are rejected before device mutation unless
`--allow-partial` is supplied. Partial output must be paired with a matching
subset plan before assembly.

The bundled stdlib-only protocol driver can provide initial HTTP/1.1,
WebSocket-over-HTTP/1.1, DNS, SIP, RTSP, FTP control-channel, IMAP/POP3/SMTPS
STARTTLS control lines, LDAP BER messages, MQTT, PCP, RADIUS, and raw UDP/TCP
stimuli.
Put the destination and protocol fixture in each
plan case's `input.request`; use
`--trigger-command ./scripts/tmos17-protocol-driver.sh` locally. The wrapper
requires the repo's uv-managed Python 3.13 environment. The container can use
`/opt/testcl/tools/tmos17-protocol-driver.py` directly.
The `behavior-packs/ldap-17.5.json` fixture additionally exercises BER-framed
LDAP bind request/response traffic split across TCP packets.

The `behavior-packs/global-legacy-controls-17.5.json` fixture is a compact,
runnable TMOS 17.5 checkpoint for the older global command surface: HTTP and
connection readers, byte-order and digest helpers, IP-list utilities, iFiles,
CPU/WHEREIS/PEM lookups, pool enumeration, link/hop controls, redirects,
shared variables, and the deterministic RADIUS helper. Run it locally with:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/global-legacy-controls-17.5.json
```

The `scenarios/multi-irule-17.5.json` fixture demonstrates multiple attached
iRules with priority ordering and a shared pool fixture.

The `behavior-packs/stateful-global-controls-17.5.json` fixture is an
executable TMOS 17.5 contract for stateful sideband connections, traffic
intents, datagroup lookups, URL categorization fixtures, top-level procedures,
event metadata, connection controls, and helper commands. Its sideband and
traffic outputs are deterministic emulator state, not live socket or TMM
evidence. Run it locally with:

```sh
TCL_LSP_ROOT=/path/to/tcl-lsp ./scripts/emulate-irule.sh \
  --behavior-pack examples/behavior-packs/stateful-global-controls-17.5.json
```

The `scenarios/live-http-17.5.json` fixture can be served to a real HTTP client
with `--data-plane`; it includes a deterministic origin response and a rule
that blocks `/private`.

The `golden-vectors/http-streaming-17.5.json` fixture is a checked-in
TMOS-17.5 contract for split request bodies, chunked responses, and pipelined
HTTP/1.x messages. It is not live-device evidence; replace its reference
outputs with independently captured observations when available.
