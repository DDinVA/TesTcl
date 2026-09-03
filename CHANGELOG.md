# Changelog

## [0.2.0rc1] — 2026-09-03

First modern emulator preview for TMOS 17.5.

### Added

- Pinned, chunked ingestion of the Tcl-LSP iRule command/event catalog.
- Local command probes, behavior candidates, catalog-wide workers, resumable
  capture plans, campaign assembly, and differential-vector workflows.
- HTTP, HTTP/2, TCP, UDP, SIP, DNS, WebSocket, TLS, packet, and protocol
  adapters with bounded API, MCP, and browser workbench access.
- Portable Python 3.13 and Docker/Compose evaluation paths.
- Golden vectors, behavior packs, live-client smoke tests, and explicit
  compatibility documentation for modeled versus unsupported behavior.

### Evidence in this preview

- 1,499 catalog entries ingested; 1,477 entries in the filtered 17.5 target
  catalog; 989 target F5 commands and 164 target events indexed.
- Local catalog evaluation and the full Python integration suite pass in the
  repository's Python 3.13 uv environment.
- Container and Compose smoke tests cover the portable API and bounded live
  data planes.

### Limitations

- This is not a BIG-IP/TMM or vLab replacement and does not claim independent
  TMOS parity.
- External capture collection remains opt-in, requires an authorized TMOS 17.5
  device, and is dry-run by default.
- Modeled subsystems are intentionally bounded; consult
  [`docs/compatibility.md`](docs/compatibility.md) before relying on behavior.
