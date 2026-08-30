This folder contains examples demonstrating how to write your TesTcl tests

The examples used are identical to the ones found on [testcl.com](http://testcl.com)

The `observations/` directory contains a TMOS 17.5 external-observation
template. Replace its placeholders with output collected independently from a
BIG-IP or vLab, then import it with `--import-observations` before running the
resulting golden-vector pack.

The `scenarios/multi-irule-17.5.json` fixture demonstrates multiple attached
iRules with priority ordering and a shared pool fixture.

The `scenarios/live-http-17.5.json` fixture can be served to a real HTTP client
with `--data-plane`; it includes a deterministic origin response and a rule
that blocks `/private`.

The `golden-vectors/http-streaming-17.5.json` fixture is a checked-in
TMOS-17.5 contract for split request bodies, chunked responses, and pipelined
HTTP/1.x messages. It is not live-device evidence; replace its reference
outputs with independently captured observations when available.
