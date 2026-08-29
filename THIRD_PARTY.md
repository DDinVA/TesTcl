# Third-party emulator dependency

The optional `tools/irule-emulator.py` adapter can load the iRule simulation
framework from [bitwisecook/tcl-lsp](https://github.com/bitwisecook/tcl-lsp).
TesTcl does not copy that framework into this repository. The container build
fetches it at a pinned commit and keeps the upstream source in `/opt/tcl-lsp`.

`tcl-lsp` is licensed under **AGPL-3.0-or-later** by its upstream authors. See
its `LICENSE` and `DUAL-LICENSING.md` files for the complete terms. A build or
deployment that distributes the emulator container must review and satisfy
those terms, or obtain an appropriate commercial license from the upstream
maintainer.

The wire-level HTTP/2 adapter uses `hpack==4.1.0`, licensed under the **MIT**
license. Its source distribution and license metadata are installed into the
container environment by the pinned dependency installation.
