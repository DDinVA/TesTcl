
# TesTcl release checklist

The `0.2.x` line is the modern Python 3.13/TMOS 17.5 emulator preview. It is
separate from the legacy Tcl package version (`testcl 1.0.14`). Do not describe
the emulator as a BIG-IP/TMM replacement: local behavior is contract evidence,
and TMOS parity requires authorized reference captures from a 17.5 device.

## Prepare locally

```bash
./scripts/setup-17.5.sh
./scripts/emulate-irule.sh --conformance
./scripts/catalog-evaluation-checkpoint-17.5.sh
./scripts/checkpoint-17.5.sh
./scripts/container-smoke-17.5.sh
```

All Python commands must run through the repo's uv-managed `.venv` and Python
3.13 or newer. The setup helper provisions the pinned Tcl-LSP checkout at
`.cache/tcl-lsp-17.5`; the emulator discovers that managed checkout without an
extra `TCL_LSP_ROOT` export.

## Publish a preview

1. Confirm the release branch is clean and CI is green.
2. Update `pyproject.toml`, `uv.lock`, `README.md`, and `CHANGELOG.md` together.
3. Commit using the privacy-safe GitHub email:

   ```bash
   git config user.email "7632431+DDinVA@users.noreply.github.com"
   git -c commit.gpgsign=false commit -am "release: TesTcl 0.2.0rc1"
   ```

4. Push the branch and merge the modernization PR after review.
5. Tag the merged commit and push the tag:

   ```bash
   git tag -a v0.2.0-rc1 -m "TesTcl 0.2.0rc1"
   git push fork v0.2.0-rc1
   ```

6. Create a GitHub prerelease titled `TesTcl 0.2.0rc1 — TMOS 17.5 emulator
   preview` using the matching `CHANGELOG.md` section.

The tag should be created from the merged default branch, not from an
unmerged feature branch. A draft GitHub release may be created earlier for
review, but it must not be presented as a stable parity release.
