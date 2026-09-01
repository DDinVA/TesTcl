#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

for smoke_script in \
  live-observation-smoke.sh \
  live-packet-observation-smoke.sh \
  live-udp-observation-smoke.sh \
  live-sip-observation-smoke.sh \
  live-sip-tcp-observation-smoke.sh \
  live-dns-observation-smoke.sh; do
  echo "== $smoke_script =="
  "$repo_root/scripts/$smoke_script"
  echo
done

echo "All live observation smoke tests passed."
