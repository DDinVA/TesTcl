#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_env="$repo_root/.venv"
default_tcl_lsp_root="$repo_root/.cache/tcl-lsp-17.5"
tcl_lsp_root=${TCL_LSP_ROOT:-$default_tcl_lsp_root}
tcl_lsp_commit=${TCL_LSP_COMMIT:-cad24955f16953c2443902efd83d9f7f95d9b648}

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required; install it from https://docs.astral.sh/uv/" >&2
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git is required to provision the pinned tcl-lsp checkout" >&2
  exit 2
fi

uv sync --python 3.13
python_bin="$python_env/bin/python"
if [[ ! -x "$python_bin" ]] || ! "$python_bin" -c \
  'import sys; raise SystemExit(0 if sys.version_info >= (3, 13) else 1)'; then
  echo "uv did not create a Python 3.13+ environment at $python_env" >&2
  exit 1
fi
if ! "$python_bin" -c 'import tkinter; tkinter.Tcl()' >/dev/null 2>&1; then
  echo "the uv Python must include Tcl/Tk support (tkinter.Tcl())" >&2
  exit 1
fi

if [[ -e "$tcl_lsp_root" ]]; then
  if [[ -L "$tcl_lsp_root" ]]; then
    echo "refusing to use a symlinked TCL_LSP_ROOT: $tcl_lsp_root" >&2
    exit 1
  fi
  if ! git -C "$tcl_lsp_root" rev-parse --git-dir >/dev/null 2>&1; then
    echo "TCL_LSP_ROOT exists but is not a git checkout: $tcl_lsp_root" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$tcl_lsp_root" status --porcelain)" ]]; then
    echo "refusing to modify a dirty tcl-lsp checkout: $tcl_lsp_root" >&2
    exit 1
  fi
  current_commit=$(git -C "$tcl_lsp_root" rev-parse HEAD)
  if [[ "$current_commit" != "$tcl_lsp_commit" ]]; then
    if [[ "$tcl_lsp_root" != "$default_tcl_lsp_root" ]]; then
      echo "supplied TCL_LSP_ROOT is at $current_commit; expected $tcl_lsp_commit" >&2
      echo "use the exact pinned checkout or omit TCL_LSP_ROOT for the managed copy" >&2
      exit 1
    fi
    git -C "$tcl_lsp_root" fetch --quiet origin "$tcl_lsp_commit"
    git -C "$tcl_lsp_root" checkout --quiet --detach "$tcl_lsp_commit"
  fi
else
  if [[ "$tcl_lsp_root" != "$default_tcl_lsp_root" ]]; then
    echo "supplied TCL_LSP_ROOT does not exist: $tcl_lsp_root" >&2
    exit 1
  fi
  tcl_lsp_parent=$(dirname "$tcl_lsp_root")
  mkdir -p "$tcl_lsp_parent"
  clone_stage=$(mktemp -d "$tcl_lsp_parent/.tcl-lsp-17.5.XXXXXX")
  cleanup_clone() {
    rm -rf "$clone_stage"
  }
  trap cleanup_clone EXIT
  git clone --quiet https://github.com/bitwisecook/tcl-lsp.git "$clone_stage/repo"
  git -C "$clone_stage/repo" checkout --quiet --detach "$tcl_lsp_commit"
  if [[ -e "$tcl_lsp_root" || -L "$tcl_lsp_root" ]]; then
    echo "TCL_LSP_ROOT appeared during clone: $tcl_lsp_root" >&2
    exit 1
  fi
  mv "$clone_stage/repo" "$tcl_lsp_root"
  trap - EXIT
  cleanup_clone
fi

verified_commit=$(git -C "$tcl_lsp_root" rev-parse HEAD)
if [[ "$verified_commit" != "$tcl_lsp_commit" ]]; then
  echo "tcl-lsp verification failed: got $verified_commit, expected $tcl_lsp_commit" >&2
  exit 1
fi

printf '%s\n' "TesTcl TMOS 17.5 environment ready"
printf 'PYTHON=%s\n' "$python_bin"
printf 'PYTHON_VERSION=%s\n' "$($python_bin --version 2>&1)"
printf 'TCL_LSP_ROOT=%s\n' "$tcl_lsp_root"
printf 'TCL_LSP_COMMIT=%s\n' "$verified_commit"
