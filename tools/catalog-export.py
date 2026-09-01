#!/usr/bin/env python3
"""Export the complete TMOS 17.5 catalog into hashed, bounded chunk files."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EMULATOR_PATH = ROOT / "tools" / "irule-emulator.py"
MAX_CHUNK_SIZE = 1000
MAX_CHUNKS = 256
MAX_FILE_BYTES = 8 * 1024 * 1024


class CatalogExportError(RuntimeError):
    """Raised when a catalog bundle cannot be written safely."""


def _load_emulator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "testcl_irule_emulator_for_catalog_export", EMULATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise CatalogExportError(f"could not load emulator module {EMULATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EMULATOR = _load_emulator()


def _json_bytes(payload: Any, filename: str) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CatalogExportError(f"could not serialize {filename}: {exc}") from exc
    if len(encoded) > MAX_FILE_BYTES:
        raise CatalogExportError(f"{filename} exceeds the {MAX_FILE_BYTES} byte limit")
    return encoded + b"\n"


def _write_json(path: Path, payload: Any) -> str:
    encoded = _json_bytes(payload, path.name)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
    except OSError as exc:
        raise CatalogExportError(f"could not write {path}: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


def _normalise_filter(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CatalogExportError(f"{field} must be a non-empty NUL-free string")
    return value


def _new_output_dir(output_dir: Path) -> tuple[Path, Path]:
    output_dir = output_dir.expanduser()
    if output_dir.is_symlink():
        raise CatalogExportError(f"output directory must not be a symlink: {output_dir}")
    output_dir = output_dir.resolve()
    if output_dir.name in {"", ".", ".."}:
        raise CatalogExportError("output directory must have a concrete name")
    if output_dir.exists() or output_dir.is_symlink():
        raise CatalogExportError(
            f"output directory already exists: {output_dir}; choose a new directory"
        )
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(
            tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
        )
    except OSError as exc:
        raise CatalogExportError(f"could not create output staging directory: {exc}") from exc
    return output_dir, staging


def export_catalog(
    *,
    output_dir: Path,
    tcl_lsp_root: str | None = None,
    chunk_size: int = 250,
    namespace: str | None = None,
    runtime_status: str | None = None,
    target_status: str | None = None,
) -> dict[str, Any]:
    """Write an immutable catalog bundle and return its manifest."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise CatalogExportError("chunk-size must be an integer")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise CatalogExportError(
            f"chunk-size must be between 1 and {MAX_CHUNK_SIZE}"
        )
    filters = {
        "namespace": _normalise_filter(namespace, "namespace"),
        "runtime_status": _normalise_filter(runtime_status, "runtime-status"),
        "target_status": _normalise_filter(target_status, "target-status"),
    }
    root = EMULATOR._find_tcl_lsp_root(tcl_lsp_root)
    final_dir, staging = _new_output_dir(output_dir)
    chunk_infos: list[dict[str, Any]] = []
    first_page: dict[str, Any] | None = None
    offset = 0
    try:
        while True:
            if len(chunk_infos) >= MAX_CHUNKS:
                raise CatalogExportError(
                    f"catalog export exceeds the {MAX_CHUNKS} chunk limit"
                )
            page = EMULATOR._build_capabilities(root, offset, chunk_size, **filters)
            if first_page is None:
                first_page = page
            chunk = page["chunk"]
            count = chunk["count"]
            if not isinstance(count, int) or count < 0:
                raise CatalogExportError("catalog returned an invalid chunk count")
            if chunk["has_more"] and count == 0:
                raise CatalogExportError("catalog pagination made no progress")
            filename = f"chunk-{len(chunk_infos):04d}.json"
            payload = {
                "schema_version": page["schema_version"],
                "profile": page["profile"],
                "tmos_version": page["tmos_version"],
                "source": page["source"],
                "filter": page["filter"],
                "chunk": chunk,
                "commands": page["commands"],
            }
            sha256 = _write_json(staging / "chunks" / filename, payload)
            chunk_infos.append(
                {
                    "file": f"chunks/{filename}",
                    "offset": chunk["offset"],
                    "limit": chunk["limit"],
                    "count": count,
                    "has_more": chunk["has_more"],
                    "sha256": sha256,
                }
            )
            if not chunk["has_more"]:
                break
            offset += count

        if first_page is None:  # pragma: no cover - loop always emits a page
            raise CatalogExportError("catalog returned no pages")
        events_sha256 = _write_json(staging / "events.json", {
            "schema_version": first_page["schema_version"],
            "profile": first_page["profile"],
            "tmos_version": first_page["tmos_version"],
            "source": first_page["source"],
            "events": first_page["events"],
        })
        profiles_sha256 = _write_json(staging / "profiles.json", {
            "schema_version": first_page["schema_version"],
            "profile": first_page["profile"],
            "tmos_version": first_page["tmos_version"],
            "source": first_page["source"],
            "profiles": first_page["profiles"],
        })
        manifest = {
            "status": "ok",
            "schema_version": 1,
            "profile": first_page["profile"],
            "tmos_version": first_page["tmos_version"],
            "source": first_page["source"],
            "filter": first_page["filter"],
            "summary": first_page["summary"],
            "chunking": {
                "chunk_size": chunk_size,
                "chunk_count": len(chunk_infos),
                "command_count": sum(item["count"] for item in chunk_infos),
            },
            "files": {
                "chunks": chunk_infos,
                "events": {"file": "events.json", "sha256": events_sha256},
                "profiles": {"file": "profiles.json", "sha256": profiles_sha256},
            },
        }
        _write_json(staging / "manifest.json", manifest)
        if final_dir.exists() or final_dir.is_symlink():
            raise CatalogExportError(f"output directory appeared during export: {final_dir}")
        staging.rename(final_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "status": "ok",
        "profile": manifest["profile"],
        "output_dir": str(final_dir),
        "summary": manifest["summary"],
        "chunking": manifest["chunking"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--tcl-lsp-root")
    parser.add_argument("--chunk-size", type=int, default=250)
    parser.add_argument("--namespace")
    parser.add_argument("--runtime-status")
    parser.add_argument("--target-status")
    args = parser.parse_args(argv)
    try:
        result = export_catalog(
            output_dir=Path(args.output_dir),
            tcl_lsp_root=args.tcl_lsp_root,
            chunk_size=args.chunk_size,
            namespace=args.namespace,
            runtime_status=args.runtime_status,
            target_status=args.target_status,
        )
    except (CatalogExportError, EMULATOR.EmulatorInputError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
