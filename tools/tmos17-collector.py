#!/usr/bin/env python3
"""Collect bounded TMOS 17.5 command observations from an existing BIG-IP VIP.

The emulator deliberately does not connect to a BIG-IP.  This companion tool
is the opt-in external boundary: it reads an assembly-ready command-probe
plan, installs one short-lived diagnostic iRule at a time on a caller-selected
virtual server, drives HTTP traffic for events it can actually trigger, reads
the resulting structured log line through iControl REST, and emits only
device-observed NDJSON records.

It is dry-run by default.  Device mutation requires both ``--execute`` and
``--allow-device-write``.  Credentials are read from BIGIP_USERNAME and
BIGIP_PASSWORD so they do not appear in shell history or process arguments.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import os
import re
import shlex
import subprocess
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import Request, urlopen


TMOS_PROFILE = "tmos-17.5"
MAX_PLAN_BYTES = 2 * 1024 * 1024
MAX_CASES = 256
MAX_ARGS = 64
MAX_ARG_BYTES = 16 * 1024
MAX_TOTAL_ARG_BYTES = 64 * 1024
MAX_ID_BYTES = 256
MAX_LOG_LINES = 5000
MAX_PROFILES = 64
MAX_PROFILE_BYTES = 256
SUPPORTED_EVENTS = frozenset({"HTTP_REQUEST", "RULE_INIT"})
DANGEROUS_TCL_COMMANDS = frozenset(
    {
        "after",
        "apply",
        "array",
        "break",
        "catch",
        "close",
        "error",
        "eval",
        "exec",
        "exit",
        "expr",
        "for",
        "foreach",
        "file",
        "global",
        "if",
        "info",
        "namespace",
        "interp",
        "load",
        "open",
        "package",
        "proc",
        "puts",
        "rename",
        "read",
        "return",
        "socket",
        "source",
        "subst",
        "switch",
        "tailcall",
        "set",
        "unset",
        "unknown",
        "uplevel",
        "upvar",
        "variable",
        "while",
    }
)
CAPTURE_PREFIX = "TESTCL_CAPTURE_V1"
COMMAND_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_:-]*$")
EVENT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
CAPTURE_LINE_RE = re.compile(
    rf"^{re.escape(CAPTURE_PREFIX)}\|(?P<id>[A-Za-z0-9_.:-]+)\|"
    r"(?P<status>ok|error)\|(?P<rc>[0-9]+)\|(?P<value>[A-Za-z0-9+/=]*)\|"
    r"(?P<error>[A-Za-z0-9+/=]*)$"
)


class CollectorError(RuntimeError):
    """Raised when a plan or external collection step cannot be trusted."""


def _tcl_quote(value: str) -> str:
    """Quote one Tcl word without allowing substitutions from input data."""
    if "\x00" in value:
        raise CollectorError("Tcl strings cannot contain NUL bytes")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    escaped = "".join(
        f"\\u{ord(character):04x}"
        if ord(character) < 0x20 or ord(character) == 0x7F
        else character
        for character in escaped
    )
    return f'"{escaped}"'


def _read_json_file(path: str) -> Any:
    if path == "-":
        raw = sys.stdin.buffer.read(MAX_PLAN_BYTES + 1)
    else:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise CollectorError(f"could not read plan {path!r}: {exc}") from exc
    if len(raw) > MAX_PLAN_BYTES:
        raise CollectorError("capture plan exceeds the 2 MiB limit")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant {value!r}")

    try:
        return json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CollectorError(f"capture plan is not valid UTF-8 JSON: {exc}") from exc


def _validate_scalar_arg(value: Any, index: int) -> str:
    if isinstance(value, bool):
        result = "1" if value else "0"
    elif isinstance(value, (str, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise CollectorError(f"argument {index} is not finite")
        result = str(value)
    else:
        raise CollectorError(f"argument {index} must be a string, number, or boolean")
    if "\x00" in result or len(result.encode("utf-8")) > MAX_ARG_BYTES:
        raise CollectorError(f"argument {index} is too long or contains NUL")
    return result


def validate_plan(plan: Any) -> dict[str, Any]:
    """Validate the collector-facing subset without importing the emulator."""
    if not isinstance(plan, dict):
        raise CollectorError("capture plan must be a JSON object")
    if plan.get("profile", TMOS_PROFILE) != TMOS_PROFILE:
        raise CollectorError("capture plan profile must be tmos-17.5")
    observations = plan.get("observations")
    if not isinstance(observations, list) or not observations:
        raise CollectorError("capture plan observations must be a non-empty array")
    if len(observations) > MAX_CASES:
        raise CollectorError(f"capture plan accepts at most {MAX_CASES} observations")

    seen: set[str] = set()
    normalised: list[dict[str, Any]] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise CollectorError(f"observation {index} must be an object")
        if set(observation) != {"id", "operation", "input", "comparisons"}:
            raise CollectorError(
                f"observation {index} must contain exactly id, operation, input, comparisons"
            )
        case_id = observation["id"]
        if (
            not isinstance(case_id, str)
            or not case_id
            or not ID_RE.fullmatch(case_id)
            or len(case_id.encode("utf-8")) > MAX_ID_BYTES
        ):
            raise CollectorError(f"observation {index} has an invalid safe identifier")
        if case_id in seen:
            raise CollectorError(f"capture plan contains duplicate id {case_id!r}")
        seen.add(case_id)
        if observation["operation"] != "command_probe":
            raise CollectorError(
                f"observation {case_id!r} is not a command_probe operation"
            )
        request = observation["input"]
        if not isinstance(request, dict):
            raise CollectorError(f"observation {case_id!r} input must be an object")
        request_unknown = sorted(
            set(request) - {"command", "args", "event", "profiles", "request"}
        )
        if request_unknown:
            raise CollectorError(
                f"observation {case_id!r} input has unsupported field(s): "
                + ", ".join(request_unknown)
            )
        command = request.get("command")
        event = request.get("event")
        if not isinstance(command, str) or not COMMAND_RE.fullmatch(command):
            raise CollectorError(f"observation {case_id!r} has an invalid command")
        if command in DANGEROUS_TCL_COMMANDS:
            raise CollectorError(
                f"observation {case_id!r} uses a command blocked by the collector safety policy"
            )
        if not isinstance(event, str) or not EVENT_RE.fullmatch(event):
            raise CollectorError(f"observation {case_id!r} has an invalid event")
        args = request.get("args", [])
        if not isinstance(args, list) or len(args) > MAX_ARGS:
            raise CollectorError(f"observation {case_id!r} args must contain 0 to 64 items")
        normalised_args: list[str] = []
        total_bytes = 0
        for arg_index, value in enumerate(args):
            arg = _validate_scalar_arg(value, arg_index)
            total_bytes += len(arg.encode("utf-8"))
            if total_bytes > MAX_TOTAL_ARG_BYTES:
                raise CollectorError(f"observation {case_id!r} arguments exceed 64 KiB")
            normalised_args.append(arg)
        profiles = request.get("profiles", [])
        if not isinstance(profiles, list) or not profiles or len(profiles) > MAX_PROFILES or any(
            not isinstance(profile, str) or not profile or "\x00" in profile
            for profile in profiles
        ):
            raise CollectorError(
                f"observation {case_id!r} profiles must contain 1 to {MAX_PROFILES} non-empty strings"
            )
        if any(len(profile.encode("utf-8")) > MAX_PROFILE_BYTES for profile in profiles):
            raise CollectorError(
                f"observation {case_id!r} contains an oversized profile name"
            )
        if "request" in request and not isinstance(request["request"], dict):
            raise CollectorError(f"observation {case_id!r} request must be an object")
        comparisons = observation["comparisons"]
        if not isinstance(comparisons, list) or not comparisons:
            raise CollectorError(f"observation {case_id!r} comparisons must be non-empty")
        normalised.append(
            {
                "id": case_id,
                "operation": "command_probe",
                "input": {
                    "command": command,
                    "args": normalised_args,
                    "event": event,
                    "profiles": list(profiles),
                    **({"request": request["request"]} if "request" in request else {}),
                },
                "event_supported": event in SUPPORTED_EVENTS,
            }
        )
    return {"profile": TMOS_PROFILE, "observations": normalised}


def render_probe_irule(
    case: dict[str, Any], rule_name: str, *, log_id: str | None = None
) -> str:
    """Render a temporary diagnostic rule for one validated plan case."""
    if not ID_RE.fullmatch(rule_name):
        raise CollectorError("temporary rule name is not safe")
    if log_id is not None and not ID_RE.fullmatch(log_id):
        raise CollectorError("capture log identifier is not safe")
    request = case["input"]
    command_words = " ".join(
        [_tcl_quote(request["command"]), *(_tcl_quote(arg) for arg in request["args"])]
    )
    case_id = _tcl_quote(log_id or case["id"])
    event = request["event"]
    return f"""when {event} {{
    set testcl_capture_rule {_tcl_quote(rule_name)}
    set testcl_capture_id {case_id}
    set testcl_capture_value ""
    set testcl_capture_error ""
    set testcl_capture_rc [catch {{set testcl_capture_value [{command_words}]}} testcl_capture_error]
    if {{ $testcl_capture_rc == 0 }} {{
        set testcl_capture_status ok
    }} else {{
        set testcl_capture_status error
    }}
    log local0. "{CAPTURE_PREFIX}|$testcl_capture_id|$testcl_capture_status|$testcl_capture_rc|[b64encode $testcl_capture_value]|[b64encode $testcl_capture_error]"
}}
"""


def parse_capture_line(line: str, expected_id: str) -> dict[str, Any] | None:
    """Decode one structured BIG-IP log line, ignoring unrelated lines."""
    candidate = line.strip()
    marker_index = candidate.find(CAPTURE_PREFIX)
    if marker_index < 0:
        return None
    match = CAPTURE_LINE_RE.fullmatch(candidate[marker_index:])
    if match is None or match.group("id") != expected_id:
        return None
    try:
        value_bytes = base64.b64decode(match.group("value"), validate=True)
        error_bytes = base64.b64decode(match.group("error"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CollectorError(f"capture log contains invalid base64 for {expected_id!r}") from exc
    result: dict[str, Any] = {
        "status": match.group("status"),
        "tcl_return_code": int(match.group("rc")),
    }
    if value_bytes:
        try:
            result["value"] = value_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result["value_base64"] = base64.b64encode(value_bytes).decode("ascii")
            result["value_bytes"] = len(value_bytes)
    if error_bytes:
        try:
            result["error"] = error_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result["error_base64"] = base64.b64encode(error_bytes).decode("ascii")
    return result


class BigIPRestClient:
    """Small standard-library iControl REST client with explicit TLS policy."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        timeout: float = 20.0,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CollectorError("BIG-IP URL must include an http:// or https:// scheme")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/"):
            raise CollectorError("iControl REST paths must start with '/'")
        raw_credentials = f"{self.username}:{self.password}".encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": "Basic " + base64.b64encode(raw_credentials).decode("ascii"),
        }
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        context = None
        parsed = urlparse(self.base_url)
        if parsed.scheme == "https" and not self.verify_tls:
            context = ssl._create_unverified_context()
        try:
            with urlopen(request, timeout=self.timeout, context=context) as response:
                raw = response.read()
        except HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise CollectorError(
                f"BIG-IP REST {method} {path} returned HTTP {exc.code}: {detail}"
            ) from exc
        except (URLError, OSError) as exc:
            raise CollectorError(f"BIG-IP REST {method} {path} failed: {exc}") from exc
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectorError(f"BIG-IP REST {method} {path} returned invalid JSON") from exc

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self.request("POST", path, body)

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return self.request("PATCH", path, body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)


def _virtual_ref(value: str) -> tuple[str, str, str]:
    """Return (partition, name, REST ref) from a safe virtual identifier."""
    if value.startswith("~"):
        match = re.fullmatch(r"~([A-Za-z0-9_.-]+)~([A-Za-z0-9_.-]+)", value)
        if match is None:
            raise CollectorError("virtual must be ~partition~name or /partition/name")
        partition, name = match.groups()
    else:
        match = re.fullmatch(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", value)
        if match is None:
            raise CollectorError("virtual must be ~partition~name or /partition/name")
        partition, name = match.groups()
    return partition, name, f"~{partition}~{name}"


def _virtual_path(value: str) -> tuple[str, str]:
    partition, name, reference = _virtual_ref(value)
    encoded_reference = quote(reference, safe="~")
    return f"/mgmt/tm/ltm/virtual/{encoded_reference}", f"/{partition}/{name}"


def _request_url(base_url: str, request_data: dict[str, Any]) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CollectorError("traffic URL must include an http:// or https:// scheme")
    uri = request_data.get("uri", "/")
    if not isinstance(uri, str) or not uri.startswith("/") or "\x00" in uri:
        raise CollectorError("plan HTTP request uri must be an absolute path")
    return urlunparse((parsed.scheme, parsed.netloc, uri, "", "", ""))


@dataclass
class CollectionResult:
    records: list[dict[str, Any]]
    skipped: list[dict[str, str]]


class PlanCollector:
    """Execute supported plan cases while restoring the selected virtual."""

    def __init__(
        self,
        client: BigIPRestClient,
        virtual: str,
        traffic_url: str,
        *,
        trigger_command: str | None = None,
        trigger_timeout: float = 60.0,
        log_lines: int = 500,
        log_timeout: float = 5.0,
        settle_seconds: float = 0.2,
    ) -> None:
        if not 1 <= log_lines <= MAX_LOG_LINES:
            raise CollectorError(f"log-lines must be between 1 and {MAX_LOG_LINES}")
        if not 0 <= log_timeout <= 60:
            raise CollectorError("log-timeout must be between 0 and 60 seconds")
        if not 0 <= settle_seconds <= 10:
            raise CollectorError("settle-seconds must be between 0 and 10 seconds")
        if not 0 < trigger_timeout <= 300:
            raise CollectorError("trigger-timeout must be greater than 0 and at most 300 seconds")
        if trigger_command is not None and not trigger_command.strip():
            raise CollectorError("trigger-command must be a non-empty executable path")
        self.client = client
        self.run_id = uuid.uuid4().hex[:12]
        self.virtual_path, self.rule_ref_prefix = _virtual_path(virtual)
        self.partition = self.rule_ref_prefix.split("/", 2)[1]
        self.traffic_url = traffic_url
        self.log_lines = log_lines
        self.log_timeout = log_timeout
        self.settle_seconds = settle_seconds
        self.trigger_command = trigger_command
        self.trigger_timeout = trigger_timeout

    def _bash(self, command: str) -> str:
        result = self.client.post(
            "/mgmt/tm/util/bash",
            {"command": "run", "utilCmdArgs": "-c " + shlex.quote(command)},
        )
        if not isinstance(result, dict) or not isinstance(result.get("commandResult"), str):
            raise CollectorError("BIG-IP bash endpoint returned no commandResult")
        return result["commandResult"]

    def _read_logs(self) -> list[str]:
        output = self._bash(f"tail -n {self.log_lines} /var/log/ltm")
        return output.splitlines()

    def _send_http(self, request_data: dict[str, Any]) -> None:
        url = _request_url(self.traffic_url, request_data)
        method = request_data.get("method", "GET")
        if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
            raise CollectorError("plan HTTP request method must contain ASCII letters")
        headers = request_data.get("headers", {})
        if not isinstance(headers, dict) or any(
            not isinstance(key, str) or not isinstance(value, (str, int, float, bool))
            for key, value in headers.items()
        ):
            raise CollectorError("plan HTTP request headers must be scalar values")
        encoded_headers = {key: str(value) for key, value in headers.items()}
        body = request_data.get("body", "")
        if isinstance(body, str):
            payload = body.encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
        else:
            raise CollectorError("plan HTTP request body must be a string")
        request = Request(url, data=payload or None, headers=encoded_headers, method=method)
        try:
            with urlopen(request, timeout=20) as response:
                response.read(1024 * 1024)
        except HTTPError as exc:
            # A 4xx/5xx response still drives HTTP_REQUEST and is a valid probe.
            exc.read(1024 * 1024)
        except (URLError, OSError) as exc:
            raise CollectorError(f"traffic request failed: {exc}") from exc

    def _run_trigger(self, case: dict[str, Any]) -> None:
        if self.trigger_command is None:
            raise CollectorError(
                f"event {case['input']['event']} requires --trigger-command"
            )
        trigger_input = {
            "profile": TMOS_PROFILE,
            "case": case["id"],
            "event": case["input"]["event"],
            "command": case["input"]["command"],
            "args": case["input"]["args"],
            "profiles": case["input"]["profiles"],
            "traffic_url": self.traffic_url,
            "virtual": self.rule_ref_prefix,
        }
        if "request" in case["input"]:
            trigger_input["request"] = case["input"]["request"]
        trigger_env = os.environ.copy()
        trigger_env.pop("BIGIP_USERNAME", None)
        trigger_env.pop("BIGIP_PASSWORD", None)
        try:
            completed = subprocess.run(
                [self.trigger_command],
                input=json.dumps(
                    trigger_input, ensure_ascii=False, allow_nan=False
                ).encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.trigger_timeout,
                check=False,
                shell=False,
                env=trigger_env,
            )
        except FileNotFoundError as exc:
            raise CollectorError(
                f"trigger executable was not found: {self.trigger_command!r}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CollectorError(
                f"trigger command timed out after {self.trigger_timeout:g} seconds"
            ) from exc
        except OSError as exc:
            raise CollectorError(f"trigger command could not start: {exc}") from exc
        if completed.returncode != 0:
            raise CollectorError(
                f"trigger command failed with exit code {completed.returncode}"
            )

    def _find_log_result(self, case_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.log_timeout
        while True:
            for line in reversed(self._read_logs()):
                result = parse_capture_line(line, case_id)
                if result is not None:
                    return result
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.2, max(0.01, deadline - time.monotonic())))
        raise CollectorError(f"no structured BIG-IP log result found for {case_id!r}")

    def collect_case(self, case: dict[str, Any]) -> dict[str, Any]:
        if not case["event_supported"] and self.trigger_command is None:
            raise CollectorError(
                f"event {case['input']['event']} is not triggerable by this collector"
            )
        rule_name = f"testcl_capture_{uuid.uuid4().hex[:12]}"
        log_id = f"{case['id']}:{self.run_id}"
        rule_reference = f"~{self.partition}~{rule_name}"
        rule_path = f"/mgmt/tm/ltm/rule/{quote(rule_reference, safe='~')}"
        rule_ref = f"/{self.partition}/{rule_name}"
        original_rules: list[Any] | None = None
        created = False
        attached = False
        try:
            virtual = self.client.get(self.virtual_path)
            rules = virtual.get("rules", []) if isinstance(virtual, dict) else []
            if not isinstance(rules, list):
                raise CollectorError("BIG-IP virtual returned a non-list rules field")
            original_rules = list(rules)
            self.client.post(
                "/mgmt/tm/ltm/rule",
                {
                    "name": rule_name,
                    "partition": self.partition,
                    "apiAnonymous": render_probe_irule(case, rule_name, log_id=log_id),
                },
            )
            created = True
            self.client.patch(self.virtual_path, {"rules": original_rules + [rule_ref]})
            attached = True
            if case["input"]["event"] == "HTTP_REQUEST":
                request_data = case["input"].get("request", {})
                if not isinstance(request_data, dict):
                    raise CollectorError("HTTP command probe request must be an object")
                self._send_http(request_data)
            elif case["input"]["event"] != "RULE_INIT":
                self._run_trigger(case)
            if self.settle_seconds:
                time.sleep(self.settle_seconds)
            output = self._find_log_result(log_id)
            return {"id": case["id"], "output": output}
        finally:
            cleanup_error: Exception | None = None
            if attached and original_rules is not None:
                try:
                    self.client.patch(self.virtual_path, {"rules": original_rules})
                except Exception as exc:  # preserve the primary collection failure
                    cleanup_error = exc
            if created:
                try:
                    self.client.delete(rule_path)
                except Exception as exc:  # preserve the primary collection failure
                    cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                raise CollectorError(f"BIG-IP collector cleanup failed: {cleanup_error}")

    def collect(self, plan: dict[str, Any], *, allow_partial: bool = False) -> CollectionResult:
        validated = validate_plan(plan)
        unsupported = [
            {
                "id": case["id"],
                "event": case["input"]["event"],
            }
            for case in validated["observations"]
            if not case["event_supported"]
        ]
        if unsupported and self.trigger_command is None and not allow_partial:
            events = ", ".join(f"{row['id']}={row['event']}" for row in unsupported[:8])
            raise CollectorError(
                "plan contains events this collector cannot drive; use --allow-partial "
                f"to collect the supported subset ({events})"
            )
        records: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        unsupported_ids = (
            {row["id"] for row in unsupported}
            if self.trigger_command is None
            else set()
        )
        for case in validated["observations"]:
            if case["id"] in unsupported_ids:
                skipped.append(
                    {"id": case["id"], "reason": f"unsupported event {case['input']['event']}"}
                )
                continue
            records.append(self.collect_case(case))
        return CollectionResult(records=records, skipped=skipped)


def _print_records(records: list[dict[str, Any]]) -> None:
    for record in records:
        print(json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect TMOS 17.5 iRule observations from BIG-IP")
    parser.add_argument("--plan", required=True, help="assembly-ready command-probe plan JSON path, or -")
    parser.add_argument("--execute", action="store_true", help="perform external collection")
    parser.add_argument(
        "--allow-device-write",
        action="store_true",
        help="acknowledge temporary iRule/virtual-server mutation (required with --execute)",
    )
    parser.add_argument("--allow-partial", action="store_true", help="skip events not triggerable by this collector")
    parser.add_argument("--bigip-url", help="BIG-IP management URL, e.g. https://bigip.example")
    parser.add_argument("--virtual", help="existing virtual server as /partition/name or ~partition~name")
    parser.add_argument("--traffic-url", help="HTTP URL that reaches the selected virtual server")
    parser.add_argument(
        "--trigger-command",
        help="executable protocol driver for non-HTTP/RULE_INIT events; receives one JSON request on stdin",
    )
    parser.add_argument(
        "--trigger-timeout",
        type=float,
        default=60.0,
        help="maximum seconds allowed for one protocol-driver invocation",
    )
    parser.add_argument("--insecure", action="store_true", help="disable BIG-IP TLS certificate verification")
    parser.add_argument("--log-lines", type=int, default=500, help="number of /var/log/ltm lines to inspect")
    parser.add_argument("--log-timeout", type=float, default=5.0, help="seconds to wait for a structured log result")
    parser.add_argument("--settle-seconds", type=float, default=0.2, help="seconds to wait after traffic before log polling")
    args = parser.parse_args(argv)
    try:
        if args.trigger_command is not None and not args.trigger_command.strip():
            raise CollectorError("trigger-command must be a non-empty executable path")
        if not 0 < args.trigger_timeout <= 300:
            raise CollectorError(
                "trigger-timeout must be greater than 0 and at most 300 seconds"
            )
        plan = validate_plan(_read_json_file(args.plan))
        if not args.execute:
            unsupported = [
                {"id": case["id"], "event": case["input"]["event"]}
                for case in plan["observations"]
                if not case["event_supported"]
            ]
            print(
                json.dumps(
                    {
                        "status": "dry-run",
                        "profile": TMOS_PROFILE,
                        "case_count": len(plan["observations"]),
                        "executable_count": (
                            len(plan["observations"])
                            if args.trigger_command
                            else len(plan["observations"]) - len(unsupported)
                        ),
                        "protocol_driver": bool(args.trigger_command),
                        "unsupported": unsupported,
                        "device_mutation": False,
                    },
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
            return 0
        if not args.allow_device_write:
            raise CollectorError("--execute requires --allow-device-write")
        if not args.bigip_url or not args.virtual or not args.traffic_url:
            raise CollectorError("--execute requires --bigip-url, --virtual, and --traffic-url")
        username = os.environ.get("BIGIP_USERNAME")
        password = os.environ.get("BIGIP_PASSWORD")
        if not username or not password:
            raise CollectorError("set BIGIP_USERNAME and BIGIP_PASSWORD for --execute")
        client = BigIPRestClient(
            args.bigip_url,
            username,
            password,
            verify_tls=not args.insecure,
        )
        collector = PlanCollector(
            client,
            args.virtual,
            args.traffic_url,
            trigger_command=args.trigger_command,
            trigger_timeout=args.trigger_timeout,
            log_lines=args.log_lines,
            log_timeout=args.log_timeout,
            settle_seconds=args.settle_seconds,
        )
        result = collector.collect(plan, allow_partial=args.allow_partial)
        _print_records(result.records)
        print(
            json.dumps(
                {
                    "status": "collected",
                    "record_count": len(result.records),
                    "skipped": result.skipped,
                    "device_mutation": True,
                },
                ensure_ascii=False,
                allow_nan=False,
            ),
            file=sys.stderr,
        )
        return 0
    except CollectorError as exc:
        print(f"tmos17-collector: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
