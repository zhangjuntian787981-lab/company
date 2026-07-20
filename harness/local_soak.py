#!/usr/bin/env python3
"""Run a bounded, loopback-only CLIProxyAPI and gateway soak."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from harness import prod_guard
from harness.redaction import assert_report_files_safe, sanitize
from harness.toolchain import resolve_executable
from harness.runner import (
    FIXTURES_DIR,
    FORBIDDEN_PORT,
    REPO_ROOT,
    RUNS_DIR,
    LocalHttpClient,
    ProcessRegistry,
    claude_headers,
    claude_tool_arguments,
    isolated_environment,
    load_ndjson,
    read_sse_response,
    render_cliproxyapi_config,
    reserve_dynamic_port,
    wait_for_proxy,
    wait_for_ready,
)


DEFAULT_CANDIDATE_BINARY = REPO_ROOT / "artifacts" / "cliproxyapi-v7.2.80-candidate"
DEFAULT_GATEWAY_BINARY = REPO_ROOT / "artifacts" / "claude-budget-gateway-v7.2.80-candidate"
LSOF_BINARY = resolve_executable("COMPAT_LSOF_BINARY", None, "lsof")
PS_BINARY = resolve_executable("COMPAT_PS_BINARY", None, "ps")
MINIMUM_FORMAL_DURATION_SECONDS = 7200.0
REQUIRED_CONCURRENCY_LEVELS = {1, 4, 16}
MANIFEST_PATH = REPO_ROOT / "patches" / "v7.2.80" / "manifest.json"
SOAK_KINDS = ("json", "sse", "tool", "http_500", "http_429", "disconnect")
SCENARIO_BY_KIND = {
    "json": "text_stream",
    "sse": "text_stream",
    "tool": "parallel_interleaved_tools_dynamic",
    "http_500": "http_500",
    "http_429": "http_429",
    "disconnect": "disconnect",
}
MODEL_BY_KIND = {
    "json": "compat-text",
    "sse": "compat-text-stream",
    "tool": "compat-parallel-tools-dynamic",
    "http_500": "compat-http-500",
    "http_429": "compat-http-429",
    "disconnect": "compat-disconnect",
}
STREAMING_KINDS = {"sse", "tool", "disconnect"}
TOOL_DEFINITIONS = [
    {
        "name": "compat.echo",
        "description": "Return a synthetic value",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    },
    {
        "name": "compat.add",
        "description": "Return synthetic numbers",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "n": {"type": "integer"},
            },
            "required": ["value", "n"],
        },
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_concurrency_levels(raw: str) -> Tuple[int, ...]:
    try:
        levels = tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as exc:
        raise ValueError("concurrency levels must be comma-separated positive integers") from exc
    if not levels or any(level <= 0 for level in levels):
        raise ValueError("concurrency levels must be comma-separated positive integers")
    if len(set(levels)) != len(levels):
        raise ValueError("concurrency levels must not repeat")
    return levels


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_set_sha256(patches: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for patch in patches:
        digest.update(str(patch["id"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_identity(candidate_binary: Path, gateway_binary: Path) -> Dict[str, str]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {
        "source_commit": str(manifest["source_commit"]),
        "patch_set_sha256": patch_set_sha256(manifest["patches"]),
        "candidate_binary_sha256": sha256_file(candidate_binary),
        "gateway_binary_sha256": sha256_file(gateway_binary),
    }


def directory_size(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        try:
            if child.is_file():
                total += child.stat().st_size
        except FileNotFoundError:
            continue
    return total


def soak_environment(run_dir: Path) -> Dict[str, str]:
    isolated = isolated_environment(run_dir)
    allowed = {
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "TMPDIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "PYTHONPATH",
        "CLIPROXYAPI_COMPAT_TEST",
        "COMPAT_NETWORK_POLICY",
    }
    env = {key: value for key, value in isolated.items() if key in allowed}
    env.update(
        {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": os.environ.get("LANG", "C"),
            "LC_ALL": "C",
        }
    )
    return env


def stop_process(process: subprocess.Popen[Any], timeout: float = 3.0) -> bool:
    if process.poll() is not None:
        return True
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        return False
    return True


def process_resources(pid: int) -> Dict[str, Any]:
    if pid <= 0:
        raise ValueError("process id must be positive")
    fd_result = subprocess.run(
        [str(LSOF_BINARY), "-p", str(pid)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
    )
    if fd_result.returncode != 0:
        raise RuntimeError("lsof could not inspect process %d" % pid)
    file_descriptors = max(0, len(fd_result.stdout.splitlines()) - 1)
    rss_result = subprocess.run(
        [str(PS_BINARY), "-o", "rss=", "-p", str(pid)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
    )
    if rss_result.returncode != 0 or not rss_result.stdout.strip():
        raise RuntimeError("ps could not inspect process %d" % pid)
    return {
        "pid": pid,
        "alive": True,
        "file_descriptors": file_descriptors,
        "rss_kib": int(rss_result.stdout.strip()),
    }


def parse_goroutine_count(profile: str) -> int:
    match = re.search(r"^goroutine profile: total (\d+)$", profile, re.MULTILINE)
    if match is None:
        raise ValueError("pprof goroutine total was unavailable")
    return int(match.group(1))


def candidate_resources(pprof_base_url: str, pid: int) -> Dict[str, Any]:
    client = LocalHttpClient()
    with client.open(pprof_base_url + "/debug/pprof/goroutine?debug=1", timeout=3.0) as response:
        profile = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    sample = process_resources(pid)
    sample["goroutines"] = parse_goroutine_count(profile)
    return sample


def resource_pair_is_bounded(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    return (
        bool(before.get("alive"))
        and bool(after.get("alive"))
        and int(after["file_descriptors"]) <= int(before["file_descriptors"]) + 2
        and (
            "goroutines" not in before
            or int(after["goroutines"]) <= int(before["goroutines"]) + 2
        )
    )


def render_soak_config(
    run_dir: Path,
    listen_port: int,
    mock_base_url: str,
    pprof_port: int,
) -> Path:
    config_path = render_cliproxyapi_config(
        run_dir,
        listen_port,
        mock_base_url,
        request_retry=0,
        instance_name="soak",
    )
    with config_path.open("a", encoding="utf-8") as handle:
        handle.write("\npprof:\n  enable: true\n  addr: 127.0.0.1:%d\n" % pprof_port)
    os.chmod(config_path, 0o600)
    return config_path


def start_candidate(
    run_dir: Path,
    env: Mapping[str, str],
    registry: ProcessRegistry,
    mock_base_url: str,
    binary: Path,
) -> Tuple[str, str, subprocess.Popen[Any]]:
    listen_port = reserve_dynamic_port()
    pprof_port = reserve_dynamic_port()
    while pprof_port == listen_port:
        pprof_port = reserve_dynamic_port()
    config_path = render_soak_config(run_dir, listen_port, mock_base_url, pprof_port)
    process = registry.start(
        [str(binary), "-config", str(config_path), "-local-model"],
        env,
        run_dir / "sandbox",
    )
    base_url = "http://127.0.0.1:%d" % listen_port
    wait_for_proxy(LocalHttpClient(), base_url, process)
    return base_url, "http://127.0.0.1:%d" % pprof_port, process


def start_gateway(
    run_dir: Path,
    env: Mapping[str, str],
    registry: ProcessRegistry,
    candidate_base_url: str,
    binary: Path,
    phase: str,
    worker: int,
) -> Tuple[str, subprocess.Popen[Any]]:
    ready_file = run_dir / "sandbox" / ("gateway-%s-%d-ready.json" % (phase, worker))
    process = registry.start(
        [
            str(binary),
            "--target",
            candidate_base_url,
            "--listen",
            "127.0.0.1:0",
            "--ready-file",
            str(ready_file),
        ],
        env,
        REPO_ROOT,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("gateway exited before readiness")
        if ready_file.is_file():
            payload = json.loads(ready_file.read_text(encoding="utf-8"))
            base_url = str(payload.get("base_url") or "")
            LocalHttpClient.validate_url(base_url)
            return base_url, process
        time.sleep(0.02)
    raise TimeoutError("gateway did not become ready")


def build_payload(kind: str, operation_id: str) -> Dict[str, Any]:
    if kind not in SOAK_KINDS:
        raise ValueError("unknown soak operation: %s" % kind)
    payload: Dict[str, Any] = {
        "model": MODEL_BY_KIND[kind],
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "local soak " + operation_id}],
        "stream": kind in STREAMING_KINDS,
    }
    if kind == "tool":
        payload["tools"] = TOOL_DEFINITIONS
    return payload


def message_request(
    client: LocalHttpClient,
    base_url: str,
    payload: Mapping[str, Any],
) -> Tuple[int, Any]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    is_stream = payload.get("stream") is True
    try:
        with client.open(
            base_url + "/v1/messages",
            "POST",
            body,
            claude_headers(),
            timeout=8.0,
        ) as response:
            if is_stream:
                return int(response.status), read_sse_response(response)
            raw = response.read()
            return int(response.status), json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code), [] if is_stream else {}


def tool_start_ids(events: Sequence[Mapping[str, Any]]) -> List[str]:
    ids: List[str] = []
    for event in events:
        data = event.get("data", {})
        if not isinstance(data, dict) or data.get("type") != "content_block_start":
            continue
        block = data.get("content_block", {})
        if isinstance(block, dict) and block.get("type") == "tool_use":
            ids.append(str(block.get("id") or ""))
    return ids


def validate_first_response(kind: str, status: int, value: Any) -> List[str]:
    if kind == "json":
        if status != 200 or not isinstance(value, dict):
            raise AssertionError("JSON response status or shape was invalid")
        content = value.get("content")
        if not isinstance(content, list) or not content or content[0].get("type") != "text":
            raise AssertionError("JSON response omitted text content")
        return []
    if kind == "sse":
        if status != 200 or not isinstance(value, list):
            raise AssertionError("SSE response status or shape was invalid")
        if [event.get("event") for event in value].count("message_stop") != 1:
            raise AssertionError("SSE response did not contain exactly one terminal event")
        return []
    if kind == "tool":
        if status != 200 or not isinstance(value, list):
            raise AssertionError("tool response status or shape was invalid")
        ids = tool_start_ids(value)
        arguments = claude_tool_arguments(value)
        if len(ids) != 2 or len(set(ids)) != 2 or set(ids) != set(arguments):
            raise AssertionError("parallel tool IDs or arguments were not isolated")
        for argument in arguments.values():
            json.loads(argument)
        return ids
    if kind in {"http_500", "http_429"}:
        if status != 424:
            raise AssertionError("retryable upstream error was not bounded as HTTP 424")
        return []
    if kind == "disconnect":
        if status != 200 or not isinstance(value, list):
            raise AssertionError("disconnect owner response status or shape was invalid")
        if any(event.get("event") == "message_stop" for event in value):
            raise AssertionError("incomplete stream was reported as terminal success")
        return []
    raise ValueError("unknown soak operation: %s" % kind)


def validate_replay_response(kind: str, status: int, value: Any) -> List[str]:
    if kind in {"tool", "http_500", "http_429", "disconnect"}:
        if status != 424:
            raise AssertionError("non-replayable or failed request was not held at HTTP 424")
        return tool_start_ids(value) if isinstance(value, list) else []
    return validate_first_response(kind, status, value)


def execute_pair(client: LocalHttpClient, base_url: str, kind: str, operation_id: str) -> Dict[str, Any]:
    payload = build_payload(kind, operation_id)
    first_status, first_value = message_request(client, base_url, payload)
    tool_ids = validate_first_response(kind, first_status, first_value)
    replay_status, replay_value = message_request(client, base_url, payload)
    replay_tool_ids = validate_replay_response(kind, replay_status, replay_value)
    return {
        "kind": kind,
        "scenario": SCENARIO_BY_KIND[kind],
        "statuses": [first_status, replay_status],
        "tool_ids": tool_ids,
        "replay_tool_ids": replay_tool_ids,
    }


class SoakCounters:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.operations = 0
        self.failures = 0
        self.operations_by_kind: Counter[str] = Counter()
        self.operations_by_phase: Counter[str] = Counter()
        self.expected_upstream: Counter[str] = Counter()
        self.statuses: Counter[str] = Counter()
        self.tool_ids: set[str] = set()
        self.duplicate_tools = 0
        self.replay_tool_emissions = 0
        self.failure_examples: List[Dict[str, str]] = []

    def record(self, phase: str, kind: str, result: Optional[Mapping[str, Any]], error: Optional[Exception]) -> None:
        with self.lock:
            self.operations += 1
            self.operations_by_kind[kind] += 1
            self.operations_by_phase[phase] += 1
            self.expected_upstream[SCENARIO_BY_KIND[kind]] += 1
            if error is not None or result is None:
                self.failures += 1
                if len(self.failure_examples) < 10:
                    self.failure_examples.append(
                        {
                            "phase": phase,
                            "kind": kind,
                            "error_type": type(error).__name__ if error is not None else "UnknownError",
                            "message": str(error)[:200] if error is not None else "operation returned no result",
                        }
                    )
                return
            for status in result.get("statuses", []):
                self.statuses[str(status)] += 1
            current_ids = [str(item) for item in result.get("tool_ids", [])]
            if len(current_ids) != len(set(current_ids)):
                self.duplicate_tools += 1
            for tool_id in current_ids:
                if tool_id in self.tool_ids:
                    self.duplicate_tools += 1
                self.tool_ids.add(tool_id)
            self.replay_tool_emissions += len(result.get("replay_tool_ids", []))


def run_operation(
    counters: SoakCounters,
    phase: str,
    worker: int,
    sequence: int,
    client: LocalHttpClient,
    base_url: str,
    kind: str,
    run_nonce: str,
) -> None:
    operation_id = "%s-%s-w%d-n%d" % (run_nonce, phase, worker, sequence)
    try:
        result = execute_pair(client, base_url, kind, operation_id)
    except Exception as exc:
        counters.record(phase, kind, None, exc)
    else:
        counters.record(phase, kind, result, None)


def run_worker(
    counters: SoakCounters,
    phase: str,
    worker: int,
    base_url: str,
    deadline: float,
    operation_interval: float,
    stop_event: threading.Event,
    run_nonce: str,
) -> None:
    client = LocalHttpClient()
    sequence = len(SOAK_KINDS)
    next_operation = time.monotonic()
    while time.monotonic() < deadline and not stop_event.is_set():
        kind = SOAK_KINDS[(worker + sequence) % len(SOAK_KINDS)]
        run_operation(counters, phase, worker, sequence, client, base_url, kind, run_nonce)
        sequence += 1
        next_operation += operation_interval
        stop_event.wait(max(0.0, min(next_operation, deadline) - time.monotonic()))


def run_phase(
    run_dir: Path,
    env: Mapping[str, str],
    registry: ProcessRegistry,
    gateway_binary: Path,
    candidate_base_url: str,
    pprof_base_url: str,
    candidate_process: subprocess.Popen[Any],
    concurrency: int,
    duration_seconds: float,
    operation_interval: float,
    counters: SoakCounters,
    stop_event: threading.Event,
    run_nonce: str,
) -> Dict[str, Any]:
    phase = "concurrency-%d" % concurrency
    gateways = [
        start_gateway(
            run_dir,
            env,
            registry,
            candidate_base_url,
            gateway_binary,
            phase,
            worker,
        )
        for worker in range(concurrency)
    ]

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        warmups = []
        for worker, (base_url, _) in enumerate(gateways):
            client = LocalHttpClient()

            def warm(worker_id: int = worker, worker_client: LocalHttpClient = client, url: str = base_url) -> None:
                for sequence, kind in enumerate(SOAK_KINDS):
                    run_operation(
                        counters,
                        phase,
                        worker_id,
                        sequence,
                        worker_client,
                        url,
                        kind,
                        run_nonce,
                    )

            warmups.append(executor.submit(warm))
        for future in warmups:
            future.result()

    time.sleep(0.2)
    candidate_before = candidate_resources(pprof_base_url, candidate_process.pid)
    gateway_before = [process_resources(process.pid) for _, process in gateways]
    started = time.monotonic()
    deadline = started + duration_seconds
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        workers = [
            executor.submit(
                run_worker,
                counters,
                phase,
                worker,
                base_url,
                deadline,
                operation_interval,
                stop_event,
                run_nonce,
            )
            for worker, (base_url, _) in enumerate(gateways)
        ]
        for future in workers:
            future.result()
    elapsed = time.monotonic() - started
    time.sleep(0.5)
    gateway_after = [process_resources(process.pid) for _, process in gateways]
    gateways_stopped = all(stop_process(process) for _, process in gateways)
    time.sleep(0.5)
    candidate_after = candidate_resources(pprof_base_url, candidate_process.pid)
    resource_bounded = resource_pair_is_bounded(candidate_before, candidate_after) and all(
        resource_pair_is_bounded(before, after)
        for before, after in zip(gateway_before, gateway_after)
    )
    return {
        "concurrency": concurrency,
        "requested_duration_seconds": duration_seconds,
        "elapsed_seconds": round(elapsed, 6),
        "duration_completed": elapsed + 0.01 >= duration_seconds and not stop_event.is_set(),
        "resource_bounded": resource_bounded,
        "gateways_stopped": gateways_stopped,
        "candidate_resources": {"before": candidate_before, "after": candidate_after},
        "gateway_resources": [
            {"before": before, "after": after}
            for before, after in zip(gateway_before, gateway_after)
        ],
    }


def observed_scenario_counts(evidence_path: Path) -> Counter[str]:
    observed: Counter[str] = Counter()
    for record in load_ndjson(evidence_path):
        scenario = str(record.get("scenario") or "")
        if record.get("kind") == "mock_request" and scenario in SCENARIO_BY_KIND.values():
            observed[scenario] += 1
    return observed


def build_checks(
    counters: SoakCounters,
    phases: Sequence[Mapping[str, Any]],
    observed: Mapping[str, int],
    processes_stopped: bool,
    production_untouched: bool,
    duration_completed: bool,
    minimum_duration_met: bool,
    required_concurrency_covered: bool,
    artifact_bytes: int,
    max_artifact_bytes: int,
) -> Dict[str, bool]:
    expected = dict(counters.expected_upstream)
    return {
        "zero_duplicate_tools": counters.duplicate_tools == 0 and counters.replay_tool_emissions == 0,
        "zero_budget_overruns": all(int(observed.get(key, 0)) <= value for key, value in expected.items()),
        "zero_resource_leaks": (
            processes_stopped
            and all(bool(phase.get("resource_bounded")) for phase in phases)
            and all(bool(phase.get("gateways_stopped")) for phase in phases)
        ),
        "bounded_artifact_growth": artifact_bytes <= max_artifact_bytes,
        "expected_upstream_attempts": all(
            int(observed.get(key, 0)) == value for key, value in expected.items()
        ),
        "operation_matrix_passed": (
            counters.failures == 0
            and all(counters.operations_by_kind.get(kind, 0) > 0 for kind in SOAK_KINDS)
        ),
        "duration_completed": duration_completed,
        "minimum_duration_met": minimum_duration_met,
        "required_concurrency_covered": required_concurrency_covered,
        "production_untouched": production_untouched,
        "loopback_only": True,
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    safe = sanitize(dict(report))
    path.write_text(json.dumps(safe, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def run(
    candidate_binary: Path,
    gateway_binary: Path,
    duration_seconds: float,
    concurrency_levels: Sequence[int],
    operation_interval: float,
    max_artifact_bytes: int,
    skip_prod_guard: bool = False,
) -> Tuple[Path, Dict[str, Any]]:
    if duration_seconds <= 0:
        raise ValueError("duration must be positive")
    if operation_interval <= 0:
        raise ValueError("operation interval must be positive")
    if max_artifact_bytes <= 0:
        raise ValueError("artifact byte limit must be positive")
    if not concurrency_levels or any(level <= 0 for level in concurrency_levels):
        raise ValueError("at least one positive concurrency level is required")
    if not candidate_binary.is_file() or not gateway_binary.is_file():
        raise FileNotFoundError("candidate and gateway binaries are required")

    old_umask = os.umask(0o077)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = "soak-local-%s-%s" % (stamp, secrets.token_hex(4))
    run_nonce = secrets.token_hex(8)
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    report_path = run_dir / "soak.json"
    mock_evidence_path = run_dir / "mock-evidence.ndjson"
    env = soak_environment(run_dir)
    registry = ProcessRegistry()
    counters = SoakCounters()
    phases: List[Dict[str, Any]] = []
    fatal_errors: List[Dict[str, str]] = []
    stop_event = threading.Event()
    monitor_stop = threading.Event()
    artifact_state = {"peak_bytes": 0, "limit_exceeded": False}
    artifact_lock = threading.Lock()
    production_before: Optional[Dict[str, Any]] = None
    production_untouched = not skip_prod_guard
    identity = load_identity(candidate_binary, gateway_binary)
    started_at = time.monotonic()

    def monitor_artifacts() -> None:
        while not monitor_stop.is_set():
            size = directory_size(run_dir)
            with artifact_lock:
                artifact_state["peak_bytes"] = max(artifact_state["peak_bytes"], size)
                if size > max_artifact_bytes:
                    artifact_state["limit_exceeded"] = True
                    stop_event.set()
            monitor_stop.wait(1.0)

    monitor = threading.Thread(target=monitor_artifacts, daemon=True)
    monitor.start()
    try:
        if not skip_prod_guard:
            baseline = prod_guard.load_baseline()
            production_before = prod_guard.snapshot(baseline)
            differences = prod_guard.compare_known(baseline, production_before)
            if differences:
                production_untouched = False
                raise RuntimeError("production baseline mismatch blocked local soak start")

        ready_path = run_dir / "sandbox" / "mock-ready.json"
        mock_process = registry.start(
            [
                sys.executable,
                "-m",
                "harness.mock_codex_mitm",
                "--fixtures",
                str(FIXTURES_DIR),
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--evidence",
                str(mock_evidence_path),
                "--ready-file",
                str(ready_path),
            ],
            env,
            REPO_ROOT,
        )
        ready = wait_for_ready(ready_path, mock_process)
        mock_port = int(ready["port"])
        if mock_port == FORBIDDEN_PORT:
            raise RuntimeError("mock selected forbidden production port")
        mock_base_url = "http://127.0.0.1:%d" % mock_port
        candidate_base_url, pprof_base_url, candidate_process = start_candidate(
            run_dir,
            env,
            registry,
            mock_base_url,
            candidate_binary,
        )
        per_phase_duration = duration_seconds / len(concurrency_levels)
        for concurrency in concurrency_levels:
            if stop_event.is_set():
                break
            phases.append(
                run_phase(
                    run_dir,
                    env,
                    registry,
                    gateway_binary,
                    candidate_base_url,
                    pprof_base_url,
                    candidate_process,
                    concurrency,
                    per_phase_duration,
                    operation_interval,
                    counters,
                    stop_event,
                    run_nonce,
                )
            )
    except KeyboardInterrupt:
        fatal_errors.append({"error_type": "KeyboardInterrupt", "message": "local soak interrupted"})
        stop_event.set()
    except Exception as exc:
        fatal_errors.append({"error_type": type(exc).__name__, "message": str(exc)[:200]})
        stop_event.set()
    finally:
        monitor_stop.set()
        monitor.join(timeout=2.0)
        registry.cleanup()
        processes_stopped = registry.all_stopped()
        if not skip_prod_guard and production_before is not None:
            baseline = prod_guard.load_baseline()
            production_after = prod_guard.snapshot(baseline)
            production_untouched = not prod_guard.compare_snapshots(
                production_before,
                production_after,
            )
        shutil.rmtree(run_dir / "sandbox", ignore_errors=True)
        os.umask(old_umask)

    observed = observed_scenario_counts(mock_evidence_path)
    completed_levels = {int(phase["concurrency"]) for phase in phases}
    duration_completed = (
        not fatal_errors
        and not artifact_state["limit_exceeded"]
        and completed_levels == set(concurrency_levels)
        and all(bool(phase.get("duration_completed")) for phase in phases)
    )
    artifact_bytes = max(directory_size(run_dir), int(artifact_state["peak_bytes"]))
    checks = build_checks(
        counters,
        phases,
        observed,
        processes_stopped,
        production_untouched,
        duration_completed,
        duration_seconds >= MINIMUM_FORMAL_DURATION_SECONDS,
        REQUIRED_CONCURRENCY_LEVELS.issubset(completed_levels),
        artifact_bytes,
        max_artifact_bytes,
    )
    overall = "PASS" if not fatal_errors and all(checks.values()) else "FAIL"
    report: Dict[str, Any] = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "overall": overall,
        **identity,
        "configuration": {
            "duration_seconds": duration_seconds,
            "minimum_formal_duration_seconds": MINIMUM_FORMAL_DURATION_SECONDS,
            "concurrency_levels": list(concurrency_levels),
            "required_concurrency_levels": sorted(REQUIRED_CONCURRENCY_LEVELS),
            "operation_interval_seconds": operation_interval,
            "max_artifact_bytes": max_artifact_bytes,
        },
        "checks": checks,
        "metrics": {
            "elapsed_seconds": round(time.monotonic() - started_at, 6),
            "operations": counters.operations,
            "operation_failures": counters.failures,
            "operations_by_kind": dict(sorted(counters.operations_by_kind.items())),
            "operations_by_phase": dict(sorted(counters.operations_by_phase.items())),
            "expected_upstream_attempts": dict(sorted(counters.expected_upstream.items())),
            "observed_upstream_attempts": dict(sorted(observed.items())),
            "statuses": dict(sorted(counters.statuses.items())),
            "unique_tool_ids": len(counters.tool_ids),
            "duplicate_tool_events": counters.duplicate_tools,
            "replay_tool_emissions": counters.replay_tool_emissions,
            "artifact_bytes": artifact_bytes,
            "artifact_peak_bytes": int(artifact_state["peak_bytes"]),
        },
        "phases": phases,
        "failure_examples": counters.failure_examples,
        "fatal_errors": fatal_errors,
        "isolation": {
            "network": "loopback-only; external proxies fail closed; port 8317 denied",
            "synthetic_credentials_only": True,
            "temporary_home": True,
            "temporary_config": True,
            "launchd_used": False,
            "production_guard_enabled": not skip_prod_guard,
        },
    }
    write_report(report_path, report)
    final_artifact_bytes = max(directory_size(run_dir), int(artifact_state["peak_bytes"]))
    if final_artifact_bytes > max_artifact_bytes:
        report["checks"]["bounded_artifact_growth"] = False
        report["metrics"]["artifact_bytes"] = final_artifact_bytes
        report["overall"] = "FAIL"
        write_report(report_path, report)
    assert_report_files_safe([report_path, mock_evidence_path])
    return run_dir, report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-binary", type=Path, default=DEFAULT_CANDIDATE_BINARY)
    parser.add_argument("--gateway-binary", type=Path, default=DEFAULT_GATEWAY_BINARY)
    parser.add_argument("--duration-seconds", type=float, default=7200.0)
    parser.add_argument("--concurrency-levels", default="1,4,16")
    parser.add_argument("--operation-interval-seconds", type=float, default=1.0)
    parser.add_argument("--max-artifact-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument(
        "--skip-prod-guard",
        action="store_true",
        help="developer smoke-only escape hatch; resulting evidence cannot pass",
    )
    args = parser.parse_args(argv)
    levels = parse_concurrency_levels(args.concurrency_levels)
    run_dir, report = run(
        args.candidate_binary.resolve(),
        args.gateway_binary.resolve(),
        args.duration_seconds,
        levels,
        args.operation_interval_seconds,
        args.max_artifact_bytes,
        skip_prod_guard=args.skip_prod_guard,
    )
    print(json.dumps({"run_dir": str(run_dir), "overall": report["overall"]}, sort_keys=True))
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
