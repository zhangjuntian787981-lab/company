#!/usr/bin/env python3
"""Run the default isolated, loopback-only compatibility self-check."""

import argparse
import atexit
import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from harness import prod_guard
from harness.redaction import DEFAULT_CANARIES, assert_report_files_safe
from harness.report import REPORT_FILES, build_environment, generate_report
from harness.toolchain import resolve_executable

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "fixtures" / "scenarios"
RUNS_DIR = REPO_ROOT / ".runs"
CONFIG_TEMPLATE = REPO_ROOT / "config" / "cliproxyapi.test.yaml.tmpl"
CLIPROXYAPI_BINARY = resolve_executable("COMPAT_CLIPROXYAPI_BINARY", None, "cliproxyapi")
CANDIDATE_GATEWAY_BINARY = REPO_ROOT / "artifacts" / "claude-budget-gateway-v7.2.80-candidate"
FORBIDDEN_PORT = 8317
CLAUDE_CLI_USER_AGENT = "claude-cli/2.1.215"
CLAUDE_MODEL_ALIASES = (
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-fable-5",
)


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


def candidate_identity(candidate_binary: Path, gateway_binary: Path) -> Dict[str, str]:
    manifest = json.loads(
        (REPO_ROOT / "patches" / "v7.2.80" / "manifest.json").read_text(encoding="utf-8")
    )
    return {
        "source_commit": str(manifest["source_commit"]),
        "patch_set_sha256": patch_set_sha256(manifest["patches"]),
        "candidate_binary_sha256": sha256_file(candidate_binary),
        "gateway_binary_sha256": sha256_file(gateway_binary),
    }


class ProcessRegistry:
    """Track subprocess groups and guarantee bounded cleanup."""

    def __init__(self) -> None:
        self.processes: List[subprocess.Popen] = []
        self.closed = False
        atexit.register(self.cleanup)

    def start(self, argv: Sequence[str], env: Mapping[str, str], cwd: Path) -> subprocess.Popen:
        process = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.processes.append(process)
        return process

    def cleanup(self) -> None:
        if self.closed:
            return
        self.closed = True
        for process in reversed(self.processes):
            if process.poll() is not None:
                continue
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
        deadline = time.monotonic() + 3.0
        for process in reversed(self.processes):
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2.0)

    def all_stopped(self) -> bool:
        return all(process.poll() is not None for process in self.processes)


class LocalHttpClient:
    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @staticmethod
    def validate_url(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "http":
            raise ValueError("only local plain HTTP is allowed")
        if parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("real network access is forbidden")
        port = parsed.port or 80
        if port == FORBIDDEN_PORT:
            raise ValueError("production port 8317 is forbidden")

    def open(
        self,
        url: str,
        method: str = "GET",
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 2.0,
    ) -> Any:
        self.validate_url(url)
        request = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        return self.opener.open(request, timeout=timeout)


def make_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "%s-%s" % (stamp, secrets.token_hex(4))


def isolated_environment(run_dir: Path) -> Dict[str, str]:
    sandbox = run_dir / "sandbox"
    paths = {
        "HOME": sandbox / "home",
        "XDG_CONFIG_HOME": sandbox / "xdg-config",
        "XDG_CACHE_HOME": sandbox / "xdg-cache",
        "XDG_DATA_HOME": sandbox / "xdg-data",
        "TMPDIR": sandbox / "tmp",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(str(path), 0o700)
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}
    }
    env.update({key: str(value) for key, value in paths.items()})
    env.update(
        {
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "all_proxy": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONPATH": str(REPO_ROOT),
            "CLIPROXYAPI_COMPAT_TEST": "1",
            "COMPAT_NETWORK_POLICY": "loopback-only-port-8317-denied",
        }
    )
    return env


def reserve_dynamic_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.bind(("127.0.0.1", 0))
        port = int(handle.getsockname()[1])
    if port == FORBIDDEN_PORT:
        return reserve_dynamic_port()
    return port


def render_cliproxyapi_config(
    run_dir: Path,
    listen_port: int,
    mock_base_url: str,
    request_retry: int = 0,
    instance_name: str = "primary",
) -> Path:
    auth_dir = run_dir / "sandbox" / ("cliproxy-auth-" + instance_name)
    auth_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    template = CONFIG_TEMPLATE.read_text(encoding="utf-8")
    rendered = (
        template.replace("{{LISTEN_PORT}}", str(listen_port))
        .replace("{{AUTH_DIR}}", json.dumps(str(auth_dir)))
        .replace("{{MOCK_BASE_URL}}", mock_base_url)
        .replace("{{REQUEST_RETRY}}", str(request_retry))
        .replace("{{MAX_RETRY_INTERVAL}}", "2" if request_retry > 0 else "0")
        .replace("{{DISABLE_COOLING}}", "false" if request_retry > 0 else "true")
    )
    if "{{" in rendered or "}}" in rendered:
        raise ValueError("unresolved isolated config placeholder")
    config_path = run_dir / "sandbox" / ("cliproxyapi.%s.test.yaml" % instance_name)
    config_path.write_text(rendered, encoding="utf-8")
    os.chmod(str(config_path), 0o600)
    return config_path


def wait_for_ready(path: Path, process: subprocess.Popen, timeout: float = 5.0) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        if process.poll() is not None:
            raise RuntimeError("mock process exited before becoming ready")
        time.sleep(0.05)
    raise TimeoutError("mock process did not become ready")


def json_request(
    client: LocalHttpClient,
    url: str,
    scenario: str,
    payload: Mapping[str, Any],
    timeout: float = 2.0,
    extra_headers: Optional[Mapping[str, str]] = None,
) -> Tuple[int, Dict[str, Any]]:
    headers = {"Content-Type": "application/json", "X-Compat-Scenario": scenario}
    headers.update(dict(extra_headers or {}))
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with client.open(url, "POST", body, headers, timeout) as response:
        return int(response.status), json.loads(response.read().decode("utf-8"))


def read_sse_response(response: Any) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    event_name: Optional[str] = None
    data_lines: List[str] = []
    while True:
        line = response.readline()
        if not line:
            break
        decoded = line.decode("utf-8", errors="strict").rstrip("\r\n")
        if not decoded:
            if data_lines:
                data_text = "\n".join(data_lines)
                try:
                    data: Any = json.loads(data_text)
                except json.JSONDecodeError:
                    data = {"json_valid": False, "data_bytes": len(data_text.encode("utf-8"))}
                events.append({"event": event_name or "message", "data": data})
            event_name = None
            data_lines = []
        elif decoded.startswith("event:"):
            event_name = decoded.split(":", 1)[1].strip()
        elif decoded.startswith("data:"):
            data_lines.append(decoded.split(":", 1)[1].lstrip())
    if data_lines:
        events.append({"event": event_name or "message", "data": {"json_valid": False}})
    return events


def sse_request(
    client: LocalHttpClient,
    url: str,
    scenario: str,
    timeout: float = 2.0,
) -> List[Dict[str, Any]]:
    payload = json.dumps({"model": "compat-model", "stream": True}).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-Compat-Scenario": scenario}
    with client.open(url, "POST", payload, headers, timeout) as response:
        return read_sse_response(response)


def _terminal_types(events: Sequence[Mapping[str, Any]]) -> List[str]:
    terminal = {"response.completed", "response.incomplete", "response.failed"}
    return [str(event.get("event")) for event in events if event.get("event") in terminal]


def _tool_arguments(events: Sequence[Mapping[str, Any]]) -> Dict[str, str]:
    arguments: Dict[str, str] = {}
    for event in events:
        if event.get("event") != "response.function_call_arguments.delta":
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        call_id = str(data.get("call_id") or data.get("item_id") or "")
        if not call_id:
            raise AssertionError("tool delta missing call identifier")
        arguments[call_id] = arguments.get(call_id, "") + str(data.get("delta", ""))
    return arguments


def wait_for_proxy(client: LocalHttpClient, base_url: str, process: subprocess.Popen, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    headers = {"Authorization": "Bearer compat-synthetic-client-key"}
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("CLIProxyAPI exited before readiness")
        try:
            with client.open(base_url + "/v1/models", headers=headers, timeout=0.4) as response:
                response.read()
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            pass
        time.sleep(0.05)
    raise TimeoutError("CLIProxyAPI did not become ready")


def start_bottle_proxy(
    run_dir: Path,
    env: Mapping[str, str],
    registry: ProcessRegistry,
    mock_base_url: str,
    request_retry: int = 0,
    instance_name: str = "primary",
    binary: Path = CLIPROXYAPI_BINARY,
) -> Tuple[str, int]:
    if not binary.is_file():
        raise FileNotFoundError(str(binary))
    listen_port = reserve_dynamic_port()
    config_path = render_cliproxyapi_config(
        run_dir,
        listen_port,
        mock_base_url,
        request_retry=request_retry,
        instance_name=instance_name,
    )
    process = registry.start(
        [str(binary), "-config", str(config_path), "-local-model"],
        env,
        REPO_ROOT,
    )
    base_url = "http://127.0.0.1:%d" % listen_port
    wait_for_proxy(LocalHttpClient(), base_url, process)
    return base_url, listen_port


def request_json_allow_error(
    client: LocalHttpClient,
    url: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout: float = 5.0,
) -> Tuple[int, Dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        with client.open(url, "POST", body, headers, timeout=timeout) as response:
            raw = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}


def claude_headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Api-Key": "compat-synthetic-client-key",
        "Anthropic-Version": "2023-06-01",
        "User-Agent": CLAUDE_CLI_USER_AGENT,
    }


def claude_payload(
    model: str,
    stream: bool = False,
    tools: Optional[Sequence[Mapping[str, Any]]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "model": model,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "synthetic bottle request"}],
        "stream": stream,
    }
    if tools is not None:
        payload["tools"] = list(tools)
    payload.update(dict(extra or {}))
    return payload


def claude_json_request(
    client: LocalHttpClient,
    base_url: str,
    model: str,
    timeout: float = 5.0,
    tools: Optional[Sequence[Mapping[str, Any]]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Tuple[int, Dict[str, Any]]:
    return request_json_allow_error(
        client,
        base_url + "/v1/messages",
        claude_payload(model, tools=tools, extra=extra),
        claude_headers(),
        timeout,
    )


def claude_sse_request(
    client: LocalHttpClient,
    base_url: str,
    model: str,
    timeout: float = 5.0,
    tools: Optional[Sequence[Mapping[str, Any]]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Tuple[int, List[Dict[str, Any]]]:
    body = json.dumps(
        claude_payload(model, stream=True, tools=tools, extra=extra),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    try:
        with client.open(base_url + "/v1/messages", "POST", body, claude_headers(), timeout) as response:
            return int(response.status), read_sse_response(response)
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code), []


def claude_tool_arguments(events: Sequence[Mapping[str, Any]]) -> Dict[str, str]:
    call_by_index: Dict[int, str] = {}
    arguments_by_index: Dict[int, str] = {}
    for event in events:
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        event_type = str(data.get("type") or event.get("event") or "")
        if event_type == "content_block_start":
            content_block = data.get("content_block", {})
            if isinstance(content_block, dict) and content_block.get("type") == "tool_use":
                call_by_index[int(data.get("index", 0))] = str(content_block.get("id") or "")
        elif event_type == "content_block_delta":
            delta = data.get("delta", {})
            if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                index = int(data.get("index", 0))
                arguments_by_index[index] = arguments_by_index.get(index, "") + str(
                    delta.get("partial_json") or ""
                )
    return {
        call_id: arguments_by_index.get(index, "")
        for index, call_id in call_by_index.items()
        if call_id
    }


def claude_stream_text(events: Sequence[Mapping[str, Any]]) -> str:
    parts: List[str] = []
    for event in events:
        data = event.get("data", {})
        if not isinstance(data, dict) or data.get("type") != "content_block_delta":
            continue
        delta = data.get("delta", {})
        if isinstance(delta, dict) and delta.get("type") == "text_delta":
            parts.append(str(delta.get("text") or ""))
    return "".join(parts)


def claude_stream_stop_reason(events: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for event in events:
        data = event.get("data", {})
        if not isinstance(data, dict) or data.get("type") != "message_delta":
            continue
        delta = data.get("delta", {})
        if isinstance(delta, dict) and isinstance(delta.get("stop_reason"), str):
            return str(delta["stop_reason"])
    return None


def scenario_records(path: Path, scenario: str) -> List[Dict[str, Any]]:
    return [
        record
        for record in load_ndjson(path)
        if record.get("kind") == "mock_request" and record.get("scenario") == scenario
    ]


def catalog_model_ids(payload: Mapping[str, Any]) -> List[str]:
    data = payload.get("data")
    if not isinstance(data, list):
        raise AssertionError("model catalog data must be a list")
    model_ids: List[str] = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise AssertionError("model catalog item must contain a string id")
        model_ids.append(str(item["id"]))
    return model_ids


def run_bottle_cases(
    run_dir: Path,
    env: Mapping[str, str],
    registry: ProcessRegistry,
    mock_base_url: str,
    mock_evidence_path: Path,
    binary: Path = CLIPROXYAPI_BINARY,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    client = LocalHttpClient()
    cases: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    primary_base_url, primary_port = start_bottle_proxy(
        run_dir,
        env,
        registry,
        mock_base_url,
        request_retry=0,
        instance_name="primary",
        binary=binary,
    )

    def add(case_id: str, dimension: str, callback: Callable[[], Mapping[str, Any]], hard: bool = False) -> None:
        case, item = case_result(case_id, dimension, callback, hard)
        cases.append(case)
        evidence.append(item)

    def direct_responses_json() -> Mapping[str, Any]:
        status, payload = request_json_allow_error(
            client,
            primary_base_url + "/v1/responses",
            {"model": "compat-text", "input": "synthetic bottle request", "stream": False},
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer compat-synthetic-client-key",
            },
        )
        assert status == 200 and payload.get("status") == "completed", (status, payload.get("status"))
        output = payload.get("output")
        assert isinstance(output, list) and output and output[0].get("type") == "message"
        return {
            "summary": "installed v7.2.80 bottle routed a Responses JSON request to loopback",
            "status_code": status,
            "proxy_port_dynamic": primary_port != FORBIDDEN_PORT,
        }

    def auth_and_catalog() -> Mapping[str, Any]:
        try:
            client.open(primary_base_url + "/v1/models", timeout=1.0)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
            exc.read()
        else:
            raise AssertionError("unauthenticated model catalog request did not return 401")
        with client.open(
            primary_base_url + "/v1/models",
            headers={"Authorization": "Bearer compat-synthetic-client-key"},
            timeout=2.0,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
        model_ids = catalog_model_ids(payload)
        expected_raw = {"compat-text", "compat-parallel-tools", "compat-incomplete"}
        assert expected_raw.issubset(set(model_ids)), sorted(model_ids)
        return {
            "summary": "bottle enforced authentication and kept raw IDs in the OpenAI catalog",
            "authenticated_status": 200,
            "model_count": len(model_ids),
            "raw_model_ids_present": sorted(expected_raw),
        }

    def claude_catalog() -> Mapping[str, Any]:
        with client.open(
            primary_base_url + "/v1/models",
            headers=claude_headers(),
            timeout=2.0,
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
        model_ids = catalog_model_ids(payload)
        assert len(model_ids) == len(CLAUDE_MODEL_ALIASES), model_ids
        assert set(model_ids) == set(CLAUDE_MODEL_ALIASES), sorted(model_ids)
        assert not any(model_id.startswith("claude-fable-5-dd-") for model_id in model_ids)
        assert not any(
            model_id.startswith("compat-") or model_id.startswith("gpt-")
            for model_id in model_ids
        )
        return {
            "summary": "Claude CLI catalog exposed only the four fixed Claude aliases",
            "model_ids": sorted(model_ids),
            "user_agent": CLAUDE_CLI_USER_AGENT,
        }

    def claude_alias_roundtrip() -> Mapping[str, Any]:
        for model_alias in CLAUDE_MODEL_ALIASES:
            before = len(scenario_records(mock_evidence_path, "text_stream"))
            status, payload = claude_json_request(client, primary_base_url, model_alias)
            records = scenario_records(mock_evidence_path, "text_stream")
            assert status == 200, (model_alias, status)
            assert len(records) == before + 1, (model_alias, before, len(records))
            assert records[-1].get("protocol_fields", {}).get("model") == "text", records[-1]
            assert payload.get("model") == model_alias, (model_alias, payload.get("model"))
        return {
            "summary": "all fixed Claude aliases routed to text and remained visible in responses",
            "alias_count": len(CLAUDE_MODEL_ALIASES),
            "upstream_model": "text",
            "response_models": list(CLAUDE_MODEL_ALIASES),
        }

    def token_count() -> Mapping[str, Any]:
        status, payload = request_json_allow_error(
            client,
            primary_base_url + "/v1/messages/count_tokens",
            {
                "model": "compat-text",
                "messages": [{"role": "user", "content": "synthetic token count"}],
            },
            claude_headers(),
        )
        assert status == 200 and int(payload.get("input_tokens", 0)) > 0, (status, payload)
        return {
            "summary": "local Claude token-count endpoint returned a positive count",
            "status_code": status,
            "input_tokens_positive": True,
        }

    def claude_text_json() -> Mapping[str, Any]:
        status, payload = claude_json_request(client, primary_base_url, "compat-text")
        assert status == 200, status
        content = payload.get("content")
        assert isinstance(content, list) and content and content[0].get("type") == "text", content
        assert content[0].get("text") == "synthetic text", content
        assert payload.get("stop_reason") == "end_turn", payload.get("stop_reason")
        return {
            "summary": "Claude Messages JSON translated a completed Codex text response",
            "status_code": status,
            "stop_reason": payload.get("stop_reason"),
        }

    def claude_text_stream() -> Mapping[str, Any]:
        status, events = claude_sse_request(client, primary_base_url, "compat-text-stream")
        event_types = [str(event.get("event")) for event in events]
        assert status == 200
        assert claude_stream_text(events) == "synthetic text", claude_stream_text(events)
        assert event_types.count("message_stop") == 1, event_types
        assert claude_stream_stop_reason(events) == "end_turn", claude_stream_stop_reason(events)
        return {
            "summary": "Claude Messages SSE preserved text deltas and one normal terminal event",
            "event_count": len(events),
            "message_stop_count": event_types.count("message_stop"),
        }

    echo_tool = {
        "name": "compat.echo",
        "description": "Return a synthetic value",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
    }
    add_tool = {
        "name": "compat.add",
        "description": "Return synthetic numbers",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "n": {"type": "integer"},
            },
            "required": ["value", "n"],
            "additionalProperties": False,
        },
    }

    def single_tool() -> Mapping[str, Any]:
        status, events = claude_sse_request(
            client, primary_base_url, "compat-single-tool", tools=[echo_tool]
        )
        arguments = claude_tool_arguments(events)
        assert status == 200 and arguments == {"call_one": '{"value":"alpha"}'}, arguments
        assert json.loads(arguments["call_one"]) == {"value": "alpha"}
        assert claude_stream_stop_reason(events) == "tool_use"
        return {
            "summary": "single tool call preserved its call ID and valid JSON arguments",
            "tool_call_count": len(arguments),
        }

    def parallel_tools() -> Mapping[str, Any]:
        status, events = claude_sse_request(
            client,
            primary_base_url,
            "compat-parallel-tools",
            tools=[echo_tool, add_tool],
        )
        arguments = claude_tool_arguments(events)
        assert status == 200
        assert arguments.get("call_alpha") == '{"value":"alpha","n":1}', arguments
        assert arguments.get("call_beta") == '{"value":"beta","n":2}', arguments
        for value in arguments.values():
            json.loads(value)
        return {
            "summary": "parallel tool argument deltas remained isolated by call ID",
            "tool_call_count": len(arguments),
        }

    def incomplete() -> Mapping[str, Any]:
        status, payload = claude_json_request(client, primary_base_url, "compat-incomplete")
        assert status == 200, status
        assert payload.get("stop_reason") == "max_tokens", payload.get("stop_reason")
        content = payload.get("content")
        assert isinstance(content, list) and content and content[0].get("text") == "partial", content
        return {
            "summary": "response.incomplete became a successful truncated Claude message",
            "status_code": status,
            "stop_reason": "max_tokens",
        }

    def failed_terminal() -> Mapping[str, Any]:
        status, payload = claude_json_request(client, primary_base_url, "compat-failed")
        assert status >= 400, (status, payload.get("type"))
        return {
            "summary": "response.failed surfaced as a downstream error",
            "status_code": status,
        }

    def no_retry_error(model: str, scenario: str, expected: int) -> Mapping[str, Any]:
        before = len(scenario_records(mock_evidence_path, scenario))
        status, _ = claude_json_request(client, primary_base_url, model, timeout=5.0)
        after = len(scenario_records(mock_evidence_path, scenario))
        assert status == expected, (status, expected)
        assert after - before == 1, (before, after)
        return {
            "summary": "HTTP %d surfaced with retry disabled and one upstream attempt" % expected,
            "status_code": status,
            "upstream_attempts": after - before,
        }

    def disconnect_no_retry() -> Mapping[str, Any]:
        before = len(scenario_records(mock_evidence_path, "disconnect"))
        status, _ = claude_json_request(client, primary_base_url, "compat-disconnect", timeout=5.0)
        after = len(scenario_records(mock_evidence_path, "disconnect"))
        assert status >= 400, status
        assert after - before == 1, (before, after)
        return {
            "summary": "terminal-less partial stream surfaced as an error without replay",
            "status_code": status,
            "upstream_attempts": after - before,
        }

    def bounded_delay() -> Mapping[str, Any]:
        started = time.monotonic()
        try:
            claude_json_request(client, primary_base_url, "compat-delay", timeout=0.2)
        except (TimeoutError, socket.timeout):
            elapsed = time.monotonic() - started
            assert elapsed < 1.0, elapsed
            return {
                "summary": "delayed upstream was bounded by the external harness timeout",
                "timeout_ms": 200,
            }
        raise AssertionError("expected bounded client timeout")

    def field_degradations() -> Mapping[str, Any]:
        before = len(scenario_records(mock_evidence_path, "text_stream"))
        status, _ = claude_json_request(
            client,
            primary_base_url,
            "compat-text",
            tools=[dict(echo_tool, strict=True, defer_loading=False)],
            extra={
                "stop_sequences": ["END"],
                "context_management": {"edits": [{"type": "clear_tool_uses_20250919"}]},
                "thinking": {"type": "adaptive"},
                "output_config": {"effort": "low"},
            },
        )
        assert status == 200, status
        records = scenario_records(mock_evidence_path, "text_stream")
        assert len(records) == before + 1
        fields = records[-1].get("protocol_fields", {})
        assert fields.get("model") == "text", fields
        assert fields.get("max_output_tokens_present") is True, fields
        assert fields.get("stop_present") is False, fields
        assert fields.get("context_management_present") is False, fields
        assert fields.get("reasoning_effort") == "low", fields
        assert int(fields.get("tool_count", 0)) >= 1, fields
        assert fields.get("strict_true_count") == 1, fields
        rejected_status, _ = claude_json_request(
            client,
            primary_base_url,
            "compat-text",
            tools=[dict(echo_tool, strict=True, defer_loading=True)],
        )
        assert rejected_status == 400, rejected_status
        assert len(scenario_records(mock_evidence_path, "text_stream")) == before + 1
        return {
            "summary": "black-box boundary confirmed field translation and explicit defer-loading rejection",
            "max_tokens_translated": True,
            "stop_sequences_enforced_locally": True,
            "context_management_enforced_locally": True,
            "strict_preserved": True,
            "defer_loading_true_status": rejected_status,
            "reasoning_effort": "low",
        }

    add("cliproxyapi-bottle-responses-json", "Protocol", direct_responses_json)
    add("cliproxyapi-auth-catalog", "Operability", auth_and_catalog)
    add("cliproxyapi-claude-catalog", "Model/Context", claude_catalog, True)
    add("cliproxyapi-claude-alias-roundtrip", "Model/Context", claude_alias_roundtrip, True)
    add("cliproxyapi-token-count", "Model/Context", token_count)
    add("cliproxyapi-claude-json", "Protocol", claude_text_json)
    add("cliproxyapi-claude-sse", "Protocol", claude_text_stream)
    add("cliproxyapi-single-tool", "Tools", single_tool, True)
    add("cliproxyapi-parallel-tools", "Tools", parallel_tools, True)
    add("cliproxyapi-incomplete-max-tokens", "Resilience", incomplete, True)
    add("cliproxyapi-failed-terminal", "Resilience", failed_terminal, True)
    add(
        "cliproxyapi-http-500-no-retry",
        "Resilience",
        lambda: no_retry_error("compat-http-500", "http_500", 500),
    )
    add(
        "cliproxyapi-http-502-no-retry",
        "Resilience",
        lambda: no_retry_error("compat-http-502", "http_502", 502),
    )
    add(
        "cliproxyapi-http-429-no-retry",
        "Resilience",
        lambda: no_retry_error("compat-http-429", "http_429", 429),
    )
    add("cliproxyapi-disconnect-no-retry", "Resilience", disconnect_no_retry, True)
    add("cliproxyapi-bounded-delay", "Resilience", bounded_delay)
    add("cliproxyapi-field-degradations", "Protocol", field_degradations)

    retry_base_url, retry_port = start_bottle_proxy(
        run_dir,
        env,
        registry,
        mock_base_url,
        request_retry=2,
        instance_name="retry",
        binary=binary,
    )

    def bounded_internal_retry(model: str, scenario: str, expected: int) -> Mapping[str, Any]:
        before = len(scenario_records(mock_evidence_path, scenario))
        status, _ = claude_json_request(client, retry_base_url, model, timeout=10.0)
        after = len(scenario_records(mock_evidence_path, scenario))
        attempts = after - before
        assert status == expected, (status, expected)
        assert 1 <= attempts <= 3, attempts
        return {
            "summary": "configured internal retries remained bounded for HTTP %d" % expected,
            "status_code": status,
            "upstream_attempts": attempts,
            "configured_request_retry": 2,
            "proxy_port_dynamic": retry_port != FORBIDDEN_PORT,
        }

    def no_partial_stream_replay() -> Mapping[str, Any]:
        before = len(scenario_records(mock_evidence_path, "disconnect"))
        status, events = claude_sse_request(
            client, retry_base_url, "compat-disconnect", timeout=8.0
        )
        after = len(scenario_records(mock_evidence_path, "disconnect"))
        attempts = after - before
        assert status == 200, status
        assert claude_stream_text(events) == "partial", claude_stream_text(events)
        assert attempts == 1, attempts
        assert "message_stop" not in [str(event.get("event")) for event in events]
        return {
            "summary": "partial streaming output was not replayed by internal retry logic",
            "upstream_attempts": attempts,
            "partial_text_observed": True,
        }

    add(
        "cliproxyapi-http-500-bounded-retry",
        "Resilience",
        lambda: bounded_internal_retry("compat-http-500", "http_500", 500),
    )
    add(
        "cliproxyapi-http-502-bounded-retry",
        "Resilience",
        lambda: bounded_internal_retry("compat-http-502", "http_502", 502),
    )
    add(
        "cliproxyapi-http-429-bounded-retry",
        "Resilience",
        lambda: bounded_internal_retry("compat-http-429", "http_429", 429),
    )
    add("cliproxyapi-partial-stream-no-replay", "Resilience", no_partial_stream_replay, True)
    return cases, evidence


def case_result(
    case_id: str,
    dimension: str,
    callback: Callable[[], Mapping[str, Any]],
    hard_failure: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    started = time.monotonic()
    try:
        details = dict(callback())
        status = "PASS"
        summary = str(details.pop("summary", "expected behavior observed"))
    except Exception as exc:  # Case boundaries intentionally convert errors to report entries.
        status = "FAIL"
        summary = "%s: %s" % (type(exc).__name__, str(exc))
        details = {}
    duration = time.monotonic() - started
    case = {
        "id": case_id,
        "dimension": dimension,
        "status": status,
        "summary": summary,
        "duration_seconds": round(duration, 6),
        "hard_failure": bool(hard_failure and status == "FAIL"),
    }
    evidence = {
        "kind": "case_observation",
        "case_id": case_id,
        "status": status,
        "duration_ms": int(duration * 1000),
        "details": details,
    }
    return case, evidence


def unverified(case_id: str, dimension: str, summary: str) -> Dict[str, Any]:
    return {
        "id": case_id,
        "dimension": dimension,
        "status": "UNVERIFIED",
        "summary": summary,
        "duration_seconds": 0.0,
        "hard_failure": False,
    }


def run_mock_cases(base_url: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    client = LocalHttpClient()
    cases: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    def add(case_id: str, dimension: str, callback: Callable[[], Mapping[str, Any]], hard: bool = False) -> None:
        case, item = case_result(case_id, dimension, callback, hard)
        cases.append(case)
        evidence.append(item)

    def health() -> Mapping[str, Any]:
        with client.open(base_url + "/healthz") as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200 and payload.get("ok") is True
        return {"summary": "mock bound on a dynamic loopback port", "status_code": 200}

    def text_json() -> Mapping[str, Any]:
        status, payload = json_request(
            client, base_url + "/v1/responses", "text", {"model": "compat-model", "input": "synthetic"}
        )
        assert status == 200 and payload.get("status") == "completed"
        assert payload.get("output", [{}])[0].get("type") == "message"
        return {"summary": "fixture returned a completed JSON text response", "status_code": status}

    def stream_terminal(scenario: str, expected: str) -> Mapping[str, Any]:
        events = sse_request(client, base_url + "/v1/responses", scenario)
        terminals = _terminal_types(events)
        assert terminals == [expected], terminals
        return {
            "summary": "%s terminal event classified correctly" % expected,
            "event_count": len(events),
            "terminal_events": terminals,
        }

    def single_tool() -> Mapping[str, Any]:
        events = sse_request(client, base_url + "/v1/responses", "single_tool")
        arguments = _tool_arguments(events)
        assert len(arguments) == 1
        parsed = [json.loads(value) for value in arguments.values()]
        assert parsed == [{"value": "alpha"}]
        assert _terminal_types(events) == ["response.completed"]
        return {"summary": "single tool arguments reassembled by call ID", "tool_call_count": 1}

    def parallel_tools() -> Mapping[str, Any]:
        events = sse_request(client, base_url + "/v1/responses", "parallel_interleaved_tools")
        arguments = _tool_arguments(events)
        assert sorted(arguments) == ["call_alpha", "call_beta"]
        parsed = {key: json.loads(value) for key, value in arguments.items()}
        assert parsed["call_alpha"] == {"value": "alpha", "n": 1}
        assert parsed["call_beta"] == {"value": "beta", "n": 2}
        assert _terminal_types(events) == ["response.completed"]
        return {
            "summary": "interleaved parallel tool deltas remained isolated by call ID",
            "tool_call_count": 2,
            "delta_event_count": sum(
                event.get("event") == "response.function_call_arguments.delta" for event in events
            ),
        }

    def status_error(scenario: str, expected: int) -> Mapping[str, Any]:
        try:
            json_request(client, base_url + "/v1/responses", scenario, {"input": "synthetic"})
        except urllib.error.HTTPError as exc:
            assert exc.code == expected
            exc.read()
            return {"summary": "HTTP %d surfaced as an error" % expected, "status_code": expected}
        raise AssertionError("expected HTTP %d" % expected)

    def disconnect() -> Mapping[str, Any]:
        events = sse_request(client, base_url + "/v1/responses", "disconnect")
        terminals = _terminal_types(events)
        assert terminals == []
        return {
            "summary": "EOF without terminal event was not classified as success",
            "event_count": len(events),
            "terminal_events": terminals,
        }

    def delayed() -> Mapping[str, Any]:
        try:
            json_request(
                client,
                base_url + "/v1/responses",
                "delay",
                {"input": "synthetic"},
                timeout=0.15,
            )
        except (TimeoutError, socket.timeout):
            return {"summary": "delayed response triggered the bounded client timeout", "timeout_ms": 150}
        raise AssertionError("expected timeout")

    def oauth_refresh() -> Mapping[str, Any]:
        body = urllib.parse.urlencode(
            {
                "grant_type": "refresh_token",
                "refresh_token": "COMPAT-CANARY-OAUTH-31f8e2",
                "client_id": "compat-client",
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        with client.open(base_url + "/oauth/token", "POST", body, headers) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200
            assert payload.get("token_type") == "Bearer"
            assert isinstance(payload.get("access_token"), str)
        return {"summary": "synthetic OAuth refresh fixture returned a replacement credential", "status_code": 200}

    def canary() -> Mapping[str, Any]:
        payload = {
            "model": "compat-model",
            "input": DEFAULT_CANARIES[3],
            "api_key": "sk-COMPATCANARY123456",
            "access_token": DEFAULT_CANARIES[1],
        }
        status, response = json_request(
            client,
            base_url + "/v1/responses",
            "text",
            payload,
            extra_headers={"Authorization": "Bearer " + DEFAULT_CANARIES[0]},
        )
        assert status == 200 and response.get("status") == "completed"
        return {
            "summary": "credential and body canaries were accepted only in memory for leak scanning",
            "canary_count": len(DEFAULT_CANARIES),
        }

    add("mock-health", "Operability", health)
    add("text-json", "Protocol", text_json)
    add("text-sse", "Protocol", lambda: stream_terminal("text_stream", "response.completed"))
    add("single-tool", "Tools", single_tool, True)
    add("parallel-interleaved-tools", "Tools", parallel_tools, True)
    add("terminal-completed", "Protocol", lambda: stream_terminal("completed", "response.completed"))
    add("terminal-incomplete", "Resilience", lambda: stream_terminal("incomplete", "response.incomplete"), True)
    add("terminal-failed", "Resilience", lambda: stream_terminal("failed", "response.failed"), True)
    add("http-500", "Resilience", lambda: status_error("http_500", 500))
    add("http-502", "Resilience", lambda: status_error("http_502", 502))
    add("http-429", "Resilience", lambda: status_error("http_429", 429))
    add("stream-disconnect", "Resilience", disconnect, True)
    add("bounded-delay", "Resilience", delayed)
    add("synthetic-oauth-refresh", "Security", oauth_refresh)
    add("redaction-canary", "Security", canary, True)
    return cases, evidence


def load_ndjson(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def run(
    skip_prod_guard: bool = False,
    cliproxyapi_binary: Path = CLIPROXYAPI_BINARY,
    gateway_binary: Optional[Path] = None,
) -> Tuple[Path, Dict[str, Any]]:
    old_umask = os.umask(0o077)
    run_id = make_run_id()
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(str(run_dir), 0o700)
    env = isolated_environment(run_dir)
    registry = ProcessRegistry()
    baseline = prod_guard.load_baseline()
    before_path = run_dir / "prod-before.json"
    after_path = run_dir / "prod-after.json"
    prod_state: Dict[str, Any] = {"enabled": not skip_prod_guard}
    prod_untouched = True
    cases: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []

    try:
        if not skip_prod_guard:
            before = prod_guard.snapshot(baseline)
            before_path.write_text(json.dumps(before, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(str(before_path), 0o600)
            known_differences = prod_guard.compare_known(baseline, before)
            prod_state.update({"known_baseline_match": not known_differences, "difference_count": len(known_differences)})
            if known_differences:
                cases.append(
                    {
                        "id": "production-baseline",
                        "dimension": "Operability",
                        "status": "FAIL",
                        "summary": "known production baseline did not match before test start",
                        "duration_seconds": 0.0,
                        "hard_failure": True,
                    }
                )
                prod_untouched = False
                raise RuntimeError("production baseline mismatch; local test start blocked")
            cases.append(
                {
                    "id": "production-baseline",
                    "dimension": "Operability",
                    "status": "PASS",
                    "summary": prod_guard.matched_summary(baseline),
                    "duration_seconds": 0.0,
                    "hard_failure": False,
                }
            )

        ready_path = run_dir / "mock-ready.json"
        mock_evidence_path = run_dir / "mock-evidence.ndjson"
        process = registry.start(
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
        ready = wait_for_ready(ready_path, process)
        mock_port = int(ready["port"])
        if mock_port == FORBIDDEN_PORT:
            raise RuntimeError("mock selected forbidden production port")
        local_cases, local_evidence = run_mock_cases("http://127.0.0.1:%d" % mock_port)
        cases.extend(local_cases)
        evidence.extend(local_evidence)

        bottle_cases, bottle_evidence = run_bottle_cases(
            run_dir,
            env,
            registry,
            "http://127.0.0.1:%d" % mock_port,
            mock_evidence_path,
            binary=cliproxyapi_binary,
        )
        cases.extend(bottle_cases)
        evidence.extend(bottle_evidence)

    except Exception as exc:
        if not any(case.get("status") == "FAIL" for case in cases):
            cases.append(
                {
                    "id": "runner",
                    "dimension": "Operability",
                    "status": "FAIL",
                    "summary": "%s: %s" % (type(exc).__name__, str(exc)),
                    "duration_seconds": 0.0,
                    "hard_failure": True,
                }
            )
    finally:
        registry.cleanup()
        processes_stopped = registry.all_stopped()
        cases.append(
            {
                "id": "process-cleanup",
                "dimension": "Operability",
                "status": "PASS" if processes_stopped else "FAIL",
                "summary": (
                    "all isolated subprocess groups stopped within the cleanup deadline"
                    if processes_stopped
                    else "one or more isolated subprocess groups remained running"
                ),
                "duration_seconds": 0.0,
                "hard_failure": not processes_stopped,
            }
        )
        if not skip_prod_guard:
            after = prod_guard.snapshot(baseline)
            after_path.write_text(json.dumps(after, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(str(after_path), 0o600)
            before = json.loads(before_path.read_text(encoding="utf-8")) if before_path.exists() else after
            changed = prod_guard.compare_snapshots(before, after)
            if changed:
                prod_untouched = False
                cases.append(
                    {
                        "id": "production-untouched",
                        "dimension": "Operability",
                        "status": "FAIL",
                        "summary": "production state changed during the test run",
                        "duration_seconds": 0.0,
                        "hard_failure": True,
                    }
                )
            else:
                cases.append(
                    {
                        "id": "production-untouched",
                        "dimension": "Operability",
                        "status": "PASS",
                        "summary": "production listener, label, metadata, and hashes were unchanged",
                        "duration_seconds": 0.0,
                        "hard_failure": False,
                    }
                )
        else:
            prod_state["known_baseline_match"] = None

        mock_records = load_ndjson(run_dir / "mock-evidence.ndjson")
        evidence.extend(mock_records)
        mock_port = 0
        if (run_dir / "mock-ready.json").exists():
            mock_port = int(json.loads((run_dir / "mock-ready.json").read_text(encoding="utf-8"))["port"])
        environment = build_environment(run_id, mock_port, prod_state)
        identity = (
            candidate_identity(cliproxyapi_binary, gateway_binary)
            if gateway_binary is not None
            else None
        )
        rating = generate_report(
            run_dir,
            environment,
            cases,
            evidence,
            prod_untouched,
            identity=identity,
        )
        assert_report_files_safe([run_dir / name for name in REPORT_FILES])
        shutil.rmtree(run_dir / "sandbox", ignore_errors=True)
        os.umask(old_umask)

    return run_dir, rating


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-prod-guard",
        action="store_true",
        help="unit-test/developer escape hatch; default runs must not use this",
    )
    parser.add_argument(
        "--cliproxyapi-binary",
        type=Path,
        default=CLIPROXYAPI_BINARY,
        help="isolated CLIProxyAPI binary to exercise; defaults to the installed bottle",
    )
    parser.add_argument(
        "--gateway-binary",
        type=Path,
        default=None,
        help="candidate gateway binary whose digest binds this bottle evidence",
    )
    args = parser.parse_args()
    run_dir, rating = run(
        skip_prod_guard=args.skip_prod_guard,
        cliproxyapi_binary=args.cliproxyapi_binary,
        gateway_binary=args.gateway_binary,
    )
    print(json.dumps({"run_dir": str(run_dir), "rating": rating["overall"]}, sort_keys=True))
    return 1 if rating["overall"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
