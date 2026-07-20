#!/usr/bin/env python3
"""Run the installed Claude Code through a safe wrapper and isolated CLIProxyAPI."""

import argparse
import hashlib
import json
import os
import queue
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from harness import prod_guard
from harness.redaction import assert_report_files_safe
from harness.toolchain import resolve_executable
from harness.runner import (
    CLIPROXYAPI_BINARY,
    FIXTURES_DIR,
    REPO_ROOT,
    ProcessRegistry,
    candidate_identity,
    case_result,
    isolated_environment,
    load_ndjson,
    scenario_records,
    start_bottle_proxy,
    wait_for_ready,
)

CLAUDE_BINARY = resolve_executable("COMPAT_CLAUDE_BINARY", None, "claude")
LOGIN_SHELL_BINARY = resolve_executable("COMPAT_LOGIN_SHELL_BINARY", Path("/bin/zsh"), "bash")
CLAUDE_SAFE_WRAPPER = REPO_ROOT / "scripts" / "claude-safe-wrapper.py"
MCP_SERVER = REPO_ROOT / "harness" / "synthetic_mcp_server.py"
RUNS_DIR = REPO_ROOT / ".runs"


def make_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "claude-code-e2e-%s-%s" % (stamp, secrets.token_hex(4))


def write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(dict(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)


def e2e_report_identity(candidate_binary: Path, gateway_binary: Path) -> Dict[str, str]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **candidate_identity(candidate_binary, gateway_binary),
    }


def run_process(
    argv: Sequence[str],
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
) -> Tuple[int, bytes, bytes, float]:
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=2.0)
        return 124, stdout, stderr, time.monotonic() - started
    return process.returncode, stdout, stderr, time.monotonic() - started


def run_stream_process(
    argv: Sequence[str],
    env: Mapping[str, str],
    cwd: Path,
    messages: Sequence[str],
    timeout: float,
) -> Tuple[int, bytes, bytes, float]:
    started = time.monotonic()
    process = subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        env=dict(env),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    output_queue: queue.Queue[Tuple[str, Optional[bytes]]] = queue.Queue()

    def read_lines(name: str, stream: Any) -> None:
        for line in iter(stream.readline, b""):
            output_queue.put((name, line))
        output_queue.put((name, None))

    readers = [
        threading.Thread(target=read_lines, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=read_lines, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    stdout = bytearray()
    stderr = bytearray()
    closed_streams: set[str] = set()
    timed_out = False
    try:
        assert process.stdin is not None
        for message in messages:
            process.stdin.write(stream_json_input([message]))
            process.stdin.flush()
            turn_complete = False
            while not turn_complete:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    name, line = output_queue.get(timeout=remaining)
                except queue.Empty:
                    timed_out = True
                    break
                if line is None:
                    closed_streams.add(name)
                    if name == "stdout":
                        raise RuntimeError("Claude Code stream closed before the turn result")
                    continue
                if name == "stderr":
                    stderr.extend(line)
                    continue
                stdout.extend(line)
                try:
                    record = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                turn_complete = isinstance(record, dict) and record.get("type") == "result"
            if timed_out:
                break
        if process.stdin and not process.stdin.closed:
            process.stdin.close()

        while not timed_out and (process.poll() is None or len(closed_streams) < 2):
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                break
            try:
                name, line = output_queue.get(timeout=remaining)
            except queue.Empty:
                timed_out = True
                break
            if line is None:
                closed_streams.add(name)
            elif name == "stdout":
                stdout.extend(line)
            else:
                stderr.extend(line)
    finally:
        if timed_out or process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2.0)
        for reader in readers:
            reader.join(timeout=1.0)

    return (
        124 if timed_out else process.returncode,
        bytes(stdout),
        bytes(stderr),
        time.monotonic() - started,
    )


def launcher_argv(wrapper_argv: Sequence[str], launcher: str) -> List[str]:
    if launcher in {"direct", "minimal-env"}:
        return list(wrapper_argv)
    if launcher == "login-shell":
        return [str(LOGIN_SHELL_BINARY), "-lc", 'exec "$@"', "claude-safe-wrapper", *wrapper_argv]
    raise ValueError("unsupported Claude launcher: %s" % launcher)


def minimal_launcher_environment(source: Mapping[str, str]) -> Dict[str, str]:
    required = {
        "HOME": str(source["HOME"]),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "ANTHROPIC_BASE_URL": str(source["ANTHROPIC_BASE_URL"]),
    }
    for name in ("TMPDIR", "COMPAT_GATEWAY_BINARY"):
        if name in source:
            required[name] = str(source[name])
    return required


def parse_json_result(stdout: bytes) -> Dict[str, Any]:
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Claude Code did not return valid JSON output")
    if not isinstance(value, dict):
        raise ValueError("Claude Code JSON output was not an object")
    return value


def parse_stream_json(stdout: bytes) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Claude Code stream output was not UTF-8")
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError("Claude Code stream output contained a non-JSON line")
        if isinstance(value, dict):
            records.append(value)
    if not records:
        raise ValueError("Claude Code stream output was empty")
    return records


def stream_json_input(messages: Sequence[str]) -> bytes:
    records = [
        {
            "type": "user",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": message}],
            },
        }
        for message in messages
    ]
    return ("\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n").encode(
        "utf-8"
    )


def claude_environment(base: Mapping[str, str], base_url: str, run_dir: Path) -> Dict[str, str]:
    env = dict(base)
    for key in (
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
    ):
        env.pop(key, None)
    config_dir = run_dir / "sandbox" / "claude-config"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(config_dir), 0o700)
    env.update(
        {
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_API_KEY": "compat-synthetic-client-key",
            "CLAUDE_CONFIG_DIR": str(config_dir),
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_ENABLE_TELEMETRY": "0",
            "DISABLE_TELEMETRY": "1",
        }
    )
    return env


def run_claude(
    env: Mapping[str, str],
    cwd: Path,
    prompt: str,
    output_format: str,
    model: Optional[str] = None,
    tools: Optional[str] = "",
    allowed_tools: Optional[str] = None,
    mcp_config: Optional[Path] = None,
    agents: Optional[Mapping[str, Any]] = None,
    forward_subagent_text: bool = False,
    enable_isolated_subagents: bool = False,
    launcher: str = "direct",
    timeout: float = 20.0,
    input_messages: Optional[Sequence[str]] = None,
) -> Tuple[int, bytes, bytes, float]:
    argv: List[str] = [
        sys.executable,
        str(CLAUDE_SAFE_WRAPPER),
        "--claude-binary",
        str(CLAUDE_BINARY),
        "--base-url",
        str(env["ANTHROPIC_BASE_URL"]),
        "--sandbox-root",
        str(cwd.parent),
    ]
    gateway_binary = env.get("COMPAT_GATEWAY_BINARY")
    if gateway_binary:
        argv.extend(["--gateway-binary", gateway_binary])
    if enable_isolated_subagents:
        argv.append("--enable-isolated-subagents")
    if env.get("ANTHROPIC_MODEL"):
        argv.extend(["--default-model", str(env["ANTHROPIC_MODEL"])])
    argv.extend(
        [
            "--",
            "--effort",
            "low",
            "--output-format",
            output_format,
            "--system-prompt",
            "You are running a local compatibility test. Follow the synthetic response exactly.",
        ]
    )
    if output_format == "stream-json":
        argv.extend(["--include-partial-messages", "--verbose"])
    if input_messages is not None:
        if output_format != "stream-json":
            raise ValueError("stream input requires stream-json output")
        if prompt:
            raise ValueError("stream input may not be combined with a prompt argument")
        argv.extend(["--input-format", "stream-json", "--replay-user-messages"])
    if forward_subagent_text:
        if output_format != "stream-json":
            raise ValueError("subagent text forwarding requires stream-json output")
        argv.append("--forward-subagent-text")
    if model is not None:
        argv.extend(["--model", model])
    if tools is not None:
        argv.extend(["--tools", tools])
    if allowed_tools is not None:
        argv.extend(["--allowedTools", allowed_tools])
    if mcp_config is not None:
        argv.extend(["--mcp-config", str(mcp_config), "--strict-mcp-config"])
    if agents is not None:
        argv.extend(["--agents", json.dumps(dict(agents), separators=(",", ":"))])
    if input_messages is None:
        argv.append(prompt)
        return run_process(launcher_argv(argv, launcher), env, cwd, timeout)
    return run_stream_process(
        launcher_argv(argv, launcher), env, cwd, input_messages, timeout
    )


def detect_claude_version(env: Mapping[str, str], cwd: Path, launcher: str = "direct") -> str:
    argv = [
        sys.executable,
        str(CLAUDE_SAFE_WRAPPER),
        "--claude-binary",
        str(CLAUDE_BINARY),
        "--base-url",
        str(env["ANTHROPIC_BASE_URL"]),
        "--sandbox-root",
        str(cwd.parent),
    ]
    gateway_binary = env.get("COMPAT_GATEWAY_BINARY")
    if gateway_binary:
        argv.extend(["--gateway-binary", gateway_binary])
    argv.extend(["--", "--version"])
    rc, stdout, stderr, _ = run_process(launcher_argv(argv, launcher), env, cwd, 10.0)
    if rc != 0 or stderr.strip():
        raise RuntimeError("safe Claude version check failed")
    version = stdout.decode("utf-8", errors="strict").strip()
    if not version or len(version) > 128:
        raise RuntimeError("safe Claude version output was invalid")
    return version


def mcp_call_records(path: Path) -> List[Dict[str, Any]]:
    return [
        item
        for item in load_ndjson(path)
        if item.get("kind") == "mcp_request" and item.get("method") == "tools/call"
    ]


def run(
    cliproxyapi_binary: Optional[Path] = None,
    gateway_binary: Optional[Path] = None,
) -> Tuple[Path, str]:
    old_umask = os.umask(0o077)
    run_dir = RUNS_DIR / make_run_id()
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(str(run_dir), 0o700)
    env = isolated_environment(run_dir)
    proxy_binary = cliproxyapi_binary or CLIPROXYAPI_BINARY
    gateway_enabled = gateway_binary is not None
    registry = ProcessRegistry()
    baseline = prod_guard.load_baseline()
    cases: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    prod_untouched = True
    claude_code_version = "unavailable"
    sandbox_cwd = run_dir / "sandbox" / "workspace"
    sandbox_cwd.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(sandbox_cwd), 0o700)
    before = prod_guard.snapshot(baseline)
    before_known = prod_guard.compare_known(baseline, before)

    def add(case_id: str, dimension: str, callback: Any, hard: bool = False) -> None:
        case, item = case_result(case_id, dimension, callback, hard)
        cases.append(case)
        evidence.append(item)

    try:
        if before_known:
            raise RuntimeError("production baseline mismatch; Claude Code E2E start blocked")
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
        if not CLAUDE_BINARY.is_file():
            raise FileNotFoundError(str(CLAUDE_BINARY))
        if not CLAUDE_SAFE_WRAPPER.is_file():
            raise FileNotFoundError(str(CLAUDE_SAFE_WRAPPER))
        if not proxy_binary.is_file():
            raise FileNotFoundError(str(proxy_binary))
        if gateway_binary is None:
            raise RuntimeError("Claude Code E2E requires the invocation gateway binary")
        if not MCP_SERVER.is_file():
            raise FileNotFoundError(str(MCP_SERVER))

        ready_path = run_dir / "mock-ready.json"
        mock_evidence_path = run_dir / "mock-evidence.ndjson"
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
        mock_base_url = "http://127.0.0.1:%d" % int(ready["port"])
        proxy_base_url, proxy_port = start_bottle_proxy(
            run_dir,
            env,
            registry,
            mock_base_url,
            request_retry=0,
            instance_name="claude-code",
            binary=proxy_binary,
        )
        claude_env = claude_environment(env, proxy_base_url, run_dir)
        if gateway_binary is not None:
            if not gateway_binary.is_file():
                raise FileNotFoundError(str(gateway_binary))
            claude_env["COMPAT_GATEWAY_BINARY"] = str(gateway_binary.resolve())
        claude_code_version = detect_claude_version(claude_env, sandbox_cwd)
        if not claude_code_version.startswith("2.1.215"):
            raise RuntimeError("Claude Code 2.1.215 is required for this evidence stage")
        cases.append(
            {
                "id": "claude-code-safe-wrapper",
                "dimension": "Security",
                "status": "PASS",
                "summary": "Each Claude Code process ran through its own fail-closed loopback gateway",
                "duration_seconds": 0.0,
                "hard_failure": False,
            }
        )

        empty_mcp_path = run_dir / "sandbox" / "empty-mcp.json"
        write_private_json(empty_mcp_path, {"mcpServers": {}})
        mcp_evidence_path = run_dir / "mcp-evidence.ndjson"
        mcp_config_path = run_dir / "sandbox" / "mcp.json"
        write_private_json(
            mcp_config_path,
            {
                "mcpServers": {
                    "compat": {
                        "type": "stdio",
                        "command": sys.executable,
                        "args": [str(MCP_SERVER)],
                        "env": {"COMPAT_MCP_EVIDENCE": str(mcp_evidence_path)},
                    }
                }
            },
        )

        def json_text() -> Mapping[str, Any]:
            before_count = len(scenario_records(mock_evidence_path, "text_stream"))
            rc, stdout, stderr, duration = run_claude(
                claude_env,
                sandbox_cwd,
                "Return the synthetic response.",
                "json",
                model="compat-text",
                tools="",
                mcp_config=empty_mcp_path,
            )
            result = parse_json_result(stdout)
            after_count = len(scenario_records(mock_evidence_path, "text_stream"))
            assert rc == 0 and result.get("is_error") is False
            assert result.get("result") == "synthetic text"
            assert after_count - before_count == 1
            return {
                "summary": "Claude Code JSON mode completed through the isolated adapter",
                "exit_code": rc,
                "upstream_attempts": after_count - before_count,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "duration_ms": int(duration * 1000),
                "proxy_port_dynamic": proxy_port != 8317,
            }

        def stream_text() -> Mapping[str, Any]:
            rc, stdout, stderr, duration = run_claude(
                claude_env,
                sandbox_cwd,
                "Return the synthetic streaming response.",
                "stream-json",
                model="compat-text-stream",
                tools="",
                mcp_config=empty_mcp_path,
            )
            records = parse_stream_json(stdout)
            result_records = [item for item in records if item.get("type") == "result"]
            partial_count = sum(
                item.get("type") == "stream_event"
                and isinstance(item.get("event"), dict)
                and item["event"].get("type") == "content_block_delta"
                for item in records
            )
            assert rc == 0 and len(result_records) == 1
            assert result_records[0].get("is_error") is False
            assert result_records[0].get("result") == "synthetic text"
            assert partial_count >= 1
            return {
                "summary": "Claude Code stream-json emitted partial content and one successful result",
                "exit_code": rc,
                "record_count": len(records),
                "partial_event_count": partial_count,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "duration_ms": int(duration * 1000),
            }

        def explicit_model_route() -> Mapping[str, Any]:
            before_count = len(scenario_records(mock_evidence_path, "text_stream"))
            rc, stdout, stderr, _ = run_claude(
                claude_env,
                sandbox_cwd,
                "Return the explicit model route response.",
                "json",
                model="claude-opus-4-8",
                tools="",
                mcp_config=empty_mcp_path,
            )
            result = parse_json_result(stdout)
            records = scenario_records(mock_evidence_path, "text_stream")
            assert rc == 0 and result.get("result") == "synthetic text"
            assert len(records) == before_count + 1
            fields = records[-1].get("protocol_fields", {})
            assert fields.get("model") == "text"
            assert fields.get("reasoning_effort") == "low"
            return {
                "summary": "explicit Opus model ID mapped to the expected isolated Codex model",
                "upstream_model": "text",
                "reasoning_effort": "low",
                "stderr_bytes": len(stderr),
            }

        def default_model_route() -> Mapping[str, Any]:
            case_env = dict(claude_env)
            case_env["ANTHROPIC_MODEL"] = "claude-sonnet-5"
            before_count = len(scenario_records(mock_evidence_path, "text_stream"))
            rc, stdout, stderr, _ = run_claude(
                case_env,
                sandbox_cwd,
                "Return the default model route response.",
                "json",
                model=None,
                tools="",
                mcp_config=empty_mcp_path,
            )
            result = parse_json_result(stdout)
            records = scenario_records(mock_evidence_path, "text_stream")
            assert rc == 0 and result.get("result") == "synthetic text"
            assert len(records) == before_count + 1
            assert records[-1].get("protocol_fields", {}).get("model") == "text"
            return {
                "summary": "ANTHROPIC_MODEL default routed Sonnet to the expected isolated Codex model",
                "upstream_model": "text",
                "stderr_bytes": len(stderr),
            }

        def sdk_retry() -> Mapping[str, Any]:
            before_count = len(scenario_records(mock_evidence_path, "http_500"))
            rc, stdout, stderr, duration = run_claude(
                claude_env,
                sandbox_cwd,
                "Exercise a synthetic retryable error.",
                "json",
                model="compat-http-500",
                tools="",
                mcp_config=empty_mcp_path,
                timeout=12.0,
            )
            after_count = len(scenario_records(mock_evidence_path, "http_500"))
            attempts = after_count - before_count
            assert rc != 0
            assert attempts >= 1
            timed_out = rc == 124
            if gateway_enabled:
                assert attempts == 1
                assert not timed_out
            return {
                "summary": (
                    "invocation gateway limited the retryable failure to one upstream attempt"
                    if gateway_enabled and attempts == 1 and not timed_out
                    else (
                        "Claude Code retry activity exceeded the external bound"
                        if timed_out or attempts > 3
                        else "Claude Code surfaced HTTP 500 with bounded client-layer attempts"
                    )
                ),
                "exit_code_nonzero": True,
                "external_timeout_triggered": timed_out,
                "upstream_attempts": attempts,
                "gateway_enabled": gateway_enabled,
                "client_retry_observed": attempts > 1,
                "retry_amplification_detected": timed_out or attempts > 3,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "duration_ms": int(duration * 1000),
            }

        def mcp_loop() -> Mapping[str, Any]:
            before_first = len(scenario_records(mock_evidence_path, "claude_code_mcp"))
            before_done = len(scenario_records(mock_evidence_path, "claude_code_mcp_done"))
            before_calls = len(mcp_call_records(mcp_evidence_path))
            rc, stdout, stderr, duration = run_claude(
                claude_env,
                sandbox_cwd,
                "Call the allowed synthetic echo tool once, then return the completion.",
                "json",
                model="compat-mcp",
                tools="mcp__compat__echo",
                allowed_tools="mcp__compat__echo",
                mcp_config=mcp_config_path,
                timeout=25.0,
            )
            result = parse_json_result(stdout)
            first_count = len(scenario_records(mock_evidence_path, "claude_code_mcp")) - before_first
            done_count = len(scenario_records(mock_evidence_path, "claude_code_mcp_done")) - before_done
            calls = mcp_call_records(mcp_evidence_path)[before_calls:]
            assert rc == 0 and result.get("result") == "mcp complete"
            assert first_count == 1 and done_count == 1
            assert len(calls) == 1 and calls[0].get("tool_name") == "echo"
            return {
                "summary": "Claude Code completed one side-effect-free MCP tool loop without duplication",
                "tool_call_count": len(calls),
                "parent_turn_count": first_count + done_count,
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "duration_ms": int(duration * 1000),
            }

        def subagent_route() -> Mapping[str, Any]:
            before_parent = len(scenario_records(mock_evidence_path, "claude_code_agent"))
            before_done = len(scenario_records(mock_evidence_path, "claude_code_agent_done"))
            before_text = len(scenario_records(mock_evidence_path, "text_stream"))
            haiku_alias = "claude-haiku-4-5-20251001"
            agents = {
                "compat-reviewer": {
                    "description": "Return a short synthetic compatibility acknowledgement.",
                    "prompt": "Return the synthetic response without using tools.",
                    "model": haiku_alias,
                    "tools": ["Read"],
                }
            }
            rc, stdout, stderr, duration = run_claude(
                claude_env,
                sandbox_cwd,
                "Run the configured compatibility subagent once.",
                "stream-json",
                model="compat-agent",
                tools=None,
                allowed_tools="Agent",
                mcp_config=empty_mcp_path,
                agents=agents,
                forward_subagent_text=True,
                enable_isolated_subagents=True,
                timeout=30.0,
            )
            output_records = parse_stream_json(stdout)
            result_records = [item for item in output_records if item.get("type") == "result"]
            parent_count = len(scenario_records(mock_evidence_path, "claude_code_agent")) - before_parent
            done_count = len(scenario_records(mock_evidence_path, "claude_code_agent_done")) - before_done
            text_records = scenario_records(mock_evidence_path, "text_stream")[before_text:]
            init_records = [
                item
                for item in output_records
                if item.get("type") == "system" and item.get("subtype") == "init"
            ]
            assert len(init_records) == 1
            advertised_tools = init_records[0].get("tools")
            assert isinstance(advertised_tools, list) and advertised_tools
            parent_tool_uses: List[Mapping[str, Any]] = []
            for item in output_records:
                if item.get("type") != "assistant" or item.get("parent_tool_use_id") is not None:
                    continue
                message = item.get("message")
                content = message.get("content") if isinstance(message, dict) else None
                if not isinstance(content, list):
                    continue
                parent_tool_uses.extend(
                    block
                    for block in content
                    if isinstance(block, dict)
                    and block.get("type") == "tool_use"
                    and block.get("name") == "Agent"
                )
            assert len(parent_tool_uses) == 1
            tool_use_id = parent_tool_uses[0].get("id")
            tool_input = parent_tool_uses[0].get("input")
            assert isinstance(tool_use_id, str) and tool_use_id
            assert isinstance(tool_input, dict) and tool_input.get("run_in_background") is False
            forwarded_records = [
                item
                for item in output_records
                if isinstance(item.get("parent_tool_use_id"), str)
                and item.get("parent_tool_use_id")
            ]
            assert forwarded_records
            assert {item.get("parent_tool_use_id") for item in forwarded_records} == {tool_use_id}
            assert any(item.get("type") == "user" for item in forwarded_records)
            child_assistant_records = [
                item for item in forwarded_records if item.get("type") == "assistant"
            ]
            assert child_assistant_records
            assert {
                item.get("message", {}).get("model")
                for item in child_assistant_records
                if isinstance(item.get("message"), dict)
            } == {haiku_alias}
            tool_results = [
                item.get("tool_use_result")
                for item in output_records
                if item.get("type") == "user"
                and item.get("parent_tool_use_id") is None
                and isinstance(item.get("tool_use_result"), dict)
            ]
            assert len(tool_results) == 1
            assert tool_results[0].get("resolvedModel") == haiku_alias
            assert tool_results[0].get("status") == "completed"
            assert rc == 0 and len(result_records) == 1
            assert result_records[0].get("result") == "agent complete"
            assert parent_count == 1 and done_count == 1
            assert len(text_records) == 1
            assert text_records[0].get("protocol_fields", {}).get("model") == "text"
            return {
                "summary": "Claude Code forwarded one foreground Agent child using the fixed Haiku alias",
                "parent_initial_request_count": parent_count,
                "parent_completion_request_count": done_count,
                "subagent_request_count": len(text_records),
                "subagent_exercised": True,
                "subagent_visible_model": haiku_alias,
                "subagent_upstream_model": "text",
                "parent_tool_use_id_forwarded": True,
                "run_in_background": False,
                "advertised_tool_count": len(advertised_tools),
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "duration_ms": int(duration * 1000),
            }

        def launcher_parity() -> Mapping[str, Any]:
            modes = [
                ("direct-absolute", "direct", dict(claude_env)),
                ("login-shell", "login-shell", dict(claude_env)),
                ("gui-minimal-env", "minimal-env", minimal_launcher_environment(claude_env)),
            ]
            observations: Dict[str, Dict[str, Any]] = {}
            versions: List[str] = []
            for label, launcher, launcher_env in modes:
                version = detect_claude_version(launcher_env, sandbox_cwd, launcher=launcher)
                before_count = len(scenario_records(mock_evidence_path, "text_stream"))
                rc, stdout, stderr, duration = run_claude(
                    launcher_env,
                    sandbox_cwd,
                    "Return the fixed alias launcher response.",
                    "json",
                    model="claude-opus-4-8",
                    tools="",
                    mcp_config=empty_mcp_path,
                    launcher=launcher,
                )
                result = parse_json_result(stdout)
                records = scenario_records(mock_evidence_path, "text_stream")
                attempts = len(records) - before_count
                assert rc == 0 and result.get("is_error") is False
                assert result.get("result") == "synthetic text"
                assert attempts == 1
                assert records[-1].get("protocol_fields", {}).get("model") == "text"
                assert proxy_port != 8317
                assert not stderr
                observations[label] = {
                    "version": version,
                    "result": "synthetic text",
                    "upstream_attempts": attempts,
                    "duration_ms": int(duration * 1000),
                }
                versions.append(version)
            assert len(set(versions)) == 1
            assert versions[0] == claude_code_version
            return {
                "summary": "direct, login-shell, and GUI-style minimal environments matched",
                "fixed_alias": "claude-opus-4-8",
                "claude_code_version": versions[0],
                "proxy_port_dynamic": proxy_port != 8317,
                "launchers": observations,
            }

        def local_compact() -> Mapping[str, Any]:
            compact_env = dict(claude_env)
            compact_env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = "1000"
            compact_env["CLAUDE_CODE_DISABLE_PRECOMPACT_SKIP"] = "1"
            matrix = {
                "before": {
                    "model": "compat-compact-before",
                    "scenario": "compact_before",
                    "reported_total_tokens": 66995,
                    "expected_requests": 3,
                    "expected_compacting": 0,
                    "expected_success": 0,
                    "expected_errors": [],
                },
                "at": {
                    "model": "compat-compact-at",
                    "scenario": "compact_at",
                    "reported_total_tokens": 66996,
                    "expected_requests": 4,
                    "expected_compacting": 1,
                    "expected_success": 1,
                    "expected_errors": [],
                },
                "after": {
                    "model": "compat-compact-after",
                    "scenario": "compact_after",
                    "reported_total_tokens": 66997,
                    "expected_requests": 4,
                    "expected_compacting": 2,
                    "expected_success": 1,
                    "expected_errors": ["too_few_groups"],
                },
            }
            observations: Dict[str, Dict[str, Any]] = {}
            for label, spec in matrix.items():
                before_count = len(scenario_records(mock_evidence_path, str(spec["scenario"])))
                rc, stdout, stderr, duration = run_claude(
                    compact_env,
                    sandbox_cwd,
                    "",
                    "stream-json",
                    model=str(spec["model"]),
                    tools="",
                    mcp_config=empty_mcp_path,
                    timeout=20.0,
                    input_messages=["Turn one.", "Turn two.", "Turn three."],
                )
                output_records = parse_stream_json(stdout)
                scenario_items = scenario_records(mock_evidence_path, str(spec["scenario"]))[
                    before_count:
                ]
                result_records = [
                    item for item in output_records if item.get("type") == "result"
                ]
                compacting = sum(
                    item.get("type") == "system" and item.get("status") == "compacting"
                    for item in output_records
                )
                compact_success = sum(
                    item.get("type") == "system" and item.get("compact_result") == "success"
                    for item in output_records
                )
                compact_errors = [
                    item.get("compact_error")
                    for item in output_records
                    if item.get("type") == "system" and item.get("compact_result") == "failed"
                ]
                assert rc == 0 and not stderr
                assert len(result_records) == 3
                assert all(item.get("is_error") is False for item in result_records)
                assert len(scenario_items) == spec["expected_requests"]
                assert compacting == spec["expected_compacting"]
                assert compact_success == spec["expected_success"]
                assert compact_errors == spec["expected_errors"]
                assert all(
                    item.get("protocol_fields", {}).get("model") == str(spec["scenario"])
                    and item.get("protocol_fields", {}).get("reasoning_effort") == "low"
                    for item in scenario_items
                )
                observations[label] = {
                    "reported_total_tokens": spec["reported_total_tokens"],
                    "upstream_requests": len(scenario_items),
                    "completed_user_turns": len(result_records),
                    "compact_attempts": compacting,
                    "compact_successes": compact_success,
                    "compact_errors": compact_errors,
                    "model_route": str(spec["scenario"]),
                    "reasoning_effort": "low",
                    "duration_ms": int(duration * 1000),
                }
            return {
                "summary": "synthetic usage crossed the observed compact boundary and completed the next user turn",
                "auto_compact_window": 1000,
                "matrix": observations,
                "body_storage": "counts and identifiers only; prompt and response bodies were not persisted",
                "remaining_unverified": [
                    "unfinished tool relationships cannot reach auto-compact through the stock turn-serial client path",
                    "explicit user interruption or cancellation state recovery",
                    "cross-process recovery, which the safe wrapper intentionally disables",
                ],
            }

        def compact_tool_state() -> Mapping[str, Any]:
            compact_env = dict(claude_env)
            compact_env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = "1000"
            compact_env["CLAUDE_CODE_DISABLE_PRECOMPACT_SKIP"] = "1"
            before_requests = len(scenario_records(mock_evidence_path, "compact_tool"))
            before_calls = len(mcp_call_records(mcp_evidence_path))
            rc, stdout, stderr, duration = run_claude(
                compact_env,
                sandbox_cwd,
                "",
                "stream-json",
                model="compat-compact-tool",
                tools="mcp__compat__echo",
                allowed_tools="mcp__compat__echo",
                mcp_config=mcp_config_path,
                timeout=30.0,
                input_messages=["Turn one.", "Turn two.", "Turn three."],
            )
            output_records = parse_stream_json(stdout)
            scenario_items = scenario_records(mock_evidence_path, "compact_tool")[
                before_requests:
            ]
            calls = mcp_call_records(mcp_evidence_path)[before_calls:]
            result_records = [item for item in output_records if item.get("type") == "result"]
            compact_success = sum(
                item.get("type") == "system" and item.get("compact_result") == "success"
                for item in output_records
            )
            assert rc == 0 and not stderr
            assert len(result_records) == 3 and all(
                item.get("is_error") is False for item in result_records
            )
            assert len(scenario_items) == 5
            assert len(calls) == 1 and calls[0].get("tool_name") == "echo"
            assert compact_success == 1
            relation_records = [
                item.get("protocol_fields", {}) for item in scenario_items[1:3]
            ]
            assert all(
                fields.get("function_call_ids") == ["call_mcp_echo"]
                and fields.get("function_output_call_ids") == ["call_mcp_echo"]
                for fields in relation_records
            )
            assert all(
                not item.get("protocol_fields", {}).get("function_call_ids")
                and not item.get("protocol_fields", {}).get("function_output_call_ids")
                for item in scenario_items[3:]
            )
            assert all(
                item.get("protocol_fields", {}).get("model") == "compact_tool"
                and item.get("protocol_fields", {}).get("reasoning_effort") == "low"
                and item.get("protocol_fields", {}).get("input_message_roles", [None])[0]
                == "developer"
                for item in scenario_items
            )
            return {
                "summary": "one closed MCP relation survived until compact and its tool executed exactly once",
                "upstream_requests": len(scenario_items),
                "completed_user_turns": len(result_records),
                "compact_successes": compact_success,
                "mcp_tool_calls": len(calls),
                "tool_call_id": "call_mcp_echo",
                "closed_relation_observed_before_compact": True,
                "tool_relation_absent_after_compact": True,
                "developer_instruction_role_preserved": True,
                "model_route": "compact_tool",
                "reasoning_effort": "low",
                "duration_ms": int(duration * 1000),
            }

        def compact_failure_recovery() -> Mapping[str, Any]:
            compact_env = dict(claude_env)
            compact_env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] = "1000"
            compact_env["CLAUDE_CODE_DISABLE_PRECOMPACT_SKIP"] = "1"
            observations: Dict[str, Dict[str, Any]] = {}
            failure_matrix = {
                "compact_http_500": {
                    "model": "compat-compact-fail-500",
                    "scenario": "compact_fail_500",
                    "error_fragment": "upstream status 500",
                },
                "compact_disconnect": {
                    "model": "compat-compact-fail-disconnect",
                    "scenario": "compact_fail_disconnect",
                    "error_fragment": (
                        "duplicate request blocked after an incomplete streaming response"
                    ),
                },
            }
            for label, spec in failure_matrix.items():
                scenario = str(spec["scenario"])
                before_requests = len(scenario_records(mock_evidence_path, scenario))
                rc, stdout, stderr, duration = run_claude(
                    compact_env,
                    sandbox_cwd,
                    "",
                    "stream-json",
                    model=str(spec["model"]),
                    tools="",
                    mcp_config=empty_mcp_path,
                    timeout=25.0,
                    input_messages=["Turn one.", "Turn two.", "Turn three."],
                )
                output_records = parse_stream_json(stdout)
                scenario_items = scenario_records(mock_evidence_path, scenario)[
                    before_requests:
                ]
                result_records = [
                    item for item in output_records if item.get("type") == "result"
                ]
                compacting = sum(
                    item.get("type") == "system" and item.get("status") == "compacting"
                    for item in output_records
                )
                compact_success = sum(
                    item.get("type") == "system" and item.get("compact_result") == "success"
                    for item in output_records
                )
                compact_errors = [
                    str(item.get("compact_error"))
                    for item in output_records
                    if item.get("type") == "system"
                    and item.get("compact_result") == "failed"
                ]
                assert rc == 0 and not stderr, {
                    "exit_code": rc,
                    "stderr": stderr.decode("utf-8", errors="replace"),
                }
                assert len(result_records) == 3 and all(
                    item.get("is_error") is False for item in result_records
                ), {"result_records": result_records}
                assert len(scenario_items) == 4, {"upstream_requests": len(scenario_items)}
                compact_upstream_attempts = len(scenario_items) - len(result_records)
                assert compact_upstream_attempts == 1, {
                    "upstream_requests": len(scenario_items),
                    "completed_user_turns": len(result_records),
                }
                assert compacting == 2 and compact_success == 0, {
                    "compact_attempts": compacting,
                    "compact_successes": compact_success,
                    "compact_errors": compact_errors,
                }
                assert len(compact_errors) == 2, {"compact_errors": compact_errors}
                assert compact_errors[0] == "too_few_groups", {
                    "compact_errors": compact_errors
                }
                assert str(spec["error_fragment"]) in compact_errors[1], {
                    "compact_errors": compact_errors
                }
                assert all(
                    item.get("protocol_fields", {}).get("model") == scenario
                    and item.get("protocol_fields", {}).get("reasoning_effort") == "low"
                    for item in scenario_items
                ), {"scenario": scenario, "scenario_items": scenario_items}
                observations[label] = {
                    "upstream_requests": len(scenario_items),
                    "completed_user_turns": len(result_records),
                    "compact_attempts": compacting,
                    "compact_local_preflight_failures": 1,
                    "compact_upstream_attempts": compact_upstream_attempts,
                    "compact_successes": compact_success,
                    "compact_errors": compact_errors,
                    "semantic_request_upstream_attempt_limit_preserved": True,
                    "continued_in_same_process": True,
                    "duration_ms": int(duration * 1000),
                }

            post_scenario = "compact_post_fail"
            before_requests = len(scenario_records(mock_evidence_path, post_scenario))
            rc, stdout, stderr, duration = run_claude(
                compact_env,
                sandbox_cwd,
                "",
                "stream-json",
                model="compat-compact-post-fail",
                tools="",
                mcp_config=empty_mcp_path,
                timeout=25.0,
                input_messages=["Turn one.", "Turn two.", "Turn three.", "Turn four."],
            )
            output_records = parse_stream_json(stdout)
            scenario_items = scenario_records(mock_evidence_path, post_scenario)[
                before_requests:
            ]
            result_records = [item for item in output_records if item.get("type") == "result"]
            compacting = sum(
                item.get("type") == "system" and item.get("status") == "compacting"
                for item in output_records
            )
            compact_success = sum(
                item.get("type") == "system" and item.get("compact_result") == "success"
                for item in output_records
            )
            compact_errors = [
                str(item.get("compact_error"))
                for item in output_records
                if item.get("type") == "system"
                and item.get("compact_result") == "failed"
            ]
            retained_turn_hashes = [
                hashlib.sha256(b"Turn three.\n").hexdigest(),
                hashlib.sha256(b"Turn four.").hexdigest(),
            ]
            last_protocol_fields = scenario_items[-1].get("protocol_fields", {})
            assert rc == 0 and not stderr, {
                "exit_code": rc,
                "stderr": stderr.decode("utf-8", errors="replace"),
            }
            assert len(result_records) == 4, {"result_records": result_records}
            assert [item.get("is_error") for item in result_records] == [
                False,
                False,
                True,
                False,
            ], {"result_records": result_records}
            assert result_records[2].get("api_error_status") == 424, {
                "failed_result": result_records[2]
            }
            assert "upstream status 500" in str(result_records[2].get("result")), {
                "failed_result": result_records[2]
            }
            assert len(scenario_items) == 5, {"upstream_requests": len(scenario_items)}
            compact_upstream_attempts = len(scenario_items) - len(result_records)
            assert compact_upstream_attempts == 1, {
                "upstream_requests": len(scenario_items),
                "completed_user_turns": len(result_records),
            }
            assert compacting == 2 and compact_success == 1, {
                "compact_attempts": compacting,
                "compact_successes": compact_success,
                "compact_errors": compact_errors,
            }
            assert compact_errors == ["too_few_groups"], {
                "compact_errors": compact_errors
            }
            assert last_protocol_fields.get("input_text_sha256", [])[-2:] == retained_turn_hashes, {
                "last_protocol_fields": last_protocol_fields
            }
            assert all(
                item.get("protocol_fields", {}).get("model") == post_scenario
                and item.get("protocol_fields", {}).get("reasoning_effort") == "low"
                for item in scenario_items
            ), {"scenario_items": scenario_items}
            observations["first_post_compact_http_500"] = {
                "upstream_requests": len(scenario_items),
                "completed_user_turns": len(result_records),
                "result_error_sequence": [
                    bool(item.get("is_error")) for item in result_records
                ],
                "failed_turn_api_error_status": result_records[2].get("api_error_status"),
                "compact_attempts": compacting,
                "compact_local_preflight_failures": 1,
                "compact_upstream_attempts": compact_upstream_attempts,
                "compact_successes": compact_success,
                "compact_errors": compact_errors,
                "failed_turn_retained_for_next_input": True,
                "semantic_request_upstream_attempt_limit_preserved": True,
                "continued_in_same_process": True,
                "duration_ms": int(duration * 1000),
            }
            return {
                "summary": "compact 500, disconnect, and first post-compact failure recovered in one process",
                "matrix": observations,
                "disconnect_duplicate_reached_upstream": False,
                "body_storage": "counts and SHA-256 values only; prompt and response bodies were not persisted",
                "remaining_unverified": [
                    "explicit user interruption or cancellation state recovery",
                    "cross-process recovery, which the safe wrapper intentionally disables",
                ],
            }

        add("claude-code-json-text", "Protocol", json_text, True)
        add("claude-code-stream-json", "Protocol", stream_text, True)
        add("claude-code-explicit-model", "Model/Context", explicit_model_route, True)
        add("claude-code-default-model", "Model/Context", default_model_route, True)
        add("claude-code-sdk-retry", "Resilience", sdk_retry)
        retry_details = evidence[-1].get("details", {})
        if retry_details.get("retry_amplification_detected"):
            cases[-1]["status"] = "FAIL"
            cases[-1]["hard_failure"] = True
            cases[-1]["summary"] = "Claude Code exceeded the external timeout or three client-layer attempts"
            evidence[-1]["status"] = "FAIL"
        add("claude-code-mcp-loop", "Tools", mcp_loop, True)
        add("claude-code-subagent-route", "Model/Context", subagent_route, True)
        add("claude-code-login-shell-matrix", "Operability", launcher_parity, True)
        add("claude-code-local-compact", "Model/Context", local_compact)
        if cases[-1]["status"] == "PASS":
            cases[-1]["status"] = "UNVERIFIED"
            cases[-1]["summary"] = (
                "synthetic threshold passed; explicit cancellation and cross-process recovery remain unverified"
            )
            evidence[-1]["status"] = "UNVERIFIED"
        add("claude-code-compact-tool-state", "Tools", compact_tool_state, True)
        add(
            "claude-code-compact-failure-recovery",
            "Resilience",
            compact_failure_recovery,
            True,
        )
    except Exception as exc:
        cases.append(
            {
                "id": "claude-code-e2e-runner",
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
        after = prod_guard.snapshot(baseline)
        changed = prod_guard.compare_snapshots(before, after)
        if changed:
            prod_untouched = False
        cases.append(
            {
                "id": "production-untouched",
                "dimension": "Operability",
                "status": "PASS" if prod_untouched else "FAIL",
                "summary": (
                    "production listener, label, metadata, and hashes were unchanged"
                    if prod_untouched
                    else "production state changed during Claude Code E2E"
                ),
                "duration_seconds": 0.0,
                "hard_failure": not prod_untouched,
            }
        )

        hard_failures = [
            str(case.get("id"))
            for case in cases
            if case.get("status") == "FAIL" and case.get("hard_failure")
        ]
        if hard_failures:
            overall = "FAIL"
        elif any(case.get("status") == "UNVERIFIED" for case in cases):
            overall = "CONDITIONAL"
        else:
            overall = "PASS"
        report = {
            "schema_version": 1,
            **(
                e2e_report_identity(proxy_binary.resolve(), gateway_binary.resolve())
                if gateway_binary is not None
                else {}
            ),
            "claude_code_version": claude_code_version,
            "cliproxyapi_version": "7.2.80",
            "gateway_enabled": gateway_enabled,
            "overall": overall,
            "hard_failures": hard_failures,
            "cases": cases,
            "evidence": evidence,
            "production_untouched": prod_untouched,
        }
        json_path = run_dir / "claude-code-e2e.json"
        write_private_json(json_path, report)
        lines = [
            "# Claude Code local E2E report",
            "",
            "Overall: **%s**" % overall,
            "",
            "| Case | Dimension | Status | Summary |",
            "|---|---|---|---|",
        ]
        for case in cases:
            lines.append(
                "| %s | %s | %s | %s |"
                % (
                    case.get("id"),
                    case.get("dimension"),
                    case.get("status"),
                    str(case.get("summary", "")).replace("|", "\\|"),
                )
            )
        lines.extend(
            [
                "",
                "All Claude Code calls passed through the fail-closed wrapper with isolated HOME/config directories, strict explicit MCP config, synthetic credentials, and dynamic loopback ports. Bare mode was used except for the explicit isolated subagent case.",
            ]
        )
        md_path = run_dir / "claude-code-e2e.md"
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(str(md_path), 0o600)
        scan_paths = [json_path, md_path]
        for optional in (run_dir / "mock-evidence.ndjson", run_dir / "mcp-evidence.ndjson"):
            if optional.exists():
                scan_paths.append(optional)
        assert_report_files_safe(scan_paths)
        shutil.rmtree(run_dir / "sandbox", ignore_errors=True)
        os.umask(old_umask)

    return run_dir, overall


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cliproxyapi-binary",
        type=Path,
        default=CLIPROXYAPI_BINARY,
        help="isolated CLIProxyAPI binary to exercise",
    )
    parser.add_argument(
        "--gateway-binary",
        type=Path,
        help="optional invocation-scoped budget gateway binary",
    )
    args = parser.parse_args()
    run_dir, overall = run(
        cliproxyapi_binary=args.cliproxyapi_binary,
        gateway_binary=args.gateway_binary,
    )
    print(json.dumps({"run_dir": str(run_dir), "overall": overall}, sort_keys=True))
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
