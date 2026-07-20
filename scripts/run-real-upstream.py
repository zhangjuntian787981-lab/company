#!/usr/bin/env python3
"""Run the approved low-cost real-upstream compatibility stage through production port 8317."""

import json
import os
import secrets
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from harness import prod_guard
from harness.redaction import assert_report_files_safe
from harness.runner import REPO_ROOT, case_result, read_sse_response, unverified
from harness.toolchain import resolve_executable

CLAUDE_BINARY = resolve_executable("COMPAT_CLAUDE_BINARY", None, "claude")
MCP_SERVER = REPO_ROOT / "harness" / "synthetic_mcp_server.py"
RUNS_DIR = REPO_ROOT / ".runs"
MODEL = "gpt-5.6-sol"


def make_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "real-upstream-%s-%s" % (stamp, secrets.token_hex(4))


def write_private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(dict(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)


def production_endpoint() -> Tuple[str, str]:
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port != 8317:
        raise RuntimeError("ANTHROPIC_BASE_URL must target http://127.0.0.1:8317")
    token = os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")
    if not token:
        raise RuntimeError("no production proxy credential is present in the environment")
    return base_url, token


def api_headers(token: str) -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
        "Anthropic-Version": "2023-06-01",
    }


def json_request(
    base_url: str,
    token: str,
    path: str,
    payload: Mapping[str, Any],
    timeout: float,
) -> Tuple[int, Dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        base_url + path,
        data=body,
        method="POST",
        headers=api_headers(token),
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
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


def stream_request(
    base_url: str,
    token: str,
    payload: Mapping[str, Any],
    timeout: float,
) -> Tuple[int, List[Dict[str, Any]]]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        base_url + "/v1/messages",
        data=body,
        method="POST",
        headers=api_headers(token),
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return int(response.status), read_sse_response(response)


def run_process(
    argv: Sequence[str],
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
) -> Tuple[int, bytes, bytes, float, bool]:
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
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
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
    return process.returncode, stdout, stderr, time.monotonic() - started, timed_out


def load_ndjson(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    records: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
    return records


def run() -> Tuple[Path, str]:
    old_umask = os.umask(0o077)
    run_dir = RUNS_DIR / make_run_id()
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(str(run_dir), 0o700)
    sandbox = run_dir / "sandbox"
    home = sandbox / "home"
    config_dir = sandbox / "claude-config"
    workspace = sandbox / "workspace"
    for path in (home, config_dir, workspace):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(str(path), 0o700)

    cases: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    baseline = prod_guard.load_baseline()
    before = prod_guard.snapshot(baseline)
    prod_untouched = True
    base_url = ""
    token = ""

    def add(case_id: str, dimension: str, callback: Any, hard: bool = False) -> None:
        case, item = case_result(case_id, dimension, callback, hard)
        cases.append(case)
        evidence.append(item)

    try:
        known_differences = prod_guard.compare_known(baseline, before)
        if known_differences:
            raise RuntimeError("production baseline mismatch; real-upstream stage blocked")
        cases.append(
            {
                "id": "production-baseline",
                "dimension": "Operability",
                "status": "PASS",
                "summary": "known production hashes, label, listener port, and PID matched",
                "duration_seconds": 0.0,
                "hard_failure": False,
            }
        )
        base_url, token = production_endpoint()
        if not CLAUDE_BINARY.is_file() or not MCP_SERVER.is_file():
            raise FileNotFoundError("required local executable is missing")

        def count_tokens() -> Mapping[str, Any]:
            status, payload = json_request(
                base_url,
                token,
                "/v1/messages/count_tokens",
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": "Reply with one short word."}],
                },
                10.0,
            )
            count = int(payload.get("input_tokens", 0))
            assert status == 200 and count > 0
            return {
                "summary": "production token-count endpoint returned a positive estimate",
                "status_code": status,
                "input_tokens": count,
                "real_model_calls": 0,
            }

        def real_json() -> Mapping[str, Any]:
            status, payload = json_request(
                base_url,
                token,
                "/v1/messages",
                {
                    "model": MODEL,
                    "max_tokens": 32,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Compatibility test: reply with exactly the single word OK.",
                        }
                    ],
                    "thinking": {"type": "adaptive"},
                    "output_config": {"effort": "low"},
                },
                30.0,
            )
            content = payload.get("content")
            usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
            assert status == 200
            assert isinstance(content, list) and any(
                isinstance(item, dict) and item.get("type") == "text" and bool(item.get("text"))
                for item in content
            )
            assert int(usage.get("input_tokens", 0)) > 0
            assert int(usage.get("output_tokens", 0)) > 0
            return {
                "summary": "minimal real JSON request returned non-empty text and usage",
                "status_code": status,
                "stop_reason": payload.get("stop_reason"),
                "input_tokens": int(usage.get("input_tokens", 0)),
                "output_tokens": int(usage.get("output_tokens", 0)),
                "real_model_calls": 1,
            }

        def real_stream() -> Mapping[str, Any]:
            status, events = stream_request(
                base_url,
                token,
                {
                    "model": MODEL,
                    "max_tokens": 32,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Compatibility test: reply with exactly the single word STREAM.",
                        }
                    ],
                    "stream": True,
                    "thinking": {"type": "adaptive"},
                    "output_config": {"effort": "low"},
                },
                30.0,
            )
            event_types = [str(item.get("event")) for item in events]
            text_delta_count = sum(
                isinstance(item.get("data"), dict)
                and item["data"].get("type") == "content_block_delta"
                and isinstance(item["data"].get("delta"), dict)
                and item["data"]["delta"].get("type") == "text_delta"
                for item in events
            )
            assert status == 200 and text_delta_count >= 1
            assert event_types.count("message_stop") == 1
            return {
                "summary": "minimal real streaming request emitted text deltas and one terminal event",
                "status_code": status,
                "event_count": len(events),
                "text_delta_count": text_delta_count,
                "message_stop_count": event_types.count("message_stop"),
                "real_model_calls": 1,
            }

        mcp_evidence_path = run_dir / "mcp-evidence.ndjson"
        mcp_config_path = sandbox / "mcp.json"
        write_private_json(
            mcp_config_path,
            {
                "mcpServers": {
                    "compat": {
                        "type": "stdio",
                        "command": os.environ.get("PYTHON", "python3"),
                        "args": [str(MCP_SERVER)],
                        "env": {"COMPAT_MCP_EVIDENCE": str(mcp_evidence_path)},
                    }
                }
            },
        )

        def real_mcp_loop() -> Mapping[str, Any]:
            child_env = {
                key: value
                for key, value in os.environ.items()
                if key
                not in {
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "http_proxy",
                    "https_proxy",
                    "all_proxy",
                }
            }
            child_env.update(
                {
                    "HOME": str(home),
                    "CLAUDE_CONFIG_DIR": str(config_dir),
                    "ANTHROPIC_BASE_URL": base_url,
                    "ANTHROPIC_API_KEY": token,
                    "ANTHROPIC_AUTH_TOKEN": token,
                    "NO_PROXY": "127.0.0.1,localhost",
                    "no_proxy": "127.0.0.1,localhost",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "CLAUDE_CODE_ENABLE_TELEMETRY": "0",
                    "DISABLE_TELEMETRY": "1",
                }
            )
            before_calls = len(
                [item for item in load_ndjson(mcp_evidence_path) if item.get("method") == "tools/call"]
            )
            argv = [
                str(CLAUDE_BINARY),
                "--print",
                "--bare",
                "--no-session-persistence",
                "--disable-slash-commands",
                "--permission-mode",
                "dontAsk",
                "--effort",
                "low",
                "--output-format",
                "json",
                "--model",
                MODEL,
                "--system-prompt",
                "Use only the allowed synthetic MCP tool when requested. Keep the final answer to one word.",
                "--tools",
                "mcp__compat__echo",
                "--allowedTools",
                "mcp__compat__echo",
                "--mcp-config",
                str(mcp_config_path),
                "--strict-mcp-config",
                "--max-budget-usd",
                "0.05",
                "--prompt-suggestions",
                "false",
                "Call the compat echo tool exactly once with value ping, then reply with exactly DONE.",
            ]
            rc, stdout, stderr, duration, timed_out = run_process(
                argv, child_env, workspace, 45.0
            )
            try:
                result = json.loads(stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                result = {}
            after_records = load_ndjson(mcp_evidence_path)
            calls = [item for item in after_records if item.get("method") == "tools/call"][before_calls:]
            assert not timed_out and rc == 0
            assert isinstance(result, dict) and result.get("is_error") is False
            assert len(calls) == 1 and calls[0].get("tool_name") == "echo"
            turns = int(result.get("num_turns", 0))
            assert 2 <= turns <= 4
            return {
                "summary": "real Claude Code request completed one allowlisted MCP loop without duplicate calls",
                "tool_call_count": len(calls),
                "num_turns": turns,
                "duration_ms": int(duration * 1000),
                "stdout_bytes": len(stdout),
                "stderr_bytes": len(stderr),
                "real_model_calls_upper_bound": turns,
            }

        add("real-count-tokens", "Model/Context", count_tokens)
        add("real-json-text", "Protocol", real_json, True)
        add("real-stream-text", "Protocol", real_stream, True)
        add("real-claude-code-mcp", "Tools", real_mcp_loop, True)
        cases.extend(
            [
                unverified(
                    "real-subagent",
                    "Model/Context",
                    "restricted local E2E exposed no runnable Agent or Task tool, so no paid subagent call was attempted",
                ),
                unverified(
                    "real-long-context-compact",
                    "Model/Context",
                    "high-token compact validation was not included in the approved low-cost first stage",
                ),
                unverified(
                    "real-natural-oauth-refresh",
                    "Security",
                    "natural upstream OAuth refresh was not included in the approved low-cost first stage",
                ),
            ]
        )
    except Exception as exc:
        cases.append(
            {
                "id": "real-upstream-runner",
                "dimension": "Operability",
                "status": "FAIL",
                "summary": "%s: %s" % (type(exc).__name__, str(exc)),
                "duration_seconds": 0.0,
                "hard_failure": True,
            }
        )
    finally:
        after = prod_guard.snapshot(baseline)
        if prod_guard.compare_snapshots(before, after):
            prod_untouched = False
        cases.append(
            {
                "id": "production-untouched",
                "dimension": "Operability",
                "status": "PASS" if prod_untouched else "FAIL",
                "summary": (
                    "production listener, label, metadata, and hashes were unchanged"
                    if prod_untouched
                    else "production state changed during real-upstream validation"
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
        total_real_calls = 0
        for item in evidence:
            details = item.get("details", {})
            if isinstance(details, dict):
                total_real_calls += int(details.get("real_model_calls", 0))
                total_real_calls += int(details.get("real_model_calls_upper_bound", 0))
        report = {
            "schema_version": 1,
            "overall": overall,
            "model": MODEL,
            "approved_stage": "low-cost-first-stage",
            "estimated_real_model_calls_upper_bound": total_real_calls,
            "hard_failures": hard_failures,
            "cases": cases,
            "evidence": evidence,
            "production_untouched": prod_untouched,
            "credential_values_persisted": False,
        }
        json_path = run_dir / "real-upstream.json"
        write_private_json(json_path, report)
        lines = [
            "# Low-cost real-upstream report",
            "",
            "Overall: **%s**" % overall,
            "",
            "Estimated real model calls upper bound: **%d**" % total_real_calls,
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
                "No credential value, raw prompt, raw response, header, or body is persisted.",
            ]
        )
        md_path = run_dir / "real-upstream.md"
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(str(md_path), 0o600)
        scan_paths = [json_path, md_path]
        if (run_dir / "mcp-evidence.ndjson").exists():
            scan_paths.append(run_dir / "mcp-evidence.ndjson")
        assert_report_files_safe(scan_paths)
        shutil.rmtree(sandbox, ignore_errors=True)
        token = ""
        os.umask(old_umask)

    return run_dir, overall


def main() -> int:
    run_dir, overall = run()
    print(json.dumps({"run_dir": str(run_dir), "overall": overall}, sort_keys=True))
    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
