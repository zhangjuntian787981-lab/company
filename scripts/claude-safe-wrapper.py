#!/usr/bin/env python3
"""Run Claude Code against one isolated non-production loopback endpoint."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlsplit

SYNTHETIC_API_KEY = "compat-synthetic-client-key"
PRODUCTION_PORT = 8317
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
OWNED_FLAGS = {
    "--print",
    "-p",
    "--bare",
    "--no-session-persistence",
    "--disable-slash-commands",
    "--permission-mode",
    "--prompt-suggestions",
    "--safe-mode",
}
BLOCKED_FLAGS = {
    "--add-dir",
    "--agent",
    "--allow-dangerously-skip-permissions",
    "--background",
    "--bg",
    "--chrome",
    "--continue",
    "-c",
    "--dangerously-skip-permissions",
    "--debug-file",
    "--file",
    "--fork-session",
    "--from-pr",
    "--ide",
    "--plugin-dir",
    "--plugin-url",
    "--remote-control",
    "--resume",
    "-r",
    "--session-id",
    "--setting-sources",
    "--tmux",
    "--worktree",
    "-w",
}
BLOCKED_COMMANDS = {
    "agents",
    "auth",
    "auto-mode",
    "doctor",
    "gateway",
    "install",
    "mcp",
    "plugin",
    "plugins",
    "project",
    "remote-control",
    "setup-token",
    "ultrareview",
    "update",
    "upgrade",
}
PATH_FLAGS = {"--mcp-config", "--settings"}


class WrapperError(ValueError):
    """Raised when an invocation would escape the test boundary."""


def validate_base_url(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    if parsed.scheme != "http":
        raise WrapperError("Claude base URL must use loopback HTTP")
    if parsed.username is not None or parsed.password is not None:
        raise WrapperError("Claude base URL may not include user information")
    if parsed.query or parsed.fragment:
        raise WrapperError("Claude base URL may not include query or fragment")
    if parsed.hostname not in {"127.0.0.1", "::1"}:
        raise WrapperError("Claude base URL must use a numeric loopback address")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WrapperError("Claude base URL port is invalid") from exc
    if port is None:
        raise WrapperError("Claude base URL must include an explicit port")
    if port == PRODUCTION_PORT:
        raise WrapperError("Claude base URL may not use production port 8317")
    if not 0 < port <= 65535:
        raise WrapperError("Claude base URL port is invalid")
    path = parsed.path.rstrip("/")
    host = "[%s]" % parsed.hostname if parsed.hostname == "::1" else parsed.hostname
    return "http://%s:%d%s" % (host, port, path)


def require_within(root: Path, raw: str, label: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise WrapperError("%s must stay inside the wrapper sandbox" % label)
    if not resolved.is_file():
        raise WrapperError("%s file is unavailable" % label)
    return resolved


def validate_claude_args(args: Sequence[str], sandbox_root: Path) -> List[str]:
    values = list(args)
    if not values:
        raise WrapperError("Claude arguments are required")
    if values[0] == "--":
        values = values[1:]
    if not values:
        raise WrapperError("Claude arguments are required")

    first_non_option = next((item for item in values if not item.startswith("-")), None)
    if first_non_option in BLOCKED_COMMANDS:
        raise WrapperError("Claude management commands are not allowed by the test wrapper")

    validated: List[str] = []
    index = 0
    saw_mcp_config = False
    saw_strict_mcp = False
    while index < len(values):
        value = values[index]
        flag = value.split("=", 1)[0]
        if flag in OWNED_FLAGS:
            raise WrapperError("%s is owned by the test wrapper" % flag)
        if flag in BLOCKED_FLAGS:
            raise WrapperError("%s is not allowed by the test wrapper" % flag)
        if flag in PATH_FLAGS:
            if "=" in value:
                path_value = value.split("=", 1)[1]
                require_within(sandbox_root, path_value, flag)
            else:
                index += 1
                if index >= len(values):
                    raise WrapperError("%s requires a path" % flag)
                require_within(sandbox_root, values[index], flag)
            if flag == "--mcp-config":
                saw_mcp_config = True
        elif flag == "--strict-mcp-config":
            saw_strict_mcp = True
        validated.append(value)
        if flag in PATH_FLAGS and "=" not in value:
            validated.append(values[index])
        index += 1

    if saw_mcp_config and not saw_strict_mcp:
        validated.append("--strict-mcp-config")
    return validated


def private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def build_environment(
    sandbox_root: Path,
    base_url: str,
    default_model: Optional[str] = None,
    inherited: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    source = dict(inherited or os.environ)
    state_root = private_dir(sandbox_root / "claude-wrapper")
    home = private_dir(state_root / "home")
    config = private_dir(state_root / "config")
    tmp = private_dir(state_root / "tmp")

    env = {
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "PATH": SAFE_PATH,
        "LANG": source.get("LANG", "C"),
        "LC_ALL": "C",
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_API_KEY": SYNTHETIC_API_KEY,
        "CLAUDE_CONFIG_DIR": str(config),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_ENABLE_TELEMETRY": "0",
        "DISABLE_TELEMETRY": "1",
        "NO_PROXY": "127.0.0.1,::1",
        "no_proxy": "127.0.0.1,::1",
    }
    if default_model:
        env["ANTHROPIC_MODEL"] = default_model
    for name in (
        "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
        "CLAUDE_AUTOCOMPACT_PCT_OVERRIDE",
        "CLAUDE_CODE_DISABLE_PRECOMPACT_SKIP",
        "CLAUDE_CODE_COLD_COMPACT",
    ):
        if name in source:
            env[name] = source[name]
    return env


def wait_for_gateway(ready_file: Path, process: subprocess.Popen[bytes], timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise WrapperError("invocation gateway exited before readiness")
        if ready_file.is_file():
            try:
                payload = json.loads(ready_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                time.sleep(0.02)
                continue
            base_url = validate_base_url(str(payload.get("base_url") or ""))
            os.chmod(ready_file, 0o600)
            return base_url
        time.sleep(0.02)
    raise WrapperError("invocation gateway did not become ready")


def stop_process_group(process: subprocess.Popen[bytes], timeout: float = 2.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return


def run_claude_process(
    command: Sequence[str],
    env: Mapping[str, str],
    first_byte_deadline: float,
    absolute_deadline: float,
) -> int:
    process = subprocess.Popen(
        list(command),
        env=dict(env),
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    first_output = threading.Event()

    def pump(stream: object, file_descriptor: int) -> None:
        if stream is None:
            return
        while True:
            data = os.read(stream.fileno(), 8192)  # type: ignore[attr-defined]
            if not data:
                return
            first_output.set()
            os.write(file_descriptor, data)

    stdout_thread = threading.Thread(target=pump, args=(process.stdout, 1), daemon=True)
    stderr_thread = threading.Thread(target=pump, args=(process.stderr, 2), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    received_signal: list[int] = []

    def forward_signal(signum: int, frame: object) -> None:
        del frame
        received_signal.append(signum)
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            return
        except PermissionError:
            try:
                process.send_signal(signum)
            except ProcessLookupError:
                return

    previous_handlers = {
        signum: signal.signal(signum, forward_signal)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    started = time.monotonic()
    timed_out = ""
    try:
        while process.poll() is None:
            elapsed = time.monotonic() - started
            if elapsed >= absolute_deadline:
                timed_out = "absolute invocation deadline"
                break
            if not first_output.is_set() and elapsed >= first_byte_deadline:
                timed_out = "first-byte deadline"
                break
            time.sleep(0.02)
        if timed_out:
            stop_process_group(process)
        else:
            process.wait()
    finally:
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        stdout_thread.join(timeout=1.0)
        stderr_thread.join(timeout=1.0)

    if timed_out:
        print("claude-safe-wrapper: %s exceeded" % timed_out, file=sys.stderr)
        return 124
    if received_signal:
        return 128 + received_signal[-1]
    return process.returncode if process.returncode >= 0 else 128 - process.returncode


def run(argv: Sequence[str], inherited: Optional[Mapping[str, str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude-binary", required=True, type=Path)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--sandbox-root", required=True, type=Path)
    parser.add_argument("--default-model")
    parser.add_argument("--gateway-binary", type=Path)
    parser.add_argument(
        "--enable-isolated-subagents",
        action="store_true",
        help="permit one explicit stream-json subagent test without --bare",
    )
    parser.add_argument("--first-byte-deadline", type=float, default=30.0)
    parser.add_argument("--absolute-deadline", type=float, default=120.0)
    parser.add_argument("claude_args", nargs=argparse.REMAINDER)
    options = parser.parse_args(list(argv))

    sandbox_root = options.sandbox_root.resolve()
    if not sandbox_root.is_dir():
        raise WrapperError("wrapper sandbox root is unavailable")
    if not Path.cwd().resolve().is_relative_to(sandbox_root):
        raise WrapperError("Claude working directory must stay inside the wrapper sandbox")

    binary = options.claude_binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise WrapperError("Claude binary is unavailable or not executable")

    base_url = validate_base_url(options.base_url)
    claude_args = validate_claude_args(options.claude_args, sandbox_root)

    if options.enable_isolated_subagents:
        required_flags = {"--agents", "--forward-subagent-text", "--mcp-config", "--system-prompt"}
        present_flags = {value.split("=", 1)[0] for value in claude_args}
        stream_json = any(
            value == "--output-format=stream-json"
            or (
                value == "--output-format"
                and index + 1 < len(claude_args)
                and claude_args[index + 1] == "stream-json"
            )
            for index, value in enumerate(claude_args)
        )
        if not required_flags.issubset(present_flags) or not stream_json:
            raise WrapperError(
                "isolated subagents require agents, forwarded stream-json, system prompt, and MCP config"
            )

    if options.first_byte_deadline <= 0 or options.absolute_deadline <= 0:
        raise WrapperError("wrapper deadlines must be positive")
    if options.first_byte_deadline > options.absolute_deadline:
        raise WrapperError("first-byte deadline may not exceed the absolute deadline")

    gateway_process: Optional[subprocess.Popen[bytes]] = None
    ready_file: Optional[Path] = None
    if options.gateway_binary is not None:
        gateway_binary = options.gateway_binary.resolve()
        if not gateway_binary.is_file() or not os.access(gateway_binary, os.X_OK):
            raise WrapperError("invocation gateway binary is unavailable")
        gateway_tmp = private_dir(sandbox_root / "claude-wrapper" / "tmp")
        ready_file = gateway_tmp / ("gateway-%s.json" % uuid.uuid4().hex)
        gateway_process = subprocess.Popen(
            [
                str(gateway_binary),
                "--target",
                base_url,
                "--listen",
                "127.0.0.1:0",
                "--ready-file",
                str(ready_file),
                "--connect-timeout",
                "5s",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            base_url = wait_for_gateway(ready_file, gateway_process)
        except Exception:
            stop_process_group(gateway_process)
            raise

    env = build_environment(
        sandbox_root,
        base_url,
        default_model=options.default_model,
        inherited=inherited,
    )
    command = [str(binary), "--print"]
    if not options.enable_isolated_subagents:
        command.append("--bare")
    command.extend(
        [
            "--no-session-persistence",
            "--disable-slash-commands",
            "--permission-mode",
            "dontAsk",
            "--prompt-suggestions",
            "false",
            *claude_args,
        ]
    )
    if gateway_process is None:
        os.execve(str(binary), command, env)
        return 126
    try:
        return run_claude_process(
            command,
            env,
            first_byte_deadline=options.first_byte_deadline,
            absolute_deadline=options.absolute_deadline,
        )
    finally:
        stop_process_group(gateway_process)
        if ready_file is not None:
            try:
                ready_file.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    try:
        return run(sys.argv[1:])
    except (OSError, WrapperError) as exc:
        print("claude-safe-wrapper: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
