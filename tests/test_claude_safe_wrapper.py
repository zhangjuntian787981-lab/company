from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "claude-safe-wrapper.py"


class ClaudeSafeWrapperTests(unittest.TestCase):
    def make_fake_claude(self, root: Path) -> tuple[Path, Path]:
        capture = root / "capture.json"
        binary = root / "fake-claude"
        binary.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            f"Path({str(capture)!r}).write_text(json.dumps({{'argv': sys.argv, 'env': dict(os.environ)}}, sort_keys=True), encoding='utf-8')\n"
            "print(json.dumps({'is_error': False, 'result': 'fake'}))\n",
            encoding="utf-8",
        )
        os.chmod(binary, 0o700)
        return binary, capture

    def make_fake_gateway(self, root: Path) -> tuple[Path, Path]:
        pid_file = root / "gateway.pid"
        binary = root / "fake-gateway"
        binary.write_text(
            "#!/usr/bin/python3\n"
            "import argparse, json, os, signal, time\n"
            "from pathlib import Path\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_argument('--target')\n"
            "parser.add_argument('--listen')\n"
            "parser.add_argument('--ready-file')\n"
            "parser.add_argument('--connect-timeout')\n"
            "args = parser.parse_args()\n"
            f"Path({str(pid_file)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
            "Path(args.ready_file).write_text(json.dumps({'base_url': 'http://127.0.0.1:19002'}), encoding='utf-8')\n"
            "os.chmod(args.ready_file, 0o600)\n"
            "signal.signal(signal.SIGTERM, lambda *_: raise_exit())\n"
            "def raise_exit():\n"
            "    raise SystemExit(0)\n"
            "while True:\n"
            "    time.sleep(1)\n",
            encoding="utf-8",
        )
        os.chmod(binary, 0o700)
        return binary, pid_file

    def run_wrapper(
        self,
        sandbox: Path,
        binary: Path,
        *claude_args: str,
        base_url: str = "http://127.0.0.1:19001",
        default_model: str | None = None,
        gateway_binary: Path | None = None,
        enable_isolated_subagents: bool = False,
        first_byte_deadline: float | None = None,
        absolute_deadline: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        workspace = sandbox / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        mcp = sandbox / "mcp.json"
        mcp.write_text('{"mcpServers":{}}\n', encoding="utf-8")
        command = [
            sys.executable,
            str(WRAPPER),
            "--claude-binary",
            str(binary),
            "--base-url",
            base_url,
            "--sandbox-root",
            str(sandbox),
        ]
        if default_model is not None:
            command.extend(["--default-model", default_model])
        if gateway_binary is not None:
            command.extend(["--gateway-binary", str(gateway_binary)])
        if enable_isolated_subagents:
            command.append("--enable-isolated-subagents")
        if first_byte_deadline is not None:
            command.extend(["--first-byte-deadline", str(first_byte_deadline)])
        if absolute_deadline is not None:
            command.extend(["--absolute-deadline", str(absolute_deadline)])
        command.extend(["--", *claude_args])
        env = dict(os.environ)
        env.update(
            {
                "ANTHROPIC_API_KEY": "real-key-must-not-survive",
                "ANTHROPIC_AUTH_TOKEN": "real-token-must-not-survive",
                "ANTHROPIC_PROFILE": "real-profile-must-not-survive",
                "AWS_SECRET_ACCESS_KEY": "real-cloud-secret-must-not-survive",
                "CLAUDE_CODE_USE_BEDROCK": "1",
            }
        )
        return subprocess.run(
            command,
            cwd=workspace,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

    def test_wrapper_executes_with_synthetic_isolated_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)
            mcp = sandbox / "mcp.json"
            mcp.write_text('{"mcpServers":{}}\n', encoding="utf-8")

            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "json",
                "--mcp-config",
                str(mcp),
                "synthetic prompt",
                default_model="claude-sonnet-5",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            captured = json.loads(capture.read_text(encoding="utf-8"))
            argv = captured["argv"]
            env = captured["env"]
            self.assertIn("--bare", argv)
            self.assertIn("--no-session-persistence", argv)
            self.assertIn("--strict-mcp-config", argv)
            self.assertEqual(env["ANTHROPIC_API_KEY"], "compat-synthetic-client-key")
            self.assertEqual(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:19001")
            self.assertEqual(env["ANTHROPIC_MODEL"], "claude-sonnet-5")
            self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
            self.assertNotIn("ANTHROPIC_PROFILE", env)
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
            self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", env)
            self.assertTrue(Path(env["HOME"]).is_relative_to(sandbox.resolve()))
            self.assertTrue(Path(env["CLAUDE_CONFIG_DIR"]).is_relative_to(sandbox.resolve()))

    def test_wrapper_opt_in_enables_agents_without_bare_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)

            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "stream-json",
                "--forward-subagent-text",
                "--system-prompt",
                "synthetic system prompt",
                "--agents",
                '{"reviewer":{"description":"synthetic","prompt":"synthetic"}}',
                "--mcp-config",
                str(sandbox / "mcp.json"),
                "synthetic prompt",
                enable_isolated_subagents=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            captured = json.loads(capture.read_text(encoding="utf-8"))
            self.assertNotIn("--bare", captured["argv"])
            self.assertIn("--forward-subagent-text", captured["argv"])

    def test_wrapper_rejects_incomplete_subagent_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)

            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "stream-json",
                "synthetic prompt",
                enable_isolated_subagents=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("isolated subagents require", result.stderr)
            self.assertFalse(capture.exists())

    def test_wrapper_owns_one_gateway_for_the_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)
            gateway, pid_file = self.make_fake_gateway(root)

            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "json",
                "synthetic prompt",
                gateway_binary=gateway,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            captured = json.loads(capture.read_text(encoding="utf-8"))
            self.assertEqual(captured["env"]["ANTHROPIC_BASE_URL"], "http://127.0.0.1:19002")
            gateway_pid = int(pid_file.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(gateway_pid, 0)

    def test_wrapper_enforces_first_byte_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary = root / "silent-claude"
            binary.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(5)\n", encoding="utf-8")
            os.chmod(binary, 0o700)
            gateway, _ = self.make_fake_gateway(root)

            result = self.run_wrapper(
                sandbox,
                binary,
                "synthetic prompt",
                gateway_binary=gateway,
                first_byte_deadline=0.1,
                absolute_deadline=1.0,
            )

            self.assertEqual(result.returncode, 124)
            self.assertIn("first-byte deadline", result.stderr)

    def test_sigterm_preserves_exit_status_and_cleans_gateway(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            workspace = sandbox / "workspace"
            workspace.mkdir(parents=True)
            child_pid_file = root / "claude.pid"
            binary = root / "slow-claude"
            binary.write_text(
                "#!/usr/bin/python3\n"
                "import os, time\n"
                "from pathlib import Path\n"
                f"Path({str(child_pid_file)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
                "print('ready', flush=True)\n"
                "while True:\n"
                "    time.sleep(1)\n",
                encoding="utf-8",
            )
            os.chmod(binary, 0o700)
            gateway, gateway_pid_file = self.make_fake_gateway(root)
            command = [
                sys.executable,
                str(WRAPPER),
                "--claude-binary",
                str(binary),
                "--base-url",
                "http://127.0.0.1:19001",
                "--sandbox-root",
                str(sandbox),
                "--gateway-binary",
                str(gateway),
                "--",
                "synthetic prompt",
            ]
            process = subprocess.Popen(
                command,
                cwd=workspace,
                env=dict(os.environ),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(process.stdout.readline().strip(), "ready")
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)

            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr)
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            gateway_pid = int(gateway_pid_file.read_text(encoding="utf-8"))

            def process_exists(pid: int) -> bool:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return False
                return True

            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and (
                process_exists(child_pid) or process_exists(gateway_pid)
            ):
                time.sleep(0.02)
            self.assertFalse(process_exists(child_pid))
            self.assertFalse(process_exists(gateway_pid))

    def test_wrapper_rejects_production_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)
            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "json",
                "synthetic prompt",
                base_url="http://127.0.0.1:8317",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("production port 8317", result.stderr)
            self.assertFalse(capture.exists())

    def test_wrapper_rejects_mcp_config_outside_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)
            outside = root / "outside-mcp.json"
            outside.write_text('{"mcpServers":{}}\n', encoding="utf-8")
            result = self.run_wrapper(
                sandbox,
                binary,
                "--output-format",
                "json",
                "--mcp-config",
                str(outside),
                "synthetic prompt",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("inside the wrapper sandbox", result.stderr)
            self.assertFalse(capture.exists())

    def test_wrapper_rejects_external_features(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sandbox = root / "sandbox"
            sandbox.mkdir()
            binary, capture = self.make_fake_claude(root)
            result = self.run_wrapper(
                sandbox,
                binary,
                "--plugin-url",
                "https://example.invalid/plugin.zip",
                "synthetic prompt",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--plugin-url", result.stderr)
            self.assertFalse(capture.exists())


if __name__ == "__main__":
    unittest.main()
