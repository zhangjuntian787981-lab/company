import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "run-claude-code-e2e.py"
SPEC = importlib.util.spec_from_file_location("run_claude_code_e2e", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClaudeCodeE2ETests(unittest.TestCase):
    def test_stream_json_input_has_one_user_record_per_turn(self) -> None:
        payload = MODULE.stream_json_input(["first", "second"]).decode("utf-8")
        records = [json.loads(line) for line in payload.splitlines()]

        self.assertEqual([record["type"] for record in records], ["user", "user"])
        self.assertEqual(records[0]["message"]["content"][0]["text"], "first")
        self.assertEqual(records[1]["message"]["content"][0]["text"], "second")

    def test_report_identity_uses_manifest_and_passed_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            gateway = root / "gateway"
            candidate.write_bytes(b"candidate-under-test")
            gateway.write_bytes(b"gateway-under-test")

            identity = MODULE.e2e_report_identity(candidate, gateway)
            manifest = json.loads(
                (REPO_ROOT / "patches" / "v7.2.80" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertEqual(identity["source_commit"], manifest["source_commit"])
            self.assertEqual(
                identity["candidate_binary_sha256"],
                hashlib.sha256(candidate.read_bytes()).hexdigest(),
            )
            self.assertEqual(
                identity["gateway_binary_sha256"],
                hashlib.sha256(gateway.read_bytes()).hexdigest(),
            )
            self.assertEqual(len(identity["patch_set_sha256"]), 64)
            datetime.fromisoformat(identity["generated_at"].replace("Z", "+00:00"))


if __name__ == "__main__":
    unittest.main()
