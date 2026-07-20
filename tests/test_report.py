import json
import os
import tempfile
import unittest
from pathlib import Path

from harness.redaction import DEFAULT_CANARIES, assert_report_files_safe
from harness.report import REPORT_FILES, generate_report


class ReportTests(unittest.TestCase):
    def test_all_artifacts_are_generated_private_and_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            cases = [
                {
                    "id": "canary",
                    "dimension": "Security",
                    "status": "PASS",
                    "summary": "handled " + DEFAULT_CANARIES[3],
                    "duration_seconds": 0.01,
                    "hard_failure": False,
                    "response_body": DEFAULT_CANARIES[3],
                },
                {
                    "id": "future",
                    "dimension": "Model/Context",
                    "status": "UNVERIFIED",
                    "summary": "deferred",
                    "duration_seconds": 0,
                    "hard_failure": False,
                },
            ]
            rating = generate_report(
                output,
                {"run_id": "test", "credential": DEFAULT_CANARIES[0]},
                cases,
                [{"status": "ok", "request_body": DEFAULT_CANARIES[3]}],
                True,
                identity={
                    "source_commit": "source",
                    "patch_set_sha256": "patches",
                    "candidate_binary_sha256": "candidate",
                    "gateway_binary_sha256": "gateway",
                },
            )
            self.assertEqual(rating["overall"], "CONDITIONAL")
            self.assertEqual(rating["candidate_binary_sha256"], "candidate")
            paths = [output / name for name in REPORT_FILES]
            self.assertTrue(all(path.exists() for path in paths))
            self.assertTrue(all((os.stat(path).st_mode & 0o077) == 0 for path in paths))
            assert_report_files_safe(paths)


if __name__ == "__main__":
    unittest.main()
