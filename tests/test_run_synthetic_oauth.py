import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-synthetic-oauth.py"
SPEC = importlib.util.spec_from_file_location("run_synthetic_oauth", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SyntheticOAuthRunnerTests(unittest.TestCase):
    def test_source_environment_is_offline_and_does_not_inherit_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"SYNTHETIC_REAL_TOKEN": "must-not-leak"}):
                env = MODULE.source_env(Path(directory))
        self.assertNotIn("SYNTHETIC_REAL_TOKEN", env)
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:1")

    def test_expected_tests_require_every_named_test_to_pass(self):
        results = {test: "PASS" for test in MODULE.REQUIRED_TESTS}
        self.assertTrue(MODULE.expected_tests_pass(results))
        results[next(iter(MODULE.REQUIRED_TESTS))] = "FAIL"
        self.assertFalse(MODULE.expected_tests_pass(results))

    def test_candidate_identity_requires_matching_build_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / ".runs" / "candidate-build-20260720T000000Z-fixture"
            report_dir.mkdir(parents=True)
            (report_dir / "candidate-build.json").write_text(
                json.dumps(
                    {
                        "overall": "PASS",
                        "source_commit": "commit",
                        "patch_set_sha256": "patch",
                        "candidate_binary_sha256": "candidate",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(MODULE, "ROOT", root):
                self.assertTrue(MODULE.candidate_identity_matches("commit", "patch", "candidate"))
                self.assertFalse(MODULE.candidate_identity_matches("commit", "other", "candidate"))


if __name__ == "__main__":
    unittest.main()
