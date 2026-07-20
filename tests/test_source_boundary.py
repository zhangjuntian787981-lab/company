import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-v7.2.80-boundary-tests.py"
SPEC = importlib.util.spec_from_file_location("source_boundary_runner", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SourceBoundaryTests(unittest.TestCase):
    def test_contract_classification_uses_test_results(self):
        document = {
            "contracts": [
                {
                    "id": "passing",
                    "evidence": [{"package": "pkg", "test": "TestPass"}],
                },
                {
                    "id": "failing",
                    "evidence": [{"package": "pkg", "test": "TestFail"}],
                },
                {
                    "id": "missing",
                    "evidence": [{"package": "pkg", "test": "TestMissing"}],
                },
            ]
        }
        results = MODULE.classify_contracts(
            document,
            {("pkg", "TestPass"): "PASS", ("pkg", "TestFail"): "FAIL"},
        )
        self.assertEqual(
            {item["id"]: item["result"] for item in results},
            {"passing": "PASS", "failing": "FAIL", "missing": "UNVERIFIED"},
        )

    def test_source_environment_is_offline_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"COMPAT_FAKE_TOKEN": "synthetic-secret"}):
                env = MODULE.source_env(Path(directory))
        self.assertNotIn("COMPAT_FAKE_TOKEN", env)
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["GOSUMDB"], "off")
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:1")
        self.assertIn("127.0.0.1", env["NO_PROXY"])
        self.assertEqual(env["CLIPROXYAPI_COMPAT_TEST"], "1")

    def test_nonzero_supplemental_exit_fails_boundary(self):
        self.assertTrue(
            MODULE.boundary_failed(
                stage_error="",
                cleanup_ok=True,
                supplemental_return_code=1,
                contract_result_counts={"PASS": 3},
            )
        )

    def test_patch_manifest_digest_and_classifications_are_valid(self):
        manifest = json.loads((ROOT / "patches" / "v7.2.80" / "manifest.json").read_text())
        self.assertEqual(
            manifest["source_repository"],
            "https://github.com/router-for-me/CLIProxyAPI.git",
        )
        patches = manifest["patches"]
        self.assertTrue(patches)
        for patch_entry in patches:
            patch_path = ROOT / "patches" / "v7.2.80" / patch_entry["path"]
            digest = hashlib.sha256(patch_path.read_bytes()).hexdigest()
            self.assertEqual(digest, patch_entry["sha256"])
        expected_patch_set = MODULE.patch_set_sha256(patches)
        self.assertEqual(len(expected_patch_set), 64)

        contracts = json.loads((ROOT / "patches" / "v7.2.80" / "contracts.json").read_text())
        allowed = {
            "SUPPORTED",
            "TRANSLATED",
            "DROPPED_WITH_WARNING",
            "DROPPED_SILENTLY",
            "REJECTED",
        }
        self.assertTrue(contracts["contracts"])
        self.assertTrue(all(item["classification"] in allowed for item in contracts["contracts"]))


if __name__ == "__main__":
    unittest.main()
