import os
import tempfile
import unittest
from pathlib import Path

from harness.runner import (
    CLAUDE_CLI_USER_AGENT,
    CLAUDE_MODEL_ALIASES,
    LocalHttpClient,
    catalog_model_ids,
    claude_headers,
    isolated_environment,
    patch_set_sha256,
)


class RunnerTests(unittest.TestCase):
    def test_patch_set_identity_depends_on_manifest_order(self):
        patches = [
            {"id": "a", "path": "a.patch", "sha256": "1" * 64},
            {"id": "b", "path": "b.patch", "sha256": "2" * 64},
        ]
        self.assertNotEqual(patch_set_sha256(patches), patch_set_sha256(list(reversed(patches))))

    def test_network_guard_allows_loopback_and_denies_production(self):
        LocalHttpClient.validate_url("http://127.0.0.1:54321/v1/responses")
        with self.assertRaises(ValueError):
            LocalHttpClient.validate_url("https://example.com/v1/responses")
        with self.assertRaises(ValueError):
            LocalHttpClient.validate_url("http://127.0.0.1:8317/v1/models")

    def test_isolated_environment_replaces_home_xdg_tmp_and_proxies(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            old = os.environ.get("HTTPS_PROXY")
            os.environ["HTTPS_PROXY"] = "http://not-allowed.invalid"
            try:
                env = isolated_environment(run_dir)
            finally:
                if old is None:
                    os.environ.pop("HTTPS_PROXY", None)
                else:
                    os.environ["HTTPS_PROXY"] = old
            self.assertTrue(env["HOME"].startswith(str(run_dir)))
            self.assertTrue(env["TMPDIR"].startswith(str(run_dir)))
            self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:9")
            self.assertEqual(env["ALL_PROXY"], "http://127.0.0.1:9")
            self.assertEqual(env["NO_PROXY"], "127.0.0.1,localhost")

    def test_claude_headers_identify_supported_cli_version(self):
        headers = claude_headers()
        self.assertEqual(headers["Anthropic-Version"], "2023-06-01")
        self.assertEqual(headers["User-Agent"], CLAUDE_CLI_USER_AGENT)
        self.assertEqual(CLAUDE_CLI_USER_AGENT, "claude-cli/2.1.215")

    def test_catalog_model_ids_preserves_fixed_aliases(self):
        payload = {"data": [{"id": model_id} for model_id in CLAUDE_MODEL_ALIASES]}
        self.assertEqual(catalog_model_ids(payload), list(CLAUDE_MODEL_ALIASES))

    def test_catalog_model_ids_rejects_malformed_catalog(self):
        with self.assertRaises(AssertionError):
            catalog_model_ids({"data": {}})
        with self.assertRaises(AssertionError):
            catalog_model_ids({"data": [{"id": 123}]})


if __name__ == "__main__":
    unittest.main()
