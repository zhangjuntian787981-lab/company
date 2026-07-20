import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.prod_guard import compare_known, compare_snapshots, load_baseline, matched_summary


class ProductionGuardTests(unittest.TestCase):
    def test_snapshot_difference_is_detected(self):
        before = {
            "port": 8317,
            "listener_pids": [30082],
            "launchd_label": "com.tristian.cliproxyapi",
            "launchd_label_loaded": True,
            "files": [{"path": "/config", "sha256": "a", "mode": "0600"}],
        }
        after = dict(before)
        after["listener_pids"] = [99999]
        self.assertIn("listener_pids", compare_snapshots(before, after))

    def test_known_hash_mismatch_is_detected(self):
        baseline = {
            "production": {"pid": 30082, "launchd_label": "label"},
            "files": [{"id": "config", "path": "/config", "sha256": "expected"}],
        }
        current = {
            "listener_pids": [30082],
            "launchd_label": "label",
            "launchd_label_loaded": True,
            "files": [{"path": "/config", "sha256": "different"}],
        }
        self.assertEqual(compare_known(baseline, current), ["file-sha256:config"])

    def test_absent_baseline_rejects_listener_or_file(self):
        baseline = {
            "mode": "absent",
            "production": {"port": 8317},
            "files": [{"id": "config", "path": "/config"}],
        }
        current = {
            "mode": "absent",
            "listener_pids": [100],
            "files": [{"path": "/config", "exists": True}],
        }
        self.assertEqual(
            compare_known(baseline, current),
            ["production-listener-present", "file-present:config"],
        )

    def test_environment_selects_relative_cloud_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "cloud.json"
            baseline.write_text('{"mode":"absent"}', encoding="utf-8")
            with mock.patch("harness.prod_guard.REPO_ROOT", root):
                with mock.patch.dict(os.environ, {"COMPAT_PROD_BASELINE": "cloud.json"}):
                    self.assertEqual(load_baseline(), {"mode": "absent"})

    def test_absent_baseline_summary_is_truthful(self):
        self.assertIn("were absent", matched_summary({"mode": "absent"}))


if __name__ == "__main__":
    unittest.main()
