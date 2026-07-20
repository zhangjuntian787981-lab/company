import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap-cloud.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_cloud", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class BootstrapCloudTests(unittest.TestCase):
    def test_dependency_environment_does_not_copy_unrelated_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(MODULE, "ROOT", Path(directory)):
                with mock.patch.dict(os.environ, {"REAL_API_TOKEN": "must-not-leak"}):
                    environment = MODULE.dependency_environment()
        self.assertNotIn("REAL_API_TOKEN", environment)
        self.assertEqual(environment["GOENV"], "off")
        self.assertEqual(environment["GOTOOLCHAIN"], "local")

    def test_new_no_checkout_clone_becomes_clean_pinned_vendor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.com"], check=True)
            (source / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-q", "-m", "fixture"], check=True)
            commit = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            vendor = root / "vendor"
            with mock.patch.object(MODULE, "VENDOR", vendor):
                MODULE.prepare_vendor(str(source), commit)
                self.assertEqual(MODULE.git_output("rev-parse", "HEAD"), commit)
                self.assertEqual(MODULE.git_output("status", "--porcelain"), "")


if __name__ == "__main__":
    unittest.main()
