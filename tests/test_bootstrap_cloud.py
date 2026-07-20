import importlib.util
import os
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


if __name__ == "__main__":
    unittest.main()
