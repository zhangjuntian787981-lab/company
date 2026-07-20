import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_source_validation.py"
SPEC = importlib.util.spec_from_file_location("run_source_validation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class SourceValidationTests(unittest.TestCase):
    def test_validation_environment_is_offline_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            env = MODULE.validation_env(Path(directory))
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:1")
        self.assertNotIn("ANTHROPIC_API_KEY", env)

    def test_touched_go_paths_are_unique_and_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.go").write_text("package a\n", encoding="utf-8")
            patches = [
                {"touched_paths": ["a.go", "missing.go", "note.txt"]},
                {"touched_paths": ["a.go"]},
            ]
            self.assertEqual(MODULE.touched_go_paths(patches, root), [root / "a.go"])


if __name__ == "__main__":
    unittest.main()
