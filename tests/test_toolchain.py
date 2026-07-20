import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.toolchain import resolve_executable


class ToolchainTests(unittest.TestCase):
    def test_environment_override_wins(self):
        with mock.patch.dict(os.environ, {"COMPAT_TEST_BINARY": "/custom/tool"}):
            self.assertEqual(
                resolve_executable("COMPAT_TEST_BINARY", Path("/preferred"), "tool"),
                Path("/custom/tool"),
            )

    def test_preferred_existing_binary_wins_before_path(self):
        with tempfile.TemporaryDirectory() as directory:
            preferred = Path(directory) / "tool"
            preferred.touch()
            with mock.patch("harness.toolchain.shutil.which", return_value="/path/tool"):
                self.assertEqual(resolve_executable("UNSET_TEST_BINARY", preferred, "tool"), preferred)

    def test_path_is_used_when_preferred_is_missing(self):
        with mock.patch("harness.toolchain.shutil.which", return_value="/path/tool"):
            self.assertEqual(
                resolve_executable("UNSET_TEST_BINARY", Path("/missing/tool"), "tool"),
                Path("/path/tool"),
            )


if __name__ == "__main__":
    unittest.main()
