import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup-cloud.sh"


class SetupCloudTests(unittest.TestCase):
    def test_mise_go_is_pinned_for_non_interactive_shells(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            scripts = project / "scripts"
            fake_bin = Path(directory) / "bin"
            scripts.mkdir(parents=True)
            fake_bin.mkdir()
            shutil.copyfile(SCRIPT, scripts / SCRIPT.name)

            mise_go = Path(directory) / "mise-go"
            self.write_executable(mise_go, "#!/bin/sh\necho 'go version go1.26.5 linux/amd64'\n")
            self.write_executable(
                fake_bin / "go",
                "#!/bin/sh\necho 'go version go1.24.3 linux/amd64'\n",
            )
            self.write_executable(
                fake_bin / "mise",
                "#!/bin/sh\n"
                "if [ \"$1\" = which ]; then printf '%s\\n' \"$FAKE_MISE_GO\"; fi\n",
            )
            self.write_executable(
                fake_bin / "claude",
                "#!/bin/sh\necho '2.1.215 (Claude Code)'\n",
            )
            self.write_executable(fake_bin / "python3", "#!/bin/sh\nexit 0\n")

            environment = os.environ.copy()
            environment["PATH"] = "%s:/usr/bin:/bin" % fake_bin
            environment["FAKE_MISE_GO"] = str(mise_go)
            result = subprocess.run(
                ["/bin/sh", str(scripts / SCRIPT.name)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            pinned_go = project / ".tools" / "go" / "bin" / "go"
            self.assertTrue(pinned_go.is_symlink())
            self.assertEqual(pinned_go.resolve(), mise_go.resolve())
            version = subprocess.run(
                [str(pinned_go), "version"],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            self.assertIn("go1.26.5", version)

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
