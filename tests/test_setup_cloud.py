import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup-cloud.sh"


class SetupCloudTests(unittest.TestCase):
    def test_mise_tools_are_pinned_for_non_interactive_shells(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            scripts = project / "scripts"
            fake_bin = Path(directory) / "bin"
            scripts.mkdir(parents=True)
            fake_bin.mkdir()
            shutil.copyfile(SCRIPT, scripts / SCRIPT.name)

            mise_bin = Path(directory) / "mise" / "bin"
            mise_bin.mkdir(parents=True)
            mise_go = mise_bin / "go"
            mise_gofmt = mise_bin / "gofmt"
            self.write_executable(mise_go, "#!/bin/sh\necho 'go version go1.26.5 linux/amd64'\n")
            self.write_executable(mise_gofmt, "#!/bin/sh\nexit 0\n")
            self.write_executable(
                fake_bin / "go",
                "#!/bin/sh\necho 'go version go1.24.3 linux/amd64'\n",
            )
            self.write_executable(
                fake_bin / "mise",
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  'install go@1.26.5'|'use --global go@1.26.5') ;;\n"
                "  'which go --tool=go@1.26.5') printf '%s\\n' \"$FAKE_MISE_GO\" ;;\n"
                "  'install node@22') ;;\n"
                "  \"exec node@22 -- npm install -g @anthropic-ai/claude-code@2.1.215 --prefix $FAKE_CLAUDE_PREFIX --no-audit --no-fund\")\n"
                "    mkdir -p \"$(dirname -- \"$FAKE_PINNED_CLAUDE\")\"\n"
                "    printf '%s\\n' '#!/bin/sh' \"echo '2.1.215 (Claude Code)'\" > \"$FAKE_PINNED_CLAUDE\"\n"
                "    chmod 700 \"$FAKE_PINNED_CLAUDE\"\n"
                "    ;;\n"
                "  *) echo \"unexpected mise arguments: $*\" >&2; exit 2 ;;\n"
                "esac\n",
            )
            self.write_executable(fake_bin / "python3", "#!/bin/sh\nexit 0\n")

            environment = os.environ.copy()
            environment["PATH"] = "%s:/usr/bin:/bin" % fake_bin
            environment["FAKE_MISE_GO"] = str(mise_go)
            environment["FAKE_CLAUDE_PREFIX"] = str(project / ".tools" / "claude")
            environment["FAKE_PINNED_CLAUDE"] = str(
                project / ".tools" / "claude" / "bin" / "claude"
            )
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
            pinned_gofmt = project / ".tools" / "go" / "bin" / "gofmt"
            pinned_claude = project / ".tools" / "claude" / "bin" / "claude"
            self.assertTrue(pinned_go.is_symlink())
            self.assertTrue(pinned_gofmt.is_symlink())
            self.assertTrue(pinned_claude.is_file())
            self.assertEqual(pinned_go.resolve(), mise_go.resolve())
            self.assertEqual(pinned_gofmt.resolve(), mise_gofmt.resolve())
            version = subprocess.run(
                [str(pinned_go), "version"],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            self.assertIn("go1.26.5", version)
            claude_version = subprocess.run(
                [str(pinned_claude), "--version"],
                text=True,
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            self.assertIn("2.1.215", claude_version)

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
