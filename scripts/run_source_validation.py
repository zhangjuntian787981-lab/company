#!/usr/bin/env python3
"""Validate the complete patched source tree in an isolated worktree."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.redaction import assert_report_files_safe, sanitize  # noqa: E402
from harness.toolchain import resolve_executable  # noqa: E402

VENDOR = ROOT / "vendor" / "CLIProxyAPI-v7.2.80"
PATCH_DIR = ROOT / "patches" / "v7.2.80"
MANIFEST_PATH = PATCH_DIR / "manifest.json"
GO = resolve_executable("COMPAT_GO_BINARY", ROOT / ".tools" / "go" / "bin" / "go", "go")
GOFMT = resolve_executable("COMPAT_GOFMT_BINARY", ROOT / ".tools" / "go" / "bin" / "gofmt", "gofmt")
GIT = resolve_executable("COMPAT_GIT_BINARY", None, "git")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_set_sha256(patches: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for patch in patches:
        digest.update(str(patch["id"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        env=dict(env) if env else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_checked(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    result = run_command(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, list(command))
    return result


def validation_env(run_dir: Path) -> Dict[str, str]:
    sandbox = run_dir / "sandbox"
    paths = {
        "HOME": sandbox / "home",
        "TMPDIR": sandbox / "tmp",
        "GOCACHE": sandbox / "gocache",
    }
    for path in paths.values():
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    return {
        "HOME": str(paths["HOME"]),
        "TMPDIR": str(paths["TMPDIR"]),
        "GOCACHE": str(paths["GOCACHE"]),
        "GOPATH": str(ROOT / ".tools" / "gopath"),
        "GOMODCACHE": str(ROOT / ".tools" / "gomodcache"),
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOFLAGS": "-mod=readonly",
        "PATH": f"{GO.parent}:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONPATH": str(ROOT),
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "all_proxy": "http://127.0.0.1:1",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
    }


def touched_go_paths(patches: Sequence[Mapping[str, Any]], worktree: Path) -> list[Path]:
    paths = {
        worktree / str(relative)
        for patch in patches
        for relative in patch.get("touched_paths", [])
        if str(relative).endswith(".go")
    }
    return sorted(path for path in paths if path.is_file())


def write_private(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(sanitize(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    os.umask(0o077)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    patches = manifest["patches"]
    source_commit = str(manifest["source_commit"])
    run_dir = ROOT / ".runs" / f"source-validation-{utc_stamp()}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, mode=0o700)
    worktree = run_dir / "sandbox" / "worktree"
    env = validation_env(run_dir)
    checks = {
        "python_tests": False,
        "redaction_canary": False,
        "gofmt": False,
        "go_race": False,
        "go_test_all": False,
        "go_build_cleanup": False,
        "temporary_worktree_removed": False,
        "vendor_clean_after": False,
    }
    error = ""
    try:
        if not GO.is_file() or not GOFMT.is_file():
            raise RuntimeError("pinned Go tools are missing")
        if run_checked([str(GIT), "-C", str(VENDOR), "status", "--porcelain"]).stdout.strip():
            raise RuntimeError("fixed vendor checkout is not clean")
        if run_checked([str(GIT), "-C", str(VENDOR), "rev-parse", "HEAD"]).stdout.strip() != source_commit:
            raise RuntimeError("fixed vendor checkout does not match manifest source commit")

        python_tests = run_command(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            cwd=ROOT,
            env=env,
        )
        checks["python_tests"] = python_tests.returncode == 0
        redaction = run_command(
            [sys.executable, "-m", "unittest", "tests.test_redaction"],
            cwd=ROOT,
            env=env,
        )
        checks["redaction_canary"] = redaction.returncode == 0
        if not checks["python_tests"] or not checks["redaction_canary"]:
            raise RuntimeError("Python harness or redaction tests failed")

        run_checked([str(GIT), "-C", str(VENDOR), "worktree", "add", "--detach", str(worktree), source_commit])
        for patch in patches:
            patch_path = PATCH_DIR / str(patch["path"])
            if sha256_file(patch_path) != str(patch["sha256"]):
                raise RuntimeError(f"patch digest mismatch: {patch['id']}")
            run_checked([str(GIT), "-C", str(worktree), "apply", "--check", str(patch_path)])
            run_checked([str(GIT), "-C", str(worktree), "apply", str(patch_path)])
        run_checked([str(GIT), "-C", str(worktree), "diff", "--check"])

        go_files = touched_go_paths(patches, worktree)
        gofmt = run_command([str(GOFMT), "-l", *[str(path) for path in go_files]], cwd=worktree, env=env)
        checks["gofmt"] = gofmt.returncode == 0 and not gofmt.stdout.strip()

        race = run_command(
            [
                str(GO),
                "test",
                "-race",
                "./internal/translator/codex/claude",
                "./internal/claudegateway",
                "./sdk/cliproxy/auth",
            ],
            cwd=worktree,
            env=env,
        )
        checks["go_race"] = race.returncode == 0
        all_tests = run_command([str(GO), "test", "./..."], cwd=worktree, env=env)
        checks["go_test_all"] = all_tests.returncode == 0

        build_output = run_dir / "test-output"
        build = run_command(
            [str(GO), "build", "-trimpath", "-buildvcs=false", "-o", str(build_output), "./cmd/server"],
            cwd=worktree,
            env=env,
        )
        if build.returncode == 0 and build_output.is_file():
            build_output.unlink()
        checks["go_build_cleanup"] = build.returncode == 0 and not build_output.exists()
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if worktree.exists():
            removed = run_command(
                [str(GIT), "-C", str(VENDOR), "worktree", "remove", "--force", str(worktree)]
            )
            checks["temporary_worktree_removed"] = removed.returncode == 0
        else:
            checks["temporary_worktree_removed"] = True
        clean = run_command([str(GIT), "-C", str(VENDOR), "status", "--porcelain"])
        checks["vendor_clean_after"] = clean.returncode == 0 and not clean.stdout.strip()

    passed = not error and all(checks.values())
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "overall": "PASS" if passed else "FAIL",
        "source_commit": source_commit,
        "patch_set_sha256": patch_set_sha256(patches),
        "checks": checks,
        "error": error or None,
    }
    report_path = run_dir / "source-validation.json"
    write_private(report_path, report)
    assert_report_files_safe([report_path])
    print(f"source validation report: {report_path}")
    print(f"overall: {report['overall']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
