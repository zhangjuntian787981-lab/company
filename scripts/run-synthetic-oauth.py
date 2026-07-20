#!/usr/bin/env python3
"""Run the zero-credential OAuth refresh and persistence matrix."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.prod_guard import compare_snapshots, load_baseline, snapshot  # noqa: E402
from harness.redaction import assert_report_files_safe, find_violations, sanitize  # noqa: E402
from harness.toolchain import resolve_executable  # noqa: E402

VENDOR = ROOT / "vendor" / "CLIProxyAPI-v7.2.80"
PATCH_DIR = ROOT / "patches" / "v7.2.80"
MANIFEST_PATH = PATCH_DIR / "manifest.json"
CANDIDATE_PATH = ROOT / "artifacts" / "cliproxyapi-v7.2.80-candidate"
GO = resolve_executable("COMPAT_GO_BINARY", ROOT / ".tools" / "go" / "bin" / "go", "go")
GIT = resolve_executable("COMPAT_GIT_BINARY", None, "git")

REQUIRED_TESTS = {
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex", "TestRefreshTokensWithRetry_InvalidGrantDoesNotLeakOrRetry"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex", "TestRefreshTokensWithRetry_ServerErrorIsBounded"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex", "TestRefreshTokensWithRetry_TimeoutIsBounded"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex", "TestRefreshTokensWithRetry_429BlocksImmediateReplay"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex", "TestRefreshTokens_DeduplicatesConcurrentRefreshAcrossInstances"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude", "TestRefreshTokensWithRetry_InvalidGrantDoesNotLeakOrRetry"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude", "TestRefreshTokensWithRetry_ServerErrorIsBounded"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude", "TestRefreshTokensWithRetry_TimeoutIsBounded"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude", "TestRefreshTokensWithRetry_429BlocksImmediateReplay"),
    ("github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude", "TestRefreshTokens_DeduplicatesConcurrentRefresh"),
    ("github.com/router-for-me/CLIProxyAPI/v7/sdk/auth", "TestFileTokenStoreOAuthRotationIsAtomicAndPrivate"),
    ("github.com/router-for-me/CLIProxyAPI/v7/sdk/auth", "TestFileTokenStoreOAuthRotationFailureKeepsPreviousFile"),
    ("github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth", "TestManager_ConcurrentStaleTokenRefreshesOnce"),
}


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


def run_checked(command: Sequence[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def source_env(run_dir: Path) -> Dict[str, str]:
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
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "all_proxy": "http://127.0.0.1:1",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "CLIPROXYAPI_COMPAT_TEST": "1",
    }


def apply_manifest(worktree: Path, patches: Sequence[Mapping[str, Any]]) -> None:
    for patch in patches:
        patch_path = PATCH_DIR / str(patch["path"])
        if sha256_file(patch_path) != str(patch["sha256"]):
            raise RuntimeError(f"patch digest mismatch: {patch['id']}")
        run_checked([str(GIT), "-C", str(worktree), "apply", "--check", str(patch_path)])
        run_checked([str(GIT), "-C", str(worktree), "apply", str(patch_path)])
    run_checked([str(GIT), "-C", str(worktree), "diff", "--check"])


def parse_go_test_events(output: str) -> Dict[Tuple[str, str], str]:
    results: Dict[Tuple[str, str], str] = {}
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = str(event.get("Action", ""))
        package = str(event.get("Package", ""))
        test = str(event.get("Test", ""))
        if package and test and action in {"pass", "fail", "skip"}:
            results[(package, test)] = action.upper()
    return results


def expected_tests_pass(results: Mapping[Tuple[str, str], str]) -> bool:
    return all(results.get(test) == "PASS" for test in REQUIRED_TESTS)


def candidate_identity_matches(source_commit: str, patch_sha: str, candidate_sha: str) -> bool:
    reports = sorted((ROOT / ".runs").glob("candidate-build-*/candidate-build.json"), reverse=True)
    for path in reports:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            report.get("overall") == "PASS"
            and report.get("source_commit") == source_commit
            and report.get("patch_set_sha256") == patch_sha
            and report.get("candidate_binary_sha256") == candidate_sha
        ):
            return True
    return False


def write_private(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    os.umask(0o077)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    source_commit = str(manifest["source_commit"])
    patches = manifest["patches"]
    patch_sha = patch_set_sha256(patches)
    candidate_sha = sha256_file(CANDIDATE_PATH) if CANDIDATE_PATH.is_file() else ""
    run_dir = ROOT / ".runs" / f"synthetic-oauth-{utc_stamp()}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, mode=0o700)
    worktree = run_dir / "sandbox" / "worktree"
    worktree.parent.mkdir(parents=True, mode=0o700)

    baseline = load_baseline()
    production_before = snapshot(baseline)
    tests: Dict[Tuple[str, str], str] = {}
    go_return_code = -1
    output_violations = []
    cleanup_ok = False
    error = ""
    try:
        if not GO.is_file():
            raise RuntimeError("pinned Go binary is missing")
        if not candidate_sha:
            raise RuntimeError("candidate binary is missing")
        run_checked([str(GIT), "-C", str(VENDOR), "worktree", "add", "--detach", str(worktree), source_commit])
        apply_manifest(worktree, patches)
        packages = sorted({"./" + package.split("/v7/", 1)[1] for package, _ in REQUIRED_TESTS})
        pattern = "^(" + "|".join(sorted({test for _, test in REQUIRED_TESTS})) + ")$"
        process = subprocess.run(
            [str(GO), "test", "-json", "-count=1", "-run", pattern, *packages],
            cwd=str(worktree),
            env=source_env(run_dir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        go_return_code = process.returncode
        tests = parse_go_test_events(process.stdout)
        output_violations = find_violations((process.stdout + process.stderr).encode("utf-8"))
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if worktree.exists():
            try:
                run_checked([str(GIT), "-C", str(VENDOR), "worktree", "remove", "--force", str(worktree)])
                cleanup_ok = True
            except (OSError, subprocess.CalledProcessError):
                cleanup_ok = False
        else:
            cleanup_ok = True

    production_after = snapshot(baseline)
    production_differences = compare_snapshots(production_before, production_after)
    production_untouched = not production_differences
    tests_pass = go_return_code == 0 and expected_tests_pass(tests)
    identity_match = bool(candidate_sha) and candidate_identity_matches(source_commit, patch_sha, candidate_sha)
    credential_values_persisted = bool(output_violations)
    passed = (
        not error
        and tests_pass
        and identity_match
        and cleanup_ok
        and production_untouched
        and not credential_values_persisted
    )
    case = {
        "id": "cliproxyapi-synthetic-oauth-file-refresh",
        "dimension": "Security",
        "status": "PASS" if passed else "FAIL",
        "hard_failure": False,
        "summary": (
            "synthetic concurrent refresh, bounded failures, and atomic private persistence passed"
            if passed
            else "synthetic OAuth source matrix or evidence identity did not pass"
        ),
        "checks": {
            "required_tests_passed": tests_pass,
            "required_test_count": len(REQUIRED_TESTS),
            "candidate_identity_matched": identity_match,
            "temporary_worktree_removed": cleanup_ok,
            "production_untouched": production_untouched,
            "report_output_redacted": not credential_values_persisted,
        },
    }
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "overall": "PASS" if passed else "FAIL",
        "source_commit": source_commit,
        "patch_set_sha256": patch_sha,
        "candidate_binary_sha256": candidate_sha or None,
        "production_untouched": production_untouched,
        "credential_values_persisted": credential_values_persisted,
        "cases": [case],
        "error": sanitize(error) if error else None,
    }
    report_path = run_dir / "synthetic-oauth.json"
    write_private(report_path, report)
    assert_report_files_safe([report_path])
    print(f"synthetic OAuth report: {report_path}")
    print(f"overall: {report['overall']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
