#!/usr/bin/env python3
"""Build the pinned CLIProxyAPI candidate twice from the patch manifest."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
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
CONTRACTS_PATH = PATCH_DIR / "contracts.json"
GO = resolve_executable("COMPAT_GO_BINARY", ROOT / ".tools" / "go" / "bin" / "go", "go")
GIT = resolve_executable("COMPAT_GIT_BINARY", None, "git")
CANDIDATE_PATH = ROOT / "artifacts" / "cliproxyapi-v7.2.80-candidate"
GATEWAY_PATH = ROOT / "artifacts" / "claude-budget-gateway-v7.2.80-candidate"


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


def run_checked(
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
        check=True,
    )


def git_output(*args: str, cwd: Path = VENDOR) -> str:
    return run_checked([str(GIT), "-C", str(cwd), *args]).stdout.strip()


def build_env(run_dir: Path, build_id: str) -> Dict[str, str]:
    sandbox = run_dir / "sandbox" / build_id
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
        "CGO_ENABLED": "0",
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
    }


def apply_manifest(worktree: Path, patches: Sequence[Mapping[str, Any]]) -> None:
    for patch in patches:
        patch_path = PATCH_DIR / str(patch["path"])
        if sha256_file(patch_path) != str(patch["sha256"]):
            raise RuntimeError(f"patch digest mismatch: {patch['id']}")
        run_checked([str(GIT), "-C", str(worktree), "apply", "--check", str(patch_path)])
        run_checked([str(GIT), "-C", str(worktree), "apply", str(patch_path)])
    run_checked([str(GIT), "-C", str(worktree), "diff", "--check"])


def build_once(
    run_dir: Path,
    build_id: str,
    source_commit: str,
    patches: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    worktree = run_dir / "sandbox" / build_id / "worktree"
    output_dir = run_dir / build_id
    output_dir.mkdir(parents=True, mode=0o700)
    run_checked([str(GIT), "-C", str(VENDOR), "worktree", "add", "--detach", str(worktree), source_commit])
    apply_manifest(worktree, patches)
    env = build_env(run_dir, build_id)
    commands = {
        "candidate": [
            str(GO),
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-buildid=",
            "-o",
            str(output_dir / "cliproxyapi"),
            "./cmd/server",
        ],
        "gateway": [
            str(GO),
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-buildid=",
            "-o",
            str(output_dir / "claude-budget-gateway"),
            "./cmd/claude-budget-gateway",
        ],
    }
    for command in commands.values():
        run_checked(command, cwd=worktree, env=env)
    return {
        "worktree": worktree,
        "candidate_path": output_dir / "cliproxyapi",
        "gateway_path": output_dir / "claude-budget-gateway",
        "candidate_sha256": sha256_file(output_dir / "cliproxyapi"),
        "gateway_sha256": sha256_file(output_dir / "claude-budget-gateway"),
    }


def reproducible(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    return (
        first.get("candidate_sha256") == second.get("candidate_sha256")
        and first.get("gateway_sha256") == second.get("gateway_sha256")
    )


def write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    os.umask(0o077)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    patches = manifest["patches"]
    source_commit = str(manifest["source_commit"])
    patch_sha = patch_set_sha256(patches)
    run_dir = ROOT / ".runs" / f"candidate-build-{utc_stamp()}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, mode=0o700)

    results = []
    worktrees = []
    cleanup_ok = True
    error = ""
    vendor_clean_before = False
    vendor_clean_after = False
    published = False
    try:
        if not GO.is_file():
            raise RuntimeError(f"pinned Go binary missing: {GO}")
        vendor_clean_before = not bool(git_output("status", "--porcelain"))
        if not vendor_clean_before:
            raise RuntimeError("fixed vendor checkout is not clean")
        if git_output("rev-parse", "HEAD") != source_commit:
            raise RuntimeError("fixed vendor checkout does not match manifest source commit")
        for build_id in ("build-a", "build-b"):
            worktrees.append(run_dir / "sandbox" / build_id / "worktree")
            result = build_once(run_dir, build_id, source_commit, patches)
            results.append(result)
        if not reproducible(results[0], results[1]):
            raise RuntimeError("candidate or gateway build hashes differ")
        CANDIDATE_PATH.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        shutil.copyfile(results[0]["candidate_path"], CANDIDATE_PATH)
        shutil.copyfile(results[0]["gateway_path"], GATEWAY_PATH)
        os.chmod(CANDIDATE_PATH, 0o755)
        os.chmod(GATEWAY_PATH, 0o755)
        published = (
            sha256_file(CANDIDATE_PATH) == results[0]["candidate_sha256"]
            and sha256_file(GATEWAY_PATH) == results[0]["gateway_sha256"]
        )
        if not published:
            raise RuntimeError("published artifact digest mismatch")
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        for worktree in reversed(worktrees):
            try:
                run_checked([str(GIT), "-C", str(VENDOR), "worktree", "remove", "--force", str(worktree)])
            except (OSError, subprocess.CalledProcessError):
                cleanup_ok = False
        vendor_clean_after = not bool(git_output("status", "--porcelain"))

    is_reproducible = len(results) == 2 and reproducible(results[0], results[1])
    passed = not error and cleanup_ok and vendor_clean_after and published and is_reproducible
    candidate_sha = results[0]["candidate_sha256"] if results else None
    gateway_sha = results[0]["gateway_sha256"] if results else None
    report = sanitize(
        {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "overall": "PASS" if passed else "FAIL",
            "source_commit": source_commit,
            "patch_set_sha256": patch_sha,
            "manifest_sha256": sha256_file(MANIFEST_PATH),
            "contracts_sha256": sha256_file(CONTRACTS_PATH),
            "candidate_binary_sha256": candidate_sha,
            "gateway_binary_sha256": gateway_sha,
            "go_version": run_checked([str(GO), "version"], env=build_env(run_dir, "metadata")).stdout.strip(),
            "builds": [
                {
                    "id": f"build-{index + 1}",
                    "candidate_sha256": result["candidate_sha256"],
                    "gateway_sha256": result["gateway_sha256"],
                }
                for index, result in enumerate(results)
            ],
            "checks": {
                "vendor_clean_before": vendor_clean_before,
                "manifest_patches_applied": len(results) == 2,
                "reproducible_build": is_reproducible,
                "artifacts_published": published,
                "temporary_worktrees_removed": cleanup_ok,
                "vendor_clean_after": vendor_clean_after,
            },
            "error": error or None,
        }
    )
    report_path = run_dir / "candidate-build.json"
    write_private(report_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    assert_report_files_safe([report_path])
    print(f"candidate build report: {report_path}")
    print(f"overall: {report['overall']}")
    if candidate_sha:
        print(f"candidate sha256: {candidate_sha}")
    if gateway_sha:
        print(f"gateway sha256: {gateway_sha}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
