#!/usr/bin/env python3
"""Prepare the ignored pinned upstream checkout and Go module cache."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.toolchain import resolve_executable  # noqa: E402

MANIFEST_PATH = ROOT / "patches" / "v7.2.80" / "manifest.json"
VENDOR = ROOT / "vendor" / "CLIProxyAPI-v7.2.80"
GO = resolve_executable("COMPAT_GO_BINARY", ROOT / ".tools" / "go" / "bin" / "go", "go")
GIT = resolve_executable("COMPAT_GIT_BINARY", None, "git")


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


def git_output(*arguments: str) -> str:
    return run_checked([str(GIT), "-C", str(VENDOR), *arguments]).stdout.strip()


def dependency_environment() -> dict[str, str]:
    paths = {
        "gopath": ROOT / ".tools" / "gopath",
        "gomodcache": ROOT / ".tools" / "gomodcache",
        "gocache": ROOT / ".gocache",
    }
    for path in paths.values():
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GOPATH": str(paths["gopath"]),
        "GOMODCACHE": str(paths["gomodcache"]),
        "GOCACHE": str(paths["gocache"]),
        "GOENV": "off",
        "GOTOOLCHAIN": "local",
    }
    for name in (
        "HOME",
        "TMPDIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def prepare_vendor(repository: str, source_commit: str) -> None:
    if not (VENDOR / ".git").exists():
        VENDOR.parent.mkdir(parents=True, exist_ok=True)
        run_checked([str(GIT), "clone", "--no-checkout", repository, str(VENDOR)])
    if git_output("remote", "get-url", "origin") != repository:
        raise RuntimeError("vendor origin does not match manifest source_repository")
    if git_output("status", "--porcelain"):
        raise RuntimeError("vendor checkout is not clean")
    run_checked([str(GIT), "-C", str(VENDOR), "fetch", "--depth=1", "origin", source_commit])
    run_checked([str(GIT), "-C", str(VENDOR), "checkout", "--detach", source_commit])
    if git_output("rev-parse", "HEAD") != source_commit:
        raise RuntimeError("vendor checkout does not match manifest source_commit")
    if git_output("status", "--porcelain"):
        raise RuntimeError("vendor checkout changed during bootstrap")


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    repository = str(manifest["source_repository"])
    source_commit = str(manifest["source_commit"])
    if not GO.is_file():
        raise RuntimeError("Go 1.26.5 is unavailable; run scripts/setup-cloud.sh first")
    version = run_checked([str(GO), "version"]).stdout
    if "go1.26.5" not in version:
        raise RuntimeError("Go 1.26.5 is required, found: %s" % version.strip())
    prepare_vendor(repository, source_commit)
    run_checked([str(GO), "mod", "download"], cwd=VENDOR, env=dependency_environment())
    print(json.dumps({"source_commit": source_commit, "vendor_clean": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
