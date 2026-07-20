#!/usr/bin/env python3
"""Apply v7.2.80 supplemental tests in a temporary worktree and report contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

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


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_checked(command: Sequence[str], *, cwd: Optional[Path] = None, env: Optional[Mapping[str, str]] = None) -> subprocess.CompletedProcess[str]:
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


def source_env(run_dir: Path) -> Dict[str, str]:
    sandbox = run_dir / "sandbox"
    paths = {
        "HOME": sandbox / "home",
        "TMPDIR": sandbox / "tmp",
        "GOCACHE": sandbox / "gocache",
        "GOPATH": ROOT / ".tools" / "gopath",
        "GOMODCACHE": ROOT / ".tools" / "gomodcache",
    }
    for path in paths.values():
        Path(path).mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "HOME": str(paths["HOME"]),
        "TMPDIR": str(paths["TMPDIR"]),
        "GOCACHE": str(paths["GOCACHE"]),
        "GOPATH": str(paths["GOPATH"]),
        "GOMODCACHE": str(paths["GOMODCACHE"]),
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_set_sha256(patches: Sequence[Mapping[str, str]]) -> str:
    digest = hashlib.sha256()
    for patch in patches:
        digest.update(str(patch["id"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def patch_touched_paths(path: Path) -> list[str]:
    process = run_checked([str(GIT), "-C", str(VENDOR), "apply", "--numstat", str(path)])
    paths: list[str] = []
    for line in process.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3 and parts[2]:
            paths.append(parts[2])
    return sorted(paths)


def run_go_tests(
    worktree: Path,
    packages: Sequence[str],
    env: Mapping[str, str],
    *,
    run_pattern: Optional[str],
    stage: str,
) -> Dict[str, Any]:
    command = [str(GO), "test", "-json", "-count=1"]
    if run_pattern:
        command.extend(["-run", run_pattern])
    command.extend(packages)

    process = subprocess.Popen(
        command,
        cwd=str(worktree),
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    tests: Dict[Tuple[str, str], str] = {}
    elapsed: Dict[Tuple[str, str], float] = {}
    package_status: Dict[str, str] = {}

    for line in process.stdout:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = str(event.get("Action", ""))
        package = str(event.get("Package", ""))
        test = str(event.get("Test", ""))
        if test and action in {"pass", "fail", "skip"}:
            tests[(package, test)] = action.upper()
            if "Elapsed" in event:
                elapsed[(package, test)] = float(event["Elapsed"])
            if action == "fail" and "/" not in test:
                print(f"{stage}: FAIL {package} {test}")
        elif package and not test and action in {"pass", "fail", "skip"}:
            package_status[package] = action.upper()

    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if stderr.strip():
        print(f"{stage}: go test wrote diagnostics to stderr ({len(stderr.encode('utf-8'))} bytes)")
    for package, status in sorted(package_status.items()):
        print(f"{stage}: {status} {package}")

    return {
        "return_code": return_code,
        "tests": tests,
        "elapsed": elapsed,
        "packages": package_status,
    }


def merge_test_results(*stages: Mapping[str, Any]) -> Dict[Tuple[str, str], str]:
    merged: Dict[Tuple[str, str], str] = {}
    for stage in stages:
        merged.update(stage.get("tests", {}))
    return merged


def classify_contracts(contracts_doc: Mapping[str, Any], tests: Mapping[Tuple[str, str], str]) -> list[Dict[str, Any]]:
    classified: list[Dict[str, Any]] = []
    for contract in contracts_doc.get("contracts", []):
        item = dict(contract)
        evidence_results = []
        for evidence in contract.get("evidence", []):
            key = (str(evidence.get("package", "")), str(evidence.get("test", "")))
            status = tests.get(key, "MISSING")
            evidence_item = dict(evidence)
            evidence_item["test_status"] = status
            evidence_results.append(evidence_item)
        statuses = {entry["test_status"] for entry in evidence_results}
        if "FAIL" in statuses:
            result = "FAIL"
        elif not statuses or statuses.intersection({"MISSING", "SKIP"}):
            result = "UNVERIFIED"
        else:
            result = "PASS"
        item["result"] = result
        item["evidence"] = evidence_results
        classified.append(item)
    return classified


def boundary_failed(
    *,
    stage_error: str,
    cleanup_ok: bool,
    supplemental_return_code: int,
    contract_result_counts: Mapping[str, int],
) -> bool:
    return (
        bool(stage_error)
        or not cleanup_ok
        or supplemental_return_code != 0
        or contract_result_counts.get("FAIL", 0) > 0
    )


def markdown_report(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# CLIProxyAPI v7.2.80 protocol boundary report",
        "",
        f"Source commit: `{report['source_commit']}`",
        f"Patch-set SHA-256: `{report['patch_set_sha256']}`",
        f"Manifest SHA-256: `{report['manifest_sha256']}`",
        f"Contracts SHA-256: `{report['contracts_sha256']}`",
        f"Applied patches: {len(report['patches'])}",
        f"Overall: **{summary['overall']}**",
        "",
        "## Contract classifications",
        "",
        "| Contract | Classification | Result | Observed behavior |",
        "|---|---|---|---|",
    ]
    for contract in report["contracts"]:
        observed = str(contract.get("observed", "")).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {contract['id']} | {contract['classification']} | {contract['result']} | {observed} |"
        )
    lines.extend(["", "## Confirmed defects", ""])
    defects = report.get("confirmed_defects", [])
    if defects:
        for defect in defects:
            lines.append(f"- `{defect['test']}` in `{defect['package']}`")
    else:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "## Test stages",
            "",
            f"- Baseline upstream packages: {report['stages']['baseline']['status']}",
            f"- Supplemental patch tests: {report['stages']['supplemental']['status']}",
            f"- Temporary worktree cleanup: {report['stages']['cleanup']['status']}",
            "",
            "No real model upstream was contacted and no service on port 8317 was used.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_private(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    os.umask(0o077)
    manifest = read_json(MANIFEST_PATH)
    contracts_doc = read_json(CONTRACTS_PATH)
    expected_commit = str(manifest["source_commit"])
    patch_entries = manifest.get("patches", [])
    if not isinstance(patch_entries, list) or not patch_entries:
        raise RuntimeError("patch manifest contains no patches")
    contract_ids = {
        str(item.get("id"))
        for item in contracts_doc.get("contracts", [])
        if isinstance(item, dict) and item.get("id")
    }
    patches = []
    for entry in patch_entries:
        contracts = [str(item) for item in entry.get("contracts", [])]
        if not contracts:
            raise RuntimeError(f"patch {entry.get('id')} has no contract mapping")
        unknown_contracts = sorted(set(contracts) - contract_ids)
        if unknown_contracts:
            raise RuntimeError(f"patch {entry.get('id')} references unknown contracts: {unknown_contracts}")
        patches.append(
            {
                "id": str(entry["id"]),
                "path": str(entry["path"]),
                "sha256": str(entry["sha256"]),
                "touched_paths": sorted(str(item) for item in entry.get("touched_paths", [])),
                "contracts": contracts,
            }
        )
    expected_patch_set_sha = patch_set_sha256(patches)
    manifest_sha = sha256_file(MANIFEST_PATH)
    contracts_sha = sha256_file(CONTRACTS_PATH)

    run_dir = ROOT / ".runs" / f"source-boundary-{utc_stamp()}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    worktree = run_dir / "sandbox" / "upstream-worktree"
    worktree.parent.mkdir(parents=True, mode=0o700)
    env = source_env(run_dir)

    stage_error = ""
    cleanup_ok = False
    applied_patch_ids: list[str] = []
    baseline: Dict[str, Any] = {"return_code": -1, "tests": {}, "packages": {}}
    supplemental: Dict[str, Any] = {"return_code": -1, "tests": {}, "packages": {}}

    try:
        if not GO.is_file():
            raise RuntimeError(f"pinned Go binary missing: {GO}")
        if git_output("status", "--porcelain"):
            raise RuntimeError("fixed vendor checkout is not clean")
        actual_commit = git_output("rev-parse", "HEAD")
        if actual_commit != expected_commit:
            raise RuntimeError(f"vendor HEAD {actual_commit} does not match {expected_commit}")
        for patch in patches:
            patch_path = PATCH_DIR / patch["path"]
            if not patch_path.is_file():
                raise RuntimeError(f"patch file missing: {patch_path}")
            actual_patch_sha = sha256_file(patch_path)
            if actual_patch_sha != patch["sha256"]:
                raise RuntimeError(
                    f"patch {patch['id']} digest {actual_patch_sha} does not match manifest"
                )
            actual_paths = patch_touched_paths(patch_path)
            if actual_paths != patch["touched_paths"]:
                raise RuntimeError(
                    f"patch {patch['id']} paths {actual_paths} do not match manifest {patch['touched_paths']}"
                )

        run_checked([str(GIT), "-C", str(VENDOR), "worktree", "add", "--detach", str(worktree), expected_commit])
        baseline = run_go_tests(
            worktree,
            manifest["baseline_packages"],
            env,
            run_pattern=None,
            stage="baseline",
        )
        if baseline["return_code"] != 0:
            raise RuntimeError("baseline upstream package tests failed before patch application")

        for patch in patches:
            patch_path = PATCH_DIR / patch["path"]
            run_checked([str(GIT), "-C", str(worktree), "apply", "--check", str(patch_path)])
            run_checked([str(GIT), "-C", str(worktree), "apply", str(patch_path)])
            applied_patch_ids.append(patch["id"])
        run_checked([str(GIT), "-C", str(worktree), "diff", "--check"])

        supplemental = run_go_tests(
            worktree,
            manifest["supplemental_packages"],
            env,
            run_pattern=None,
            stage="supplemental",
        )
    except (KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        stage_error = f"{type(exc).__name__}: {exc}"
    finally:
        if worktree.exists():
            try:
                run_checked([str(GIT), "-C", str(VENDOR), "worktree", "remove", "--force", str(worktree)])
                cleanup_ok = True
            except (OSError, subprocess.CalledProcessError):
                cleanup_ok = False
        else:
            cleanup_ok = True

    all_tests = merge_test_results(baseline, supplemental)
    contracts = classify_contracts(contracts_doc, all_tests)
    known_defects = []
    for item in manifest.get("known_defect_tests", []):
        key = (str(item["package"]), str(item["test"]))
        if all_tests.get(key) == "FAIL":
            known_defects.append(dict(item))

    result_counts = Counter(item["result"] for item in contracts)
    classification_counts = Counter(item["classification"] for item in contracts)
    failed = boundary_failed(
        stage_error=stage_error,
        cleanup_ok=cleanup_ok,
        supplemental_return_code=int(supplemental.get("return_code", -1)),
        contract_result_counts=result_counts,
    )
    report = sanitize(
        {
            "schema_version": 2,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_tag": manifest["source_tag"],
            "source_commit": expected_commit,
            "patches": patches,
            "patch_set_sha256": expected_patch_set_sha,
            "manifest_sha256": manifest_sha,
            "contracts_sha256": contracts_sha,
            "summary": {
                "overall": "FAIL" if failed else ("CONDITIONAL" if result_counts.get("UNVERIFIED", 0) else "PASS"),
                "contract_results": dict(sorted(result_counts.items())),
                "classifications": dict(sorted(classification_counts.items())),
            },
            "stages": {
                "baseline": {
                    "status": "PASS" if baseline.get("return_code") == 0 else "FAIL",
                    "package_count": len(baseline.get("packages", {})),
                },
                "patches": {
                    "status": "APPLIED" if len(applied_patch_ids) == len(patches) else "NOT_APPLIED",
                    "applied_ids": applied_patch_ids,
                    "count": len(patches),
                },
                "supplemental": {
                    "status": "PASS" if supplemental.get("return_code") == 0 else "FAIL",
                    "package_count": len(supplemental.get("packages", {})),
                },
                "cleanup": {"status": "PASS" if cleanup_ok else "FAIL"},
            },
            "stage_error": stage_error or None,
            "checks": {
                "patch_manifest_paths": not bool(stage_error),
                "patches_applied": len(applied_patch_ids) == len(patches),
                "git_diff_check": not bool(stage_error) and len(applied_patch_ids) == len(patches),
                "supplemental_tests": supplemental.get("return_code") == 0,
                "cleanup": cleanup_ok,
            },
            "confirmed_defects": known_defects,
            "contracts": contracts,
            "vendor_clean_after": not bool(git_output("status", "--porcelain")),
        }
    )

    json_path = run_dir / "protocol-contracts.json"
    markdown_path = run_dir / "protocol-contracts.md"
    write_private(json_path, json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    write_private(markdown_path, markdown_report(report))
    assert_report_files_safe([json_path, markdown_path])

    print(f"protocol contract JSON: {json_path}")
    print(f"protocol contract Markdown: {markdown_path}")
    print(f"overall: {report['summary']['overall']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
