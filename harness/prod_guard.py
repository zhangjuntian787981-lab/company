#!/usr/bin/env python3
"""Hash-only production isolation guard. Never parses or prints configuration values."""

import argparse
import hashlib
import json
import os
import pwd
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = REPO_ROOT / "baseline" / "production.lock.json"


def sha256_file(path: Path) -> Optional[str]:
    try:
        handle = path.open("rb")
    except FileNotFoundError:
        return None
    digest = hashlib.sha256()
    with handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _run_lines(argv: Sequence[str]) -> List[str]:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def listener_pids(port: int) -> List[int]:
    lines = _run_lines(["lsof", "-nP", "-t", "-iTCP:%d" % port, "-sTCP:LISTEN"])
    values: List[int] = []
    for line in lines:
        try:
            values.append(int(line))
        except ValueError:
            continue
    return sorted(set(values))


def label_loaded(label: str) -> bool:
    domain = "gui/%d/%s" % (os.getuid(), label)
    try:
        result = subprocess.run(
            ["launchctl", "print", domain],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def file_metadata(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False, "sha256": None}
    try:
        owner = pwd.getpwuid(stat.st_uid).pw_name
    except KeyError:
        owner = str(stat.st_uid)
    return {
        "path": str(path),
        "exists": True,
        "sha256": sha256_file(path),
        "mode": "%04o" % (stat.st_mode & 0o7777),
        "owner": owner,
        "mtime_ns": stat.st_mtime_ns,
    }


def load_baseline(path: Optional[Path] = None) -> Dict[str, Any]:
    selected = path
    if selected is None:
        configured = os.environ.get("COMPAT_PROD_BASELINE", "").strip()
        selected = Path(configured) if configured else DEFAULT_BASELINE
    if not selected.is_absolute():
        selected = REPO_ROOT / selected
    return json.loads(selected.read_text(encoding="utf-8"))


def snapshot(baseline: Mapping[str, Any]) -> Dict[str, Any]:
    mode = str(baseline.get("mode", "known"))
    port = int(baseline["production"]["port"])
    files = [file_metadata(Path(item["path"])) for item in baseline["files"]]
    label = str(baseline["production"].get("launchd_label", ""))
    return {
        "schema_version": 1,
        "mode": mode,
        "port": port,
        "listener_pids": listener_pids(port),
        "launchd_label": label,
        "launchd_label_loaded": label_loaded(label) if label else False,
        "files": files,
    }


def compare_known(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> List[str]:
    differences: List[str] = []
    mode = str(baseline.get("mode", "known"))
    if current.get("mode", "known") != mode:
        differences.append("baseline-mode")
    if mode == "absent":
        if current.get("listener_pids"):
            differences.append("production-listener-present")
        actual_files = {item["path"]: item for item in current.get("files", [])}
        for expected in baseline["files"]:
            if actual_files.get(expected["path"], {}).get("exists"):
                differences.append("file-present:%s" % expected["id"])
        return differences
    expected_pid = int(baseline["production"]["pid"])
    if current.get("listener_pids") != [expected_pid]:
        differences.append("production-listener-pid")
    expected_label = str(baseline["production"]["launchd_label"])
    if current.get("launchd_label") != expected_label or not current.get("launchd_label_loaded"):
        differences.append("production-launchd-label")
    actual_files = {item["path"]: item for item in current.get("files", [])}
    for expected in baseline["files"]:
        actual = actual_files.get(expected["path"], {})
        if actual.get("sha256") != expected["sha256"]:
            differences.append("file-sha256:%s" % expected["id"])
    return differences


def compare_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> List[str]:
    differences: List[str] = []
    for key in ("mode", "port", "listener_pids", "launchd_label", "launchd_label_loaded"):
        if before.get(key) != after.get(key):
            differences.append(key)
    before_files = {item["path"]: item for item in before.get("files", [])}
    after_files = {item["path"]: item for item in after.get("files", [])}
    for path in sorted(set(before_files) | set(after_files)):
        if before_files.get(path) != after_files.get(path):
            differences.append("file:%s" % path)
    return differences


def matched_summary(baseline: Mapping[str, Any]) -> str:
    if baseline.get("mode") == "absent":
        return "production listener and listed production files were absent"
    return "known production hashes, label, listener port, and PID matched"


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check-known", action="store_true")
    group.add_argument("--snapshot", type=Path)
    group.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args()
    baseline = load_baseline(args.baseline)
    if args.check_known:
        differences = compare_known(baseline, snapshot(baseline))
        if differences:
            print(json.dumps({"ok": False, "differences": differences}, sort_keys=True))
            return 1
        print(json.dumps({"ok": True, "differences": []}, sort_keys=True))
        return 0
    if args.snapshot:
        _write_json(args.snapshot, snapshot(baseline))
        print(json.dumps({"ok": True, "snapshot": str(args.snapshot)}, sort_keys=True))
        return 0
    before = json.loads(Path(args.compare[0]).read_text(encoding="utf-8"))
    after = json.loads(Path(args.compare[1]).read_text(encoding="utf-8"))
    differences = compare_snapshots(before, after)
    print(json.dumps({"ok": not differences, "differences": differences}, sort_keys=True))
    return 1 if differences else 0


if __name__ == "__main__":
    raise SystemExit(main())
