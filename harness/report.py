#!/usr/bin/env python3
"""Generate machine-readable and human-readable compatibility reports."""

import json
import os
import platform
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from harness.redaction import assert_report_files_safe, sanitize

REPORT_FILES = (
    "environment.json",
    "cases.json",
    "evidence.ndjson",
    "junit.xml",
    "rating.json",
    "report.md",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(str(path), 0o600)


def _write_json(path: Path, value: Any) -> None:
    safe = sanitize(value)
    _write_text(path, json.dumps(safe, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def build_environment(run_id: str, mock_port: int, prod_guard: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": _utc_now(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "implementation": platform.python_implementation(),
        "mock": {"host": "127.0.0.1", "port": mock_port},
        "isolation": {
            "temporary_home": True,
            "temporary_xdg": True,
            "temporary_tmp": True,
            "umask": "077",
            "network_policy": "loopback-only; port 8317 denied",
            "user_configuration_loaded": False,
        },
        "production_guard": dict(prod_guard),
    }


def _dimension_rating(cases: Sequence[Mapping[str, Any]], names: Sequence[str]) -> str:
    selected = [case for case in cases if case.get("dimension") in names]
    if any(case.get("status") == "FAIL" for case in selected):
        return "FAIL"
    if any(case.get("status") == "UNVERIFIED" for case in selected) or not selected:
        return "UNVERIFIED"
    return "PASS"


def build_rating(cases: Sequence[Mapping[str, Any]], prod_untouched: bool) -> Dict[str, Any]:
    hard_failures = [
        case.get("id", "unknown") for case in cases if case.get("hard_failure") is True
    ]
    if not prod_untouched:
        hard_failures.append("FAIL-PROD-ISOLATION")

    dimensions = {
        "Security": _dimension_rating(cases, ("Security",)),
        "Protocol": _dimension_rating(cases, ("Protocol",)),
        "Tools": _dimension_rating(cases, ("Tools",)),
        "Resilience": _dimension_rating(cases, ("Resilience",)),
        "Model/Context": _dimension_rating(cases, ("Model/Context",)),
        "Operability": _dimension_rating(cases, ("Operability",)),
    }
    if hard_failures or any(value == "FAIL" for value in dimensions.values()):
        overall = "FAIL"
    elif any(value == "UNVERIFIED" for value in dimensions.values()):
        overall = "CONDITIONAL"
    else:
        overall = "PASS"

    return {
        "schema_version": 1,
        "overall": overall,
        "dimensions": dimensions,
        "hard_failures": hard_failures,
        "allowed_scope": (
            "Local mock and minimal bottle text routing only; no claim yet for the full "
            "retry/streaming matrix, client end-to-end, launchd recovery, long context, "
            "or real upstream behavior."
            if overall == "CONDITIONAL"
            else "See case results and approval policy."
        ),
    }


def _build_junit(cases: Sequence[Mapping[str, Any]]) -> str:
    suite = ET.Element(
        "testsuite",
        {
            "name": "cliproxyapi-compat",
            "tests": str(len(cases)),
            "failures": str(sum(case.get("status") == "FAIL" for case in cases)),
            "skipped": str(sum(case.get("status") == "UNVERIFIED" for case in cases)),
        },
    )
    for case in cases:
        node = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": str(case.get("dimension", "Compatibility")),
                "name": str(case.get("id", "unknown")),
                "time": "%.3f" % float(case.get("duration_seconds", 0.0)),
            },
        )
        status = case.get("status")
        if status == "FAIL":
            failure = ET.SubElement(node, "failure", {"message": "compatibility case failed"})
            failure.text = str(sanitize(case.get("summary", "failed")))
        elif status == "UNVERIFIED":
            skipped = ET.SubElement(node, "skipped", {"message": "not implemented in first milestone"})
            skipped.text = str(sanitize(case.get("summary", "unverified")))
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def _build_markdown(cases: Sequence[Mapping[str, Any]], rating: Mapping[str, Any]) -> str:
    lines = [
        "# CLIProxyAPI compatibility report",
        "",
        "Overall rating: **%s**" % rating["overall"],
        "",
        "## Dimensions",
        "",
        "| Dimension | Rating |",
        "|---|---|",
    ]
    for name, value in rating["dimensions"].items():
        lines.append("| %s | %s |" % (name, value))
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Dimension | Status | Summary |",
            "|---|---|---|---|",
        ]
    )
    for case in cases:
        summary = str(sanitize(case.get("summary", ""))).replace("|", "\\|").replace("\n", " ")
        lines.append(
            "| %s | %s | %s | %s |"
            % (case.get("id"), case.get("dimension"), case.get("status"), summary)
        )
    lines.extend(
        [
            "",
            "## Allowed scope",
            "",
            str(rating["allowed_scope"]),
            "",
            "## Unverified in this milestone",
            "",
            "- Full CLIProxyAPI streaming, retry, error, and OAuth refresh matrices.",
            "- Claude Code client, synthetic MCP, model mapping, compact, and launchd recovery.",
            "- Fixed source checkout tests and any real-upstream request.",
            "",
            "Persisted artifacts contain only sanitized status, counts, hashes, and shapes.",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_report(
    output_dir: Path,
    environment: Mapping[str, Any],
    cases: Sequence[Mapping[str, Any]],
    evidence: Iterable[Mapping[str, Any]],
    prod_untouched: bool,
    identity: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(output_dir), 0o700)
    safe_cases = sanitize(list(cases))
    safe_evidence = [sanitize(item) for item in evidence]
    rating = build_rating(safe_cases, prod_untouched)
    rating["generated_at"] = _utc_now()
    if identity:
        rating.update(sanitize(identity))

    _write_json(output_dir / "environment.json", environment)
    _write_json(output_dir / "cases.json", {"schema_version": 1, "cases": safe_cases})
    evidence_text = "".join(
        json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n" for item in safe_evidence
    )
    _write_text(output_dir / "evidence.ndjson", evidence_text)
    _write_text(output_dir / "junit.xml", _build_junit(safe_cases))
    _write_json(output_dir / "rating.json", rating)
    _write_text(output_dir / "report.md", _build_markdown(safe_cases, rating))

    report_paths = [output_dir / name for name in REPORT_FILES]
    assert_report_files_safe(report_paths)
    return rating
