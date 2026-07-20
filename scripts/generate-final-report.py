#!/usr/bin/env python3
"""Compute the final compatibility rating from policy and persisted evidence."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from harness.redaction import assert_report_files_safe, sanitize
from harness.runner import REPO_ROOT


MISSING = object()


def load(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evidence was not a JSON object: %s" % path)
    return value


def get_path(value: Mapping[str, Any], dotted_path: str, default: Any = MISSING) -> Any:
    current: Any = value
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def patch_set_sha256(patches: Iterable[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for patch in patches:
        digest.update(str(patch["id"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(patch["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def latest_path(runs_dir: Path, pattern: str) -> Optional[Path]:
    paths = [path for path in runs_dir.glob(pattern) if path.is_file()]
    if not paths:
        return None
    return max(paths, key=lambda path: path.stat().st_mtime_ns)


def write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    os.chmod(str(path), 0o600)


def normalize_status(value: Any, pass_values: Sequence[str], fail_values: Sequence[str]) -> str:
    status = str(value).upper() if value is not MISSING else ""
    if status in {item.upper() for item in fail_values}:
        return "FAIL"
    if status in {item.upper() for item in pass_values}:
        return "PASS"
    return "UNVERIFIED"


def evidence_freshness(
    document: Mapping[str, Any],
    path: Path,
    now: datetime,
    max_age_seconds: int,
    future_skew_seconds: int,
) -> Tuple[bool, str, str]:
    timestamp = parse_timestamp(document.get("generated_at"))
    source = "generated_at"
    if timestamp is None:
        timestamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        source = "mtime"
    age = (now - timestamp).total_seconds()
    if age > max_age_seconds:
        return False, "evidence is stale by %d seconds" % int(age - max_age_seconds), source
    if age < -future_skew_seconds:
        return False, "evidence timestamp is too far in the future", source
    return True, "evidence age is %d seconds" % max(0, int(age)), source


def finding_id(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("id") or value.get("feature") or value.get("observed") or "finding")
    return str(value)


def normalized_dimension_rating(value: Any) -> str:
    if isinstance(value, Mapping):
        return str(value.get("rating", "UNVERIFIED"))
    return str(value or "UNVERIFIED")


def find_fail_baseline(
    runs_dir: Path, baseline_policy: Mapping[str, Any]
) -> Tuple[Optional[Path], Optional[Dict[str, Any]]]:
    expected = str(baseline_policy.get("required_overall", "FAIL"))
    matches: List[Tuple[Path, Dict[str, Any]]] = []
    for path in runs_dir.glob(str(baseline_policy.get("pattern", "final-*/final-report.json"))):
        if not path.is_file():
            continue
        try:
            document = load(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(document.get("overall")) == expected:
            matches.append((path, document))
    if not matches:
        return None, None
    return max(matches, key=lambda item: item[0].stat().st_mtime_ns)


def collect_hard_failures(
    source_id: str,
    document: Mapping[str, Any],
    default_dimension: str,
    failures: Dict[str, Dict[str, Any]],
) -> None:
    for raw in document.get("hard_failures", []):
        if isinstance(raw, Mapping):
            failure_id = str(raw.get("id") or "hard-failure")
            observed = str(raw.get("observed") or raw.get("summary") or failure_id)
            dimension = str(raw.get("dimension") or default_dimension)
        else:
            failure_id = str(raw)
            observed = str(raw)
            dimension = default_dimension
        item = failures.setdefault(
            failure_id,
            {
                "id": failure_id,
                "dimension": dimension,
                "observed": observed,
                "sources": [],
            },
        )
        if source_id not in item["sources"]:
            item["sources"].append(source_id)


def build_report(
    repo_root: Path = REPO_ROOT,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    repo_root = repo_root.resolve()
    runs_dir = repo_root / ".runs"
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    policy_path = repo_root / "policy" / "rating-policy.json"
    policy = load(policy_path)
    report_policy = policy.get("final_report")
    if not isinstance(report_policy, Mapping):
        raise ValueError("rating policy has no final_report section")
    dimensions = [str(item) for item in policy.get("dimensions", [])]
    if len(dimensions) != 6 or len(set(dimensions)) != 6:
        raise ValueError("rating policy must define six unique dimensions")

    max_age_seconds = int(report_policy.get("max_evidence_age_seconds", 0))
    future_skew_seconds = int(report_policy.get("future_clock_skew_seconds", 0))
    manifest_dimension = str(report_policy["manifest_dimension"])
    contracts_dimension = str(report_policy["contracts_dimension"])
    default_hard_failure_dimension = str(report_policy["default_hard_failure_dimension"])
    dimension_checks: Dict[str, List[Dict[str, Any]]] = {name: [] for name in dimensions}
    hard_failure_map: Dict[str, Dict[str, Any]] = {}
    evidence_records: Dict[str, Dict[str, Any]] = {}
    stage_results: Dict[str, Dict[str, Any]] = {}

    def add_check(dimension: str, check_id: str, status: str, detail: str, source: str) -> None:
        if dimension not in dimension_checks:
            raise ValueError("policy references unknown dimension: %s" % dimension)
        dimension_checks[dimension].append(
            {
                "id": check_id,
                "status": status,
                "detail": detail,
                "source": source,
            }
        )

    input_records: Dict[str, Dict[str, Any]] = {
        "policy": {
            "path": str(policy_path),
            "sha256": sha256_file(policy_path),
        }
    }

    manifest_path = repo_root / str(report_policy.get("manifest_path", ""))
    manifest: Optional[Dict[str, Any]] = None
    manifest_patch_sha: Optional[str] = None
    source_commit: Optional[str] = None
    try:
        manifest = load(manifest_path)
        source_commit = str(manifest["source_commit"])
        manifest_patch_sha = patch_set_sha256(manifest["patches"])
        input_records["manifest"] = {
            "path": str(manifest_path),
            "sha256": sha256_file(manifest_path),
            "status": "PASS",
        }
        add_check(manifest_dimension, "manifest", "PASS", "manifest identity was computed", "manifest")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        input_records["manifest"] = {
            "path": str(manifest_path),
            "sha256": None,
            "status": "UNVERIFIED",
            "reason": "%s: %s" % (type(exc).__name__, exc),
        }
        add_check(manifest_dimension, "manifest", "UNVERIFIED", "manifest is missing or invalid", "manifest")

    identity: Dict[str, Any] = {
        "manifest": {
            "source_commit": source_commit,
            "patch_set_sha256": manifest_patch_sha,
        },
        "artifacts": {},
    }

    artifact_results: Dict[str, Dict[str, Any]] = {}
    for artifact_policy in report_policy.get("candidate_artifacts", []):
        artifact_id = str(artifact_policy["id"])
        artifact_path = repo_root / str(artifact_policy["path"])
        dimension = str(artifact_policy["dimension"])
        required = bool(artifact_policy.get("required", True))
        try:
            artifact_sha = sha256_file(artifact_path)
            result = {
                "path": str(artifact_path),
                "sha256": artifact_sha,
                "status": "PASS",
            }
            add_check(dimension, "artifact:%s" % artifact_id, "PASS", "artifact hash was computed", artifact_id)
        except OSError as exc:
            artifact_sha = None
            result = {
                "path": str(artifact_path),
                "sha256": None,
                "status": "UNVERIFIED" if required else "OPTIONAL",
                "reason": "%s: %s" % (type(exc).__name__, exc),
            }
            if required:
                add_check(
                    dimension,
                    "artifact:%s" % artifact_id,
                    "UNVERIFIED",
                    "required artifact is missing",
                    artifact_id,
                )
        artifact_results[artifact_id] = result
        identity["artifacts"][artifact_id] = {"sha256": artifact_sha}

    contracts_path = repo_root / str(report_policy.get("contracts_path", ""))
    silent_degradations: List[Dict[str, Any]] = []
    contract_blocks_pass = False
    try:
        contracts = load(contracts_path)
        input_records["contracts"] = {
            "path": str(contracts_path),
            "sha256": sha256_file(contracts_path),
            "status": "PASS",
        }
        classification_policy = report_policy.get("contract_classifications", {})
        for contract in contracts.get("contracts", []):
            classification = str(contract.get("classification", ""))
            impact = classification_policy.get(classification)
            if not isinstance(impact, Mapping):
                continue
            finding = {
                "id": str(contract.get("id", "contract")),
                "feature": str(contract.get("feature", "")),
                "classification": classification,
                "observed": str(contract.get("observed", "")),
            }
            silent_degradations.append(finding)
            impact_status = str(impact.get("rating", "UNVERIFIED"))
            impact_dimension = str(impact.get("dimension", contracts_dimension))
            add_check(
                impact_dimension,
                "contract:%s" % finding["id"],
                impact_status,
                "%s is classified %s" % (finding["id"], classification),
                "contracts",
            )
            contract_blocks_pass = contract_blocks_pass or bool(impact.get("blocks_pass", False))
        if not silent_degradations:
            add_check(contracts_dimension, "contracts", "PASS", "no blocking contract classification was present", "contracts")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        input_records["contracts"] = {
            "path": str(contracts_path),
            "sha256": None,
            "status": "UNVERIFIED",
            "reason": "%s: %s" % (type(exc).__name__, exc),
        }
        add_check(contracts_dimension, "contracts", "UNVERIFIED", "contracts are missing or invalid", "contracts")
        contract_blocks_pass = True

    baseline_policy = report_policy.get("baseline", {})
    baseline_path, baseline = find_fail_baseline(runs_dir, baseline_policy)
    baseline_dimension = str(baseline_policy.get("dimension", "Operability"))
    if baseline_path is None or baseline is None:
        baseline_record: Dict[str, Any] = {
            "path": None,
            "sha256": None,
            "status": "UNVERIFIED",
        }
        add_check(
            baseline_dimension,
            "fail-baseline",
            "UNVERIFIED",
            "preserved FAIL baseline was not found",
            "baseline",
        )
    else:
        baseline_record = {
            "path": str(baseline_path),
            "sha256": sha256_file(baseline_path),
            "status": "PASS",
            "overall": baseline.get("overall"),
        }
        add_check(
            baseline_dimension,
            "fail-baseline",
            "PASS",
            "preserved FAIL baseline was linked",
            "baseline",
        )

    stage_documents: Dict[str, Dict[str, Any]] = {}
    for stage_policy in report_policy.get("required_stages", []):
        stage_id = str(stage_policy["id"])
        stage_dimensions = [str(item) for item in stage_policy.get("dimensions", [])]
        stage_path = latest_path(runs_dir, str(stage_policy["pattern"]))
        required_cases = stage_policy.get("required_cases", [])
        if stage_path is None:
            stage_result = {
                "status": "UNVERIFIED",
                "raw_status": None,
                "path": None,
                "sha256": None,
                "reasons": ["required stage evidence is missing"],
                "cases": [],
            }
            for dimension in stage_dimensions:
                add_check(
                    dimension,
                    "stage:%s" % stage_id,
                    "UNVERIFIED",
                    "required stage evidence is missing",
                    stage_id,
                )
            for case_policy in required_cases:
                add_check(
                    str(case_policy["dimension"]),
                    "%s:%s" % (stage_id, case_policy["id"]),
                    "UNVERIFIED",
                    "required case evidence is missing",
                    stage_id,
                )
            stage_results[stage_id] = stage_result
            continue

        reasons: List[str] = []
        case_results: List[Dict[str, Any]] = []
        try:
            stage_document = load(stage_path)
            stage_sha = sha256_file(stage_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            stage_document = {}
            stage_sha = sha256_file(stage_path) if stage_path.is_file() else None
            reasons.append("stage evidence is invalid: %s: %s" % (type(exc).__name__, exc))

        fresh, freshness_detail, freshness_source = evidence_freshness(
            stage_document,
            stage_path,
            now,
            max_age_seconds,
            future_skew_seconds,
        )
        if not fresh:
            reasons.append(freshness_detail)

        raw_status = get_path(stage_document, str(stage_policy["status_path"]))
        stage_status = normalize_status(
            raw_status,
            [str(item) for item in stage_policy.get("pass_values", ["PASS"])],
            [str(item) for item in stage_policy.get("fail_values", ["FAIL"])],
        )

        for check in stage_policy.get("checks", []):
            actual = get_path(stage_document, str(check["path"]))
            if actual is MISSING:
                reasons.append("required check is missing: %s" % check["path"])
                if stage_status != "FAIL":
                    stage_status = "UNVERIFIED"
            elif actual != check.get("equals"):
                reasons.append("required check failed: %s" % check["path"])
                stage_status = "FAIL"

        identity_valid = True
        for match in stage_policy.get("matches", []):
            actual = get_path(stage_document, str(match["path"]))
            expected = get_path(identity, str(match["expected"]))
            if actual is MISSING or expected is MISSING or actual is None or expected is None:
                reasons.append("identity value is missing: %s" % match["path"])
                identity_valid = False
            elif actual != expected:
                reasons.append("identity mismatch: %s" % match["path"])
                identity_valid = False

        evidence_trusted = fresh and identity_valid
        if not evidence_trusted:
            stage_status = "UNVERIFIED"
        else:
            stage_documents[stage_id] = stage_document
            collect_hard_failures(
                stage_id,
                stage_document,
                stage_dimensions[0] if stage_dimensions else "Operability",
                hard_failure_map,
            )

        cases_document = stage_document
        cases_path_value = stage_policy.get("cases_path")
        cases_path: Optional[Path] = None
        cases_sha: Optional[str] = None
        if cases_path_value:
            cases_path = stage_path.parent / str(cases_path_value)
            try:
                cases_document = load(cases_path)
                cases_sha = sha256_file(cases_path)
                if evidence_trusted:
                    collect_hard_failures(
                        "%s-cases" % stage_id,
                        cases_document,
                        stage_dimensions[0] if stage_dimensions else "Operability",
                        hard_failure_map,
                    )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                cases_document = {}
                reasons.append("case evidence is missing or invalid: %s: %s" % (type(exc).__name__, exc))

        cases_by_id = {
            str(item.get("id")): item
            for item in cases_document.get("cases", [])
            if isinstance(item, Mapping) and item.get("id") is not None
        }
        trusted_cases = cases_by_id.values() if evidence_trusted else ()
        for case in trusted_cases:
            if not bool(case.get("hard_failure")):
                continue
            failure_id = str(case["id"])
            failure_dimension = str(case.get("dimension") or default_hard_failure_dimension)
            hard_failure_map[failure_id] = {
                "id": failure_id,
                "dimension": failure_dimension,
                "observed": str(case.get("summary") or failure_id),
                "sources": [stage_id],
            }
        for case_policy in required_cases:
            case_id = str(case_policy["id"])
            dimension = str(case_policy["dimension"])
            case = cases_by_id.get(case_id)
            if case is None:
                case_status = "UNVERIFIED"
                detail = "required case is missing"
            else:
                case_status = normalize_status(case.get("status"), ["PASS"], ["FAIL"])
                detail = str(case.get("summary") or "case reported %s" % case_status)
                reported_dimension = case.get("dimension")
                if reported_dimension is not None and str(reported_dimension) != dimension:
                    case_status = "UNVERIFIED"
                    detail = "case dimension does not match policy"
                if evidence_trusted and bool(case.get("hard_failure")):
                    failure_id = case_id
                    hard_failure_map[failure_id] = {
                        "id": failure_id,
                        "dimension": dimension,
                        "observed": detail,
                        "sources": [stage_id],
                    }
                    case_status = "FAIL"
            if not evidence_trusted:
                case_status = "UNVERIFIED"
                detail = "case belongs to stale or mismatched stage evidence"
            elif stage_status == "UNVERIFIED" and case_status == "PASS":
                case_status = "UNVERIFIED"
                detail = "case belongs to unverified stage evidence"
            add_check(dimension, "%s:%s" % (stage_id, case_id), case_status, detail, stage_id)
            case_results.append({"id": case_id, "dimension": dimension, "status": case_status, "detail": detail})

        for dimension in stage_dimensions:
            add_check(
                dimension,
                "stage:%s" % stage_id,
                stage_status,
                reasons[0] if reasons else "stage reported %s" % stage_status,
                stage_id,
            )

        stage_result = {
            "status": stage_status,
            "raw_status": None if raw_status is MISSING else raw_status,
            "path": str(stage_path),
            "sha256": stage_sha,
            "fresh": fresh,
            "freshness": freshness_detail,
            "freshness_source": freshness_source,
            "reasons": reasons,
            "cases": case_results,
        }
        if cases_path is not None:
            stage_result["cases_evidence"] = {
                "path": str(cases_path),
                "sha256": cases_sha,
            }
        stage_results[stage_id] = stage_result
        evidence_records[stage_id] = {
            "path": str(stage_path),
            "sha256": stage_sha,
        }

    for failure in hard_failure_map.values():
        dimension = str(failure.get("dimension") or default_hard_failure_dimension)
        if dimension not in dimension_checks:
            dimension = default_hard_failure_dimension
        add_check(
            dimension,
            "hard-failure:%s" % failure["id"],
            "FAIL",
            str(failure["observed"]),
            ",".join(failure["sources"]),
        )

    dimension_results: Dict[str, Dict[str, Any]] = {}
    unverified: List[Dict[str, Any]] = []
    blocking_findings: List[Dict[str, Any]] = []
    for dimension, checks in dimension_checks.items():
        statuses = [str(item["status"]) for item in checks]
        if "FAIL" in statuses:
            rating = "FAIL"
        elif "CONDITIONAL" in statuses:
            rating = "CONDITIONAL"
        elif not statuses or "UNVERIFIED" in statuses:
            rating = "UNVERIFIED"
        else:
            rating = "PASS"
        counts = dict(sorted(Counter(statuses).items()))
        dimension_results[dimension] = {
            "rating": rating,
            "summary": ", ".join("%s=%d" % item for item in sorted(counts.items())) or "no checks",
            "checks": checks,
        }
        for check in checks:
            if check["status"] == "UNVERIFIED":
                unverified.append({"dimension": dimension, **check})
            if check["status"] != "PASS":
                blocking_findings.append({"dimension": dimension, **check})

    hard_failures = sorted(hard_failure_map.values(), key=lambda item: item["id"])
    dimension_ratings = [item["rating"] for item in dimension_results.values()]
    every_check_passed = all(
        check["status"] == "PASS"
        for checks in dimension_checks.values()
        for check in checks
    )
    if hard_failures or "FAIL" in dimension_ratings:
        overall = "FAIL"
    elif (
        all(rating == "PASS" for rating in dimension_ratings)
        and every_check_passed
        and not contract_blocks_pass
    ):
        overall = "PASS"
    else:
        overall = "CONDITIONAL"

    decisions = report_policy.get("decisions", {})
    decision = str(decisions.get(overall, overall))
    e2e_document = stage_documents.get("claude_code_e2e", {})
    real_document = stage_documents.get("real_upstream", {})
    report: Dict[str, Any] = {
        "schema_version": 2,
        "generated_at": now.isoformat(),
        "overall": overall,
        "decision": decision,
        "chain": {
            "source_commit": source_commit,
            "patch_set_sha256": manifest_patch_sha,
            "candidate_binary_sha256": get_path(identity, "artifacts.candidate_binary.sha256", None),
            "gateway_binary_sha256": get_path(identity, "artifacts.gateway_binary.sha256", None),
            "claude_code": e2e_document.get("claude_code_version"),
            "proxy": e2e_document.get("cliproxyapi_version"),
            "model": real_document.get("model"),
        },
        "dimensions": dimension_results,
        "hard_failures": hard_failures,
        "silent_degradations": silent_degradations,
        "unverified": unverified,
        "blocking_findings": blocking_findings,
        "stage_results": stage_results,
        "evidence": evidence_records,
        "inputs": input_records,
        "artifacts": artifact_results,
        "baseline": baseline_record,
    }

    if baseline is None:
        report["baseline_comparison"] = {
            "status": "UNVERIFIED",
            "reason": "preserved FAIL baseline was not found",
        }
    else:
        baseline_dimensions = baseline.get("dimensions", {})
        changes = []
        for dimension in dimensions:
            before = normalized_dimension_rating(baseline_dimensions.get(dimension))
            after = dimension_results[dimension]["rating"]
            if before != after:
                changes.append({"dimension": dimension, "before": before, "after": after})
        before_hard = {finding_id(item) for item in baseline.get("hard_failures", [])}
        after_hard = {finding_id(item) for item in hard_failures}
        before_silent = {finding_id(item) for item in baseline.get("silent_degradations", [])}
        after_silent = {finding_id(item) for item in silent_degradations}
        report["baseline_comparison"] = {
            "status": "PASS",
            "path": str(baseline_path),
            "sha256": baseline_record["sha256"],
            "overall": {"before": baseline.get("overall"), "after": overall},
            "dimension_changes": changes,
            "hard_failures": {
                "before_count": len(before_hard),
                "after_count": len(after_hard),
                "resolved": sorted(before_hard - after_hard),
                "new": sorted(after_hard - before_hard),
            },
            "silent_degradations": {
                "before_count": len(before_silent),
                "after_count": len(after_silent),
                "removed": sorted(before_silent - after_silent),
                "new": sorted(after_silent - before_silent),
            },
            "unverified_count": {
                "before": len(baseline.get("unverified", [])),
                "after": len(unverified),
            },
        }

    return sanitize(report)


def markdown_report(report: Mapping[str, Any]) -> str:
    lines = [
        "# CLIProxyAPI adapter final validation",
        "",
        "Overall: **%s**" % report["overall"],
        "",
        "Decision: **%s**" % report["decision"],
        "",
        "## Dimension ratings",
        "",
        "| Dimension | Rating | Evidence summary |",
        "|---|---|---|",
    ]
    for name, result in report["dimensions"].items():
        lines.append("| %s | %s | %s |" % (name, result["rating"], result["summary"]))

    lines.extend(["", "## Hard failures", ""])
    if report["hard_failures"]:
        for finding in report["hard_failures"]:
            lines.append("- **%s:** %s" % (finding["id"], finding["observed"]))
    else:
        lines.append("- None reported by the selected evidence.")

    lines.extend(["", "## Silent degradations", ""])
    if report["silent_degradations"]:
        for finding in report["silent_degradations"]:
            lines.append("- `%s`: %s" % (finding["id"], finding["observed"]))
    else:
        lines.append("- None in the selected contracts.")

    lines.extend(["", "## Required stages", "", "| Stage | Status | Evidence | SHA-256 |", "|---|---|---|---|"])
    for stage_id, result in report["stage_results"].items():
        lines.append(
            "| %s | %s | `%s` | `%s` |"
            % (stage_id, result["status"], result.get("path") or "missing", result.get("sha256") or "missing")
        )

    lines.extend(["", "## Remaining unverified", ""])
    if report["unverified"]:
        for finding in report["unverified"]:
            lines.append("- `%s` (%s): %s" % (finding["id"], finding["dimension"], finding["detail"]))
    else:
        lines.append("- None.")

    comparison = report["baseline_comparison"]
    lines.extend(["", "## Preserved FAIL baseline comparison", ""])
    if comparison.get("status") != "PASS":
        lines.append("- UNVERIFIED: %s" % comparison.get("reason", "baseline unavailable"))
    else:
        lines.append("- Baseline: `%s`" % comparison["path"])
        lines.append(
            "- Overall: %s -> %s"
            % (comparison["overall"]["before"], comparison["overall"]["after"])
        )
        lines.append(
            "- Hard failures: %d -> %d"
            % (
                comparison["hard_failures"]["before_count"],
                comparison["hard_failures"]["after_count"],
            )
        )
        for change in comparison["dimension_changes"]:
            lines.append(
                "- %s: %s -> %s"
                % (change["dimension"], change["before"], change["after"])
            )

    lines.extend(["", "## Candidate artifacts", "", "| Artifact | Status | SHA-256 | Path |", "|---|---|---|---|"])
    for artifact_id, artifact in report["artifacts"].items():
        lines.append(
            "| %s | %s | `%s` | `%s` |"
            % (artifact_id, artifact["status"], artifact.get("sha256") or "missing", artifact["path"])
        )
    return "\n".join(lines) + "\n"


def run(repo_root: Path = REPO_ROOT, *, now: Optional[datetime] = None) -> Path:
    report = build_report(repo_root, now=now)
    runs_dir = repo_root / ".runs"
    timestamp = parse_timestamp(report["generated_at"]) or datetime.now(timezone.utc)
    run_dir = runs_dir / (
        "final-%s-%s" % (timestamp.strftime("%Y%m%dT%H%M%SZ"), secrets.token_hex(4))
    )
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(str(run_dir), 0o700)
    json_path = run_dir / "final-report.json"
    markdown_path = run_dir / "final-report.md"
    write_private(json_path, json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    write_private(markdown_path, markdown_report(report))
    assert_report_files_safe([json_path, markdown_path])
    return run_dir


def main() -> int:
    run_dir = run()
    report = load(run_dir / "final-report.json")
    print(json.dumps({"run_dir": str(run_dir), "overall": report["overall"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
