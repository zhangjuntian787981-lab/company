import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "generate-final-report.py"
SPEC = importlib.util.spec_from_file_location("generate_final_report", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
generate_final_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_final_report)


NOW = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
DIMENSIONS = [
    "Security",
    "Protocol",
    "Tools",
    "Resilience",
    "Model/Context",
    "Operability",
]


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_policy():
    required_cases = [
        {"id": "case-%s" % index, "dimension": dimension}
        for index, dimension in enumerate(DIMENSIONS)
    ]
    return {
        "schema_version": 2,
        "ratings": ["PASS", "CONDITIONAL", "FAIL", "UNVERIFIED"],
        "dimensions": DIMENSIONS,
        "hard_failures": ["fixture hard failure"],
        "overall": {
            "FAIL": "hard failure or failed dimension",
            "CONDITIONAL": "required evidence is not PASS",
            "PASS": "all required evidence passes",
        },
        "final_report": {
            "max_evidence_age_seconds": 3600,
            "future_clock_skew_seconds": 60,
            "manifest_path": "patches/manifest.json",
            "manifest_dimension": "Operability",
            "contracts_path": "patches/contracts.json",
            "contracts_dimension": "Protocol",
            "default_hard_failure_dimension": "Operability",
            "baseline": {
                "pattern": "final-*/final-report.json",
                "required_overall": "FAIL",
                "dimension": "Operability",
            },
            "contract_classifications": {
                "DROPPED_SILENTLY": {
                    "dimension": "Protocol",
                    "rating": "CONDITIONAL",
                    "blocks_pass": True,
                }
            },
            "candidate_artifacts": [
                {
                    "id": "candidate_binary",
                    "path": "artifacts/candidate",
                    "dimension": "Operability",
                    "required": True,
                }
            ],
            "required_stages": [
                {
                    "id": "core",
                    "pattern": "core-*/result.json",
                    "status_path": "overall",
                    "pass_values": ["PASS"],
                    "fail_values": ["FAIL"],
                    "dimensions": DIMENSIONS,
                    "checks": [{"path": "checks.complete", "equals": True}],
                    "matches": [
                        {"path": "source_commit", "expected": "manifest.source_commit"},
                        {"path": "patch_set_sha256", "expected": "manifest.patch_set_sha256"},
                        {
                            "path": "candidate_binary_sha256",
                            "expected": "artifacts.candidate_binary.sha256",
                        },
                    ],
                    "required_cases": required_cases,
                }
            ],
            "decisions": {
                "PASS": "fixture pass",
                "CONDITIONAL": "fixture conditional",
                "FAIL": "fixture fail",
            },
        },
    }


def create_fixture(root: Path) -> Path:
    write_json(root / "policy" / "rating-policy.json", fixture_policy())
    artifact = root / "artifacts" / "candidate"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"candidate-binary")
    manifest = {
        "source_commit": "fixture-commit",
        "patches": [
            {
                "id": "fixture-patch",
                "path": "fixture.patch",
                "sha256": "a" * 64,
            }
        ],
    }
    write_json(root / "patches" / "manifest.json", manifest)
    write_json(
        root / "patches" / "contracts.json",
        {
            "contracts": [
                {
                    "id": "supported-contract",
                    "classification": "SUPPORTED",
                    "observed": "preserved",
                }
            ]
        },
    )
    write_json(
        root / ".runs" / "final-old" / "final-report.json",
        {
            "overall": "FAIL",
            "dimensions": {dimension: {"rating": "FAIL"} for dimension in DIMENSIONS},
            "hard_failures": [{"id": "old-hard-failure"}],
            "silent_degradations": ["old degradation"],
            "unverified": ["old unverified"],
        },
    )
    patch_sha = generate_final_report.patch_set_sha256(manifest["patches"])
    stage_path = root / ".runs" / "core-1" / "result.json"
    write_json(
        stage_path,
        {
            "generated_at": NOW.isoformat(),
            "overall": "PASS",
            "source_commit": manifest["source_commit"],
            "patch_set_sha256": patch_sha,
            "candidate_binary_sha256": file_sha256(artifact),
            "checks": {"complete": True},
            "hard_failures": [],
            "cases": [
                {
                    "id": "case-%s" % index,
                    "dimension": dimension,
                    "status": "PASS",
                    "summary": "fixture passed",
                    "hard_failure": False,
                }
                for index, dimension in enumerate(DIMENSIONS)
            ],
        },
    )
    return stage_path


class GenerateFinalReportTests(unittest.TestCase):
    def test_repository_policy_binds_runtime_evidence_and_separates_privileged_stages(self):
        policy = json.loads(
            (SCRIPT_PATH.parents[1] / "policy" / "rating-policy.json").read_text(
                encoding="utf-8"
            )
        )
        stages = {
            stage["id"]: stage
            for stage in policy["final_report"]["required_stages"]
        }
        identity_paths = {
            "source_commit",
            "patch_set_sha256",
            "candidate_binary_sha256",
            "gateway_binary_sha256",
        }
        for stage_id in ("bottle_black_box", "claude_code_e2e"):
            self.assertEqual(
                {match["path"] for match in stages[stage_id]["matches"]},
                identity_paths,
            )
        bottle_cases = {
            case["id"] for case in stages["bottle_black_box"]["required_cases"]
        }
        self.assertNotIn("cliproxyapi-synthetic-oauth-file-refresh", bottle_cases)
        self.assertNotIn("isolated-launchd", bottle_cases)
        self.assertIn("synthetic_oauth", stages)
        self.assertIn("isolated_launchd", stages)
        self.assertTrue(stages["real_upstream"]["requires_explicit_authorization"])

    def test_all_required_evidence_produces_pass_and_baseline_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_fixture(root)

            report = generate_final_report.build_report(root, now=NOW)

            self.assertEqual(report["overall"], "PASS")
            self.assertTrue(
                all(value["rating"] == "PASS" for value in report["dimensions"].values())
            )
            self.assertEqual(report["hard_failures"], [])
            self.assertEqual(report["unverified"], [])
            self.assertIsNotNone(report["chain"]["candidate_binary_sha256"])
            self.assertIsNotNone(report["chain"]["patch_set_sha256"])
            self.assertEqual(report["stage_results"]["core"]["status"], "PASS")
            self.assertIsNotNone(report["stage_results"]["core"]["sha256"])
            self.assertEqual(
                report["baseline_comparison"]["overall"],
                {"before": "FAIL", "after": "PASS"},
            )
            self.assertEqual(
                report["baseline_comparison"]["hard_failures"]["resolved"],
                ["old-hard-failure"],
            )
            run_dir = generate_final_report.run(root, now=NOW)
            persisted = json.loads((run_dir / "final-report.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["overall"], "PASS")
            self.assertTrue((run_dir / "final-report.md").is_file())
            self.assertEqual((run_dir.stat().st_mode & 0o077), 0)
            self.assertEqual(((run_dir / "final-report.json").stat().st_mode & 0o077), 0)

    def test_hard_failure_produces_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage_path = create_fixture(root)
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["cases"][2].update(
                {
                    "status": "FAIL",
                    "summary": "tool arguments crossed call IDs",
                    "hard_failure": True,
                }
            )
            write_json(stage_path, stage)

            report = generate_final_report.build_report(root, now=NOW)

            self.assertEqual(report["overall"], "FAIL")
            self.assertEqual(report["dimensions"]["Tools"]["rating"], "FAIL")
            self.assertEqual([item["id"] for item in report["hard_failures"]], ["case-2"])

    def test_missing_stale_and_mismatched_evidence_are_conditional(self):
        for scenario in ("missing", "stale", "mismatch", "missing-artifact"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage_path = create_fixture(root)
                if scenario == "missing":
                    stage_path.unlink()
                elif scenario == "missing-artifact":
                    (root / "artifacts" / "candidate").unlink()
                else:
                    stage = json.loads(stage_path.read_text(encoding="utf-8"))
                    if scenario == "stale":
                        stage["generated_at"] = "2020-01-01T00:00:00+00:00"
                    else:
                        stage["patch_set_sha256"] = "b" * 64
                    write_json(stage_path, stage)

                report = generate_final_report.build_report(root, now=NOW)

                self.assertEqual(report["overall"], "CONDITIONAL")
                self.assertEqual(report["hard_failures"], [])
                self.assertTrue(
                    any(value["rating"] == "UNVERIFIED" for value in report["dimensions"].values())
                )
                self.assertGreater(len(report["unverified"]), 0)

    def test_stale_or_mismatched_fail_is_unverified_without_hard_failure(self):
        for scenario in ("stale", "mismatch"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stage_path = create_fixture(root)
                stage = json.loads(stage_path.read_text(encoding="utf-8"))
                stage["overall"] = "FAIL"
                stage["hard_failures"] = [{"id": "untrusted-stage-failure"}]
                stage["cases"][2].update(
                    {
                        "status": "FAIL",
                        "summary": "untrusted tool failure",
                        "hard_failure": True,
                    }
                )
                if scenario == "stale":
                    stage["generated_at"] = "2020-01-01T00:00:00+00:00"
                else:
                    stage["patch_set_sha256"] = "b" * 64
                write_json(stage_path, stage)

                report = generate_final_report.build_report(root, now=NOW)

                self.assertEqual(report["overall"], "CONDITIONAL")
                self.assertEqual(report["stage_results"]["core"]["status"], "UNVERIFIED")
                self.assertEqual(report["hard_failures"], [])
                self.assertTrue(
                    all(
                        case["status"] == "UNVERIFIED"
                        for case in report["stage_results"]["core"]["cases"]
                    )
                )

    def test_dropped_silently_blocks_pass_according_to_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_fixture(root)
            write_json(
                root / "patches" / "contracts.json",
                {
                    "contracts": [
                        {
                            "id": "silent-field",
                            "feature": "fixture field",
                            "classification": "DROPPED_SILENTLY",
                            "observed": "field was omitted",
                        }
                    ]
                },
            )

            report = generate_final_report.build_report(root, now=NOW)

            self.assertEqual(report["overall"], "CONDITIONAL")
            self.assertEqual(report["dimensions"]["Protocol"]["rating"], "CONDITIONAL")
            self.assertEqual(
                [item["id"] for item in report["silent_degradations"]],
                ["silent-field"],
            )


if __name__ == "__main__":
    unittest.main()
