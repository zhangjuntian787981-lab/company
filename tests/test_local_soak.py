import json
import os
import tempfile
import unittest
from pathlib import Path

from harness.local_soak import (
    SCENARIO_BY_KIND,
    SOAK_KINDS,
    SoakCounters,
    build_checks,
    build_payload,
    parse_concurrency_levels,
    parse_goroutine_count,
    resource_pair_is_bounded,
    soak_environment,
    validate_replay_response,
)


class LocalSoakTests(unittest.TestCase):
    def test_final_policy_requires_all_formal_soak_gates(self):
        policy_path = Path(__file__).resolve().parents[1] / "policy" / "rating-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        stages = {
            stage["id"]: stage
            for stage in policy["final_report"]["required_stages"]
        }
        self.assertEqual(
            {check["path"] for check in stages["local_soak"]["checks"]},
            {
                "checks.zero_duplicate_tools",
                "checks.zero_budget_overruns",
                "checks.zero_resource_leaks",
                "checks.bounded_artifact_growth",
                "checks.expected_upstream_attempts",
                "checks.operation_matrix_passed",
                "checks.duration_completed",
                "checks.minimum_duration_met",
                "checks.required_concurrency_covered",
                "checks.production_untouched",
                "checks.loopback_only",
            },
        )

    def test_default_concurrency_levels(self):
        self.assertEqual(parse_concurrency_levels("1,4,16"), (1, 4, 16))
        with self.assertRaises(ValueError):
            parse_concurrency_levels("1,0,16")
        with self.assertRaises(ValueError):
            parse_concurrency_levels("1,4,4")

    def test_payload_matrix_is_synthetic_and_complete(self):
        for kind in SOAK_KINDS:
            payload = build_payload(kind, "run-phase-w0-n1")
            self.assertEqual(payload["model"], payload["model"].strip())
            self.assertEqual(payload["messages"][0]["role"], "user")
            self.assertEqual(payload["stream"], kind in {"sse", "tool", "disconnect"})
        self.assertEqual(len(build_payload("tool", "id")["tools"]), 2)

    def test_soak_environment_does_not_inherit_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.environ.get("EXAMPLE_API_KEY")
            os.environ["EXAMPLE_API_KEY"] = "must-not-be-inherited"
            try:
                env = soak_environment(Path(directory))
            finally:
                if old is None:
                    os.environ.pop("EXAMPLE_API_KEY", None)
                else:
                    os.environ["EXAMPLE_API_KEY"] = old
        self.assertNotIn("EXAMPLE_API_KEY", env)
        self.assertEqual(env["COMPAT_NETWORK_POLICY"], "loopback-only-port-8317-denied")

    def test_resource_pair_has_small_idle_tolerance(self):
        before = {"alive": True, "file_descriptors": 10, "goroutines": 20}
        self.assertTrue(
            resource_pair_is_bounded(
                before,
                {"alive": True, "file_descriptors": 12, "goroutines": 22},
            )
        )
        self.assertFalse(
            resource_pair_is_bounded(
                before,
                {"alive": True, "file_descriptors": 13, "goroutines": 20},
            )
        )
        self.assertEqual(parse_goroutine_count("goroutine profile: total 37\n"), 37)

    def test_non_replayable_tool_must_be_http_424(self):
        self.assertEqual(validate_replay_response("tool", 424, []), [])
        with self.assertRaises(AssertionError):
            validate_replay_response("tool", 200, [])

    def test_policy_checks_require_exact_attempts_for_overall_matrix(self):
        counters = SoakCounters()
        for kind in SOAK_KINDS:
            counters.record(
                "concurrency-1",
                kind,
                {"statuses": [200, 200], "tool_ids": [], "replay_tool_ids": []},
                None,
            )
        observed = dict(counters.expected_upstream)
        phases = [
            {
                "resource_bounded": True,
                "gateways_stopped": True,
            }
        ]
        checks = build_checks(
            counters,
            phases,
            observed,
            processes_stopped=True,
            production_untouched=True,
            duration_completed=True,
            minimum_duration_met=True,
            required_concurrency_covered=True,
            artifact_bytes=1024,
            max_artifact_bytes=2048,
        )
        self.assertTrue(all(checks.values()))
        observed[SCENARIO_BY_KIND["http_500"]] = 2
        checks = build_checks(
            counters,
            phases,
            observed,
            processes_stopped=True,
            production_untouched=True,
            duration_completed=True,
            minimum_duration_met=True,
            required_concurrency_covered=True,
            artifact_bytes=1024,
            max_artifact_bytes=2048,
        )
        self.assertFalse(checks["zero_budget_overruns"])
        self.assertFalse(checks["expected_upstream_attempts"])

        short_checks = build_checks(
            counters,
            phases,
            dict(counters.expected_upstream),
            processes_stopped=True,
            production_untouched=True,
            duration_completed=True,
            minimum_duration_met=False,
            required_concurrency_covered=True,
            artifact_bytes=1024,
            max_artifact_bytes=2048,
        )
        self.assertFalse(short_checks["minimum_duration_met"])


if __name__ == "__main__":
    unittest.main()
