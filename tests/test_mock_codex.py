import json
import tempfile
import threading
import unittest
from pathlib import Path

from harness.mock_codex_mitm import (
    EvidenceSink,
    FixtureRegistry,
    MockCodexServer,
    materialize_fixture,
    object_field_values,
)
from harness.runner import LocalHttpClient, _terminal_types, _tool_arguments, sse_request
from harness.redaction import DEFAULT_CANARIES, find_violations


class MockCodexTests(unittest.TestCase):
    def test_object_field_values_collects_only_matching_identifiers(self) -> None:
        value = {
            "items": [
                {"type": "function_call", "call_id": "call_one", "arguments": "private"},
                {"type": "function_call_output", "call_id": "call_two", "output": "private"},
            ]
        }

        self.assertEqual(object_field_values(value, "function_call", "call_id"), ["call_one"])
        self.assertEqual(
            object_field_values(value, "function_call_output", "call_id"), ["call_two"]
        )

    def test_fixture_sequence_advances_and_repeats_last_step(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "first.json").write_text(
                json.dumps({"name": "first", "status": 200}), encoding="utf-8"
            )
            (root / "second.json").write_text(
                json.dumps({"name": "second", "status": 201}), encoding="utf-8"
            )
            (root / "sequence.json").write_text(
                json.dumps({"name": "sequence", "sequence": ["first", "second"]}),
                encoding="utf-8",
            )

            registry = FixtureRegistry(root)

            self.assertEqual(registry.get("sequence", "session-a")["name"], "first")
            self.assertEqual(registry.get("sequence", "session-a")["name"], "second")
            self.assertEqual(registry.get("sequence", "session-a")["name"], "second")
            self.assertEqual(registry.get("sequence", "session-b")["name"], "first")

    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.temp = tempfile.TemporaryDirectory()
        self.evidence_path = Path(self.temp.name) / "evidence.ndjson"
        registry = FixtureRegistry(root / "fixtures" / "scenarios")
        self.server = MockCodexServer(("127.0.0.1", 0), registry, EvidenceSink(self.evidence_path))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = "http://127.0.0.1:%d" % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def test_parallel_tool_deltas_are_interleaved_and_reassemblable(self):
        events = sse_request(
            LocalHttpClient(), self.base_url + "/v1/responses", "parallel_interleaved_tools"
        )
        arguments = _tool_arguments(events)
        self.assertEqual(json.loads(arguments["call_alpha"]), {"value": "alpha", "n": 1})
        self.assertEqual(json.loads(arguments["call_beta"]), {"value": "beta", "n": 2})
        self.assertEqual(_terminal_types(events), ["response.completed"])

    def test_mock_evidence_never_contains_canary_or_original_body(self):
        client = LocalHttpClient()
        raw = json.dumps({"input": DEFAULT_CANARIES[3]}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Compat-Scenario": "text",
            "Authorization": "Bearer " + DEFAULT_CANARIES[0],
        }
        with client.open(self.base_url + "/v1/responses", "POST", raw, headers) as response:
            response.read()
        data = self.evidence_path.read_bytes()
        self.assertEqual(find_violations(data), [])
        self.assertNotIn(DEFAULT_CANARIES[3].encode("utf-8"), data)

    def test_request_scoped_fixture_ids_are_stable_and_distinct(self):
        fixture = self.server.fixtures.get("parallel_interleaved_tools_dynamic")
        first = materialize_fixture(fixture, b'{"input":"first"}')
        repeated = materialize_fixture(fixture, b'{"input":"first"}')
        second = materialize_fixture(fixture, b'{"input":"second"}')
        first_text = json.dumps(first, sort_keys=True)
        self.assertEqual(first, repeated)
        self.assertNotEqual(first, second)
        self.assertNotIn("{{request_sha12}}", first_text)
        self.assertNotIn("request_hash_placeholders", first)


if __name__ == "__main__":
    unittest.main()
