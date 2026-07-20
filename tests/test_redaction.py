import json
import tempfile
import unittest
from pathlib import Path

from harness.redaction import (
    DEFAULT_CANARIES,
    assert_report_files_safe,
    find_violations,
    sanitize,
    summarize_payload,
)


class RedactionTests(unittest.TestCase):
    def test_sensitive_fields_and_canaries_do_not_survive(self):
        source = {
            "status": "ok",
            "Authorization": "Bearer " + DEFAULT_CANARIES[0],
            "access_token": DEFAULT_CANARIES[1],
            "api_key": "sk-COMPATCANARY123456",
            "request_body": DEFAULT_CANARIES[3],
            "note": "prefix %s suffix" % DEFAULT_CANARIES[3],
        }
        encoded = json.dumps(sanitize(source), sort_keys=True).encode("utf-8")
        self.assertEqual(find_violations(encoded), [])
        self.assertNotIn(b"Authorization", encoded)
        self.assertNotIn(b"access_token", encoded)
        self.assertNotIn(b"request_body", encoded)
        self.assertIn(b"[REDACTED]", encoded)

    def test_payload_summary_contains_no_original_body(self):
        raw = json.dumps(
            {"input": DEFAULT_CANARIES[3], "refresh_token": DEFAULT_CANARIES[1]}
        ).encode("utf-8")
        summary = summarize_payload(raw, "application/json")
        encoded = json.dumps(summary).encode("utf-8")
        self.assertNotIn(DEFAULT_CANARIES[3].encode("utf-8"), encoded)
        self.assertNotIn(DEFAULT_CANARIES[1].encode("utf-8"), encoded)
        self.assertEqual(summary["payload_shape"]["hidden_field_count"], 1)

    def test_report_scan_blocks_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"note": DEFAULT_CANARIES[0]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                assert_report_files_safe([path])


if __name__ == "__main__":
    unittest.main()
