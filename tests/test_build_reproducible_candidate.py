import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_reproducible_candidate.py"
SPEC = importlib.util.spec_from_file_location("build_reproducible_candidate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReproducibleCandidateTests(unittest.TestCase):
    def test_patch_set_digest_is_order_sensitive(self):
        patches = [
            {"id": "a", "path": "a.patch", "sha256": "1" * 64},
            {"id": "b", "path": "b.patch", "sha256": "2" * 64},
        ]
        self.assertNotEqual(
            MODULE.patch_set_sha256(patches),
            MODULE.patch_set_sha256(list(reversed(patches))),
        )

    def test_reproducible_requires_both_artifact_hashes_to_match(self):
        first = {"candidate_sha256": "candidate", "gateway_sha256": "gateway"}
        self.assertTrue(MODULE.reproducible(first, dict(first)))
        self.assertFalse(
            MODULE.reproducible(first, {"candidate_sha256": "other", "gateway_sha256": "gateway"})
        )
        self.assertFalse(
            MODULE.reproducible(first, {"candidate_sha256": "candidate", "gateway_sha256": "other"})
        )


if __name__ == "__main__":
    unittest.main()
