from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from report.expected_validator import ExpectedValidator


class ExpectedValidatorRecallFirstTest(unittest.TestCase):
    def _validator(self, cases: list[dict]) -> ExpectedValidator:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "cases.expected.json"
        path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
        return ExpectedValidator(path)

    def test_positive_case_passes_with_precision_candidates(self):
        validator = self._validator(
            [
                {
                    "id": "POS001",
                    "function": "case_POS001",
                    "expected_data_sources": ["source_A.ret"],
                    "forbidden_data_sources": ["source_B.ret"],
                }
            ]
        )

        result = validator.validate("case_POS001", {"source_A.ret", "source_B.ret"})

        self.assertEqual("PASS", result["verdict"])
        self.assertTrue(result["recall_pass"])
        self.assertFalse(result["precision_clean"])
        self.assertEqual("REFINEMENT_PENDING", result["precision_status"])
        self.assertEqual(["source_B.ret"], result["forbidden_sources_found"])

    def test_positive_case_still_fails_when_expected_source_is_missing(self):
        validator = self._validator(
            [
                {
                    "id": "POS002",
                    "function": "case_POS002",
                    "expected_data_sources": ["source_A.ret"],
                    "forbidden_data_sources": ["source_B.ret"],
                }
            ]
        )

        result = validator.validate("case_POS002", {"source_B.ret"})

        self.assertEqual("FAIL", result["verdict"])
        self.assertFalse(result["recall_pass"])
        self.assertEqual(["source_A.ret"], result["missing_expected_sources"])

    def test_unlisted_extra_source_is_also_a_precision_candidate(self):
        validator = self._validator(
            [
                {
                    "id": "CASE001",
                    "function": "case_CASE001",
                    "expected_data_sources": ["source_A.ret"],
                    "forbidden_data_sources": [],
                }
            ]
        )

        result = validator.validate("case_CASE001", {"source_A.ret", "source_new.ret"})

        self.assertEqual("PASS", result["verdict"])
        self.assertEqual(["source_new.ret"], result["precision_candidate_sources"])
        self.assertEqual("REFINEMENT_PENDING", result["precision_status"])

    def test_flow_fallback_ignores_composite_source_descriptions(self):
        validator = self._validator(
            [
                {
                    "id": "FUSED001",
                    "function": "case_FUSED001",
                    "expected_data_sources": ["expected_data_sources_placeholder"],
                    "expected_flow": [
                        {"sink": "first sink", "source": "source_A.ret"},
                        {"sink": "second sink", "source": "source_C.ret"},
                        {
                            "sink": "joined sink",
                            "source": "source_A.ret+source_C.ret",
                            "kind": "fusion",
                        },
                    ],
                }
            ]
        )

        result = validator.validate(
            "case_FUSED001",
            {"source_A.ret", "source_C.ret"},
        )

        self.assertEqual("PASS", result["verdict"])
        self.assertEqual(
            ["source_A.ret", "source_C.ret"],
            result["expected_sources"],
        )
        self.assertEqual([], result["missing_expected_sources"])

    def test_negative_case_rejects_any_observed_source(self):
        validator = self._validator(
            [
                {
                    "id": "NEG001",
                    "function": "case_NEG001",
                    "expected_no_sources": True,
                    "forbidden_data_sources": ["source_A.ret"],
                }
            ]
        )

        result = validator.validate("case_NEG001", {"unexpected_source.ret"})

        self.assertEqual("FAIL", result["verdict"])
        self.assertTrue(result["negative_case"])
        self.assertFalse(result["negative_control_pass"])
        self.assertEqual("NEGATIVE_CONTROL_VIOLATION", result["precision_status"])
        self.assertEqual(["unexpected_source.ret"], result["forbidden_sources_found"])

    def test_negative_case_passes_only_when_candidate_set_is_empty(self):
        validator = self._validator(
            [
                {
                    "id": "NEG002",
                    "function": "case_NEG002",
                    "expected_no_sources": True,
                    "forbidden_data_sources": ["source_A.ret"],
                }
            ]
        )

        result = validator.validate("case_NEG002", set(), set())

        self.assertEqual("PASS", result["verdict"])
        self.assertTrue(result["negative_control_pass"])
        self.assertEqual("CLEAN", result["precision_status"])


if __name__ == "__main__":
    unittest.main()
