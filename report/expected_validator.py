from __future__ import annotations

import json
from pathlib import Path


class ExpectedValidator:
    def __init__(self, expected_path: str | Path):
        self.expected_path = Path(expected_path)
        self.cases = self._load_cases(self.expected_path)

    def validate(
        self,
        function_name: str,
        actual_sources: set[str],
        actual_control_sources: set[str] | None = None,
    ) -> dict:
        actual_control_sources = actual_control_sources or set()
        case = self.cases.get(function_name)
        if case is None:
            return {
                "case_id": None,
                "function": function_name,
                "verdict": "NO_EXPECTED",
                "actual_sources": sorted(actual_sources),
                "actual_control_sources": sorted(actual_control_sources),
                "expected_sources": [],
                "expected_control_sources": [],
                "missing_expected_sources": [],
                "missing_expected_control_sources": [],
                "forbidden_sources_found": [],
                "forbidden_control_sources_found": [],
            }
        expected = set(case.get("expected_data_sources") or case.get("expected_sources") or [])
        expected_control = set(case.get("expected_control_sources") or [])
        forbidden = set(case.get("forbidden_data_sources") or case.get("forbidden_sources") or [])
        forbidden_control = set(case.get("forbidden_control_sources") or [])
        missing = sorted(expected - actual_sources)
        missing_control = sorted(expected_control - actual_control_sources)
        forbidden_found = sorted(forbidden & actual_sources)
        forbidden_control_found = sorted(forbidden_control & actual_control_sources)
        verdict = "PASS" if not missing and not missing_control and not forbidden_found and not forbidden_control_found else "FAIL"
        return {
            "case_id": case.get("id"),
            "function": function_name,
            "verdict": verdict,
            "actual_sources": sorted(actual_sources),
            "actual_control_sources": sorted(actual_control_sources),
            "expected_sources": sorted(expected),
            "expected_control_sources": sorted(expected_control),
            "missing_expected_sources": missing,
            "missing_expected_control_sources": missing_control,
            "forbidden_sources_found": forbidden_found,
            "forbidden_control_sources_found": forbidden_control_found,
        }

    def _load_cases(self, expected_path: Path) -> dict[str, dict]:
        cases: dict[str, dict] = {}
        paths = [expected_path] if expected_path.is_file() else sorted(expected_path.glob("*.expected.json"))
        for path in paths:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for case in data.get("cases", []):
                cases[case.get("function")] = case
        return cases
