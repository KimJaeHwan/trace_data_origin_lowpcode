from __future__ import annotations

import json
import re
from pathlib import Path


class ExpectedValidator:
    def __init__(self, expected_path: str | Path):
        self.expected_path = Path(expected_path)
        self.cases, self.case_ids = self._load_cases(self.expected_path)

    def validate(
        self,
        function_name: str,
        actual_sources: set[str],
        actual_control_sources: set[str] | None = None,
        sink_count: int | None = None,
    ) -> dict:
        actual_sources = self._canonical_source_set(actual_sources)
        actual_control_sources = self._canonical_source_set(actual_control_sources or set())
        case = self.cases.get(function_name)
        if case is None:
            no_observed_flow = not actual_sources and not actual_control_sources
            family_id = self._case_family_id(function_name)
            dependency_without_flow = bool(
                no_observed_flow
                and family_id
                and family_id in self.case_ids
            )
            no_sink_without_flow = bool(no_observed_flow and sink_count == 0)
            if dependency_without_flow or no_sink_without_flow:
                reason = (
                    "no_sink_without_observed_flow"
                    if no_sink_without_flow
                    else "expected_family_dependency_without_observed_flow"
                )
                return {
                    "case_id": family_id,
                    "function": function_name,
                    "verdict": "PASS",
                    "actual_sources": sorted(actual_sources),
                    "actual_control_sources": sorted(actual_control_sources),
                    "expected_sources": [],
                    "expected_control_sources": [],
                    "missing_expected_sources": [],
                    "missing_expected_control_sources": [],
                    "forbidden_sources_found": [],
                    "forbidden_control_sources_found": [],
                    "validation_reason": reason,
                }
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
        expected = self._expected_sources_for_case(case)
        expected_control = self._canonical_source_set(set(case.get("expected_control_sources") or []))
        forbidden = self._canonical_source_set(set(case.get("forbidden_data_sources") or case.get("forbidden_sources") or []))
        forbidden_control = self._canonical_source_set(set(case.get("forbidden_control_sources") or []))
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

    def _load_cases(self, expected_path: Path) -> tuple[dict[str, dict], set[str]]:
        cases: dict[str, dict] = {}
        case_ids: set[str] = set()
        paths = [expected_path] if expected_path.is_file() else sorted(expected_path.glob("*.expected.json"))
        for path in paths:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for case in data.get("cases", []):
                function = case.get("function")
                if function:
                    cases[function] = case
                case_id = case.get("id") or self._case_family_id(function or "")
                if case_id:
                    case_ids.add(str(case_id))
        return cases, case_ids

    def _case_family_id(self, function_name: str) -> str | None:
        match = re.match(r"^case_([^_]+)", function_name or "")
        return match.group(1) if match else None

    def _expected_sources_for_case(self, case: dict) -> set[str]:
        flow_sources = self._expected_flow_sources(case)
        if flow_sources:
            return flow_sources
        return self._canonical_source_set(set(case.get("expected_data_sources") or case.get("expected_sources") or []))

    def _expected_flow_sources(self, case: dict) -> set[str]:
        sources: set[str] = set()
        for entry in case.get("expected_flow") or []:
            if not isinstance(entry, dict):
                continue
            if "sink" not in str(entry.get("sink") or "").lower():
                continue
            for key in ("source", "carries", "from"):
                value = entry.get(key)
                if isinstance(value, str) and self._is_source_label_token(value):
                    sources.add(self._canonical_source_label(value))
        return sources

    def _is_source_label_token(self, value: str) -> bool:
        return re.match(r"^[^\s]+\.ret$", value or "") is not None

    def _canonical_source_set(self, values: set[str]) -> set[str]:
        return {self._canonical_source_label(value) for value in values}

    def _canonical_source_label(self, value: str) -> str:
        match = re.match(r"^(dfb_source_.+?)_[0-9a-fA-F]{6,16}(\.ret)$", value or "")
        if match:
            return f"{match.group(1)}{match.group(2)}"
        return value
