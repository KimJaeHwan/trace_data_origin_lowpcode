from __future__ import annotations

from pathlib import Path

from core.graph import FunctionGraph
from query.backward_slice import SliceResult


class TextReport:
    def write(self, path: str | Path, function_graph: FunctionGraph, validation: dict, slices: list[SliceResult]) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# V8 Phase 1 Report: {function_graph.function_name}",
            "",
            f"architecture: {function_graph.architecture.name}",
            f"verdict: {validation.get('verdict')}",
            f"case_id: {validation.get('case_id') or '-'}",
            "",
            "## Sources",
            "",
            "actual: " + (", ".join(validation.get("actual_sources", [])) or "-"),
            "expected: " + (", ".join(validation.get("expected_sources", [])) or "-"),
            "",
            "## Slice Edges",
            "",
        ]
        for result in slices:
            lines.append(f"target: {result.target}")
            for source, target, kind in result.edges:
                lines.append(f"  [{kind}] {source} -> {target}")
            if not result.edges:
                lines.append("  -")
            lines.append("")
        if function_graph.warnings:
            lines.extend(["## Warnings", ""])
            lines.extend(f"- {warning}" for warning in function_graph.warnings)
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
