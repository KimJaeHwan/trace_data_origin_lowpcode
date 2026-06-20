import argparse
import json
import os
import sys
import traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.slice_graph_builder import SliceGraphBuilder
from frontend.low_pcode_loader import LowPcodeLoader
from query.backward_slice import BackwardSliceQuery
from report.expected_validator import ExpectedValidator
from report.graph_exporter import GraphExporter
from report.text_report import TextReport


DEFAULT_EXPECTED_PATH = REPO_ROOT / "expected"


def iter_json_inputs(input_dir: Path, case_filter: set[str] | None = None):
    for path in sorted(input_dir.rglob("case_DFB*_low_pcode.json")):
        if case_filter and not any(path.name.startswith(case) for case in case_filter):
            continue
        yield path


def result_name_for(json_path: Path) -> str:
    return json_path.stem.replace("_low_pcode", "")


def case_output_dir(json_path: Path, input_root: Path, output_dir: Path) -> Path:
    try:
        relative_parent = json_path.relative_to(input_root).parent
    except ValueError:
        relative_parent = Path()
    return output_dir / relative_parent / result_name_for(json_path)


def run_one(json_path: Path, input_root: Path, output_dir: Path, expected_path: Path) -> dict:
    program = LowPcodeLoader().load(json_path)
    function_graph = SliceGraphBuilder().build(program)
    query = BackwardSliceQuery(function_graph)

    slices = []
    actual_sources = set()
    for sink_node in function_graph.sink_index.values():
        result = query.run(sink_node)
        slices.append(result)
        actual_sources.update(result.source_labels)

    validation = ExpectedValidator(expected_path).validate(function_graph.function_name, actual_sources)

    case_out = case_output_dir(json_path, input_root, output_dir)
    case_out.mkdir(parents=True, exist_ok=True)
    exporter = GraphExporter()
    exporter.export_json(function_graph.slice_graph, case_out / "slice_graph.json")
    exporter.export_json(function_graph.cfg, case_out / "cfg.json")
    exporter.export_dot(function_graph.slice_graph, case_out / "slice_graph.dot")
    try:
        exporter.export_graphml(function_graph.slice_graph, case_out / "slice_graph.graphml")
        exporter.export_graphml(function_graph.cfg, case_out / "cfg.graphml")
    except Exception as exc:
        function_graph.warnings.append(f"graphml_export_failed:{exc}")

    report_path = case_out / "report.md"
    TextReport().write(report_path, function_graph, validation, slices)

    return {
        "json": str(json_path),
        "output_dir": str(case_out),
        "report": str(report_path),
        "function": function_graph.function_name,
        "architecture": function_graph.architecture.name,
        "verdict": validation.get("verdict"),
        "case_id": validation.get("case_id"),
        "actual_sources": validation.get("actual_sources", []),
        "expected_sources": validation.get("expected_sources", []),
        "missing_expected_sources": validation.get("missing_expected_sources", []),
        "forbidden_sources_found": validation.get("forbidden_sources_found", []),
        "sink_count": len(function_graph.sink_index),
        "source_count": len(function_graph.source_index),
        "warnings": list(function_graph.warnings),
    }


def write_summary(output_dir: Path, results: list[dict], counts: dict[str, int]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.json").write_text(
        json.dumps({"counts": counts, "results": results}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    lines = ["# V8 Low-PCode Batch", "", "## Summary", ""]
    for verdict, count in sorted(counts.items()):
        lines.append(f"- {verdict}: {count}")
    lines.extend(["", "## Cases", "", "| verdict | arch | case | function | actual | expected | report |", "|---|---|---|---|---|---|---|"])
    for result in results:
        report = os.path.relpath(result.get("report", ""), output_dir).replace(os.sep, "/") if result.get("report") else "-"
        lines.append(
            "| {verdict} | {architecture} | {case_id} | {function} | {actual} | {expected} | {report} |".format(
                verdict=result.get("verdict"),
                architecture=result.get("architecture") or "-",
                case_id=result.get("case_id") or "-",
                function=result.get("function") or "-",
                actual=", ".join(result.get("actual_sources", [])) or "-",
                expected=", ".join(result.get("expected_sources", [])) or "-",
                report=report,
            )
        )
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="V8 / New V1 Phase 1 Low-PCode SliceGraph batch runner.")
    parser.add_argument("input_dir", nargs="?", default=str(REPO_ROOT / "samples" / "low_pcode"))
    parser.add_argument("output_dir", nargs="?", default=str(REPO_ROOT / "output" / "v8_phase1"))
    parser.add_argument("expected_path", nargs="?", default=str(DEFAULT_EXPECTED_PATH))
    parser.add_argument("--cases", nargs="*", default=["case_DFB001", "case_DFB002"])
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    expected_path = Path(args.expected_path)
    case_filter = set(args.cases) if args.cases else None

    results = []
    for json_path in iter_json_inputs(input_dir, case_filter):
        try:
            result = run_one(json_path, input_dir, output_dir, expected_path)
            print("[{verdict}] {architecture} {function}".format(**result))
        except Exception as exc:
            result = {
                "json": str(json_path),
                "function": json_path.name.replace("_low_pcode.json", ""),
                "architecture": "-",
                "verdict": "ERROR",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
            print("[ERROR] {function}: {error}".format(**result))
        results.append(result)

    counts: dict[str, int] = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
    write_summary(output_dir, results, counts)
    print(f"[+] Summary: {output_dir / 'summary.md'}")
    return 1 if counts.get("ERROR") or counts.get("FAIL") else 0


if __name__ == "__main__":
    raise SystemExit(main())
