import argparse
import json
import os
import traceback

from pcode_ssa_report_v6 import DEFAULT_EXPECTED_PATH, SourceSinkCallSiteBinderV6


def iter_json_inputs(input_dir):
    for name in sorted(os.listdir(input_dir)):
        if name.startswith("case_DFB") and name.endswith("_low_pcode.json"):
            yield os.path.join(input_dir, name)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def report_name_for(json_path):
    base = os.path.splitext(os.path.basename(json_path))[0]
    return base.replace("_low_pcode", "") + "_v6_report.txt"


def run_one(json_path, reports_dir, expected_path):
    report_path = os.path.join(reports_dir, report_name_for(json_path))
    engine = SourceSinkCallSiteBinderV6(json_path)
    engine.build_ssa_graph()
    validation = engine.generate_report(None, report_path, expected_path)
    return {
        "json": json_path,
        "report": report_path,
        "function": engine.data.get("function_name"),
        "verdict": validation.get("verdict"),
        "case_id": validation.get("case_id"),
        "actual_sources": validation.get("actual_sources", []),
        "expected_sources": validation.get("expected_sources", []),
        "missing_expected_sources": validation.get("missing_expected_sources", []),
        "forbidden_sources_found": validation.get("forbidden_sources_found", []),
        "sink_count": len(engine.sink_anchors),
        "source_call_count": len(engine.source_return_nodes),
    }


def write_markdown_summary(summary_path, results, counts):
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# V6 Low-PCode Batch Expected Validation\n\n")
        f.write("## Summary\n\n")
        for verdict, count in sorted(counts.items()):
            f.write(f"- {verdict}: {count}\n")
        f.write("\n## Cases\n\n")
        f.write("| verdict | case | function | actual | expected | report |\n")
        f.write("|---|---|---|---|---|---|\n")
        for result in results:
            actual = ", ".join(result.get("actual_sources", [])) or "-"
            expected = ", ".join(result.get("expected_sources", [])) or "-"
            report = os.path.relpath(result["report"], os.path.dirname(summary_path)).replace(os.sep, "/") if result.get("report") else "-"
            f.write(
                "| {verdict} | {case_id} | {function} | {actual} | {expected} | {report} |\n".format(
                    verdict=result.get("verdict"),
                    case_id=result.get("case_id") or "-",
                    function=result.get("function") or "-",
                    actual=actual,
                    expected=expected,
                    report=report,
                )
            )


def main():
    parser = argparse.ArgumentParser(description="Batch-run v6 Low-PCode source/sink expected validation.")
    parser.add_argument("input_dir", nargs="?", default="samples/low_pcode")
    parser.add_argument("output_dir", nargs="?", default="output/v6_batch")
    parser.add_argument("expected_path", nargs="?", default=DEFAULT_EXPECTED_PATH)
    args = parser.parse_args()

    reports_dir = ensure_dir(os.path.join(args.output_dir, "reports"))
    results = []

    for json_path in iter_json_inputs(args.input_dir):
        try:
            result = run_one(json_path, reports_dir, args.expected_path)
            print("[{verdict}] {function}".format(**result))
        except Exception as exc:
            result = {
                "json": json_path,
                "report": None,
                "function": os.path.basename(json_path).replace("_low_pcode.json", ""),
                "verdict": "ERROR",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
            print("[ERROR] {function}: {error}".format(**result))
        results.append(result)

    counts = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1

    ensure_dir(args.output_dir)
    summary_json = os.path.join(args.output_dir, "summary.json")
    summary_md = os.path.join(args.output_dir, "summary.md")
    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump({"counts": counts, "results": results}, f, indent=2, ensure_ascii=False, sort_keys=True)
    write_markdown_summary(summary_md, results, counts)
    print("[+] Batch summary JSON: %s" % summary_json)
    print("[+] Batch summary Markdown: %s" % summary_md)
    return 1 if counts.get("ERROR") or counts.get("FAIL") else 0


if __name__ == "__main__":
    raise SystemExit(main())
