# Low-PCode Data Origin Analyzer

Ghidra Low P-Code JSON을 입력으로 받아 DataFlowBench 케이스의 data origin을 역추적하는 실험용 분석기다.

이 저장소는 기존 `tracing_Data_Origin`에서 Low-PCode 전환 작업만 떼어낸 독립 레포다. 기존 High P-Code GUI slicer는 포함하지 않고, `tools/pcode_ssa_report_v5.py` 이후의 Low-PCode 기반 SSA 분석 흐름을 중심으로 구성한다.

## 역할

DataFlowBench의 `case_DFB*` 함수에서 sink 인자로 들어가는 값이 어떤 `dfb_source_*` 함수에서 왔는지 찾고, `expected/*.expected.json` 정답과 비교한다.

흐름은 다음과 같다.

```text
DataFlowBench binary
  -> Ghidra scripts/lowpcode_json_dumper.py
  -> samples/low_pcode/*.json
  -> tools/pcode_ssa_batch_v7.py
  -> output/v7_batch/summary.md
```

## 디렉터리

```text
tools/
  pcode_ssa_report_v5.py      Low-PCode SSA / memory-region baseline
  pcode_ssa_report_v6.py      source/sink call-site binding
  pcode_ssa_report_v7.py      stack object recovery + libc transfer summaries
  pcode_ssa_batch_v6.py       v6 batch validator
  pcode_ssa_batch_v7.py       v7 batch validator
  pcode_summary_builder.py    helper function summary DB builder

scripts/
  lowpcode_json_dumper.py     Ghidra Jython Low P-Code JSON exporter

expected/
  DataFlowBench expected JSON oracle

samples/
  low_pcode/                  checked-in sample Low-PCode dumps
  v7_batch/                   reference v7 batch result

docs/, dev_docs/
  design notes and progress logs from the extraction source
```

## Quick Start

Python side dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the v7 analyzer on the included sample Low-PCode dumps:

```bash
python3 tools/pcode_summary_builder.py samples/low_pcode samples/low_pcode/function_summaries.json
python3 tools/pcode_ssa_batch_v7.py
```

The default batch input is `samples/low_pcode`, default output is `output/v7_batch`, and default oracle path is `expected`.

The current reference sample result is:

```text
PASS: 51
FAIL: 24
```

The command exits with status `1` while FAIL cases remain. That is intentional so it can be used as a regression gate.

## Ghidra Export

To refresh Low-PCode JSON dumps, open a DataFlowBench binary in Ghidra, run Auto Analysis, then run:

```text
scripts/lowpcode_json_dumper.py
```

The dumper exports `case_DFB*` roots and reachable internal helper functions. It skips `dfb_source_*`, `dfb_sink_*`, external functions, and empty-body terminal targets because those are boundaries for the current source/sink analyzer.

The output path is built with `os.path.join`, so the same script works on Windows and macOS/Linux without producing backslash-literal filenames.

## Current Binder Notes

The v6/v7 call-site binder handles both common x86 argument preparation forms:

```text
PUSH arg
CALL target

MOV dword ptr [ESP + n], arg
CALL target
```

## Relationship To DataFlowBench

This repo does not build test binaries. It consumes binaries and expected JSON produced by DataFlowBench. The checked-in `expected/` directory is copied from the local `tdo_testbed/expected` oracle so this repository can run sample validation independently.
