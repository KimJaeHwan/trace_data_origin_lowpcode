# Phase 3: Control Dependency

Goal: distinguish data-only source collection from data+control source
collection and pass branch/PHI control dependency cases.

## Gate

```text
DFB010 branch phi PASS
DFB014 control-only dependency PASS
DFB001 / DFB002 regression remains PASS across current architecture samples
```

## Implementation Checklist

- [x] Preserve predecessor states at CFG join points.
- [x] Create minimal `PHI` nodes when predecessor storage states differ.
- [x] Track `CBRANCH` condition values.
- [x] Add `control` edges from branch conditions to PHI nodes.
- [x] Keep default validation data-only.
- [x] Run an additional data+control query for reporting and diagnostics.
- [x] Support `expected_control_sources` / `forbidden_control_sources` in the validator.
- [x] Show data and control source sets separately in text reports and batch summaries.

## Current Policy

The Phase 3 implementation is an MVP. It handles acyclic branch joins in the
current DataFlowBench samples by merging predecessor states at CFG join points.
Loop fixed-point convergence, widening, and hashed state comparison remain
future work for the later loop/fixed-point phase.

Data-only traversal remains the validation default. Data+control traversal is
reported separately so control-only sources do not become data sources.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/PE_x86/win_core output/v8_phase3_probe expected --cases case_DFB010 case_DFB014` | PASS 2 | DFB010 data A/B and control C; DFB014 no data source and control C |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase3_regression expected --cases case_DFB001 case_DFB002` | PASS 12 | Phase 1 regression across six architecture/platform sample roots |
