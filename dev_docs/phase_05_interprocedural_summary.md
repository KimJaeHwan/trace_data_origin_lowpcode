# Phase 5: Interprocedural Skeleton + Bottom-up Auto Summary

Goal: add a program-level graph skeleton and minimal automatic summaries for
direct calls while keeping the core convention-free.

## Gate

```text
DFB026 global interprocedural reader PASS across all architecture sample roots.
Phase 4 global/heap cases remain PASS across all architecture sample roots.
DFB001 / DFB002 all-architecture regression remains PASS.
```

## Implementation Checklist

- [x] Add `ProgramSliceGraph` composition path to the batch runner.
- [x] Add `MinimalAutoFunctionSummaryProvider` skeleton.
- [x] Record direct call graph edges from resolved low-pcode call targets.
- [x] Compute SCC ids for direct-call graph components.
- [x] Interpret Address-to/from-Address `COPY` as global memory storage.
- [x] Summarize source-boundary to global-storage writes.
- [x] Summarize global-storage reads to primary observed value storage.
- [x] Inject `summary_memory` edges at caller callsites for global write/read flow.
- [x] Use Ghidra data-reference hints for computed global storage keys.
- [x] Preserve allocator storage through `realloc` from observed heap-pointer storage.
- [ ] Add callee-entry observed storage nodes.
- [ ] Promote `call_in_reg` candidates with use-before-def evidence.
- [ ] Add general observed-storage to observed-storage auto summaries.
- [ ] Add summary cache persistence.

## Current Policy

The Phase 5 MVP handles direct calls by composing per-function slice graphs into
a program-level graph, then applying automatic summaries as explicit
`summary_memory` edges.

The current automatic summary is intentionally narrow:

```text
source boundary -> global storage write
global storage read -> primary observed value storage
```

This is enough for DFB026-style flows where one callee writes source-derived
data into global storage and another callee reads that global storage into an
observed post-call storage. It does not introduce argument, return, or calling
convention semantics into core graph topology.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_basic expected --cases case_DFB001 case_DFB002` | PASS 12 | All architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_dfb026_all_arch expected --cases case_DFB026` | PASS 6 | PE_x64, PE_x86, linux_386, linux_amd64, linux_arm64, linux_arm_v7 |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_global_heap_all_arch expected --cases case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031` | PASS 36 | Includes Phase 4 global/heap all-architecture backfill |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_control_all_arch expected --cases case_DFB010 case_DFB014` | PASS 8 / FAIL 4 | Residual non-gate control/sink-selection precision work remains for x64/aarch64 variants |
