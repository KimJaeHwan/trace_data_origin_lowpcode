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
- [x] Add observed-storage to primary-storage auto summaries for direct calls.
- [x] Add observed-storage to observed-memory write summaries for x86_64 stack/heap pointer expressions.
- [x] Keep x86_64 multi-input primary summaries conservative by summarizing only the latest primary write.
- [ ] Add callee-entry observed storage nodes.
- [ ] Promote `call_in_reg` candidates with use-before-def evidence.
- [ ] Generalize observed-memory write summaries for x86 stack and ARM/AArch64 register sets.
- [ ] Add field-sensitive observed-memory input summaries for pointer-to-field reads.
- [ ] Add summary cache persistence.

## Current Policy

The Phase 5 MVP handles direct calls by composing per-function slice graphs into
a program-level graph, then applying automatic summaries as explicit
`summary_memory` edges.

The current automatic summary is intentionally narrow:

```text
source boundary -> global storage write
global storage read -> primary observed value storage
observed storage -> primary observed value storage
observed storage -> observed memory write, when the caller pointer expression resolves
```

This is enough for DFB026-style flows where one callee writes source-derived
data into global storage and another callee reads that global storage into an
observed post-call storage. The observed-storage summaries cover direct
identity/nested-call flows and x86_64 pointer-output writes. They do not
introduce argument, return, out-param, or calling convention semantics into core
graph topology; summary edges are still modeled as observed storage transitions.

Current residuals:

```text
DFB057 remains FAIL across all roots: requires field-sensitive memory input summaries.
DFB058/DFB059 PASS on PE_x64 and linux_amd64, remain FAIL on x86, AArch64, and ARMv7:
callee-entry stack/register observed storage mapping is still needed.
Full testbed remains intentionally incomplete for recursion-global, indirect/callback,
libc buffer, C++/exception, thread/runtime, and precision-heavy bitfield/overlap cases.
```

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_basic expected --cases case_DFB001 case_DFB002` | PASS 12 | All architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_dfb026_all_arch expected --cases case_DFB026` | PASS 6 | PE_x64, PE_x86, linux_386, linux_amd64, linux_arm64, linux_arm_v7 |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_global_heap_all_arch expected --cases case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031` | PASS 36 | Includes Phase 4 global/heap all-architecture backfill |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_regression_control_all_arch expected --cases case_DFB010 case_DFB014` | PASS 8 / FAIL 4 | Residual non-gate control/sink-selection precision work remains for x64/aarch64 variants |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_residual_summary_ret_probe expected --cases case_DFB050 case_DFB056` | PASS 12 | Observed-storage primary summaries, all roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_residual_core_gate_probe expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB030 case_DFB031` | PASS 42 | Core/global/heap gate remains stable |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_regression_fix_probe expected --cases case_DFB041 case_DFB051 case_DFB058 case_DFB059 case_DFB061 case_DFB062 case_DFB064 case_DFB101` | PASS 28 / FAIL 20 | x86_64 memory-output summaries pass; known non-x64 residuals remain |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_full_after_summary_refine2 expected --cases` | PASS 273 / FAIL 215 | Full testbed, +13 PASS and 0 regressions against `output/v8_full_after_observed_summary` |
