# Phase 5: Interprocedural Skeleton + Bottom-up Auto Summary

Goal: add a program-level graph skeleton and minimal automatic summaries for
direct calls while keeping the core convention-free.

## Gate

```text
DFB026 global interprocedural reader PASS across all architecture sample roots.
Phase 4 global/heap cases remain PASS across all architecture sample roots.
DFB001 / DFB002 all-architecture regression remains PASS.
DFB057 / DFB058 / DFB059 observed-memory summary cases PASS across all architecture sample roots.
DFB152 callee use-before-def case PASS across all architecture sample roots.
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
- [x] Load Ghidra register/address-space metadata as architecture storage hints.
- [x] Generalize observed-memory write summaries for x86 stack and ARM/AArch64 register sets.
- [x] Load schema v4 structured metadata identity for architecture/index-aware caches.
  - Uses `metadata_identity.metadata_hash` and structured architecture metadata.
  - Does not use calling convention, signature, parameter, local-variable, or
    stack-frame facts as core semantics.
- [x] Add callee-entry observed storage nodes.
- [x] Promote `call_in_reg` candidates with use-before-def evidence.
- [x] Add field-sensitive observed-memory input summaries for pointer-to-field reads.
- [x] Add summary cache persistence.

## Current Policy

The Phase 5 MVP handles direct calls by composing per-function slice graphs into
a program-level graph, then applying automatic summaries as first-class
`call_out_*` boundary edges. The older `summary_data` / `summary_memory`
relation names are retained only as edge provenance (`summary_kind` / `opcode`)
so reports can explain why the boundary edge exists.

The current automatic summary is intentionally narrow:

```text
source boundary -> global storage write
global storage read -> primary observed value storage
observed storage -> primary observed value storage
observed storage -> observed memory write, when the caller pointer expression resolves
source boundary -> observed memory write, when callee low-pcode stores a source-derived value through an observed pointer
observed memory read through observed pointer -> primary observed value storage
observed storage -> double-dereferenced observed memory write, when low-pcode shows pointer-loaded address flow
observed storage -> caller memory after call, when callee low-pcode writes through an observed pointer and caller post-call memory evidence exists
```

This is enough for DFB026-style flows where one callee writes source-derived
data into global storage and another callee reads that global storage into an
observed post-call storage. The observed-storage summaries cover direct
identity/nested-call flows and pointer-output writes across x86, x86_64,
AArch64, and ARMv7 sample roots. They do not
introduce argument, return, out-param, or calling convention semantics into core
graph topology; summary edges are still modeled as observed storage transitions.

Ghidra metadata is used only as storage/address/symbol identity metadata:
register aliases, special register filtering, address-space classification,
data-reference address identity, import/thunk naming, and metadata cache
identity. It does not add named argument, return, calling-convention, parameter,
local-variable, or stack-frame semantics to the analysis model.

Current residuals:

```text
Full testbed remains intentionally incomplete for recursion-global, indirect/callback,
C++/exception, thread/runtime, deep-field nested pointer passthrough summaries,
and trusted external import helper coverage.
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
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_metadata_summary_probe7 expected --cases case_DFB058 case_DFB059` | PASS 12 | Observed-memory output summaries now pass on PE_x64, PE_x86, linux_386, linux_amd64, linux_arm64, linux_arm_v7 |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_metadata_phase5_gate_final expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB058 case_DFB059` | PASS 72 | Phase 5 metadata-backed gate across all architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_metadata_full_final expected --cases` | PASS 313 / FAIL 175 | Full testbed, +40 PASS and 0 regressions against `output/v8_full_after_summary_refine2` |
| 2026-06-20 | `python3 scripts/run_ghidra_headless_lowpcode.py` | 848 function JSON files extracted | Schema v4 metadata: registers, register aliases, address spaces, symbols, data refs, imports, thunks, metadata hash |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_metadata_v4_phase5_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB058 case_DFB059` | PASS 72 | Schema v4 metadata-backed Phase 5 gate across all architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_metadata_v4_full expected --cases` | PASS 313 / FAIL 175 | Full testbed, 0 regressions against `output/v8_metadata_full_final`, +40 PASS and 0 regressions against `output/v8_full_after_summary_refine2` |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_completed_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Completed Phase 5 gate with field-sensitive observed-memory input and callee use-before-def coverage |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_completed_risky expected --cases case_DFB021 case_DFB022 case_DFB023 case_DFB053 case_DFB055 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB151 case_DFB152` | PASS 42 / FAIL 24 | Expected residuals stay in 021/023/053/055; 056/057/058/059/151/152 PASS across all roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_completed_full2 expected --cases` | PASS 334 / FAIL 154 | Full testbed, +21 PASS and 0 regressions against `output/v8_metadata_v4_full` |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_outparam_closed_v2 expected --cases case_DFB021 case_DFB022 case_DFB023` | PASS 18 | Source-to-memory outparam and double-pointer summaries now pass across all architecture/platform roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_callout_phase5_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Phase 5 gate remains stable after first-class `call_out_*` boundary promotion |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_risky_after_callout expected --cases case_DFB020 case_DFB021 case_DFB022 case_DFB023 case_DFB034 case_DFB035 case_DFB040 case_DFB041 case_DFB042 case_DFB043 case_DFB044 case_DFB045 case_DFB046 case_DFB047 case_DFB048 case_DFB049 case_DFB053 case_DFB055 case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 104 / FAIL 28 | DFB021/DFB023 residuals closed; remaining failures are bitfield, partial-overwrite, large-struct, and deep-field clusters |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_callout_full expected --cases` | PASS 370 / FAIL 118 | Full testbed, +36 PASS against `output/v8_phase5_completed_full2` |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_deep_struct_probe2 expected --cases case_DFB053 case_DFB055` | PASS 6 / FAIL 6 | DFB053 large struct return-buffer flow passes across all roots; DFB055 remains nested deep-field passthrough work |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_large_struct_regression_gate expected --cases case_DFB050 case_DFB053 case_DFB056 case_DFB057 case_DFB058 case_DFB059` | PASS 36 | Large-struct return-buffer closure preserves existing interprocedural summary gate cases |
