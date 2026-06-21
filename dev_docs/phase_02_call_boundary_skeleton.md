# Phase 2: Convention-Free Call Boundary Skeleton

Goal: introduce convention-free call boundary nodes without reconnecting
post-call storage to stale pre-call values.

## Gate

```text
CALLSITE nodes exist.
CALL_PRE_* observed storage nodes exist.
CALL_POST_REG candidate nodes exist.
CALL_POST_REG candidates do not depend on stale pre-call register values.
DFB001 / DFB002 regression remains PASS across current architecture samples.
```

## Implementation Checklist

- [x] Add `analysis.call_resolver.CallResolver`.
- [x] Add `analysis.call_boundary_mapper.CallBoundaryMapper`.
- [x] Add `CallContext` and `ObservedStorage` skeletons.
- [x] Add `FunctionGraph.callsite_index`.
- [x] Add `FunctionGraph.call_pre_storage_index`.
- [x] Add `FunctionGraph.call_post_storage_index`.
- [x] Add `CALLSITE` synthetic nodes.
- [x] Add `CALL_PRE_REG` synthetic nodes for observed pre-call registers.
- [x] Add `CALL_PRE_STACK` / `CALL_PRE_MEM` candidates for the most recent observed memory store.
- [x] Add safe-lazy `CALL_POST_REG` candidate nodes for architecture general register aliases.
- [x] Clear recent memory store after call boundary materialization.
- [x] Replace the prototype `SOURCE_RET` opcode label with `SOURCE_BOUNDARY_VALUE`.
- [x] Add callee-entry observed storage nodes.
- [x] Add verified `call_in_reg`, `call_in_stack`, and `call_in_mem` edges once callee-entry observation exists.
  - Only callee use-before-def observed storage becomes a default data-slice edge.
  - Unverified convention-like candidates are not promoted.
- [x] Add `call_out_*` edges once summaries or callee exit observation exists.
  - Verified automatic and external summary outputs are represented as
    first-class `call_out_reg`, `call_out_mem`, or `call_out_global` edges.
  - Legacy summary relation names are preserved as edge provenance via
    `summary_kind` / `opcode`; they are not the primary boundary taxonomy.
  - Source-to-outparam memory writes and double-pointer writes are summarized
    from low-pcode evidence, including ARM/AArch64 `LOAD <- OBSERVED_MEMORY`
    address forms.

Closed dependency:

- The `call_out_*` item overlapped with Phase 5 because Phase 2 only created
  convention-free call boundary candidates.
- Phase 5 added the evidence model that verifies `call_in_*` through
  observed-storage reachability and use-before-def analysis.
- Verified summary outputs now use first-class `call_out_*` edges, so Phase 2's
  call boundary taxonomy is closed without introducing argument, return,
  parameter, or calling-convention semantics into the core graph.

## Current Policy

Phase 2 uses safe-lazy post-call register materialization:

```text
CALL instruction
  -> CALLSITE
  -> CALL_PRE_REG / CALL_PRE_STACK / CALL_PRE_MEM candidates
  -> CALL_POST_REG candidates for known general register aliases
```

`CALL_POST_REG` nodes are candidate storage states. They intentionally have no
incoming data edge from pre-call register values, which prevents stale register
dependencies after opaque calls.

DataFlowBench expected labels such as `dfb_source_A.ret` remain compatibility
labels in the adapter/report layer only.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_smoke expected --cases case_DFB001 case_DFB002` | PASS 12 | Also confirmed CALLSITE, CALL_PRE_REG, CALL_POST_REG, SOURCE_BOUNDARY_VALUE in graph export |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase5_completed_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Includes callee-entry observed storage and verified `call_in_reg` evidence across all roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_outparam_closed_v2 expected --cases case_DFB021 case_DFB022 case_DFB023` | PASS 18 | Verified source-to-memory outparam, observed-storage-to-memory outparam, and double-pointer outparam across PE/Linux x86/x64 and Linux ARM/AArch64 roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_callout_phase5_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Existing Phase 5 gate remains stable after `call_out_*` promotion |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_callout_libc_buffer expected --cases case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 24 | External and compiler-lowered buffer cases remain stable with `call_out_mem` edges |
