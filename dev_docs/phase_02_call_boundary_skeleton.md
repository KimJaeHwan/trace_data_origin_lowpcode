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
- [ ] Add `call_out_*` edges once summaries or callee exit observation exists.

Deferred dependency:

- The remaining `call_out_*` item overlaps with Phase 5 because Phase 2 only
  creates convention-free call boundary candidates.
- Phase 5 added the evidence model that verifies `call_in_*` through
  observed-storage reachability and use-before-def analysis.
- The current Phase 5 implementation uses `summary_data` and `summary_memory`
  edges instead of first-class `call_out_*` edges, so call-out remains open.
- Finishing Phase 5 gates does not automatically close these Phase 2 residuals;
  they close when the verified summary behavior is either represented as
  first-class call-boundary edges or explicitly documented as the replacement
  edge taxonomy.

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
