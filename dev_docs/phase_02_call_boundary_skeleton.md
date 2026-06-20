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
- [ ] Add callee-entry observed storage nodes.
- [ ] Add candidate `call_in_reg`, `call_in_stack`, and `call_in_mem` edges once callee-entry observation exists.
- [ ] Add `call_out_*` edges once summaries or callee exit observation exists.

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
