# Phase 4: Memory + Architecture Expansion

Goal: introduce explicit memory-object skeletons and allocation-site heap
tracking while preserving the convention-free core.

## Gate

```text
DFB024 global value flow PASS
DFB025 global field precise PASS
DFB027 readonly global baseline PASS
DFB030 heap field PASS
DFB031 realloc preserve PASS
DFB001 / DFB002 all-architecture regression PASS
DFB010 / DFB014 x86 control regression PASS
```

DFB026 is intentionally not a Phase 4 gate. It requires interprocedural global
reader connectivity and belongs to Phase 5 summary/call graph work.

## Implementation Checklist

- [x] Add `core.memory_object` skeletons.
- [x] Add `StackObject`, `GlobalObject`, `HeapObject`, and `UnknownExternalObject`.
- [x] Add `analysis.memory_model.MemoryModel`.
- [x] Route stack/global/unknown memory keys through `MemoryModel`.
- [x] Add allocation-site heap pointer expressions for allocator call post storage.
- [x] Propagate pointer expressions through stack store/load.
- [x] Classify heap stores/loads as `heap:allocsite:<site>:offset:<n>`.
- [x] Preserve `realloc` storage by reusing the prior heap allocation-site expression when observed.
- [ ] Add Ghidra Language API architecture loader.
- [ ] Add Ghidra symbol/data-reference global symbolization.
- [ ] Add full heap alias groups.
- [ ] Add byte-range or field-sensitive memory precision beyond fixed offsets.

## Current Policy

Allocator calls are treated as observed storage transitions, not convention
facts. For Phase 4 MVP, when a known allocator call produces a post-call
observed storage that also matches the DataFlowBench adapter's source-boundary
storage set, that storage receives a `heap_ptr` expression:

```text
heap:allocsite:<callsite>:offset:<offset>
```

Heap objects are transfer storage, not sources. Source identity still comes from
upstream source boundary nodes.

`realloc` preserves the prior heap allocation-site expression when the old heap
pointer is observed in the most recent pre-call memory store.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/PE_x86/win_core output/v8_phase4_probe expected --cases case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031` | PASS 5 / FAIL 1 | DFB026 remains Phase 5 interprocedural global-reader work |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase4_regression_basic expected --cases case_DFB001 case_DFB002` | PASS 12 | All architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/PE_x86/win_core output/v8_phase4_regression_x86 expected --cases case_DFB010 case_DFB014 case_DFB024 case_DFB025 case_DFB027 case_DFB030 case_DFB031` | PASS 7 | x86 control/global/heap gate |
