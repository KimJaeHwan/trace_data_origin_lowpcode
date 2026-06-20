# Phase 1: Walking Skeleton

Goal: create an independent V8 / New V1 package skeleton and pass the smallest
DataFlowBench gates without changing the v5/v6/v7 prototype files.

## Gate

```text
DFB001 direct value PASS
DFB002 arithmetic value PASS
```

## Implementation Checklist

- [ ] Create package directories: `core`, `frontend`, `analysis`, `query`, `report`.
- [ ] Add `core.value_id.ValueId`.
- [ ] Add `core.architecture.ArchitectureSpec.from_preset("x86")`.
- [ ] Add minimal x86 register canonicalization through `RegisterStorage`.
- [ ] Add `core.storage` storage key types for register, stack, memory, constants.
- [ ] Add `core.graph.FunctionGraph` with separate `slice_graph` and `cfg`.
- [ ] Add `frontend.low_pcode_loader` to parse existing JSON dumps.
- [ ] Ensure register varnodes go through `ArchitectureSpec.canonicalize_register`.
- [ ] Add fallback `analysis.cfg_builder.CFGBuilder`.
- [ ] Add minimal `analysis.slice_graph_builder.SliceGraphBuilder`.
- [ ] Add `query.backward_slice.BackwardSliceQuery` with edge policy.
- [ ] Add `report.expected_validator.ExpectedValidator`.
- [ ] Add `report.graph_exporter.GraphExporter`.
- [ ] Add a Phase 1 CLI or batch entry point.
- [ ] Validate DFB001 and DFB002 against `expected/`.

## Out Of Scope

- Interprocedural call boundary modeling.
- CALL_PRE / CALL_POST synthetic storage.
- Heap object recovery.
- Full global source modeling.
- Full x86-64 / AArch64 alias precision.
- PDB, symbol, or dynamic overlays.

## Notes For Implementation

- Do not modify `tools/pcode_ssa_report_v5.py`, `tools/pcode_ssa_report_v6.py`,
  or `tools/pcode_ssa_report_v7.py` as part of Phase 1 unless a test harness
  import compatibility issue requires a tiny, isolated change.
- Keep compatibility with current sample input:
  `samples/low_pcode/case_DFB001_direct_value.json` and
  `samples/low_pcode/case_DFB002_arithmetic_value.json`.
- Keep generated output under `output/v8_phase1/` or another ignored output
  directory.
- If a term is useful only for human interpretation, keep it in report/adapters,
  not in core graph node or edge semantics.

## Verification Log

Record each run here while Phase 1 is active.

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | Not run yet | N/A | Phase document created |

