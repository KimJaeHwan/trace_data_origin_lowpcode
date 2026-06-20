# Phase 1: Walking Skeleton

Goal: create an independent V8 / New V1 package skeleton and pass the smallest
DataFlowBench gates without changing the v5/v6/v7 prototype files.

## Gate

```text
DFB001 direct value PASS
DFB002 arithmetic value PASS
```

## Implementation Checklist

- [x] Create package directories: `core`, `frontend`, `analysis`, `query`, `report`.
- [x] Add `core.value_id.ValueId`.
- [x] Add `core.architecture.ArchitectureSpec.from_preset("x86")`.
- [x] Add minimal x86 register canonicalization through `RegisterStorage`.
- [x] Add `core.storage` storage key types for register, stack, memory, constants.
- [x] Add `core.graph.FunctionGraph` with separate `slice_graph` and `cfg`.
- [x] Add `frontend.low_pcode_loader` to parse existing JSON dumps.
- [x] Ensure register varnodes go through `ArchitectureSpec.canonicalize_register`.
- [x] Add fallback `analysis.cfg_builder.CFGBuilder`.
- [x] Add minimal `analysis.slice_graph_builder.SliceGraphBuilder`.
- [x] Add `query.backward_slice.BackwardSliceQuery` with edge policy.
- [x] Add `report.expected_validator.ExpectedValidator`.
- [x] Add `report.graph_exporter.GraphExporter`.
- [x] Add a Phase 1 CLI or batch entry point.
- [x] Validate DFB001 and DFB002 against `expected/`.

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
- Keep compatibility with current sample input under architecture-specific
  directories such as `samples/low_pcode/PE_x86/win_core/` and
  `samples/low_pcode/linux_arm64/win_core/`.
- Keep generated output under `output/v8_phase1/` or another ignored output
  directory.
- If a term is useful only for human interpretation, keep it in report/adapters,
  not in core graph node or edge semantics.

## Verification Log

Record each run here while Phase 1 is active.

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | Not run yet | N/A | Phase document created |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase1 expected --cases case_DFB001 case_DFB002` | PASS 12 | DFB001/DFB002 passed for PE_x86, PE_x64, linux_386, linux_amd64, linux_arm64, linux_arm_v7 |
