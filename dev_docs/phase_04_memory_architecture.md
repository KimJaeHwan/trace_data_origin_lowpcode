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
- [x] Add partial Ghidra architecture metadata loader.
  - Implemented through extracted `program.registers` and `program.address_spaces`
    metadata, not by calling the Ghidra Language API directly at analysis time.
  - Used for register aliases, special-register filtering, and address-space
    classification while preserving the convention-free core model.
  - Updated to schema v4 structured metadata:
    `program.architecture.registers`, `register_aliases`, and
    `address_spaces`.
  - Direct Language API ingestion remains out of process in the Ghidra
    dumper/headless extraction layer.
- [x] Add partial Ghidra data-reference global symbolization.
  - Implemented data-reference based global keying from Ghidra `refs_from`
    hints for computed global accesses.
  - Updated to schema v4 structured indices:
    `indices.symbols_by_address`, `data_refs_by_from`, `imports_by_address`,
    `imports_by_entry`, and `thunks_by_entry`.
  - Remaining: full symbolic names/types for globals are not attached to memory
    objects yet.
- [ ] Add full heap alias groups.
- [x] Add byte-range memory precision beyond fixed offsets.
  - Loads materialize exact byte ranges and connect overlapping prior writes.
  - Byte-lane demand from `SUBPIECE`, low-byte `AND` masks, and 1-byte
    register views narrows broad loads without adding argument/return or
    calling-convention facts.
  - Exact byte `memory_range` nodes are preserved when they carry summary
    copy provenance such as `call_out_mem`.
- [x] Add bitfield precision for sub-byte read-modify-write flows.
  - Tracks bit-level demand through `INT_AND`, `INT_OR`, `INT_LEFT`,
    `INT_RIGHT`, `INT_SRIGHT`, `SUBPIECE`, zero/sign extension, and constant
    `INT_NEGATE` masks.
  - Resolves bit contributors through memory-backed load leaves, so a later
    bit demand can re-enter the stored byte expression and exclude unrelated
    bit lanes.
  - Handles compiler-shaped x86/x64 `SHR/AND`, ARMv7 byte-lane forms, and
    AArch64 `BFXIL/BFM/UBFX` low-pcode lowering without using arguments,
    returns, parameters, stack-frame declarations, or calling conventions.
  - Remaining field-sensitive aggregate precision is tracked separately from
    byte-range and bit-range overlap.

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

Partial overwrite policy:

- A broad memory load remains conservative and may connect every overlapping
  write.
- When later p-code proves a narrower byte demand, for example `AL`,
  `SUBPIECE(..., 0)`, or `AND 0xff`, the graph creates a byte-lane view that
  keeps only memory predecessors overlapping that requested byte.
- Larger register aliases are not treated as ABI facts. Stale covered aliases
  are discarded only when they are not data ancestors of the new wider write,
  preserving zero/sign-extension chains while removing obsolete source/call
  observations.
- Summary-produced memory ranges are not flattened away during narrowing, so
  `call_out_mem` edges from external or interprocedural summaries remain
  visible to the backward slice.

Bitfield policy:

- Bitfield narrowing is demand-driven. The graph does not assume struct field
  layouts, C declarations, ABI packing, parameter lists, return registers, or
  calling conventions.
- Low-pcode arithmetic is used as evidence. Masks clear or preserve explicit
  bit ranges, shifts remap demanded bits, and OR nodes union only the branches
  whose bit ranges can contribute.
- If a demanded bit range reaches a memory-backed load leaf, the builder first
  narrows to the overlapping byte range and then resolves the stored byte's own
  bit expression. This is what separates `flags` bits [0..3] from `value` bits
  [4..7] in DFB034/DFB035.
- Constant mask folding is limited to low-pcode constants such as `INT_SUB`,
  `INT_AND`, `INT_OR`, shifts, and `INT_NEGATE`; it does not import language or
  compiler ABI facts.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/PE_x86/win_core output/v8_phase4_probe expected --cases case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031` | PASS 5 / FAIL 1 | DFB026 remains Phase 5 interprocedural global-reader work |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase4_regression_basic expected --cases case_DFB001 case_DFB002` | PASS 12 | All architecture/platform sample roots |
| 2026-06-20 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/PE_x86/win_core output/v8_phase4_regression_x86 expected --cases case_DFB010 case_DFB014 case_DFB024 case_DFB025 case_DFB027 case_DFB030 case_DFB031` | PASS 7 | x86 control/global/heap gate |
| 2026-06-20 | `python3 scripts/run_ghidra_headless_lowpcode.py` | 848 function JSON files extracted | Schema v4 structured architecture metadata and indices, all Ghidra extraction batches reported `fail=0` |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_partial_overwrite_probe9 expected --cases case_DFB046 case_DFB049 case_DFB122` | PASS 18 | Byte-lane narrowing, exact byte load ranges, and summary-copy memory ranges pass across all roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_partial_overwrite_struct_gate4 expected --cases case_DFB040 case_DFB041 case_DFB042 case_DFB043 case_DFB044 case_DFB045 case_DFB046 case_DFB047 case_DFB048 case_DFB049` | PASS 60 | Struct/offset/partial-overwrite gate across all architecture/platform roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_bitfield_probe5 expected --cases case_DFB034 case_DFB035` | PASS 12 | Bitfield read-modify-write precision across x86/x64/AArch64/ARMv7 roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_bitfield_offset_gate expected --cases case_DFB040 case_DFB041 case_DFB042 case_DFB043 case_DFB044 case_DFB045 case_DFB046 case_DFB047 case_DFB048 case_DFB049` | PASS 60 | Offset and partial-overwrite regression after bit-range tracking |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_bitfield_risky_gate expected --cases case_DFB034 case_DFB035 case_DFB046 case_DFB048 case_DFB049 case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 54 | Bitfield, byte-lane, and memory API risky subset across all roots |
