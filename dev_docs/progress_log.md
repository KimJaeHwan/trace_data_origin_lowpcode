# V8 / New V1 Progress Log

This log records implementation progress by phase. Detailed task checklists live
in the phase-specific files.

## 2026-06-20

- Read the V8 / New V1 integrated design document.
- Reintroduced `dev_docs/` for the new V8 development line.
- Imported the design snapshot as `dev_docs/v8_v1_design.md`.
- Created the phase plan and Phase 1 walking-skeleton tracker.
- Implemented the Phase 1 independent package skeleton.
- Added `tools/pcode_slicegraph_v8_phase1.py`.
- Verified DFB001 and DFB002 across six architecture/platform sample roots.
- Started Phase 2 call boundary skeleton.
- Added CALLSITE, CALL_PRE_* candidates, and safe-lazy CALL_POST_REG candidates.
- Confirmed Phase 2 smoke keeps DFB001/DFB002 at PASS 12.
- Implemented Phase 3 minimal branch PHI merge and control edges.
- Verified DFB010 and DFB014 with separated data/control sources.
- Started Phase 4 memory model expansion.
- Added MemoryObject skeletons and allocation-site heap tracking.
- Verified DFB030 and DFB031 heap cases as PASS.
- Left DFB026 as an explicit Phase 5 interprocedural global-reader gate.
- Started Phase 5 interprocedural summary skeleton.
- Added program-level graph composition and minimal automatic global summaries.
- Verified DFB026 across all six architecture/platform sample roots.
- Backfilled Phase 4 global/heap validation across all six roots: DFB024/025/026/027/030/031 PASS 36.
- Recorded residual non-gate control precision work for x64/aarch64 DFB010/014 variants.
- Expanded Phase 5 observed-storage summaries without adding argument/return semantics to the core model.
- Added x86_64 RDX/RSI register alias coverage for observed storage tracking.
- Added address-provenance edges for STORE nodes so pointer-expression summaries can target observed memory cells.
- Verified DFB050/DFB056 across all six roots: PASS 12.
- Verified x86_64 DFB058/DFB059 for PE_x64 and linux_amd64.
- Ran the full testbed at `output/v8_full_after_summary_refine2`: PASS 273 / FAIL 215, with 13 improvements and 0 regressions against `output/v8_full_after_observed_summary`.
- Loaded Ghidra register/address-space metadata into `ArchitectureSpec` as storage hints while preserving the convention-free core model.
- Generalized observed-memory output summaries across x86, x86_64, AArch64, and ARMv7 sample roots.
- Verified DFB058/DFB059 across all six architecture/platform sample roots: PASS 12.
- Preserved meaningful stack/heap/constant expressions across broad post-call storage candidates to avoid metadata-driven clobbering.
- Verified the metadata-backed Phase 5 gate at `output/v8_metadata_phase5_gate_final`: PASS 72.
- Ran the full testbed at `output/v8_metadata_full_final`: PASS 313 / FAIL 175, with 40 improvements and 0 regressions against `output/v8_full_after_summary_refine2`.
- Upgraded the Ghidra low-pcode dumper output to schema v4 structured metadata:
  architecture registers, register aliases, address spaces, symbol/data-ref/import/thunk indices, and metadata hashes.
- Re-extracted low pcode with Ghidra headless into `samples/low_pcode`: 848 function JSON files, with all extraction batches reporting `fail=0`.
- Verified schema v4 metadata presence across all extracted JSON files: no missing register aliases, address spaces, structured indices, or metadata hashes.
- Verified the schema v4 Phase 5 gate at `output/v8_metadata_v4_phase5_gate`: PASS 72.
- Ran the schema v4 full testbed at `output/v8_metadata_v4_full`: PASS 313 / FAIL 175, with 0 regressions against `output/v8_metadata_full_final`.

## 2026-06-21

- Added callee-entry observed storage indexing from Low P-code use-before-def evidence.
- Added verified `call_in_reg` / `call_in_stack` / `call_in_mem` edges for observed callee-entry storage only; unverified convention-like candidates remain excluded from default data slicing.
- Added source-boundary to observed-primary summaries for callees that produce an internal source value.
- Added field-sensitive observed-memory input summaries for pointer-to-field reads without introducing argument, return, parameter, ABI, or calling-convention semantics.
- Added address edges for materialized observed-memory loads so pointer provenance survives into summary generation.
- Fixed negative constant parsing for already-negative Low P-code constants.
- Added persistent summary cache files under `output/.summary_cache`, keyed by the metadata-aware directory fingerprint and summary cache schema.
- Verified the completed Phase 5 gate at `output/v8_phase5_completed_gate`: PASS 84.
- Ran high-risk interprocedural residual checks at `output/v8_phase5_completed_risky`: PASS 42 / FAIL 24, with expected residuals only in 021/023/053/055.
- Ran the full testbed at `output/v8_phase5_completed_full2`: PASS 334 / FAIL 154, with 21 improvements and 0 regressions against `output/v8_metadata_v4_full`.

## Current Focus

Post-Phase 5 residual reduction.

Next engineering step:

```text
Move to the next phase/residual cluster: precision-heavy bitfield/overlap,
recursive-global effects, unresolved indirect/callback flows, libc buffer
summaries, C++ exception flow, and thread/runtime cases. Keep convention
metadata as optional interpretation only, not core semantics.
```
