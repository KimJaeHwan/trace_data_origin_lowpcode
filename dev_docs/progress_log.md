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
- Started Phase 6 external summary resolution.
- Stopped tracking generated `samples/low_pcode` JSON outputs for future commits
  while preserving the local files for regression runs.
- Upgraded the Ghidra dumper to schema v5 external prototype metadata:
  `external_prototypes_by_entry`, `external_prototypes_by_name`, normalized
  names, external locations, thunk targets, signature/prototype metadata,
  parameter/output metadata, flags, and per-prototype metadata hashes.
- Added `ExternalPrototype`, `KnownExternalEffectRegistry`, and
  `ResolvedExternalSummary` infrastructure without applying external summary
  edges yet.
- Added initial curated external effect registry files for libc, POSIX, and
  WinAPI effects.
- Verified Phase 6 infrastructure smoke: synthetic `memcpy` prototype resolves
  to `memory_copy`, and DFB001/DFB002 remain PASS 12.
- Re-extracted schema v5 low-pcode JSON with Ghidra headless: 848 function JSON
  files and 22 manifests under `samples/low_pcode`, with observed extraction
  batches reporting `fail=0`.
- Verified schema v5 metadata across the extracted samples: 848/848 files at
  schema v5, 36,461 external prototype entries, 0 missing prototype metadata
  hashes, and 7,236 curated registry matches.
- Added `CompositeSummaryProvider` and routed the existing automatic
  low-pcode function summaries behind it.
- Added `ExternalSummaryProvider` for resolved external memory copy/fill,
  read/write source/sink, and allocation lifetime boundary effects. External
  edges carry provider, effect, trust, provenance, and resolver cache keys.
- Verified external libc buffer cluster at
  `output/v8_phase6_external_libc_buffer`: PASS 12 / FAIL 12. DFB122 `strcpy`
  improved to PASS across all architecture/platform roots, DFB123 stayed PASS,
  and DFB120/DFB121 were identified as compiler-lowered inline-copy residuals
  with no surviving `memcpy`/`memmove` call target.
- Verified Phase 5 regression gate after Phase 6 provider wiring at
  `output/v8_phase6_phase5_gate`: PASS 84.
- Checked DFB130/DFB131 at `output/v8_phase6_external_import_probe`: FAIL 12,
  expected for now because the DFB helper imports are not registry-known
  libc/POSIX/WinAPI APIs.
- Added byte-range overlap memory modeling for stack/global/heap memory keys.
  Loads now materialize their requested byte range and connect overlapping
  prior memory writes with `LOAD_OVERLAP`, so compiler-lowered copy sequences
  can flow from narrow source stores through wider loads/stores and back to
  narrow sink loads.
- Verified the memory API cluster at `output/v8_memory_overlap_libc_buffer`:
  PASS 24 across all architecture/platform roots. This covers DFB120/DFB121
  lowered `memcpy`/`memmove`, DFB122 external `strcpy`, and DFB123
  memset/partial-copy behavior.
- Verified the Phase 5 regression gate after byte-range overlap modeling at
  `output/v8_memory_overlap_phase5_gate`: PASS 84.
- Ran byte-range risky cases at `output/v8_memory_overlap_risky`: PASS 92 /
  FAIL 40. Remaining failures are expected residual clusters: outparam,
  bitfield, partial-overwrite, large-struct, and deep-field summaries.
- Closed the remaining Phase 2 `call_out_*` taxonomy item by promoting verified
  automatic and external summary outputs to first-class `call_out_reg`,
  `call_out_mem`, and `call_out_global` edges. Legacy summary labels are kept
  as provenance, not core edge taxonomy.
- Added source-boundary to observed-memory output summaries for callees that
  store source-derived values through observed pointers.
- Added double-dereference observed-memory summaries using low-pcode
  LOAD/STORE evidence, including ARM/AArch64 `LOAD <- OBSERVED_MEMORY`
  address forms.
- Verified outparam closure at `output/v8_phase2_outparam_closed_v2`: PASS 18
  across PE/Linux x86/x64 and Linux ARM/AArch64 roots.
- Verified Phase 5 gate after `call_out_*` promotion at
  `output/v8_phase2_callout_phase5_gate`: PASS 84.
- Verified memory API cluster after `call_out_mem` promotion at
  `output/v8_phase2_callout_libc_buffer`: PASS 24.
- Re-ran risky residuals at `output/v8_phase2_risky_after_callout`: PASS 104 /
  FAIL 28. DFB021/DFB023 residuals are closed; remaining failures are bitfield,
  partial-overwrite, large-struct, and deep-field clusters.
- Ran the full testbed at `output/v8_phase2_callout_full`: PASS 370 / FAIL
  118, improving by 36 PASS against `output/v8_phase5_completed_full2`.

## Current Focus

Phase 6 external summary resolution.

Next engineering step:

```text
Continue Phase 6 with residual clustering after Phase 2 call boundary closure.
Memory API cases DFB120-123 and outparam/double-pointer cases DFB021-023 now
pass across all roots. The next targets are bitfield and partial-overwrite
range precision, large-struct/deep-field summary residuals, and trusted
external import helper coverage. Keep trusted external semantics outside the
core graph model and record provenance on every summary edge.
```
