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
- Added an external memory API call-preserved probe outside the default full
  regression root. The probe builds a small PE x64 DLL with builtin expansion
  disabled, confirms `memcpy`, `memmove`, `memset`, and `strcpy` imports are
  preserved, extracts low-pcode to
  `samples/low_pcode_probes/external_memapi_call_preserved`, and verifies
  DFB120-123 at `output/v8_probe_external_memapi_call_preserved`: PASS 4.
- Kept generated probe JSON out of git via `samples/low_pcode_probes/` so the
  default repository stays light while preserving a reproducible local probe.
- Added byte-lane demand narrowing for partial-overwrite flows without using
  function signatures, arguments, returns, or calling conventions. The graph now
  narrows broad loads when low p-code proves a 1-byte demand via subregister
  reads, `SUBPIECE`, or low-byte masks, while exact byte `memory_range` nodes
  preserve `call_out_mem` summary provenance.
- Verified the focused byte-lane gate at `output/v8_partial_overwrite_probe9`:
  PASS 18 across DFB046, DFB049, and DFB122 on all roots.
- Verified the struct/offset partial-overwrite gate at
  `output/v8_partial_overwrite_struct_gate4`: PASS 60.
- Verified the byte-lane risky gate at `output/v8_byte_lane_risky_gate2`: PASS
  60, including DFB120-123 and DFB007 subregister alias coverage.
- Added bit-range demand tracking for bitfield read-modify-write flows without
  adding argument, return, parameter, stack-frame, ABI, or calling-convention
  assumptions. The graph now tracks contributors through masks, shifts, OR
  merges, subpieces, extensions, low-pcode constant masks, and memory-backed
  load leaves.
- Added latest-byte coverage selection for overlapping zero-initializer and
  byte-store patterns so zero-init stores do not obscure later bitfield byte
  writes.
- Verified bitfield precision at `output/v8_bitfield_probe5`: PASS 12 across
  DFB034/DFB035 on all architecture/platform roots.
- Verified offset/partial-overwrite regression after bit-range tracking at
  `output/v8_bitfield_offset_gate`: PASS 60.
- Verified risky bitfield/byte-lane/memory-API subset at
  `output/v8_bitfield_risky_gate`: PASS 54.
- Closed DFB053 large-struct return-buffer flow by resolving automatic
  observed-memory write summaries to caller post-call memory evidence, not to
  pre-call buffer contents.
- Included reachable callee sinks in target slice queries so nested sink cases
  can be analyzed without treating helper arguments or returns as conventions.
- Verified `output/v8_deep_struct_probe2`: DFB053 PASS 6 across all roots;
  DFB055 remains FAIL 6 and is now isolated to nested deep-field pointer
  passthrough summary composition.
- Verified `output/v8_large_struct_regression_gate`: PASS 36 across DFB050,
  DFB053, and DFB056-059 on all roots.
- Added transitive observed-memory-to-reachable-sink summaries for nested
  pointer passthrough. The composition propagates callee sink effects
  bottom-up through direct-call evidence, then binds the top-level caller's
  field memory through observed pointer expressions at the callsite.
- Kept the implementation convention-free: no argument list, return slot,
  parameter metadata, stack-frame declaration, or calling convention is used as
  core semantics. Stack argument cases are handled as observed memory storage,
  not as ABI parameters.
- Bumped the persistent summary cache schema to v7 so cached summaries include
  the new reachable-sink effects.
- Verified DFB055 at `output/v8_dfb055_nested_sink_probe2`: PASS 6 across all
  roots.
- Verified deep-struct focused gate at `output/v8_deep_struct_probe3`: PASS 12
  across DFB053/DFB055 on all roots.
- Verified Phase 5 gate after nested sink composition at
  `output/v8_after_dfb055_phase5_gate`: PASS 84.
- Verified risky residual cluster at `output/v8_after_dfb055_risky_gate`: PASS
  132.
- Ran the full testbed at `output/v8_after_dfb055_full`: PASS 403 / FAIL 85,
  improving by 33 PASS with 0 regressions against
  `output/v8_phase2_callout_full`.

## Current Focus

Phase 6 external summary resolution.

Next engineering step:

```text
Continue Phase 6 with residual clustering after Phase 2 call boundary closure.
Memory API cases DFB120-123 and outparam/double-pointer cases DFB021-023 now
pass across all roots. Bitfield, partial-overwrite byte/bit precision,
large-struct return-buffer flow, and DFB055-style nested deep-field pointer
passthrough now pass across focused all-root gates. The next target is trusted
external import helper coverage. Keep trusted external semantics outside the
core graph model and record provenance on every summary edge.
```
