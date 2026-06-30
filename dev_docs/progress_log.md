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
- Applied the UE testbed M1 false-positive fix from
  `tdo_testbed_UE/docs/engine_fix_proposals.md`: pointer arithmetic over
  observed general registers now produces field-sensitive
  `unknown:register:<base>:offset:<n>` memory keys instead of collapsing through
  reused unique temporaries. Stack/frame registers are excluded from this
  fallback so unresolved stack effects do not create unsafe aliases.
- Kept the change convention-free: it uses only observed low-pcode dataflow,
  register storage identity, and constant offsets; it does not introduce
  arguments, returns, parameters, stack-frame declarations, ABI roles, or
  calling-convention semantics.
- Verified UE release artifacts from `tdo_testbed_UE/dist/release_0.3.0`:
  Development remains PASS 7 / FAIL 15 with no forbidden sources; DebugGame
  remains PASS 2 / FAIL 20 but the previous TV2U008/TV2U009 forbidden
  `dfb_source_B.ret` paths are removed and now degrade to false negatives.
- Verified existing risky DFB gate at `output/v8_ue_pointer_regression_gate2`:
  PASS 66 across bitfield, byte-lane, large-struct, DFB055 nested pointer, and
  memory API cases on all sample roots.
- Added curated trusted external helper summaries for source-carrying storage
  passthrough and source-to-pointed-memory writes. The loader now merges
  embedded call-target external prototypes with indexed prototype metadata so
  helper imports and thunk-backed helpers are visible to the external summary
  resolver. The resulting graph edges stay in the summary layer with external
  provenance and bind only observed source-carrying pre-call storage to observed
  post storage or pointed memory; no core argument, return, parameter, ABI, or
  calling-convention semantics were added.
- Verified trusted helper coverage at `/tmp/lowpcode_external_helpers_all4`:
  DFB130/DFB131 PASS 12 across PE x86/x64, Linux x86/x64, AArch64, and ARMv7
  sample roots.
- Rechecked PE x64 smoke at `/tmp/lowpcode_smoke_after3`: PASS 11 across
  DFB001/002, DFB050, DFB056-059, and DFB120-123.
- Refined observed pointer-memory identity so reused scratch address registers
  no longer collapse distinct pointer targets. Auto summaries now record
  observed-memory-to-observed-memory storage transitions and materialize
  post-call memory values for summary writes, redirecting only post-call memory
  consumers. This keeps pointer swaps/copies convention-free and avoids
  transitive same-call chaining through freshly written summary outputs.
- Verified DFB066 all-root focused gate at
  `/tmp/lowpcode_cycle3_dfb066_allroots_after3`: PASS 6 across PE x86/x64,
  Linux x86/x64, AArch64, and ARMv7 sample roots.
- Rechecked pointer/memory summary smoke at `/tmp/lowpcode_cycle3_memory_smoke`:
  DFB021/022/023/055/120/121/122/123/130/131 PASS 60 across the sample roots.
- Repaired the cycle 4 ARM64 DFB100 regression without weakening the call
  boundary model. PHI expressions now preserve small same-base stack-address
  alternatives, loads can bind to existing stack memory across those
  alternatives, and 32-bit signed stack offsets are normalized for address
  recovery. The change keeps observed storage transitions in the low-pcode
  graph as source of truth and does not add argument, return, parameter, ABI, or
  calling-convention semantics. Bumped the summary cache schema to force stale
  summaries to rebuild.
- Verified the repair at `/tmp/lowpcode_cycle4_dfb100_066_after`: DFB100 and
  DFB066 PASS 12 across PE x86/x64, Linux x86/x64, AArch64, and ARMv7 sample
  roots.
- Rechecked the focused stack/summary smoke at
  `/tmp/lowpcode_cycle4_stack_phi_smoke`: DFB100/DFB066/DFB130/DFB131/DFB151
  PASS 30 across the sample roots.
- Refined the DataFlowBench sink boundary adapter so fixed candidate ordering
  does not outrank observed source-reaching low-pcode dataflow. When multiple
  possible sink storage values exist, the adapter now prefers candidates that
  already reach a source boundary through data/memory edges, preserving the
  existing ordering only as a tie-breaker. This repaired the Linux x64
  DFB010/DFB012/DFB016 branch/switch/memory PHI misses without binding every
  synthetic source-call post register and without adding argument, return,
  parameter, ABI, or calling-convention semantics.
- Verified the focused repair at `/tmp/lowpcode_after_sink_source_pref_dfb010`:
  Linux x64 DFB010/DFB012/DFB016 PASS.
- Rechecked guards at `/tmp/lowpcode_after_sink_source_pref_guard`:
  DFB100/DFB066/DFB130/DFB131 PASS 24 across PE x86/x64, Linux x86/x64,
  AArch64, and ARMv7 sample roots.
- Rechecked source/sink PHI smoke at
  `/tmp/lowpcode_after_sink_source_pref_smoke`: DFB001/002/004/005/006/007/010/
  012/016 PASS 54 across the sample roots.
- Rechecked the known armv7 DFB065 false-positive shape at
  `/tmp/lowpcode_after_sink_source_pref_dfb065`; it remains the pre-existing
  `dfb_source_C.ret` recursive-summary false positive and was not newly
  introduced by sink selection.
- Repaired the cycle 6 sink-selection false-positive shape without broadening
  summary propagation. DataFlowBench sink binding now uses explicit
  prototype-provided storage only as an adapter-level hint when that storage
  maps to an observed low-pcode value already present in the current state,
  including same-canonical subregister widening such as `EDI` to `RDI`. This
  prevents a live unrelated source register from outranking the actual sink
  storage in fused tail-call cases while keeping core graph semantics
  convention-free.
- Verified the repair against the listed TV2 false-positive cluster by direct
  backward-slice source collection: TV2C001/011/012/013/017/018/020 no longer
  report forbidden `dfb_source_B.ret` on the checked P0/P1 x64 samples.
- Rechecked focused guards: `/tmp/lowpcode_cycle6_sink_hint_dfb100_066_2`
  keeps DFB100/DFB066 PASS 12 across all sample roots,
  `/tmp/lowpcode_cycle6_sink_hint_phi_guard` keeps DFB010/DFB012/DFB016 PASS
  18 across all sample roots, and
  `/tmp/lowpcode_cycle6_sink_hint_helper_guard` keeps DFB130/DFB131 PASS 12
  across all sample roots.
- Rechecked basic source/sink smoke at
  `/tmp/lowpcode_cycle6_sink_hint_basic_smoke`: DFB001/002/004/005/006/007
  PASS 36 across all sample roots.
- After narrowing the prototype hint to the first declared sink storage,
  rechecked `/tmp/lowpcode_cycle6_sink_hint_quick_final`: DFB010/066/100/130/
  131 PASS 30 across all sample roots.
- Repaired cycle 7 false-positive shapes without adding ABI argument/return
  semantics. Recursive auto summaries no longer treat ARMv7 synthetic
  `CALL_POST_REG` candidates as observed callee inputs, which removes the
  DFB065 `dfb_source_C.ret` leak while leaving explicit low-pcode source
  transitions intact. The graph builder now preserves register-derived address
  expressions across non-primary candidate call-post boundaries, prefers a
  computed source-reaching sink value over a stale raw source boundary alias,
  and narrows loads from wider memory objects to the requested byte window when
  prior producers prove the subrange. This fixes the prioritized UE
  TV2U008/TV2U009 and P0 TV2R003/TV2R012 false positives without broad
  over-approximation. Bumped the summary cache schema for the changed summary
  and graph semantics.
- Verified cycle 7 repairs with `/tmp/lowpcode_cycle7_after_dfb065_final`
  (armv7 DFB065 PASS), `/tmp/lowpcode_cycle7_after_guards_final`
  (DFB066/DFB100/DFB130/DFB131 PASS 24 across sample roots), and
  `/tmp/lowpcode_cycle7_after_phi_final` (DFB010/DFB012/DFB016 PASS 18 across
  sample roots). Direct UE case probes show TV2U008/TV2U009 PASS in Development
  and P0, and TV2R003/TV2R012 PASS in P0; Development TV2R003/TV2R012 remain
  missing-only in the focused probe.
- Repaired the cycle 8 Development TV2R003/TV2R012 missing-only shape by adding
  a narrow direct-internal observed-storage preservation edge in the summary
  layer. The edge connects exact pre-call storage to exact post-call storage
  only for non-primary general registers, only when the internal callee's
  low-pcode has no concrete overlapping write, only when the synthetic post
  storage is consumed by real post-call p-code, and only when the pre-call value
  already reaches an observed source boundary. This keeps the model as observed
  storage transitions and does not introduce argument, return, parameter, ABI,
  or calling-convention semantics.
- Repaired the cycle 8 Linux AArch64 DFB034/DFB035 false-positive shape by
  keeping the latest overlapping byte store as the producer for a later wider
  range load. This prevents range-load narrowing from rewiring a bitfield
  read-modify-write back to the older byte producer before the later bit
  extraction can select the correct source lane. Bumped the summary cache schema
  for the changed graph/summary semantics.
- Verified focused cycle 8 checks: direct TV2R003/TV2R012 scoped probes now
  collect `dfb_source_A.ret`; Linux AArch64 DFB034/DFB035 PASS at
  `/tmp/lowpcode_cycle8_dfb034_035_guard2_88239`; ARMv7 DFB065 PASS at
  `/tmp/lowpcode_cycle8_dfb065_armv7_88298`; DFB066/DFB100/DFB130/DFB131 PASS
  24 at `/tmp/lowpcode_cycle8_preserve_guards_88049`; DFB010/DFB012/DFB016
  PASS 18 at `/tmp/lowpcode_cycle8_phi_guard_88051`; TV2U008/TV2U009 scoped
  Development and DebugGame probes still collect `dfb_source_A.ret`; DFB034/
  DFB035/DFB046/DFB048/DFB049/DFB120/DFB121/DFB122/DFB123 PASS 54 at
  `/tmp/lowpcode_cycle8_memory_lane_guard_88299`.
- Repaired several cycle 9 unresolved/missing-summary call-boundary misses with
  a guarded summary-layer passthrough. The edge is emitted only when normal
  summaries and trusted external effects left a consumed primary post-call
  storage unconnected, the pre-call observed storage already reaches exactly
  one source label, and present callees do not introduce their own source-to-
  output/global source summary. Unresolved/no-summary boundaries prefer
  source-carrying registers over stack snapshots to avoid unrelated live stack
  alternatives, while present callees require all source-carrying pre-storage to
  agree on one source. Direct sink consumption of the post-call storage is now a
  valid observed use. This keeps the edge in the summary layer and does not add
  argument, return, parameter, ABI, or calling-convention semantics. Bumped the
  summary cache schema for the changed summary injection.
- Verified the cycle 9 boundary repair at `/tmp/lowpcode_cycle9_final_focus`:
  DFB051/052/056/061/065/066/072/074/075/101/151/152 PASS 71 with only the
  existing Linux 386 DFB072 stack-selector ambiguity still failing. Rechecked
  FP-sensitive guards at `/tmp/lowpcode_cycle9_guard_final`: DFB034/035/065/
  066/100/130/131 PASS 42 across sample roots. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py frontend/external_prototype.py`.

## Current Focus

Phase 6 external summary resolution.

Next engineering step:

```text
Continue Phase 6 with residual clustering after Phase 2 call boundary closure.
Memory API cases DFB120-123 and outparam/double-pointer cases DFB021-023 now
pass across all roots. Bitfield, partial-overwrite byte/bit precision,
large-struct return-buffer flow, and DFB055-style nested deep-field pointer
passthrough now pass across focused all-root gates. Trusted external import
helpers DFB130/DFB131 now pass across the sample roots. Continue residual
clustering on callback/indirect, recursion/global, thread/runtime,
setjmp/longjmp, C++ exception, obfuscated state-machine, and remaining
unresolved call-boundary cases while keeping trusted external semantics outside
the core graph model and recording provenance on every summary edge.
```
