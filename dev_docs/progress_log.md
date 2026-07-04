# V8 / New V1 Progress Log

This log records implementation progress by phase. Detailed task checklists live
in the phase-specific files.

## 2026-07-03

- Repaired part of the rebuilt cpp_like low-pcode regression without changing
  expected files, manifests, generated samples, or oracle data.
- Added loader-level flow-target name annotations and kept DataFlowBench marker
  interpretation inside `BoundaryProvider`.
- Fixed x86 external stack-slot binding for call summaries by deriving caller
  stack slots from the observed call-adjacent stack layout when a return slot is
  materialized in low p-code. This lets `memcpy`/large-copy summaries bind
  distinct destination/source/size storage in rebuilt P0/P1 x86 samples.
- Added p-code zero-idiom handling for `INT_XOR x, x` and `INT_SUB x, x` so
  self-canceling operations kill stale data origins instead of propagating a
  false source through PHI merges.
- Rejected the previous prototype-pointer write fallback because it introduced
  false positives in 09/UE and crossed too far into prototype-derived argument
  semantics.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query report tools`.
- Verified `python3 -m harness.orchestrator --suite 09,10 --mode local-samples
  --run-id manual_fp_repair_check --no-cache --no-ledger`:
  09_tdo_testbed PASS 488 / FAIL 0 / FP 0; 10_tdo_testbed_UE PASS 120 /
  FAIL 12 / FP 0. Remaining 10 failures are missing-only rebuilt cpp_like
  residuals, primarily P1 armv7 and call_out_mem mutation cases.

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
- Repaired the cycle 11 recursion/global-effect miss with a summary-layer
  observed-storage-to-program-memory relation. Auto summaries now record when
  a concrete observed callee input flows into a program memory write, excluding
  program-memory self inputs so read-only global helpers do not become writes.
  Call-site injection materializes the exact program-memory post node and
  source-gated redirects later same-storage memory consumers to that post-call
  transition. This keeps the edge convention-free and based on observed
  low-pcode storage flow. Bumped the summary cache schema for the new summary
  field and redirect semantics.
- Verified cycle 11 locally with lightweight V8 checks: DFB026/063/110 plus
  DFB010/066/100/130/131 guard cases PASS 47 / FAIL 1 / FP 0 across sample
  roots, with only the pre-existing Linux amd64 DFB110 miss remaining in that
  focused set. Full local DFB sweep: PASS 452 / FAIL 36 / FP 0 over 488
  checked-in DataFlowBench samples.
- Repaired the cycle 12 DFB090 thread/shared-memory recall cluster with a
  guarded summary-layer runtime boundary transition. The new edge is emitted
  only for selected thread/control-transfer runtime calls when a pre-call
  observed storage value points to memory that already reaches exactly one
  source label, and the post-call storage or later observed program-memory read
  is actually consumed by a sink. Stack-carried pointer slots are handled as
  observed storage, including raw stack memory keys without a `mem:` prefix.
  This preserves the convention-free core model and avoids treating prototypes,
  parameters, or return slots as semantic truth. Bumped the summary cache
  schema for the new summary injection.
- Verified cycle 12 locally with lightweight checks: DFB090 PASS 8/8 across
  sample roots; DFB092 remains a sink-discovery residual with no forbidden
  source hits; DFB010/066/100/130/131 guard cases PASS 30 / FP 0. Compilation
  check: `.venv/bin/python -m py_compile analysis/interprocedural_summary.py`.
- Repaired the cycle 13 DFB071 callback-registration cluster with a guarded
  summary-layer indirect sink discovery pass. Computed calls now materialize a
  DataFlowBench sink anchor only when the low-pcode CALLIND target storage can
  be traced to an observed summary-written global callback slot, the target
  itself does not carry a source label, and the consumed pre-call storage
  already reaches exactly one source label. ARM `blr`/`blx` computed calls are
  now materialized as call boundaries, and CALLIND target tracing follows
  architecture-aware program-counter writes back to the general register that
  supplied the target. This remains convention-free and does not treat
  prototype parameters or ABI return locations as core semantics. Bumped the
  summary cache schema for the new sink discovery behavior.
- Verified cycle 13 locally with lightweight checks: DFB071 PASS 6/6 across
  sample roots. Guard/nearby set DFB010/066/071/072/090/092/100/130/131
  produced PASS 49 / FAIL 9 with no forbidden-source hits; residual failures
  were the existing DFB092 cluster and the known Linux 386 DFB072 ambiguity.
  Compilation check: `.venv/bin/python -m py_compile
  analysis/interprocedural_summary.py analysis/slice_graph_builder.py`.
- Repaired the cycle 15 obfuscated state-machine cluster for observed
  computed-jump control flow and loop-carried storage. CFG construction now
  treats low-pcode `COMPUTED_JUMP` / `BRANCHIND` flow targets as real
  successors, and slice construction performs a bounded revisit from observed
  CFG backedge targets so PHI/storage edges can see loop-carried writes without
  adding a broad fixed-point over-approximation. This recovers DFB201 on PE
  x64, PE x86, Linux amd64, Linux arm64, and Linux armv7; Linux 386 remains a
  separate PIC/global-table residual.
- Added a guarded summary-layer runtime-escape sink for C++ throw helpers.
  When low-pcode shows a callee contains a terminal `__cxa_throw`-style escape,
  source-carrying observed pre-call storage and observed post-call storage are
  connected to a synthetic escape sink only if the reaching source label set is
  exactly one. This keeps the core model arg/ret-free and uses metadata only as
  a no-return/name hint mapped back onto observed low-pcode storage.
- Verified cycle 15 locally with lightweight checks: DFB111 PASS 6/6 across
  sample roots; DFB010/066/071/072/090/100/130/131/201 guard set PASS 54 /
  FAIL 2 with no forbidden-source hits, where the failures are the known Linux
  386 DFB072 ambiguity and the Linux 386 DFB201 PIC/global-table residual.
  Compilation check: `.venv/bin/python -m py_compile
  analysis/interprocedural_summary.py analysis/slice_graph_builder.py
  analysis/cfg_builder.py`.
- Repaired the cycle 16 DFB092 pthread table-dispatch recall cluster with a
  guarded summary-layer thread-callback sink. A synthetic sink is materialized
  only for observed thread-start calls when the root has no ordinary sink and
  the observed pointed context memory reaches exactly one source label. A
  low-pcode constant matching a function entry in the same dump metadata is
  recorded as an optional confidence hint when available. This keeps the
  transition convention-free and avoids pulling in adjacent source-carrying
  stack/table entries.
- Repaired the cycle 18 residual DataFlowBench recall cluster with three
  guarded observed-storage mechanisms. X86 sink binding can now fall back to a
  source-reaching observed memory value when register candidates are source
  empty and all current source-bearing memory candidates agree on the same
  source-label set; unresolved computed-call passthrough narrows stale
  source-carrying pre-storage by the latest concrete source-boundary address
  before bridging to consumed post storage; and setjmp/longjmp-style runtime
  calls can restore a single source-bearing observed pre-storage into
  sink-reaching post registers. These remain summary/boundary-layer repairs and
  do not introduce arg/ret or ABI semantics into the core graph.
- Verified cycle 18 locally with lightweight checks: DFB072 and DFB201 PASS on
  linux_386; DFB110 PASS on linux_amd64; protected guard cases
  DFB010/066/071/090/092/100/130/131 stayed PASS for the sample roots checked.
  Focused UE x64/P1_x64 smoke probes did not add new source labels to the
  selected TV2C cases. A broad all-sample local gate was attempted but did not
  complete in this sandbox, so the outer harness remains the authoritative
  full 09/10 regression.
- Repaired the cycle 19 C++/UE struct-copy and thunk-write recall cluster with
  guarded summary-layer observed transitions. External memory-copy summaries
  now add offset-preserving range edges only when the callsite has concrete
  observed source/destination pointer expressions, a concrete copy size, and an
  exact same-size source memory node that already reaches a source label; later
  explicit stores are not treated as copy destinations. Source-boundary calls
  can preserve a single-source non-primary observed register into an overlapping
  consumed post-call register view, and thunk-like computed-jump helpers can
  write a single-source observed pre-call value into sink-reaching pointed
  memory when the pointer range and size are observed at the callsite. These
  remain convention-free storage transitions and skip calls with trusted
  external summaries or non-thunk bodies. Bumped the summary cache schema for
  the changed summary-layer behavior.
- Verified cycle 19 locally with lightweight checks: selected C++ x64/P1_x64
  TV2C001/011/012/013/018/020 now PASS in a validator-style probe, TV2C005 and
  TV2C006 retained their forbidden-source guards, and TV2C017 remains a known
  control-source miss. DFB guard smokes passed on linux_386 for
  DFB010/066/071/072/090/092/100/130/131/201 and on linux_amd64 for
  DFB010/066/071/090/092/100/110/130/131. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/cfg_builder.py`.
- Split test-oracle source/sink matching out of the core slice builder behind
  `analysis.boundary_provider.BoundaryProvider`. `SliceGraphBuilder` now
  defaults to `NoBoundaryProvider`, while `ProgramSliceGraphBuilder` injects the
  DataFlowBench provider for current regression harness compatibility. Summary
  cache fingerprints now include the active boundary provider key so pure
  no-boundary analysis, DataFlowBench/TV2 validation, and future PDB/UE boundary
  providers cannot reuse each other's source/sink summaries.
- Repaired cycle 21 recall misses with two convention-free graph refinements.
  Memory-key recovery now prefers a single observed general-register address
  identity over a stale zero constant, and intra-procedural range matching now
  understands `unknown:register:*:offset:*` memory keys. This reconnects
  register-relative UE container element stores to later loads without treating
  the register as an ABI role. Control slicing also records branch dependence
  for memory values present on only some predecessors and for branch-reached
  sink boundaries, covering both ordinary diamond joins and optimized tail-call
  sink branches. Bumped the summary cache schema for the changed graph/summary
  inputs.
- Verified cycle 21 locally with lightweight checks: all available cpp-like
  x64/P1_x64 TV2C cases PASS 22/22, including TV2C017 with
  `dfb_source_A.ret` as data and `dfb_source_C.ret` as control while keeping
  `dfb_source_B.ret` out of data. Focused UE probes now pass TV2R001,
  TV2R002, and TV2U005; TV2R005 remains a recall miss. DFB guard run
  DFB010/066/071/090/100 passed across the sampled roots. Compilation check:
  `.venv/bin/python -m py_compile analysis/slice_graph_builder.py
  analysis/interprocedural_summary.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired part of the cycle 22 UE recall cluster with guarded summary-layer
  observed transitions. Consecutive source-boundary calls now preserve
  single-source non-primary storage through a later call-pre consumer, allowing
  chained marker boundaries to expose the original observed source without
  adding ABI roles. Non-varargs thunk calls can also connect a single-source
  observed input to a later sink-reaching observed memory read only when the
  same call has a non-source pointer input whose recovered memory range matches
  the read address provenance. The thunk guard avoids normal container helper
  bodies and varargs assertion thunks.
- Verified cycle 22 locally with lightweight checks: scoped UE validation over
  66 cycle-22 case-scope targets improved to PASS 52 / FAIL 14 with no
  forbidden-source findings, including development TV2R005 and TV2U010 now
  reaching `dfb_source_A.ret`; DebugGame TV2R002 stayed free of the wrong
  `dfb_source_A.ret` edge. DFB smoke
  DFB001/002/050/056/057/058/059/120/121/152 passed across the available sample
  roots. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py`.
- Repaired part of the cycle 23 UE container/value-flow cluster with
  observed-pointer provenance and narrowed prior-memory overlap recovery. When
  a pointer register is loaded from an observed memory slot, register-relative
  memory keys now retain that loaded-pointer provenance instead of using only
  the temporary register name. The memory range parsers also treat
  `unknown:register:*` identities before stack identities, so provenance strings
  that contain `:stack:` are not misparsed as concrete stack slots. A late
  composed-graph bridge can connect sink-reaching observed memory loads to the
  latest prior same-identity source-reaching write, narrowing the prior write to
  the load byte range. For data-dependent element stores, the bridge has a
  guarded adjacent-slot fallback only when the store address itself reaches a
  source label and the stored value has a single source label.
- Verified cycle 23 locally with lightweight checks: the 14 reported FAIL
  case-scope targets improved to PASS 4 / FAIL 10 with no forbidden-source
  findings. Newly passing targets were Development TV2R007/TV2R008 and
  DebugGame TV2R001/TV2R002. C++ guards TV2C005/TV2C006/TV2C017 stayed PASS,
  including C017's data/control split and no forbidden data source. DFB smoke
  DFB010/050/056 passed on the available `tracing_Data_Origin` root; local
  DFB120/121 buffer files in that root still fail and were not treated as
  representative of the closed 09 harness baseline. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired part of the cycle 24 UE recall cluster without adding convention
  roles. Summary memory-output recovery now composes a callee's observed
  pointer-relative memory offset with the caller's concrete pointer expression,
  so source writes such as `reg:x8 + 96` can land on the caller's actual stack
  return-buffer slot. Register-offset expression recovery also excludes the
  fallback register's current value from the immediate-offset operands, keeping
  `register + constant` addresses from collapsing to a zero offset when the
  register currently holds a constant-like value. Bumped the summary cache
  schema for the changed graph/summary inputs.
- Verified the 10 cycle-24 reported UE FAIL scopes locally after the repair:
  PASS 2 / FAIL 8 with no forbidden-source findings. The newly passing targets
  are Development and DebugGame TV2U004 return-buffer; the remaining failures
  are container/value-flow alias transfers requiring deeper observed pointer
  identity bridging.
- Repaired part of the cycle 25 UE container/value-flow cluster with a guarded
  dynamic pointer-store bridge. The prior observed-memory overlap pass now
  recognizes source-reaching stores through `base + scaled/indexed` pointer
  expressions when the later sink-reaching observed load has the same recovered
  pointer identity. For packed stores, the bridge narrows through the stored
  value bytes before accepting the edge, so an 8-byte container element carrying
  adjacent 4-byte sources can connect only the requested subfield. This keeps
  the transition based on observed address/value flow and avoids ABI roles or
  broad pointer-memory aliasing. Bumped the summary cache schema for the changed
  graph/summary behavior.
- Verified cycle 25 locally with lightweight checks: the 10 reported UE FAIL
  scopes improved to PASS 2 / FAIL 8 with no forbidden-source findings. Newly
  passing targets are Development TV2R001 and TV2R002, with TV2R001 selecting
  `dfb_source_A.ret` from the low half of the packed store and TV2R002 selecting
  `dfb_source_B.ret` at the second element offset. C++ guards
  TV2C005/TV2C006/TV2C017 passed on x64 and P1_x64, including TV2C017's
  data/control split and no forbidden-source hits. DFB smoke
  DFB010/050/056 passed across 18 available sample roots. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 27 fused call-chain recall miss without reapplying the
  rejected cycle 26 memory-identity change. Observed storage preservation now
  accepts same-canonical overlapping register ranges when a source-reaching
  pre-call storage is consumed only by a later call-pre node, and the proven edge
  is written into both the per-function graph and the composed program graph so
  subsequent call sites in the same fused chain can use it. The guard still
  requires a concrete callee low-pcode body with no overlapping write and does
  not introduce argument, return, or ABI semantics. A trial of the cycle 26
  loaded-pointer identity recovery reproduced regressions in Development
  TV2R002/TV2R007/TV2R008 and was reverted.
- Verified cycle 27 locally with focused checks: Development TV2R007 and
  TV2R008 now PASS with `dfb_source_A.ret`; Development TV2R001/TV2R002 and
  DebugGame TV2R001/TV2R002 remain PASS; remaining UE memory/provenance misses
  stay missing-only with no forbidden-source hits. Non-UE guard cases
  DFB010/050/056 on PE_x64, PE_x86, and linux_386 plus TV2C005/TV2C006/TV2C017
  on P0/P1 x64 all PASS. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 28 Development TV2R011 large-element recall miss with a
  guarded same-base register-memory bridge. The prior observed-memory overlap
  pass can now connect a source-reaching store through one register-derived
  address to a later sink-reaching load through another register-derived address
  only when both address expressions load the same pointer storage and their
  byte ranges overlap. The bridge reuses existing byte-lane narrowing before
  accepting the edge, so packed 16-byte element stores expose only the requested
  4-byte source field. This remains based on observed storage/address flow and
  does not add argument, return, or ABI roles. Bumped the summary cache schema
  for the changed graph behavior.
- Verified cycle 28 locally with focused checks: all 44 available UE case-scope
  target files now report PASS 37 / FAIL 7, improving Development TV2R011 to
  PASS with `dfb_source_A.ret` and leaving the remaining failures missing-only
  with no forbidden-source findings. Operator regression guards Development
  TV2R001/TV2R002/TV2R007/TV2R008 and DebugGame TV2R001/TV2R002 all remain
  PASS. DFB smoke DFB010/050/056 passed across the available sample roots.
  Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired part of the cycle 29 DebugGame object/component chain recall cluster
  with a guarded same-field register-memory bridge. The prior observed-memory
  overlap pass can now connect a source-reaching store through one transient
  register-derived address to a later sink-reaching load through another
  transient register only when the byte offset and width are identical, the
  store address itself reaches exactly the same single source label as the
  stored value, and prior same-field source labels are unambiguous. This keeps
  the edge based on observed address/value flow and avoids argument, return, or
  ABI roles. Bumped the summary cache schema for the changed graph behavior.
- Verified cycle 29 locally with focused checks: all 44 available UE case-scope
  targets now report PASS 39 / FAIL 5 with no forbidden-source findings.
  Newly passing targets are DebugGame TV2R007 and TV2R008. Operator regression
  guards Development and DebugGame TV2R001/TV2R002/TV2R007/TV2R008 all remain
  PASS. DFB smoke DFB010/050/056 passed across 18 available sample-root cases.
  Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 30 DebugGame nested-container recall miss by making
  register-derived memory range parsing use the last `:offset:` component.
  Nested pointer identities such as
  `unknown:register:mem:...:offset:0:8:offset:0:4` now retain the inner pointer
  identity and expose the final byte range to the existing guarded prior-memory
  overlap bridge. This is a parser/range precision fix only; it does not add
  ABI roles, source/sink naming assumptions, or broad aliasing. Bumped the
  summary cache schema for the changed range behavior.
- Verified cycle 30 locally with focused checks: all 44 available UE
  case-scope targets now report PASS 40 / FAIL 4 with no forbidden-source
  findings. Newly passing target is DebugGame TV2R010 nested container; the
  remaining failures are Development TV2R009 and DebugGame TV2R005/TV2R009/
  TV2R011, all missing-only. C++ guards TV2C005/TV2C006/TV2C017 passed on
  P0/P1 x64, including TV2C017's data/control split. DFB smoke
  DFB010/050/056 passed across 18 available sample-root cases. Compilation
  check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 31 DebugGame TV2R011 large-element recall miss with a
  byte-offset-preserving external-copy fallback. When a trusted memory-copy
  summary has a concrete read range and size but the write pointer is a computed
  value that cannot be expressed as a direct memory range, the summary layer can
  connect source bytes to later sink-reaching observed-memory loads only if the
  load offset lies inside the copy, the matching read-side byte range reaches
  exactly one source label, and the write pointer and load address share an
  observed memory-range origin. This keeps the edge tied to low-pcode value and
  address provenance rather than ABI roles or broad aliasing. Bumped the summary
  cache schema for the changed external-copy behavior.
- Verified cycle 31 locally with focused checks: all 24 available UE TV2R
  case-scope targets now report PASS 21 / FAIL 3 with no forbidden-source
  findings. Newly passing target is DebugGame TV2R011; remaining misses are
  DebugGame TV2R005, DebugGame TV2R009, and Development TV2R009. C++ guards
  TV2C005/TV2C006/TV2C017 passed on x64 and P1_x64, including TV2C017's
  data/control split. DFB smoke DFB010/050/056 passed across 18 available
  sample-root cases. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 32 DebugGame container-result recall misses with a guarded
  prior-call context bridge. When a sink-reaching memory load is addressed by a
  later call's observed post-register result, the composed graph can now connect
  a previous call on the same observed pointer context to that load only if the
  context is a real general-register pre-node consumed by the callee body and
  the previous call contributes exactly one source label either through a scalar
  observed input or through a pointed field at the requested byte range. This
  covers FString buffer lookup and TMap value lookup without treating live
  frame/link register snapshots or stale pointer registers as object identity.
  Bumped the summary cache schema for the changed graph behavior.
- Verified cycle 32 locally with focused checks: all 44 available UE case-scope
  targets now report PASS 43 / FAIL 1 with no forbidden data or control source
  findings. Newly passing targets are DebugGame TV2R005 and DebugGame TV2R009;
  the remaining UE recall miss is Development TV2R009. DFB smoke
  DFB010/050/056 passed across 18 available sample-root cases, and C++ guards
  TV2C005/TV2C006/TV2C017 passed on x64 and P1_x64. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Repaired the cycle 33 Development TV2R009 TMap value recall miss with a
  loaded-pointer-origin prior-call bridge. When a sink-reaching observed-memory
  load is computed from nested loaded pointer origins rather than a call-post
  register, the composed graph can now match those concrete origin ranges
  against an earlier call's consumed pointer context. The source side is limited
  to fields recovered through consumed pointer snapshots, so incidental
  temporary-register snapshots and source-marker scalar calls do not become
  broad aliases. Bumped the summary cache schema for the changed graph behavior.
- Verified cycle 33 locally with focused checks: all 44 available UE case-scope
  targets now report PASS 44 / FAIL 0 with no forbidden data or control source
  findings. DFB smoke DFB010/050/056 passed across 18 available sample-root
  cases. C++ guards TV2C005/TV2C006/TV2C017 passed on x64 and P1_x64, including
  TV2C017's data/control split. Compilation check:
  `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py analysis/boundary_provider.py
  query/backward_slice.py`.
- Reviewed cycle 34 pre-regression output after the current UE recall repairs:
  checked-in 09_tdo_testbed cases remain PASS 488 / FAIL 0 / FP 0, available
  10_tdo_testbed_UE x64/P1_x64 and local UE cases remain PASS 66 / FAIL 0 /
  FP 0, and the remaining six ERROR entries are `NO_SAMPLES` for cpp-like
  x86/ARM sample directories that are absent from the testbed artifact tree.
  No engine traceback, diagnose dump, missing-source delta, or forbidden-source
  finding is present in the cycle 34 report. Rechecked local guards with
  py_compile and DFB010/050/056 across 18 sample-root cases.
- Repaired the case-author frontier C502 fused/rebuilt helper-copy misses with
  a guarded observed-thunk pointer-memory copy bridge. For resolved non-boundary
  thunk-like calls without an external summary, the composed graph can now
  connect a concrete source pointer's same-relative field to a later
  sink-reaching destination memory range when both pointers are observed in
  call-pre storage and the source side reaches exactly one source label. The
  bridge is driven by low-pcode storage expressions and observed memory ranges,
  not ABI argument or return conventions, and it also handles fused zero-init
  plus later load-range targets. Bumped the summary cache schema for the changed
  graph behavior.
- Verified the frontier fix locally with focused checks: TV2C502 now reaches
  `dfb_source_B.ret` on P0 x86/x64 and P1 x86/x64/aarch64 with no forbidden
  labels. A sweep over the other reported C++ failures did not add forbidden
  labels; the broad P1 armv7 misses remain empty-source residuals. UE R202 is
  unchanged by this bridge (`SUMMARY_OBSERVED_THUNK_POINTER_MEMORY_COPY` adds no
  edges there) and remains on the pre-existing prior-observed-memory overlap
  false-positive path for a separate realloc/alias-kill refinement.
- Refined the R202 pointer-derived memory overlap path with zero-offset address
  proofs for dynamic stores. Prior observed-memory overlap and intra-procedural
  load-range fallback now require a graph-backed proof that a wide
  pointer-derived store addresses the base range before narrowing it into a
  smaller sink-reaching range. This prevents later neighbor/indexed writes from
  winning solely because they share the same abstract pointer identity after
  realloc or copy-loop lowering. Bumped the summary cache schema for the changed
  graph behavior.
- Verified the R202 refinement locally: Development TV2R202 now passes with
  only `dfb_source_A.ret`; DebugGame TV2R202 no longer reports forbidden
  `dfb_source_C.ret` and is reduced to a missing-only residual. The focused
  cycle 02 failure sweep shows no forbidden labels in the reported C++/UE
  residuals. Local guards passed for DFB010/031/050/056/120/121 across the
  available sample roots, and py_compile passed for the changed engine modules.
- Refined pointer-derived load-range selection for rebuilt/fused TArray-style
  stores. Dynamic wide stores over unknown-register memory now prove the
  concrete range start, not just the base identity, before they can cover or be
  narrowed into a smaller sink-reaching range. The proof handles nested
  constant address terms such as `base + index * element_size + field_offset`
  with bounded observed constant sets, including `INT_MULT`, and skips
  unproven later stores so older proven stores can still satisfy the load. This
  keeps the R202 neighbor/indexed kill from becoming a false positive while
  recovering same-field reads for fused TArray element copies. Bumped the
  summary cache schema for the changed graph behavior.
- Verified locally against focused UE frontier cases from the cycle 03
  pre-regression scopes: DebugGame TV2R001, TV2R201, and TV2R202 now pass with
  no forbidden labels; Development TV2R011 now passes with no forbidden labels.
  Development TV2R002 remains a separate miss on the `unknown:unique` to `x8`
  allocation/data-pointer bridge and was left as a residual rather than
  over-approximating aliases.
- Repaired the cycle 04 rebuilt ARMv7 C++ fused-tail residuals with a
  caller-local observed-storage bridge for terminal branches into shared
  extracted tail blocks. When low-pcode shows a no-fallthrough branch into an
  instruction range owned by another extracted function and that target block
  already contains a real sink boundary, the composed graph now creates a
  caller-local synthetic sink and connects only the same observed storage live
  at the branch. Source-reaching condition registers immediately preceding the
  branch are attached as control edges. This keeps the shared target sink from
  accumulating incoming edges from every fused caller while preserving
  convention-free observed storage semantics. Bumped the summary cache schema
  for the changed composed-graph behavior.
- Verified locally: the focused P1 ARMv7 C++ sweep over 13 available TV2C cases
  now reports PASS 13 / FAIL 0 / FP 0, including TV2C001/002/004/005/006/011/
  012/013/017/018/020/501/502. Read-only checks over P0 x86 and P1 x86 remain
  at the existing TV2C018 missing-only residual with FP 0. The UE Development
  R002 scope remains a missing-only residual on the `unknown:unique` to `x8`
  data-pointer bridge and was not widened. Local guards passed for
  DFB010/031/050/056/120/121 across the available sample roots, and
  `py_compile` passed for the changed engine modules.
- Repaired the cycle 05 rebuilt x86 C018 call-out memory mutation miss with a
  guarded observed-thunk scalar-to-pointer-field bridge. For resolved
  non-boundary thunk-like calls without an external summary, the composed graph
  can now connect single-label scalar call-pre storage into a later
  sink-reaching observed memory range only when a separate non-source call-pre
  pointer expression proves that exact target object and field. This covers
  stack-passed x86 helper mutations without introducing ABI argument or return
  semantics, and the summary cache schema was bumped for the changed graph
  behavior.
- Verified locally against the cycle 05 excerpt: TV2C018 P0/P1 x86 now pass
  with `dfb_source_A.ret`, TV2R201 Development passes with `dfb_source_C.ret`
  after summary cache invalidation, and focused neighboring C++ x86 cases
  TV2C001/005/502 still pass with no forbidden labels. TV2R002 Development
  remains a missing-only residual because the needed store-to-load match would
  require proving `[x8 + w0 * 8] == [x8 + 8]`; the current graph does not prove
  that offset, so the engine does not widen the `unknown:unique` to `x8`
  alias.
- Refined internal-call observed register preservation for rebuilt UE helper
  boundaries. A non-primary register write inside a resolved callee no longer
  unconditionally blocks caller-side preservation when the callee graph itself
  proves the latest overlapping register value reaches the same
  callee-entry-observed storage through stack memory, such as a low-pcode
  save/restore sequence. This keeps the behavior convention-free and
  architecture-aware: the edge is still driven by observed storage and graph
  reachability, not ABI callee-saved rules or signature metadata. Bumped the
  summary cache schema for the changed composed-graph behavior. Local
  `py_compile` passed for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; focused engine execution could not be run
  in this shell because `networkx` is not installed and no cached wheel is
  available.
- Repaired the cycle 07 UE Development TV2R002 optimized TArray append/read
  residual without widening core memory identity. The prior observed-memory
  unknown-offset bridge now also accepts a prior `unknown:unique` dynamic store
  when the store address graph contains the exact sink-reaching register
  identity and the stored width ends at the target's fixed offset. Candidate
  selection still requires a single data source and keeps the latest prior
  candidate, so the B append reaches `Items[1].ItemId` while the A append does
  not. Bumped the summary cache schema for the changed composed-graph behavior.
- Verified locally with the repository venv: focused UE cycle 07 scopes
  TV2R001/TV2R002/TV2R011/TV2R201/TV2R202 pass for both DebugGame and
  Development with FP 0; PE_x64 DFB010/031/050/056/120/121 pass; and
  `py_compile` passes for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`. A broader all-scope UE sweep and an
  all-root DFB guard were stopped for runtime after producing no completed
  summary; the bounded checks above completed cleanly.

## 2026-07-04

- Tightened the latest-unique dynamic object bridge so it now defers when a
  precise prior single-source memory-overlap candidate exists, preventing the
  stronger rebuilt UE TArray neighbor-field case from replacing an observed
  stack field source with a later unrelated unique object. Added a constrained
  call-summary pointer-field snapshot fallback for optimized container
  emplacement: when a summary write stores a pointer snapshot and a later
  sibling observed field reaches a sink, the edge is emitted only from the
  pointed field if that field has exactly one source label. This repaired the
  current cycle_02 UE Development frontier failures TV2R009 and TV2R202 while
  preserving TV2R301.
- Verified with `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`, the focused TV2R009/TV2R202/TV2R301 reproductions, all 26
  current `ue-local-development` scoped proposed cases from the cycle_02
  pre-regression artifact, and the checked-in DFB001/DFB002 smoke over
  `samples/low_pcode`.

- Partially repaired the stronger proposed frontier failures from the rebuilt
  09/10 regression without editing expected files, manifests, generated
  low-pcode samples, or oracle data. A temporary DataFlowBench wrapper/callback
  marker fallback was rejected because it named the proposed helper shape
  directly; the committed direction keeps marker facts in the boundary adapter
  and leaves the core to consume only observed storage and memory transitions.
- Added constrained summary bridges for selected stack-slot to global-pointer
  observed memory, latest single-source dynamic object fields, keyed nested
  pointer values selected by matching observed key constructors, and summary
  pointer-field snapshots. Tightened prior-call context matching to stable
  heap/unique/global pointer contexts to avoid the TV2R302 wrong-key false
  positive.
- Bumped the summary cache schema for the new composed-graph behavior.
- Verified with the repository venv and a cold summary cache:
  `stronger_frontier_no_hardcode_regression` reports suite09 PASS 488 /
  FAIL 0 / FP 0 and suite10 PASS 169 / FAIL 3 / FP 0 with proposed cases
  included. TV2C602, TV2R301, and TV2R302 are repaired without forbidden
  sources; the remaining residual is TV2C601 on P0 aarch64 and P1 x86/x64.
  Also verified `compileall -q analysis core frontend query report tools`.

- Repaired the residual stronger proposed callback/frontier case without
  naming case-local helpers or offsets. Boundary adapters may now expose
  generic metadata source-pointer marker facts, while the interprocedural
  summary layer consumes them only under strict observed-storage guards:
  unresolved/computed or thunk-like calls, no existing source reachability, a
  later sink-reaching memory field, a matching pre-call pointer range, and a
  prior zero-initialized overlap. This covers optimized aggregate/vector
  clearing before callback-table writes while preserving the no arg/no ret
  core model and avoiding ABI parameter semantics.
- Bumped the summary cache schema again for the metadata source-pointer marker
  bridge. Rechecked all eight available cpp-like roots with the local runner:
  120 checked case/root combinations, 0 failures, including TV2C601 with
  `dfb_source_A.ret` and no forbidden sources on the residual P0 aarch64 and
  P1 x86/x64 roots. `compileall -q analysis core frontend query report tools`
  also passed. Full no-cache proposed regression
  `tv2c601_full_nohardcode_regression` reports suite09 PASS 488 / FAIL 0 /
  FP 0 and suite10 PASS 172 / FAIL 0 / FP 0.

- Accepted the first frontier-generated cpp-like fusion case, TV2C603, as a
  proposed regression and used it to harden summary field precision rather than
  adding case-specific handling. The interprocedural scalar pointer-field
  fallback now requires callee summary evidence for the same observed scalar
  input, pointer storage, field offset, and size before creating a
  `SUMMARY_OBSERVED_THUNK_SCALAR_POINTER_FIELD` edge. Observed summary memory
  writes with a concrete address storage no longer fall back to arbitrary latest
  pre-call memory ranges when the pointed field cannot be matched, preventing
  aggregate/vector clears from merging a neighbor field source into a sibling
  sink field.
- Verified with `.venv/bin/python -m compileall -q analysis`, targeted
  `tv2c603_after_output_guard` over all tv2 tier0 P0/P1 architectures
  (PASS 8 / FAIL 0 / FP 0), and full no-cache proposed regression
  `tv2c603_full_09_10_after_output_guard`: suite09 PASS 488 / FAIL 0 / FP 0;
  suite10 PASS 177 / FAIL 3 / FP 0. The remaining suite10 failures are
  missing-recall residuals TV2C018 on x86/P1-x86 and TV2C502 on P1 aarch64,
  not forbidden-source regressions.

- Accepted the next frontier-generated cpp-like fusion case, TV2C604, as a
  proposed regression. The case combines aggregate initialization, function
  pointer table dispatch, a callback field write, a neighbor-field forbidden
  source, and a final field sink. This was used as a structural regression for
  indirect-call summary wiring rather than as a case-name-specific rule.
- Extended the low-pcode Ghidra dumper to schema v6 so root extraction follows
  Ghidra-observed data function-pointer evidence (`PTR_<function>_<addr>`
  symbols, data pointer references, and concrete data pointer values) when
  collecting reachable internal helpers. This keeps helper discovery
  convention-free: no ABI argument/return semantics and no source/sink oracle
  interpretation are added to the core.
- Extended the loader and slice graph builder to carry observed function
  pointer facts through low-pcode loads/copies/stores and to resolve otherwise
  unresolved indirect calls only when the current value graph contains a unique
  observed function-pointer target. Bumped the summary cache schema for this
  graph behavior.
- Verified `TV2C604` over all eight tv2 tier0 P0/P1 architecture/profile
  variants: PASS 8 / FAIL 0 / FP 0. Re-extracted tv2 P0/P1 with the v6 dumper
  and verified full no-cache proposed regression
  `post_tv2c604_v6_full_09_10`: suite09 PASS 488 / FAIL 0 / FP 0; suite10
  PASS 186 / FAIL 2 / FP 0. UE local Development and DebugGame both pass 26 /
  FAIL 0 / FP 0. The remaining suite10 failures are pre-existing missing-recall
  frontiers TV2C601 on P1 x86 and TV2C502 on P1 aarch64, with no forbidden
  sources.

- Repaired the two remaining frontier residuals without case names, helper
  names, ABI argument rules, or return-value conventions. Observed-memory loads
  from direct positive stack slots now retain loaded-pointer address provenance
  only when the load width matches the architecture pointer size, allowing
  later pointer-field stores to summarize back to the observed input memory
  they came from without broad `unknown:register` aliasing. The expression
  builder also recognizes conservative stack `INT_OR` low-bit offset idioms,
  covering compiler-lowered aligned stack field addresses such as `sp | 4`
  without treating arbitrary bitwise operations as pointer arithmetic. The
  prior-call context bridge now accepts concrete stack-local pointer contexts
  when a later sink-reaching observed-memory load carries that exact loaded
  origin, recovering local object/container value flow while staying based on
  observed storage rather than ABI roles. Summary cache schema is now 50.
- Verified with `.venv/bin/python -m compileall -q analysis core frontend
  query report tools`, focused no-cache checks
  `stackctx_tv2c502_p1_aarch64`, `stackctx_tv2c601_p1_x86`, and
  `stackctx_tv2r009_ue_dev` (all PASS 1 / FAIL 0 / FP 0), and full no-cache
  proposed regression `post_stack_context_full_09_10`: suite09 PASS 488 /
  FAIL 0 / FP 0; suite10 PASS 188 / FAIL 0 / FP 0.

- Fixed a stack-address precision loss seen in optimized ARMv7 fused field
  access. `INT_ADD` / pointer arithmetic now applies proven constant-valued
  operands to stack and heap pointer expressions before falling back to generic
  register-offset modeling. This keeps post-indexed and fused address
  sequences such as `stack_pointer_copy + constant_register` in concrete
  observed stack storage instead of widening them to `unknown:register` memory,
  without using ABI roles or overriding Low P-code with decompiler metadata.
  Summary cache schema is now 51.
- Verified with `.venv/bin/python -m compileall -q analysis core frontend
  query report tools` and a focused eight-variant TV2C605 check over the
  pre-regression P0/P1 x86, x64, armv7, and aarch64 inputs: PASS 8 / FAIL 0 /
  FP 0, with actual source set `dfb_source_A.ret` for every variant.

- Exercised the Codex-backed frontier case-author closed loop on suite10. The
  loop generated TV2C606 and TV2C607 as proposed cpp-like fusion regressions,
  applied them through the approval-gated work-item path, regenerated expected
  data from the manifest, and attempted P0/P1 all-architecture rebuild/extract.
  The first generated proposals used unsupported `dfb_source_int(...)` source
  markers, so the suite10 work-item doctor now rejects non-canonical source
  labels and source text before they reach build/extract. This keeps generated
  cases within the boundary-provider source/sink contract instead of teaching
  the engine new test-only source names.
- Repaired the proposed TV2C606 indexed callback heap-field frontier with
  convention-free graph evidence. `operator.new` is modeled as a heap allocator,
  automatic summaries now propagate through expression provenance and a second
  observed-storage preservation pass, scalar pointer-field summary edges can
  use callee-observed memory effects on non-thunk helpers, and callsite-aware
  stack/register storage matching maps callee stack inputs back to caller
  pre-call storage. The affine address recognizer now handles observed-input
  loads and `INT_LEFT` shift operands, allowing callee stores such as
  `base + index * stride + field` to match caller heap field ranges without
  ABI argument or return conventions.
- Verified the frontier changes with `.venv/bin/python -m compileall -q
  analysis core frontend query report tools`, `git diff --check`, and focused
  no-cache harness checks. Stable suite10 tier0 remains green at PASS 104 /
  FAIL 0 / FP 0. Stable suite09 improved from the prior PASS 470 / FAIL 18 /
  FP 0 snapshot to PASS 476 / FAIL 12 / FP 0. Proposed TV2C606 improved to
  PASS 5 / FAIL 3 / FP 0 across the eight P0/P1 tier0 variants. Proposed
  TV2C607 remains PASS 0 / FAIL 8 / FP 0 and is kept as a loaded-pointer /
  container-alias frontier rather than being forced through expected edits.

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
