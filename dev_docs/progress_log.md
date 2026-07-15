# V8 / New V1 Progress Log

This log records implementation progress by phase. Detailed task checklists live
in the phase-specific files.

## 2026-07-14

- Cycle 2 Suite09/10 repair: recovered the regression set without adding
  case-specific semantics. Source-empty concrete-store pruning now requires
  summary evidence to be no later than the concrete store, so earlier
  zero-initializers no longer erase later external out-parameter writes.
  Computed metadata source-pointer marker writes now treat overlapping
  concrete `STORE_VAL` nodes as real source-bearing evidence before applying a
  weak marker overwrite, preventing stale callback-field sources from
  surviving a later concrete field kill. Packed byte/subrange lowering now
  resolves `SUBPIECE` through bit-expression sources before falling back to
  stale memory-byte narrowing, and constant recovery ignores the
  `SUBPIECE_OFFSET` operand as a value. Finally, non-overlap pruning preserves
  single-source `LOAD_OVERLAP` evidence into sink-reaching register-backed
  dynamic reads when the unresolved register storage is anchored to the same
  concrete memory identity. These repairs use low-pcode dataflow,
  architecture-aware storage ranges, observed source reachability, call/order
  evidence, and storage identity only; they do not use case IDs, helper names,
  expected labels, fixed offsets, ABI roles, parameter names, or signatures as
  semantics.
- Bumped the summary cache schema for the ordering and register-backed overlap
  changes. Verified with `py_compile`, `compileall -q analysis core frontend
  query report tools`, and fresh-cache focused validation of the 11 reported
  cycle-02 pre-regression failures: DFB131 across the reported PE/Linux
  architectures, DFB034/DFB035 armv7, TV2C626 x86/x64/aarch64, and TV2R001
  UE DebugGame all now pass with expected sources and no forbidden sources.

- Cycle 1 Suite09/10 follow-up repair: fixed multi-sink field-overwrite and
  heap selected-node false positives without adding case-specific source
  semantics. Constant-annihilator handling now treats `INT_AND` with a literal
  or propagated source-empty zero, and `INT_MULT` with a literal zero, as
  source-empty values instead of retaining the killed operand. Source-empty
  pointer-memory overwrite pruning now recognizes stale summary read/carry
  edges into the overwritten target, filters wide `LOAD_OVERLAP` carriers by
  exact observed source slot when a later source-empty overwrite kills one
  field, and prunes stale packed-subrange reads after the overwrite. Concrete
  local source-empty stores now shadow older source-bearing summary inputs to
  the same `STORE_VAL` memory version, covering heap payload constant
  overwrites as well as stack fields. The repair uses Low P-code graph facts,
  source labels, summary provenance, architecture-aware ranges, and exact
  observed storage slots; it does not use case IDs, helper names, expected
  labels, fixed offsets, ABI roles, parameter names, or signatures as
  semantics.
- Verified with `py_compile`, targeted expected validation of the eight
  reported failing scopes (TV2C675 across the reported tier0 variants and
  TV2R340 UE Development), and the in-repo V8 sample gate for
  DFB001/DFB002/DFB004/DFB005 across included sample architectures. All checked
  scopes now validate with expected sources and no forbidden sources.

- Cycle 1 Suite09/10 repair: tightened summary-backed observed storage and
  memory version selection for fused multi-sink and heap alias reload cases.
  Program-level source reachability now follows expression-held ValueIds when
  deciding whether source-bearing non-primary register storage can be preserved
  across a call whose low-pcode body does not write that storage, and
  provider-recognized sink marker calls without scoped bodies can preserve
  unrelated source-bearing observed registers for subsequent code. Precise
  observed-memory read materialization also prefers the latest source-bearing
  program memory version for the same resolved range, so source-empty
  initialization does not mask later summary writes while later same-range
  overwrites still win. The repair is based on low-pcode summaries,
  program-level graph reachability, observed storage, call ordering, and
  architecture-aware memory ranges only; it does not use case IDs, helper
  names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures as semantics.
- Bumped the summary cache schema for the observed storage/memory version
  selection changes. Verified with `py_compile`, `compileall -q analysis core
  frontend query report tools`, fresh-cache focused validation of the five
  supplied failing scoped roots (TV2C673 P1 x86/x64/armv7/aarch64 and TV2R339
  UE DebugGame), and checked-in DFB001/002/034 smoke across sample
  architectures (`PASS 18/18`).

- Cycle 3 Suite09/10 repair: added late pruning for secondary weak metadata
  source-pointer marker writes when the sink-reaching field address is itself
  recovered through a memory-loaded pointer alias. These fallback writes now
  remain available for direct observed fields, but they no longer prove that a
  later alias reload survived unavailable helper-private field kills without
  independent low-pcode or summary evidence. The repair uses weak marker edge
  provenance, observed memory address origins, sink reachability, field order,
  and architecture-aware memory ranges only; it does not use case IDs, helper
  names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures as semantics.
- Bumped the summary cache schema for the alias-loaded metadata-marker pruning.
  Verified with `py_compile`, `compileall -q analysis core frontend query
  report tools`, fresh-cache focused replay of TV2C670, TV2C666, and TV2R335,
  and a checked-in DFB001/002/034 smoke across sample architectures (`PASS
  18/18`).

- Cycle 1 Suite09/10 repair: tightened fused field/alias handling around
  source-empty overwrites, weak metadata marker writes, and call-post pointer
  expressions. Call-post register storage can now preserve an address
  expression from the matching call-pre storage only when the call summary does
  not provide a real output for that storage, so later selected reloads can
  resolve their address without inventing return-value semantics. Source-empty
  memory overwrite materialization now prefers exact-width output ranges and
  refuses broad non-zero-offset projections that would erase sibling fields;
  explicit source-empty overwrite evidence also prunes conflicting source-bearing
  summary-memory inputs to the same target. For thunk-like helpers with no body
  output evidence, weak ordered metadata marker field writes are invalidated
  when a later same-pointer call can shadow the selected field before the sink.
  These repairs use low-pcode dataflow, observed call-pre/post storage, pointer
  expressions, source-empty provenance, weak metadata marker provenance, call
  ordering, and architecture-aware memory ranges only; no case IDs, helper
  names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures were added as semantics.
- Verified with `py_compile`, `compileall -q analysis core frontend query
  report tools`, fresh-cache focused replay of the five supplied Suite10
  failing scoped roots, and a checked-in DFB001/002/034 smoke across sample
  architectures (`PASS 18/18`).

- Cycle 4 regression repair: tightened precise summary-memory overwrite
  selection and dereferenced computed write projection for Suite09/10 weak
  frontier cases. Summary observed-memory writes with precise observed output
  ranges can now shadow stale prior memory even when the summary edge does not
  carry an explicit relative offset, and packed primary subrange stores are
  treated as precise only when their packed store range covers the target
  range. Dereferenced memory-valued summary addresses now resolve through the
  caller's loaded pointer value plus the callee's callsite-resolved affine
  field offset; the resolver no longer falls back to treating the pointer slot
  address itself as the pointee for `deref:mem...` summaries. The repair uses
  Low P-code graph facts, observed call-pre/post storage, architecture-aware
  memory ranges, and source reachability; it does not use case IDs, helper
  names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures as semantics.
- Bumped the summary cache schema for the precise-write and dereferenced
  affine summary semantics. Verified with `py_compile`, `compileall`, and
  fresh-cache focused validation of the eight reported cycle-04 failing
  scopes: TV2C664 P0 x64/armv7/aarch64, TV2C661 P0 aarch64, TV2C607 P1 x86,
  TV2C660 P1 x86, and TV2C664 P1 x64/aarch64. All eight now validate with
  expected sources and no forbidden sources.

- Cycle 2 regression repair: tightened post-call memory carry semantics after
  the Suite09/10 pre-regression run exposed stale adjacent-field and empty
  placeholder propagation. Later post-call memory-to-read edges are now treated
  as weak carry evidence during cleanup, precise read ranges no longer inherit
  wider predecessor ranges when deciding overlap, and empty call-post memory
  placeholders lose to real prior memory versions when resolving loaded pointer
  slots. Dereferenced summary output resolution also now handles missing
  caller input nodes without crashing. The repair is based on low-pcode storage
  ranges, observed call-pre/post memory versions, and source reachability; it
  does not use case IDs, helper names, expected labels, fixed offsets, ABI
  roles, parameter names, or signatures as semantics.
- Verified by replaying all 13 reported cycle-02 Suite09/10 non-PASS scoped
  roots with fresh builders; all now validate with expected sources and no
  forbidden sources. Also ran `py_compile` and the repository compile sweep.

- Cycle 1 Suite09/10 repair: added convention-free interprocedural memory
  bridging for fused field/alias cases where a call writes source-bearing memory
  and a later sink observes a selected reload rather than a direct call result.
  Summary materialization now projects dereferenced pointer outputs through the
  caller's observed pointer expression, can connect a latest single-source
  post-call memory version to a later overlapping read when no intervening
  conflicting write exists, and can derive selected pointer-output offsets from
  callee low-pcode loads before resolving them against caller memory ranges.
  The repair also follows exact spill/reload memory stores when deriving
  constant pointer offsets, which keeps stale field copies and noise overwrites
  from masking the selected payload. The implementation uses low-pcode dataflow,
  observed storage, source labels, call ordering, and architecture-aware ranges
  only; it does not use case IDs, helper names, expected labels, fixed offsets,
  ABI roles, parameter names, or signatures as semantics.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`, a
  repository Python compile sweep, and fresh-cache focused replay of the four
  supplied Suite09/10 non-PASS scopes: TV2C668 x86/armv7 and TV2R335 UE
  Development/DebugGame. All four now report the expected source labels at the
  sink. A small Phase 1 smoke run passed the selected DFB001/DFB002 cases across
  the normal roots but exited nonzero because the PE no-binary entries still
  emit two legacy `ERROR: None` rows.

- Cycle 5 Suite09/10 repair: tightened unresolved computed adjacent-source
  field writes so dispatch/selector scalars are not reclassified as callback
  payload writes. The adjacent-source fallback now skips callsites with local
  concrete function-pointer evidence and rejects any candidate scalar whose
  observed storage contributes to the computed target through low-pcode
  data/address dependencies. This preserves payload-style unresolved callback
  writes while avoiding stale selector/decoy sources in fused callback-table
  field cases. The repair uses observed low-pcode storage, call-pre expression
  facts, and architecture-aware storage overlap only; no case IDs, helper
  names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures were added as semantics.

- Cycle 2 Suite09/10 repair: reclassified loaded-pointer expression repair
  edges as weak fallback evidence when a later low-pcode proof resolves the
  same sink-facing memory to a precise source. Exact dynamic wide-store
  subrange and dynamic-base subrange repairs can now displace stale loaded
  pointer/prior-overlap inputs, which restores fused realloc and live-tail
  payload reads without treating unresolved register-backed writes as final
  evidence. Post-call memory redirection is also scoped to the caller function
  when matching equivalent same-storage memory nodes, preventing recursive
  helper snapshots from stealing caller global reloads. The validator now reads
  whole source-label tokens from `expected_flow` entries that explicitly target
  a sink, so multi-sink oracles can express distinct per-sink sources without
  relying on placeholder flat expected-source arrays. These changes use
  low-pcode storage, expression, source reachability, and oracle structure only;
  no case IDs, helper names, expected labels, fixed offsets, ABI roles, or
  signature metadata were added as semantics.
- Verified with `.venv/bin/python -m py_compile
  analysis/interprocedural_summary.py report/expected_validator.py
  tools/pcode_slicegraph_v8_phase1.py`, `.venv/bin/python -m compileall -q
  analysis core frontend query report tools`, and fresh-cache focused replay of
  all 13 supplied cycle-02 Suite09/10 non-PASS roots (`remaining 0`).

- Cycle 1 Suite09/10 core repair: generalized latest-write shadowing for
  observed-memory summary writes and source-empty global overwrites. Plain
  observed-memory reads now participate in the same precise summary-write
  pruning used for load ranges and call-post memory snapshots, so later
  same-field writes displace older conflicting summary inputs. Observed global
  writes now redirect later global consumers even when the written value is
  source-empty, preserving no-source overwrites instead of keeping stale prior
  global state. UE loaded-pointer reads also get a late expression-resolved
  memory bridge: when a sink-reaching observed-memory address resolves to a
  concrete stack/heap/register memory expression, the matching single-source
  memory node is connected and weak prior-context sources are removed. These
  changes use low-pcode storage, expression, and source reachability only; no
  case IDs, helper names, expected labels, fixed offsets, ABI roles, or
  signature metadata were added as semantics.
- Verified with `py_compile`, `compileall -q analysis core frontend query
  report tools`, replay of all 17 reported Suite09/10 failing scoped roots with
  fresh `/tmp` caches, and checked-in DFB001/002/034 smoke across sample
  architectures (`PASS 18/18`).

- Cycle 2 UE repair: treated packed primary subrange store/load edges as weak
  fill evidence when a later precise dynamic memory write reaches the same
  sink-facing target. Packed edges now record the wide store range used to
  justify the selected lane, invalid packed edges are pruned against that range,
  and later precise overwrite logic may displace packed-fill predecessors just
  like load-overlap/prior-overlap evidence. This removes stale reindexed-field
  sources while preserving struct-return lane rewrites; it uses low-pcode
  storage ranges and source reachability only, with no case IDs, helper names,
  expected labels, fixed offsets, ABI roles, or signature metadata as semantics.
- Verified with `py_compile`, `compileall -q analysis core frontend query
  report tools`, focused TV2R301/TV2R329/TV2R311 DebugGame and Development
  scoped roots, all TV2C658 struct-return lane scoped roots retaining
  `dfb_source_A.ret`, and checked-in DFB001/002/034/048/053 smoke across sample
  architectures (`PASS 30/30`).
- Cycle 1 Engine11 repair: tightened interprocedural memory summaries for fused
  slot/lane writes. Concrete callee memory writes are now filtered by their
  callsite-resolved relative store offset before summary outputs are applied,
  observed-to-memory writes use the same feasible-write guard, and precise
  post-call memory subranges can feed later wider sink-reaching reads. Packed
  subrange repairs now prune conflicting weak overlap predecessors after a
  single selected source is proven. x86 address recovery also handles
  same-instruction multiply/subpiece lowering, and call-boundary detection now
  treats jump-class low-pcode flow metadata as authoritative over `CALL`
  mnemonic text so get-PC branches do not manufacture clobbering call-post
  registers. These changes are driven by low-pcode storage/dataflow only; no
  case IDs, helper names, source labels, ABI parameter/return roles, or fixed
  test offsets were added as semantics.
- Verified with `py_compile`, `compileall -q analysis core frontend query
  report tools`, focused replay of the four reported TV2C661 P0/P1 variants
  with fresh `/tmp` summary caches (all slice only to `dfb_source_A.ret`), and
  checked-in DFB001/002/034/048/053 smoke across sample architectures
  (`PASS 30/30`).
- Cycle 3 validation repair: no-oracle scoped dependency roots that belong to a
  known expected case family and produce no data/control source evidence now
  validate as PASS with an explicit dependency/no-flow reason instead of
  failing as `NO_EXPECTED`. Exact expected entries, unknown no-oracle functions,
  and no-oracle functions with any observed source evidence still keep their
  previous behavior. The repo runner also passes `sink_count` into validation
  for local no-target roots. This is a report-layer harness classification
  change only; it does not infer sources, ABI roles, helper semantics, or
  source/sink markers in Engine11 core.
- Verified with `py_compile`, `compileall -q report tools`, harness-style
  validator probes for the TV2C658/TV2R330 dependency roots, unknown/no-oracle
  negative probes, and exact wrapper probes for TV2C658 and TV2R330.
- Cycle 2 repair follow-up: constrained late source-fill repairs so they do not
  add a distinct source to a target that already has graph-real precise source
  input. Packed primary subrange store/load edges now also require observable
  target memory ranges to be contained by the packed store range, while
  expression-only packed facts can still materialize the selected lane. This
  removes stale adjacent-field and latest-unique false positives without case
  IDs, helper names, expected labels, fixed offsets, ABI roles, or signature
  metadata as semantics.
- Verified with `py_compile`, `compileall`, replay of all 13 supplied
  cycle-02 non-PASS entries with fresh `/tmp` caches (3 now PASS, 10 remain
  source-empty `NO_EXPECTED` helper roots), all eight TV2C658 lane-rewrite
  scoped variants, and a checked-in DFB001/002/034/048/053 smoke across sample
  architectures.

## 2026-07-13

- Cycle 3 repair: refined late dynamic wide-store displacement after the cycle
  2 guard proved too strict for fused TArray swap/remove flows. Later
  register-backed dynamic writes may now replace stale exact/prior-overlap
  inputs when the later write is the latest same-base candidate, its narrowed
  subrange carries one source, and either exact address terms match or the
  observed dynamic storage identity and offset already match. This restores
  reindexed/live-tail payload reads without case IDs, helper names, source-label
  rules, ABI roles, or fixed offsets.
- Verified `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py`, `.venv/bin/python -m compileall -q analysis
  core frontend query report tools`, and scoped replay of the four reported
  TV2R301/TV2R329 development/debuggame roots with fresh `/tmp` summary caches;
  all four now slice only to `dfb_source_C.ret`. The adjacent TV2R311
  development/debuggame scoped roots also still pass.
- Cycle 2 repair: narrowed later call-pre memory snapshot repair to the
  overlapping memory lane before adding read edges, and prevented broad
  latest-dynamic writes from displacing conflicting exact subrange proofs
  unless their address terms exactly match the target. This removes stale
  adjacent-lane sources in callback/field-kill and TArray realloc cases without
  case IDs, helper names, source-label rules, ABI roles, or fixed offsets.
- Verified `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py`, `.venv/bin/python -m compileall -q analysis
  core frontend query report tools`, replayed all 24 cycle-02 pre-regression
  failures with `remaining_fail 0`, checked all eight TV2C657 scoped variants,
  and ran a 30-root DFB001/002/034/043/048 smoke across checked-in samples.
- Cycle 1 repair: tightened register-backed observed-memory read repair for
  fused swap/remove flows. Later dynamic writes may now supersede earlier
  exact-dynamic fallback edges for register-backed observed reads, and a later
  call-pre memory snapshot can repair an unresolved observed read only when the
  snapshot overlaps the read, carries a single source, is not downstream of the
  read, and no intervening write touches the range. This removes stale prior
  overlap sources without case IDs, helper names, source-label rules, ABI
  roles, or fixed offsets.
- Verified the three reported scoped Suite10 roots; each now slices only to
  `dfb_source_C.ret`. Also ran py_compile, compileall, and a DFB001/002/034
  smoke over checked-in architecture samples.
- Cycle 5 repair: added a late exact dynamic wide-store subrange bridge for
  register-backed observed reads. The bridge requires exact address-term
  equality, matching pointer-slot provenance, and a single narrowed source
  label before replacing stale dynamic unique-object fallback edges. This
  restores fused TArray element/field reads without helper-name, case-id,
  source-label, ABI role, or fixed-offset rules.
- Extended low-pcode numeric recovery for callsite-resolved address terms:
  recorded INT_AND/XOR operands are preserved, constant-only bitwise/right-shift
  and complement/two's-complement sequences can fold through known call-pre
  constants, and normal affine shift recovery may use a single constant
  bit-range fallback only when the recorded operand is unresolved. Wide-load
  subrange tracing now computes byte lanes across overlapping memory inputs so
  low 32-bit reads select the correct source cell.
- Verified `.venv/bin/python -m py_compile analysis/interprocedural_summary.py
  analysis/slice_graph_builder.py`, `.venv/bin/python -m compileall -q analysis
  core frontend query tools`, and scoped replay of TV2R001, TV2R202, and
  TV2R315 with fresh `/tmp` output/cache directories; all three now slice only
  to `dfb_source_A.ret`.
- Cycle 4 follow-up: fixed numeric address recovery for narrowed bit-provenance
  shift edges. Affine and constant evaluators now prefer the recorded low-pcode
  operand node for operations such as `INT_LEFT`, using `*_BIT_RANGE` edges only
  as fallback provenance. This preserves source-carrying bit slices while
  preventing masked lane expressions like `index ^ const` from being treated as
  the unmasked index during exact store/load matching.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`; replayed the three reported scoped Suite10 failures with a
  fresh `/tmp` summary cache, all slicing to only `dfb_source_A.ret`; and ran a
  30-root DFB smoke set covering DFB001/002/034/043/048 across checked-in
  architectures with zero failures.
- Repaired fused masked-alias copy/kill propagation without adding case,
  helper, source-label, or ABI-specific rules. Late exact-affine store/load
  repair now acts as an alias-identity bridge: same-storage stack spill/reload
  rewrites are allowed only when the stored value already depends on a
  cross-identity exact bridge. This preserves the generated masked-alias case
  while avoiding stale same-stack history that caused negative-only false
  positives.
- Constrained source-empty primary constant summaries to leaf functions. This
  keeps useful low-pcode constants from simple selector helpers, but prevents
  PIC/call-helper constants in functions with nested calls from overriding
  observed interprocedural source flow.
- Hardened low-pcode expression recovery for negative hex constants,
  source-preserving XOR/shift bit-range edges, and loads whose observed memory
  predecessor carries the address calculation. These changes keep low p-code as
  source of truth and do not introduce argument/return semantics or ABI
  parameter conventions.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`; replayed all 111 pre-repair failures from cycle 02 with
  `remaining_fail 0`; and checked all eight TV2C657 scoped variants, each
  slicing to `dfb_source_A.ret`.
- Repaired shift-derived observed-address recovery by keeping explicit
  low-pcode operand attributes on shift nodes while using narrowed bit-range
  edges as provenance. This restores exact affine stack-to-observed-memory
  overlap proofs in fused array/struct cases and prevents later stale
  unique-memory fallbacks from suppressing the true prior source, without using
  ABI return/argument semantics, helper names, case IDs, source labels, or
  fixed offsets as rules.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`; the two reported UE scoped roots now both slice to only
  `dfb_source_A.ret`.

## 2026-07-11

- Repaired computed callback field-read propagation through direct wrappers and
  tail wrappers whose indirect target is loaded from one observed object field
  while the callback payload pointer is loaded from a neighboring field. The
  summary layer now recognizes source-bearing call-post primary outputs,
  refreshes summaries after late computed-callback edges, traces loaded pointer
  origins through observed memory/bit-range nodes, and applies a guarded
  one-level payload-pointer dereference for computed tail wrappers. The rule is
  based on low-pcode storage origins, observed object fields, source reachability,
  and unique payload-field evidence; it does not add ABI roles, helper-name
  rules, case IDs, source-label rules in core, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; the six reported TV2C637 variants across
  P0 x86/x64/armv7/aarch64 and P1 x86/x64 now produce `dfb_source_A.ret`
  without forbidden sources; adjacent TV2C630-TV2C637 across those affected C++
  roots passes `48/48`; and the local DFB callback guard
  DFB070/071/080/081 across repository sample roots passes `24/24`.

- Extended the late computed-call pointer-scalar memory-write fallback to cover
  observed function-pointer targets whose body is not present in the scoped
  low-pcode set. The pass still requires a single concrete pointer field target,
  a single latest source-bearing scalar, and storage-overlap exclusion before it
  materializes a post-call memory write, so resolved internal functions with
  available summaries continue to use summary-backed flow instead of fallback
  inference.

## 2026-07-10

- Repaired computed function-pointer writer/read selection for fused callback
  cases by preferring callsite-specialized target-body field evidence over
  selector-indexed field fallback when a producer resolves to concrete function
  pointers. Repeated callback-read passes now replace earlier same-post field
  summaries, so a later resolved memory write can shadow stale preserved
  storage. The constant p-code executor also handles additional integer
  comparisons and unresolved PC-relative scalar function refs without using ABI
  roles, helper names, case IDs, source labels, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  targeted TV2C621/622/625 across the reported x86, armv7, and P1_x86
  variants plus adjacent TV2C623 armv7 (`PASS`); Suite10 TV2C620-TV2C629 across
  x86, x64, armv7, aarch64, P1_x86, P1_x64, P1_armv7, and P1_aarch64
  (`PASS 80/80`); and the focused Suite09 DFB001/002/005/070/071/080/081/120/121
  guard across local sample architectures (`PASS 42/42`).

- Tightened unresolved computed-call fallback selection so ambiguous
  multi-source memory/scalar pre-call states no longer collapse to the latest
  source-bearing storage without target or field evidence. This is a
  convention-free false-positive repair for fused computed-call cases: single
  source-bearing evidence still passes through, while adjacent fields with
  distinct source labels require a more precise summary or observed target body
  before contributing to the slice.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  targeted TV2C630 across x86, x64, armv7, aarch64, P1_x86, P1_x64, P1_armv7,
  and P1_aarch64 now reports no forbidden source but still lacks the expected
  source where scoped low-pcode has no target-body field-read evidence; adjacent
  TV2C620-TV2C630 across the same eight variants is `PASS 80 / FAIL 8` with
  only the TV2C630 missing-source residual; and the focused DFB guard for
  DFB001/002/005/070/071/080/081/120/121 across local sample architectures is
  `PASS 54/54`.
- Repaired summary memory-copy application so a call's synthesized
  `CALL_POST_OBSERVED_MEMORY` nodes are not eligible as input snapshots for the
  same callsite during repeated summary passes. This keeps multi-output memory
  transforms such as swaps connected from pre-call memory into each post-call
  output, without introducing output-to-output cycles that can leak independent
  sources across destinations. The rule is based only on observed callsite
  storage timing and applies generally to fused summary reinjection.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  DFB066 across all local sample architectures (`PASS 6/6`); and a focused DFB
  guard for DFB001/002/005/066/070/071/080/081/120/121 across local sample
  architectures (`PASS 60/60`).

## 2026-07-09

- Refined unresolved/computed thunk passthrough and callback field reads for
  Suite09/Suite10 without adding case, helper, source-label, or ABI-specific
  rules. Pointer-addressed fallback is now suppressed for resolved internal
  callees whose consumed primary storage is backed by an ambiguous multi-input
  memory read, and precise field-read stages can replace earlier unresolved
  fallback edges on the same post-call storage. Summary cache schema is now 75.
- Added an evidence-gated callback field-read synthesis for computed calls
  whose target comes from a prior pointer-table helper or from an optimized
  constant function-pointer producer. The new edge requires a unique concrete
  caller pointer, a unique source-bearing field, and either a caller-observed
  selector or a unique register-relative field read in the constant target
  body; post-call values that feed explicit cancelled consumers are ignored.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  Suite10 TV2C620-C627 across x86, x64, armv7, aarch64, P1_x86, P1_x64,
  P1_armv7, and P1_aarch64 (`PASS 64/64`); and a focused DFB guard for
  DFB001/002/005/070/071/080/081/120/121 across local sample architectures
  (`PASS 54/54`).

- Added `dev_docs/large_binary_scaling_plan.md` to shift the optimization
  track from focused hot-case cleanup to game-scale readiness. The plan keeps
  the Engine11 invariants intact: no argument/return vocabulary in the core, no
  ABI-specific parameter semantics, no benchmark/source/sink naming shortcuts,
  and no OLLVM symbolic deobfuscation inside the baseline backward-slice core.
  The next optimization sequence is scale telemetry, persistent parsed/index
  caching, deterministic parallel FunctionGraph construction, graph backend
  isolation, and only then demand-driven/lazy materialization work.

## 2026-07-08

- Started the Engine11 performance-hardening pass while keeping the existing
  Suite09/Suite10 harness as the regression gate. Program directory
  fingerprints are now cached for the lifetime of a `ProgramSliceGraphBuilder`
  instance, avoiding repeated JSON metadata scans for every case in the same
  variant. This keeps the analysis convention-free and does not change slice
  semantics.
- Replaced repeated `networkx.compose` graph copying with direct node/edge
  accumulation for per-directory composed slice graphs, and retained
  path-to-function/source-index metadata on `ProgramSliceGraph` so target
  lookup does not reload the target JSON. Focused `tv2-tier0-P0-x64` timing
  improved from `15.10s` after fingerprint caching to `10.92s` with the
  composed-graph optimization while remaining `PASS 35 / FAIL 0 / FP 0`.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools` and full Suite09/Suite10 local-samples regression with proposed
  regressions included: Suite09 `PASS 488 / FAIL 0 / FP 0`, Suite10 `PASS 334 /
  FAIL 0 / FP 0`. Harness timing improved from `849.18s` aggregate case time
  before the fingerprint cache to `378.54s` after it, then to `306.34s` after
  composed-graph accumulation in serial fallback mode.
- Completed the safe optimization batch by reusing already-loaded low-pcode
  JSON for metadata-aware fingerprints, retaining merged source indexes and
  path-to-function lookup on `ProgramSliceGraph`, avoiding duplicate data-slice
  traversals in harness cut-point reporting, and caching stable artifact hashes
  in the harness. Directory fingerprint reuse is guarded by file stat keys so a
  long-lived builder does not reuse stale fingerprints after regenerated JSON.
  Final full Suite09/Suite10 guard remains green: Suite09 `PASS 488 / FAIL 0 /
  FP 0`, Suite10 `PASS 334 / FAIL 0 / FP 0`. Final aggregate case timing is
  `290.64s` in serial fallback mode; the remaining slow cases are dominated by
  ProgramSliceGraph build time rather than query traversal.
- Added build-stage profiling metadata to `ProgramSliceGraph`/`FunctionGraph`
  so harness performance reports can show which load, summary, compose, or
  injection stage dominates slow cold builds. This is instrumentation only; it
  records timing metadata and does not alter dataflow edges or boundary policy.
- Used the new profiler to trim `inject_metadata_source_pointer_marker_edges`:
  metadata source-pointer propagation now skips instruction keys that have no
  call-pre storage snapshot, because the downstream pointer-field matching
  cannot succeed without one. Focused `tv2-tier0-P0-x64` stayed green and
  improved from `10.56s` to `7.57s`; full Suite09/Suite10 stayed green
  (Suite09 `PASS 488 / FAIL 0 / FP 0`, Suite10 `PASS 334 / FAIL 0 / FP 0`)
  with aggregate serial-fallback timing reduced to `272.36s`.
- Added function-level build profiling inside `SliceGraphBuilder`. The current
  hot spots are large low-pcode functions rather than query traversal:
  `case_TV2R301_tarray_swap_remove_reindexed_field`, `case_TV2R010_nested_container`,
  `FindIndexByHash<FName>`, `Rehash`, and PE TLS helper `__emutls_get_address`.
  Full Suite09/Suite10 remains green with aggregate serial-fallback timing
  `269.69s`. The next safe optimization track should profile pcode-op/node
  creation costs before considering rustworkx or multiprocessing.

- Repaired the Suite09/Suite10 cycle-03 false-positive regressions without
  adding case/helper/source-label/ABI rules. Low-confidence prior-memory carry
  edges into post-call memory are now pruned when any later summary edge
  materializes an observed write to the same post-call memory, preventing stale
  pre-call contents from being joined with real overwrites such as swaps and
  callback field kills. The prior indexed-thunk read bridge now reruns after
  that pruning so AArch64 indexed field reads can use the cleaned post-call
  evidence. Unresolved computed pointer writes also try a 4-byte lane when the
  only scalar evidence is pointer-width on a 64-bit target, while keeping the
  exact-one concrete target requirement. Summary cache schema is now 73.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`; a Suite09 guard over DFB001/DFB002/DFB054/DFB066/DFB080/
  DFB081/DFB120/DFB121 across checked-in sample architectures (`PASS 48 /
  FAIL 0`); and all 26 reported Suite10 cpp-like cycle-03 failures (`PASS 26 /
  FAIL 0`).

- Repaired the Suite09/Suite10 cycle-02 regressions from the computed
  write/read hardening without adding case, helper, source-label, or ABI
  special cases. Post-call observed memory redirection now skips self-redirects
  and preserves a source-bearing prior exact memory version when an empty
  post-call memory node is only being used to retarget later consumers. The
  unresolved computed pointer-scalar overwrite bridge now narrows candidate
  write width from low-pcode scalar expressions, so a zero/sign-extended
  32-bit source in a 64-bit storage selects the 4-byte field instead of an
  ambiguous pointer-sized overlap. Summary cache schema is now 71.
- Verified `.venv/bin/python -m compileall -q analysis core frontend query
  report tools`; a Suite09 guard over DFB001/DFB002/DFB054/DFB080/DFB081/
  DFB120/DFB121 across checked-in sample architectures (`PASS 42 / FAIL 0`);
  all reported cpp-like failures for TV2C609/TV2C615/TV2C621 (`PASS 6 /
  FAIL 0`); and the reported UE R301 DebugGame scope (`PASS`, actual
  `dfb_source_C.ret`, no forbidden `dfb_source_B.ret`).

- Hardened Suite 10 computed write-to-read field flow without ABI, helper-name,
  case-id, or source-label-specific rules. Computed pointer writes now accept
  later call-pre memory snapshots as observed consumers, redirect those
  snapshots to materialized post-call memory, and unresolved memory-indirect
  computed reads prefer the latest single-label observed memory snapshots from
  the composed graph. Direct observed memory writes can now materialize a
  concrete post-call memory version when later call-pre pointer evidence
  observes the same location, and unresolved computed reads rank those
  pointer-addressed memory versions together with ordinary pre-storage
  candidates while excluding memory used only to determine the indirect target.
  Pointer write target selection now uses concrete pointer preference before
  generic call-pre candidates to avoid frame/base register noise.
- Verified all eight focused TV2C622 variants across x86, x64, ARMv7,
  AArch64, and P1 variants: PASS with `dfb_source_A.ret` and no forbidden
  `dfb_source_C.ret`. Verified `.venv/bin/python -m py_compile
  analysis/interprocedural_summary.py`, `.venv/bin/python -m compileall -q
  analysis core frontend query report tools`, and the DFB guard set
  `case_DFB001 case_DFB002 case_DFB080 case_DFB081 case_DFB120 case_DFB121`
  as PASS 36 / FAIL 0.

- Added a constrained unresolved computed-call pointer-scalar memory overwrite
  bridge for Suite 10 field-kill flows. The bridge requires an unresolved
  computed call target derived from a prior call-post value, exactly one concrete
  pointer memory target that later reaches a sink, and a latest single-label
  scalar pre-value; it supports register aliases and observed stack pre-values
  without ABI parameter/return semantics. Conflicting prior summary-memory
  inputs into the proven post-call memory version are pruned after later summary
  passes. Summary cache schema is now 70.
- Verified `case_TV2C621_computed_writer_field_kill` across x86, x64, ARMv7,
  AArch64, and P1 variants (`PASS 8 / FAIL 0`) with actual
  `dfb_source_C.ret`; verified `.venv/bin/python -m py_compile
  analysis/interprocedural_summary.py`; and verified `.venv/bin/python -m
  compileall -q analysis core frontend query report tools`.

- Added a constrained prior indexed-thunk field-read bridge for Suite 10
  cpp-like fused helper flows. The edge is still based on observed storage:
  same concrete pointer expression, same single small selector, latest prior
  single-label scalar source, and a consumed post-call primary register. It
  avoids ABI/signature parameter or return semantics and filters frame/GOT-like
  pointer noise with storage/expression evidence.
- Verified the TV2C620 regression cluster across x86, x64, ARMv7, AArch64,
  and P1 variants: all eight targeted variants PASS with actual
  `dfb_source_B.ret` and no forbidden sources.
- Verified `.venv/bin/python -m py_compile analysis/interprocedural_summary.py`.

## 2026-07-05

- Added a final same-location memory overlap backfill for flattened state
  machines after graph finalization. The repair is still storage/range based:
  it accepts CFG cycles only when producer and target refer to the same memory
  location, rejects source-bearing targets, and keeps ambiguous stored-PHI
  sources out of the slice.
- Extended the prior-overlap target set from source-empty observed memory loads
  to source-empty memory PHIs that already reach a sink or consumed call-pre
  storage. This restores the reported DFB201 A+C stack-PHI flow across x86_64,
  AArch64, and ARMv7 without adding ABI argument/return semantics.
- Fresh-cache probes now have DFB201 passing for PE_x64, linux_amd64,
  linux_arm64, and linux_arm_v7, and restore OBF001/OBF006/OBF007 in
  OLLVM_FLA_SUB_SPLIT while keeping the focused OLLVM OBF008-OBF011 rows free
  of forbidden B/C labels. OBF008/009/010/011 remain missing-source frontier
  cases where broad memory overlap would recreate the Suite12 false positives.
- Hardened Suite12 OLLVM summary composition without introducing ABI
  argument/return semantics or marker-name special cases. Unresolved boundary
  passthrough keeps the strict single-label rule for register candidates and
  named internal helpers, while allowing unresolved computed calls with only
  memory candidates to use the existing latest-source narrowing. This restores
  DFB072 without reopening OLLVM register-ambiguous false positives.
- Pruned flattened stack-PHI backedges only when a later stack store feeds an
  earlier stack PHI and the stored value reaches a source through an ambiguous
  PHI. This removes the reported OBF008 false positives without suppressing
  direct stack stores or source-equivalent PHIs.
- Added `INT_XOR` bit-expression cancellation while preserving the existing
  `x ^ x` zero-idiom kill, so obfuscation arithmetic can cancel repeated terms
  instead of reintroducing stale source edges.
- Bumped the summary cache schema to 57 for the changed summary facts and graph
  repair behavior.
- Focused fresh-cache diagnostic over DFB072 plus the reported Suite12 OLLVM
  failures now has DFB072 passing and no forbidden labels in the OLLVM rows;
  remaining OLLVM rows are missing-source frontier cases.
- Verified `.venv/bin/python -m py_compile analysis/slice_graph_builder.py
  analysis/interprocedural_summary.py`.

## 2026-07-03

- Repaired part of the rebuilt cpp_like low-pcode regression without changing
  expected files, manifests, generated samples, or oracle data.
- Added a narrow observed-thunk scalar field overwrite repair for late
  `CALL_POST_OBSERVED_MEMORY` nodes. The repair requires sink reachability,
  pointer/range agreement, and an unambiguous latest source-carrying scalar
  preparation before the call; pointer-sized/container-wide writes stay out of
  the fallback.
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

- Tightened the TV2C606 heap-field frontier with allocation-site observed
  memory materialization. When Low P-Code address arithmetic proves a concrete
  `heap:allocsite:*` memory key, the graph now materializes an observed heap
  memory node just like observed stack/global/unknown program memory. This lets
  later summary edges attach to the actual sink-reaching heap field load
  without relying on ABI parameter roles, return conventions, helper names, or
  expected edits. The change closed the P0 x64 and P0 aarch64 heap-field LOAD
  residuals by preserving the `operator.new` allocation identity through stack
  spill/reload and field-offset arithmetic.
- Verified with `.venv/bin/python -m compileall -q analysis core frontend
  query report tools`, `git diff --check`, focused no-cache TV2C606 proposed
  regression PASS 7 / FAIL 1 / FP 0, and focused TV2C607 proposed regression
  PASS 0 / FAIL 8 / FP 0. Stable suite10 tier0 remains PASS 104 / FAIL 0 /
  FP 0, and stable suite09 remains PASS 476 / FAIL 12 / FP 0. The remaining
  TV2C606 P1-x64 failure is intentionally left as a thunk-body extraction /
  provider-design frontier: its helper JSON is only a thunk jump, so forcing it
  through Ghidra prototype parameter semantics would violate the convention-free
  core policy.

- Repaired loaded-pointer/container-alias scalar field propagation using
  Low P-Code graph evidence only. Scalar pointer-field summary matching now
  recognizes a destination pointer loaded from observed caller memory, resolves
  that loaded pointer back to concrete stack/heap/register-offset storage, and
  matches the callee's affine field write against the caller's sink-reaching
  observed memory range. The affine recognizer also preserves observed memory
  terms, follows dereferenced observed addresses, and handles narrowed
  subpieces from same-instruction scaled index expressions. Summary cache
  schema is now 54.
- Focused checks close the P0/P1 TV2C607/TV2C608 loaded-pointer misses for
  x86, armv7, and aarch64, plus P0 x64 and P1 x64 TV2C608, without adding
  ABI argument/return semantics or helper/case/source-name special cases.
  P1 x64 TV2C607 remains a thunk-body frontier because its helper Low P-Code
  file is only a computed-jump thunk and the concrete target body is absent
  from the scope; forcing the write from prototype metadata would violate the
  convention-free core policy.

- Repaired source-empty post-call memory redirects with a guarded summary-layer
  preservation edge. When a later `CALL_POST_OBSERVED_MEMORY` node has no data
  producer, reaches a sink, and its outgoing memory edge records that consumers
  were redirected from exactly one overlapping source-bearing prior memory node,
  the composed graph now preserves that prior source into the post-call memory
  node. This is driven by existing low-pcode storage ranges and redirect
  provenance, not ABI roles, helper names, expected labels, or fixed offsets.
  Summary cache schema is now 55.
- Focused cycle-02 checks now pass the reported P1 x86/armv7 TV2C603 misses and
  the DebugGame TV2R001/TV2R201/TV2R301 misses. The P1 x64 TV2C606 and TV2C607
  residuals remain the known thunk-body/provider frontier: their sink-reaching
  post-memory nodes do not have a source-bearing prior redirect to preserve.

- Hardened the low-pcode evidence model for obfuscated Suite12 samples without
  moving source/sink knowledge into the core. Prior observed-memory overlap now
  accepts CFG-preceding stores so flattened state-machine blocks can connect
  later-address stores back to sink-reaching loads, and it may seed call input
  memory when the consumed call output is proven by graph use. Computed
  callback wrappers now add observed-storage passthrough edges only from
  low-pcode evidence: a callee contains a computed call, a non-target observed
  input reaches the computed call input, and the computed-call output is
  consumed by the caller. The fallback unresolved-boundary passthrough is now
  source-aware: it does not add another source to a post-call storage once any
  source label already reaches that post, preventing DFB call-context and
  recursion false positives while still allowing opaque constant/control
  predecessors in obfuscated code.
- Verified with `.venv/bin/python -m compileall analysis` plus no-cache harness
  gates: Suite09 `PASS 488 / FAIL 0 / FP 0`, Suite10 `PASS 152 / FAIL 0 / FP 0`,
  and Suite12 `PASS 91 / FAIL 0 / FP 0`. No expected JSON, manifest, or sample
  low-pcode files were edited.

- Re-audited Suite12 OBF after suspecting the OLLVM oracle/extraction inputs.
  The OBF010 case source/oracle was corrected in `tdo_testbed_Obf`: the helper
  index now resolves to lane1 so the sink is intentionally `dfb_source_A.ret`
  rather than the killed lane2 constant. The low-pcode dumper was also updated
  to include address-taken function pointer targets from DATA references even
  when Ghidra does not classify the reference as a read, closing missing helper
  extraction for `obf009_pick_left`, `obf009_pick_right`, and
  `obf011_payload_path` across all Suite12 profiles.
- Verified the corrected input baseline with `python3 -m py_compile` for
  `analysis/interprocedural_summary.py`, `analysis/slice_graph_builder.py`, and
  `scripts/lowpcode_json_dumper.py`; `python3 -m harness.design_lint
  --engine-repo /Volumes/DO/00_gitProject/01_tdo/lowpcode_data_origin`;
  Suite09 quick cached harness `PASS 488 / FAIL 0 / FP 0`; and a fresh Suite12
  rebuild/extract/regression over all current profiles. The corrected Suite12
  frontier is no longer a missing-helper issue: P0 is `PASS 8 / FAIL 3 / FP 1`,
  P1 `PASS 9 / FAIL 2 / FP 1`, P2 `PASS 7 / FAIL 4 / FP 0`, OLLVM_ALL
  `PASS 7 / FAIL 4 / FP 2`, and the other OLLVM profiles retain OBF006/008/009/
  010/011 recall or forbidden-source precision residuals. Next Suite12 engine
  work should repair false positives first (OBF008/009/011 forbidden B) and then
  improve missing-source recall, without moving test-marker knowledge into the
  core or relying on ABI calling-convention roles.

- Repaired several Suite12 OLLVM residuals in the summary/boundary layer while
  keeping Low P-code storage as the source of truth. Function summaries now
  prefer pointer-sized general registers when narrowing observed memory
  addresses, drop addressless memory-output fallbacks once concrete address
  outputs exist for the same input, and match post-call memory candidates by
  requested byte-range overlap. Computed callback wrapper passthrough now
  connects overlapping post-register aliases and can use a single-label memory
  value reached through a non-source pointer input. Resolved computed callees
  are filtered to concrete observed memory for unresolved-boundary fallback, so
  unknown-register decoy paths are not promoted as broad call returns.
- Added caller-side support for nested indexed pointer writes proven by callee
  affine address terms. When a summary output names memory reached through a
  loaded pointer plus a constant caller index, the caller resolves the concrete
  range from the observed pointer snapshot and materializes the corresponding
  post-call memory node if the later pass has not created it yet. This repairs
  fused callback/container layouts without introducing ABI parameter or return
  semantics.
- Focused validation now keeps the Suite09 DFB guard green for
  DFB051/DFB075/DFB101 across sampled roots, keeps the armv7/P1 cpp-like
  callback family green (`48/48` with data+control slices, including both
  TV2C607 variants), and improves the compact Suite12 OBF sweep to `PASS 117 /
  FAIL 26 / FP 5` against the verified `PASS 109 / FAIL 34 / FP 5` baseline.
  Remaining OBF residuals are concentrated in OBF008 stack-slot reconstruction,
  split/FLA OBF009/OBF010 missing A, and OBF011 decoy/payload precision.
  Summary cache schema is now 62.

- 2026-07-07: Repaired the Suite10 computed-callback struct-overwrite residual
  without adding case/helper/source-label logic. Computed callback wrapper
  detection now carries exact observed pointer-relative memory inputs, including
  memory-backed pointer bases and recovered register+constant address forms
  when Ghidra materializes an observed memory node as unknown unique storage.
  Terminal computed-jump wrappers are treated as the same low-pcode storage
  transition shape, and computed-call wrapper outputs may use a primary
  post-call storage only when that storage is not overwritten before function
  exit. This preserves convention-free semantics while covering fused tail-call
  callback forms across x86, x64, armv7, and aarch64.
- Verified the focused repair with `py_compile` for
  `analysis/interprocedural_summary.py`, direct validation of all eight reported
  TV2C612 variants (`PASS 8 / FAIL 0 / FP 0`), and a same-suite x64 cpp-like
  guard with data+control validation (`PASS 25 / FAIL 0`).

- 2026-07-07: Repaired the Suite10 computed-callback field-kill residual using
  observed low-pcode evidence rather than case-specific labels. Metadata marker
  memory-effect injection now accepts callback-summary-validated field targets
  that appear as observed memory, memory ranges, or call-post observed memory,
  while still requiring source-free sink reachability, a selected callback
  summary, and a pointer-relative write offset match. Prior zero-fill dataflow no
  longer blocks the callback field write, but later post-call data writes still
  do.
- The loader now treats a single Ghidra `PARAM` data reference to a function
  symbol on a load as the same optional function-pointer fact shape used for
  pointer-symbol reads. This preserves low-pcode dataflow as source of truth and
  lets optimized table-load callback selections feed the existing callback
  summary path without ABI or helper-name semantics. Summary cache schema is now
  64.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`,
  `analysis/slice_graph_builder.py`, and `frontend/low_pcode_loader.py`; direct
  validation of all eight TV2C613 roots (`PASS 8 / FAIL 0 / FP 0`); and a
  same-suite x64 cpp-like guard over expected case files (`PASS 26`).

- 2026-07-08: Repaired the Suite10 computed-callback field-kill regression by
  strengthening low-pcode value equality for XOR cancellation. The slice graph
  builder now treats `x ^ x` as zero when both inputs are separate loads of the
  same observed memory version, not only when they are the identical SSA node.
  This lets existing constant propagation resolve callback-table index zero,
  select the observed computed-call target, and apply the normal field-sensitive
  callback summary/overwrite path without ABI roles, helper-name matching, or
  source-label rules. Summary cache schema is now 65.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; direct validation of TV2C614 on x86 and x64
  (`PASS 2 / FAIL 0 / FP 0`); and a focused DFB smoke batch for
  DFB001/DFB002/DFB080/DFB081/DFB111 across available sample architectures
  (`PASS 30 / FAIL 0`).

- 2026-07-08: Hardened computed-callback field flow for Suite10 without adding
  ABI or case-specific semantics. Metadata-marker callback writes now also
  recognize source-empty pointer fields that are stored before a computed call
  but consumed after it, and summary overlap narrowing no longer reintroduces a
  broad memory-range node when a precise summary source already covers the
  requested field. Redirected prior-memory sources are skipped when a narrower
  successor has an exact source summary, preventing selector data from leaking
  into the selected field. Summary cache schema is now 66.
- Verified with `compileall`; focused TV2C615 validation across x86, x64,
  aarch64, P1_x86, P1_armv7, P1_x64, and P1_aarch64 (`PASS 7 / FAIL 0`);
  a local Suite10 cpp-like sweep over available case/variant inputs
  (`PASS 224 / FAIL 0`); and a representative Suite09 DFB smoke batch for
  DFB001/DFB002/DFB080/DFB081/DFB111/DFB120/DFB121 across checked-in sample
  architectures (`PASS 42 / FAIL 0`).

- 2026-07-08: Hardened interprocedural field memory summaries for Suite10
  without ABI or case-specific semantics. Observed memory-to-primary summary
  reads now derive the callee's pointer-relative field offset from low-pcode
  address expressions and map that precise field back to the caller, including
  narrow field loads zero-extended into wider primary storage. Observed
  scalar-to-memory summary writes now materialize a post-call memory version and
  redirect later consumers, so fused read-after-write field flows see the latest
  observed storage transition instead of an older overlapping field. Summary
  cache schema is now 67.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`; direct
  validation of all 12 pre-regression Suite10 failures for TV2C617/TV2C618
  across x86, x64, armv7, and aarch64 (`remaining []`); and a representative
  Suite09 DFB smoke batch for
  DFB001/DFB002/DFB080/DFB081/DFB111/DFB120/DFB121 across checked-in sample
  architectures (`PASS 42 / FAIL 0`).

- 2026-07-08: Repaired the Suite10 cycle-02 false-positive regressions without
  adding ABI, helper-name, case-id, or source-label-specific rules. Observed
  memory-to-primary summaries now require the candidate callee memory field to
  reach the latest concrete primary output node, avoiding dispatch/input fields
  that only overlap the output storage. Caller-side summary memory writes now
  materialize precise post-call fields when the low-pcode pointer expression and
  observed memory range prove containment, and memory consumer redirection is
  range-overlap checked. Computed callback wrappers suppress only source-disjoint
  observed-memory read summaries for the same post-call output, so the callback
  data passthrough remains the chosen source. Prior-call context transfer now
  prefers explicit source-bearing consumed field snapshots when they form a
  single selected lane, preventing key-side snapshots from being projected onto
  value-field sinks. Summary cache schema is now 68.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; direct validation of the six reported cycle-02
  failures (`TV2C612` x86/x64/armv7/aarch64, `TV2C615` aarch64, and `TV2R302`
  UE Development) with `PASS 6 / FAIL 0`; and a representative Suite09 DFB
  smoke batch for DFB001/DFB002/DFB080/DFB081/DFB111/DFB120/DFB121 across
  checked-in sample architectures (`PASS 42 / FAIL 0`).

- 2026-07-08: Repaired the Suite10 cycle-03 prior-context false-positive
  regressions without adding ABI, helper-name, case-id, or source-label-specific
  rules. Explicit consumed-field snapshot projection is now used only when the
  target field offset proves a later same-sized lane; first-lane and
  one-field-offset targets fall back to the exact low-pcode expression/range
  lookup. This keeps the nested-field R302 Development repair while avoiding
  neighbor/key-field projection onto TArray/TMap first-field sinks. Summary
  cache schema is now 69.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; direct validation of the four cycle-03 regressions
  plus the R302 UE Development guard (`PASS 5 / FAIL 0`); and focused Suite10
  cpp-like validation of TV2C612/TV2C615 across x86, x64, armv7, aarch64,
  P1_x86, P1_x64, P1_armv7, and P1_aarch64 (`PASS 16 / FAIL 0`).

- 2026-07-08: Added optional opcode-level SliceGraphBuilder profiling for
  performance work. `ProgramSliceGraphBuilder(profile_opcodes=True)` now
  records per-low-pcode opcode counts, elapsed time, and node/edge growth for
  the hottest function builds. This is an instrumentation-only path: the
  default builder remains unchanged, and the harness must opt in with
  `--slice-profile-opcodes`.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; focused Suite10 P0 x64 opcode-profile run
  (`PASS 35 / FAIL 0 / FP 0`); and full default Suite09/Suite10 regression
  without opcode profiling (`09 PASS 488 / FAIL 0 / FP 0`, `10 PASS 334 /
  FAIL 0 / FP 0`, 822 total cases, 271.11s aggregate timing).

- 2026-07-09: Reduced ProgramSliceGraph post-processing scan cost by grouping
  graph nodes and PHI edges by function before the overlap and ambiguous-stack
  pruning passes. This keeps the same low-pcode semantics and summary rules but
  avoids repeatedly scanning the full composed graph for each function.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; focused Suite10 P0 x64 validation (`PASS 35 / FAIL 0 /
  FP 0`); focused TV2R301 UE validation (`PASS 2 / FAIL 0 / FP 0`); and full
  default Suite09/Suite10 regression (`09 PASS 488 / FAIL 0 / FP 0`, `10 PASS
  334 / FAIL 0 / FP 0`, 822 total cases, 256.15s aggregate timing).

- 2026-07-09: Extended the optional SliceGraphBuilder profiler to include
  non-opcode function-build steps. When `profile_opcodes=True`, hot function
  reports now include merge, call-boundary materialization, source/sink binding,
  and state-copy timing. This confirmed TV2R301's function-build bottleneck is
  mostly call-boundary materialization and merge-state work, while state-copy and
  individual opcode handlers are smaller. Linear merge skipping and architecture
  storage caching were inspected but not kept because the measured benefit was
  too small for the semantic risk/complexity.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; focused TV2R301 UE profiler validation (`PASS 2 / FAIL
  0 / FP 0`); and full default Suite09/Suite10 regression (`09 PASS 488 / FAIL
  0 / FP 0`, `10 PASS 334 / FAIL 0 / FP 0`, 822 total cases, 255.78s aggregate
  timing).

- 2026-07-09: Extended optional function-build profiling with callsite-level
  call-boundary details. Hot function rows now report the slowest callsites,
  target names, repeated materialization count, unique pre/post storage counts,
  and node/edge growth when profiling is enabled. TV2R301 showed the
  call-boundary cost is distributed across many callsites rather than one
  outlier, with DebugGame callsites commonly materializing 58 post storages and
  hundreds of pre-storage observations. This points the next optimization toward
  call-boundary candidate volume/lazy materialization, not source/sink or opcode
  handling.
- Verified with `compileall` over `analysis`, `core`, `frontend`, `query`,
  `report`, and `tools`; focused TV2R301 UE call-boundary profiler validation
  (`PASS 2 / FAIL 0 / FP 0`); and full default Suite09/Suite10 regression (`09
  PASS 488 / FAIL 0 / FP 0`, `10 PASS 334 / FAIL 0 / FP 0`, 822 total cases,
  255.75s aggregate timing).

- 2026-07-09: Added a resolved function-pointer scalar memory-write summary
  pass for computed calls. When a computed target is dataflow-linked to a prior
  observed call result, the pass recovers concrete candidate callees from
  low-pcode function-address constants and optional per-instruction data
  references, then reuses callee observed-to-memory summaries only if the
  pointer field and source storage bind unambiguously at the callsite. This
  repairs fused computed writer field overwrites without treating ABI
  signatures or source labels as semantics.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  targeted TV2C623 validation across x86, x64, armv7, and aarch64 all producing
  `dfb_source_A.ret`; adjacent TV2C620-C623 scan across the same four
  architectures preserving C620=`dfb_source_B.ret`, C621=`dfb_source_C.ret`,
  C622=`dfb_source_A.ret`, and C623=`dfb_source_A.ret`; and a focused DFB guard
  for DFB001/002/005/080/081/120/121 across available sample architectures
  (`PASS` for all emitted rows).

- 2026-07-09: Hardened metadata source-pointer marker writes for synthesized
  post-call memory. Computed-call field candidates now include
  `CALL_POST_OBSERVED_MEMORY` nodes for the same callsite, but marker writes to
  those nodes are treated as replacement evidence: they may prune conflicting
  summary carry/preservation inputs, must not compete with resolved
  function-pointer memory-write summaries, and for actual computed-call
  instructions must match the latest observed source-bearing scalar at the
  callsite. Direct dispatch wrappers can still create post-call memory from
  callback-summary evidence. This keeps callback field recovery general while
  avoiding stale metadata overriding observed pre-call dataflow.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  focused TV2C613/TV2C621/TV2C624 checks; Suite10 P0 TV2C620-C624 across x86,
  x64, armv7, and aarch64 (`PASS` 20/20); broader Suite10 P0 scan across x86,
  x64, armv7, and aarch64 (`PASS` 148/148); and a focused DFB guard for
  DFB001/002/005/080/081/120/121 across local sample architectures (`PASS`
  42/42).

- 2026-07-09: Added late refinement/materialization for unresolved computed
  pointer scalar memory writes. The late pass revisits early unresolved
  computed-call memory summaries after preservation, callback, and overlap
  evidence has been injected; it replaces stale write sources only when the
  final call-pre graph has a unique latest source-bearing scalar that does not
  overlap the output memory. A companion materialization path covers computed
  targets loaded through temporaries when the target value still traces to a
  prior observed call result, there is exactly one concrete pointer-addressed
  memory target, and the source selection is unique. This repairs fused
  callback field overwrite/kill cases across register and stack-prepared
  forms without using ABI roles, helper names, or case labels.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  Suite10 P1 TV2C620-C625 across x86, x64, armv7, and aarch64 (`PASS 24/24`);
  broader Suite10 P1 TV2C* scan with data/control validation across the same
  four architectures (`PASS 152/152`); and a focused DFB guard for
  DFB001/002/005/080/081/120/121 across local sample architectures (`PASS`
  42/42).

- 2026-07-09: Repaired unresolved computed pointer scalar memory-write
  fallback precedence. Late refinement/materialization now treats unresolved
  computed-call memory writes as a fallback only: if the same synthesized
  post-call memory already has a non-fallback summary write, such as a resolved
  function-pointer callee summary, the late latest-scalar heuristic will not
  replace it. This preserves stronger observed storage-transition evidence for
  fused computed writers while keeping the unresolved path available for cases
  without resolved callee/body evidence.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  targeted TV2C623 x86/x64 validation (`PASS`, both producing
  `dfb_source_A.ret`); Suite10 P0 TV2C620-C625 across x86, x64, armv7, and
  aarch64 (`PASS 24/24`); broader Suite10 P0 TV2C* scan with data/control
  validation across the same four architectures (`PASS 152/152`); Suite10 P1
  TV2C620-C625 across x86, x64, armv7, and aarch64 (`PASS 24/24`); and a
  focused DFB guard for DFB001/002/005/070/071/080/081/120/121 across local
  sample architectures (`PASS 54/54`).

- 2026-07-10: Refreshed auto summaries after observed/source storage
  preservation has been injected, then re-applied summary edges. This lets
  source-bearing values preserved across a boundary call inside a callee become
  precise source-to-pointer-field memory summaries for direct callers. The
  repair is based on observed storage transitions already present in the graph;
  it does not use ABI roles, helper names, source labels, or case IDs as
  semantics.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  targeted TV2C628 across P1 x86, x64, armv7, and aarch64 (`PASS 4/4`,
  producing only `dfb_source_A.ret`); adjacent Suite10 P1 TV2C620-C628 across
  the same four architectures (`PASS 36/36`); and a focused DFB guard for
  DFB001/002/005/070/071/080/081/120/121 across local sample architectures
  (`PASS 54/54`).

- 2026-07-10: Added evidence-backed computed function-pointer target-set
  summary edges and callsite-specialized constant function-pointer selection.
  The new computed-call pass resolves observed local function-pointer table
  stores only when every concrete target summary agrees on the same observed
  input-to-primary output flow at the callsite. The callback field-read pass can
  now narrow producer-returned function-pointer sets with low-pcode constant
  branch evidence, including intra-instruction conditional p-code and generic
  `PTR_<function>_<address>` pointer-symbol hints. The logic remains in the
  summary layer and does not assign ABI return/argument semantics or use case
  IDs, helper names, source labels, or fixed offsets as rules.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  focused DFB072 local CLI check (`PASS`); and a direct TV2C630 matrix probe
  across P0/P1 x86, armv7, and aarch64 (`PASS 6/6`, only
  `dfb_source_A.ret`). The P0/P1 x64 TV2C630 samples still have no source in
  the focused probe because the scoped low-pcode exposes the picker as a thunk
  without picker/reader target bodies; no signature/name-based fallback was
  added.

- 2026-07-10: Added a guarded scalar field-read bridge for unresolved computed
  calls with boundary-provider metadata source-pointer markers. When an
  indirect target value is itself traced to a prior observed call result, the
  call has exactly one concrete non-source pointer input, and a marker-selected
  source-bearing field under that pointer uniquely matches the consumed
  post-register width, the summary layer connects that field to the post-call
  primary storage. This covers thunk/fused cases where helper bodies are not
  scoped without adding ABI return semantics, helper-name rules, case IDs, or
  fixed field offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`; direct
  probes for TV2C630 P0/P1 x64 now produce only `dfb_source_A.ret`; Suite10
  x64 TV2C620-TV2C630 across P0/P1 (`PASS 22/22`); and a focused Suite09 local
  DFB guard for DFB001/002/005/080/081/120/121 across sample architectures
  (`PASS 42/42`).

- 2026-07-10: Added a source-selected function-pointer dispatch memory-write
  summary pass for unresolved computed calls. When an indirect call target is
  loaded from a prior internal function-pointer producer, that producer has
  multiple concrete internal target constants, the producer callsite has one
  latest source-carrying selector, and the candidate target summaries show
  ambiguous pointer-field write sources at the dispatch callsite, the summary
  layer now records the selector as the source of the observed memory
  transition and prunes stale fallback computed-pointer writes into the same
  post-call memory node. This stays convention-free: the evidence is low-pcode
  target production, observed callsite storage, concrete target summaries, and
  sink-reaching memory overlap, not ABI roles, helper names, case IDs, source
  labels, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  direct TV2C631 probes across P0 x86, x64, armv7, and aarch64 now produce
  only `dfb_source_A.ret`; and a lightweight Suite10 P0 x64 TV2C* sweep using
  data and control slicing matched expected results for 44/44 case roots.

- 2026-07-10: Added direct-table computed-call field-read summary handling and
  tightened the unresolved metadata-marker fallback. The new direct-table pass
  resolves low-pcode function-pointer table loads from constants, data refs, and
  pointer-symbol global ranges, then connects caller pointer-field sources to
  consumed primary post storage only when all concrete target summaries agree
  on one observed pointer-field read. For unresolved table calls, the
  metadata-marker bridge now yields to concrete source-bearing evidence at the
  selected pointer base field, preventing a low-confidence marker from
  overwriting an observed pre-call field source. This stays source-label,
  helper-name, case-ID, fixed-offset, and ABI-signature independent.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`;
  focused TV2C626/TV2C632 probes covering the reported six TV2C632 variants plus
  the adjacent TV2C626 aarch64 false-positive guard (`PASS 7/7`); and a
  Suite10 TV2C620-TV2C632 adjacent sweep across P0 armv7/aarch64 and P1
  x86/x64/armv7/aarch64 (`PASS 78/78`).

- 2026-07-10: Tightened computed function-pointer memory-write handling for
  callback field overwrites. The summary layer now narrows function-pointer
  producer outputs with concrete low-pcode selector execution, including
  intra-instruction conditional branches, simple scalar ops/shifts, optional
  function-entry data-ref facts for literal/PC-relative stores, and explicit
  prior storage writes when an intervening call boundary refreshed a preserved
  target register. Ambiguous computed targets no longer assert unresolved
  concrete field writes, and resolved broad-target writes avoid overwriting a
  prior summary-written field when the target set is not uniquely selected.
  This keeps the rule based on observed storage, low-pcode control/data facts,
  and internal target summaries rather than ABI roles, helper names, source
  labels, case IDs, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`; direct
  TV2C633 probes across P0 x86/x64/armv7/aarch64 and P1
  x86/x64/armv7/aarch64 now produce only `dfb_source_A.ret` (`PASS 8/8`).

- 2026-07-11: Hardened observed memory identity and post-call memory
  materialization for callback/global field flows. Register and register-offset
  pointer expressions that have exactly one constant address origin now
  materialize concrete global memory keys, and global identities are normalized
  before range comparison so equivalent zero-padded and non-padded addresses
  overlap. Caller-side source-to-memory summaries now splice post-call observed
  memory into later overlapping memory/load consumers, and storage-overlap
  pruning compares heap, stack, and global ranges as well as register ranges.
  The change remains based on low-pcode storage/data evidence and summary
  memory transitions; it does not introduce ABI argument/return semantics,
  helper-name rules, case IDs, source-label rules, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; focused Suite10 UE probes show the global
  callback field precise development/debug variants now produce only the
  expected observed source, while the remaining computed mutator/overwrite/read
  failures still require narrower computed-call source selection.

- 2026-07-11: Repaired Suite10 UE computed-call regressions without adding
  case/helper/source-label rules. Constant memory-key materialization now
  requires all address-expression inputs to be constant before collapsing a
  pointer expression to a global offset, preserving source-bearing pointer bases
  in fused TArray address calculations. Computed-call memory-write handling now
  accepts resolved-but-unscoped function-pointer targets only when a single
  concrete pointer write and single source are observed, gates the late
  unresolved fallback when multiple source labels are live without target
  support, redirects later summary-memory reads through post-call overwrite
  nodes, and inserts a no-source overwrite barrier when all ambiguous computed
  targets write the same pointer memory but disagree on source. The low-pcode
  builder also honors constant forward intra-instruction `CBRANCH` targets and
  evaluates constant equality expressions.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; focused rerun of the nine pre-regression
  Suite10 UE failures moved TArray cases to the expected data sources
  (TV2R002/TV2R011/TV2R301), fixed callback field precision/read cases
  (TV2R304/TV2R305), and removed the wrong computed-call sources from
  TV2R307/TV2R309. The local expected-validator check reports 5/9 PASS on the
  prior failure set; TV2R307 and TV2R309 still miss `dfb_source_A.ret` pending
  stronger dispatch-target selection.

- 2026-07-11: Added callsite-scoped low-pcode constant target selection for
  ambiguous computed calls and made selected computed source-to-memory summaries
  materialize a post-call memory node before redirecting later consumers. This
  lets concrete function-pointer dispatches use the selected target's observed
  memory summary and shadow prior heap field stores without trusting Ghidra's
  single displayed target name. The unresolved computed-pointer heap write
  fallback now declines to pick a latest scalar when multiple source labels are
  live and no target summary supports the overwrite, avoiding unsupported heap
  false positives while leaving stack/local strict-latest cases available.
  These rules are based on low-pcode constants, observed storage, and summary
  memory transitions, not ABI roles, helper names, source labels, case IDs, or
  fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; focused rerun of the 12 reported Cycle 3
  failures now passes 10/12. The affected-family subset
  TV2C621/TV2C627/TV2C630/TV2R307/TV2R308/TV2R309 across the report variants
  passes 28/30, with only TV2R307 Development/DebugGame still missing
  `dfb_source_A.ret` and no forbidden source.

- 2026-07-11: Tightened post-call memory load redirection after the Cycle 4
  regression. A later `CALL_POST_OBSERVED_MEMORY` node now rewrites direct
  `LOAD` memory inputs only when that post node has effective overwrite
  evidence: a source-bearing path, a non-carry summary-memory write, or an
  explicit no-source overwrite barrier. Source-empty broad post snapshots can
  still feed later call-pre storage, but they no longer erase a precise
  source-bearing subfield/lane load. This is based on observed storage ranges
  and summary-write evidence, not ABI roles, helper names, case IDs, source
  labels as rules, or fixed offsets.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; the 18 reported Cycle 4 Suite10 C++
  regressions now pass in focused local probes. Adjacent UE guard probes for
  TV2R301/304/305/309 stay passing across Development and DebugGame; TV2R307
  remains a no-source miss because the scoped low-pcode includes the resolver
  identity but not the selected mutator bodies needed for convention-free
  source selection.

- 2026-07-11: Repaired the remaining Suite10 UE TV2R307 computed mutator miss
  with a guarded unresolved-computed field-write summary. When an indirect
  target is traced to a prior observed call result, a single concrete non-source
  pointer pre-storage reaches the later sink field, and exactly one source
  scalar is prepared immediately after that pointer in the observed low-pcode
  callsite storage flow, the summary layer now writes that scalar to the
  precise sink-reaching field. Pre-call initialized fields are accepted only
  when a post-call sink consumer proves the field is read after the computed
  call, and competing candidates are narrowed to the smallest matching memory
  range. This remains based on low-pcode storage order, pointer expressions,
  source reachability, and memory ranges; it does not use ABI names, helper
  names, case IDs, source labels as rules, or fixed offsets.
- Bumped the summary cache schema for the changed computed-call summary
  behavior. Verified with `py_compile`/`compileall`, direct scoped TV2R307
  Development and DebugGame checks producing only `dfb_source_A.ret`, and a
  compact UE guard over TV2R301/304/305/307/309 in both `low_pcode` and
  `low_pcode_P0`.

- 2026-07-11: Tightened unresolved computed callback readers for scoped UE
  cases where the callback body is unavailable but the caller low-pcode shows
  the callback target loaded from a concrete field of the same pointed object.
  The summary layer now selects the nearest prior source-bearing field before
  the loaded callback slot, removes the fallback unresolved passthrough, and
  records the observed pointer, field offset, callback-field offset, and field
  size on the summary edge. This stays convention-free: it uses materialized
  callsite storage, pointer expressions, memory ranges, and source reachability,
  not ABI roles, helper names, case IDs, source labels as rules, or fixed
  offsets.
- Verified with `compileall`, a scoped TV2R311 check returning exactly
  `dfb_source_A.ret`, and the local DFB080/DFB081 computed-call guard across
  the repository sample roots.

- 2026-07-11: Fixed Suite09/10 regression cycle 1 by preserving temporal
  order for source-to-memory summaries and broadening DFB metadata marker
  recognition inside the boundary adapter. Source-to-memory summary writes now
  materialize a `CALL_POST_OBSERVED_MEMORY` value before redirecting later
  consumers, so a post-call field write no longer contaminates pre-call memory
  used by an earlier fused/computed callback. The DFB boundary provider still
  prefers explicit `PTR_dfb_source_*` symbols, but can now fall back to
  source-name string symbols when pointer markers are absent in scoped UE
  low-pcode. Both changes remain outside core ABI semantics and use observed
  storage, memory ranges, and boundary-provider marker interpretation.
- Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/boundary_provider.py`; focused reruns of TV2C638 x86/armv7 and
  TV2R313 Development/DebugGame now pass. Additional guards passed: selected
  Suite10 callback/summary P1 x86 cases 7/7, selected Suite09 DFB memory and
  function-pointer cases 9/9, all Suite10 P1 x86 C++ cases 51/51 with control
  validation, and UE scoped Development plus DebugGame sweeps 37/37 each.

- 2026-07-11: Repaired Suite09/10 cycle 1 direct pointer-field read misses in
  fused C++ and UE scoped cases. The interprocedural summary layer now resolves
  callee primary outputs that are loaded through observed input pointers,
  branch-selected stack-resident pointers, and nested indexed pointer reads
  when callsite low-pcode constants make the selected storage unique. Affine
  address tracing now follows explicit stack spills used in address
  expressions, and pre-call memory lookup can consume a source-bearing prior
  summary write whose materialized memory node is anchored by a later observed
  read, provided no overlapping write intervenes before the current call. The
  repair uses observed low-pcode storage, memory ranges, graph reachability,
  and architecture storage sizes; it does not rely on ABI parameter/return
  roles, helper names, case IDs, source labels as rules, or fixed offsets.
- Bumped the summary cache schema for the new summary behavior. Verified with
  `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; all 7 pre-regression failures from the
  cycle report now produce exactly `dfb_source_B.ret` in focused local probes.
  The documented V8 Phase 1 gate for DFB001/DFB002 also passes across the
  checked-in sample architecture roots.

- 2026-07-11: Repaired Suite09/10 cycle 2 regressions from the direct
  pointer-field summary work. Prior summary-write lookup no longer treats an
  unparseable or wildcard memory key as a match-all range; when a requested
  range cannot be parsed, lookup and intervening-write checks require exact
  materialized storage identity. This preserves the intended prior-summary
  reuse for concrete byte ranges while preventing broad stack-frame matches
  from poisoning single-source thread/runtime evidence or UE direct field-read
  precision.
- Bumped the summary cache schema for the tightened memory lookup behavior.
  Verified with `py_compile`, focused DFB092 across all eight checked-in
  variants, the scoped UE DebugGame TV2R301 probe producing only
  `dfb_source_C.ret`, and the documented DFB001/DFB002 phase gate across the
  checked-in sample architecture roots.

- 2026-07-11: Repaired Suite09/10 cycle 1 fused computed-call and UE indexed
  field-read regressions without introducing ABI return/argument semantics.
  Unresolved computed calls whose target is source-clean and loaded from
  observed memory can now connect a single sink-reaching post register to the
  earliest uniquely ordered source-bearing call-pre storage, pruning only
  conflicting summary predecessors. Auto summaries now prefer direct observed
  address-base storage over transitive index contributors, trace a single
  consistent affine value through multi-predecessor `INT_LEFT` nodes, and can
  use prior same-base summary memory writes for indexed reads when exact byte
  offsets are under-specified but the selected prior field has one source
  label. These paths are gated by observed low-pcode storage, graph
  reachability, memory ranges, and architecture sizes; they do not use
  case/helper/source names, fixed offsets, ABI roles, or signature metadata as
  semantics.
- Bumped the summary cache schema for the new summary and fallback edges.
  Verified with `py_compile` for `analysis/interprocedural_summary.py`; focused
  reruns of TV2C640 across x86/x64/armv7/aarch64 and TV2R315 UE Development
  plus DebugGame now produce exactly `dfb_source_A.ret`; the documented
  DFB001/DFB002 phase gate also passes across the checked-in sample roots.

- 2026-07-11: Tightened the unresolved computed loaded-target fallback after
  Suite09/10 cycle 2 exposed false-positive source selection on stack and
  generic register-relative computed calls. The fallback now applies only when
  the computed target memory is heap-backed, either directly by storage identity
  or through the actual target-value address chain reaching heap allocation
  storage. Stack/table and non-heap register-relative targets continue to rely
  on more precise function-pointer, memory-write, and summary evidence instead
  of label ordering. This keeps the heap closure/lambda repair while avoiding
  broad earliest-source propagation across fused callback fields.
- Bumped the summary cache schema for the tightened fallback. Verified with
  `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; all 17 reported cycle-2 regressions
  passed in focused probes, and guard probes for TV2C640 x86/x64/armv7/aarch64
  plus TV2R315 Development/DebugGame still produce exactly `dfb_source_A.ret`.
  The documented DFB001/DFB002 phase gate passed across the checked-in sample
  architecture roots.

- 2026-07-11: Tightened source-to-memory summary application for callees whose
  pointer-field writes merge through branch-controlled memory PHIs. When a
  callsite provides constant observed inputs, summary application now reuses the
  existing Low-Pcode constant executor to compute reachable callee instruction
  addresses and narrows source-to-memory edges only to source boundaries that
  reach concrete `STORE_VAL` writes for the same output memory range on those
  reachable paths. If constant evaluation or concrete write evidence is absent,
  the existing conservative summary union is preserved. This remains
  convention-free: it uses observed call-pre storage, architecture-aware
  register overlap, low-pcode execution, and memory ranges, not ABI roles,
  helper names, source labels as rules, case IDs, or fixed offsets.
- Bumped the summary cache schema for the callsite-feasible summary behavior.
  Verified with `py_compile` for `analysis/interprocedural_summary.py`; focused
  expected-validator probes for the reported stack-field branch overwrite case
  now pass on x86, x64, armv7, and aarch64 with only `dfb_source_A.ret`. The
  documented DFB001/DFB002 phase gate also passes across the checked-in sample
  architecture roots.

- 2026-07-11: Repaired Suite09/10 cycle 1 fused pointer-field and indexed heap
  lane misses without adding ABI return/argument semantics. Interprocedural
  memory-read summary application can now recover callee address expressions
  that become affine only after callsite constants are folded, including masked
  indexed selectors, and affine tracing preserves in-place scaled unique values
  instead of falling back to an earlier narrowed bit-range source. For scaled
  field reads whose selector is not constant, a narrow fallback uses the
  callee's observed base-plus-stride address expression and selects a same-object
  aligned field only when the zero slot is source-clean and the stride slot has
  one source-bearing value. The repair is based on Low-Pcode graph reachability,
  observed storage, byte ranges, and architecture sizes; it does not depend on
  case IDs, helper names, expected labels as rules, fixed test offsets, or
  signature/ABI roles.
- Bumped the summary cache schema for the new callsite-resolved indexed-read
  behavior. Verified with `py_compile` for
  `analysis/interprocedural_summary.py`; focused probes for the reported
  TV2C642 x86/x64 and TV2R317 Development/DebugGame failures now pass with only
  `dfb_source_A.ret`.

- 2026-07-11: Repaired Suite09/10 cycle 2 fused ARMv7 callback false
  positives by tightening affine tracing for reused Low-Pcode temporaries. For
  `INT_LEFT`, explicit bit-range operands now take precedence over the
  previous-version fallback; the fallback is used only when no explicit value
  operand can be resolved. This preserves the in-place shift recovery path while
  avoiding stale unique-temp terms that under-scale indexed memory writes and
  cause prior field values to be preserved across real overwrites. The repair
  is based on Low-Pcode edge evidence, observed storage, callsite constants,
  and byte ranges; it does not depend on case IDs, helper names, source labels,
  fixed offsets, ABI roles, or signature metadata.
- Bumped the summary cache schema for the corrected affine summaries. Verified
  with `py_compile` for the touched engine modules, a focused TV2C606/TV2C607
  probe producing only `dfb_source_A.ret`, the full Suite10 P1 ARMv7 C++ sweep
  at 55/55 PASS, and the documented DFB001/DFB002 phase gate across the
  checked-in sample architecture roots.

- 2026-07-11: Repaired the Suite10 cycle 3 indexed heap-lane false positive
  by preserving the actual Low-Pcode shift value/shift operands as node
  metadata and using those operands for affine memory-address recovery. This
  prevents source-slice bit-range edges from replacing the numeric operand of
  destructive/in-place shifts when a reused unique temporary carries additional
  arithmetic context such as `selector + 1`. Callsite-resolved affine recovery
  now also follows stack spill/load pairs and is preferred when caller constants
  make the indexed address concrete, so masked or overwritten selectors select
  the observed lane instead of falling back to the base field. The repair uses
  Low-Pcode operand identity, observed storage, stack/memory graph edges, and
  byte ranges; it does not use case IDs, helper names, expected source labels,
  fixed offsets, ABI roles, or signature metadata as semantics.
- Bumped the summary cache schema for the shift-operand affine behavior.
  Verified with `py_compile` for `analysis/interprocedural_summary.py` and
  `analysis/slice_graph_builder.py`; scoped TV2R317 Development and DebugGame
  now pass with only `dfb_source_A.ret`. Guard probes for TV2C606/TV2C607
  ARMv7 and TV2C642 x86/x64 still produce only `dfb_source_A.ret`, and the
  documented DFB001/DFB002 phase gate passes across the checked-in sample
  architecture roots.

## Current Focus

- 2026-07-11: Repaired Suite10 cycle 1 remaining callback/heap overwrite
  false positives by refining observed-memory write summaries around terminal
  writers. Auto summaries now remove earlier observed-input writes to the same
  address/range only when Low-Pcode evidence identifies a later surviving
  writer: straight-line storage versions select the latest writer, and PHI
  outputs are collapsed only when the PHI control condition is locally proven
  by Low-Pcode value facts such as a nonzero `INT_OR` feeding an equality test.
  General summary injection and thunk scalar-pointer-field injection both
  consult the same callee-local survivor predicate, so specialized fused
  callback paths cannot resurrect overwritten fields. The repair uses
  observed storage, Low-Pcode graph edges, memory ranges, storage overlap, and
  local control/value facts; it does not use case IDs, helper names, expected
  labels, fixed test offsets, ABI roles, or signature metadata as semantics.
- Bumped the summary cache schema for terminal observed-memory write pruning.
  Verified with `py_compile` for `analysis/interprocedural_summary.py`, the
  five reported repros TV2C647 on x86/x64/armv7/aarch64 plus TV2R322
  DebugGame, the adjacent C++ TV2C645-TV2C647 cluster across all four P0
  architecture roots, and exact UE TV2R321/TV2R322 DebugGame repros. A small
  Suite09 smoke was attempted but skipped because the expected Suite09 sample
  root was not present in this workspace path.

- 2026-07-11: Repaired the Suite10 cycle 2 ARMv7 optimized
  loaded-pointer callback overwrite false positive without adding ABI
  return/argument semantics. When a nested loaded-pointer memory summary has
  been normalized to `deref:<observed storage>` plus a field output, summary
  output selection now recovers the original callee Low-Pcode memory address,
  resolves affine/index terms with callsite constants, and applies the write
  to the exact caller memory range before stale preservation can carry an older
  value. The repair uses Low-Pcode address expressions, observed storage,
  architecture-aware memory ranges, and callsite constants; it does not use
  case IDs, helper names, expected labels, fixed offsets, ABI roles, or
  signature metadata as semantics.
- Verified with `py_compile` for `analysis/interprocedural_summary.py`, the
  focused TV2C607 P1 ARMv7 repro, the P1 ARMv7 callback cluster TV2C605-C608
  and TV2C611-C614, TV2C607 across all eight Tier0 variants, full P1 ARMv7
  cpp-like Suite10 local cases (59/59 PASS), and Suite09 smoke DFB001/DFB005/
  DFB066 across the checked-in sample architecture roots.

- 2026-07-11: Repaired Suite10 post-apply cycle 1 fused heap/lambda and UE
  computed-dispatch false positives without adding ABI return/argument
  semantics. Summary refresh now rebuilds function summaries from the composed
  local graph so nested call effects are visible to wrapper summaries. Nested
  loaded-pointer memory summaries are normalized into dereferenced observed
  storage, including explicit offset-zero fields, and summary memory range/key
  parsing now handles `summary:field` and nested offset-zero identities. The
  unresolved computed-field overwrite pass now also runs after late overlap
  evidence, accepts computed calls whose target was materialized by Low-Pcode
  evidence, bounds ambiguous callback wrapper pairs, and redirects stale
  cancelled-operation consumers only when a precise post-call memory overwrite
  replaces the old source-bearing memory. The repair uses Low-Pcode graph
  edges, observed storage, architecture-aware ranges, callsite materialization,
  and byte offsets; it does not use case IDs, helper names, expected labels,
  fixed test offsets, ABI roles, or signature metadata as semantics.
- Bumped the summary cache schema for nested loaded-pointer and computed-field
  overwrite behavior. Verified with `py_compile` for
  `analysis/interprocedural_summary.py` and focused repros for TV2C646 on
  x86/x64/armv7/aarch64 plus TV2R321 Development/DebugGame; all six now match
  their expected source sets with no forbidden sources.

- 2026-07-11: Repaired Suite10 post-apply cycle 1 split-lane and heap-select
  misses without introducing ABI return/argument semantics. Callsite-resolved
  affine tracing now treats observed memory as a valid base, follows direct
  observed-memory loads and overlap stack reloads, and uses explicit PHI
  control plus small callsite constants to select adjacent field/lane terms.
  Pointer expression recovery now follows short data chains through summary
  edges and stack spills, preferring concrete heap/stack expressions over
  synthetic unknown-register identities. A narrow callsite-resolved pointer
  identity edge is added only when callee Low-Pcode proves `output = input + 0`
  for exactly one pointer-valued observed input at that callsite. This repair
  is based on Low-Pcode graph edges, observed storage, callsite constants,
  architecture-aware storage, and byte ranges; it does not use case IDs, helper
  names, expected labels, fixed offsets, ABI roles, or signature metadata as
  semantics.
- Bumped the summary cache schema for the callsite affine/identity behavior.
  Verified with `py_compile` for `analysis/interprocedural_summary.py` and a
  focused six-case probe covering TV2C645 on x86/x64/armv7/aarch64 plus
  TV2R320 Development/DebugGame; all six now slice to only
  `dfb_source_B.ret`.

- 2026-07-12: Repaired the negative-only and live field-overwrite frontier
  failures without adding ABI return/argument semantics. Auto summaries now
  record concrete pointer-memory stores whose stored value tree is source-empty
  and observed-input-empty, and summary application materializes those stores
  as no-source overwrite barriers before redirecting later consumers. Memory
  preservation across calls now selects the latest unambiguous source-bearing
  memory node for the same caller range before the call, so later disjoint
  writes preserve the live post-call field value instead of resurrecting an
  older store. The repair is based on Low-Pcode store/value trees, observed
  storage, callsite expressions, and architecture-aware memory ranges; it does
  not use case IDs, helper names, expected labels, fixed offsets, ABI roles, or
  signature metadata as semantics.
- Bumped the summary cache schema for source-empty overwrite summaries.
  Verified with `py_compile` for `analysis/interprocedural_summary.py`; all
  six reported repro variants pass: TV2C648 P1 x86/x64/armv7/aarch64 now
  produces no sources, and TV2R323 UE Development/DebugGame now produces only
  `dfb_source_C.ret`. A wider C64x P1 probe was interrupted after 30 adjacent
  cases had passed, including TV2C648 through x86/x64/armv7 and the first
  three aarch64 adjacent cases.

- 2026-07-12: Tightened late thunk scalar post-memory fallback for fused
  overwrite cases without adding ABI return/argument semantics. When a
  post-call observed memory field already has a source-bearing summary write
  for the same output range with a different source label, the late thunk
  scalar materialization now yields instead of adding a competing carry edge
  from the pre-call field. This keeps later preservation through observed
  storage transitions, but prevents older field contents from being resurrected
  after a precise source-marker or summary overwrite. The repair is based on
  post-call memory storage, summary edge provenance, source labels already
  reaching predecessor nodes, and architecture-aware range overlap; it does
  not use case IDs, helper names, expected labels, fixed offsets, ABI roles, or
  signature metadata as semantics.
- Bumped the summary cache schema for the guarded late thunk fallback.
  Verified with a focused local probe for TV2C649 P0 x86/x64/armv7/aarch64;
  all four variants now produce only `dfb_source_A.ret`. An adjacent x86/x64
  C646-C649 sweep preserved C646=`dfb_source_A.ret`,
  C647=`dfb_source_B.ret`, C648=no sources, and
  C649=`dfb_source_A.ret`.

- 2026-07-12: Rebalanced metadata source-pointer marker writes as fallback
  evidence instead of letting them dominate observed callsite dataflow. For
  computed calls, marker writes now yield when a latest source-bearing register
  scalar prepared for that same callsite has a different label, but
  source-bearing memory snapshots do not suppress marker writes because those
  snapshots are precisely the field contents a marker-backed write may
  overwrite. Marker write opcodes are also treated as fallback when deciding
  whether later precise computed-memory writes may replace an existing
  post-call memory input. This repairs fused callback/write cases where an
  older marker source was resurrected after a later scalar field write, while
  preserving virtual field overwrite cases where marker evidence is the
  precise observed storage transition. The repair uses callsite storage,
  source labels, register-vs-memory observed storage class, and
  architecture-aware memory overlap; it does not use case IDs, helper names,
  expected labels, fixed offsets, ABI roles, or signature metadata as
  semantics.
- Bumped the summary cache schema for metadata marker fallback rebalancing.
  Verified with `py_compile`, a focused probe covering TV2C621 P0/P1 x64,
  TV2R305 UE DebugGame, TV2R323 UE DebugGame, and TV2C649 P0
  x86/x64/armv7/aarch64, and an adjacent C646-C649 sweep across P0/P1
  x86/x64/armv7/aarch64; all 32 adjacent cases passed.

- 2026-07-12: Refined computed-call fallback writes around materialized
  observed memory transitions. Metadata source-pointer marker writes may now
  materialize a concrete prior memory target even when a different
  source-bearing selector scalar is prepared for the same computed call; that
  selector conflict still suppresses ordinary post-call marker writes. The
  late adjacent-source field-write pass also requires `CALL_POST_OBSERVED_MEMORY`
  candidates to belong to the same callsite it is summarizing, so an earlier
  unresolved callback cannot claim a later callback's post-state merely because
  both use the same concrete base pointer. The repair is based on low-pcode
  callsite storage, observed post-memory identity, source reachability, and
  architecture-aware memory ranges; it does not use case IDs, helper names,
  expected labels, fixed offsets, ABI roles, or signature metadata as
  semantics.
- Bumped the summary cache schema for the computed-call fallback refinement.

- 2026-07-12: Added affine observed-address matching for direct helper
  field/lane reads backed by prior helper writes. When a callee load address
  and an earlier callee store address are both affine over observed callsite
  storage, the direct pointer-field read resolver now maps those terms into
  caller expressions, requires the non-source address terms to match, and uses
  the latest single-label source-bearing value input from the matching writer.
  This covers register, stack, widened register-carrier, and indexed lane
  forms without adding ABI argument/return semantics or helper/case-specific
  names. The guard stays narrow: ambiguous labels, source-tainted address
  terms, non-matching affine expressions, and mismatched observed input widths
  are rejected.
- Verified with `py_compile`; focused TV2C652 probes across P0 x86/armv7 and
  P1 x86/armv7/aarch64 all produce `dfb_source_C.ret`; expected validation
  passes for TV2C652 x86 and P1 aarch64; adjacent x86 checks for TV2C650 and
  TV2C648 preserved their prior source sets; DFB001 PE_x64 remains PASS.

- 2026-07-14: Refined dynamic register-backed memory overwrite handling for
  fused TArray-style stores and later indexed reads. Latest same-base dynamic
  stores may displace stale exact-subrange edges only when their value
  subrange maps back to the sink-sized read and no same-base zero write proves
  a disjoint neighbor field. Wide dynamic subrange propagation now rejects
  same-instruction store nodes that carry conflicting observed address terms,
  but it does not require exact affine-constant equality once Low P-code has
  resolved the same dynamic storage identity and the extracted value subrange
  has a single source label. This keeps neighbor-field writes from leaking
  through realloc paths while preserving fused/indexed overwrites where the
  resolved pointer slot, source subrange, and observed storage transition are
  precise. The repair is based on low-pcode address expressions, observed
  memory storage identities, source-label reachability, and architecture-aware
  ranges; it does not use case IDs, helper names, expected labels, fixed
  offsets, ABI roles, or signature metadata as semantics.
- Bumped the summary cache schema for the dynamic overwrite refinement.
  Verified with `compileall` and a fresh-cache scoped UE probe covering
  TV2R202, TV2R301, TV2R329, TV2R315, and TV2R311 in DebugGame and
  Development; all ten focused checks passed.

- 2026-07-14: Added packed observed-storage subrange summaries for fused
  aggregate-producing helpers. Auto summaries now preserve byte lanes when a
  primary observed output is assembled from multiple observed inputs, and
  caller-side repair materializes only the requested lane through exact affine
  store/load relations or byte-aligned register extraction shifts. This
  restores struct-return lane rewrites without treating the whole output
  storage as tainted by every packed input, and without case IDs, helper names,
  expected labels, fixed offsets, ABI roles, or signature metadata as
  semantics.
- Bumped the summary cache schema for packed observed-storage subranges.
  Verified with `py_compile`, `compileall`, the four reported TV2C658 P0/P1
  x64/aarch64 scoped roots, adjacent TV2C658 P0/P1 x86/armv7 scoped roots,
  and a checked-in DFB001/002/034/048/053 smoke across sample architectures.

- 2026-07-14: Added late pruning for stale wide load inputs shadowed by
  loop-carried narrow stores. Sink-reaching loads now drop older conflicting
  whole-range memory predecessors when a later same-object narrow store is
  carried through a loop whose observed bound covers the loaded width. This
  handles bytewise payload copies that overwrite decoy words without treating
  every partial write as a full overwrite. The guard requires matching
  architecture-aware memory identity, a single source label on the narrow
  overwrite, a CFG backedge, and a loop-body bound matching the load width; it
  does not use case IDs, helper names, expected labels, fixed offsets, ABI
  roles, or signature metadata as semantics.
- Verified with `compileall`, the four reported TV2C659 P0 scoped roots across
  x86/x64/armv7/aarch64, and a checked-in DFB001/002/080 smoke across sample
  architectures.

- 2026-07-14: Added late pruning for shadowed memory inputs after a precise
  selected-field summary write. When a sink-reaching load-range or call-post
  observed memory snapshot has a latest single-label summary memory write that
  directly covers the target byte range, older conflicting load-overlap and
  summary-memory predecessors for that same observed memory target are removed.
  This handles fused aggregate-copy followed by selected-field overwrite forms
  without treating whole aggregates as overwritten and without using case IDs,
  helper names, expected labels, fixed offsets, ABI roles, or signature
  metadata as semantics.
- Verified with `py_compile`, the reported TV2C660 P1 x86 and armv7 scoped
  roots (`dfb_source_A.ret` only), and a checked-in DFB001/002 smoke across
  sample architectures.

- 2026-07-14: Refined metadata source-pointer fallback writes for unavailable
  thunk/helper bodies. When boundary metadata exposes multiple source markers
  and Low P-code shows multiple disjoint sink-reaching field reads under the
  same observed pointer storage, the fallback now maps markers to fields by
  observed byte-lane order instead of applying the first marker to every field.
  Broad fallback writes are split into exact sink-reaching subranges when those
  subranges contiguously cover the observed container, and later metadata
  fallback writes are blocked from overwriting already sourced overlapping
  memory. This preserves convention-free behavior: the repair uses discovered
  boundary-provider markers, observed memory ranges, sink reachability, and
  architecture-aware storage sizes, not ABI roles, parameter names, case IDs,
  helper names, expected labels, or fixed offsets.
- Bumped the summary cache schema for metadata source-pointer subrange
  fallback semantics. Verified with `py_compile`, `compileall`, and the
  reported TV2C666 P0/P1 x64 scoped roots; both roots now produce
  `dfb_source_A.ret` and `dfb_source_B.ret` with no `dfb_source_C.ret`.

- 2026-07-14: Tightened computed-call and post-call memory handling after the
  Suite09/10 cycle-02 regression report. Indirect call resolution no longer
  promotes a memory-loaded target to the only stack function-pointer-looking
  value unless that function pointer is actually carried on the target value;
  unresolved computed calls therefore fall back to observed dataflow summaries
  instead of optional metadata. Source-bearing memory preservation across an
  empty call-post placeholder is disabled because an empty post-call memory
  node is not evidence that prior source storage survived the call. Added a
  same-object/latest-source fallback for unresolved computed field readers and
  a late consistency pass that propagates source-bearing summary facts across
  duplicate synthetic `LOAD_RANGE` versions with identical address and storage.
  The repair uses Low P-code graph facts, architecture-aware storage ranges,
  source labels from boundary providers, and sink reachability; it does not use
  case IDs, helper names, fixed offsets, ABI roles, parameter names, or expected
  source labels as semantics.
- Verified with `compileall` and fresh-cache focused validation of the seven
  reported cycle-02 failing scopes: TV2C606 x86, TV2C624 armv7/aarch64,
  TV2C636 aarch64, TV2C632 x86, TV2C611 x64, and TV2R303 aarch64. All seven
  now validate with only `dfb_source_A.ret` and no reported forbidden sources.
  Bumped the summary cache schema for the computed-call and call-post memory
  semantics change.

- 2026-07-14: Repaired the Suite09/10 cycle-03 regression cluster in computed
  call and post-call memory summaries. Post-call memory redirection now refuses
  to carry a prior source version across an intervening non-boundary call that
  observed overlapping memory, preventing stale virtual/field values from
  bypassing later calls. Late unresolved computed pointer writes now require
  narrowed callee/write support instead of using a latest-source fallback, which
  avoids stack callback false positives. Redirected summary memory reads can
  attach the precise source-bearing memory version when a later summary register
  read consumes an otherwise empty post-call memory snapshot. Default unresolved
  adjacent-source field writes remain gated for stack-like cases, but are
  allowed for source-clean function-pointer table dispatch into a concrete heap
  allocsite when observed call-pre storage, source labels, pointer identity, and
  sink-reaching memory ranges select a single field. The repair uses Low P-code
  graph facts, architecture-aware storage ranges, boundary-provider source
  labels, and optional function-pointer metadata only as a dispatch-context
  hint; it does not use case IDs, helper names, expected labels, fixed offsets,
  ABI roles, parameter names, or signatures as semantics.
- Bumped the summary cache schema for the computed-call/post-call memory
  semantics change. Verified with `py_compile`, `compileall`, and fresh-cache
  focused validation of the ten reported cycle-03 non-PASS roots: TV2C649
  x86/armv7/aarch64 P0, TV2C604/TV2C614/TV2C615 aarch64 P0, TV2C664
  x86/armv7 P1, TV2C622 aarch64 P1, and TV2R321 UE DebugGame. All ten now
  validate with the expected sources and no forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-04 computed callback/field
  overwrite regression cluster without adding case-specific semantics. Carry
  post-memory snapshots now include redirected prior-source edges in the carry
  class, and late cleanup repairs carry-only post-call field snapshots and
  summary field reads when a latest prior precise summary write covers the same
  storage range with no intervening write. Unresolved adjacent-source callback
  writes now skip calls with concrete function-pointer callee evidence, but can
  materialize a later unresolved overwrite from observed pointer/source/write
  facts and redirect consumers to the newer post-call field. Ambiguous
  function-pointer target sets no longer overwrite an existing precise field
  write with a conflicting source unless the overwrite is uniquely supported.
  ARM/Thumb function constants are normalized before selector evaluation. The
  repair remains convention-free: it uses Low P-code dataflow, source labels,
  architecture-aware memory ranges, and optional function-pointer constants as
  dispatch hints only, not ABI roles, parameter names, case IDs, helper names,
  expected labels, or fixed offsets.
- Bumped the summary cache schema for the carry-snapshot and ambiguous-target
  summary semantics. Verified with `py_compile`, `compileall`, and fresh-cache
  focused validation of the seven reported cycle-04 failing scopes: TV2C622
  P0 x86, TV2C633 P0 x86/P1 x86/P1 x64/P1 armv7, TV2R305 UE DebugGame, and
  TV2R310 UE DebugGame. All seven now validate with expected sources and no
  forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-03 stale post-call memory
  regression cluster without adding test-specific source semantics. Observed
  summary memory write/copy edges that connect caller-local storage are now
  mirrored into the caller function graph as well as the composed program graph,
  so later caller-local read selection sees source-bearing post-call memory
  versions instead of falling back to older pre-call stores. Redirected summary
  memory reads now prune the stale predecessor edge when the replacement memory
  version has a non-carry source-bearing summary input, covers the same
  architecture-aware range, and the old labels conflict with the replacement
  labels. Selected-pointer output memory reads are also treated as precise
  same-call inputs when their selected storage/range covers the target, allowing
  them to shadow generic loaded-pointer expression reads without widening whole
  aggregates. The repair uses Low P-code graph facts, observed storage ranges,
  summary provenance, and boundary-provider source labels; it does not use case
  IDs, helper names, expected labels, fixed offsets, ABI roles, parameter names,
  or signatures as semantics.
- Bumped the summary cache schema for the caller-local summary edge and stale
  redirected-read semantics. Verified with `py_compile`, `compileall`, a
  checked-in fresh-cache DFB001/DFB002/DFB040/DFB053/DFB092 smoke, and
  fresh-cache focused validation of the eleven reported failing scopes:
  TV2C618 P0/P1 across x86/x64/armv7/aarch64, TV2C652 P0 aarch64, TV2R335 UE
  Development, and TV2R305 UE DebugGame. All eleven now validate with expected
  sources and no forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-02 fused stale-copy/selected-field
  regressions without adding case-specific source semantics. Later metadata
  marker calls may now refresh an existing same-label fallback marker on the
  same concrete observed field when the prior source-bearing inputs are only
  earlier metadata fallback writes; this preserves the latest observed write
  through later same-pointer cleanup instead of leaving only a stale earlier
  marker. Source-empty pointer-memory overwrites no longer shadow source-bearing
  summary memory writes solely because the concrete output size matches after
  both map to the same caller slot; cross-identity shadowing now requires
  shared observed-address identity or overlapping observed outputs. The repair
  uses Low P-code storage/dataflow facts, architecture-aware ranges, and
  boundary-provider labels only, and does not use case IDs, helper names,
  expected labels, fixed offsets, ABI roles, parameter names, or signatures as
  semantics.
- Bumped the summary cache schema for the metadata marker refresh and
  source-empty overwrite pruning semantics. Verified with `py_compile`,
  `compileall`, fresh-cache focused validation of the two reported failing
  scopes (TV2C666 P1 x64 and TV2R335 UE Development), and a fresh-cache
  16-scope family check covering all TV2C666 arch/config variants plus
  TV2R332/TV2R334/TV2R335/TV2R336 UE Development and DebugGame. All checked
  scopes now validate with expected sources and no forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-03 fused computed-dispatch,
  indexed-helper, and source-empty overwrite regression cluster without adding
  case-specific source semantics. Unresolved computed callback field writes now
  allow exact stack/frame object fields when a single concrete pointer, a
  single adjacent source scalar, and a sink-reaching target field identify the
  overwrite; register reuse in computed-call target checks is treated as
  versioned graph identity instead of storage-name dependency. Ambiguous field
  candidates now prefer the unique sink-reaching memory version before using
  relative-offset tie breakers, which lets later callback overwrites displace
  stale fields. Materialized computed-call metadata marker post-memory targets
  may overwrite an older source-bearing field rather than being blocked by the
  stale overlap itself. Callsite affine recovery now runs same-instruction
  scaled `SUBPIECE` repair before generic pass-through, fixing masked/indexed
  helper field offsets when a stale memory predecessor is also present. Concrete
  source-empty `STORE_VAL` nodes now prune cross-function summary source
  predecessors attached to that same store, so later loaded-pointer reads see
  the observed overwrite. The repair remains convention-free: it uses Low
  P-code storage/dataflow, architecture-aware ranges, boundary-provider labels,
  and optional metadata markers as boundary facts only; it does not use case IDs,
  helper names, expected labels, fixed offsets, ABI roles, parameter names, or
  signatures as semantics.
- Bumped the summary cache schema for the computed callback, affine subpiece,
  metadata marker overwrite, and source-empty pruning semantics. Verified with
  `py_compile` and fresh-cache focused validation of the eleven reported
  failing scopes: TV2C649 P0 x86/x64/armv7/aarch64, TV2C661 P0 x86, TV2C624 P0
  armv7/aarch64, TV2C614 P0 aarch64, TV2C636 P0 aarch64, TV2R340 UE
  Development, and TV2R305 UE DebugGame. All eleven now validate with expected
  sources and no forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-04 callback field false-positive
  cluster without adding case-specific semantics. Metadata source-pointer
  fallback writes now stand down when a computed call has concrete local
  function-pointer evidence whose selected callback summary does not write the
  same sink-reaching field; selected callback write support includes both
  observed scalar-to-memory writes and source-bearing source-to-memory writes
  matched by relative memory ranges. Unresolved adjacent-source computed-call
  field synthesis now stands down when concrete local function-pointer summary
  evidence is available, and also refuses to add a conflicting source beside an
  existing metadata marker on the same target field. Post-call memory to later
  read propagation now requires containment or same-start subrange compatibility
  instead of any overlap, avoiding sibling-field bleed from wider stack slots.
  The repair uses Low P-code dataflow, observed storage ranges, selected
  function-pointer summary facts, and boundary-provider marker facts only; it
  does not use case IDs, helper names, expected labels, fixed offsets, ABI
  roles, parameter names, or signatures as semantics.
- Bumped the summary cache schema for the metadata marker, adjacent computed
  field, and post-call memory range semantics. Verified with `py_compile`,
  `compileall`, and focused direct validation of the twelve reported failing
  Suite10 scopes: TV2C604 P0 x86/x64, TV2C615 P0 x86/x64/armv7 and P1
  x86/armv7, TV2C626 P0 x86/x64/aarch64, and TV2C638 P0/P1 aarch64. All twelve
  now validate with expected sources and no forbidden sources.

- 2026-07-14: Repaired the Suite09/10 cycle-05 computed callback field
  overwrite regression cluster. Unresolved computed-call adjacent-source field
  synthesis no longer treats unrelated local function-pointer evidence as a
  veto; only evidence tied to the indirect target storage suppresses the
  fallback. Precise same-call post-memory overwrites may now displace
  conflicting metadata source-pointer fallback markers. Resolved callback
  wrapper calls now materialize source-scalar-to-field post-memory writes when
  the callee low-pcode contains a computed callback wrapper, the caller has a
  concrete object pointer, a single sink-reaching field can be selected, and a
  single source label maps through either the selected callback summary tied to
  the wrapper's actual target origin or the observed adjacent-source fallback.
  The selected-summary path composes callback input/address storage through the
  wrapper's inner computed call or tail jump and excludes global/static summary
  inputs from argument-source composition, leaving global storage flows to their
  dedicated machinery. The repair uses Low P-code storage/dataflow,
  architecture-aware ranges, and optional metadata only as target-origin hints;
  it does not use case IDs, helper names, expected labels, fixed offsets, ABI
  roles, parameter names, or signatures as semantics.
- Verified with `py_compile`, `git diff --check`, and focused direct validation
  of the nine reported failing scopes: TV2C613 P0 x86/armv7/aarch64 and P1
  armv7/aarch64, TV2C624 P0 armv7/aarch64, TV2C636 P0 aarch64, and TV2R305 UE
  DebugGame. All nine now validate with expected sources and no forbidden
  sources.

- 2026-07-15: Repaired the Suite10 cycle-09 computed-call scope/completeness
  cluster without adding case-specific semantics. The Ghidra dumper now keeps
  duplicate helper entries address-aware and recognizes computed-call flow
  evidence for unresolved indirect calls. The loader preserves internal
  function identity for duplicate raw names, and the harness case-scope closure
  includes only nearby function-pointer-table targets referenced by the current
  closure instead of every address-taken function. Expected-source validation
  canonicalizes entry-suffixed generated source labels back to their stable
  boundary label. These changes use Low P-code references, function entry
  identity, structured metadata, and observed closure locality as completeness
  facts only; they do not use case IDs, helper names, expected labels, fixed
  offsets, ABI roles, parameter names, or signatures as core semantics.
- Verified with `py_compile`, `harness.design_lint`, `git diff --check`, and
  focused no-cache validation of the cycle-09 repair targets:
  TV2C649 P0 aarch64, TV2C675 across all tier0 P0/P1 x86/x64/armv7/aarch64
  variants, and TV2R340 across UE DebugGame/Development. All targeted repair
  scopes now validate with expected sources and no forbidden sources. A full
  no-cache Suite09/10 run with proposed regressions is not yet globally green:
  Suite09 reports PASS 472 / FAIL 16 / FP 0, and Suite10 reports PASS 763 /
  FAIL 79 / FP 34. Those remaining failures are recorded as residual frontier
  clusters for follow-up rather than treated as cycle-09 repair blockers.

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
