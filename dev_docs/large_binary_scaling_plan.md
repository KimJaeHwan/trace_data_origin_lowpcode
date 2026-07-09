# Large Binary Scaling Plan

Status: active design, 2026-07-09

This document records the scaling strategy for Engine11 before testing real
game-sized binaries. The current Suite09/Suite10 engine is intentionally a
convention-free low-pcode backward-slice core. Large-binary work must preserve
that model instead of adding ABI, benchmark, helper-name, or source/sink
shortcuts.

## Goal

Prepare the low-pcode backward-slice engine for binaries where the limiting
factor is no longer one case or one function, but whole-program size:

- many low-pcode JSON files
- thousands of functions
- very large UE-style functions
- high callsite density
- repeated regression cycles over mostly unchanged samples
- memory pressure from composed graphs and parsed JSON

The target is not merely to make Suite09/Suite10 faster. The target is to make
the same convention-free analysis usable when a user points it at a large
binary without benchmark source/sink naming conventions.

## Non-Goals

- Do not add ABI-specific argument or return rules.
- Do not encode DataFlowBench, TV2, UE, OBF, source, sink, or helper names in
  the analysis core.
- Do not make OLLVM symbolic deobfuscation part of the core backward-slice
  optimization pass. OLLVM remains a later adversarial layer.
- Do not replace NetworkX with rustworkx until the graph operation boundary and
  performance baseline are clear.
- Do not accept false positives as a speed tradeoff.

## Current Evidence

Recent profiling over Suite09/Suite10 showed:

- cold `ProgramSliceGraph` build time dominates query traversal time
- hot functions are large low-pcode functions, not individual opcodes
- opcode-level profiling is useful, but pcode op processing is not the main
  current bottleneck
- call-boundary materialization is expensive in UE-style functions, but the
  cost is distributed across many callsites rather than one outlier
- post-processing scans improved when grouped by function before traversing the
  composed graph

This points toward structural scaling work: avoid unnecessary whole-program
work, reuse parsed/indexed artifacts, parallelize independent function builds,
and isolate graph backend choices.

## Scaling Invariants

- Boundary providers may identify requested source/sink roots, but core graph
  semantics remain marker-agnostic.
- The core may use Ghidra metadata as structural evidence, not as a calling
  convention oracle.
- Any demand-driven build must have a whole-program fallback.
- Any cache must be content-addressed and schema-versioned.
- Parallel and cached builds must be deterministic: same inputs produce the
  same graph nodes, edges, reports, and validation result.

## Optimization Tracks

### 1. Scale Telemetry

Before changing more algorithms, collect stable scale metrics in each harness
run:

- input bytes and file count
- function count
- instruction and pcode counts
- graph node and edge counts
- callsite count
- per-stage build time
- top hot functions and hot build steps
- cache hit/miss counters
- optional peak RSS when available

The existing profiler already reports function and stage timing. The next step
is to aggregate those into a compact scale profile that can be compared across
large runs.

### 2. Demand-Driven Program Closure

For game-scale binaries, building every function for every query will not
scale. Add a planner that can build a conservative function closure from query
roots:

- start from requested sink or target functions supplied by a boundary provider
- include known caller/callee neighbors needed for summary connectivity
- include unresolved or metadata-incomplete regions conservatively
- fall back to full-program composition when the closure is not trustworthy

This remains convention-free because the planner selects code regions, not
argument or return semantics.

### 3. Persistent Parsed/Index Cache

Large low-pcode JSON parsing and metadata indexing should be cached by content
hash:

- dumper schema/version
- engine cache schema
- program language id
- JSON path, size, mtime, and content fingerprint
- extracted architecture metadata
- per-function instruction/pcode indexes

The cache should live outside tracked sample JSON and be invalidated whenever
the dumper or engine schema changes.

### 4. Parallel FunctionGraph Build

FunctionGraph construction is mostly independent before program composition.
Add a deterministic parallel build path:

- process or worker pool per function chunk
- serial fallback for debugging
- stable ordering during graph merge
- memory budget controls for very large binaries
- no shared mutable graph writes from workers

The first target is reducing cold build wall time without changing graph
semantics.

### 5. Graph Backend Boundary

NetworkX has been useful for correctness and iteration speed, but game-scale
graphs may require a faster backend. Introduce a narrow graph adapter only
after the operation set is known:

- add/remove node and edge
- predecessor/successor traversal
- attribute lookup
- induced traversal for backward slice
- deterministic export

Then benchmark NetworkX against rustworkx on real engine operations. A backend
swap must be invisible to report output and expected validation.

### 6. Lazy Heavy Edge Materialization

Call-boundary and summary edges are semantically sensitive. Defer this track
until telemetry, caching, and parallel function builds are in place.

Possible later work:

- materialize post-call storage edges only for relevant storage families
- avoid duplicate boundary candidates across equivalent observed storage
- keep exact whole-program fallback and full Suite09/Suite10 regression gate

## Phase Order

1. Add scale-profile aggregation to harness reports.
2. Run full Suite09/Suite10 with scale-profile enabled and record baseline.
3. Add persistent parsed/index cache behind an opt-in flag.
4. Add deterministic parallel FunctionGraph build behind an opt-in flag.
5. Compare NetworkX and rustworkx behind a graph adapter prototype.
6. Add demand-driven function-closure planning with full-program fallback.
7. Revisit lazy call-boundary materialization only after the above is stable.
8. Bring Suite12/OLLVM back as an adversarial overlay, not as the core
   performance design driver.

## Regression Gates

Core optimization changes require:

- Python compile check over engine packages
- Suite09/Suite10 local-samples with proposed regressions included
- zero false positives
- no new expected/manifest/generated-sample edits as a way to pass
- before/after performance profile saved with the commit notes

Suite12/OLLVM remains useful as a stress signal, but it should not force the
backward-slice core into symbolic path reasoning or architecture-specific
calling convention behavior.

## Immediate Next Implementation

The next concrete patch should be scale telemetry, not another semantic
fallback:

1. aggregate existing build-profile fields into a per-run scale summary
2. include top stage totals and hot function families
3. make the report cheap when profiling is disabled
4. verify Suite09/Suite10 remains green

After that baseline exists, decide between persistent parsed/index cache and
parallel FunctionGraph build based on measured large-run costs.
