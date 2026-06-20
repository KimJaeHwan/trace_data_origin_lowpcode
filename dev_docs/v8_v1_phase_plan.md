# V8 / New V1 Phase Plan

Source design snapshot: `dev_docs/v8_v1_design.md`

Original imported document:
`/Volumes/DO/00_gitProject/01_tdo/999_tmp_dir/v8_V1설계문서.md`

This directory tracks the V8 / New V1 development line. Unlike the legacy
v5/v6/v7 prototype files, V8 is developed as an independent package structure.

## Core Invariants

- Low P-code is the source of truth.
- High P-code and decompiler output may only be used as hints.
- Build the graph before selecting a backward-slice target.
- Core graph nodes and edges must not encode calling convention concepts.
- Function calls are modeled as observed storage transitions.
- Summary edges preserve interprocedural connectivity; inline expansion only
  improves precision.
- Global storage is program-wide and may become a source boundary only by rule.
- Heap storage is allocation-site based transfer storage by default.

## Forbidden Core Vocabulary

The core package, analysis core classes, node kinds, and edge kinds should not
introduce these concepts as semantic model names:

```text
arg
argument
param
parameter
return
ret
cdecl
stdcall
fastcall
thiscall
Win64
SysV
ABI
CALL_RET
CALL_RESET
CALL_CLOBBER
pending_stack_args
arg0_to_ret_summary
```

DataFlowBench adapters, compatibility validators, and human-facing report
interpretation sections may still display legacy labels when required by the
test oracle.

## Phase Status

| Phase | Name | Gate | Status |
| --- | --- | --- | --- |
| 1 | Walking Skeleton | DFB001 / DFB002 PASS | Complete |
| 2 | Convention-free Call Boundary Skeleton | synthetic CALL_POST storage exists without stale dependency | In progress |
| 3 | Control Dependency | DFB010 PASS with data/control split | Not started |
| 4 | Memory + Architecture Expansion | global/heap skeleton and architecture storage expansion | Not started |
| 5 | Interprocedural Skeleton + Bottom-up Auto Summary | direct-call summary connectivity | Not started |
| 6 | Summary Refinement / Libc / Cache | composite providers and reusable summary cache | Not started |
| 7 | Symbol / PDB Overlay | optional overlay, core graph unchanged | Deferred |
| 8 | Dynamic / Agent Overlay | optional runtime overlay, core graph unchanged | Deferred |

## Phase 1 Scope

Phase 1 intentionally avoids interprocedural calls, heap precision, full global
modeling, full register aliasing, and production ARM64 support.

Required modules:

```text
core/value_id.py
core/architecture.py
core/storage.py
core/graph.py
frontend/low_pcode_loader.py
analysis/cfg_builder.py
analysis/slice_graph_builder.py
query/backward_slice.py
report/expected_validator.py
report/graph_exporter.py
```

Reusable prototype logic:

```text
_build_basic_blocks       -> analysis/cfg_builder.py
_const_from_node          -> analysis/const_propagator.py or slice builder helper
_collect_data_sources     -> query/backward_slice.py
_validate_expected_sources -> report/expected_validator.py
```

Completion criteria:

- DFB001 direct value PASS.
- DFB002 arithmetic value PASS.
- `slice_graph` and `cfg` are separate graph objects.
- Minimal graph export works.
- Text report includes edge kinds.
