# Phase 6: External Summary Resolution / Summary Refinement

Goal: introduce a unified external summary layer for libc, POSIX, MSVCRT/UCRT,
WinAPI, and later PDB-backed APIs without weakening the V8 core invariants.

## Position In The Plan

`ResolvedExternalSummary` belongs at the start of Phase 6, before the old
`LibcSummaryProvider` idea.

Updated Phase 6 order:

```text
0. Repository hygiene: exclude generated samples/low_pcode JSON from future commits.
1. Define ResolvedExternalSummary and its provenance model.
2. Extract richer Ghidra external prototype metadata.
3. Introduce CompositeSummaryProvider.
4. Add KnownExternalEffectRegistry.
5. Implement ExternalSummaryProvider using resolved summaries.
6. Add or explicitly replace Phase 2 call_out_* edges.
7. Validate residual clusters with trusted external summaries on/off.
```

This keeps `memcpy`, `malloc`, `recv`, `ReadFile`, `HeapAlloc`, and later
PDB-backed APIs under one model instead of creating one provider per library
family.

## Why This Exists

Phase 5 automatic summaries are based on internal low-pcode observations. That
works for direct user-defined functions, but external APIs often have no body or
only a thunk/import stub in the analyzed program.

Pure observation is too weak for these cases:

```text
malloc/calloc/realloc     -> heap pointer creation or preservation
memcpy/memmove/strcpy     -> memory copy from one observed region to another
memset/bzero              -> memory fill or kill
read/recv/ReadFile/fread  -> external source writes into a buffer
write/send/WriteFile      -> external sink reads from a buffer
HeapAlloc/RtlAllocateHeap -> Windows heap allocation
GetProcAddress/LoadLibrary -> dynamic import and indirect-call hints
```

The practical answer is to trust selected external API effects, but keep that
trust outside the core graph model and make it auditable.

## Core Policy

The core remains convention-free:

```text
no arg
no return
no parameter semantics
no ABI/calling convention semantics in node or edge kinds
```

External summaries are allowed only in the summary/provider layer. They may use
prototype roles internally, but the graph receives only storage and memory
transitions such as `summary_data` and `summary_memory`.

Every external summary edge must record provenance:

```text
provider=external
effect=<effect kind>
prototype_source=ghidra|pdb|manual|none
effect_source=curated_registry|project_override
trust=<trust level>
matched_name=<canonical external name>
```

Trusted external summaries must be optional so verification can compare
trusted-summary-on and trusted-summary-off behavior.

## Ghidra's Role

Ghidra does not provide the complete data-origin summary we need. It provides
external identity and prototype metadata that can be joined with our effect
registry.

Ghidra metadata to extract:

```text
external identity:
  library/module name
  external symbol name
  original import name if available
  normalized external name
  external address/location
  import table entry
  thunk chain and final thunk target

function prototype:
  prototype string
  signature source
  calling convention name
  varargs flag
  no-return flag
  stack purge size if known
  effective signature hash

parameter metadata:
  ordinal
  name
  data type name
  data type size
  pointer depth if derivable
  storage string if Ghidra exposes it
  source type

output metadata:
  return type name
  return storage string if Ghidra exposes it
  return source type

program identity for cache keys:
  language id
  compiler spec id
  executable format
  image base
  metadata hash
```

This metadata is used to resolve external summaries. It is not used to add
calling-convention concepts to core node kinds or edge kinds.

## PDB Compatibility

The same model must accept PDB-derived prototypes later.

Current Phase 6:

```text
Ghidra import/signature metadata
  + curated effect registry
  -> ResolvedExternalSummary
```

Future Phase 7:

```text
PDB prototype/type metadata
  + curated effect registry
  -> ResolvedExternalSummary
```

Because both paths produce the same resolved object, PDB support should improve
names, types, and role binding quality without changing core slice topology.

## Data Model

### ExternalPrototype

Metadata extracted from Ghidra, PDB, or a project override.

```text
id
source
library
name
normalized_name
external_location
thunk_target
signature
signature_source
calling_convention_name
parameters[]
output
flags
confidence
metadata_hash
```

This object may contain words like parameter or calling convention because it is
metadata imported from external tools. It must not leak those names into core
graph node kinds, edge kinds, or default analysis semantics.

### KnownExternalEffect

Curated effect semantics managed by this project.

```text
id
match names/libraries
effect
role_bindings
trust_default
notes
```

Initial effect vocabulary:

```text
alloc
realloc
free
memory_copy
memory_fill
string_copy
external_read_source
external_write_sink
format_write
readonly_compare
noreturn
dynamic_symbol_lookup
library_load
```

### ResolvedExternalSummary

The join result used by the summary provider.

```text
prototype: ExternalPrototype
effect: KnownExternalEffect
role_resolution:
  role -> prototype ordinal/name/storage candidate
trust_level
provenance
cache_key
```

Only `ResolvedExternalSummary` is consumed by `ExternalSummaryProvider`.

## Registry Management

Start with a small curated registry in the repository:

```text
summaries/external/libc.yaml
summaries/external/posix.yaml
summaries/external/winapi.yaml
summaries/external/msvcrt.yaml
summaries/external/ucrt.yaml
summaries/external/project_overrides.yaml
```

Initial entries should cover only the cases used by the current residual work:

```text
malloc, calloc, realloc, free
memcpy, memmove, memset, strcpy
read, write, recv, send
fread, fwrite
HeapAlloc, HeapFree, RtlAllocateHeap, RtlFreeHeap
ReadFile, WriteFile
CopyMemory, MoveMemory, ZeroMemory, RtlCopyMemory, RtlMoveMemory, RtlZeroMemory
```

The registry should be declarative. Code should implement effect interpreters,
not one-off logic for every API name.

Example shape:

```yaml
version: 1
functions:
  - match:
      names: ["memcpy", "__memcpy_chk", "CopyMemory", "RtlCopyMemory"]
    effect: memory_copy
    roles:
      write_buffer: 0
      read_buffer: 1
      size: 2
    trust: trusted_external_prototype

  - match:
      names: ["recv", "read", "ReadFile", "fread"]
    effect: external_read_source
    roles:
      write_buffer: 1
      size: 2
    trust: trusted_external_prototype

  - match:
      names: ["send", "write", "WriteFile", "fwrite"]
    effect: external_write_sink
    roles:
      read_buffer: 1
      size: 2
    trust: trusted_external_prototype
```

Role names are registry/provider vocabulary only. They should not become core
storage names.

## Summary Edge Creation

`ExternalSummaryProvider` creates summary edges from a resolved effect and the
callsite boundary nodes.

Examples:

```text
memory_copy:
  observed memory at read_buffer
    -> summary_memory
  observed memory at write_buffer

memory_fill:
  fill value or unknown_fill boundary
    -> summary_memory
  observed memory at write_buffer

external_read_source:
  external source boundary
    -> summary_memory
  observed memory at write_buffer

external_write_sink:
  observed memory at read_buffer
    -> summary_data or summary_memory
  external sink boundary

alloc:
  allocation site boundary
    -> summary_data
  observed post-call storage with heap_ptr expression
```

The provider may use trusted prototype role positions to bind storage candidates
when the prototype is reliable. If role binding is weak, it must lower trust or
skip edge creation.

## Trust Levels

```text
observed
  Supported by internal low-pcode body evidence.

trusted_external_prototype
  External effect registry matched and Ghidra/PDB prototype metadata supports
  the role layout.

trusted_external_name_only
  External effect registry matched by name, but prototype quality is weak.
  Use only for low-risk effects or require opt-in.

project_override
  User-supplied project-specific summary.

disabled
  External summaries are not applied.
```

## Cache Key

Resolved external summaries must participate in summary cache identity:

```text
program metadata hash
external prototype metadata hash
effect registry hash
project override hash
trusted external summary mode
summary schema version
```

Changing Ghidra extraction, PDB metadata, or registry entries must invalidate
the affected summary cache.

## Verification Plan

Phase 6 verification should record trusted external summaries separately:

```text
trusted external summaries OFF:
  existing Phase 5 gate must remain stable.

trusted external summaries ON:
  DFB120 memcpy buffer
  DFB121 memmove buffer
  DFB122 strcpy buffer
  DFB123 memset partial memcpy
  POSIX read/write style cases if present
  Windows PE import-backed API cases as they are added
```

Full-testbed reporting must compare:

```text
baseline Phase 5
external summaries off
external summaries on
regressions
new passes
edge provenance samples
```

## Implementation Checklist

- [x] Stop tracking generated `samples/low_pcode` JSON outputs in future commits.
- [x] Add this Phase 6 design document to the active phase plan.
- [x] Extend Ghidra dumper metadata for external prototypes and role-binding inputs.
  - Schema v5 adds `indices.external_prototypes_by_entry` and
    `indices.external_prototypes_by_name`.
  - Each prototype records Ghidra source, library/name/normalized name,
    external location, thunk target, signature/prototype text, signature
    source, calling convention name, parameter metadata, output metadata,
    flags, and metadata hash.
  - These fields are summary-resolution metadata only; the core graph still
    must not interpret parameters, returns, or calling conventions.
- [x] Add `ExternalPrototype` loader model.
  - `frontend.external_prototype` parses schema v5 prototype indices and keeps
    a legacy/call-target fallback for older JSON.
- [x] Add `KnownExternalEffectRegistry` loader.
  - Initial JSON registry covers libc allocation/memory effects, POSIX
    read/write effects, and WinAPI heap/memory/read/write effects.
- [x] Add `ResolvedExternalSummary` resolver.
  - `analysis.external_summary` resolves prototypes against the curated
    registry, binds roles when prototype parameter metadata exists, records
    trust level, provenance, and cache keys.
- [x] Add `CompositeSummaryProvider`.
- [x] Move current automatic summaries behind the composite provider.
- [x] Add `ExternalSummaryProvider` for alloc/realloc/free boundary effects.
  - Allocation pointer expressions still come from the existing low-pcode call
    boundary materialization. Phase 6 records resolved external lifetime
    provenance without adding argument/return semantics to the core graph.
- [x] Add `ExternalSummaryProvider` for memory copy/fill/string copy effects.
  - Provider resolves Ghidra prototype storage to observed callsite storage and
    adds first-class `call_out_mem` edges with external provenance.
  - DFB122 `strcpy` is now covered across all architecture/platform roots.
  - DFB120/DFB121 are not external-summary cases in the current binaries
    because the compiler lowered `memcpy`/`memmove` into ordinary low-pcode
    load/store ranges. They are now covered by byte-range overlap memory
    modeling in the core low-pcode builder.
- [x] Add `ExternalSummaryProvider` for read/write source/sink effects.
  - Infrastructure is present for POSIX/WinAPI read/write style effects.
  - Dedicated runtime test coverage is still pending because the current
    DFB130/DFB131 shared-import cases are benchmark helpers, not registry-known
    libc/POSIX/WinAPI functions.
- [ ] Add summary cache invalidation for external prototype and registry hashes.
  - Directory fingerprints already include per-file metadata hashes.
  - Persistent external edge caching is not added yet, so registry hash
    invalidation remains a future cache item.
- [ ] Verify trusted external summaries on/off across residual clusters.

## Verification Log

| Date | Command | Result | Notes |
| --- | --- | --- | --- |
| 2026-06-21 | `python3 -m py_compile frontend/external_prototype.py frontend/low_pcode_loader.py analysis/external_summary.py scripts/lowpcode_json_dumper.py` | PASS | Loader, resolver, registry, and dumper syntax |
| 2026-06-21 | synthetic schema v5 `memcpy` prototype resolver smoke | PASS | Resolved `memory_copy` with `trusted_external_prototype` and bound roles |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase6_external_infra_smoke expected --cases case_DFB001 case_DFB002` | PASS 12 | Existing Phase 1 dataflow path unchanged |
| 2026-06-21 | `python3 scripts/run_ghidra_headless_lowpcode.py` | PASS | Re-extracted schema v5 low-pcode JSON with Ghidra headless: 848 function JSON files, 22 manifests, all observed batches `fail=0` |
| 2026-06-21 | schema v5 metadata validation script over `samples/low_pcode` | PASS | 848/848 files at schema v5, 36,461 external prototype entries, 0 missing prototype metadata hashes, 7,236 registry matches |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode/linux_amd64/win_core output/v8_phase6_external_probe expected --cases case_DFB122 case_DFB123` | PASS 2 | Local probe: external `strcpy` summary fixes DFB122 and keeps DFB123 stable |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase6_external_libc_buffer expected --cases case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 12 / FAIL 12 | DFB122 and DFB123 PASS across all roots; DFB120/121 remain inline-copy residuals with no surviving external call target |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase6_phase5_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Composite provider and external edge injection caused no regression in Phase 5 gate |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase6_external_import_probe expected --cases case_DFB130 case_DFB131` | FAIL 12 | Expected residual: DFB helper imports are not registry-known external APIs yet |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_memory_overlap_libc_buffer expected --cases case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 24 | Byte-range overlap memory modeling covers compiler-lowered DFB120/121 and keeps external DFB122/DFB123 stable across all roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_memory_overlap_phase5_gate expected --cases case_DFB001 case_DFB002 case_DFB024 case_DFB025 case_DFB026 case_DFB027 case_DFB030 case_DFB031 case_DFB050 case_DFB056 case_DFB057 case_DFB058 case_DFB059 case_DFB152` | PASS 84 | Existing Phase 5 summary gate remains stable after byte-range overlap edges |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_memory_overlap_risky expected --cases case_DFB020 case_DFB021 case_DFB022 case_DFB023 case_DFB034 case_DFB035 case_DFB040 case_DFB041 case_DFB042 case_DFB043 case_DFB044 case_DFB045 case_DFB046 case_DFB047 case_DFB048 case_DFB049 case_DFB053 case_DFB055 case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 92 / FAIL 40 | Memory API cluster passes; remaining residuals are outparam, bitfield, partial-overwrite, large-struct, and deep-field cases |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_outparam_closed_v2 expected --cases case_DFB021 case_DFB022 case_DFB023` | PASS 18 | Source-to-memory outparam and double-pointer observed memory writes pass across all roots |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_callout_libc_buffer expected --cases case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 24 | External and compiler-lowered buffer flows remain stable after `call_out_mem` promotion |
| 2026-06-21 | `.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py samples/low_pcode output/v8_phase2_risky_after_callout expected --cases case_DFB020 case_DFB021 case_DFB022 case_DFB023 case_DFB034 case_DFB035 case_DFB040 case_DFB041 case_DFB042 case_DFB043 case_DFB044 case_DFB045 case_DFB046 case_DFB047 case_DFB048 case_DFB049 case_DFB053 case_DFB055 case_DFB120 case_DFB121 case_DFB122 case_DFB123` | PASS 104 / FAIL 28 | DFB021/DFB023 outparam residuals closed; remaining failures are bitfield, partial-overwrite, large-struct, and deep-field clusters |
