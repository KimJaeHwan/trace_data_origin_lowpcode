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

## Current Focus

Phase 5: Interprocedural Skeleton + Bottom-up Auto Summary.

Next engineering step:

```text
Expand observed-storage summaries beyond global read/write while preserving
the convention-free core model.
```
