# Recall-First Candidate Refinement Design

Status: adopted, 2026-08-17

## Decision

The convention-free backward-slice core is a conservative candidate generator.
Its primary correctness obligation is to include every real source that can
explain the observed sink. Extra source candidates do not fail the core recall
gate; they remain explicit precision evidence for a later refinement layer.

This replaces the previous exact-source primary gate while preserving all
forbidden-source observations and strict negative controls.

## Deterministic Validation Policy

For a positive case:

```text
RECALL_PASS = expected_sources is a subset of candidate_sources
PRECISION_CLEAN = candidate_sources minus expected_sources is empty
```

`RECALL_PASS` determines the primary PASS/FAIL verdict. A positive case that
recalls every expected source but also emits any source outside the expected
set is reported as `PASS + REFINEMENT_PENDING`. Oracle `forbidden_*` matches
remain a named, high-value subset of those candidates.

For an explicit negative case (`expected_no_sources: true`):

```text
NEGATIVE_PASS = candidate_data_sources and candidate_control_sources are empty
```

Any observed source fails a negative case, including a label not listed in the
oracle. This prevents an empty expected set from passing vacuously.

## Result Layers

```text
candidate_sources    conservative backward-slice output
confirmed_sources    future refiner evidence: feasible source-to-sink flow
rejected_sources     future refiner evidence: infeasible or killed flow
unresolved_sources   candidates not decided within the refinement budget
```

The current implementation emits every observed source as a candidate and
marks every source outside the expected set as a precision candidate. Oracle
`forbidden_*` matches are retained as a named subset, not the only way a new
candidate can enter the refinement backlog.
Confirmed/rejected classification belongs to a later `CandidateRefiner` and is
not inferred from expected labels.

## Refinement Boundary

```text
BoundaryProvider
    -> ConservativeBackwardSlice
    -> CandidateRefiner
         -> KillAndOverwriteRefiner
         -> ContextSensitiveForwardTaintRefiner
         -> BoundedPathFeasibilityRefiner
```

A forward traversal over the same over-approximate slice graph is not enough:
every backward candidate already has such a graph path. A useful refiner needs
additional CFG, version/kill, call-context, or branch-feasibility evidence.
Solver work is bounded and optional; an exhausted budget produces `unresolved`,
not a guessed rejection.

## Design Invariants

- no arg, no ret, convention-free
- no ABI parameter or return semantics
- no case IDs, helper names, expected labels, or fixed test offsets in core
- source/sink interpretation remains in BoundaryProvider/wrapper layers
- forbidden labels are validation probes, never graph-construction hints
- precision telemetry cannot change the recall objective
- negative controls remain hard gates
- NetworkX and optimized traversal paths must emit the same candidate set

## Harness Outputs

- `failure_report_v2.json`: primary verdict plus recall/precision fields
- `precision_report.json`: positive cases requiring later refinement
- `summary.json`: PASS/FAIL, `PRECISION_PENDING`, and negative failures
- `gate.json`: recall completeness, negative-control cleanliness, and precision
  cleanliness as separate facts

The automated engine-repair loop responds to recall regressions, crashes, and
negative-control failures. It does not modify the backward-slice core merely to
remove positive precision candidates.

## Next Layer

After the Suite09/Suite10 recall-first case-author loop demonstrates repeated
first-pass green results:

1. define a `CandidateRefiner` protocol and evidence schema
2. implement kill/overwrite and call-context checks first
3. add forward taint over CFG and memory versions
4. add bounded path feasibility only for unresolved branch-sensitive candidates
5. keep the conservative candidate set available in every final report

OLLVM remains a later adversarial overlay after the general refiner is stable.
