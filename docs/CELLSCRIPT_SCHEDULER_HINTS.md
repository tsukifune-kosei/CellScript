# CellScript Scheduler Hints

**Status**: production metadata contract for CellScript 0.12.

CellScript emits scheduler-facing metadata for CKB. These hints are not hidden
comments; they are part of action metadata and the Molecule scheduler witness.

## Exposed Fields

Each action can expose:

- effect class
- `parallelizable`
- `touches_shared`
- estimated cycles
- scheduler-visible input/output/cell-dep accesses
- binding hashes for conflict grouping

Mutating shared state sets `parallelizable = false` and records mutate-input and
mutate-output accesses.

## Consumption Boundary

The compiler and metadata make the hints available. Production schedulers,
wallets, builders, and devnet acceptance must consume them according to their
policy.

For 0.12, the supported policy boundary is:

- admission tooling may group or reject actions based on shared touch sets
- wallet/build tooling may use estimated cycles for budget summaries
- acceptance reports must preserve scheduler witness evidence for bundled
  examples

Consensus-level scheduler enforcement is a chain/runtime concern and is not
claimed by the compiler alone.

## Policy Report

Use:

```bash
cellc scheduler-plan contract.cell --target-profile ckb
```

The report consumes action scheduler hints and emits:

- actions that require serial admission because `parallelizable = false`
- shared touch-set conflicts that must not run in parallel
- per-action estimated cycles
- total and max-action estimated cycle summaries

This command is a policy consumer for tooling and CI. It does not claim
consensus-level scheduling enforcement by itself.
