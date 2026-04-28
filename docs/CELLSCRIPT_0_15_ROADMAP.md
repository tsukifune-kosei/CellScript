# CellScript 0.15 Roadmap

**Updated**: 2026-04-28

0.15 is the scoped-invariant and Covenant ProofPlan track. It builds on the
0.14 CKB semantic surface by making verifier trigger, scope, reads, coverage,
builder assumptions, and enforcement gaps explicit in source and metadata.

## Goals

1. Add a source-level scoped invariant model.
2. Add aggregate invariant primitives for common covenant-style relations.
3. Emit Covenant ProofPlan metadata for source invariants and compiler-recognized
   protocol flows.
4. Surface dangerous lock/type coverage assumptions as diagnostics.
5. Keep metadata-only invariant claims clearly separated from executable CKB
   verifier coverage.

## Implemented In This Branch

| Track | Status | Notes |
|---|---|---|
| Scoped invariant syntax | Implemented | Top-level `invariant` declarations require explicit `trigger`, `scope`, and `reads`. Supported triggers are `explicit_entry`, `lock_group`, and `type_group`; supported scopes are `selected_cells`, `group`, and `transaction`. |
| Invariant IR and metadata model | Implemented | Invariants are preserved through AST, type checking, IR, module metadata, formatting, LSP symbols, hover/completions, docs, and scoped CKB entry compilation. |
| Aggregate invariant primitives | Implemented as metadata-only | `assert_sum`, `assert_conserved`, `assert_delta`, `assert_distinct`, and `assert_singleton` are parsed, type-checked, formatted, lowered into IR metadata, and emitted into ProofPlan records. Aggregate fields must resolve to fixed-width integer or fixed-byte schema fields. |
| Covenant ProofPlan metadata | Implemented | Runtime, action, function, and lock metadata expose ProofPlan records with trigger, scope, reads, coverage, relation checks, group cardinality, identity/lifecycle policy, builder assumptions, diagnostics, and codegen coverage status. |
| `cellc explain-proof` | Implemented | The CLI emits human-readable and JSON ProofPlan output for packages and single `.cell` files. |
| Runtime-obligation policy gate | Implemented | `cellc check --deny-runtime-obligations` rejects runtime-required ProofPlan gaps, including declared invariants whose coverage is still metadata-only. |
| Lock-group transaction risk diagnostics | Implemented | ProofPlan records warn when a `lock_group` verifier scans transaction-wide views, because only inputs sharing that lock trigger the verifier. |
| Protocol macro provenance | Implemented | ProofPlan coverage records include macro provenance for selected compiler-recognized flows such as `transfer`, `create`, `claim`, `settle`, `consume`, `destroy`, and pool protocol metadata. |
| Documentation and tests | Implemented | README, docgen, CLI tests, parser tests, metadata tests, and aggregate invariant tests cover the new surface. |

## Boundaries

- Declared invariants and aggregate primitives are currently ProofPlan metadata,
  not executable verifier lowering. They intentionally emit
  `codegen_coverage_status: "gap:metadata-only"` and `status:
  "runtime-required"` until a later lowering pass proves them on chain.
- `lock_group + transaction` means the verifier can inspect transaction-wide
  views, but the active CKB trigger is still the lock ScriptGroup. Builders and
  auditors must not read that as type-group conservation.
- Aggregate primitives only accept fixed-width fields so future executable
  lowering has a concrete ABI boundary. Dynamic tables, generic collections, and
  bool fields are rejected for aggregate relation targets.
- `assert_sum(...) <= assert_sum(...)` records a relation check in ProofPlan, but
  it does not yet generate an output-scan verifier.
- Protocol macro provenance is audit metadata. It records how recognized source
  effects map to consume/create/write-intent shapes; it is not a replacement for
  builder-backed CKB transaction evidence.

## Verification

Focused 0.15 checks:

```bash
cargo test --locked -p cellscript proof_plan --lib
cargo test --locked -p cellscript aggregate_invariant --lib
cargo test --locked -p cellscript explain_proof --test cli
cargo run --locked -p cellscript -- explain-proof examples/token.cell --target-profile ckb --json
```

Full gate before closing the branch:

```bash
cargo fmt --all
cargo check --locked -p cellscript --all-targets
cargo test --locked -p cellscript
cargo clippy --locked -p cellscript --all-targets -- -D warnings
git diff --check
```
