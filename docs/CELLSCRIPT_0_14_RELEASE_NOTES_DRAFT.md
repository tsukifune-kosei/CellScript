# CellScript 0.14 Release Notes Draft

**Status**: Release-gate draft for the `cellscript-0.14` implementation branch.

**Updated**: 2026-04-27.

CellScript 0.14 is the CKB semantic-completeness milestone. It exposes more of
CKB's concrete transaction surface in source syntax, metadata, constraints, and
tooling while keeping authorization boundaries explicit.

The short version: 0.14 adds Spawn/IPC verifier composition, typed CKB Source
and WitnessArgs views, fixed-width `lock_args` binding, explicit sighash digest
surface, TYPE_ID and `outputs_data` evidence, declarative since/time and
capacity surfaces, and a formal CKB target-profile ABI contract.

## Highlights

### CKB Source, Witness, And Lock Args

0.14 makes CKB data sources visible instead of hiding them behind ordinary
parameters:

- `source::input`, `source::output`, `source::cell_dep`, `source::header_dep`,
  `source::group_input`, and `source::group_output`;
- `witness::raw`, `witness::lock`, `witness::input_type`, and
  `witness::output_type`;
- `lock_args T` for fixed-width typed decoding of the executing `Script.args`;
- `env::sighash_all(source)` for an explicit CKB sighash digest surface.

Important boundary: `lock_args Address`, `witness Address`, and
`env::sighash_all(...)` do not create signer authority by themselves. Signature
verification remains explicit future work; there is no hidden signer derivation
from an `Address` value or parameter name.

### Spawn/IPC Verifier Composition

0.14 adds bounded verifier reuse through CKB VM v2-shaped Spawn/IPC helpers:

- `spawn`
- `wait`
- `process_id`
- `pipe`
- `pipe_write`
- `pipe_read`
- `inherited_fd`
- `close`

Spawn targets must be static string literals or `String` constants. Metadata
records runtime-required CellDep or DepGroup obligations for the child verifier.
The type checker rejects statically visible file-descriptor use-after-close,
double-close, and unclosed fd paths for `pipe()` and `inherited_fd(...)`.

### Target Profile Contract

The CKB target profile now reports a structured ABI contract in metadata,
constraints, and `cellc explain-profile ckb`:

- witness ABI;
- lock args ABI;
- Source encoding;
- Spawn/IPC ABI;
- since/time ABI;
- CellDep and script reference ABI;
- `outputs` / `outputs_data` ABI;
- capacity floor ABI;
- TYPE_ID ABI;
- CKB tx version.

Metadata validation rejects mismatched profile ABI fields so release evidence
cannot silently drift from compiler policy.

### outputs / outputs_data Boundary

CKB transactions keep Cell output metadata and Cell data in parallel arrays:

```text
outputs[i]      = capacity, lock, type
outputs_data[i] = data bytes for the same output Cell
```

0.14 records each CellScript-created output's index-aligned
`outputs[i] -> outputs_data[i]` binding and validates that those bindings are
present and consistent.

### TYPE_ID And Script References

0.14 exposes TYPE_ID output plans and script reference evidence for CKB audit
tooling. `constraints.ckb.script_references` aggregates:

- TYPE_ID script references;
- Spawn/IPC CellDep or DepGroup targets;
- `read_ref` CellDep references.

This keeps `code_hash`, `hash_type`, and `args` visible instead of treating a
source-level name as authority.

### Declarative Since/Time And Capacity Surfaces

0.14 adds profile-visible CKB policy helpers:

- `require_maturity`
- `require_time`
- `require_epoch_after`
- `require_epoch_relative`
- `with_capacity_floor(shannons)`
- `occupied_capacity("TypeName")`

`with_capacity_floor(...)` declares a type-level output-capacity floor. It is
not full capacity evidence: builders still must fund outputs, measure occupied
capacity, measure consensus transaction size, and keep acceptance reports.

### Dynamic BLAKE2b Policy

Dynamic in-script `hash_blake2b` remains fail-closed until a real linked
RISC-V implementation, test vectors, cycle evidence, and profile policy are
present. `hash_chain` remains metadata-visible for supported profile use.

### Examples And Tooling

0.14 adds language examples for:

- Spawn/IPC delegate verification;
- multi-step Spawn/IPC pipelines;
- witness/source views;
- TYPE_ID creation;
- capacity/time policy;
- canonical style using `protected`, `lock_args`, `witness`, `require`,
  field shorthand, and `[]`.

LSP and the VS Code extension now cover the 0.14 surface with completions,
snippets, and highlighting for `lock_args`, CKB Source views, WitnessArgs
helpers, `ckb::*`, and `env::sighash_all`.

### Bug Fixes And Hardening

0.14 also includes a focused fuzzy-debugging pass:

- Unicode and malformed hex inputs now fail with controlled diagnostics instead
  of panicking in metadata, scheduler, and CLI decoding paths.
- Invalid or reversed LSP incremental edit ranges are ignored safely instead of
  corrupting document state.
- Oversized static metadata widths and entry-witness width calculations now
  fail closed instead of overflowing internal size arithmetic.
- Malformed numeric package versions are rejected instead of being treated as
  compatible.
- The canonical style example was moved into `examples/language/` so the flat
  production bundled example set remains exactly the seven CKB acceptance
  contracts.

## Intentional Boundaries

0.14 does not include:

- first-class verified signer values;
- implicit signer derivation from `Address`;
- hidden sighash defaults;
- `protects T { self ... }` sugar;
- dynamic in-script BLAKE2b;
- full generic maps or cell-backed collection ownership;
- ProofPlan trigger/scope/coverage semantics, which remain 0.15 scope.

## Verification

Targeted 0.14 gate:

```bash
cargo fmt --all
cargo check --locked -p cellscript
cargo test --locked -p cellscript --test v0_14 -- --test-threads=1
cargo test --locked -p cellscript --test examples -- --test-threads=1
cargo test --locked -p cellscript --test cli cellc_explain_profile_reports_ckb_v0_14_contract -- --test-threads=1
cargo test --locked -p cellscript --lib lsp -- --test-threads=1
cd editors/vscode-cellscript && npm run validate
git diff --check
```

Roadmap example gate:

```bash
cargo run --locked -p cellscript -- explain-profile ckb --json
cargo run --locked -p cellscript -- constraints examples/language/v0_14_witness_source.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_delegate_verify.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_multi_step_pipeline.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_witness_source.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_ckb_type_id_create.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_capacity_time.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/canonical_style.cell --target-profile ckb
```

## Summary

CellScript 0.14 moves the compiler closer to CKB-native language semantics by
making transaction surfaces explicit: Source views, witness fields, script args,
script references, output data, capacity floors, since/time policy, and bounded
verifier composition. The release keeps the security boundary conservative:
data-source syntax is not signer authority, and signer verification remains a
separate explicit hardening track.
