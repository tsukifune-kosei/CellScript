# CellScript 0.14 Roadmap

**Updated**: 2026-04-27

0.14 is the CKB semantic-completeness track. It builds on the 0.13 syntax and
bounded-vector release by exposing more of CKB's real execution surface in
CellScript source and metadata.

## Goals

1. Expose bounded verifier composition through Spawn/IPC builtins.
2. Make CKB `WitnessArgs` and Source views explicit.
3. Formalize the `ckb` target profile contract.
4. Surface ScriptGroup, `outputs` / `outputs_data`, TYPE_ID, script reference,
   capacity, and since/time assumptions in metadata and tests.

## Implemented In This Branch

| Track | Status | Notes |
|---|---|---|
| Spawn/IPC surface | Implemented | `spawn`, `wait`, `process_id`, `pipe`, `pipe_write`, `pipe_read`, `inherited_fd`, and `close` lower to CKB VM v2 syscall stubs and metadata. Spawn targets must be string literals or `String` constants and produce runtime-required CellDep/DepGroup script-reference obligations. |
| Spawn/IPC fd safety | Implemented | The type checker rejects statically visible use-after-close, double-close, and unclosed fd paths for values produced by `pipe()` or `inherited_fd(...)`. |
| Source views | Implemented | `source::input`, `source::output`, `source::cell_dep`, `source::header_dep`, `source::group_input`, and `source::group_output` are typed and metadata-visible. |
| ScriptGroup metadata | Implemented | CKB actions and locks now expose entry kind, active lock/type group kind, selected Source surfaces, and group-scoped Source usage. |
| outputs/outputs_data binding | Implemented | Each CKB create output records an index-aligned `outputs[i]` to `outputs_data[i]` binding, and metadata validation rejects missing or mismatched bindings. |
| Structured witness fields | Implemented | `witness::raw`, `witness::lock`, `witness::input_type`, and `witness::output_type` are typed as explicit CKB witness surfaces. |
| Lock args source | Implemented | Lock parameters can declare `lock_args` for fixed-width typed CKB `Script.args` data. This is source binding only, not signer authority. |
| Sighash surface | Implemented | `env::sighash_all(source)` is explicit and metadata-visible; no hidden signer derivation is introduced. |
| Target profile contract | Implemented | Target metadata and `constraints.ckb.profile_abi_contract` now record witness ABI, lock args ABI, Source encoding, Spawn/IPC ABI, since ABI, CellDep ABI, script reference ABI, outputs/outputs_data ABI, capacity floor ABI, TYPE_ID ABI, and tx version; `cellc explain-profile ckb` reports the same contract. Metadata validation rejects mismatched profile ABI fields. |
| Script reference table | Implemented | `constraints.ckb.script_references` aggregates TYPE_ID script references, spawn CellDep/DepGroup targets, and read_ref CellDep references for audit tooling. |
| Declarative since/time surface | Implemented | `require_maturity`, `require_time`, `require_epoch_after`, and `require_epoch_relative` are profile-visible runtime checks. |
| Declarative capacity surface | Implemented | `with_capacity_floor(shannons)` declares a type-level CKB output capacity floor; `occupied_capacity("TypeName")` remains available for runtime-visible capacity evidence. Builders still have to measure occupied capacity and tx size. |
| Dynamic BLAKE2b policy | Implemented as fail-closed | `hash_blake2b` is rejected until a real linked RISC-V implementation is selected; `hash_chain` is metadata-visible. |
| v0.14 examples | Implemented | Language examples cover delegate verification, Spawn/IPC pipelines, witness/source views, TYPE_ID creation, and capacity/time policy. |

## Boundaries

- Spawn/IPC is bounded verifier reuse. It does not make a CKB Cell's type script
  slot multi-tenant.
- `spawn("target")` is not an inline script reference. The transaction builder
  must provide the child verifier as a resolvable CellDep or DepGroup script
  reference, and metadata exposes that requirement instead of treating the name
  as authority.
- `lock_args`, `witness::lock`, and `env::sighash_all` expose script-args,
  witness data, and digest surfaces. They do not create first-class signer
  authority by themselves.
- Source group views are scoped to the active script group.
- `outputs` and `outputs_data` are treated as index-aligned CKB transaction
  surfaces. CellScript metadata exposes that boundary; it does not silently
  remap output data between cells.
- Script references keep `code_hash`, `hash_type`, and `args` visible through
  the target profile and deployment metadata.
- `with_capacity_floor(...)` is a declared output-capacity floor, not full
  capacity evidence. Builders still need to fund outputs, measure occupied
  capacity, and attach tx-size evidence.
- TYPE_ID support uses the CKB TYPE_ID ABI and remains tied to explicit
  builder/deployment evidence.
- Dynamic in-script BLAKE2b remains fail-closed until linked implementation,
  test vectors, cycles, and profile policy are all present.
- Higher-level trigger/scope/coverage ProofPlan work remains 0.15 scope.

## Verification

Targeted 0.14 gate:

```bash
cargo test --locked -p cellscript --test v0_14 -- --test-threads=1
cargo run --locked -p cellscript -- explain-profile ckb --json
cargo run --locked -p cellscript -- constraints examples/language/v0_14_witness_source.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_delegate_verify.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_multi_step_pipeline.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_witness_source.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_ckb_type_id_create.cell --target-profile ckb
cargo run --locked -p cellscript -- examples/language/v0_14_capacity_time.cell --target-profile ckb
```
