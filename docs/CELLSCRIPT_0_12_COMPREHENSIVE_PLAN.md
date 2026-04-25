# CellScript 0.12 Acceptance Record

- **Date**: 2026-04-24
- **Release**: CellScript 0.12.0
- **Status**: accepted for the current 0.12 production scope
- **CellScript commit**: `40c81af Fix CKB tx measure helper paths`
- **Spora integration commit**: `4e342a85 Update CellScript CI helper path`

This document used to be the comprehensive 0.12 plan. It is now the acceptance
record for that plan. It records what was delivered, what was verified, and the
explicit production boundary for CellScript 0.12.

CellScript 0.12 is accepted as a production-gated compiler/toolchain release for
the bundled Spora and CKB contract suite. The acceptance claim is evidence based:
compiler tests, package verification, Spora production evidence, CKB on-chain
production evidence, backend shape gates, and release-evidence validators have
all passed for the current scope.

This is not a third-party security audit statement and does not claim complete
future mainnet risk closure for arbitrary contracts.

---

## 1. Acceptance Summary

### 1.1 Release State

The release state has been landed:

- `cellscript` crate version is `0.12.0`.
- The Spora workspace dependency is `cellscript = { version = "0.12.0", path = "cellscript" }`.
- Root `Cargo.lock` and standalone `cellscript/Cargo.lock` are synchronized.
- README and README_CH manifest examples use `0.12.0`.
- CHANGELOG marks `0.12.0` as released on `2026-04-24`.

### 1.2 Production Gate State

The current production closure is accepted:

- Spora production evidence validates.
- CKB final hardening evidence validates.
- CKB production mode no longer accepts compile-only evidence as release-ready.
- CKB production evidence requires builder-backed transactions, measured cycles,
  consensus serialized tx size, exact occupied capacity, per-output capacity
  sufficiency, and malformed transaction rejection evidence.
- The seven bundled examples remain the fixed production regression suite:
  `amm_pool.cell`, `launch.cell`, `multisig.cell`, `nft.cell`,
  `timelock.cell`, `token.cell`, and `vesting.cell`.

### 1.3 Evidence Artifacts

Accepted local evidence:

- CKB production report:
  `/Users/arthur/RustroverProjects/Spora/target/ckb-cellscript-acceptance/20260424-205425-31807/ckb-cellscript-acceptance-report.json`
- Spora production evidence:
  `/Users/arthur/RustroverProjects/Spora/target/devnet-acceptance/20260424-165644-5799/production-evidence.json`

These reports were validated with:

```bash
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/20260424-205425-31807/ckb-cellscript-acceptance-report.json

python3 scripts/validate_spora_production_evidence.py \
  target/devnet-acceptance/20260424-165644-5799/production-evidence.json
```

---

## 2. Verified Commands

The following commands were run and passed during the 0.12 acceptance pass.
They are recorded here as evidence; they were not rerun while converting this
document from plan to acceptance record.

### 2.1 CellScript Compiler and Package Gates

```bash
cargo fmt --check
cargo test --locked -p cellscript -- --test-threads=1
cargo clippy --locked -p cellscript --all-targets -- -D warnings
cargo package --manifest-path cellscript/Cargo.toml --locked --allow-dirty --offline
cargo package --manifest-path cellscript/Cargo.toml --list --locked --allow-dirty --offline
```

Observed results:

- `362` library tests passed.
- `71` CLI tests passed.
- `15` bundled example tests passed.
- Doc tests passed.
- Clippy passed with `-D warnings`.
- Package verification passed as `cellscript v0.12.0`.
- Package list contains `48` files.

### 2.2 Spora Integration Gate

```bash
cargo check --locked -p spora-testing-integration
```

Observed result:

- Spora integration check passed with `cellscript v0.12.0`.

### 2.3 Evidence Validators

```bash
python3 scripts/validate_ckb_cellscript_production_evidence.py <ckb-report>
python3 scripts/validate_spora_production_evidence.py <spora-evidence>
```

Observed result:

- CKB CellScript production evidence validated.
- Spora production evidence validated.

### 2.4 Diff and Script Checks

```bash
bash -n scripts/ckb_cellscript_acceptance.sh
python3 -m py_compile \
  scripts/validate_ckb_cellscript_production_evidence.py \
  scripts/validate_spora_production_evidence.py
git diff --check
```

Observed result:

- Shell syntax passed.
- Python validators compiled.
- Diff whitespace check passed.

---

## 3. Accepted Deliverables

## Track A: Runtime Errors and Diagnostics

Accepted:

- Added a stable runtime error registry in `src/runtime_errors.rs`.
- Exposed runtime error code/name/hint data through metadata and constraints.
- Added registry consistency tests.
- Added documentation in `docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md`.
- Verified that codegen no longer emits unregistered numeric fail literals.

Acceptance evidence:

- `runtime_errors::tests::runtime_error_registry_roundtrips_and_has_unique_codes`
- `runtime_errors::tests::runtime_error_docs_cover_every_registered_code`
- `runtime_errors::tests::codegen_does_not_emit_unregistered_numeric_fail_literals`

## Track B: CKB Profile Authoring

Accepted:

- Added CKB Blake2b helper support through `ckb_blake2b256` and
  `cellc ckb-hash`.
- Pinned the CKB `ckb-default-hash` empty-input vector:
  `44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e`.
- Added manifest-level `deploy.ckb.hash_type`.
- Added `[[deploy.ckb.cell_deps]]` with `code` and `dep_group` support.
- Added atomic `out_point = "0x<32-byte-tx-hash>:<index>"` support.
- Kept split `tx_hash` plus `index` as compatibility syntax, with fail-closed
  validation for incomplete or conflicting declarations.
- Added structured `constraints.ckb.timelock_policy`.
- Added `constraints.ckb.capacity_evidence_contract`.
- Added CKB tx measurement helper under `tools/ckb-tx-measure`.
- Spora acceptance now builds the CKB tx measurement helper through a generated
  temporary manifest that points at the configured CKB checkout.

Acceptance evidence:

- `ckb_hash_tests::ckb_blake2b256_matches_blank_hash_vector`
- `tests::ckb_deploy_manifest_surfaces_hash_type_and_dep_group_policy`
- `tests::ckb_deploy_manifest_rejects_invalid_hash_type`
- `tests::ckb_deploy_manifest_rejects_invalid_dep_type`
- `tests::ckb_deploy_manifest_rejects_conflicting_cell_dep_locations`
- `tests::ckb_deploy_manifest_rejects_incomplete_split_cell_dep_location`
- `cellc_ckb_hash_emits_default_blake2b_vector`
- CKB production evidence validator passed for the full production report.

Boundary:

- In-script dynamic `ckb::blake2b256(data)` is not claimed in 0.12. The accepted
  surface is builder/release/helper hashing. A future in-script version requires
  linking a real RISC-V Blake2b implementation into generated artifacts and
  covering that path in production gates.

## Track C: Collections and Dynamic Data

Accepted:

- Added `docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md`.
- Documented the distinction between schema/ABI dynamic values, IR collection
  construction, runtime helpers, and cell-backed collection ownership.
- Covered `Vec<u8>`, `Vec<Address>`, `Vec<Hash>`, and opaque nested
  `Vec<Vec<u8>>` entry witness payloads.
- Kept generic runtime collection support bounded and explicit.
- Kept cell-backed linear collection ownership as a documented unsupported
  production boundary instead of a silent claim.

Acceptance evidence:

- `tests::entry_witness_encoder_includes_schema_backed_params_as_length_prefixed_bytes`
- `tests::compile_marks_cell_backed_vec_runtime_features`
- `cellc_entry_witness_subcommand_encodes_schema_backed_params`
- Bundled example shape and scheduler tests.

Boundary:

- 0.12 does not claim full generic `HashMap<K, V>` runtime support.
- 0.12 does not claim complete linear ownership for cell-backed collections.

## Track D: Mutate and Replacement Outputs

Accepted:

- Added `docs/CELLSCRIPT_MUTATE_AND_REPLACEMENT_OUTPUTS.md`.
- Documented that mutate is Input -> Output replacement, not physical in-place
  cell mutation.
- Documented preserved fields, transition fields, type hash preservation, lock
  hash preservation, and builder obligations.
- AMM remains the canonical advanced mutate example.
- Append transition behavior is documented through the mutate guide and examples.

Acceptance evidence:

- `tests::fixed_byte_mutable_state_set_transition_is_checked_under_ckb_profile`
- `tests::u128_mutable_state_transition_with_u64_delta_is_checked`
- `tests::dynamic_mutable_schema_transitions_are_checked_after_table_decoding`
- `amm_pool_mutable_shared_params_are_scheduler_visible`

## Track E: Linear Ownership

Accepted:

- Added `docs/CELLSCRIPT_LINEAR_OWNERSHIP.md`.
- Documented compile-time linear checks.
- Documented runtime consume zeroing as a defense, not the primary ownership
  mechanism.
- Documented the cell-backed collection ownership gap.
- Kept unsupported resource collection cases fail-closed or surfaced as stable
  blockers.

Acceptance evidence:

- Existing type and compile tests for consume-after-move, branch ownership,
  loop ownership, local references to linear roots, and linear aggregate moves
  passed in the 0.12 test run.

## Track F: Entry Witness ABI

Accepted:

- Added `docs/CELLSCRIPT_ENTRY_WITNESS_ABI.md`.
- Documented `CSARGv1\0`.
- Documented scalar, fixed-byte, and schema-backed payload layout.
- Documented register and stack placement.
- Added `cellc abi` JSON explanation command.
- Added entry witness encoder tests and CLI tests.

Acceptance evidence:

- `tests::entry_witness_encoder_matches_u64_wrapper_abi`
- `tests::entry_witness_encoder_supports_fixed_byte_params`
- `tests::entry_witness_encoder_includes_schema_backed_params_as_length_prefixed_bytes`
- `tests::entry_witness_wrapper_supports_scalar_stack_args`
- `cellc_abi_subcommand_explains_entry_witness_layout`
- `cellc_entry_witness_subcommand_emits_parameterized_witness_json`
- `cellc_entry_witness_subcommand_rejects_wrong_width_fixed_bytes`

## Track G: Scheduler Hints

Accepted:

- Added `docs/CELLSCRIPT_SCHEDULER_HINTS.md`.
- Added `cellc scheduler-plan` as a concrete scheduler-hint consumer.
- The command reports serial-required actions, shared touch-set conflicts, and
  estimated cycle budgets.
- Scheduler metadata remains an admission/tooling policy surface, not a claim
  that consensus scheduler enforcement was redesigned in 0.12.

Acceptance evidence:

- `cellc_scheduler_plan_consumes_shared_touch_hints`
- `mutable_shared_param_forces_mutating_scheduler_hint`
- Bundled scheduler metadata tests.

## Track H: Optimizer and Backend Shape

Accepted:

- Added `cellc opt-report`.
- Kept backend shape budgets and release baselines for bundled examples.
- Kept branch relaxation, machine CFG, call-edge tracking, and backend shape
  reports as release gates.
- Package release remains measurement-first; aggressive optimizer work is not
  part of 0.12.

Acceptance evidence:

- `cellc_opt_report_compares_all_optimization_levels`
- `bundled_examples_backend_shape_report_serializes`
- `bundled_examples_stay_near_backend_shape_release_baseline`
- `bundled_examples_stay_within_backend_shape_budgets`
- `bundled_examples_compile_to_elf`

## Track I: Documentation and Examples

Accepted documentation:

- `docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md`
- `docs/CELLSCRIPT_CKB_PROFILE_AUTHORING.md`
- `docs/CELLSCRIPT_CKB_DEPLOYMENT_MANIFEST.md`
- `docs/CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md`
- `docs/CELLSCRIPT_ENTRY_WITNESS_ABI.md`
- `docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md`
- `docs/CELLSCRIPT_MUTATE_AND_REPLACEMENT_OUTPUTS.md`
- `docs/CELLSCRIPT_LINEAR_OWNERSHIP.md`
- `docs/CELLSCRIPT_SCHEDULER_HINTS.md`
- `docs/CELLSCRIPT_0_12_MIGRATION_NOTES.md`
- `docs/CELLSCRIPT_0_12_RELEASE_EVIDENCE.md`

Accepted authoring examples:

- `docs/examples/ckb_hashing.md`
- `docs/examples/mutate_append.md`
- `docs/examples/collections_matrix.md`
- `docs/examples/deployment_manifest.md`

Accepted packaging boundary:

- The crates.io package excludes `.github/`, `docs/`, `editors/`, `tools/`,
  and unpublished helper binaries.
- README links point to repository-hosted documentation for excluded docs.
- Package verification passed for `cellscript v0.12.0`.

---

## 4. CKB Production Acceptance

The CKB line is accepted for the bundled 0.12 production scope.

Validated CKB requirements:

- production mode
- strict original compile coverage
- exact bundled action coverage
- `43/43` builder-backed action runs
- no handwritten harness action runs
- measured cycles for every action
- measured consensus serialized tx size for every action
- measured occupied capacity for every action
- per-output capacity sufficiency
- no under-capacity outputs
- committed valid transactions
- rejected malformed transactions
- malformed rejection is not policy/capacity based
- passed `final_production_hardening_gate`

Validator:

```bash
python3 scripts/validate_ckb_cellscript_production_evidence.py <report>
```

Accepted report:

```text
/Users/arthur/RustroverProjects/Spora/target/ckb-cellscript-acceptance/20260424-205425-31807/ckb-cellscript-acceptance-report.json
```

Important boundary:

- `--compile-only` validates strict compile coverage only. It is not sufficient
  for external release evidence.

---

## 5. Spora Production Acceptance

The Spora line is accepted for the bundled 0.12 production scope.

Validated Spora requirements:

- production profile
- production gate passed
- standard mass policy used
- scoped action standard relay readiness
- full-file monolith standard relay readiness
- no standard relay incompatible examples
- valid action-specific builder coverage
- malformed action matrix coverage
- bundled example deployment compatibility

Validator:

```bash
python3 scripts/validate_spora_production_evidence.py <production-evidence>
```

Accepted evidence:

```text
/Users/arthur/RustroverProjects/Spora/target/devnet-acceptance/20260424-165644-5799/production-evidence.json
```

---

## 6. Non-Goals and Boundaries

0.12 explicitly does not claim:

- full generic `HashMap<K, V>` runtime support
- complete linear ownership for cell-backed collections
- in-script dynamic CKB Blake2b lowering
- a consensus-level scheduler rewrite
- a large optimizer pass suite
- a third-party security audit closure
- arbitrary-contract mainnet risk elimination

These are valid future tracks, but they are not part of the accepted 0.12 scope.

---

## 7. Final Acceptance Decision

CellScript 0.12 is accepted for release under the current scope.

The accepted scope is:

- production-gated Spora and CKB bundled contract suite
- inspectable compiler metadata and constraints
- stable runtime error registry
- CKB hash/deployment/capacity authoring surfaces
- documented witness ABI
- documented Molecule and collection boundaries
- documented mutate and linear ownership semantics
- package and LSP/tooling surfaces consistent with the 0.12 release boundary

The release is evidence-backed, not merely smoke-tested. Future 0.13 work can
start from the explicit non-goals above instead of reopening the 0.12 acceptance
scope.
