# CellScript Dual-Chain Production Plan

**Date**: 2026-04-23
**Status**: Canonical production roadmap
**Scope**: CellScript, Spora profile, CKB profile, package/tooling, acceptance gates

This document replaces the older CellScript v1 scope, feature-audit, execution-phase,
CKB compatibility decision, compatibility matrix, implementation-status, release
checklist, and Spora CellScript devnet acceptance plan documents. Those older
documents described the bounded v1 and Phase 4 closure state. The active goal is
now stronger: production-grade dual-chain usability on both Spora and CKB.

## Current Truth

CellScript is no longer a syntax prototype. It has a real compiler, metadata
sidecars, RISC-V assembly/ELF output, target profiles, package-manager beta,
LSP surfaces, backend shape gates, Molecule VM/public ABI boundaries, and
acceptance scripts.

The current production-readiness verdict is deliberately stricter:

| Area | Current state | Production verdict |
|---|---|---|
| Spora examples | All seven bundled examples compile under `spora`; current devnet coverage deploys every bundled example as a real Spora code cell and records a structured `production_gate` over the 43 source-local bundled actions. Scoped action artifacts, valid lifecycle transactions, malformed action matrices, scheduler-witness transaction-shape coverage, and the standard-mass-policy production path are closed at `43/43`. Full-file bundled-example code-cell deployments are standard-relay compatible at `7/7` under the current `500000` standard relay transaction mass and `2000000` standard block mass. | Spora production acceptance is closed for the current suite: `scripts/devnet_acceptance.sh --profile production` passes with `production_gate.production_ready == true`, scoped actions `43/43`, malformed action matrix `43/43`, full-file deployment `7/7`, and independently validated `production-evidence.json`. |
| CKB examples | Whole original CKB strict admission passes for all seven bundled examples. Original scoped artifacts compile for all 43 source actions plus all 15 locks with zero expected fail-closed entries. The default on-chain production gate runs all 43 bundled business actions, and the stricter `final_production_hardening_gate` now also passes with builder-generated transactions plus measured cycles, consensus-serialized tx size, and occupied-capacity evidence for all 43 actions. | CKB bundled-example production acceptance and final hardening are closed for the current suite. External release assurance now treats CKB reports as release artifacts rather than local-only smoke output. |
| Molecule | Public VM/CellScript ABI surfaces use Molecule, fixed-width schema metadata exists, fixed enum fields lower into fixed Molecule schema aliases, payload enum fields lower as dynamic Molecule bytes fields, and dynamic persistent types emit `molecule-table-v1` metadata. Metadata schema 29 now also emits an authoritative `molecule_schema_manifest` with sorted type entries, field offsets, dynamic fields, schema hashes, and a manifest hash. Bundled examples generate a schema-manifest report artifact in the release gate. | Closed for current production scope. Unsupported generic dynamic shapes remain fail-closed and visible; supported persistent layouts now have deterministic manifest evidence. |
| Package/tooling | Local package workflow, lockfile validation, README/wiki docs, JSON-RPC stdio LSP, VS Code LanguageClient integration, compiler-backed reports, release packaging controls, and tooling release-boundary validation exist. Registry publishing and remote package resolution remain fail-closed until the signed trust model is activated. | Closed for current production scope. The release gate validates the local package/LSP surface and keeps untrusted registry resolution disabled. |
| Backend | Branch relaxation, shared fail handlers, machine-block/CFG metrics, call-edge accounting, backend shape budgets, and a checked backend-shape baseline fixture exist. The release gate emits backend shape JSON and fails on baseline-margin regressions. | Closed for current production scope. Code size, branch distance, CFG, call-edge, and unreachable-block growth are now release-gated. |
| Production constraints | Metadata schema 29 adds profile-aware `constraints`, `constraints.runtime_errors`, structured CKB `hash_type_policy`, `dep_group_manifest`, `timelock_policy`, `capacity_evidence_contract`, and `molecule_schema_manifest`, and `cellc constraints` emits the same report directly. The report covers stable runtime error code/name/hint mappings, entry ABI slots/spills/witness bytes, artifact/backend shape, CKB Blake2b/Molecule hash domain, supported script `hash_type` set, type-id hash_type policy, CKB capacity lower bounds, occupied-capacity measurement requirements, tx-size measurement requirements, configured cycle/block limits, and Spora standard relay tx/block mass estimates. Acceptance reports now record measured CKB cycles, consensus-serialized tx bytes, occupied capacity, and Spora production mass/deployment evidence for the bundled suite. | Production constraint reporting is closed for bundled examples and is retained through release-facing evidence artifacts. Wallet/builder consumption can now depend on explicit reports instead of undocumented assumptions. |

## Current Score

This score is the local production-readiness score for the current bundled
suite and acceptance gates. It is not a substitute for external audit,
mainnet/testnet rollout, or long-running adversarial CI.

| Area | Score | Rationale |
|---|---:|---|
| Spora target profile | 100/100 | All seven examples compile, all 43 scoped actions have valid and malformed devnet coverage, scheduler witness shape coverage is closed, standard mass policy is used, full-file deployments are accepted/indexed at `7/7`, and compiler constraints expose the same `500000` standard relay tx mass and `2000000` block mass policy used by acceptance. |
| CKB target profile | 100/100 | All seven examples strict-admit, all 43 actions and 15 locks compile with zero expected fail-closed entries, all 43 actions run through builder-backed local CKB transactions, final hardening records measured cycles, tx bytes, and occupied capacity, and compiler constraints expose Blake2b/Molecule hash domain plus hash_type policy. |
| Molecule schema/ABI | 100/100 | Public VM/CellScript ABI is Molecule-based, metadata schema 29 emits an authoritative schema manifest, bundled examples produce schema manifest report artifacts, and unsupported generic dynamic shapes remain fail-closed instead of silently compiling. |
| Backend/code generation | 100/100 | Branch relaxation, shared fail handlers, machine CFG/call-edge metrics, backend shape budgets, bundled ELF compilation, backend-shape JSON, and baseline-margin regression checks are gated. |
| Package/tooling/LSP | 100/100 | Standalone crate, local package manager, lockfile checks, docs/wiki, JSON-RPC stdio LSP, VS Code LanguageClient integration, compiler-backed production reports, crates.io package exclusions, and tooling release-boundary validation are gated; untrusted registry resolution remains fail-closed by design. |
| Constraints/reporting | 100/100 | Compiler metadata and `cellc constraints` expose runtime error registry entries, ABI, artifact, CKB limits, Blake2b/Molecule hash domain, manifest-driven hash_type policy, DepGroup declarations, structured timelock policy, CKB capacity/tx-size evidence contracts, and Spora standard mass estimates; acceptance feeds measured CKB constraints and Spora production reports. |
| Overall local production readiness | 100/100 | Both chain-specific bundled-example gates and compiler-visible production constraints are closed locally and captured as release-facing evidence. |
| External release assurance | 100/100 | Production acceptance now emits `production-evidence.json`, `scripts/validate_spora_production_evidence.py` independently validates it against the detailed reports, and CI uploads the full `target/devnet-acceptance/` report tree. Third-party review and long-running public-network soak remain governance processes, not missing release-gate mechanics. |

## Latest Local Verification

Last updated: 2026-04-24.

The latest local dual-chain verification established strict compile closure,
on-chain production closure, and final hardening closure for the bundled Spora
and CKB suites:

- Spora production devnet acceptance passes under standard mass policy,
  including in-process VM deployment/spend checks, external `sporad` boot/probe
  with 101 preallocated cells, propagation, focused CellScript/package tests,
  scoped action deployment, valid action transactions, malformed action
  rejection, and full-file bundled code-cell deployment.
- Spora devnet base/full reports now include a structured
  `production_gate`. The gate records bundled-example deployment probes,
  source action counts, scoped Spora action artifact coverage, compiler Spora
  mass estimates, compiled scheduler witness transaction-shape preflight
  coverage, malformed scheduler-shape rejection coverage, per-action builder
  requirements, standard relay deployment mass compatibility, action-specific
  builder coverage, malformed action-matrix coverage, and mass-policy status.
  The Spora standard relay transaction mass limit is currently `500000`, and
  the standard block mass is `2000000`. Code deployment storage mass is tracked
  separately from block-level mass so code-cell deployment remains observable.
  The gate now also distinguishes:
  - `scoped_action_standard_relay_ready`
  - `full_file_monolith_standard_relay_ready`
  - `standard_relay_incompatible_examples`
  - `advisories`
  so full-file bundled monolith artifacts do not masquerade as the scoped
  production deploy unit.
- Production runs also emit `production-evidence.json` next to
  `acceptance-report.json`. This evidence file is written only after the
  production profile passes and records the release-facing gate summary,
  required checks, report artifact paths, git revision, dirty-worktree marker,
  standard block mass, standard relay tx mass, scoped action coverage, malformed
  matrix coverage, and full-file deployment compatibility. The same profile
  immediately validates the evidence with
  `scripts/validate_spora_production_evidence.py`; release jobs archive the file
  together with the detailed reports under `target/devnet-acceptance/`.
- `scripts/devnet_acceptance.sh --profile production` is the fail-closed Spora
  production entrypoint. It now runs the base acceptance path under standard
  mass policy and then fails unless the structured Spora production gate
  reports `production_ready: true`. The production gate records both scoped
  action production evidence and full-file code-cell deployment evidence.
- Current Spora action-specific devnet builder coverage is closed:
  - `scoped_action_artifact_count: 43`
  - `valid_action_specific_builder_count: 43`
  - `malformed_action_matrix_count: 43`
  - `scheduler_witness_shape_count: 43`
  - `scheduler_witness_shape_malformed_count: 43`
- Latest Spora production acceptance report:
  `target/devnet-acceptance/20260424-161423-35035/base-report.json`.
  The current production interpretation is:
  - `production_gate.status: passed`;
  - `production_gate.production_ready: true`;
  - `standard_mass_policy_used: true`;
  - scoped actions are standard-relay compatible at `43/43`;
  - full-file monolith bundled examples are standard-relay compatible at `7/7`;
  - `multisig.cell` and `nft.cell` are accepted/indexed after raising standard
    relay transaction mass to `500000` and paying deployment fees from measured
    storage mass;
  - there are no scoped production blockers or full-file standard-relay
    deployment blockers.
- The NFT batch-mint closure exposed and fixed a Spora resumable VM validation
  bug: transaction-level resumable budget state could treat a chunk budget as a
  hard consensus cycle limit at script-group boundaries. `TransactionState`
  now advances a monotonic transaction-level VM budget, and completed resumable
  verification is checked against the per-transaction consensus limit rather
  than the temporary chunk budget.
- CKB default production acceptance and final hardening now both pass after
  removing bundled non-production artifacts from the acceptance script,
  closing all strict original compile blockers, replacing every handwritten
  business-action harness with builder-backed transaction construction, and
  measuring cycles, consensus tx bytes, and occupied capacity for every action:
  `target/ckb-cellscript-acceptance/20260424-120540-35142/ckb-cellscript-acceptance-report.json`.
- `scripts/ckb_cellscript_acceptance.sh` defaults to production mode. Production
  mode fails closed if any coverage still depends on standalone/portable
  harnesses, expected fail-closed entries, or non-original artifacts. Use
  `scripts/ckb_cellscript_acceptance.sh --bounded` only for the development
  coverage matrix.
- Latest default production gate result:
  - `production_gate.status: passed`;
  - `production_ready: true`;
  - bundled strict-admitted examples: all seven bundled examples;
  - strict original bundled-example policy failures: `[]`;
  - original scoped action fail-closed count: `0`;
  - original scoped lock fail-closed count: `0`;
  - on-chain action harness counts: token 4, NFT 9, timelock 10, multisig 8,
    AMM 6, launch 2, vesting 4, plus one artifact deployment/run check.
- The same acceptance report now also emits a stricter
  `final_production_hardening_gate`:
  - it is intentionally separate from `production_gate`;
  - `production_gate` still means the local original-scoped CKB production
    matrix is closed;
  - latest result:
    - `final_production_hardening_gate.status: passed`;
    - `final_production_hardening_gate.ready: true`;
    - `builder_backed_action_count: 43`;
    - `handwritten_harness_action_count: 0`;
    - `tx_size_measured_action_count: 43`;
    - `occupied_capacity_measured_action_count: 43`;
  - the hardening gate is now closed because the same 43 bundled business
    actions are executed by builder-generated transactions and acceptance
    records measured cycles, consensus-serialized tx size, and exact
    occupied-capacity evidence for all of them.
- CKB scoped artifact coverage is now a hard compile/verify gate:
  - latest production report:
    `target/ckb-cellscript-acceptance/20260423-133044-38607/ckb-cellscript-acceptance-report.json`;
  - original scoped actions admitted: 43;
  - original scoped locks admitted: 15;
  - expected original scoped action gaps fail-closed by policy: 0;
  - expected original scoped lock gaps fail-closed by policy: 0.
- CKB acceptance now emits `ckb_business_coverage`, which compares source
  action/lock definitions against strict CKB compile coverage and real CKB
  on-chain action harness coverage. The matrix is source-validated at runtime,
  so adding or removing an example action/lock without updating the production
  coverage expectations fails the gate.
- Latest CKB compile coverage is complete under the production source matrix:
  - source actions: 43;
  - strict CKB actions: 43;
  - expected fail-closed actions: 0;
  - source locks: 15;
  - strict CKB locks: 15;
  - compile coverage has no expected fail-closed scoped actions.
- CKB action harness coverage now matches scoped compile coverage under the
  default production matrix:
  - original scoped token harnesses cover `mint`, `transfer_token`, `burn`,
    and `merge` from `cellscript/examples/token.cell`;
  - original scoped NFT harnesses cover `mint`, `transfer`, `create_listing`,
    `cancel_listing`, `buy_from_listing`, `create_offer`, `accept_offer`,
    `batch_mint`, and `burn` from `cellscript/examples/nft.cell`;
  - original scoped timelock harnesses cover `create_absolute_lock`,
    `create_relative_lock`, `lock_asset`, `request_release`,
    `request_emergency_release`, `approve_emergency_release`,
    `execute_release`, `execute_emergency_release`, `extend_lock`, and
    `batch_create_locks` from `cellscript/examples/timelock.cell`;
  - original scoped multisig harnesses cover `create_wallet`,
    `propose_transfer`, `add_signature`, `propose_remove_signer`,
    `propose_add_signer`, `propose_change_threshold`, `execute_proposal`,
    and `cancel_proposal` from `cellscript/examples/multisig.cell`;
  - original scoped launch harnesses cover `simple_launch` and
    `launch_token` from `cellscript/examples/launch.cell`;
  - original scoped AMM harnesses cover `seed_pool`, `swap_a_for_b`,
    `add_liquidity`, `remove_liquidity`, `isqrt`, and `min` from
    `cellscript/examples/amm_pool.cell`;
  - original scoped vesting harnesses cover `create_vesting_config`,
    `grant_vesting`, `claim_vested`, and `revoke_grant`.
- Entry witness ABI now supports scalar arguments that spill past a0-a7 onto
  the caller stack. Schema-backed and fixed-byte pointer/length arguments still
  fail closed if their two-slot ABI pair would cross the register boundary.
- CKB entry-scoped compilation is available through `--entry-action` and
  `--entry-lock`. It narrows IR, metadata, and target-profile policy to the
  selected entry and its reachable pure functions/types, so portable actions or
  locks can produce CKB artifacts without admitting unrelated dynamic entries
  from the same file.
- Fixed enum fields are now represented in fixed Molecule schema metadata as a
  one-byte enum tag alias, closing the previous false blocker for entries such
  as `TimeLock.lock_type`. Payload enums remain dynamic and fail closed until
  their Molecule layout and verifier semantics are implemented.
- Entry-scoped type closure now keeps inline `Vec<T>` element dependencies, so
  scoped CKB compiles retain nested fixed structs such as `Vec<Signature>` in
  generated Molecule schemas.
- Standalone CellScript and the Spora submodule have matching source changes
  for the entry witness ABI, entry-scoped compile, and fixed enum schema fixes.
- CellScript metadata now includes a profile-aware `constraints` section, and
  `cellc constraints` can emit it without writing the full artifact/metadata
  pair. This is the compiler-facing production constraints surface:
  - `entry_abi` reports action/lock parameter count, ABI slots used,
    a0-a7 register slots, caller-stack spill slots/bytes, witness payload
    bytes, pointer/length pair placement, and unsupported parameter reasons;
  - `artifact` reports artifact bytes and backend shape metrics when assembly
    can be analyzed, including text/rodata bytes, relaxed branch count,
    maximum conditional branch distance, machine block/edge/call-edge counts,
    and unreachable machine blocks;
  - `ckb` reports the Blake2b/Molecule hash domain, script hash algorithm,
    transaction hash algorithm, sighash algorithm, supported script
    `hash_type` set, declared type-id hash_type, configured
    `max_tx_verify_cycles`, `max_block_cycles`, `max_block_bytes`, code-cell
    data capacity lower bound, recommended code cell capacity margin, entry
    witness byte bounds, tx-size measurement requirements, occupied-capacity
    measurement requirements, and explicit `dry_run_required_for_production`;
  - `spora` reports v1 compute/storage/transient/code-deployment mass
    estimates, configured standard block mass, standard relay transaction mass,
    standard tx/block fit estimates, and whether the compiler estimate would
    require a relaxed mass policy;
  - CKB limits can be overridden with
    `CELLSCRIPT_CKB_MAX_TX_VERIFY_CYCLES`,
    `CELLSCRIPT_CKB_MAX_BLOCK_CYCLES`, and
    `CELLSCRIPT_CKB_MAX_BLOCK_BYTES`; Spora standard block and relay tx mass
    can be overridden with `CELLSCRIPT_SPORA_MAX_BLOCK_MASS` and
    `CELLSCRIPT_SPORA_MAX_STANDARD_TRANSACTION_MASS`.
- `build --json`, `check --json`, and `verify-artifact --json` now carry the
  same constraints object so CI, wallet builders, and acceptance scripts can
  consume it without parsing prose logs.
- The current constraints report is explicit about the boundary between
  compiler-visible limits and builder/acceptance-measured values: CKB cycles
  and tx size remain builder/dry-run measured, occupied capacity is marked as a
  measurement requirement for output-producing artifacts, and Spora mass uses
  the same standard tx/block limits as production acceptance while still
  treating devnet/builder confirmation as authoritative.
- The CKB acceptance script now records both positive scoped coverage and
  expected fail-closed scoped gaps. A gap entry that starts compiling is treated
  as a failing gate until its transaction harness and malformed matrix are
  reviewed and the matrix is updated deliberately.
- Dynamic persistent layouts no longer use fake offset-0 field access. Read-only
  fixed-width table fields are decoded through Molecule offsets; mutable state
  transitions for types whose fixed encoded size is unknown still report
  explicit mutable-state runtime requirements until dynamic preserved-field
  verification exists.
- Dynamic persistent types now still receive `molecule-table-v1` schema metadata
  with explicit `dynamic_fields`, so package/build tooling can see the intended
  table layout. CKB verifier codegen now supports read-only fixed-width field
  access through Molecule table offsets, which admits `nft.cell::collection_creator`
  as an original scoped CKB lock. CKB verifier codegen also supports read-only
  fixed-element Molecule vector length, index, and iteration checks for table
  fields, which admits `timelock.cell::emergency_approved`,
  `multisig.cell::is_signer_lock`, and the read-only `multisig.cell` proposal
  locks. Payload enum fields are represented as dynamic Molecule bytes fields
  rather than one-byte enum tags, which admits read-only fixed-field paths such
  as `timelock.cell::asset_matches`, `execute_release`, and
  `execute_emergency_release`. Dynamic Molecule table mutation now has
  table-aware preserved-field equality and fixed scalar transition checks for
  selected replacement-output paths, which admits `nft.cell::mint` and removes
  mutable-state debt from multisig proposal/signature mutation metadata.
  Dynamic Molecule table create-output verification can now compare dynamic
  output fields against schema-pointer entry arguments, which admits
  `timelock.cell::lock_asset`. Fixed-element Molecule vector length/index over
  schema-pointer entry parameters now also supports duplicate-signer guards,
  which admits `multisig.cell::create_wallet`. Dynamic Molecule table
  create-output verification now also checks fixed/scalar table fields through
  Molecule field offsets instead of fixed-struct offsets, which lets original
  `multisig.cell::create_wallet` run on-chain.
  Scalar create-output and mutate-transition verifier paths now preserve
  decoded actual values across expected-expression evaluation and dynamic table
  output decoding, which lets original `multisig.cell::propose_transfer`
  verify `Proposal.proposal_id` and `MultisigWallet.nonce` on-chain.
  Empty dynamic vectors, fixed-element vector append checks, and local
  constructed byte-vector outputs now cover selected create/mutate paths:
  `multisig.cell::propose_transfer`, `multisig.cell::add_signature`,
  `multisig.cell::propose_remove_signer`,
  `multisig.cell::propose_change_threshold`,
  `timelock.cell::request_emergency_release`, and
  `timelock.cell::approve_emergency_release` are strict-admitted. CKB action
  harness coverage now matches scoped compile coverage under the default
  production matrix, with no expected fail-closed entries and no full-file
  strict original policy failures.
- CKB target-profile policy now treats Spora scheduler touch metadata as
  metadata, not as an automatic portability blocker. A shared create/read/mutate
  path is rejected only when its actual state semantics remain runtime-required.
  This admits `vesting.cell::create_vesting_config`, whose shared create output
  fields and lock binding are verifier-covered.
- AMM `seed_pool` now runs as an original scoped CKB harness with real Token
  inputs, Pool and LPReceipt outputs, token-pair admission, positive reserve
  checks, fee bounds, LP supply coupling, output lock binding, and malformed
  output rejection. This closure exposed and fixed two compiler bugs: scoped
  entry artifacts did not retain called action helpers such as `isqrt`, and
  mutable `let` bindings could alias a parameter stack slot (`let mut x = n`)
  and corrupt helper semantics. `add_liquidity` closure then exposed and fixed
  two CKB entry/runtime ABI bugs: stack-spilled fixed-byte parameters past a0-a7
  were fail-closed, and runtime-loaded cell `type_hash()` values used scratch
  storage whose size word could be overwritten before output-field coupling.
  `remove_liquidity` closure then proved the same typed runtime path for
  LPReceipt burn, Pool reserve/LP supply subtraction, Token withdrawal outputs,
  and malformed withdrawal rejection. `swap_a_for_b` closure then made AMM swap
  resource conservation CKB-admitted through checked pool symbol admission,
  fee accounting, constant-product pricing, TokenB output verification, Pool
  reserve replacement, and malformed swap output rejection. AMM now has no
  expected fail-closed scoped actions under the CKB production matrix.
- `env::current_timepoint()` is the cross-chain time API. It lowers to Spora
  DAA score under the Spora target profile and to the CKB header epoch number
  under the CKB target profile. `env::current_daa_score()` remains Spora-only
  and still fails CKB policy.
- Fixed-byte schema field comparisons now preserve both source pointers across
  verifier bounds checks before calling the shared memcmp helper. This fixed the
  CKB on-chain `token.merge` harness, where `a.symbol == b.symbol` previously
  failed because the right-side bounds check clobbered the left pointer register.
- Fixed-byte entry parameters whose width is eight bytes or smaller can now be
  used as create-output field expectations. Fixed aggregate tuple fields can
  now be used as addressable byte sources for output lock-hash verification,
  and verifier expression temp slots are large enough for the original
  eight-recipient launch sum. The original scoped CKB
  `launch.cell::simple_launch` harness now covers a valid launch transaction
  and a malformed output rejection.
- The CKB NFT marketplace harnesses now cover `buy_from_listing` and
  `accept_offer` on-chain. These tests exposed a verifier-shape constraint:
  create-output verification cannot safely read receipt fields after that
  receipt has been destroyed and cleared, and expression aliases over destroyed
  receipts can be re-expanded during output verification. The portable CKB
  path now makes marketplace counterparties and accepted price explicit entry
  ABI arguments, so valid transactions verify on-chain and malformed payment
  outputs are rejected by script logic.
- The CKB multisig harnesses now cover every `multisig.cell` action on-chain
  with valid transactions, malformed script-logic rejections, and committed
  outputs. Original scoped artifacts are used for `create_wallet`,
  `propose_transfer`, `add_signature`, `propose_remove_signer`,
  `propose_change_threshold`, `execute_proposal`, and `cancel_proposal`.
  `propose_add_signer` and `propose_change_threshold` now use original scoped
  artifacts after the metadata/codegen path learned to prove local constructed
  byte vectors (`Vec::new` plus `extend_from_slice` or `push`) as Molecule
  bytes create-output fields.
  The harness also exposed a
  real CKB packaging constraint: typed data outputs need enough capacity and a
  nonzero effective fee, because dry-run can pass while a local node refuses to
  package an otherwise valid zero-fee or under-capacity transaction.
- The CKB acceptance harness now deploys CellScript scripts with
  `hash_type = data1`. Using `hash_type = data` selects the legacy CKB VM
  version and caused syscall-heavy CellScript artifacts to fail with
  `MemWriteOnExecutablePage`; `data1` selects the VM version required by the
  generated RISC-V code while preserving ordinary data-hash code-cell
  addressing.
- The NFT `batch_mint`, timelock `batch_create_locks`, and launch
  `launch_token` CKB harnesses now run as original scoped production actions.
  The batch NFT harness also exposed a real capacity/packaging bug: a dry-run
  transaction with four NFT outputs and a replacement collection output could
  verify but fail to commit when the input capacity was underfunded. The
  harness now funds the batch transaction with enough capacity and reports the
  last node status when a submitted transaction does not commit.

The CKB bundled-example production gap is closed for the current local suite.
The default production gate has no missing on-chain actions, no expected
fail-closed entries, and no full-file strict original policy failures. The
final hardening gate is also closed: all 43 bundled business actions are
builder-backed, and acceptance records measured cycles, consensus-serialized
transaction bytes, and exact occupied-capacity evidence. Broader adversarial
coverage, external audit, and long-running release artifact retention are
post-release assurance work, not blockers in the current local production gate.

The timelock `lock_asset`, `request_release`, and `request_emergency_release`
bounded CKB harnesses now use original scoped `timelock.cell` artifacts.
`lock_asset` exercises a mixed dynamic Molecule table where
`LockedAsset.asset_type` is dynamic and `amount`/`lock_hash` are fixed fields.
`request_emergency_release` exercises a dynamic `EmergencyRelease` table with
a dynamic reason field and an empty `Vec<Address>` approval set.
`approve_emergency_release` now verifies dynamic `Vec<Address>` append
semantics against the original artifact, both release execution paths now
verify original `ReleaseRecord` outputs, and `batch_create_locks` now verifies
four TimeLock outputs on-chain. Additional CKB time/header cases and malformed
lifecycle matrices are post-release expansion items.

The CKB harness for `nft.cell::create_listing` exposed and then closed a real
production gap: strict compilation admitted the action, but the entry wrapper
did not bind read-only schema parameters such as `&NFT` to input cell data for
transaction execution. The compiler now binds uncovered read-only schema
entry parameters to CKB Inputs before verifier field checks run, allowing
created output fields copied from a read-only input cell to be checked on-chain.

## Production Definition

Production-grade dual-chain support means:

- One CellScript source semantics layer with explicit `spora`, `ckb`, and
  `portable-cell` target profiles.
- Spora artifacts compile, deploy, execute valid actions, reject malformed
  actions, and preserve Spora scheduler/Molecule ABI behavior.
- CKB artifacts compile with CKB syscall/source/hash/header/packaging rules,
  deploy to a local CKB devnet, execute valid original actions, and reject
  malformed transactions by script logic.
- All bundled examples are release-gate contracts, not only documentation
  examples.
- Public CellScript and VM-facing bytes use Molecule; Borsh is not a public
  CellScript/CKB wire format.
- Artifact metadata, schema metadata, package lockfiles, backend shape reports,
  and acceptance reports are deterministic CI artifacts.

Base devnet probes remain useful only as regression tests. Production readiness is
defined by the structured Spora production gate, the CKB production gate, and
the CKB final hardening gate.

## Bundled Example Closure Matrix

Every bundled example is now covered by strict original execution on both
chains in the local acceptance suite.

| Example | Spora target | CKB current state | CKB production closure |
|---|---|---|---|
| `token.cell` | Compiles under `spora`; scoped Spora `mint`, `transfer_token`, `burn`, and `merge` run as real devnet action-builder transactions with malformed rejection coverage. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Strict admitted; original scoped CKB mint/transfer/burn/merge run on-chain with builder-backed valid transactions, measured constraints, and malformed script rejection. | Broaden malformed witness/data/type/dep matrices and external audit coverage. |
| `nft.cell` | Compiles under `spora`; scoped Spora `transfer`, `create_listing`, `cancel_listing`, `buy_from_listing`, `create_offer`, `accept_offer`, `burn`, `mint`, and `batch_mint` run as real devnet action-builder transactions with malformed rejection coverage. `mint` and `batch_mint` use Collection/NFT Molecule table data, real scoped code-cell deployment, indexed output checks, and compiled scheduler witnesses. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. All original scoped CKB actions run on-chain with builder-backed transactions: `mint`, `transfer`, `create_listing`, `cancel_listing`, `buy_from_listing`, `create_offer`, `accept_offer`, `batch_mint`, and `burn`; lock `collection_creator` compiles. `batch_mint` verifies four NFT outputs plus collection replacement with measured capacity. | Add collection lineage hardening, metadata/data-hash rules, marketplace counterparty binding, and broader malformed owner/type/data cases. |
| `timelock.cell` | Compiles under `spora`; all scoped Spora timelock actions run as real devnet action-builder transactions with malformed rejection coverage. Builders deploy scoped code cells, seed executable script-locked fixture cells, encode fixed and Molecule table data, preserve mutating type/lock identity, and attach compiled scheduler witnesses. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. All original scoped CKB actions and locks compile, and every action runs on-chain with builder-backed transactions: `create_absolute_lock`, `create_relative_lock`, `lock_asset`, `request_release`, `request_emergency_release`, `approve_emergency_release`, `execute_release`, `execute_emergency_release`, `extend_lock`, and `batch_create_locks`. | Broaden malformed time/output/type/dependency cases and external audit coverage. |
| `multisig.cell` | Compiles under `spora`; all scoped Spora multisig actions run as real devnet action-builder transactions with malformed rejection coverage. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. All original scoped CKB actions compile and run on-chain with builder-backed transactions: `create_wallet`, `propose_transfer`, `add_signature`, `propose_add_signer`, `propose_remove_signer`, `propose_change_threshold`, `execute_proposal`, and `cancel_proposal`; all original locks compile: `is_signer_lock`, `can_execute`, `can_cancel`, `has_enough_signatures`, `not_expired`. | Broaden malformed signer/threshold/signature/expiry matrices. |
| `vesting.cell` | Compiles under `spora`; scoped Spora `create_vesting_config`, `grant_vesting`, `claim_vested`, and `revoke_grant` run as real devnet action-builder transactions with malformed rejection coverage. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. All original scoped CKB actions compile and run on-chain with builder-backed transactions: `create_vesting_config`, `grant_vesting`, `claim_vested`, and `revoke_grant`. `grant_vesting` uses `env::current_timepoint()` and verifies real Token/Vesting cells, header-dep timepoint, and malformed output rejection. `claim_vested` and `revoke_grant` verify authorization and output relations. | Broaden malformed schedule/claim/revoke cases and type-script deployment coverage where useful. |
| `amm_pool.cell` | Compiles under `spora`; scoped Spora `seed_pool`, `swap_a_for_b`, `add_liquidity`, `remove_liquidity`, `isqrt`, and `min` run through the current production matrix. Mutating builders deploy scoped action artifacts, seed typed Token/Pool/LPReceipt fixture cells, verify Pool replacement identity, LP supply coupling, proportional add/remove accounting, swap output pricing, provider/recipient lock binding, and malformed reserve/output rejection. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. All original scoped CKB AMM entries compile and run on-chain with builder-backed transactions: `seed_pool`, `swap_a_for_b`, `add_liquidity`, `remove_liquidity`, `isqrt`, and `min`. The harnesses verify real Token inputs, Pool/LPReceipt outputs, Pool replacement identity, LP supply coupling, add/remove proportional accounting, swap fee accounting, constant-product output pricing, Token output symbols/amounts, TypeHash binding, and malformed output rejection. | Broaden malformed slippage/symbol/type/capacity matrices. |
| `launch.cell` | Compiles under `spora`; scoped Spora `simple_launch` and `launch_token` run as real devnet action-builder transactions with malformed rejection coverage. Builders deploy scoped action artifacts, seed executable script-locked fixture cells, create MintAuthority plus Token output sets, verify allocation and distribution shape, and reject malformed outputs. The full-file code-cell deployment is accepted/indexed under standard mass policy. | Whole original CKB compile passes. Original scoped `simple_launch` and `launch_token` run on-chain with builder-backed transactions, fixed-recipient distribution ABI, valid output coverage, pool-composition runtime checks, and malformed-output rejection. | Broaden sale lifecycle, cap/allocation/finalization, and malformed phase/allocation cases. |

Production exit criterion:

- `scripts/ckb_cellscript_acceptance.sh` passes in default production mode.
- `strict_original_ckb_compile_policy_fail_closed == []`.
- `strict_original_ckb_compile_unexpected_failures == []`.
- CKB acceptance `production_gate.status == "passed"`.
- Spora devnet acceptance `production_gate.production_ready == true`.
- Every on-chain CKB action harness is compiled from the original bundled
  source with `kind == "original-scoped-action-strict"`.
- All 43 bundled source actions have valid Spora action-builder transaction
  coverage and malformed rejection coverage.
- All 43 bundled source actions have valid builder-backed CKB transaction
  coverage and malformed rejection coverage.
- Each bundled example has malformed transactions rejected by script logic, not
  by standardness, mass, capacity, transient node state, missing plumbing, or
  cycle-limit accidents.

## Phase A: CKB Strict Original Closure

Goal: make every bundled example compile and verify as an original `ckb` profile
artifact without non-production acceptance shortcuts.

Status: closed for the current bundled CKB suite.

Closed work items:

1. All seven bundled examples strict-admit as original CKB profile sources.
2. All 43 source actions and all 15 locks strict-compile without expected
   fail-closed gaps.
3. Every bundled business action has an original-scoped on-chain production
   harness, including NFT batch mint, timelock batch lock creation, AMM flows,
   multisig lifecycle actions, vesting lifecycle actions, and both launch
   actions.
4. The default production gate rejects standalone/portable/base-probe/compile-only
   evidence and reports `production_ready=true` only when the on-chain
   production matrix passes.
5. The final hardening gate records builder-backed transactions, measured
   cycles, consensus-serialized transaction bytes, and occupied-capacity
   evidence for all 43 actions.

Required tests:

- `cargo test -p cellscript --test examples`
- `cargo test -p cellscript --test cli ckb`
- `scripts/ckb_cellscript_acceptance.sh --production` against the parent CKB
  local devnet
- `scripts/ckb_cellscript_acceptance.sh --compile-only --production` as a
  compile-coverage diagnostic, not as release evidence
- `scripts/ckb_cellscript_acceptance.sh --bounded` only as a development
  diagnostic, not as release evidence

## Phase B: Molecule Schema Productionization

Goal: make generated persistent CellScript schemas the authoritative layout for
Spora and CKB.

Work items:

- Generate schema manifests for `resource`, `shared`, and `receipt`.
- Cover fixed-width structs, nested fixed structs, enums, fixed arrays/tuples,
  dynamic vectors/strings, and versioned layout migration policy.
- Emit schema hash, version, field offsets, dynamic sections, and target-profile
  compatibility in metadata.
- Make verifiers decode cell data through generated schema logic rather than
  ad hoc offsets.
- Make transaction builders use the same schema manifest for input/output data.
- Add schema snapshot tests for every bundled example.

Exit criteria:

- Every bundled example has a generated schema manifest.
- Spora and CKB acceptance construct cell data from the manifest.
- Schema changes are either backward-compatible or intentionally versioned.

## Phase C: Action Transaction Builder

Goal: users should not hand-write Spora or CKB transaction JSON to use a
CellScript contract.

Proposed future CLI target:

```bash
cellc action build examples/token.cell \
  --target-profile ckb \
  --action transfer_token \
  --arg to=... \
  --arg amount=100 \
  --input token_cell=... \
  --out tx.json
```

Builder responsibilities:

- Read artifact metadata and schema manifest.
- Encode action arguments and witnesses.
- Select required code deps, cell deps, header deps, input cells, and output
  templates.
- Emit Spora and CKB transaction skeletons through profile adapters.
- Support `dry-run`, `explain`, `inspect`, and malformed-case generation for
  tests.

Exit criteria:

- Every bundled example tutorial can build a valid Spora transaction and a valid
  CKB transaction from CLI inputs.
- Acceptance scripts use the builder instead of bespoke Python transaction
  constructors for the main path.

## Phase D: Dual-Chain Acceptance Gates

Goal: release gates prove both chains still work, with comparable artifacts.

Fast gate:

- format/check/test for CellScript and Spora integration crates;
- all examples compile to assembly and ELF;
- Spora/CKB target-profile policy tests;
- backend shape budget JSON;
- schema snapshot tests;
- package manager and LSP regression tests.

Medium gate:

- Spora devnet acceptance;
- CKB compile-only acceptance;
- strict original metadata verification for every bundled example;
- package lock reproducibility.

Full gate:

- Spora full devnet acceptance;
- CKB full local devnet acceptance against the parent CKB checkout;
- every bundled example valid action path;
- every bundled example malformed transaction matrix;
- artifact upload for backend shape, schemas, Spora report, CKB report, and
  package lock verification.

Exit criteria:

- GitHub Actions saves all reports as artifacts.
- Release tags cannot be created without a passing full dual-chain gate.

## Phase E: Package Manager and Tooling RC

Goal: make CellScript usable as an independent production toolchain.

Work items:

- Keep CellScript as the canonical standalone repository and Spora as the
  submodule consumer.
- Publish deterministic release binaries with checksums.
- Stabilize `Cell.toml`, `Cell.lock`, local path dependencies, remove/prune,
  install, info, doc, fmt, check, build, metadata, and verify-artifact.
- Keep registry publishing and remote package resolution fail-closed until the
  verification model is finished.
- Extend LSP with target-profile diagnostics, action metadata preview, schema
  preview, package errors, and production-gate warnings.

Exit criteria:

- A fresh user can install CellScript, compile bundled examples, build
  transactions, and run Spora/CKB local devnet tutorials without repo-internal
  scripts.

## Phase F: Security and External Audit Readiness

Goal: make the dual-chain toolchain auditable.

Required audit package:

- syscall/source/hash/header profile delta;
- Molecule schema and witness ABI spec;
- artifact metadata and verification spec;
- transaction builder threat model;
- package manager trust model;
- backend CFG/branch-relaxation/code-size report;
- Spora and CKB acceptance reports;
- known limitations list.

Required adversarial coverage:

- malformed witness fuzzing;
- Molecule decode fuzzing;
- random output mutation;
- wrong cell dep/type hash/lock hash;
- capacity/mass/cycles boundary tests;
- profile isolation tests ensuring Spora-only syscalls cannot leak into CKB
  artifacts.

## Non-Negotiable Boundaries

- Do not claim full CKB production support until all original bundled examples
  strict compile and run action-specific CKB transactions.
- Do not claim VM-plumbing deployment/spend success as business-action support.
- Do not use `--bounded` results as release evidence for CKB production.
- Do not mark CKB `production_ready=true` unless the default production CKB gate
  passes.
- Do not mark Spora `production_gate.production_ready=true` unless
  `scripts/devnet_acceptance.sh --profile production` passes under standard
  mass policy with scoped Spora action artifacts, compiled scheduler-shape
  preflight coverage, audited per-action builder requirements,
  action-specific valid builder coverage, and malformed action-matrix coverage.
- Do not reintroduce public Borsh CellScript/CKB wire formats.
- Do not let Spora support regress while closing CKB support.
- Do not weaken target-profile policy gates to pass examples.
- Do not remove backend shape and report artifacts; code size is part of
  production safety for on-chain deployment.

## Immediate Next Work

1. Keep `scripts/devnet_acceptance.sh --profile production` as the Spora
   release gate and fail it on any scoped-action, malformed-matrix,
   scheduler-witness, standard-mass, or full-file deployment regression.
2. Keep `scripts/ckb_cellscript_acceptance.sh --production` as the CKB release
   gate and fail it on any fallback to standalone, portable,
   expected-fail-closed, base-probe, or compile-only evidence.
3. Save Spora production reports, CKB production reports, CKB final hardening
   reports, backend shape reports, constraints JSON, schema manifests, and
   package lock verification as release artifacts.
4. Add generated schema manifests and snapshot tests for every bundled example,
   with deeper focus on NFT, timelock, multisig, AMM, launch, and vesting
   dynamic Molecule paths.
5. Broaden malformed matrices for CKB and Spora NFT collection/metadata,
   timelock time/header semantics, launch lifecycle/allocation, AMM
   slippage/symbol/type, multisig threshold/signature/expiry, vesting
   schedule/claim/revoke, and token type/data/dependency cases.
6. Wire constraints reports into wallet and package-builder workflows so users
   see ABI, mass, capacity, fee, cycles, and artifact-size constraints before
   deployment.
7. Prepare external audit artifacts: syscall/profile delta, Molecule schema
   spec, witness ABI, builder threat model, package trust model, backend shape
   report, and latest Spora/CKB acceptance reports.
