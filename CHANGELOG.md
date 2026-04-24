# Changelog

## 0.11.0 - 2026-04-23

- Release CellScript 0.11.0 as the standalone dual-chain compiler package.
- Close the current CKB bundled-example production acceptance suite: all seven
  examples strict-admit, all 43 actions and 15 locks strict-compile, and every
  bundled business action has an original-scoped on-chain production harness.
- Keep Spora compatibility intact while documenting the remaining Spora
  production hardening track around action builders, malformed matrices, and
  measured mass/cycle constraints.
- Preserve the production safety gates added in the 2026-04-23 development
  log: no CKB policy bypass, no unresolved-call ELF stubs, audit-only
  Wasm, tightened backend shape reporting, narrowed crates.io packaging, and
  explicit profile-aware constraints metadata.
- Promote the VS Code extension to production-grade local tooling with
  compiler-backed validation, formatting, scratch compilation, metadata and
  constraints reports, target-profile selection, status feedback, and stricter
  extension validation.

## 2026-04-23

- Marked Wasm output as audit-only instead of metadata-only production output.
- Renamed the legacy always-empty runtime metadata field to
  `legacy_symbolic_cell_runtime_features` and stopped emitting the old symbolic
  ELF feature surface.
- Reduced crates.io package contents by excluding GitHub workflow, wiki, and
  VS Code extension packaging files.
- Cleaned remaining clippy mechanical warnings and documented the intentional
  broad compiler-helper signature allowances so `cargo clippy --locked
  --all-targets -- -D warnings` is a release gate.
- Removed the remaining placeholder artifact-validation surface by returning a
  source-free `ValidatedArtifact` for metadata verification instead of building
  a synthetic AST.
- Removed the private legacy scheduler witness Borsh metadata/test helper and
  kept scheduler witness metadata Molecule-only.
- Marked Wasm report output as audit-only and excluded standalone docs from the
  crates.io package contents.
- Stripped externally-linked RISC-V ELF artifacts when an external toolchain is
  available, matching the internal production artifact surface more closely.
- Made external RISC-V toolchains explicit opt-in via `CELLSCRIPT_RISCV_CC` or
  `CELLSCRIPT_RISCV_AS`/`CELLSCRIPT_RISCV_LD`, so production ELF output and
  backend shape budgets no longer depend on tools accidentally present in PATH.
- Rebased the multisig bundled-example ELF budget on the deterministic internal
  ELF artifact size while keeping the assembly text/CFG budgets unchanged.
- Removed the executable Wasm pseudo-lowering path; the Wasm module now remains
  audit-only and rejects action/function modules instead of emitting approximate
  code.
- Removed empty module doc comments and simplified duplicated verifier branches
  reported by clippy.
- Clarified README CLI docs that `cellc test` is a compiler/policy harness, not
  trusted runtime execution.
- Removed the old CKB acceptance policy exception path so the CKB target
  profile now rejects unportable artifacts through the normal production policy
  gate.
- Removed unresolved-call ELF stub generation; production ELF emission now
  fails when a generated call target has not been lowered.
- Added executable cross-module callable linking for resolver-backed imports,
  so `launch.cell` links the real `seed_pool` callee and its transitive `isqrt`
  helper instead of relying on a synthetic fail-closed stub.
- Tightened launch example regression coverage to ensure imported callees are
  linked without pulling unrelated AMM actions into the artifact.
- Added `env::current_timepoint()` as a chain-neutral runtime time source:
  Spora lowers it to DAA score and CKB lowers it to header epoch number.
- Switched bundled `vesting.cell` to the chain-neutral timepoint API, allowing
  original scoped `grant_vesting` artifacts under the CKB target profile.
- Added original scoped CKB on-chain acceptance for
  `vesting.cell::grant_vesting` with real Token/VestingConfig inputs,
  VestingGrant output verification, header dependency timepoint input, and
  malformed output rejection.
- Marked dynamic Molecule vector `len()` results as verifier-covered u64
  transition sources, so `collection.total_supply += recipients.len()` style
  CKB mutations are checked at runtime instead of reported as mutable-cell
  transition blockers.
- Fixed fixed-aggregate field byte-source lowering so original CKB verifier
  output lock checks can compare tuple-array address fields without fail-closed
  traps.
- Increased verifier expression temp slots and added regression coverage for
  the original `launch.cell::simple_launch` eight-recipient remaining-output
  sum.
- Switched CKB acceptance launch coverage from a standalone portable harness to
  the original scoped `launch.cell::simple_launch` artifact.
- Fixed dynamic Molecule table create-output checks for fixed/scalar fields so
  original `multisig.cell::create_wallet` verifies table fields through
  Molecule offsets instead of fixed-struct offsets.
- Switched the CKB multisig `create_wallet` acceptance harness to the original
  scoped artifact with dynamic `Vec<Address>` signer data.
- Preserved scalar verifier values across expected-expression evaluation and
  dynamic output decoding, fixing original `multisig.cell::propose_transfer`
  CKB checks for `Proposal.proposal_id` and `MultisigWallet.nonce`.
- Switched the CKB multisig `propose_transfer` acceptance harness to the
  original scoped artifact with dynamic `MultisigWallet` and `Proposal`
  Molecule table data.
- Switched CKB multisig `add_signature`, `propose_add_signer`,
  `propose_remove_signer`, and `propose_change_threshold` acceptance to
  original scoped artifacts with dynamic `Proposal` table/vector data.
- Switched CKB multisig `execute_proposal` and `cancel_proposal` acceptance to
  original scoped artifacts, removing the last standalone on-chain action
  harnesses from the bounded CKB matrix.
- Fixed destroy lowering to retain consumed input pointers for post-destroy
  output verification while relying on the checked Output absence scan for the
  actual destroy rule.
- Fixed scalar output verification to prefer schema/prelude expression sources
  but use runtime stack values for ordinary scalar variables, covering
  branch/match-derived bool outputs such as `ExecutionRecord.success`.
- Switched CKB token `mint`, `transfer_token`, `burn`, and `merge` acceptance
  from standalone harness sources to original scoped `token.cell` artifacts.
- Switched CKB NFT non-batch action acceptance from standalone harness sources
  to original scoped `nft.cell` artifacts, including dynamic `Collection`
  Molecule table data for `mint`.
- Switched CKB timelock `create_absolute_lock`, `create_relative_lock`,
  `lock_asset`, `request_release`, `request_emergency_release`, and
  `approve_emergency_release`, `execute_release`, `execute_emergency_release`,
  and `extend_lock` acceptance from standalone harness sources to original
  scoped `timelock.cell` artifacts.
- Fixed the CKB Molecule vector append verifier to compare fixvec payload
  bytes after the 4-byte count header, enabling original dynamic approval-list
  append checks.
- Switched CKB AMM pure-entry `isqrt` and `min` acceptance from standalone
  harness sources to original scoped `amm_pool.cell` artifacts.

## 2026-04-22

- Tightened backend CFG reachability analysis so unreachable-block metrics are rooted at the selected ELF entry label instead of treating every `.global` text symbol as reachable.
- Added a regression test proving unused global exports are still counted as unreachable from the entry root.
- Removed obsolete `global_text_labels` parser storage after entry-root reachability replaced global-root reachability.
- Rebased bundled-example unreachable-block budgets on the stricter entry-root metric while keeping call-edge and CFG shape budgets enforced.
- Declared Rust 1.85.0 as the standalone crate MSRV so CI and users run with Cargo support for Edition 2024 dependencies.
- Updated standalone CI to archive backend-shape reports as release evidence.
- Added a committed standalone `Cargo.lock` and changed standalone CI to run with `--locked`.
