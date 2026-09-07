---
name: cellscript-builder-deployment
description: Generated builders, action-aware scans, deployment plans, live registry verification, and evidence boundaries.
references:
  - docs/CELLSCRIPT_CKB_ADAPTER.md
  - docs/CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md
  - docs/CELLSCRIPT_PACKAGE_PROVENANCE_AND_DEPLOYMENT_IDENTITY.md
  - docs/CELLSCRIPT_PROTOCOL_BUNDLE.md
  - examples/ckb-sdk-builder/README.md
commands:
  - cellc action build
  - cellc gen-builder
  - cellc deploy plan
  - cellc deploy verify
  - cellc tx validate
  - cellc protocol bundle check
---

# CellScript Builder And Deployment

Use this skill for builder and deployment work. The compiler emits semantic
plans and metadata. Builders provide concrete live Cells, output data, CellDeps,
witnesses, capacity/fee evidence, dry-run evidence, signing, and optional
submission.

Do not claim CKB production readiness from compile-only evidence. A plain
`ActionPlan` is not a submitted transaction. A `ResolvedActionTx` is adapter
materialisation. `AcceptedActionTx` requires node-facing evidence.

Validation defaults:

- run `cellc action build --json` for action plan shape;
- inspect `action_scan_selectors` / `actionScanSelectors` for compile-only
  live-cell scan guidance derived from `transaction_runtime_input_requirements`;
- require runtime adapters to return `scanSelectorEvidence` for generated
  `actionScanSelectors`; missing or mismatched selector evidence is a
  pre-transaction builder failure, not a CKB acceptance claim;
- use `transaction_draft.scan_selector_evidence` for the equivalent
  materialised `ActionPlan` JSON consumed by the Rust adapter;
- run `cellc deploy plan --json` for deployment planning;
- run `cellc tx validate --json` against concrete transaction evidence.
- use `cellc protocol bundle check --json` to admit independent ELF artifacts;
  provide the generated builder manifest for every action entry and explicit
  `builder_assumption_evidence` required by each artifact's metadata;
- reject offline role/index/witness/dependency/policy conflicts and `PB212`
  metadata-assumption failures before signing; treat transaction
  serialization, CKB-VM, and chain evidence as unexecuted.
- pass a successful report with concrete input OutPoints, output data, and
  witness bytes to
  `cellscript_ckb_adapter::materialize_protocol_bundle_report`; require all
  per-group records to carry its exact serialized transaction hash and keep
  execution/chain evidence `not-executed` until a later adapter step runs them.
- use `CkbSdkAcceptance::dry_run_protocol_bundle` for node execution of those
  exact bytes; retain its aggregate cycles, null per-group cycles, uncommitted
  state, and separately unobserved spawned-verifier status.
- call `verify_protocol_bundle_live_inputs` before relying on input capacities
  or fee evidence; require exact chain identity and `live-node` capacity source,
  and remember that a successful query is still uncommitted state.
- call `verify_protocol_bundle_live_dependencies` with that live-input record;
  require every artifact code CellDep or expanded dep-group member to match its
  admitted ELF data hash and Script hash type before signing.
- build `ReadyToSignProtocolBundleTx`, run caller-owned SDK unlockers through
  `unlock_protocol_bundle_transaction`, dry-run the signed bytes, require bound
  tx-pool acceptance, and only then call `submit_signed_protocol_bundle`;
  submitted evidence remains uncommitted.
- generated TypeScript packages may use `bindProtocolBundleArtifact` and
  `createProtocolBundleClient`; keep signing resumable through the opaque
  `ProtocolBundleSigningRequest` and never add key material to bundle data.
