# CellScript CKB Adapter

**Status**: production contract for the current CellScript CKB profile. The
headless Rust adapter crate landed in the 0.19 line; 0.21 extends the builder
resolution surface with materialised action plans, action-aware scan selector
evidence, variable-length `args_parts`, manifest-backed CellDep completion, and
fail-closed live-cell evidence validation. The 0.30 development line adds
byte-exact ProtocolBundle transaction materialization while keeping group
execution and chain evidence explicit.

This document defines which CKB-facing responsibilities belong to CellScript,
`ckb-std`, `ckb-sdk-rust`, and the adapter.

CellScript is the semantic compiler. `ckb-std` is the contract-side ABI/runtime
oracle. `ckb-sdk-rust` is the transaction realiser. The adapter is the boundary
object between compiler outputs and real CKB transactions.

In practical terms:

```text
CellScript emits verified transaction intent.
cellscript-ckb-adapter realises that intent through ckb-sdk-rust.
CKB node acceptance is the production evidence.
```

The compiler should stay focused on artifacts, metadata, ABI, deployment plans,
action plans, witness bytes, and CKB constraints. The adapter should use those
outputs to construct, sign, preflight, validate, and optionally submit real CKB
transactions with machine-readable evidence.

## Boundary

The compiler core must not depend on `ckb-sdk-rust`.

Keeping the SDK out of compiler core preserves offline compilation, metadata
inspection, static checks, package workflows, and future non-CKB target profiles
without dragging in CKB RPC, indexer, signing, or node-version concerns.

The split is:

| Layer | Responsibility |
|---|---|
| `cellc` compiler | Parse, type-check, lower, emit artifact, metadata, ABI, constraints, action build plan, entry witness bytes, deploy plan. |
| `ckb-std` | Provide the contract-side Rust reference for CKB syscalls, sources, witnesses, TYPE_ID, since, and exec/spawn semantics. |
| `cellscript-ckb-adapter` | Load compiler outputs, verify hashes and schemas, resolve deployments, materialise CKB transaction shape, attach evidence. |
| `ckb-sdk-rust` (5.x) | Provide CKB data structures, sync and async RPC / indexer clients, `CellCollector` (Default / Offchain / LightClient), `CellDepResolver`, `HeaderDepResolver`, `Signer` and lock-specific `ScriptUnlocker` implementations (SecpSighash, SecpMultisig Legacy/V2, ACP, Cheque, OmniLock), `CapacityBalancer` / `CapacityProvider`, protocol-specific `tx_builder` modules (acp, cheque, dao, omni_lock, transfer, udt), `unlock_tx` / `unlock_tx_async`, tx-pool acceptance, and submission. |
| CKB node | Estimate cycles, accept or reject the transaction, and provide the chain-facing evidence boundary. |

This avoids making CellScript a wallet, indexer, signer, or submission layer.
It also avoids pretending that compiler success is the same as node acceptance.

## Inputs And Outputs

The adapter consumes compiler-side records:

```text
compiled artifact bytes
CompileMetadata
cellc action build JSON
cellc entry-witness bytes
cellc deploy plan JSON
cellc deploy lock-deps JSON
constraints.ckb
successful cellc protocol bundle check JSON
```

It should emit chain-side records:

```text
DeploymentManifest
ActionPlan
ResolvedActionTx
AcceptedActionTx
AcceptanceReport
LiveOutputLineage
MaterializedProtocolBundleTx
```

Every adapter-owned JSON/TOML record must include an explicit `schema` and
`version`. Schema drift must fail closed. The adapter should never silently
reinterpret metadata emitted by a newer compiler schema.

## Implementation Shape

The reusable implementation lives in the formal adapter crate:

```text
crates/cellscript-ckb-adapter/
```

It parses compiler `ActionPlan` JSON, materializes `ResolvedActionTx` values
with `ckb-sdk-rust` / CKB packed types, rejects under-capacity outputs before
RPC, and exposes signer, `estimate_cycles`, `test_tx_pool_accept`, and optional
submission as adapter-owned node calls. It also builds unsigned deploy
transactions that create either TYPE_ID code Cells or immutable data Cells from
a `DeployArtifactSpec`, and
generates `DeploymentManifest` records from the resulting evidence. It also
tests that CellScript entry witness bytes use the versioned
`cellscript-witnessargs-input-type-v2` contract and are placed into
`WitnessArgs.input_type` before SDK signing while preserving the lock
placeholder. A signed multisig-v2 CKB-VM regression verifies both the lock and
the CellScript type script, and proves that post-signing witness mutation is
rejected. TYPE_ID args are computed from the packed first input plus output
index before adapter submission.

The full transaction lifecycle bridge includes:

| Bridge component | SDK 5.x integration | Purpose |
|---|---|---|
| `ManifestCellDepResolver` | `ckb_sdk::traits::CellDepResolver` | Maps deployment manifest entries to concrete CellDeps by code_hash + hash_type |
| `TransactionSubmitter` | `CkbRpcClient` `send_transaction`, `get_transaction` | Submit + confirm + wait for commitment |
| `SigningAdapter` | `ckb_sdk::traits::Signer`, `ScriptUnlocker` | Tracks signing state and signer labels |
| `CapacityBridge` | `ckb_sdk::tx_builder::CapacityBalancer` | Builds balancer with change lock + fee rate |
| `TransactionLifecycleEvidence` | Combined evidence | Records full deploy/action → sign → balance → accept → submit → commit flow |

The cookbook wrapper lives at:

```text
examples/ckb-sdk-builder/
```

That crate depends on `cellscript-ckb-adapter` and exists to show the boundary.
It should not grow an independent implementation.

Current tests cover the offline adapter shape. Focused node evidence is covered
by `scripts/cellscript_ckb_adapter_acceptance.sh`.

## ProtocolBundle transaction materialization

`materialize_protocol_bundle_report()` is the first runtime-adapter step for a
checked multi-Script bundle. It rejects failed or hash-mismatched reports,
requires exact standalone and metadata-validation evidence for every selected
artifact, then builds one CKB packed transaction from concrete input OutPoints,
output data, witnesses, CellDeps, and HeaderDeps.

The returned `cellscript-protocol-bundle-materialization-v1` evidence binds the
bundle hash, raw transaction hash, complete serialized transaction hash and
size, capacity totals, fee remainder, exact code CellDep positions, and global
to group-relative indexes. Every selected Lock and Type artifact must occur in
a real transaction Script Group and have a matching bundle role. All group
records carry the same serialized transaction hash. The function checks
occupied capacity and witness commitments, but performs no RPC, signing, or
execution. Its CKB-VM and chain evidence fields therefore remain
`not-executed`; input capacity and fee remain skeleton-sourced until live Cell
resolution.

`verify_protocol_bundle_live_inputs()` upgrades those skeleton claims through
the node. It rejects a chain ID or genesis mismatch, non-live input, missing
cell data, reordered OutPoint, or any difference in packed CellOutput, data,
capacity, or fee. The resulting
`cellscript-protocol-bundle-live-resolution-v1` evidence uses
`capacity_source = live-node`. It is still uncommitted state and must be
refreshed before signing/submission when freshness matters.

`verify_protocol_bundle_live_dependencies()` consumes that exact live-input
record and resolves every artifact code CellDep. Direct code deps must expose
the admitted ELF bytes; dep-group roots must contain a canonical Molecule
`OutPointVec`, and every member is queried before matching the code. Data,
data1, and data2 identities require the code-data hash; type identities require
the live code Cell's Type Script hash, while all four modes independently
require the admitted ELF data hash. The result remains uncommitted and bound to
the same bundle, network, raw transaction, and complete serialization hash.

`protocol_bundle_ready_to_sign_evidence()` requires both live records before
signing. `unlock_protocol_bundle_transaction()` accepts caller-owned CKB SDK
`ScriptUnlocker` implementations, refuses any Lock Script Group left locked,
and never accepts private keys as an adapter data field. It requires the raw
transaction and all `WitnessArgs.input_type`/`output_type` fields to remain
byte-identical; only witness lock fields may change.

`dry_run_signed_protocol_bundle()` binds node execution and signature
verification to the signed serialization hash. `test_signed_protocol_bundle()`
then requires that dry-run and records the node's tx-pool cycles and fee.
`submit_signed_protocol_bundle()` validates the complete signed/tx-pool chain
before calling `send_transaction` and rejects a returned hash that differs from
the raw transaction hash. Its receipt says `submitted-uncommitted`; commitment
still requires a later status query.

`CkbSdkAcceptance::dry_run_protocol_bundle()` and the equivalent
`CellScriptAdapter` method call CKB `estimate_cycles` with that exact
transaction. A successful result produces
`cellscript-protocol-bundle-dry-run-v1`, preserves the aggregate cycles, and
marks each direct group as accepted under the same full-serialization hash.
Because the node RPC exposes one aggregate count, the report leaves individual
group cycles null and says so in `cycle_attribution`. This is executable node
dry-run evidence; tx-pool acceptance and chain confirmation remain false, and
spawned verifiers are not claimed as independently observed.

Do not start with a framework. Start with cookbook-grade examples that complete
real deployment and transaction acceptance loops.

## Deployment Probe

The first useful adapter flow is code-cell deployment:

```text
CellScript artifact binary
+ deploy plan
+ constraints.ckb
+ capacity input cell
      |
      v
build_deploy_transaction(spec)
      |
      v
ResolvedDeployTx + ResolvedDeployEvidence
      |
      v
CKB code cell deployment transaction
      |
      v
deployment manifest + evidence
```

`build_deploy_transaction()` constructs an unsigned CKB transaction that
deploys a CellScript artifact as an on-chain code Cell. It:

- verifies that the supplied artifact hash matches the artifact bytes;
- computes TYPE_ID args for `type` deployments, while `data`, `data1`, and
  `data2` deployments omit the Type Script and bind to the artifact data hash;
- constructs the lock script for the code Cell;
- calculates occupied capacity for the code cell from artifact size;
- constructs a change output with remaining capacity minus fee;
- validates that both outputs meet occupied-capacity floors;
- inserts the 65-byte zeroed secp-sighash signing placeholder and enforces the
  default 1,000 shannons/KB relay-policy fee floor;
- assembles the transaction and returns `ResolvedDeployEvidence`.

`build_deployment_manifest_from_evidence()` produces a `DeploymentManifest`
from the evidence after a successful commit, recording the on-chain code cell
reference.

The library builder is headless: no RPC, no live-cell selection, no signing.
The caller provides a pre-resolved capacity input and all required CellDeps.
The CLI adds an RPC boundary: it requires CKB mainnet and verifies that the
selected input is live, owned by the requested secp lock, has no Type Script,
and has empty data before it calls the library builder.

The output manifest should bind the CellScript artifact to the on-chain code
cell:

```toml
schema = "cellscript-ckb-deployment-manifest-v1"
version = 1

[script]
name = "identity-token"
artifact_hash = "7efaa134..."
data_hash = "0x..."
code_hash = "0x..."
hash_type = "type"
type_id_args = "0x..."
cell_dep = { out_point = "0x...:0", dep_type = "code" }

[evidence]
occupied_capacity_shannons = 12300000000
tx_size_bytes = 1024
tx_hash = "0x..."
output_index = 0
acceptance = "test_tx_pool_accept"
```

Hash fields must stay distinct:

- `artifact_hash` is the CellScript compiler artifact hash.
- `data_hash` is the CKB code cell data hash.
- `code_hash` is the value later used in `Script.code_hash`.
- when `hash_type = "type"`, `code_hash` is the type script hash for the
  deployed code cell, not the data hash.

The deployment probe answers the production question: "How do I know this
on-chain script cell is the CellScript artifact that was compiled and audited?"

## Action Transaction Materialisation

The second flow turns one action plan into one CKB transaction candidate:

```text
cellc action build JSON
+ entry-witness bytes
+ deployment manifest
+ live-cell inputs
      |
      v
ResolvedActionTx
      |
      v
cellc tx validate
+ estimate_cycles
+ tx-pool acceptance
      |
      v
AcceptedActionTx
```

Use three distinct states:

| State | Meaning |
|---|---|
| `ActionPlan` | Compiler-side semantic plan. No live cells, no final deps, no signing. |
| `ResolvedActionTx` | Adapter-side CKB transaction with selected cells, outputs, outputs_data, witnesses, CellDeps, capacity evidence, and change policy. |
| `AcceptedActionTx` | Node-facing acceptance result with cycles, tx size, tx hash when submitted, and any rejection diagnostics. |

`cellc action build` remains a semantic plan. The adapter turns that plan into a
chain transaction. Node acceptance is the reality check.

Current machine-readable status: `cellc action build --json` emits
`adapter_contract.schema = cellscript-ckb-adapter-contract-v0.19` and a
`transaction_draft.packed_materialization` section naming the CKB packed
transaction, output, CellDep, and WitnessArgs records that the adapter must
produce. It also emits `witness_policy`, `resolved_tx_required_fields`, and an
`acceptance_report_template` for adapter output. The draft still reports
`can_submit = false`, `ckb_vm_execution = false`, and `tx_pool_acceptance =
false`.

For 0.21 builder runtimes, the same JSON includes
`action_scan_selectors.schema = cellscript-action-scan-selectors-v0.21` both at
top level and under `builder_requirements`. This envelope is a compile-only
projection of `transaction_runtime_input_requirements`: each selector records
the action, feature, CKB source, role, binding, component, field, ABI, status,
blocker class, and adapter action. It is designed to let builders ask the right
live-cell or transaction-shape question without inferring protocol semantics
from the action name. It is not an indexer query result, outpoint binding,
dry-run, tx-pool acceptance, or submission claim.

Generated TypeScript builders carry this same envelope in
`cellscript-builder-manifest.json`, `actionSpecs`, and each
`GeneratedActionPlan.actionScanSelectors`. Runtime adapters receive it through
`resolveLiveCells({ plan, options })`, so generated builders and Rust adapter
flows can share the same selector vocabulary while keeping live-cell selection
adapter-owned.

The generated builder also expects `resolveLiveCells` to return
`scanSelectorEvidence` for declared selectors. The evidence is still
adapter-owned and compile-guided, not node proof. It is checked before
`buildTransaction`: missing selector evidence and mismatched selector fields
such as role, source, binding, feature, component, or script field fail closed.
For materialised `ActionPlan` JSON consumed by the Rust adapter, the same
evidence is represented as `transaction_draft.scan_selector_evidence` and is
validated before `ResolvedActionTx` construction.

0.21 adds a strict materialised-plan bridge:
`resolve_materialized_action_plan()` and
`resolve_materialized_action_plan_with_manifest()` turn a builder/runtime-filled
`transaction_draft.inputs`, `outputs`, `outputs_data`, `witnesses`,
`cell_deps`, `header_deps`, and `lineage` section into `ResolvedActionTx`.
When a deployment manifest is supplied, matching output lock/type scripts can
complete their CellDeps through `ManifestCellDepResolver`. Plain compiler
templates still fail closed with a `requires-runtime-resolution` diagnostic;
they do not imply live-cell discovery, signing authority, dry-run success, or
tx-pool acceptance.

Materialised output lock/type scripts still accept the compact
`args = "0x..."` form. Builder runtimes that need variable-length construction
may instead provide `args_parts`, a byte-fragment array:

```json
{
  "args": "0x",
  "args_parts": [
    { "kind": "utf8", "value": "CS" },
    { "kind": "u8", "value": 7 },
    { "kind": "u32_le", "value": 42 },
    { "kind": "hex", "value": "0xaa55" }
  ]
}
```

The adapter concatenates those fragments into packed `Script.args` and rejects
ambiguous drafts that combine non-empty `args` with `args_parts`. This is byte
construction only; protocol-specific ScriptArgs meaning and node acceptance
remain adapter/node evidence.

The adapter-side example also emits a headless `ActionPreview` data model for
consumed inputs, created outputs, lineage, witnesses, warnings, and estimated
fee. It is frontend-ready JSON, not a UI layer.

Focused local gate:

```text
./scripts/cellscript_ckb_ecosystem_reuse_gate.sh quick
./scripts/cellscript_ckb_ecosystem_reuse_gate.sh full
```

These ecosystem-reuse scripts are standalone manual tools, not unified gate
modes and not release-evidence claims. See
[`CELLSCRIPT_GATE_POLICY.md`](CELLSCRIPT_GATE_POLICY.md) for the release gate
boundary.

Focused local-node adapter gate:

```text
./scripts/cellscript_ckb_adapter_acceptance.sh
```

That script starts a local CKB devnet, checks a compiler action plan, verifies
the formal adapter crate materialization path, runs `estimate_cycles`, runs
`test_tx_pool_accept`, submits the deploy transaction, generates blocks until
committed, and verifies the code cell is live on-chain. It is adapter-boundary
evidence, not a replacement for stateful business-flow acceptance and not a
unified `cellscript_gate.sh` release mode.

## Validation Loop

A production adapter flow should be:

```text
cellc action build
  -> adapter materialise
  -> cellc tx validate
  -> ckb-sdk-rust estimate_cycles
  -> ckb-sdk-rust test_tx_pool_accept
  -> optional ckb-sdk-rust send_transaction
  -> acceptance_report.json
```

If a workflow uses `dry_run_transaction`, the adapter must expose an explicit
RPC wrapper and report that exact method. Otherwise reports should say
`test_tx_pool_accept`, `estimate_cycles`, or `send_transaction` instead of
using "dry run" as a loose synonym.

The acceptance report should include at least:

```text
package hash
metadata hash
artifact hash
deployment ref
action selector
input and output bindings
witness layout
CellDeps and HeaderDeps
cycles
serialized transaction size
occupied capacity
fee and change policy
tx-pool acceptance result
submitted tx hash, when submitted
old output -> new output lineage
known limitations
```

## Capacity And CellDeps

Capacity is transaction-specific. The compiler exposes floors and evidence
requirements through `constraints.ckb`; the adapter must compute actual
occupied capacity for the concrete `CellOutput` and `outputs_data` it builds.

The adapter should use CKB packed transaction and capacity APIs for measurement,
not local approximations. Under-capacity outputs must be rejected before
signing.

CellDep resolution must come from deployment records and SDK resolvers. The
adapter must verify that declared hash type, code hash, dep type, out point,
data hash, and Type ID lineage match the compiler metadata and deployment
manifest.

## Witnesses

CellScript entry witness bytes are compiler-owned ABI output. The adapter may
call `cellc entry-witness` or the Rust metadata helper, but it must not invent a
parallel witness encoding.

Final CKB witnesses still belong to the transaction builder. The adapter must
place CellScript entry witness bytes inside the correct `WitnessArgs` field and
leave lock signatures explicit. It must not assume hidden signer authority.

## `tx solve`

`cellc tx solve` is a planning and debugging helper. It is not a chain
transaction builder.

It does not perform:

- live-cell collection;
- concrete CellDep or HeaderDep resolution;
- fee/change calculation;
- occupied-capacity measurement;
- final witness placement;
- signing;
- tx-pool acceptance;
- submission.

For real CKB transaction construction, use `cellscript-ckb-adapter` and the CKB
SDK. The `examples/ckb-sdk-builder` crate is a cookbook wrapper only.

## Minimal API

The first library surface should stay small:

```rust
load_compile_metadata(path) -> CompileMetadata
load_action_plan(path) -> ActionPlan
load_deployment_manifest(path) -> DeploymentManifest

build_deploy_transaction(spec)
build_action_transaction(...)
emit_acceptance_report(...)
```

The currently landed stable subset includes `load_action_plan`,
`load_deployment_manifest`, `build_action_transaction`, script construction and
script-ref helpers, WitnessArgs placement helpers, TYPE_ID args helpers, and
acceptance report emission.

`CellScriptAdapter` provides RPC validation and node-interaction helpers. The
legacy `deploy_artifact` and `build_deploy` convenience methods fail closed
because automatic coin selection and signing are not implemented:

```rust
// Connect to a CKB node
let adapter = CellScriptAdapter::connect("http://127.0.0.1:8114")?;

// Registry deployment tooling rejects non-mainnet nodes.
adapter.require_mainnet()?;

// Validate a caller-selected live input before constructing DeployArtifactSpec.
let (capacity, data) =
    adapter.resolve_pure_capacity_input(&capacity_out_point, &deployer_lock_script)?;

// Build with build_deploy_transaction(&spec), then send the unsigned
// transaction to an external wallet. Never submit it before signing.

// Node interaction helpers
adapter.submit_transaction(&signed_tx)?;
adapter.submit_transaction(&tx)?;
adapter.wait_for_commitment(&tx_hash, 30, 500)?;
```

Internal modules can exist without becoming stable public API:

```text
ArtifactVerifier
DeploymentBuilder
ActionTxBuilder
WitnessBuilder
CapacityEvidenceBuilder
AcceptanceRunner
```

The public API should remain smaller than the cookbook. Most early value should
come from concrete, inspectable examples.

## Cookbook Order

Initial cookbook topics should be narrow and executable:

```text
01_deploy_cellscript_artifact_with_type_id.md
02_build_action_transaction_from_action_plan.md
03_bind_outputs_and_outputs_data.md
04_resolve_celldeps_from_deployment_manifest.md
05_calculate_occupied_capacity.md
06_generate_entry_witness_bytes.md
07_validate_tx_against_cellscript_metadata.md
08_run_tx_pool_acceptance.md
09_emit_acceptance_report.md
```

These are more important than a broad framework guide. CKB developers need to
see exactly how a real transaction is assembled, measured, accepted, and
reported.

## Non-Goals

- Do not make compiler core depend on `ckb-sdk-rust`.
- Do not replace `ckb-sdk-rust`.
- Do not replace CCC or wallet connectors for TypeScript and browser workflows.
- Do not infer protocol semantics from action names such as `mint`, `claim`, or
  `swap`.
- Do not hide signer authority or sighash defaults.
- Do not mark a deployment mainnet-certified without external audit and chain
  evidence.
- Do not treat package registry resolution as deployment verification.
- Do not treat builder success as CKB node acceptance.

## CLI: `cellscript-deploy`

The adapter crate ships a CLI binary for building mainnet deployment
transactions and querying status without writing Rust code. It does not own
wallet keys. Consequently, `deploy` fails closed and `build-deploy` emits an
unsigned transaction with `can_submit: false`; a CKB wallet must sign and
broadcast it.

```bash
# Build the binary
cargo build -p cellscript-ckb-adapter --bin cellscript-deploy

# Build the canonical Registry Type Script deployment for external signing
export LOCK_ARG=0x$(cat ~/.ckb/default-lock-arg)  # your secp256k1 lock arg
cellscript-deploy --rpc http://127.0.0.1:8114 --json build-deploy \
  --artifact contracts/registry-type-script/artifacts/v0.24.0/cellscript-registry-type-script \
  --lock-arg $LOCK_ARG \
  --name cellscript-registry-type-script \
  --hash-type data1 \
  --capacity-out-point 0x<LIVE_PURE_CAPACITY_TX_HASH>:<INDEX>

# TYPE_ID remains available for upgradeable deployments
cellscript-deploy build-deploy \
  --artifact contract.elf \
  --lock-arg $LOCK_ARG \
  --capacity-out-point 0x<tx_hash>:<index>

# Query transaction status
cellscript-deploy status --tx-hash 0x<tx_hash>

# Node info
cellscript-deploy info
```

The build command validates the RPC genesis hash against CKB mainnet and
resolves the actual input capacity/data instead of trusting command-line
values. The canonical mainnet secp-sighash dep group
`0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c:0`
is the default. All commands support `--json` for
structured output and `--rpc` to override the default
`http://127.0.0.1:8114` endpoint.

## External Positioning

CellScript does not compete with `ckb-sdk-rust`. It gives CKB developers a
higher-level verifier specification layer with ABI, metadata, witness, action
plans, and constraints. `ckb-sdk-rust` remains the Rust infrastructure for
transaction construction and chain interaction.

CellScript also does not replace `ckb-std`. The CKB backend should stay
compatible with `ckb-std` at the contract-side ABI boundary: syscall numbers,
source encoding, witness handling, TYPE_ID, since, occupied capacity, and
exec/spawn semantics. See
[`CELLSCRIPT_CKB_STD_COMPAT.md`](CELLSCRIPT_CKB_STD_COMPAT.md) for that
compatibility contract.

That is the intended production workflow:

```text
CellScript tells builders what the transaction must mean.
ckb-std tells contract authors what CKB runtime reality means.
ckb-sdk-rust helps builders make it real.
The CKB node proves whether it is accepted.
```
