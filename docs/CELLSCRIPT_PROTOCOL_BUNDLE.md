# CellScript ProtocolBundle v1

Status: 0.30 development contract for issues
[#9](https://github.com/CellScript-Labs/CellScript/issues/9) and
[#10](https://github.com/CellScript-Labs/CellScript/issues/10), plus the exact
artifact identity layer of
[#11](https://github.com/CellScript-Labs/CellScript/issues/11).

## Boundary

`cellscript-protocol-bundle-v1` is an off-chain composition object for two or
more independently compiled CKB Script artifacts. The offline checker:

1. loads each referenced ELF, compile metadata, lowering record, source map,
   and action-builder manifest from paths confined to the input document's
   directory;
2. admits every artifact through `cellscript-artifact-checker` and the current
   metadata validator;
3. binds the selected entry, package/lock identity, exact ELF hash, interface,
   typed semantics, target profile, deployment, code CellDep, and generated
   builder projection, then derives an exact Script/verifier receipt and
   fixed-width handle;
4. merges explicitly named input, output, witness, CellDep, HeaderDep, fee,
   and change claims against one deterministic transaction skeleton;
5. validates that same skeleton and its explicit builder-assumption evidence
   against every admitted artifact's compile metadata; and
6. resolves closed cross-Script roles through checked Molecule schema,
   interface, ELF, and deployment identities; and
7. emits a stable bundle hash, conflict report, and runtime evidence template.

This layer does not link ELF files, merge their trust boundaries, call one CKB
Script from another, query RPC, sign, submit, or claim CKB-VM/chain evidence.
The separate `cellscript-ckb-adapter` materialization boundary can turn a
successful report with concrete fields into one packed CKB transaction without
changing those limits.

## Schemas and hash

The local authoring document uses
`cellscript-protocol-bundle-input-v1`. Its artifact paths are local evidence
locators and are excluded from the resolved bundle hash. Successful checking
emits a `cellscript-protocol-bundle-v1` object inside a
`cellscript-protocol-bundle-report-v1` report.

The `bundle_hash` is CKB Blake2b-256 over:

```text
"cellscript-protocol-bundle-v1" || 0x00 || canonical_json(resolved_bundle)
```

Artifacts are sorted by ID. Role, witness, dependency, and policy claims are
sorted by their physical key and artifact identity. Transaction arrays keep
their exact order because their position is part of CKB semantics. Reordering
input declarations that describe the same composition therefore retains the
same hash, while changing an index, claim, deployment, checked artifact, or
transaction slot changes it.

## Input contract

The top-level input contains:

| Field | Contract |
|---|---|
| `network` | Non-empty chain ID plus canonical `0x`-prefixed 32-byte lowercase genesis hash |
| `artifacts` | 2 to 64 independent checked ELF references |
| `transaction` | Version-0 transaction skeleton with exact ordered cell, witness, CellDep, HeaderDep, fee-policy, and change-policy commitments; optional concrete adapter fields are hash-bound when present |
| `roles` | Named input/output indexes with exclusive or shared-read ownership and optional exact Script/resource/cell/capacity requirements |
| `closed_roles` | Typed provider/consumer relations over existing Cell or witness claims, using `cellscript-protocol-closed-role-v1` |
| `witnesses` | Exact `WitnessArgs` index/field, ABI, commitment, signing domain, and write/read ownership |
| `cell_deps` / `header_deps` | Named logical dependencies mapped to exact global positions |
| `policies` | Fee or change policy hashes with exclusive or shared ownership |

Every artifact record names a package coordinate and exact `Cell.lock` node
identity, one selected action/lock/function, the Script role (`lock`, `type`,
or `spawned-verifier`), four checked artifact files, and one exact deployment.
Action entries must also supply the `cellscript-generated-action-builder-v0.23-edition-2026`
manifest emitted by `cellc gen-builder`. Its metadata/artifact/compiler/profile
identities, runtime contract, structural manifests, and selected action
projection must agree with the admitted metadata. Lock entries may omit it
because the current generated builder surface is action-oriented.
For `data`, `data1`, and `data2` deployments, the Script code hash must equal
the checked ELF's CKB hash. A `type` deployment binds the separately supplied
Type-hash identity. All deployments must use a hash type admitted by the
artifact target profile.

Every resolved artifact contains two additional issue #11 identities:

- `exact_handle_receipt` uses
  `cellscript-exact-script-handle-receipt-v1` to bind package coordinate,
  exact `Cell.lock` node, selected entry, Script role, interface, typed
  semantics, ELF, target profile, the package/Registry ABI hash, verified
  bundle, deployment Script, code CellDep, and chain identity;
- `exact_handle` uses `cellscript-exact-script-handle-value-v1` and
  `CSHDLv1-fixed-202`, a 202-byte value containing a magic/version class,
  explicit Script role, and six 32-byte commitments for the receipt, complete
  CKB Script, interface, ELF, target profile, and runtime ABI.

The complete Script commitment is CKB Blake2b-256 over canonical Molecule
`Script` bytes. Its encoding is checked against `ckb-types` for `data`,
`data1`, `data2`, and `type`. Data-hash deployments require the Script
`code_hash` to equal the admitted ELF hash; Type-hash deployments retain an
explicit exact-code-Cell policy and bind the ELF and code CellDep separately.
The handle is a copyable identity value. It does not own, create, consume,
replace, relock, execute, or authorize a Cell.

Paths must be relative, must resolve to regular files inside the input
document's directory, and are read only after byte budgets are checked. The
standalone checker must report verified binding, structure, lowering, and
typed semantics for every artifact.

## Ownership

`exclusive` means one artifact owns the cell role. `shared-read` means the
artifact only observes it. Two exclusive claims on one physical cell conflict.
One exclusive role and compatible shared readers can coexist, which permits a
Lock Script and Type Script to validate the same Cell. Explicit expected Lock,
Type, resource, cell, and capacity values must still agree with each other and
the transaction skeleton.

Witness fields use `exclusive-write` or `shared-read`. Multiple writers
conflict. A writer and readers may share a field only when their ABI, value
commitment, and signing domain agree. Optional `lock_bytes`,
`input_type_bytes`, and `output_type_bytes` values are exact lowercase hex. If
the corresponding commitment is present, it must equal CKB Blake2b-256 of
those bytes. This records ownership and materialization; it does not
manufacture a signature or canonical signing message.

## Closed typed roles

A closed role connects already admitted artifacts; it does not select a Script
at runtime. The provider and every consumer reference an existing physical
Cell or witness claim:

```json
{
  "schema": "cellscript-protocol-closed-role-v1",
  "role_id": "settlement-record",
  "kind": "cell",
  "schema_identity": {
    "type_name": "SettlementRecord",
    "schema_hash": "...64 lowercase hex digits..."
  },
  "provider": { "artifact": "order-type", "claim": "settlement-output" },
  "consumers": [
    { "artifact": "token-type", "claim": "settlement-output" }
  ],
  "correspondence": "exact-physical-binding"
}
```

The provider must own the physical Cell claim with `exclusive`, or the witness
claim with `exclusive-write`. Consumers must use `shared-read`. Every claim
must resolve to the identical Cell slot or `WitnessArgs` field and name the
same resource/ABI as `schema_identity.type_name`. Checked metadata for every
participant must expose that exact Molecule type name and schema hash.

The resolved record copies each participant's package coordinate, selected
entry, Script role, interface hash, ELF hash, complete deployment identity,
and exact fixed-width handle into the canonical bundle. This makes the relation
auditable and hash-bound; it does not mean that CKB-VM links the ELFs or calls
one Script from another.
Runtime-selected/open roles remain outside this schema until the separately
versioned Script-handle contract is admitted.

## Conflict codes

The checker returns conflicts in stable code/key/artifact order and never
chooses a winner:

| Code | Class | Rejection condition |
|---|---|---|
| `PB200` | input ownership | Multiple artifacts claim exclusive ownership of one cell slot |
| `PB201` | output placement | A cell commitment or output placement disagrees |
| `PB202` | witness ABI | Witness field writers, ABIs, or commitments disagree |
| `PB203` | dependency ordering | A CellDep/HeaderDep identity or logical position disagrees |
| `PB204` | Script identity | Expected Lock/Type Script identity disagrees |
| `PB205` | resource identity | Explicit logical/Type-ID resource identities disagree |
| `PB206` | capacity | Exact or minimum capacity is not satisfied |
| `PB207` | fee/change | Fee/change policy identity or exclusive ownership disagrees |
| `PB208` | network/deployment | An artifact deployment uses another chain identity |
| `PB209` | profile/version | Target, VM, source encoding, or ABI profile hashes disagree |
| `PB210` | signature policy | Signing domains disagree for one witness field |
| `PB211` | skeleton binding | A claimed global index does not exist |
| `PB212` | builder validation | The shared transaction skeleton or supplied evidence violates an artifact's metadata builder assumptions |
| `PB213` | closed typed role | A provider/consumer has the wrong ownership, physical source, schema, interface-bound artifact, or deployment identity |

Malformed schemas, unknown fields, duplicate artifact/claim identities,
unknown artifact references, non-canonical hashes, escaped paths, over-budget
inputs, and failed artifact admission are structural errors rather than
resolvable conflicts.

## CLI

```bash
cellc protocol bundle check protocol-bundle.json --json
cellc protocol bundle check protocol-bundle.json --output build/protocol-bundle.report.json
```

On success, `status` is `ok`, `conflicts` is empty,
`evidence.structural_verification` is `verified`, and every
`evidence.metadata_transaction_validation` entry is `ok`. On conflict, the
command exits unsuccessfully after writing the requested report so tooling can
inspect the complete conflict set. No signing or network operation occurs.

## Runtime adapter materialization

`cellscript_ckb_adapter::materialize_protocol_bundle_report` consumes the exact
JSON report emitted by `cellc protocol bundle check`. It independently:

- checks the report state, per-artifact standalone admission, and metadata
  transaction-validation coverage;
- recomputes the canonical resolved-bundle hash;
- requires an `out_point` for every input and exact `data` bytes for every
  output;
- verifies committed witness bytes and preserves ordered inputs, outputs,
  witnesses, CellDeps, and HeaderDeps in a Molecule `TransactionView`;
- checks occupied output capacity and computes the capacity remainder as the
  candidate fee; and
- resolves each selected Lock or Type artifact to global and group-relative
  indexes, with the same complete serialized transaction hash attached to
  every group record.

Its `cellscript-protocol-bundle-materialization-v1` evidence records the raw
transaction hash, complete serialized transaction hash and byte size, input,
output, occupied-capacity and fee totals, and per-artifact Script Group
identity. Transaction serialization is `verified`; every group execution,
CKB-VM evidence, and chain evidence remains `not-executed`. Spawned verifiers
bind their exact code CellDep but are not misreported as direct CKB Script
Groups. Input capacity and the resulting fee are sourced from the bundle
skeleton until live Cell resolution verifies them.

`CkbSdkAcceptance::verify_protocol_bundle_live_inputs` first checks the
connected node's chain ID and genesis hash, then resolves every transaction
input with `get_live_cell(..., true)`. Each Cell must still be live and its
packed `CellOutput`, data hash, capacity, OutPoint, and order must match the
hash-bound materialization expectation. The resulting
`cellscript-protocol-bundle-live-resolution-v1` record changes
`capacity_source` to `live-node` and recomputes the fee from verified live
inputs. This is uncommitted live-state evidence; the Cell can still be spent
before submission.

`CkbSdkAcceptance::verify_protocol_bundle_live_dependencies` then resolves
every artifact code CellDep on the same connected chain. A direct code dep must
contain bytes whose CKB data hash equals the admitted ELF hash. A dep-group root
must decode as a canonical Molecule `OutPointVec`; every listed member must be
live and one must satisfy the artifact identity. Data, data1, and data2 Scripts
bind that data hash directly, while type Scripts bind the live code Cell's Type
Script hash. The dependency evidence is rejected unless the earlier live-input
record preserves every input observation and the exact materialized transaction
identity.

The signing path is an ordered state machine:

1. `protocol_bundle_ready_to_sign_evidence` requires exact live-input and
   live-dependency evidence.
2. `unlock_protocol_bundle_transaction` runs caller-supplied CKB SDK unlockers,
   rejects remaining Lock Groups, preserves the raw transaction and all
   compiler-owned witness fields, and records only changed witness lock indexes.
3. `dry_run_signed_protocol_bundle` executes those signed bytes and upgrades
   signature verification from pending to node-verified.
4. `test_signed_protocol_bundle` binds tx-pool cycles and the node-computed fee
   to the same signed serialization hash.
5. `submit_signed_protocol_bundle` checks that evidence before RPC submission
   and emits an explicitly uncommitted receipt.
6. `wait_for_protocol_bundle_confirmation` polls the canonical transaction
   location to a caller-selected depth, restarts if an observed inclusion
   disappears or changes, and emits `ConfirmedProtocolBundleTx` only after a
   final location recheck.

Private keys are never fields in the ProtocolBundle or its evidence. Hardware,
wallet, and software signers remain behind CKB SDK `ScriptUnlocker` interfaces.
Generated TypeScript builders expose the same rule through
`ProtocolBundleSigningRequest.privateKeysIncluded = false`. They also export
`bindClosedProtocolRole`, which requires every bound generated artifact to
expose the exact Molecule type/hash before producing a closed-role input. Their
`createProtocolBundleClient` rejects duplicate artifact IDs, wrong stage names,
and any bundle or raw-transaction identity change between stages. Each package
also exports `bindProtocolBundleArtifact`, which refuses a deployment ELF hash
different from the generated builder's admitted artifact hash.
Builder manifests bind the exact receipt/value schemas, fixed-width encoding,
target-profile hash, and existing ABI hash. `bindCheckedExactScriptHandle`
accepts a receipt/value returned by a successful bundle check only when its
role, entry, interface, typed semantics, ELF, profile, ABI, verified bundle,
deployment, and fixed-width shape match the generated artifact. Cryptographic
receipt/value recomputation remains the Rust checker's responsibility.
The compiler-side `script_handle::exact_script_handle_value_hash` function
computes the CKB Blake2b-256 literal consumed by source-level exact-handle
runtime helpers. It hashes the full fixed value, so changing any receipt,
interface, artifact, profile, ABI, role, or Script identity byte changes the
literal.
Successful bundle artifacts and closed-role participants emit that value as
`exact_handle_hash`; generated TypeScript binders retain it as `handleHash`.

Registry verified-build evidence makes that capability discoverable without
weakening admission. A release carries `protocol_bundle_schema`,
`protocol_bundle_artifact_binding_schema`, and
`protocol_bundle_runtime_adapter` only when its CKB ELF, compile metadata,
lowering record, and source map pass the standalone checker. The values are
exactly `cellscript-protocol-bundle-v1`,
`cellscript-protocol-bundle-artifact-binding-v1`, and
`cellscript-ckb-adapter`. The Registry rejects partial or unknown triples and
does not attach them to generic hash-bound executables or source-only
snapshots. Composition still re-admits the exact local files and, for action
entries, the generated builder manifest.

`CkbSdkAcceptance::dry_run_protocol_bundle` sends that exact packed transaction
to CKB `estimate_cycles`. A successful response emits
`cellscript-protocol-bundle-dry-run-v1`: every direct Lock/Type group is marked
`accepted-by-aggregate-estimate-cycles` under the same serialized byte hash,
and the aggregate cycle count is retained. The RPC does not expose per-group
cycles, so each group cycle field remains null and `cycle_attribution` states
that limitation. Spawned-verifier records remain `not-independently-observed`
unless later execution evidence proves that path ran. Dry-run evidence is
uncommitted and does not imply tx-pool acceptance or chain confirmation.

## Evidence tiers and remaining phases

The v1 offline report retains the standalone checker report and metadata
transaction-validation report for every artifact. Generated action-builder
manifests are admitted and exact selected-action projections are checked.
`transaction_serialization`, `ckb_vm_execution`, and `chain_evidence` remain
`not-executed`, with no exact transaction hash. This is the Phase 0
format/threat-model contract plus the builder-contract portion of Phase 1
offline composition. The adapter evidence advances a concrete report to a
byte-exact transaction while preserving the offline report unchanged.

Later bundle phases may add builder-selected live Cells, independently
attributed per-group cycles from a backend that can report them, and
product-specific finality policies. None is inferred by the closed-role
contract or the current adapter evidence.

The original compiler report remains offline structural evidence. Adapter
materialization, live resolution, dependency resolution, signed dry-run,
tx-pool, and submission records advance the same hash-bound transaction without
rewriting that report. Submission is still uncommitted. The versioned
confirmation record upgrades it only to an observed canonical inclusion at the
required depth and explicitly does not claim absolute finality.
