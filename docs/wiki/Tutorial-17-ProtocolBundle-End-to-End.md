# Tutorial 17: ProtocolBundle End to End

ProtocolBundle v1 composes two or more independently compiled CKB Script
artifacts into one transaction while keeping every Script's artifact identity,
transaction claims, and evidence separate. This tutorial follows the 0.30
development contract from checked ELF files through an externally signed,
bounded confirmation receipt.

The current endpoint records a canonical-chain inclusion and caller-selected
depth without claiming absolute finality. Automatic builder-selected live Cells
and independently measured per-Script-Group cycles remain open.

## 1. Know the three identities

ProtocolBundle uses three versioned schemas for different jobs:

| Identity | Meaning |
|---|---|
| `cellscript-protocol-bundle-input-v1` | Local authoring document with evidence file paths |
| `cellscript-protocol-bundle-v1` | Canonical resolved bundle covered by `bundle_hash` |
| `cellscript-protocol-bundle-report-v1` | Offline result containing the resolved bundle, conflicts, and evidence template |

Generated TypeScript builders use
`cellscript-protocol-bundle-artifact-binding-v1` to bind one generated package
to its exact metadata, ELF, interface, builder manifest, selected entry, Script
role, and deployment. Closed cross-Script roles use
`cellscript-protocol-closed-role-v1`.

The bundle hash is the CKB Blake2b-256 digest of the domain string, a zero byte,
and canonical JSON for the resolved bundle. Local file paths do not enter that
hash. Artifact hashes, deployment identities, selected entries, physical
indexes, and transaction arrays do.

## 2. Prepare every artifact independently

For every Lock Script, Type Script, or bounded spawned verifier, retain:

- the RISC-V ELF;
- compile metadata;
- the lowering record;
- the source map;
- the exact deployment Script and code CellDep; and
- for an action entry, the generated action-builder manifest.

Build action artifacts and their TypeScript package with the normal public
commands:

```bash
cellc build . --target riscv64-elf --target-profile ckb --entry-action transfer
cellc gen-builder . --target typescript --output target/cellscript-builder/typescript --target-profile ckb --json
```

Repeat that process in each independently built package. A bundle does not link
the ELFs or erase package boundaries. Its first job is to prove exactly which
artifacts and deployments the proposed transaction uses.

If an artifact came from the Registry, inspect its accepted `verified_build`
evidence. The following triple means the Registry artifact verifier found a
complete CellScript CKB ELF sidecar set and passed it through the standalone
checker:

```json
{
  "protocol_bundle_schema": "cellscript-protocol-bundle-v1",
  "protocol_bundle_artifact_binding_schema": "cellscript-protocol-bundle-artifact-binding-v1",
  "protocol_bundle_runtime_adapter": "cellscript-ckb-adapter"
}
```

The triple is discovery evidence. The local bundle checker still re-admits the
exact ELF and sidecars. Generic hash-bound executables and source-only snapshots
do not receive it.

## 3. Describe one shared transaction

Create `protocol-bundle.json` beside the evidence files. Its top-level shape is:

```json
{
  "schema": "cellscript-protocol-bundle-input-v1",
  "network": {
    "chain_id": "ckb_testnet",
    "genesis_hash": "0x...64 lowercase hex digits..."
  },
  "artifacts": [],
  "transaction": {
    "version": 0,
    "inputs": [],
    "outputs": [],
    "witnesses": [],
    "cell_deps": [],
    "header_deps": [],
    "fee_policy_hash": "0x...64 lowercase hex digits...",
    "change_policy_hash": "0x...64 lowercase hex digits...",
    "builder_assumption_evidence": {}
  },
  "roles": [],
  "closed_roles": [],
  "witnesses": [],
  "cell_deps": [],
  "header_deps": [],
  "policies": []
}
```

Each artifact entry names its package coordinate, exact `Cell.lock` node,
selected action/lock/function, Script role, deployment, and evidence files.
Transaction arrays preserve CKB order. Role and witness claims then explain
which artifact owns or reads each physical slot.

Use `exclusive` for the artifact that owns a Cell role and `shared-read` for
another Script that only observes the same Cell. Witness fields use
`exclusive-write` and `shared-read`. The checker rejects multiple owners,
multiple writers, incompatible ABIs, different signing domains, conflicting
Script identities, and claims for indexes outside the skeleton. It reports
stable `PB200` through `PB213` codes and never chooses a winner.

A `closed_roles` entry turns compatible physical claims into a typed
cross-Script relation. It names one provider claim, one or more consumer
claims, and an exact Molecule type name/hash. Every participant must expose
that schema in checked metadata. The resolver copies each participant's
interface hash, ELF hash, selected entry, and deployment Script identity into
the canonical bundle. Providers use `exclusive` or `exclusive-write`;
consumers use `shared-read`; all references must resolve to the identical Cell
slot or witness field. Open/runtime-selected participants are not accepted by
this schema.

## 4. Run the offline composition check

```bash
cellc protocol bundle check protocol-bundle.json --json
cellc protocol bundle check protocol-bundle.json --output build/protocol-bundle.report.json
```

A successful report has `status: "ok"`, no conflicts, verified structural
admission for every artifact, and one successful metadata transaction-validation
record per artifact. The command does not use RPC, sign, or execute CKB-VM.

When the check fails, inspect each conflict's `code`, `key`, and `artifacts`.
Change the transaction or its explicit ownership claims and run the same check
again. Do not resolve a conflict by removing the metadata or builder evidence
that exposed it.

## 5. Advance the exact transaction through the Rust adapter

Pass the report bytes to
`cellscript_ckb_adapter::materialize_protocol_bundle_report`. Concrete input
OutPoints, output data, and witness field bytes must already be hash-bound in
the successful report. The adapter emits one packed CKB transaction and records
its raw hash, complete serialized hash, byte size, capacities, candidate fee,
and every direct Script Group's global and group-relative indexes.

The node-backed states are ordered:

| State | New evidence |
|---|---|
| `MaterializedProtocolBundleTx` | Exact Molecule transaction bytes and hashes |
| `LiveResolvedProtocolBundleTx` | Every input is live and its output/data/capacity still matches |
| `LiveDependenciesResolvedProtocolBundleTx` | Code Cells and complete dep groups match admitted ELF and Script identity |
| `ReadyToSignProtocolBundleTx` | Both live receipts bind the same transaction and network |
| `SignedProtocolBundleTx` | Caller-owned unlockers filled Lock witness fields without changing the raw transaction |
| `SignedDryRunProtocolBundleTx` | The node executed the signed bytes successfully |
| `TxPoolAcceptedProtocolBundleTx` | Tx-pool acceptance binds node cycles and computed fee |
| `SubmittedProtocolBundleTx` | The node returned the expected transaction hash |
| `ConfirmedProtocolBundleTx` | Canonical inclusion survived the requested bounded confirmation depth |

`CkbSdkAcceptance` checks the connected chain ID and genesis hash before live
resolution. Direct code deps must contain bytes with the admitted ELF data hash.
A `dep_group` is decoded as a canonical Molecule `OutPointVec`; every member
must be live and a matching code Cell must be present.

The signed path runs caller-supplied CKB SDK `ScriptUnlocker` implementations.
It permits Lock witness changes while preserving the raw transaction and
compiler-owned input/output-type witness fields. Private keys never become
fields in a ProtocolBundle or evidence record.

## 6. Use the generated TypeScript state machine

Every generated TypeScript action-builder package exports:

- `bindProtocolBundleArtifact`;
- `bindClosedProtocolRole`;
- `createProtocolBundleClient`;
- the same nine state names;
- `ProtocolBundleSigningRequest`; and
- the bundle, report, and artifact-binding schema constants.

The generated client accepts an application runtime that calls the Rust adapter
or an equivalent service boundary. Its flow is resumable around an external
wallet:

```typescript
const artifact = builder.bindProtocolBundleArtifact({
  id: "token-type",
  entry: { kind: "action", name: "transfer" },
  scriptRole: "type",
  deployment,
});

const sharedSchema = artifact.schemaContracts.find(
  (schema) => schema.type_name === "SettlementRecord",
);
if (!sharedSchema) throw new Error("SettlementRecord schema is not exported");

bundleInput.closed_roles = [builder.bindClosedProtocolRole({
  roleId: "settlement-record",
  kind: "cell",
  schemaIdentity: sharedSchema,
  provider: { artifact, claim: "settlement-output" },
  consumers: [{ artifact: authArtifact, claim: "settlement-output" }],
})];

const client = builder.createProtocolBundleClient(runtime);
const flow = await client.prepare(bundleInput, [artifact, authArtifact]);
const request = client.signingRequest(flow.prepared);

// Send request.unsignedTransaction to a wallet or hardware signer.
const signed = await client.resumeSigned(flow.prepared, signedTransaction);
const accepted = await client.acceptSigned(signed);
const submitted = await client.submit(signed, accepted.accepted);
const confirmed = await client.confirm(submitted, {
  requiredConfirmations: 6,
  maxAttempts: 120,
  pollingIntervalMs: 5000,
});
```

`request.privateKeysIncluded` is always `false`. The client rejects duplicate
artifact IDs, unknown stage names, a failed offline report, and changes to the
bundle or raw-transaction identity between stages. The application owns wallet
interaction and the concrete transport to `cellscript-ckb-adapter`.

## 7. Read the evidence literally

An aggregate `estimate_cycles` success can mark direct groups as accepted under
the same transaction bytes, but that RPC does not attribute cycles to individual
groups. Per-group cycle fields therefore remain empty. Spawned verifiers remain
unobserved unless separate evidence proves execution.

`SubmittedProtocolBundleTx` proves that the node accepted a submission request
and returned the expected transaction hash. It remains explicitly uncommitted.
The confirmation poll uses `get_transaction`'s canonical committed location and
`get_tip_header` to derive depth. If an observed inclusion disappears or moves,
it increments `reorgs_observed` and restarts the count. Before returning it reads
the location again. `ConfirmedProtocolBundleTx` records that bounded snapshot,
including the inclusion block/index and observed tip, while its
`finality_claim` remains `bounded-observation-not-absolute-finality`.

For the complete field and conflict contract, read
[CellScript ProtocolBundle v1](../CELLSCRIPT_PROTOCOL_BUNDLE.md). For deployment
and node adapter details, read the
[CKB adapter contract](../CELLSCRIPT_CKB_ADAPTER.md).
