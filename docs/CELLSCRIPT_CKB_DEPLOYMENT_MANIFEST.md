# CellScript CKB Deployment Manifest

**Status**: production authoring surface for CellScript 0.12 metadata and
builder handoff.

CellScript does not ask contract authors to encode CKB `CellDep`, `hash_type`,
or capacity evidence in ad hoc scripts. A package can declare deployment-facing
CKB facts in `Cell.toml`, and the compiler copies those facts into
`constraints.ckb`.

## Manifest Shape

```toml
[deploy.ckb]
hash_type = "data1"
artifact_hash = "blake2b:..."
data_hash = "0x..."
out_point = "0x...:0"
dep_type = "code"
type_id = "0x..."

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x...:0"
dep_type = "dep_group"
hash_type = "type"
```

`[[deploy.ckb.cell_deps]]` also accepts the older split location form:
`tx_hash = "0x..."` plus `index = 0`. Use one form per dependency. A manifest
that specifies both forms for the same dependency is rejected.

Supported `hash_type` values are:

- `data`
- `type`
- `data1`
- `data2`

Supported `dep_type` values are:

- `code`
- `dep_group`

Unknown `hash_type` or `dep_type` values are compile errors. They are not
warnings, because a builder that uses the wrong script hash mode or cell dep
mode can deploy a transaction that differs from the audited artifact identity.

## CKB Default Hash Helper

Use:

```bash
cellc ckb-hash --hex 00
cellc ckb-hash --file build/contract
```

The command computes Blake2b-256 with the `ckb-default-hash` personalization.
Empty bytes must hash to:

```text
44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e
```

The same algorithm is available to Rust tooling as
`cellscript::ckb_blake2b256`. This is the supported 0.12 builder/release helper
surface. It is not an in-script syscall and does not claim arbitrary dynamic
on-chain hashing unless the artifact links a real RISC-V Blake2b implementation.

## Constraints Output

`cellc constraints --target-profile ckb` emits:

- `ckb.hash_type_policy`
- `ckb.dep_group_manifest`
- `ckb.timelock_policy`
- `ckb.capacity_evidence_contract`

The compiler still does not claim to statically prove full CKB occupied
capacity. The production contract is explicit: builders must attach measured
occupied-capacity evidence and consensus transaction-size evidence for
state-changing transactions.

## Builder Requirements

A production CKB builder must verify:

- deployed script `hash_type` equals the manifest or compiler default
- declared `dep_group` entries are referenced or expanded intentionally
- code cell data hash matches the compiled artifact
- type-id lineage matches metadata when type-id is used
- tx-size and occupied-capacity measurements are retained as release evidence
