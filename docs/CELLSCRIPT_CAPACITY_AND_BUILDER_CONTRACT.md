# CellScript Capacity And Builder Contract

**Status**: CKB builder contract.

CellScript exposes capacity requirements, but it does not claim to statically
prove every CKB transaction's occupied capacity. Capacity is a transaction-level
fact because it depends on concrete lock/type scripts, output data, fees, and
builder-selected cell layout.

## Source-Level Capacity Declarations

CellScript supports a conservative type-level floor:

```cell
resource TimedToken has store
with_capacity_floor(6100000000)
{
    amount: u64,
}
```

`with_capacity_floor(...)` records a minimum output capacity in shannons for
that typed cell. The compiler carries it into `TypeMetadata` and
`constraints.ckb.declared_capacity_floors`.

This is not full capacity proof. It gives builders and auditors a declared
floor to preserve while the builder still computes the real occupied capacity
for the final `CellOutput` and output data.

## Compiler Output

For CKB artifacts, `constraints.ckb.capacity_evidence_contract` includes:

- code cell lower-bound capacity
- recommended code cell capacity margin
- declared type-level capacity floors, when present
- whether occupied-capacity evidence is required
- whether consensus transaction-size evidence is required
- measured occupied capacity, when supplied by acceptance/builder tooling
- measured tx size, when supplied by acceptance/builder tooling

State-changing actions that create or mutate outputs require builder evidence.

## Measurement Helper

The release helper lives at `tools/ckb-tx-measure` and reads a CKB JSON
transaction from stdin. The checked-in manifest assumes the standalone
repository layout where `ckb/` and `CellScript/` are siblings:

```bash
cargo run --manifest-path tools/ckb-tx-measure/Cargo.toml --locked < tx.json
```

When CellScript is used from the nested checkout, the
CKB acceptance script builds the same source through a generated temporary
manifest pointing at its configured `CKB_REPO`.

This helper is a repository-local release evidence tool. It is intentionally
excluded from the crates.io package because it links against a local CKB checkout
to reuse CKB packed transaction and occupied-capacity implementations.

It emits:

- `consensus_serialized_tx_size_bytes`
- `occupied_capacity_shannons`
- `output_occupied_capacity_shannons`
- `output_capacity_shannons`
- `capacity_is_sufficient`
- `under_capacity_output_indexes`

Occupied capacity is derived with CKB's own `packed::CellOutput` capacity API:
`output.occupied_capacity(Capacity::bytes(output_data.len()))`. The helper does
not use a local approximation and rejects transactions whose `outputs` and
`outputs_data` lengths differ.

## Builder Requirements

A production builder must:

- preserve any `constraints.ckb.declared_capacity_floors` on matching outputs
- compute occupied capacity for every output
- reject under-capacity outputs before submission
- retain measured occupied-capacity evidence in release reports
- retain consensus-serialized transaction size
- retain dry-run or VM execution evidence for cycles
- preserve `hash_type`, CellDep, and type-id metadata declared by the compiler
  and deployment manifest

The compiler can give lower bounds and requirements. The builder supplies the
transaction-specific proof.

## Mass Constraints

For CKB, `constraints.ckb` exposes compiler-estimated compute, storage,
transient, code deployment, standard transaction mass, and block mass. The
devnet/acceptance path remains authoritative for real transaction mass because
the final mass depends on the full transaction and network policy.
