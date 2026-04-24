# CellScript 0.12 Migration Notes

**Status**: working migration notes for the 0.12 line.

## Metadata Schema

Metadata schema is now `29`.

New production-facing fields include:

- `constraints.runtime_errors`
- `constraints.ckb.hash_type_policy`
- `constraints.ckb.dep_group_manifest`
- `constraints.ckb.timelock_policy`
- `constraints.ckb.capacity_evidence_contract`
- `molecule_schema_manifest`

Consumers that validate metadata schema versions must accept schema 29.

## Runtime Error Codes

Generated fail-closed paths now use the stable runtime error registry. Assembly
contains comments such as:

```asm
# cellscript runtime error 14 mutate-transition-mismatch
```

Use `constraints.runtime_errors` or `docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md` to
map numeric exit codes to names and hints.

## CKB Deployment Manifests

Packages can declare CKB deployment facts in `Cell.toml`:

```toml
[deploy.ckb]
hash_type = "data1"
out_point = "0x...:0"
dep_type = "code"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x...:0"
dep_type = "dep_group"
```

Invalid `hash_type` or `dep_type` values now fail compilation.
The older split `tx_hash` plus `index` form remains accepted, but new manifests
should prefer `out_point` so the dependency identity is one atomic field.

## Builder Evidence

Production CKB release evidence must retain tx-size and occupied-capacity
measurements. Production Spora evidence must retain standard mass policy checks.

## Compatibility

Existing source programs continue to compile unless they add invalid deployment
manifest values. The new fields are additive metadata/report surfaces.
