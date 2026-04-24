# CellScript CKB Tx Measure

This is a repository-local release evidence helper, not part of the published
`cellscript` crates.io package.

It reads a CKB JSON transaction from stdin and emits:

- consensus serialized transaction size
- total occupied capacity
- per-output occupied capacity
- per-output declared capacity
- under-capacity output indexes

The helper links against a local CKB checkout so it can use CKB's packed
transaction and occupied-capacity implementations directly. The checked-in
manifest is optimized for the standalone CellScript repository layout:

```text
parent/
  ckb/
  CellScript/
```

The Spora acceptance script builds the same source through a temporary manifest
that points at its configured `CKB_REPO`, so the standalone helper manifest does
not need to encode the nested `Spora/cellscript` checkout shape.

Run:

```bash
cargo run --manifest-path tools/ckb-tx-measure/Cargo.toml --locked < tx.json
cargo test --manifest-path tools/ckb-tx-measure/Cargo.toml --locked
```

Those commands assume the standalone layout shown above. The Spora CKB
acceptance script uses the same `src/bin/ckb_tx_measure.rs` source, but builds it
through a generated temporary manifest that points at the acceptance run's
configured `CKB_REPO`.
