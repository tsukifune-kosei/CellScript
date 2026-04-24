# CellScript 0.12 Release Evidence

**Status**: release evidence checklist for CellScript 0.12.

This document records the evidence expected before cutting a 0.12 release. It
does not replace Spora or CKB acceptance reports; it defines what must be
archived from them.

## Compiler Evidence

Run from the CellScript crate:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo package --list --locked --allow-dirty --offline
cargo package --locked --allow-dirty --offline
```

On a clean CI or release checkout, the stricter package verification command is:

```bash
cargo package --locked --offline
```

If the release environment has crates.io network access, also run:

```bash
cargo publish --dry-run --locked
```

Network failures while fetching `https://index.crates.io/config.json` are
environment failures, not package-content failures. Package-content closure is
established by the offline package-list gate plus `cargo package` verification.

Expected coverage:

- runtime error registry consistency
- CKB Blake2b default-hash vector
- Spora stdlib BLAKE3 helper emits syscall `3001`, matching the Spora VM
  `BLAKE3_HASH` syscall table
- invalid CKB `hash_type` fail-closed
- invalid CKB `dep_type` fail-closed
- entry witness ABI encoding
- `Vec<u8>`, `Vec<Address>`, `Vec<Hash>`, and opaque nested `Vec<Vec<u8>>`
  entry-witness payload encoding
- Molecule table/vector decoding for dynamic persistent schemas
- mutate replacement-output metadata and append verifier coverage
- backend shape budgets and release baselines for the seven bundled examples

Package-content evidence:

- crates.io package contents exclude `.github/`, `docs/`, `editors/`, `tools/`,
  and auxiliary unpublished binaries
- `cargo package --locked --allow-dirty --offline` verifies the published crate
  can compile from its packaged source

## CKB Tx Shape Evidence

Run from the standalone CellScript crate when a CKB JSON transaction is
available and the parent directory also contains a local `ckb/` checkout:

```bash
cargo run --manifest-path tools/ckb-tx-measure/Cargo.toml --locked < tx.json
cargo test --manifest-path tools/ckb-tx-measure/Cargo.toml --locked
```

For the nested `Spora/cellscript` checkout, use
`scripts/ckb_cellscript_acceptance.sh` from the Spora repository root. The
acceptance script builds the same helper source through a temporary manifest
that points at the configured `CKB_REPO`, so release evidence is not tied to a
hard-coded relative checkout shape.

Archive the helper output:

- `consensus_serialized_tx_size_bytes`
- `occupied_capacity_shannons`
- `output_occupied_capacity_shannons`
- `output_capacity_shannons`
- `capacity_is_sufficient`
- `under_capacity_output_indexes`

The helper uses CKB packed transaction serialization and CKB occupied-capacity
logic. Any `capacity_is_sufficient=false` result is a release blocker.

## Spora Acceptance Evidence

Archive the Spora devnet acceptance report tree, including:

- production gate status
- bundled example deployment status
- standard relay compatibility
- malformed rejection matrix
- mass policy values and measured mass evidence

Do not use relaxed or bounded diagnostic runs as production release evidence.

## CKB Acceptance Evidence

Archive the CKB acceptance/final hardening report tree, including:

- strict original policy status for all bundled examples
- scoped action and lock compile coverage
- builder-backed action count
- dry-run cycles
- consensus serialized tx size
- occupied capacity
- under-capacity output check
- malformed rejection matrix

The final hardening gate must fail if builder-generated transactions are
missing, tx-size evidence is missing, occupied-capacity evidence is missing, or
any generated output is under-capacity.

Validate the CKB release evidence with:

```bash
python3 ../scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

The validator requires production mode, strict original compile coverage,
`43/43` builder-backed action runs, exact per-family action coverage, passed
valid transaction dry-runs, committed valid transactions, rejected malformed
transactions, malformed rejection reasons that are not policy/capacity
failures, positive measured cycles, consensus-serialized transaction size,
exact occupied capacity, per-output capacity sufficiency, no under-capacity
outputs, and a passed `final_production_hardening_gate`. `--compile-only` can
validate the strict compile gate, but it is not sufficient for external release
evidence.

## Documentation Evidence

The 0.12 documentation set must include:

- runtime error code table
- CKB profile authoring guide
- CKB deployment manifest guide
- capacity and builder contract
- entry witness ABI specification
- collections support matrix
- mutate and replacement output guide
- linear ownership guide
- scheduler hints guide
- 0.12 migration notes
- docs/examples authoring examples

The top-level bundled examples remain exactly:

```text
amm_pool.cell
launch.cell
multisig.cell
nft.cell
timelock.cell
token.cell
vesting.cell
```
