# CKB Hashing Example

This example is intentionally documented as a builder/release workflow instead
of a bundled `.cell` source file. The top-level `examples/*.cell` suite is fixed
to the seven production examples used by regression tests.

## Hash Artifact Bytes

```bash
cellc examples/token.cell \
  --target riscv64-elf \
  --target-profile ckb \
  --entry-action transfer \
  -o build/token-transfer.elf

cellc ckb-hash --file build/token-transfer.elf --json
```

The command uses CKB Blake2b-256 with `ckb-default-hash` personalization.

## Hash Hex Input

```bash
cellc ckb-hash --hex 00
```

Empty bytes are the pinned vector:

```text
44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e
```

## Rust Builder API

```rust
let data_hash = cellscript::ckb_blake2b256(artifact_bytes);
```

This does not imply arbitrary in-script dynamic Blake2b support. It is the
0.12 builder and release-evidence surface.
