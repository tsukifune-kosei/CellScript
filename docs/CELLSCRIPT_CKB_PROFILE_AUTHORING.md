# CellScript CKB Profile Authoring

**Status**: production authoring guide for the CellScript 0.12 CKB profile.

The CKB profile is not a Spora artifact with different flags. It is a separate
lowering profile with CKB syscall numbers, canonical CKB source constants,
Molecule-facing schemas, CKB deployment metadata, and CKB admission constraints.

Use this guide when writing `.cell` source or package manifests that must deploy
through the CKB path.

## Compile Target

Use the CKB profile explicitly:

```bash
cellc check examples/token.cell --target-profile ckb
cellc examples/token.cell --target riscv64-elf --target-profile ckb --entry-action transfer -o build/token-transfer.elf
cellc constraints examples/token.cell --target-profile ckb --json
```

Production CKB builds should use scoped action or lock entries. Full-file
monolith artifacts are accepted only when they pass the same relay, size,
capacity-evidence, and policy gates as scoped artifacts.

## Time APIs

Use `env::current_timepoint()` for cross-profile source code.

Profile lowering:

- Spora: lowers to DAA score.
- CKB: lowers to CKB epoch semantics.

Use `env::current_daa_score()` only for Spora-only contracts. The CKB profile
rejects DAA-specific APIs because CKB headers do not expose Spora DAA.

For CKB since-style locks, use CKB-specific authoring and builder evidence.
The compiler exposes the timelock policy in `constraints.ckb.timelock_policy`;
the transaction builder must still set concrete input `since` values and retain
release evidence for the produced transaction.

## Hashing

CKB artifact identity and release evidence use Blake2b-256 with the
`ckb-default-hash` personalization.

Use:

```bash
cellc ckb-hash --file build/token
cellc ckb-hash --hex 00
```

Rust builders can call:

```rust
let digest = cellscript::ckb_blake2b256(bytes);
```

This is the supported 0.12 builder/release helper. Do not document or depend on
generic in-script dynamic `ckb::blake2b256(data)` unless the final artifact
links a real RISC-V Blake2b implementation and that path is covered by the
production gate.

## Deployment Manifest

Put CKB deployment facts in `Cell.toml` instead of hard-coding them in scripts:

```toml
[package]
name = "token"
version = "0.1.0"

[deploy.ckb]
hash_type = "data1"
out_point = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0"
dep_type = "code"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd:0"
dep_type = "dep_group"
hash_type = "type"
```

For compatibility with existing manifests, a cell dep may also use separate
`tx_hash` and `index` fields. Do not specify both `out_point` and
`tx_hash`/`index` for the same cell dep; conflicting locations fail closed.

Supported `hash_type` values:

- `data`
- `type`
- `data1`
- `data2`

Supported `dep_type` values:

- `code`
- `dep_group`

Invalid values fail compilation. They are not warnings.

## Capacity and Size

The compiler emits lower bounds and evidence requirements. It does not claim to
statically prove every CKB transaction's occupied capacity.

Production builders must retain:

- occupied capacity for every output
- consensus-serialized transaction size
- dry-run or VM cycle evidence
- code cell data hash
- deployment manifest hash type and cell dep usage

Inspect the current contract with:

```bash
cellc constraints contract.cell --target-profile ckb --json
```

Relevant metadata paths:

- `constraints.artifact`
- `constraints.entry_abi`
- `constraints.ckb.capacity_evidence_contract`
- `constraints.ckb.hash_type_policy`
- `constraints.ckb.dep_group_manifest`

## Entry Witness ABI

Inspect action or lock witness layout before building transactions:

```bash
cellc abi examples/token.cell --target-profile ckb --action transfer
cellc entry-witness examples/token.cell --target-profile ckb --action transfer --json
```

Scalar parameters are assigned to the CKB-VM argument registers first and may
spill according to the documented ABI. Schema-backed and fixed-byte payloads
use the CellScript entry witness payload format:

```text
magic(8) | version(u16) | flags(u16) | action_hash(32) | arg_count(u16)
args: kind(u8) | reserved(u8) | len(u32) | bytes
```

The compiler reports unsupported ABI layouts fail-closed. Builders should not
guess witness layouts from source text.

## CellDeps and DepGroups

CKB CellDeps are transaction-level facts. In 0.12, CellScript exposes DepGroup
requirements through the package manifest and metadata, not through a first-class
DSL statement.

Builders must either:

- include the declared DepGroup exactly, or
- expand it intentionally and record that choice in release evidence.

The compiler reports the manifest under `constraints.ckb.dep_group_manifest`.

## Type ID and Lineage

CellScript can expose type-id and lineage expectations in metadata, but the CKB
builder remains responsible for constructing the creation transaction and
verifying the deployed script matches the expected type-id lineage.

Do not treat a local name hash as a CKB Type ID. CKB Type ID behavior depends on
the first input and output index of the creation transaction.

## Spora-Only Features

The CKB profile rejects Spora-only surfaces, including:

- DAA-specific APIs
- Spora-only syscalls
- Spora VM ABI trailer assumptions
- Spora BLAKE3 identity rules for CKB artifact identity
- scheduler-only mass policy as a replacement for CKB capacity/cycles/tx-size

When code must support both chains, prefer cross-profile APIs and let
`cellc check --target-profile portable-cell` catch accidental profile leakage.

## Production Checklist

Before claiming a CKB artifact is production-ready:

1. Compile the scoped action or lock with `--target-profile ckb`.
2. Run `cellc constraints --target-profile ckb --json`.
3. Run `cellc abi` for every externally callable entry.
4. Compute artifact hashes with `cellc ckb-hash`.
5. Ensure the package manifest records hash type and CellDeps.
6. Build a concrete transaction and retain occupied-capacity, tx-size, and cycle evidence.
7. Run the CKB acceptance/final hardening gate.
8. Archive the constraints report, deployment manifest, transaction evidence, and artifact hash.
