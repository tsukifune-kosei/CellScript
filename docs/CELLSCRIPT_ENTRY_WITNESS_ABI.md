# CellScript Entry Witness ABI

**Status**: production contract for CellScript 0.12 authoring and builder tooling.

CellScript action and lock entrypoints are normal RISC-V functions at the machine
level, but chain transactions provide their public arguments through the grouped
input witness. The compiler-generated `_cellscript_entry` wrapper loads that
witness, validates the envelope, decodes positional arguments, and then tail-calls
the selected action or lock.

## Envelope

Every parameterized entry witness starts with:

```text
43 53 41 52 47 76 31 00
```

This is the ASCII magic `CSARGv1\0`.

Wrong magic, missing bytes, or unsupported parameter placement fails closed with
runtime error `25 entry-witness-abi-invalid`.

## Parameter Order

Parameters are encoded in source order. The ABI does not include names or field
tags in the witness payload; names are published in metadata and in
`cellc constraints`.

Runtime-bound parameters that are supplied by cell data, type hash pointers, or
the chain environment may reserve ABI registers without consuming direct witness
payload bytes. The constraints report marks this through each parameter's
`abi_kind`, `abi_slots`, `witness_bytes`, and pointer flags.

## Scalar Parameters

Fixed-width scalars are encoded little-endian.

| Type | Witness bytes |
|---|---:|
| `bool` | 1 |
| `u8` | 1 |
| `u16` | 2 |
| `u32` | 4 |
| `u64` | 8 |
| `u128` | 16 |

Scalar arguments are placed into ABI slots in source order. The first eight slots
map to `a0..a7`; additional scalar slots are spilled to the caller stack by the
entry wrapper. The constraints report exposes `register_slots_used`,
`stack_spill_slots`, and `stack_spill_bytes`.

## Fixed-Byte Parameters

Fixed byte values such as `Address`, `Hash`, and fixed byte arrays are encoded as
raw bytes with an exact-size check. The entry wrapper passes them as
pointer/length pairs. A fixed-byte parameter whose length is wrong fails closed
with `4 exact-size-mismatch`.

## Schema-Backed Dynamic Parameters

Schema-backed values are encoded as:

```text
u32 little-endian byte_length
byte[byte_length] payload
```

The payload is Molecule data for the parameter's published schema. The wrapper
passes a pointer/length pair to the action. If the parameter also needs a trusted
type hash, metadata marks the additional type-hash pointer/length pair.

Schema-backed and fixed-byte pointer/length pairs must not cross the `a0..a7`
boundary. If placement would split the pair across registers and stack, the
compiler marks the entry unsupported and the production gate must fail.

## Inspection Commands

Use:

```bash
cellc abi contract.cell --target-profile spora --action action_name
cellc abi contract.cell --target-profile ckb --action action_name
cellc constraints contract.cell --target-profile spora --entry-action action_name
cellc constraints contract.cell --target-profile ckb --entry-action action_name
```

The `cellc abi` report is the focused developer-facing view. The
`constraints.entry_abi` report remains the canonical machine-readable contract
for CI and builders. Both include:

- parameter name and type
- ABI classification
- register and stack placement
- witness byte count
- pointer/length pair placement
- unsupported reasons

The same metadata also includes `constraints.runtime_errors`, which maps the
runtime numeric exit codes to stable names and debugging hints.
