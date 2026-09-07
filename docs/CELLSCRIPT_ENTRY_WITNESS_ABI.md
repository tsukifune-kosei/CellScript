# CellScript Entry Witness ABI

**Status**: production contract for current CellScript authoring and builder
tooling.

CellScript action and lock entrypoints are normal RISC-V functions at the machine
level. Most public arguments come through the current script group's witness. Lock
parameters declared as `lock_args T` instead come from the executing lock
script's `Script.args` bytes. The compiler-generated `_cellscript_entry` wrapper
loads the required source(s), validates the envelope or script-args layout,
decodes positional arguments, and then tail-calls the selected action or lock.

## Placement ABI v2

The current CKB placement contract is
`cellscript-witnessargs-input-type-v2`:

```text
WitnessArgs {
  lock:       wallet / lock-script signatures,
  input_type: CellScript CSARGv1 entry payload,
  output_type: protocol-specific output witness data,
}
```

The generated wrapper first loads `GroupInput#0`. If the active script group
has no input, it loads `GroupOutput#0`. It never substitutes transaction-global
`Input#0`, because the first member of one lock/type group may be any global
input index. The selected witness must be a canonical three-field Molecule
`WitnessArgs`; its `input_type` `BytesOpt` must contain the entry payload.

A failed input-witness load does not establish that the group is empty. Before
using output fallback, the wrapper probes the mandatory capacity field of
`GroupInput#0` and requires `INDEX_OUT_OF_BOUND`. If that Cell exists, a missing
witness rejects with runtime error 25 even when `GroupOutput#0` resolves a valid
payload elsewhere. Other probe errors reject as well. This enforces the existing
placement contract without changing the payload encoding or placement identity.

This split lets canonical lock scripts, including multisig-v2, retain exclusive
ownership of `WitnessArgs.lock`. Builders must preserve an existing lock field
and fail rather than overwrite an existing `input_type` field.

Builders must place the CellScript payload before lock-script signing. CKB
signers commit to the complete serialized `WitnessArgs` while replacing only
the `lock` signature bytes with their zero placeholder; consequently,
`input_type` and `output_type` are part of the signed message. Any change to
those fields after signing invalidates the signature. The adapter helper is
therefore named `place_entry_witness_payload_before_signing`, accepts a lock
placeholder, validates the `CSARGv1\0` payload magic, and must run before the
SDK unlock/sign step.

Placement ABI `cellscript-witnessargs-input-type-v2` has no raw-payload
compatibility path. The selected group-relative witness must be a canonical
`WitnessArgs`; a raw `CSARGv1\0` payload, malformed table, absent `input_type`,
or payload placed in `lock`/`output_type` fails closed with runtime error
`25 entry-witness-abi-invalid`.

## Bounded read-only field views

Metadata schema 70 adds explicit read-only views over the outer witness and
its three owner fields. `witness::bounded_raw(view, max)` selects the complete
serialized witness; `bounded_lock`, `bounded_entry`, and
`bounded_output_type` select the payload bytes of `lock`, `input_type`, and
`output_type` respectively. `bounded_entry` therefore reads the same
`WitnessArgs.input_type` value used by the `CSARGv1` entry ABI. It does not
define another envelope or another writable field.

The maximum is a compile-time integer literal in `0..=65536`. A
`WitnessBytesView<owner,max>` exposes `.size`, exact byte/u32/u64 reads, and
full-view streaming CKB Blake2b. All offsets are relative to the selected
logical payload. The runtime reads fixed-size headers and requested words, or
streams hash chunks directly from `LOAD_WITNESS`; it does not allocate or copy
the complete logical value.

These views do not transfer field authority. Wallets and Lock Scripts still
own signature construction in `lock`; CellScript entry, bounded-plan, and
authorization consumers share the one `entry`/`input_type` value; protocols
may assign `output_type` separately. An absent `BytesOpt` fails with error 67,
while `Some(empty)` is a present zero-length value. A value above its declared
maximum fails with error 68. The 65,536-byte read-view ceiling does not widen
the 4,096-byte `CSARGv1` entry trampoline limit described below.

Metadata schema 71 adds the separately versioned
`cellscript-ckb-sighash-all-zero-lock-v1` message domain. It preserves the
serialized first `WitnessArgs` and replaces only the complete `lock` payload
with equal-length zero bytes before hashing. The existing `input_type` entry
payload and `output_type` bytes therefore remain committed. This contract
matches a completely zero-filled lock placeholder; multisig placeholders with
a retained configuration prefix continue to use their standard Lock signer or
a separately specified domain.

## Payload Envelope v1

Every parameterized entry payload that has witness-backed arguments starts with:

```text
43 53 41 52 47 76 31 00
```

This is the ASCII magic `CSARGv1\0`.

The magic remains necessary even though the resolved compatibility profile
records this ABI: Edition 2026 identifies source semantics, the placement ABI
identifies the witness location, and the magic identifies runtime bytes inside
`input_type`. It prevents unrelated protocol bytes from being decoded as
CellScript positional arguments.

Wrong magic, missing bytes, malformed Molecule, or unsupported parameter
placement fails closed with runtime error `25 entry-witness-abi-invalid`.

Entries whose parameters are entirely runtime-bound, `lock_args`-backed, or
zero-width unit values do not require a witness envelope. A unit `()` consumes
no payload bytes; the host encoder accepts either an explicit `Unit` placeholder
or its omission, producing the same bytes. It does not shift the decoded
nonempty payload value ordinal in provenance records.

The wrapper and provenance emitter share IR-based layout rules. Fixed
`Script.args` ranges are byte ranges, including nested arrays and tuples, not
signature parameter indexes. Generated read-expression names cannot suppress a
same-named scalar witness parameter: physical Cell binding identity is separate
from an author's identifier spelling.

## Compiler Buffer And Frame Bounds

The generated entry trampoline has a 4096-byte local witness decode buffer and
a 1024-byte local `Script` buffer. These are CellScript process-safety limits,
not CKB consensus limits. A witness that cannot fit the local decode buffer is
rejected before copying.

The trampoline frame size is derived from the two buffers, their size/cursor
slots, 208 reserved ABI bytes, and the saved return address. It is currently
5376 bytes and 16-byte aligned. The return-address offset is derived from that
frame size rather than maintained as an independent magic number. Outgoing
arguments beyond `a7` are staged below the current frame, then exposed by the
caller's stack adjustment; a callee prologue grows in the opposite direction
and cannot overlap the entry buffers.

## Parameter Order

Parameters are encoded in source order. The ABI does not include names or field
tags in the witness payload; names are published in metadata and in
`cellc constraints`.

Runtime-bound parameters that are supplied by cell data, type hash pointers, or
the chain environment may reserve ABI registers without consuming direct witness
payload bytes. The constraints report marks this through each parameter's
`abi_kind`, `abi_slots`, `witness_bytes`, and pointer flags.

`lock_args` parameters are decoded from `Script.args` in source order and do not
consume entry witness bytes. The wrapper currently supports fixed-width scalar,
fixed-byte, tuple, and array shapes. It rejects trailing `Script.args` bytes
after the declared typed parameters.

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

## Bounded Cell Parameters

A checked `input BoundedCellSet<T, N>` is runtime-bound to the current Type
Script `GroupInput`. It reserves a pointer/length ABI pair but consumes no
positional witness argument. A checked `witness BoundedList<P, N>` is one
schema-backed dynamic argument whose inner bytes use:

```text
"CSBPLv1\0" || u32_count_le || fixed_width_plan_elements
```

The compiler publishes `bounded-type-group-inputs-v1` or
`bounded-output-plan-v1` in `bounded_runtime_contract` and `abi_kind`.
`encode_bounded_output_plan_v1` validates element width, count, and the
4084-byte inner limit. Pass its result as one `EntryWitnessArg::Bytes` to the
action metadata's `entry_witness_args`; that helper omits the runtime-bound
input set and emits the `CSARGv1\0` length-prefixed plan argument. The CKB
adapter then places the result in `WitnessArgs.input_type` before signing.

## Inspection Commands

Use:

```bash
cellc abi contract.cell --target-profile ckb --action action_name
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
