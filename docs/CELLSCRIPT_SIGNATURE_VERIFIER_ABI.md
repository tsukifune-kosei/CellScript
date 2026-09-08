# CellScript BIP340 Verifier CellDep ABI

**Status**: executable verifier boundary plus one bounded 0.30 CKB
signing-message domain; deployment and authority policy remain package
responsibilities.

CKB-VM does not provide a signature-verification syscall. CellScript therefore
spawns a separately deployed verifier binary from a transaction `CellDep` and
sends one fixed request over an inherited VM2 pipe.

## Source API

Use the explicit form for new code:

```cellscript
ckb::require_cell_data_hash(source::cell_dep(3), pinned_verifier_data_hash)
verifier::btc::bip340::require_signature_from_cell_dep(
    3,
    message_hash,
    xonly_pubkey,
    signature,
)
```

The dependency index must be an integer literal in `0..=63`. The
`require_cell_data_hash` preflight binds the selected resolved CellDep's data
hash before it is spawned. `require_signature(message_hash, xonly_pubkey,
signature)` remains a compatibility spelling that selects CellDep index `0`;
new packages should make the index explicit.

The expected verifier data hash must come from a reviewed manifest or other
trusted package configuration. Accepting it from witness data does not create
an identity guarantee. A builder must also pin the dependency out point and
`dep_type`; CKB syscalls expose the resolved CellDep sequence, not the original
DepGroup container identity.

## Frozen Request Envelope

The spawned verifier receives exactly 144 bytes (`18` little-endian `u64`
writes) on inherited file descriptor `0`:

| Offset | Size | Field | Required value |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `NSBV0IPC` |
| 8 | 2 | version | `0`, little-endian |
| 10 | 2 | scheme | `1`, BIP340 Schnorr/secp256k1 |
| 12 | 4 | flags | `0` |
| 16 | 32 | message | caller-provided prehash |
| 48 | 32 | public key | BIP340 x-only key |
| 80 | 64 | signature | BIP340 `r || s` |

Exit code `0` accepts. Any non-zero child exit, pipe/spawn/write/close/wait
failure, malformed fixed-width value, or dependency mismatch rejects the
parent script with a stable runtime error.

The compatible verifier package in `proposals/novaseal/v0-mvp-skeleton` pins
`verifier_id = "btc.bip340.v0"` and
`ipc_abi = "cellscript-btc-bip340-ipc-v0"`. That package is deployment evidence,
not an ambient standard-library implementation.

## Security Boundary

This ABI verifies only the supplied 32-byte prehash against the supplied key
and signature. The application profile must separately define and test:

- domain separation and canonical message construction;
- CKB ScriptGroup and `WitnessArgs` selection;
- lock placeholder and sighash rules;
- binding the verified key to on-chain authority;
- chain, script, action, nonce, and protocol replay policy;
- exact verifier artifact/out point and upgrade policy;
- positive and negative CKB-VM fixtures.

The compiler does not infer these rules from action names or field names. A
successful BIP340 call is not, by itself, proof that the correct transaction
message or authority was verified.

## Bounded zero-lock signing domain

The 0.30 development surface provides one explicitly named message contract:

```cellscript
let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
verifier::btc::bip340::require_signature_from_cell_dep(
    3,
    digest,
    xonly_pubkey,
    signature,
)
```

The arguments are compile-time bounds for current-group inputs, transaction
inputs, witnesses after the input count, and bytes in each included witness.
Their admitted ranges are `1..=64`, `1..=256`, `0..=64`, and `1..=65536`, and
the group bound cannot exceed the input bound. Exceeding a declared runtime
bound terminates with error `69 sighash-bound-exceeded`.

The helper computes CKB default Blake2b-256 over this exact sequence:

1. the exact 32-byte `LOAD_TX_HASH` result;
2. the first current-input Script-group witness, prefixed by its little-endian
   `u64` byte length, after replacing the complete `WitnessArgs.lock` payload
   with equal-length zero bytes;
3. each later present current-group witness in group order, with the same
   length prefix; and
4. each witness after the transaction input count in transaction order, with
   the same length prefix.

The first witness must be canonical Molecule `WitnessArgs`. The result type is
`SighashAllDigest`, so it cannot silently enter a generic `Hash` domain.
`Hash::from_sighash_all(digest)` is the explicit conversion when a generic hash
consumer is required. The BIP340 verifier API accepts the domain type directly.

This contract matches signers whose complete lock placeholder is zero-filled.
It does not describe multisig layouts that retain a nonzero configuration
prefix while zeroing only signature slots. Such Locks must keep using their
standard lock implementation and SDK signer, or gain a separately named and
tested CellScript message domain. Metadata schema 72 records the exact scope,
transform, ordering, digest type, and four bounds; the standalone artifact
checker binds them to typed call operands and runtime access provenance.

`env::sighash_all(source)` does not implement canonical CKB transaction
sighash construction. It is a separate legacy spelling from the bounded
zero-lock contract above. Its source spelling remains available for inspection,
but metadata classifies it as `ckb-sighash-all-deferred` and
`DenyFailClosed` rejects artifact generation. Audit artifacts compiled with
`AllowFailClosed` terminate the VM with error `66 sighash-all-unsupported`
whenever the call executes, including inside a helper or with an unused result.
They cannot pass a placeholder digest to this verifier.

The explicit BIP340 API above still verifies independently supplied messages.
Standard CKB Lock signing remains a separate supported route; the real
multisig-v2 fixture in `tests/entry_witness_abi.rs` places CellScript's
`WitnessArgs.input_type` payload before SDK signing and checks post-signing
witness tampering. Neither route supplies an implicit transaction digest to a
custom CellScript Lock.
