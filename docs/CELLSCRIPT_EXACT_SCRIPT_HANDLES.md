# CellScript Exact Script Handles

Status: implemented exact-artifact source/runtime boundary on the `0.30`
development branch. Generic compatible or open handles remain deferred.

## Purpose

`ExactScriptHandle` lets one compiled contract require one already admitted
CKB Script artifact without treating a raw Script, interface, ELF, deployment,
or Registry record as interchangeable. It is an ordinary non-linear value. It
does not grant authority to consume or create a Cell.

The authoritative off-chain receipt is
`cellscript-exact-script-handle-receipt-v1`. Its runtime value uses
`CSHDLv1-fixed-202`:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | `CSHDLv1\0` magic |
| 8 | 1 | class: Script or verifier |
| 9 | 1 | role: Lock, Type, or spawned verifier |
| 10 | 32 | receipt hash |
| 42 | 32 | complete CKB Script hash |
| 74 | 32 | package interface hash |
| 106 | 32 | exact ELF artifact hash |
| 138 | 32 | target-profile hash |
| 170 | 32 | runtime-ABI hash |

`script_handle::exact_script_handle_value_hash` computes CKB Blake2b-256 over
all 202 bytes. Successful ProtocolBundle output exposes the same value as
`exact_handle_hash`; generated TypeScript binders expose it as `handleHash`.
A consuming source embeds that 32-byte result as a literal:

```cell
action verify(witness verifier: ExactScriptHandle) -> u64 {
    let dep = ckb::cell_dep(0)
    ckb::require_cell_dep_exact_verifier_handle(
        dep,
        verifier,
        Hash::from_bytes(b"0123456789abcdef0123456789abcdef")
    )
    return 0
}
```

The other checked forms are:

```cell
ckb::require_cell_lock_exact_handle(cell, lock_handle, expected_handle_hash)
ckb::require_cell_type_exact_handle(cell, type_handle, expected_handle_hash)
```

The third argument must lower from a compile-time `Hash` literal. A witness or
other runtime-selected expected hash is rejected before code generation.

## Runtime contract

All three helpers require the exact 202-byte width, magic, class, role, and
full-value hash. Lock and Type handles then compare the complete selected CKB
Script hash at the supplied typed source view. The verifier form requires a
`CellDepView` and compares its consensus data hash with the handle artifact
hash. Missing or malformed source views use error 44; any handle, commitment,
role, or selected-identity mismatch uses stable error 70.

Compile metadata records `ckb-exact-script-handle-v1`, exact 32-byte runtime
access provenance, and a checked-runtime ProofPlan entry. Typed semantics keep
the fixed handle type and literal hash operand. The standalone artifact checker
rejects helper relabeling, effect/type changes, and literal changes even when
outer sidecar hashes are recomputed. CKB-VM tests mutate every identity region
and the selected verifier artifact.

## Deferred boundary

This phase expresses exact artifact identity. `ScriptHandle<I>`,
`VerifierHandle<I>`, compatible interface selection, deployment-line upgrade
policies, Registry-selected runtime linkage, and open ProtocolBundle roles need
their own versioned construction and verification contracts. They must not be
inferred from an `ExactScriptHandle` or from matching only one embedded field.
