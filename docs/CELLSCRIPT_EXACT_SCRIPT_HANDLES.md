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

## Pre-signing transaction validation

Every exact-handle ProofPlan record emits an `exact_script_handle` builder
assumption. `cellc tx validate` requires a keyed evidence record before
signing:

```json
{
  "builder_assumption_evidence": {
    "<assumption-id>": {
      "assumption_id": "ba-<assumption-id>",
      "kind": "exact_script_handle",
      "origin": "action:verify#exact-script-handle:0:1",
      "feature": "spawned-verifier:<64-lowercase-hex-handle-hash>",
      "proof_plan_status": "checked-runtime",
      "evidence": {
        "handle": "0x<202-byte-CSHDLv1-value>",
        "source": { "location": "cell_dep", "index": 0 },
        "witness": { "index": 0, "field": "input_type" }
      }
    }
  }
}
```

The source location is `input`, `output`, or `cell_dep` and must match the
typed source view compiled into the helper call. The indexed transaction item
must expose enough resolved data to recompute the selected identity: a concrete
Lock/Type Script or its full hash for Script handles, and concrete data or its
consensus data hash for a verifier CellDep. A CellDep outpoint alone is not
sufficient evidence.

The indexed witness may be a canonical raw Molecule `WitnessArgs` hex value or
an object whose `input_type` contains the `CSARGv1` entry payload. Validation
decodes the compiled parameter layout and requires the complete 202-byte value
at the declared exact-handle parameter position. It rejects a correct value in
the wrong parameter slot, a copied evidence value absent from the transaction,
wrong source or witness indexes, Script args/hash-type changes, substituted
CellDep data, and changes to any receipt/interface/artifact/profile/ABI byte.
This is deterministic metadata evidence; CKB-VM execution and tx-pool
acceptance remain separate release checks.

## Deferred boundary

This phase expresses exact artifact identity. `ScriptHandle<I>`,
`VerifierHandle<I>`, compatible interface selection, Registry-selected runtime
linkage, and open ProtocolBundle roles need their own versioned construction
and verification contracts. The exact active-version deployment-line path is
specified in [Deployment-line handles](CELLSCRIPT_DEPLOYMENT_LINE_HANDLES.md).
Compatible/open behavior must not be inferred from either fixed handle or from
matching only one embedded field.
