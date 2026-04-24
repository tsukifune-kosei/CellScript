# CellScript Runtime Error Codes

CellScript-generated artifacts return `0` on success. Non-zero values are
stable runtime verifier error codes emitted by generated fail-closed paths.

The compiler also emits an assembly comment next to generated fail handlers:

```asm
# cellscript runtime error 14 mutate-transition-mismatch
li a0, 14
```

Use the symbolic name first when debugging. Numeric codes are retained for VM,
wallet, explorer, and acceptance-script compatibility.

The same table is emitted in metadata schema 29 under
`constraints.runtime_errors`, so `cellc constraints`, `cellc check --json`, and
sidecar metadata all expose the same machine-readable registry.

| Code | Name | Meaning | Debugging hint |
|---:|---|---|---|
| 1 | `syscall-failed` | A target VM syscall returned a non-zero status while loading transaction context. | Check transaction input/output/cell_dep indexes, source flags, and target-profile syscall compatibility. |
| 2 | `bounds-check-failed` | Loaded bytes were smaller than the verifier-required minimum. | Check witness or cell data length against the schema manifest and entry ABI report. |
| 3 | `cell-load-failed` | Cell data or field loading failed or returned an unusable result. | Check that the expected input, output, or dep cell exists and is reachable by the generated script. |
| 4 | `exact-size-mismatch` | Loaded bytes did not match the exact fixed-size schema requirement. | Check fixed-width schema fields and ensure the builder encodes the exact Molecule byte length. |
| 5 | `assertion-failed` | A source-level assert or invariant check evaluated to false. | Inspect the action invariant or assert expression and the transaction values that feed it. |
| 7 | `lifecycle-transition-mismatch` | A lifecycle state transition did not match the declared transition rule. | Compare consumed and produced lifecycle state fields with the declared lifecycle transitions. |
| 8 | `lifecycle-new-state-invalid` | A created or replacement lifecycle state was outside the declared state range. | Check created output lifecycle state values and declared lifecycle states. |
| 9 | `lifecycle-old-state-invalid` | A consumed lifecycle state was outside the declared state range. | Check consumed input lifecycle state values and declared lifecycle states. |
| 10 | `entry-witness-magic-mismatch` | Entry witness bytes did not start with the CellScript witness ABI magic. | Encode entry witnesses with `cellc entry-witness` or the documented `CSARGv1\0` wire format. |
| 11 | `type-hash-preservation-mismatch` | A replacement output did not preserve the consumed input type hash. | Check the replacement output type script and builder output ordering. |
| 12 | `lock-hash-preservation-mismatch` | A replacement output did not preserve the consumed input lock hash. | Check the replacement output lock script and builder output ordering. |
| 13 | `field-preservation-mismatch` | An output field required to be preserved differs from its input field. | Check replacement output fields that should preserve lock/type/data identity. |
| 14 | `mutate-transition-mismatch` | A mutable replacement output failed its declared field transition check. | Check the mutable field delta against the documented transition formula. |
| 15 | `data-preservation-mismatch` | Replacement output data outside transition ranges differs from the input data. | Check that non-transition output data bytes are copied from the consumed input. |
| 16 | `dynamic-field-bounds-invalid` | A Molecule dynamic field offset or length failed bounds validation. | Validate Molecule table offsets, field count, and dynamic field lengths. |
| 17 | `type-hash-mismatch` | A loaded cell type hash did not match the expected CellScript type identity. | Check type script hash/hash_type/args and the expected CellScript type identity. |
| 18 | `fixed-byte-comparison-unresolved` | A fixed-byte verifier comparison could not resolve its trusted source bytes. | Use schema-backed parameters or fixed-byte values that the verifier can address. |
| 19 | `claim-signature-failed` | Claim authorization signature verification failed. | Check the authorization domain, signer public key hash, signature, and target profile. |
| 20 | `numeric-or-discriminant-invalid` | A numeric verifier check, enum discriminant, or arithmetic guard failed. | Check enum tags, arithmetic bounds, and generated collection length arithmetic. |
| 21 | `collection-bounds-invalid` | A runtime collection index, length, or capacity check failed. | Check collection length, index, and capacity values in witness or cell data. |
| 22 | `consume-invalid-operand` | A consume operation or target-profile runtime primitive reached an unsupported operand/path. | Inspect compiler metadata blockers and target-profile policy output. |
| 23 | `destroy-invalid-operand` | A destroy operation reached codegen with an invalid or unsupported operand. | This indicates an unsupported lowering path; inspect compiler metadata blockers. |
| 24 | `collection-runtime-unsupported` | A runtime collection helper shape is not supported by the current backend. | Avoid advertising this collection helper as production-ready until support is implemented. |
| 25 | `entry-witness-abi-invalid` | Entry witness payload layout, width, or parameter ABI placement was invalid. | Inspect `cellc constraints` or `cellc abi` output for parameter slots and witness byte layout. |
| 32 | `dynamic-field-value-mismatch` | A dynamic Molecule field value did not match the expected verifier source. | Check dynamic Molecule field encoding and the value source used by the verifier. |

## Stability

- Existing numeric codes must not be reused for a different condition.
- New generated fail-closed paths must add a registry entry before they can
  emit a new non-zero code.
- Codes `6`, `26` through `31`, and values above `32` are currently reserved.
