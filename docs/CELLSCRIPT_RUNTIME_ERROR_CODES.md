# CellScript Runtime Error Codes

CellScript-generated artifacts return `0` on success. Non-zero values are
stable runtime verifier error codes emitted by generated fail-closed paths.

The compiler also emits an assembly comment next to generated fail handlers:

```asm
# cellscript runtime error 14 mutate-transition-mismatch
li a0, 14
```

Use the error name first when debugging. Numeric codes are retained for VM,
wallet, explorer, and acceptance-script compatibility.

The table was introduced in compile metadata schema 30 and is emitted by the
current metadata schema 68 on the `0.30` development branch under
`constraints.runtime_errors`, so `cellc constraints`, `cellc check --json`, and
sidecar metadata all expose the same machine-readable registry.
The experimental `0.26b` baseline emitted the same registry in schema 67.
The verified lowering record also identifies mapped runtime-error exits, and
`cellc test` negative scenarios must match both the numeric code and stable
name under the selected execution backend.
When a CLI failure can be tied to this registry, stderr uses the same
`error[E####]` code and points to `cellc explain E####`.

## Error-Code Channels

Some CellScript runtime error numbers intentionally overlap with CKB syscall
return codes and RISC-V exception causes. For example, CellScript code `1`
means `syscall-failed`, while a raw CKB syscall return value of `1` means
`CKB_INDEX_OUT_OF_BOUND` in the syscall ABI.

This overlap is functionally safe because the values travel through different
channels. A generated verifier returns a CellScript error only by loading the
stable CellScript code into `a0` and exiting normally. Raw CKB syscall return
codes are checked immediately after `ecall` and are converted into CellScript
errors before verifier exit. A RISC-V exception or VM trap is reported by the
CKB-VM as a VM-level failure, not as the verifier's normal `a0` return value.

Use the table below only for normal CellScript verifier exit codes. Do not
interpret raw syscall status registers or VM trap diagnostics with this table.

On `0.26b`, the versioned `current-vm-process-exit-v1` contract makes generated
fatal verification failures terminate the current VM process, including failures
inside helpers whose results the caller discards. Ordinary nonzero integers,
false predicates, wide/aggregate values and explicitly exposed raw status APIs
remain values; they are not implicit exceptions. The machine exit uses the
[CKB EXIT ABI](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0009-vm-syscalls/0009-vm-syscalls.md#exit).
A spawning parent can still observe a child's exit through its explicit status
API. See the [verified artifact boundary](CELLSCRIPT_VERIFIED_ARTIFACT_BOUNDARY.md#fatal-verifier-failures)
for the independent check's exact scope.

| Code | Name | Meaning | Debugging hint |
|---:|---|---|---|
| 1 | `syscall-failed` | A target VM syscall returned a non-zero status while loading transaction context. | Check transaction input/output/cell_dep indexes, source flags, and target-profile syscall compatibility. |
| 2 | `bounds-check-failed` | Loaded bytes were smaller than the verifier-required minimum. | Check witness or cell data length against the schema manifest and entry ABI report. |
| 3 | `cell-load-failed` | Cell data or field loading failed or returned an unusable result. | Check that the expected input, output, or dep cell exists and is reachable by the generated script. |
| 4 | `exact-size-mismatch` | Loaded bytes did not match the exact fixed-size schema requirement. | Check fixed-width schema fields and ensure the builder encodes the exact Molecule byte length. |
| 5 | `assertion-failed` | A source-level assert or invariant check evaluated to false. | Inspect the action invariant or assert expression and the transaction values that feed it. |
| 7 | `flow-transition-mismatch` | A flow transition did not match the declared transition rule. | Compare consumed and produced state fields with the declared flow transitions. |
| 8 | `flow-new-state-invalid` | A created or proposed output state value was outside the declared state range. | Check created output state values and declared flow states. |
| 9 | `flow-old-state-invalid` | A consumed state value was outside the declared state range. | Check consumed input state values and declared flow states. |
| 10 | `entry-witness-magic-mismatch` | Entry witness bytes did not start with the CellScript witness ABI magic. | Encode entry witnesses with `cellc entry-witness` or the documented `CSARGv1\0` wire format. |
| 11 | `type-hash-preservation-mismatch` | A proposed output did not preserve the consumed input type hash. | Check the proposed output type script and builder output ordering. |
| 12 | `lock-hash-preservation-mismatch` | A proposed output did not preserve the consumed input lock hash. | Check the proposed output lock script and builder output ordering. |
| 13 | `field-preservation-mismatch` | An output field required to be preserved differs from its input field. | Check proposed output fields that should preserve lock/type/data identity. |
| 14 | `mutate-transition-mismatch` | A proposed output failed its declared field transition check. | Check the field delta against the documented transition formula. |
| 15 | `data-preservation-mismatch` | Proposed output data outside transition ranges differs from the input data. | Check that non-transition output data bytes are copied from the consumed input. |
| 16 | `dynamic-field-bounds-invalid` | A Molecule dynamic field offset or length failed bounds validation. | Validate Molecule table offsets, field count, and dynamic field lengths. |
| 17 | `type-hash-mismatch` | A loaded cell type hash did not match the expected CellScript type identity. | Check type script hash/hash_type/args and the expected CellScript type identity. |
| 18 | `fixed-byte-comparison-unresolved` | A fixed-byte verifier comparison could not resolve its trusted source bytes. | Use schema-backed parameters or fixed-byte values that the verifier can address. |
| 20 | `numeric-or-discriminant-invalid` | A numeric verifier check, enum discriminant, or arithmetic guard failed. | Check enum tags, arithmetic bounds, and generated collection length arithmetic. |
| 21 | `collection-bounds-invalid` | A runtime collection index, length, or capacity check failed. | Check collection length, index, and capacity values in witness or cell data. |
| 22 | `consume-invalid-operand` | A consume operation or target-profile runtime primitive reached an unsupported operand/path. | Inspect compiler metadata blockers and target-profile policy output. |
| 23 | `destroy-invalid-operand` | A destroy operation reached codegen with an invalid or unsupported operand. | This indicates an unsupported lowering path; inspect compiler metadata blockers. |
| 24 | `collection-runtime-unsupported` | A runtime collection helper shape is not supported by the current backend. | Avoid advertising this collection helper as production-ready until support is implemented. |
| 25 | `entry-witness-abi-invalid` | Entry witness payload layout, width, or parameter ABI placement was invalid. | Inspect `cellc constraints` or `cellc abi` output for parameter slots and witness byte layout. |
| 26 | `capacity-preservation-mismatch` | A proposed output did not preserve the consumed input capacity. | Check the proposed output capacity and builder output ordering. |
| 32 | `dynamic-field-value-mismatch` | A dynamic Molecule field value did not match the expected verifier source. | Check dynamic Molecule field encoding and the value source used by the verifier. |
| 33 | `out-point-mismatch` | A loaded input OutPoint field did not match the expected transaction lineage. | Check the input OutPoint tx hash/index and the expected lineage binding. |
| 34 | `script-field-malformed` | A loaded CKB Script field did not match the expected Molecule Script layout. | Check the lock/type Script Molecule encoding, args length, and whether the cell actually has that script field. |
| 35 | `dao-header-lineage-mismatch` | The DAO field loaded from an input's committed block header did not match the supplied HeaderDep. | Bind the HeaderDep to the exact input/deposit header used for DAO accumulated-rate accounting. |
| 36 | `dao-maturity-violation` | The DAO input since value was below the required maturity lower bound. | Check the withdrawal request since value and ensure the consumed DAO input has reached the required maturity. |
| 37 | `ckb-since-malformed` | A CKB since value, constructor argument, or typed narrowing was malformed. | Check reserved flags, metric type, scalar/timestamp bounds, epoch number/index/length bounds, and requested mode/metric. |
| 38 | `script-args-mismatch` | A loaded CKB Script args field did not match the expected args policy. | Check lock/type script args and whether this protocol path requires empty script args. |
| 39 | `metapoint-mismatch` | A loaded CKB MetaPoint relation did not match the expected input/output index and relative distance. | Check the paired input OutPoints or output indexes and the signed relative-distance field. |
| 40 | `metapoint-cardinality-mismatch` | A current-script lock/type MetaPoint pair scan found a duplicate, missing, or unbalanced relation. | Check current-script lock-only/type-only cell counts and ensure every MetaPoint has exactly one paired cell. |
| 41 | `script-identity-mismatch` | A loaded CKB Script code_hash or hash_type did not match the expected identity. | Check Script code_hash, hash_type, deployed dep, and whether lock/type role is correct. |
| 42 | `witness-malformed` | Loaded witness bytes did not match the expected Molecule WitnessArgs layout or ABI magic. | Verify witness encoding follows the expected Molecule format with correct total_size, field_count and field offsets. |
| 43 | `witness-field-truncated` | A WitnessArgs field offset or length exceeded the loaded witness byte range. | Check that each witness field offset and data length fall within the loaded witness byte range. |
| 44 | `ckb-source-view-invalid` | A CKB SourceView value was malformed or used with an incompatible source-specific helper. | Pass a SourceView produced by the matching `source::*` helper and keep indexes in range. |
| 45 | `header-dep-missing` | A required HeaderDep source view was absent or could not be bound to the requested header. | Add the required header dep and bind it to the input/deposit whose DAO data is read. |
| 46 | `dao-field-malformed` | A loaded DAO header or cell field did not match the expected encoded layout. | Check DAO header bytes, accumulated-rate width, and deposit/withdrawal cell data layout. |
| 47 | `script-role-mismatch` | The script was used in a lock/type role that violates the declared invariant. | Check whether the script is deployed and invoked as the expected lock or type script. |
| 48 | `xudt-binding-mismatch` | An xUDT type args, owner-mode, or amount binding check failed. | Check xUDT type args, owner-mode flags, input type hash, and token data layout. |
| 49 | `aggregate-amount-mismatch` | A lowered aggregate/C256 accounting equality or inequality check failed. | Compare generated aggregate inputs/outputs and inspect overflow or exact-equality assumptions. |
| 50 | `bip340-pipe-create-failed` | The BIP340 runtime verifier path failed while creating the IPC pipe. | Check CKB VM v2 pipe syscall availability and parent script VM version. |
| 51 | `bip340-spawn-failed` | The BIP340 runtime verifier path failed while resolving or spawning the verifier CellDep. | Check verifier CellDep ordering, out_point, hash_type, and spawn source/place wiring. |
| 52 | `bip340-message-write-failed` | The BIP340 runtime verifier path failed while writing the 32-byte message hash. | Compare the generated 32-byte message hash words with the verifier CLI input. |
| 53 | `bip340-pubkey-write-failed` | The BIP340 runtime verifier path failed while writing the 32-byte x-only pubkey. | Compare the generated 32-byte x-only pubkey words with the verifier CLI input. |
| 54 | `bip340-signature-write-failed` | The BIP340 runtime verifier path failed while writing the 64-byte signature. | Compare the generated 64-byte signature words with the verifier CLI input. |
| 55 | `bip340-verifier-read-failed` | The BIP340 runtime verifier path failed while closing or reading verifier IPC status. | Check IPC fd close/read/wait wiring between parent and child verifier. |
| 56 | `bip340-child-rejected` | The spawned BIP340 child verifier returned a non-zero verification status. | Run the exact message, pubkey, and signature tuple through the local verifier CLI. |
| 57 | `fixed-u64-le-input-unresolved` | The backend could not materialize a fixed-byte input for a u64 little-endian load. | Inspect schema field provenance for the fixed-byte scalar source. |
| 58 | `fixed-byte-comparison-materialization-unresolved` | The backend could not materialize one side of a fixed-byte comparison. | Inspect fixed-byte provenance for schema fields, aliases, nested projections, and local aggregates. |
| 59 | `bip340-message-materialization-unresolved` | The backend could not materialize the 32-byte BIP340 message hash for verifier IPC. | Compare signed_intent_hash provenance with the local verifier tuple. |
| 60 | `bip340-pubkey-materialization-unresolved` | The backend could not materialize the 32-byte BIP340 x-only pubkey for verifier IPC. | Inspect the nested witness pubkey field source and copied ABI bytes. |
| 61 | `bip340-signature-materialization-unresolved` | The backend could not materialize the 64-byte BIP340 signature for verifier IPC. | Inspect the nested witness signature field source and copied ABI bytes. |
| 62 | `packed-hash-preimage-materialization-unresolved` | The backend could not materialize canonical packed bytes for a packed hash preimage. | Inspect packed-hash lowering and schema-backed fixed aggregate materialization. |
| 63 | `bounded-cell-dep-not-found` | A bounded resolved CellDep scan did not find the required data hash. | Check the compile-time scan bound, resolved CellDep order, expected data hash, and builder manifest. |
| 64 | `merkle-root-mismatch` | A bounded SHA256d Merkle proof did not reconstruct the expected root. | Check leaf byte order, sibling order, depth, leaf index, hash algorithm, and expected root. |
| 65 | `shift-amount-invalid` | A runtime integer shift amount was greater than or equal to the left operand width. | Keep runtime shift amounts below the bit width of the shifted integer value. |
| 66 | `sighash-all-unsupported` | Canonical CKB transaction sighash construction is deferred and cannot produce a digest. | Use an authenticated standard Lock or an explicit verifier with an independently specified message contract. |

## Stability

- Existing numeric codes must not be reused for a different condition.
- New generated fail-closed paths must add a registry entry before they can
  emit a new non-zero code.
- Codes `6`, `19`, `27` through `31`, and values above `66` are currently reserved.
