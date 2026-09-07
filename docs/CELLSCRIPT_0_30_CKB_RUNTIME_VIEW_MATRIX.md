# CellScript 0.30 CKB Runtime-View Matrix

## Status and contract

**Status: active implementation matrix for
`cellscript-ckb-runtime-view-v1`. This is a development contract, not a claim
that issue #24 or the 0.30 release gate is complete.**

Compile metadata schema 68 records the contract name in
`runtime.ckb_runtime_view_contract`. Metadata validation rejects an absent,
older, or changed value. The contract covers typed, read-only views and the
bounded CKB runtime operations listed below. It does not grant Cell lifecycle
authority and does not turn a value read from a transaction into authorization.

The syscall behavior is based on CKB's
[VM Syscalls RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0009-vm-syscalls/0009-vm-syscalls.md)
and
[syscall summary](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0046-syscalls-summary/0046-syscalls-summary.md).
`LOAD_HEADER_BY_FIELD` exposes epoch number, epoch start block number, and epoch
length. Header timestamp and exact block number require bounded full-header
decoding and are not represented as field-syscall values.

The typed temporal subset is defined separately in the
[0.30 temporal-domain contract](CELLSCRIPT_0_30_TEMPORAL_DOMAINS.md) and follows
CKB RFC0017 wire semantics.

## Classification terms

| Status | Meaning |
|---|---|
| Executable | Typed source accepted, bounded lowering emitted, and a runtime failure terminates verification. |
| Executable, limited | Executable only for the named fixed-width or bounded shape. |
| Composition boundary | Executable only after an exact external identity and adapter contract is declared. |
| Builder evidence | Supplied or checked outside CKB-VM and never presented as an ambient syscall result. |
| Deferred | Rejected or unavailable in production artifacts until its typed and bounded contract exists. |
| Outside 0.30 | Deliberately excluded from the release portfolio. |

## Typed read-only handles

Every constructor takes a `u64` index. `InputView<T>` and `OutputView<T>` also
require a declared cell-backed resource, shared type, or receipt type argument.
The runtime representation is a closed source-kind/index pair. A malformed pair
fails with `ckb-source-view-invalid`; a missing indexed item fails through the
field-specific terminal error.

| Handle and constructor | Source | Executable fields | Source type | Runtime width and failure |
|---|---|---|---|---|
| `ckb::input<T>(i)` | Input | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script`, `out_point`, `since: EncodedSince` | `InputView<T>` | Scalars are 8 bytes; hashes are 32 bytes; OutPoint is 36 bytes. Invalid/missing reads terminate. |
| `ckb::group_input<T>(i)` | GroupInput | Same field set as `InputView<T>` | `InputView<T>` | Same fixed widths; current Script-group-relative index. |
| `ckb::output<T>(i)` | Output | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script`, `output_index` | `OutputView<T>` | Same scalar/hash bounds; output index is derived from the closed source view. |
| `ckb::group_output<T>(i)` | GroupOutput | Same field set as `OutputView<T>` | `OutputView<T>` | Same fixed widths; current Script-group-relative index. |
| `ckb::cell_dep(i)` | CellDep | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script` | `CellDepView` | Same fixed widths. Resolved dep position is runtime evidence; original DepGroup/OutPoint identity remains builder or manifest evidence. |
| `ckb::header_dep(i)` | HeaderDep | `epoch_number: EpochNumber`, `epoch_start_block_number: BlockNumber`, `epoch_length: EpochLength` | `HeaderDepView` | Each field is exactly 8 bytes through `LOAD_HEADER_BY_FIELD`; bad source uses error 44 and missing/one-past-last HeaderDep uses error 45. |
| `witness::args(i)` | Witness/Input | `size`, fixed 32-byte `lock`, `input_type`, `output_type` projections | `WitnessArgsView` | `size` is 8 bytes. Field projections are executable only when the selected Molecule field is exactly 32 bytes; malformed/truncated values use errors 42/43. |
| `ckb::input_out_point(input)` or `input.out_point` | inherited Input/GroupInput | `tx_hash`, `index` | `OutPoint` | 32-byte transaction hash plus 4-byte CKB index widened to `u64`; incompatible source or malformed width terminates. |
| `ckb::lock_script(cell)` or `cell.lock` | inherited Cell source | `hash`, `code_hash`, `hash_type`, `args_empty`, `args_hash` | `ScriptView` | Complete `hash` is `ScriptHash`; `code_hash` and `args_hash` are raw `Hash`; scalar fields are bounded and Molecule-checked. |
| `ckb::type_script(cell)` or `cell.type_script` | inherited Cell source | Same as Lock `ScriptView` | `ScriptView` | An absent Type Script is not fabricated. Use `ckb::cell_has_type(cell)` before a conditional read. |

`ScriptHash`, `Hash`, and `Address` are separate source domains. A complete
Lock/Type Script hash from a typed view is `ScriptHash`. A code hash, data hash,
transaction hash, or args hash is `Hash`. `ckb::script_hash(hash)` is an
explicit assertion that already trusted raw bytes represent a complete Script
hash; it does not prove existence, deployment, or authorization.

## Existing bounded runtime families

| Family | Admitted operations | Classification and bound |
|---|---|---|
| Source views | `source::{input,output,group_input,group_output,cell_dep,header_dep}` | Executable closed source-kind/index values. Legacy `u64` consumers remain accepted for Edition 2026 compatibility; typed handles are preferred for new authoring. |
| Cell scalars and fixed bytes | capacity/occupied/unoccupied, count, type presence, data size, exact u8/u32/u64 reads, serialized Script byte/size reads | Executable or executable limited. Every byte offset is checked; fixed reads never allocate an unbounded buffer. |
| Cell identities | data/lock/type hash reads and requirements, Script code-hash/hash-type/args checks, current Script args checks | Executable fixed 32-byte or scalar reads. Absent Type Script and wrong Script domain fail closed. |
| Input lineage | full OutPoint transaction hash/index requirements and MetaPoint pair helpers | Executable fixed-width helpers. Pair scanners are protocol-neutral but have separately documented cardinality bounds. |
| Temporal and DAO | typed HeaderDep fields, opaque `InputView.since`, `since_absolute_epoch`, `since_relative_epoch`, explicit raw conversions, legacy raw constructors, DAO accumulated-rate/header-lineage/maturity helpers | The additive epoch subset is executable under the typed temporal contract. Same-domain epoch-Since comparisons use canonical fraction ordering. Block/timestamp variants, decoded Since, and duration arithmetic remain owned by issue #12. |
| Witness | count/size, exact byte/u32/u64/bytes32 reads, bounded spans, selected gather hashing, fixed 32-byte WitnessArgs fields | Executable limited. Arbitrary materialization of a variable-length witness or WitnessArgs field is deferred. |
| Transaction preimage | `transaction_u32_le`, bounded gather BLAKE2b, raw-transaction hash without CellDeps | Executable limited to the declared offsets/chunks. Canonical CKB sighash-all remains fail-closed until its message and witness-ownership contract is implemented. |
| Hashing | CKB BLAKE2b data/span helpers, fixed SHA-256/SHA256d values and pairs, bounded SHA256d Merkle proofs | Executable fixed-width or literal-bounded operations. No allocator-backed streaming hash surface is implied. |
| CellDep delegation | exact-index/literal-bounded data-hash checks; fixed u8/hex4 EXEC; hex4 SPAWN/WAIT | Raw adapters remain fail-closed under production policy. `trusted_*` forms are a composition boundary requiring an exact manifest declaration and data hash; successful delegation does not prove external internals. |
| Protocol helpers | bounded xUDT, DAO, C256, and MetaPoint requirements | Executable only for their documented fixed shapes. They do not widen the general transaction-view contract. |

## Stable failures used by v1

| Code | Name | Runtime-view use |
|---:|---|---|
| 1 | `syscall-failed` | CKB syscall returned an unsupported nonzero status where no narrower error applies. |
| 2 | `bounds-check-failed` | Requested byte range is outside the admitted source length. |
| 3 | `cell-load-failed` | Required Cell bytes or fields could not be loaded. |
| 4 | `exact-size-mismatch` | Fixed-width syscall result did not have the exact required size. |
| 33 | `out-point-mismatch` | Input lineage differs from the required OutPoint. |
| 34 | `script-field-malformed` | Serialized Script field is absent or malformed for the requested projection. |
| 37 | `ckb-since-malformed` | Since flags or epoch-fraction components violate the admitted encoding. |
| 38 | `script-args-mismatch` | Script args violate the declared exact/empty rule. |
| 41 | `script-identity-mismatch` | Script code hash or hash type differs from the required identity. |
| 42 | `witness-malformed` | WitnessArgs or entry envelope is not canonical Molecule data. |
| 43 | `witness-field-truncated` | WitnessArgs offset/length exceeds the loaded witness. |
| 44 | `ckb-source-view-invalid` | Closed source kind and consumer are incompatible or the encoded view is malformed. |
| 45 | `header-dep-missing` | HeaderDep index is missing, including one-past-last. |
| 46 | `dao-field-malformed` | DAO header or cell field has the wrong fixed layout. |
| 63 | `bounded-cell-dep-not-found` | Literal-bounded CellDep scan reached its maximum without an exact data hash. |
| 66 | `sighash-all-unsupported` | Deferred canonical signing-message construction was requested. |

## Current executable evidence

`tests/typed_runtime_views.rs` executes the new Cell, input, CellDep, and
HeaderDep fields in CKB-VM. It covers a nonzero header epoch at index zero, the
derived epoch-start block number, a one-past-last HeaderDep, exact absolute and
relative Since wire vectors, canonical epoch-fraction comparisons, a malformed
fraction, an exact CellDep data hash, and a substituted hash.
`tests/authoring_replace.rs` exercises the
`ScriptHash` domain against real output Lock Script hashes. Existing
`tests/ickb_diff.rs`, `tests/crypto_primitives.rs`, and artifact-checker mutation
suites retain the older bounded helper families.

The following work remains before issue #24 can close:

- version source/index/range provenance beyond the existing handle and runtime
  access records, including dynamic-index representation;
- bounded variable-length witness and WitnessArgs field values with explicit
  ownership shared across #8, #13, and #22;
- full-header decoding for timestamp, block number, and header hash when the
  frozen business corpus requires them;
- the remaining block/timestamp, decoded-Since, duration-arithmetic, migration,
  and business-fixture work owned by #12;
- persistent-policy and generated-builder parity for every admitted row;
- standalone-checker machine mutations for the new HeaderDep source/index,
  field selector, exact width, syscall status, and terminal error;
- maximum-bound cycle, stack, ELF, witness, and transaction-size measurements;
  and
- `ci`, `backend`, release, and independent-review evidence on the exact
  candidate source.

## Deferred and excluded surfaces

Production source does not admit raw numeric syscalls, arbitrary pointers,
unbounded transaction/witness/header materialization, an unchecked syscall
status, or a generic `unsafe` escape hatch. CKB2023 process pipes and inherited
file descriptors remain fail-closed except for the exact bounded adapters
already used by declared external verifiers. Raw extension loading, allocator
configuration, dynamic libraries, and general process programming are outside
the 0.30 business portfolio unless a later scoped issue changes that decision.
