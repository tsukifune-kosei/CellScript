# CellScript 0.30 CKB Runtime-View Matrix

## Status and contract

**Status: active implementation matrix for
`cellscript-ckb-runtime-view-v1`. This is a development contract, not a claim
that issue #24 or the 0.30 release gate is complete.**

Compile metadata schema 71 records the view contract name in
`runtime.ckb_runtime_view_contract` and binds
`cellscript-ckb-runtime-access-provenance-v1` in
`runtime.ckb_runtime_access_provenance_contract`. Metadata validation and the
standalone artifact checker reject an absent, older, changed, or internally
inconsistent provenance record. Every runtime access identifies the resolved
source, source origin, static/dynamic/bounded index and admitted byte range.
The legacy numeric `index` remains a compatibility projection; it is zero for
dynamic accesses and the structured index is authoritative. The contract
covers typed, read-only views and the bounded CKB runtime operations listed
below. It does not grant Cell lifecycle authority and does not turn a value
read from a transaction into authorization.

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

Every constructor takes a `u64` index. Static literals and dynamic parameter
bindings remain distinct in provenance, and every source-view index carries
`max_inclusive = 4294967295`. `InputView<T>` and `OutputView<T>` also require a
declared cell-backed resource, shared type, or receipt type argument. The
runtime representation is a closed source-kind/index pair. An out-of-domain
dynamic index or malformed pair fails with `ckb-source-view-invalid`; a missing
indexed item fails through the field-specific terminal error.

| Handle and constructor | Source | Executable fields | Source type | Runtime width and failure |
|---|---|---|---|---|
| `ckb::input<T>(i)` | Input | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script`, `out_point`, `since: EncodedSince` | `InputView<T>` | Scalars are 8 bytes; hashes are 32 bytes; OutPoint is 36 bytes. Invalid/missing reads terminate. |
| `ckb::group_input<T>(i)` | GroupInput | Same field set as `InputView<T>` | `InputView<T>` | Same fixed widths; current Script-group-relative index. |
| `ckb::output<T>(i)` | Output | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script`, `output_index` | `OutputView<T>` | Same scalar/hash bounds; output index is derived from the closed source view. |
| `ckb::group_output<T>(i)` | GroupOutput | Same field set as `OutputView<T>` | `OutputView<T>` | Same fixed widths; current Script-group-relative index. |
| `ckb::cell_dep(i)` | CellDep | `capacity`, `occupied_capacity`, `unoccupied_capacity`, `data_size`, `data_hash`, `lock_hash`, `type_hash`, `lock`, `type_script` | `CellDepView` | Same fixed widths. Resolved dep position is runtime evidence; original DepGroup/OutPoint identity remains builder or manifest evidence. |
| `ckb::header_dep(i)` | HeaderDep | `epoch_number: EpochNumber`, `epoch_start_block_number: BlockNumber`, `epoch_length: EpochLength`, `block_number: BlockNumber`, `timestamp: TimestampMillis` | `HeaderDepView` | Epoch fields are exact 8-byte `LOAD_HEADER_BY_FIELD` reads. Block/timestamp fields require an exact 208-byte `LOAD_HEADER` result and fixed RawHeader offsets. Bad source uses error 44, malformed size uses error 4, and missing/one-past-last HeaderDep uses error 45. |
| `witness::args(i)` | Witness/Input | `size`, fixed 32-byte `lock`, `input_type`, `output_type` projections | `WitnessArgsView` | `size` is 8 bytes. Field projections stream the selected bytes and are executable only when that Molecule field is exactly 32 bytes, regardless of sibling-field or total WitnessArgs size; absent or non-32-byte values use error 4 and malformed/truncated values use errors 42/43. |
| `witness::bounded_raw(view, max)` | inherited Input/Output/GroupInput/GroupOutput | `size`, exact byte/u32/u64 reads, full-view CKB Blake2b | `WitnessBytesView<raw,max>` | `max` is a literal in `0..=65536`; the logical value is the complete serialized witness. Reads and hashing stream from `LOAD_WITNESS` without materializing the value. |
| `witness::bounded_lock(view, max)` | inherited witness source | Same bounded operations over `WitnessArgs.lock` | `WitnessBytesView<lock,max>` | Missing differs from `Some(empty)`; absent uses error 67, values above `max` use 68, and malformed field encoding uses 42/43. This read-only view does not grant signer authority. |
| `witness::bounded_entry(view, max)` | inherited witness source | Same bounded operations over the one `WitnessArgs.input_type` value | `WitnessBytesView<entry,max>` | The logical bytes are the existing `CSARGv1` entry envelope when that ABI is used. This is the shared owner for bounded plan, authorization, and entry consumers, not a second payload. |
| `witness::bounded_output_type(view, max)` | inherited witness source | Same bounded operations over `WitnessArgs.output_type` | `WitnessBytesView<output_type,max>` | The owner is distinct from `lock` and `entry`; all offsets are relative to the selected field payload. |
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
| Temporal and DAO | typed HeaderDep epoch fields plus full-header block number and millisecond timestamp; opaque and decoded `InputView.since`; six absolute/relative block, epoch, and timestamp `Since` domains; checked narrowing; checked `EpochDuration` arithmetic; explicit raw conversions; legacy raw constructors; DAO accumulated-rate/header-lineage/maturity helpers | The additive temporal subset is executable under the typed temporal contract. Full-header reads require the exact 208-byte Molecule Header; Since decoding validates RFC0017 flags and payloads; same-domain epoch-Since comparisons use canonical fraction ordering; duration construction and EpochNumber add/sub enforce the 24-bit domain. |
| Witness | count/size, legacy exact byte/u32/u64/bytes32 reads, bounded spans, selected gather hashing, exact 32-byte typed WitnessArgs fields, and owner-tagged variable-length raw/lock/entry/output_type views with exact scalar reads and streaming Blake2b | Executable limited. Bounded views admit at most 65,536 bytes and do not expose allocation, mutation, slicing as an owned value, or unchecked pointers. |
| Transaction identity and preimage | canonical `ckb::transaction_hash()` through exact 32-byte `LOAD_TX_HASH`; bounded `env::sighash_all_zero_lock`; `transaction_u32_le`; bounded gather BLAKE2b; raw-transaction hash without CellDeps | The raw transaction hash is fixed-width. The zero-lock signing domain is executable only for the current input Script group and its four declared bounds. The generic `env::sighash_all(source)` spelling remains fail-closed. |
| Signing-message domain | `env::sighash_all_zero_lock(max_group_inputs, max_inputs, max_extra_witnesses, max_witness_bytes) -> SighashAllDigest`; explicit `Hash::from_sighash_all` conversion | Hashes the exact transaction hash, the first group witness with the complete `WitnessArgs.lock` payload replaced by equal-length zero bytes, later group witnesses, and witnesses after the transaction input count. Every witness is prefixed by its little-endian `u64` byte length. This covers simple all-zero lock placeholders. It does not implement multisig layouts that preserve a nonzero configuration prefix. |
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
| 20 | `numeric-or-discriminant-invalid` | EpochDuration construction or EpochNumber arithmetic exceeded the 24-bit domain or underflowed. |
| 33 | `out-point-mismatch` | Input lineage differs from the required OutPoint. |
| 34 | `script-field-malformed` | Serialized Script field is absent or malformed for the requested projection. |
| 37 | `ckb-since-malformed` | Since flags, metric, scalar bound, timestamp conversion, epoch-fraction components, or requested narrowing violate the admitted encoding. |
| 38 | `script-args-mismatch` | Script args violate the declared exact/empty rule. |
| 41 | `script-identity-mismatch` | Script code hash or hash type differs from the required identity. |
| 42 | `witness-malformed` | WitnessArgs or entry envelope is not canonical Molecule data. |
| 43 | `witness-field-truncated` | WitnessArgs offset/length exceeds the loaded witness. |
| 44 | `ckb-source-view-invalid` | Closed source kind and consumer are incompatible or the encoded view is malformed. |
| 45 | `header-dep-missing` | HeaderDep index is missing, including one-past-last. |
| 46 | `dao-field-malformed` | DAO header or cell field has the wrong fixed layout. |
| 63 | `bounded-cell-dep-not-found` | Literal-bounded CellDep scan reached its maximum without an exact data hash. |
| 66 | `sighash-all-unsupported` | Deferred canonical signing-message construction was requested. |
| 67 | `witness-field-absent` | A bounded WitnessArgs field is absent; `Some(empty)` remains a present zero-length value. |
| 68 | `witness-bound-exceeded` | The selected raw witness or field is larger than its compile-time declared maximum. |
| 69 | `sighash-bound-exceeded` | A group/input/extra-witness count or included witness exceeds the signing-domain literals. |
| 70 | `exact-script-handle-invalid` | An exact handle encoding, commitment, class, role, selected Script, or verifier code identity differs. |
| 71 | `deployment-line-handle-invalid` | An exact active line, admission CellDep, code CellDep, or selected Script identity differs. |

## Current executable evidence

`tests/typed_runtime_views.rs` executes the new Cell, input, CellDep, and
HeaderDep fields and bounded witness views in CKB-VM. It covers a nonzero header epoch at index zero, the
derived epoch-start block number, a one-past-last HeaderDep, exact absolute and
relative wire vectors for all six Since domains, checked decoding and
narrowing, canonical epoch-fraction comparisons, malformed flags/fractions and
scalar bounds, checked epoch-duration arithmetic and its overflow/underflow
boundaries, exact full-header block/timestamp reads, the exact 32-byte CKB raw
transaction hash, an exact CellDep data hash, a substituted hash, successful
dynamic Input/CellDep/Witness index zero, and a dynamic index above the 32-bit
view domain. The bounded witness cases cover
all four owners, 700/900/1024-byte fields, the complete serialized witness,
exact scalar reads, streaming hashes, `Some(empty)`, absent and over-bound
values, malformed/truncated Molecule data, and GroupOutput provenance.
`tests/sighash_zero_lock.rs` differentially compares the emitted digest with
the pinned `ckb-sdk-rust` message generator across a non-contiguous two-input
Script group, an unrelated input witness, and a transaction-level extra
witness. It also proves post-message witness mutation changes verification and
all four declared bounds terminate with error 69. Metadata schema 71 records
the exact transform, order, digest domain, scope, and limits; the independent
checker binds those records to runtime access provenance and typed call
operands after outer hashes are rebound. Generated TypeScript builder manifests
and plans preserve the same domain and require pre-signing witness placement;
the metadata-only browser summary exposes it as well.
`tests/artifact_checker.rs` changes source, index bound, range, contract,
transaction-hash operation/syscall/binding/width, bounded owner/maximum,
handle, and module/entry copies after outer hash rebinding and requires
independent `V2410` rejection. Generated
TypeScript builder tests retain the same dynamic parameter bound.
`tests/authoring_replace.rs` exercises the
`ScriptHash` domain against real output Lock Script hashes. Existing
`tests/ickb_diff.rs`, `tests/crypto_primitives.rs`, and artifact-checker mutation
suites retain the older bounded helper families.

The following work remains before issue #24 can close:

- full-header hash decoding if the frozen business corpus requires it;
- any additional signing domain selected by the business corpus, including a
  multisig prefix-preserving layout, as a separately named contract;
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
