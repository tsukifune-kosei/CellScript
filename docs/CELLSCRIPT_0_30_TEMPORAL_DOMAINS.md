# CellScript 0.30 Typed CKB Temporal Domains

## Status

**Status: implementation-complete additive issue #12 contract for typed
HeaderDep fields, all six RFC0017 `Since` mode/metric domains, checked decoding,
checked whole-epoch duration arithmetic, migration, interfaces, builders, and
product parity. Full candidate gates and independent review remain before issue
#12 or the 0.30 release gate can close.**

The normative chain behavior comes from
[CKB RFC 0017](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md).
CKB stores each input `since` as a `u64`: the high byte selects absolute or
relative mode and one of block number, epoch fraction, or timestamp; the low 56
bits carry the metric value. An epoch fraction encodes a 24-bit epoch number,
16-bit index, and 16-bit length. The compiler therefore keeps the exact wire
bits while assigning distinct source and IR types to values with different
meanings.

## Implemented source contract

| Source type | Meaning | Runtime representation |
|---|---|---|
| `EpochNumber` | Whole epoch number returned by a HeaderDep field read | checked 8-byte scalar |
| `EpochDuration` | Whole-epoch interval bounded to the 24-bit CKB epoch-number domain | checked 8-byte scalar |
| `BlockNumber` | Epoch start block number returned by a HeaderDep field read | checked 8-byte scalar |
| `EpochLength` | Epoch length returned by a HeaderDep field read | checked 8-byte scalar |
| `TimestampMillis` | CKB header timestamp in milliseconds | checked 8-byte scalar |
| `EncodedSince` | Opaque, undecoded `since` read from `InputView.since` | exact CKB `u64` wire bits |
| `DecodedSince` | Validated RFC0017 value retaining its wire tag | exact CKB `u64` wire bits |
| `AbsoluteBlockSince` | Absolute block-number `Since` | exact CKB `u64` wire bits |
| `AbsoluteEpochSince` | Absolute epoch-fraction `Since` | exact CKB `u64` wire bits |
| `AbsoluteTimestampSince` | Absolute timestamp-seconds `Since` | exact CKB `u64` wire bits |
| `RelativeBlockSince` | Relative block-count `Since` | exact CKB `u64` wire bits |
| `RelativeEpochSince` | Relative epoch-fraction `Since` | exact CKB `u64` wire bits |
| `RelativeTimestampSince` | Relative timestamp-seconds `Since` | exact CKB `u64` wire bits |

The six concrete `Since` names are the development spellings of the conceptual
`Since<Mode, Metric>` product. Stable public value-generics are owned by issue
#23, so this tranche does not expose a generic spelling that the current
monomorphizer would misclassify as a user template.

The typed constructors are:

```cellscript
let absolute = ckb::since_absolute_epoch(42, 3, 10)
let relative = ckb::since_relative_epoch(2, 1, 4)
let block = ckb::since_absolute_block(123)
let block_delay = ckb::since_relative_block(7)
let timestamp = ckb::since_absolute_timestamp(1700000000)
let timestamp_delay = ckb::since_relative_timestamp(3600)
```

Epoch constructors validate the 24-bit epoch-number bound, the 16-bit fraction
bounds, nonzero length, and `index < length`. Block constructors validate the
56-bit RFC0017 payload bound. Timestamp arguments are RFC0017 seconds; the
compiler also checks that consensus conversion to header milliseconds cannot
overflow `u64`. Invalid values terminate with stable runtime error 37,
`ckb-since-malformed`.

Values may be compared only within the same temporal domain. Epoch-fraction
ordering compares the epoch number first and then compares `index / length` by
bounded cross multiplication. It never orders the packed `u64` directly,
because the fraction fields occupy more-significant bits than the epoch number.
Equivalent fractions such as `1/2` and `2/4` compare equal.

`InputView.since` must be decoded before its tag or payload is inspected:

```cellscript
let decoded = ckb::since_decode(input.since)
let from_protocol_bytes = ckb::since_from_raw_checked(raw)

require ckb::since_metric(decoded) <= 2
require !ckb::since_is_relative(decoded)
let exact: AbsoluteEpochSince = ckb::since_as_absolute_epoch(decoded)
```

`since_decode` accepts only `EncodedSince`; the explicit low-level escape hatch
`since_from_raw_checked` accepts `u64`. Both reject reserved flag bits, metric
tag `11`, invalid epoch fractions, and timestamp values whose consensus
milliseconds conversion would overflow. The RFC0017 `(index=0, length=0)`
epoch increment form is accepted by the decoder as consensus-valid and retains
its exact wire bits. `since_as_*` checks both mode and metric before returning a
concrete domain. `since_metric` returns `0` for block, `1` for epoch fraction,
and `2` for timestamp; `since_value` returns the low 56 bits, and
`since_is_disabled` identifies the all-zero encoding.

Raw representation is available only through explicit conversions:

```cellscript
let raw_since: u64 = ckb::since_to_raw(absolute)
let raw_epoch: u64 = ckb::epoch_number_to_u64(header.epoch_number)
let raw_duration: u64 = ckb::epoch_duration_to_u64(ckb::epoch_duration(5))
let raw_start: u64 = ckb::block_number_to_u64(header.epoch_start_block_number)
let raw_length: u64 = ckb::epoch_length_to_u64(header.epoch_length)
let raw_block: u64 = ckb::block_number_to_u64(header.block_number)
let raw_timestamp: u64 = ckb::timestamp_millis_to_u64(header.timestamp)
```

Whole-epoch arithmetic uses an explicit duration domain:

```cellscript
let duration = ckb::epoch_duration(5)
let unlock_epoch = ckb::epoch_add(header.epoch_number, duration)
let prior_epoch = ckb::epoch_sub(header.epoch_number, duration)
```

The constructor rejects values at or above `2^24`. Addition rejects results at
or above that bound, and subtraction rejects underflow. All three paths also
revalidate their typed operands at the runtime boundary and use stable error 20,
`numeric-or-discriminant-invalid`, on failure. `EpochNumber` and
`EpochDuration` remain distinct source and IR types; ordinary numeric operators
and mixed-domain comparisons do not erase that distinction.

`HeaderDepView.block_number` and `.timestamp` use CKB's full `LOAD_HEADER`
syscall because the field syscall exposes only the three epoch projections.
The runtime loads the complete fixed 208-byte Molecule `Header`, requires that
exact returned length, then reads RawHeader `number` at byte offset 16 or
`timestamp` at byte offset 8. Header timestamps are milliseconds, while
RFC0017 timestamp-Since payloads are seconds, so `TimestampMillis` cannot be
compared to either timestamp-Since domain without an explicit conversion path.

The conversion calls survive typed IR and typed-semantics records as named
runtime operations. The machine ABI carries every implemented temporal value
as one 64-bit scalar, including across CellScript helper calls. The standalone
artifact checker admits ordered comparisons only when both operands have the
same temporal type. Target and deployment metadata bind the wire and
constructor/decoder contract as `since_abi = ckb-since-rfc0017-typed-v1`.

## Compatibility

The existing Edition 2026 functions retain their raw `u64` return types:

- `ckb::since_epoch_absolute(number, index, length)`;
- `ckb::since_epoch_relative(number, index, length)`;
- `ckb::input_since_at(input_view)`;
- `ckb::input_since()` and the existing no-argument header helpers; and
- `env::current_timepoint()`.

New code obtains an opaque input value from `InputView.since`, validates it with
`since_decode`, and narrows it to the required domain. No existing raw function
silently changes meaning. Compiler and LSP diagnostic `W3012` identifies each
legacy call with a total raw-compatible replacement. The language-server
quick-fix rewrites every such call in the document while preserving comments
and the surrounding `u64` result. The legacy untyped GroupInput#0 reader becomes
the explicitly named `ckb::input_since_raw()` alias because no Cell type can be
inferred from that no-argument call.

Canonical `cellscript-package-interface-v3` records the fixed scalar/wire
representation, all six constructors, both checked decoder entry points, the
complete domain inventory, `since_abi`, and the migration identity. The v2
reader remains available for compatibility comparison; adding or changing the
temporal contract is classified as a runtime/deployment break, while changing
an exported raw signature to a typed domain is also a source/call-ABI break.

## Executable evidence

`tests/typed_runtime_views.rs` runs the contract in CKB-VM. It checks exact
all six RFC0017 mode/metric wire vectors, helper-call ABI preservation, ordered
comparisons, rationally equivalent fractions, a case where packed-integer
ordering is wrong, checked decoding and narrowing, HeaderDep temporal reads,
reserved-bit rejection, scalar bounds, timestamp multiplication overflow, and
malformed zero-length constructor rejection. The same CKB-VM fixture covers
duration construction, addition, subtraction, overflow, and underflow.
It also checks nonzero full-header block and timestamp values against a
`ckb-testtool` Header. Type-checker tests reject
absolute/relative mixing, block/epoch/timestamp mixing, and implicit comparison
with raw integers. The standalone checker rejects typed-semantics mutations
that change either mode or metric on a comparison operand.

Formatter round-trip, LSP `W3012` migration, VS Code grammar, generated-builder,
package-interface v2/v3 interoperation, Registry validation, metadata-only WASM,
and Playground checks cover the same public contract. The canonical browser
bundle uses a bounded summary construction path while native builds retain the
complete interface, typed-semantics, ProofPlan, scheduler, Molecule, and
artifact records. Its current reproducible build is 560,647 bytes gzip, below the
600 KB budget. Timelock, DAO, vesting, NFT-expiry, governance, and atomic-swap
fixtures now compile through typed HeaderDep and Since operations without a
legacy raw temporal diagnostic.

## Remaining issue #12 acceptance evidence

The implementation surface is complete. Full `ci`, `backend`, release, and
independent-review evidence must still pass on one clean candidate revision
before the issue is closed or used in a release claim.
