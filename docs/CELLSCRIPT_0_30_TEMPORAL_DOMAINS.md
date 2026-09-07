# CellScript 0.30 Typed CKB Temporal Domains

## Status

**Status: implemented additive Phase 1 contract for typed HeaderDep epoch
fields, all six RFC0017 `Since` mode/metric domains, and checked decoding. This
document does not close issue #12 or the 0.30 release gate.**

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
| `BlockNumber` | Epoch start block number returned by a HeaderDep field read | checked 8-byte scalar |
| `EpochLength` | Epoch length returned by a HeaderDep field read | checked 8-byte scalar |
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
let raw_start: u64 = ckb::block_number_to_u64(header.epoch_start_block_number)
let raw_length: u64 = ckb::epoch_length_to_u64(header.epoch_length)
```

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
silently changes meaning. A later migration phase will add targeted diagnostics
and mechanical replacements once the complete typed surface is available.

## Executable evidence

`tests/typed_runtime_views.rs` runs the contract in CKB-VM. It checks exact
all six RFC0017 mode/metric wire vectors, helper-call ABI preservation, ordered
comparisons, rationally equivalent fractions, a case where packed-integer
ordering is wrong, checked decoding and narrowing, HeaderDep temporal reads,
reserved-bit rejection, scalar bounds, timestamp multiplication overflow, and
malformed zero-length constructor rejection. Type-checker tests reject
absolute/relative mixing, block/epoch/timestamp mixing, and implicit comparison
with raw integers. The standalone checker rejects typed-semantics mutations
that change either mode or metric on a comparison operand.

## Remaining issue #12 work

The following work remains before the temporal issue can close:

- typed timestamp and whole-block readers backed by a bounded full-header
  decoding contract where CKB field syscalls do not expose those values;
- checked `EpochDuration` arithmetic and overflow/underflow evidence;
- migration warnings, a mechanical migration action, and old-edition package
  interoperation tests;
- explicit constructor/decoder requirements in exported package-interface
  compatibility checks beyond the target-level `since_abi` binding;
- standalone-checker mutations for changed temporal types and comparisons;
- formatter, VS Code, Playground, generated-builder, and package-fixture parity;
- migrated timelock, DAO, vesting, NFT-expiry, governance, and atomic-swap
  business fixtures; and
- full `ci`, `backend`, release, and independent-review evidence on one clean
  candidate revision.
