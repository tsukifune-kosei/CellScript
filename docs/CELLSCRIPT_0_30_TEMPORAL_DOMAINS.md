# CellScript 0.30 Typed CKB Temporal Domains

## Status

**Status: implemented additive Phase 1 contract for epoch reads and epoch-based
`Since` values. This document does not close issue #12 or the 0.30 release
gate.**

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
| `AbsoluteEpochSince` | Absolute epoch-fraction `Since` | exact CKB `u64` wire bits |
| `RelativeEpochSince` | Relative epoch-fraction `Since` | exact CKB `u64` wire bits |

`AbsoluteEpochSince` and `RelativeEpochSince` are the concrete development
spellings of the conceptual `Since<Absolute, EpochFraction>` and
`Since<Relative, EpochFraction>` domains. Stable public value-generics are
owned by issue #23, so this tranche does not expose a generic spelling that the
current monomorphizer would misclassify as a user template.

The typed constructors are:

```cellscript
let absolute = ckb::since_absolute_epoch(42, 3, 10)
let relative = ckb::since_relative_epoch(2, 1, 4)
```

Both validate the 24-bit epoch-number bound, the 16-bit fraction bounds,
nonzero length, and `index < length`. Invalid values terminate with stable
runtime error 37, `ckb-since-malformed`.

Values may be compared only within the same temporal domain. Epoch-fraction
ordering compares the epoch number first and then compares `index / length` by
bounded cross multiplication. It never orders the packed `u64` directly,
because the fraction fields occupy more-significant bits than the epoch number.
Equivalent fractions such as `1/2` and `2/4` compare equal.

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
same temporal type.

## Compatibility

The existing Edition 2026 functions retain their raw `u64` return types:

- `ckb::since_epoch_absolute(number, index, length)`;
- `ckb::since_epoch_relative(number, index, length)`;
- `ckb::input_since_at(input_view)`;
- `ckb::input_since()` and the existing no-argument header helpers; and
- `env::current_timepoint()`.

New code obtains an opaque input value from `InputView.since` and uses the new
typed constructors. No existing raw function silently changes meaning. A later
migration phase will add targeted diagnostics and mechanical replacements once
the complete typed surface is available.

## Executable evidence

`tests/typed_runtime_views.rs` runs the contract in CKB-VM. It checks exact
absolute and relative RFC0017 wire vectors, helper-call ABI preservation,
all ordered comparison forms, rationally equivalent fractions, a case where
packed-integer ordering is wrong, HeaderDep temporal reads, and malformed
zero-length rejection. Type-checker tests reject absolute/relative mixing,
epoch/block mixing, and implicit comparison with raw integers.

## Remaining issue #12 work

The following work remains before the temporal issue can close:

- absolute and relative block-number and timestamp `Since` domains;
- typed timestamp and whole-block readers backed by a bounded full-header
  decoding contract where CKB field syscalls do not expose those values;
- checked raw `Since` decoding into a six-variant tagged value;
- checked `EpochDuration` arithmetic and overflow/underflow evidence;
- migration warnings, a mechanical migration action, and old-edition package
  interoperation tests;
- public-interface constructor/decoder version records beyond the preserved IR
  type and fixed ABI;
- standalone-checker mutations for changed temporal types and comparisons;
- formatter, VS Code, Playground, generated-builder, and package-fixture parity;
- migrated timelock, DAO, vesting, NFT-expiry, governance, and atomic-swap
  business fixtures; and
- full `ci`, `backend`, release, and independent-review evidence on one clean
  candidate revision.

