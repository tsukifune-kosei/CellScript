# CellScript Bounded Output Plan Contract

**Status**: accepted implementation contract for the 0.30 branch.

This document fixes the executable meaning of a witness
`BoundedList<Plan, N>` consumed by `create_each`. It closes the bounded output
plan and one-to-one GroupOutput correspondence part of issue #8.

## Accepted source shape

```cellscript
struct Plan {
    owner: Address
    amount: u64
}

resource Token has store, create
with_capacity_floor(10000000000)
{
    amount: u64
}

action mint(witness plans: BoundedList<Plan, 16>) -> u64 {
    verification
        create_each plan in plans {
            require plan.amount > 0
            create Token { amount: plan.amount } with_lock(plan.owner)
        }
        return 0
}
```

The checked contract requires all of the following:

- the collection is a witness `BoundedList<Plan, N>` with `1 <= N <= 1024`;
- `Plan` is fixed width and `12 + N * sizeof(Plan) <= 4084`;
- the created resource is fixed width from 1 through 512 bytes, has no
  separate resource identity policy, and declares a positive capacity floor;
- the body has exactly one complete `create` template with an explicit Lock;
- every output data field and the Lock are direct fields of the same Plan
  element with equal fixed types and widths;
- the per-element body contains checked predicates and no unsupported loop
  control or side effects.

Computed output values, multiple or incomplete create templates, dynamic data,
implicit Locks, missing capacity policy, and custom resource identity remain
fail-closed. A production compile rejects those shapes with E2105. A permissive
artifact terminates with runtime error 24.

## Witness codec and shared envelope

The Plan parameter is one length-delimited parameter inside the ordinary
`CSARGv1\0` entry payload in `WitnessArgs.input_type`. Other action parameters
remain in their declared order, so the contract composes with a shared entry
witness without claiming the Lock or `output_type` fields.

The parameter bytes use `bounded-output-plan-v1`:

| Offset | Width | Meaning |
|---:|---:|---|
| 0 | 8 | ASCII `CSBPLv1\0` |
| 8 | 4 | little-endian `u32` element count |
| 12 | `count * element_width` | fixed-width Plan elements in order |

The length must equal `12 + count * element_width` exactly. Zero elements are
valid. Counts above `N`, trailing bytes, truncated fields, a different magic,
or payloads above 4084 bytes reject the transaction.

## GroupOutput correspondence

For Plan ordinal `i`, the verifier selects `GroupOutput[i]`, where
`GroupOutput` is CKB's canonical output array filtered by the complete current
Type Script. It then requires:

1. output data has the exact resource width;
2. each output field equals its declared Plan field byte for byte;
3. the output Type hash equals the current Script hash;
4. the output Lock hash equals the declared 32-byte Plan field;
5. Lock and current Type Script hashes are different roles;
6. output capacity is at least the declared resource floor.

After the last Plan element, a capacity probe at `GroupOutput[count]` must
return `CKB_INDEX_OUT_OF_BOUND`. This rejects missing and extra group outputs
and fixes the one-to-one correspondence without scanning unrelated outputs.

Normative upstream sources:

- [CKB RFC 0046: syscalls](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0046-syscalls/0046-syscalls.md)
- [CKB RFC 0022: transaction structure](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md)

## Identity and equal values

Created Cells receive fresh transaction OutPoints. Within the current Type
Script group, the Plan ordinal is the correspondence identity. Equal Plan bytes
are allowed and create distinct outputs at distinct output indexes. This is
required for fungible splits with equal amounts. Protocols that need unique
application identities must declare and enforce their own resource identity
policy outside this admitted `identity = none` contract.

## Builder and transaction evidence

Metadata schema 72 emits a
`cellscript-bounded-output-plan-contract` beside the collection record. It
includes the codec, maximum, fixed Plan and output layouts, exact field and Lock
bindings, capacity floor, Type policy, ordering, correspondence, and identity
policy.

Generated TypeScript builders expose `encodeBoundedOutputPlanV1` and
`materializeBoundedOutputPlanV1`. The action plan contains ordered materialized
output data, Lock hashes, capacity floors, and ordinals. The CKB adapter and
`cellc tx validate` independently require a
`cellscript-bounded-output-plan-evidence-v1` record containing:

- action and Plan binding;
- `WitnessArgs.input_type` witness index;
- the exact Plan payload;
- the current Script hash;
- strictly increasing transaction output indexes that exactly enumerate its
  Type Script group.

Both validators re-decode the Plan and compare every concrete output data byte,
Lock hash, Type hash, capacity, count, and order. Evidence that is missing,
duplicated, reordered, stale, or inconsistent rejects before signing.

## Stable failures

| Code | Meaning in this contract |
|---:|---|
| 1 | current Script hash syscall failed |
| 3 | GroupOutput data or exact field comparison failed |
| 4 | returned data or hash width is not exact |
| 5 | a per-element predicate is false |
| 12 | output Lock hash differs from the Plan Lock field |
| 21 | Plan bound or exact output count is wrong |
| 24 | source shape has no admitted runtime contract |
| 25 | entry or Plan witness codec is malformed |
| 26 | output capacity is below the declared floor |
| 47 | Lock and Type Script roles are conflated |

All failures terminate the verifier. No partially checked output plan returns
success.

## Independent machine evidence

The typed lowering contains one `bounded-plan-load`, one
`bounded-output-verify`, and one `bounded-output-end` per contract. The
standalone artifact checker independently decodes the RISC-V code and requires:

- the 12-byte header, all eight magic bytes, `count <= N`, and exact length;
- Plan pointer arithmetic, fixed element width, and presence result slots;
- the same typed ordinal for Plan decode, output data, Lock, capacity, and the
  first absent GroupOutput probe;
- exact data width and one guarded comparison per typed output field;
- all four words of the current-Type/output-Lock role check;
- a 32-byte comparison using the decoded Plan pointer and Lock-field offset;
- the metadata capacity-floor constant and stable error exits.

Mutations of metadata ordering, identity, field mapping, magic, count, ordinal,
data width, Lock comparison, Type role, or capacity comparison are rejected as
V2420 after sidecar identities are rebound.

## Acceptance corpus and bounds

[`bounded_output_plan_v1.json`](../tests/fixtures/bounded_output_plan_v1.json)
is the shared simulator, CKB-VM, adapter, and live-node corpus. It covers zero,
one, `N`, `N + 1`, missing and extra outputs, data/Lock/Type/capacity mismatch,
predicate failure, malformed codecs, and equal Plan bytes at distinct ordinals.

The maximum encodable `Plan { owner: Address, amount: u64 }` bound is 101
elements because `12 + 101 * 40 = 4052`. The separate
[`bounded_output_plan_max.cell`](../tests/fixtures/bounded_output_plan_max.cell)
fixture executes all 101 outputs under a 4 KiB stripped ELF budget and a
10,000,000-cycle CKB-VM budget. These are focused release guards, not general
transaction fee or maximum-size promises.

The production evidence validator recomputes the fixture SHA-256 and requires
exactly one `bounded-output-plan-v1:verify` build/deployment row. It binds the
stateful report's artifact path and CKB data hash to that row and validates all
case identities, exits, ordered indexes, commits, rejected transactions, live
outputs, and retained trigger inputs.

The clean-source acceptance run on 2026-09-09 passed all 14 cases at commit
`00f39a16`. The four accepted shapes consumed 3,687 cycles for zero outputs,
7,784 for one output, 15,978 for three outputs, and 11,881 for two equal Plan
values at distinct ordinals. Every negative case returned its declared stable
error. The 3,296-byte deployed ELF has SHA-256
`59949f7f68bb7ca1b42452066659b79620a644b68104aed5e67fd9f434542d25`
and CKB data hash
`08dbdb407ddc44af139a42c47718abaf8f8de15b70ddbd6bf235a6373c7a9b75`.
The complete production report passed the independent production-evidence
validator against fixture SHA-256
`11abfc6ae2980ebd6a10c6a798024a4fffeb8f7603834bddf6d5a052bf7ac68c`.
