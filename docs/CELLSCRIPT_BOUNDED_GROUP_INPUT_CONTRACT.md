# CellScript Bounded Group Input Contract

**Status**: accepted implementation contract for the 0.30 branch.

This document fixes the production meaning of
`input BoundedCellSet<Resource, N>` consumed by `consume_each`. It closes the
bounded dynamic GroupInput part of issue #7. It does not introduce a generic
transaction iterator or an allocation-backed Cell collection.

## Accepted source shape

The accepted shape is:

```cellscript
resource Token has store, consume {
    amount: u64
}

action verify(input inputs: BoundedCellSet<Token, 16>) -> u64 {
    verification
        let mut total: u64 = 0
        consume_each token in inputs {
            require token.amount > 0
            total += token.amount
        }
        require total <= 1600
        return 0
}
```

The contract requires all of the following:

- the parameter source is explicitly `input`;
- `1 <= N <= 1024`;
- the element is a `resource` with an exact encoded width from 1 through 512
  bytes;
- selection uses the current Type Script's `GroupInput` source;
- every selected input is decoded exactly once and the body runs exactly once;
- the body contains only pure `require` predicates and `+=` updates to mutable
  numeric accumulators declared outside the body;
- every selected linear resource is discharged by the operation.

Any other source, dynamic or recursive element layout, larger bound, or
arbitrary loop side effect remains unsupported. Production compilation rejects
those shapes with E2105. A permissive artifact retains runtime error 24 rather
than returning success.

## CKB source and ordering

CKB defines `CKB_SOURCE_GROUP_INPUT` as the virtual input array containing
Cells that use the same complete Script as the currently executing Script. A
Type Script group is formed from inputs and outputs that share that complete
Type Script. CellScript therefore does not perform a transaction-wide scan and
does not infer membership from data, Lock hash, or a partial code-hash match.

The runtime starts at group-relative index zero and increments by one. This is
the canonical filtered transaction-input order supplied by CKB. Only
`CKB_INDEX_OUT_OF_BOUND` ends the scan. Any other syscall status rejects the
transaction.

Normative upstream sources:

- [CKB RFC 0046: syscalls](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0046-syscalls/0046-syscalls.md)
- [CKB RFC 0022: transaction structure](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md)

## Runtime algorithm

For a declared bound `N`, the generated verifier performs this algorithm:

1. Call `LOAD_CELL_DATA(index, GroupInput)` into a bounded stack buffer.
2. On success, require `index < N`. A successful load at index `N` proves the
   group has at least `N + 1` members and rejects it.
3. Require the returned byte length to equal the typed resource width.
4. Load the current Script hash.
5. Load the selected GroupInput's Type hash and compare all four 64-bit words
   with the current Script hash.
6. Load its Lock hash and require that the current Type Script hash is not
   being reused in the Lock role.
7. Decode the fixed-width value, execute every body predicate and accumulator
   update, and increment the index exactly once.
8. On `CKB_INDEX_OUT_OF_BOUND`, produce the absent-element result and exit the
   loop.

Zero members are accepted when the Type Script is invoked through its output
group. This gives `BoundedCellSet<T, N>` the runtime cardinality `0..=N`; it
does not silently change the minimum to one.

## Identity and duplicate values

Group membership uses the complete current Type Script. Transaction inputs are
identified by distinct OutPoints at the CKB transaction layer. The collection
operation does not treat an arbitrary resource data field as a second global
identity namespace.

Two selected Cells may therefore contain the same application field value.
The shared fixture records this as
`duplicate_application_identity_is_collection_neutral`. A protocol that needs
field uniqueness must declare and enforce that resource identity through its
creation/replacement policy or a separate checked invariant. The collection
contract must not invent a uniqueness rule from a field name.

## Stable failures

| Code | Meaning in this contract |
|---:|---|
| 1 | CKB syscall failed where no more specific mapped status applies |
| 3 | GroupInput Cell data load failed |
| 4 | fixed-width data or hash result length is not exact |
| 5 | a per-element or post-loop `require` predicate is false |
| 17 | selected input Type hash differs from the current Script hash |
| 21 | actual group cardinality exceeds `N` |
| 24 | requested bounded collection shape has no supported runtime contract |
| 47 | current Script is used in the wrong Script role |

All failures terminate the verifier process. No partial discharge or clean
success path is emitted after an error.

## Typed and independent evidence

The compiler records a `bounded-cell-load` operation whose declared type is
`BoundedCellSet<T, N>`. ProofPlan records the runtime cardinality, exact
GroupInput source, fixed-width decoding, per-element predicate execution, and
linear discharge. The source map and lowering record bind those typed blocks
to the emitted machine blocks.

The standalone artifact checker additionally decodes the RISC-V sequence. It
requires:

- `LOAD_CELL_DATA` with `GroupInput`, the typed loop ordinal, the exact stack
  buffer/length slots, and the success/end/error split;
- the strict `index < N` branch over that same ordinal and stable error 21;
- the exact typed byte-width comparison over the syscall's length slot and
  stable error 4;
- current Script hash loading plus GroupInput Type-hash field 5, including
  successful syscall status, exact 32-byte lengths, exact corresponding
  0/8/16/24 word offsets, and mismatch failure;
- GroupInput Lock-hash field 3, the same loop ordinal, all four corresponding
  hash words folded into the Lock/Type distinction result, and stable role
  failure;
- exact loaded/absent destination and presence-bit stack slots;
- the stable terminal errors used by the scan.

Deterministic checker mutations change the count immediate, decode width,
GroupInput ordinal, Type-hash word offset, identity length, Lock fold,
success pointer, absent result slot, and the predicate's typed-to-machine
binding. Every mutation is rejected with V2420 after all artifact and sidecar
hashes are rebound.

## Acceptance corpus and budgets

[`bounded_group_input_v1.json`](../tests/fixtures/bounded_group_input_v1.json)
is the versioned shared corpus. The simulator adapter and the `ckb-testtool`
full transaction adapter execute the same case identities and expected exit
codes:

- zero, one, `N`, and `N + 1` members;
- malformed fixed-width data;
- false predicate at the first, middle, and last position;
- wrong-Type/GroupInput-excluded Cells;
- repeated application identity values.

The maximum supported bound has a separate executable fixture at
[`bounded_group_input_max.cell`](../tests/fixtures/bounded_group_input_max.cell).
The test executes 1024 GroupInput Cells and enforces a 4 KiB stripped ELF limit
and a 3,000,000-cycle CKB-VM limit. These are release guards for this focused
contract, not general transaction size or fee promises.

The stateful CKB acceptance run on 2026-09-08 executed all ten cases against one
deployed 1,752-byte ELF. The `N = 3` success case measured 8,996 cycles; the
one-element, excluded-foreign, and duplicate-application-identity successes
measured 4,348, 4,885, and 6,672 cycles. Over-bound, malformed, and false
predicate cases returned exactly 21, 4, and 5 and left every seeded input live.
The production-evidence validator recomputes the current fixture SHA-256,
requires exactly one `bounded-group-input-v1:verify` build/deployment row, and
binds the acceptance artifact path and CKB data hash to that row. Stale,
spliced, missing, or duplicate evidence fails closed.
