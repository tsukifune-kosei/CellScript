# Tutorial 10: Standard Library

CellScript's standard library is intentionally small. It is not a place for
hidden protocol policy. A standard-library item is acceptable only when the
compiler can lower it to explicit verifier effects, verifier constraints, or a
small target-runtime helper.

Read stdlib calls as audit-visible shorthand. If a helper would hide Cell
movement, signer authority, capacity policy, or collection ownership, it does
not belong in the stable stdlib surface.

## The Rule

Every stable stdlib primitive must have one of these shapes:

| Shape | Meaning |
|---|---|
| Canonical pattern | Expands into `consume`, `create`, `require`, named output constraints, or metadata equality checks. |
| Runtime helper | Lowers to a bounded ckb-vm helper or syscall wrapper with explicit metadata. |
| Collection helper | Operates on verifier-local stack-backed values, not on hidden Cell ownership. |

Unknown `std::...` patterns fail at compile time. This is deliberate: authors
should not be able to smuggle protocol semantics through a name that the
compiler does not understand.

## Namespaces

The current stdlib surface keeps the 0.15 lifecycle namespace model and uses
these source-facing namespaces:

| Namespace | Purpose |
|---|---|
| `std::cell` | Cell identity, lock, and capacity continuity helpers. |
| `std::accounting` | Simple field-level conservation helpers. |
| `std::lifecycle` | Explicit lifecycle patterns that consume an input and constrain a named output. |
| `std::receipt` | Receipt redemption patterns for receipts that declare an output type. |

The backend also contains ckb-vm syscall/runtime helpers and bounded collection
helpers. Those are covered later in this chapter.

## Cell Metadata Helpers

Cell metadata helpers express continuity requirements that are not ordinary data
fields.

| Helper | Canonical meaning |
|---|---|
| `std::cell::same_type(output, input)` | Require the output and input Cell type hash to match. |
| `std::cell::preserve_type(output, input)` | Same as `same_type`; use when the action is phrased as preservation. |
| `std::cell::same_lock(output, input)` | Require the output and input lock metadata to match. |
| `std::cell::preserve_lock(output, input)` | Same as `same_lock`; use when the action is phrased as preservation. |
| `std::cell::preserve_capacity(output, input)` | Require the output and input capacity metadata to match. |

Example:

```cellscript
action preserve_coin_boundary(coin_before: Coin) -> coin_after: Coin {
    transition coin_before -> coin_after

    verification
        std::cell::preserve_type(coin_after, coin_before)
        std::cell::preserve_lock(coin_after, coin_before)
        std::cell::preserve_capacity(coin_after, coin_before)
}
```

`same_lock`, `preserve_lock`, and `preserve_capacity` lower to canonical Cell
metadata verifier checks. They are not data-field comparisons and should not be
replaced with ad hoc field names.

## Accounting Helpers

`std::accounting::conserved(output, input)` is a small field-level conservation
pattern. It requires both values to have an `amount` field with matching field
types and then checks:

```text
require output.amount == input.amount
```

Example:

```cellscript
action keep_amount(coin_before: Coin) -> coin_after: Coin {
    transition coin_before -> coin_after

    verification
        std::accounting::conserved(coin_after, coin_before)
}
```

Use this only for the simple one-input, one-output amount continuity case. More
complex accounting, such as fees, splits, merges, pool reserves, or multi-asset
conservation, should stay as explicit `require` statements so the proof remains
reviewable.

## Lifecycle Patterns

Lifecycle patterns are the main reason the stable stdlib surface exists. The
old core `transfer`, `claim`, and `settle` expression verbs are gone. The
stdlib replacements are explicit patterns with canonical expansions.

| Pattern | Required arguments | Expansion shape |
|---|---|---|
| `std::lifecycle::transfer(input, output, to) { fields }` | input Cell, named output binding, lock target | Consume `input`, create `output` with `with_lock(to)`, preserve the listed data fields, and check type continuity. |
| `std::receipt::claim(receipt, output, lock) { fields }` | receipt Cell, named output binding, lock target | Consume `receipt`, create the declared receipt output type with `with_lock(lock)`, and preserve the listed output fields. |
| `std::lifecycle::settle(input, output, lock) { fields }` | input Cell, named output binding, lock target | Consume `input`, create `output` with `with_lock(lock)`, and preserve the listed output fields. |

The field block is a whitelist. It must cover every data field required to
construct the output. This keeps newly added fields from being silently copied or
silently ignored.

Example transfer:

```cellscript
resource Coin has store, create, consume, replace, burn, relock {
    amount: u64,
    nonce: u64,
}

action transfer_coin(coin: Coin, to: Address) -> next_coin: Coin {
    verification
        std::lifecycle::transfer(coin, next_coin, to) {
            amount
            nonce
        }
}
```

This has the same audit shape as writing the pieces directly:

```text
consume coin

create next_coin = Coin {
    amount: coin.amount,
    nonce: coin.nonce
} with_lock(to)

std::cell::preserve_type(next_coin, coin)
```

Example receipt claim:

```cellscript
receipt Voucher -> Coin has create, consume, burn {
    amount: u64,
    nonce: u64,
    holder: Address,
}

action redeem_voucher(voucher: Voucher) -> coin: Coin {
    verification
        std::receipt::claim(voucher, coin, voucher.holder) {
            amount
            nonce
        }
}
```

`std::receipt::claim` requires the receipt declaration to name its output type
with `receipt Voucher -> Coin`. That arrow is part of the contract surface; the
compiler does not infer an arbitrary claim output.

Example settlement:

```cellscript
action settle_voucher(voucher: Voucher) -> coin: Coin {
    verification
        std::lifecycle::settle(voucher, coin, voucher.holder) {
            amount
            nonce
        }
}
```

Use `settle` only when the protocol language really benefits from the word. It
still lowers to explicit input consumption plus named output constraints.

## Require Blocks Stay Pure

Lifecycle stdlib patterns are Cell effects. Do not put them inside anonymous
`require` blocks.

Allowed:

```text
require {
    output.amount == input.amount
    output.nonce == input.nonce + 1
}
```

Rejected:

```text
require {
    std::lifecycle::transfer(input, output, to) {
        amount
        nonce
    }
}
```

A `require` block is pure boolean proof syntax. Lifecycle and Cell operation
syntax must stay at the action proof level where the consumed inputs and created
outputs remain visible.

## Bounded Collection Helpers

The compiler recognizes verifier-local stack-backed `Vec<T>` operations for
fixed-width values. This is useful for small lists such as signers, hashes,
fixed payload values, and local membership checks.

Supported helper surface:

```text
Vec::new
Vec::with_capacity
Vec::capacity
Vec::push
Vec::extend_from_slice
Vec::len
Vec::is_empty
indexing
Vec::first
Vec::last
Vec::contains
Vec::set
Vec::remove
Vec::pop
Vec::insert
Vec::reverse
Vec::truncate
Vec::swap
Vec::clear
```

Supported element categories are fixed-width values such as `u64`, `Address`,
`Hash`, and fixed-width schema values covered by the layout machinery.

This is not Cell-backed collection ownership. Do not model a set of independent
input Cells as `Vec<Cell<T>>`, a generic `HashMap`, or a hidden order book. Use
explicit action parameters and named output bindings until a verifier-backed
collection ownership primitive exists.

Generated allocation-backed collection symbols are fail-closed in the current
stdlib assembly and are not a production allocator ABI.

## Runtime And CKB Helpers

The backend tracks production CKB syscall surfaces used by generated code:

```text
syscall_load_tx_hash
syscall_load_script_hash
syscall_load_cell
syscall_load_header
syscall_load_input
syscall_load_script
syscall_load_cell_by_field
syscall_load_cell_data
syscall_load_witness
syscall_current_cycles
```

Most authors should reach these through language features, metadata commands, or
profile-specific builtins such as CKB time/header helpers. Treat raw syscall
helpers as backend machinery unless a compiler diagnostic or low-level document
explicitly tells you otherwise.

The 0.30 development surface exposes one signing-message builtin with visible
bounds:

```cellscript
let digest: SighashAllDigest =
    env::sighash_all_zero_lock(4, 8, 4, 4096)
let generic_hash = Hash::from_sighash_all(digest)
```

It uses the current input Script group and replaces the complete first
`WitnessArgs.lock` payload with equal-length zeros. The four literals bound
group inputs, all inputs, extra witnesses, and bytes per included witness.
This is not a prefix-preserving multisig domain. The generic
`env::sighash_all(source)` spelling remains deferred.

## What The Stdlib Does Not Do

The current standard library does not provide:

- hidden signer derivation from `Address`, `witness Address`, parameter names, or
  receipt names;
- hidden sighash verification;
- full generic `HashMap<K, V>` or `HashSet<T>`;
- allocation-backed `Vec`, `HashMap`, or `HashSet` runtime helpers;
- `Vec<Cell<T>>` or other hidden Cell-backed ownership collections;
- automatic capacity planning or change-output generation;
- arbitrary dynamic Blake2b policy;
- protocol-specific settlement, DAO, bridge, AMM, or order-book semantics hidden
  behind one generic word.

These are release boundaries, not accidental omissions. If a future helper
crosses one of these boundaries, it needs parser, type checker, lowering,
codegen, metadata, docs, and production evidence together.

## Example File

The compact language example lives at:

```text
examples/language/core/stdlib.cell
```

It demonstrates the stable stdlib patterns:

```text
std::cell::preserve_type(coin_after, coin_before)
std::cell::same_lock(coin_after, coin_before)
std::cell::preserve_lock(coin_after, coin_before)
std::cell::preserve_capacity(coin_after, coin_before)
std::accounting::conserved(coin_after, coin_before)
std::lifecycle::transfer(coin, next_coin, to) { amount nonce }
std::receipt::claim(voucher, coin, voucher.holder) { amount nonce }
std::lifecycle::settle(voucher, coin, voucher.holder) { amount nonce }
```

When reviewing a contract, expand these patterns mentally or with compiler
metadata: what input is consumed, what named output is constrained, what lock is
used, which fields are preserved, and which Cell metadata obligations are
emitted.
