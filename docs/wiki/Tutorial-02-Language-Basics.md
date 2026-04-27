CellScript source reads best when you treat it as a small Cell story. First you
name the module. Then you describe the state that can exist on chain. Finally
you write the actions and locks that say how that state may change or be spent.

This chapter is a map. It does not cover every syntax detail, but it gives you
the vocabulary you need before reading the bundled examples.

## A Source File At A Glance

A typical `.cell` file contains:

- one `module` declaration;
- persistent declarations such as `resource`, `shared`, and `receipt`;
- optional ordinary `struct`, `enum`, and `const` declarations;
- executable `action` entries;
- executable `lock` entries.

The first split to learn is simple:

- ordinary data helps you calculate;
- persistent declarations describe Cell-backed state;
- actions change state;
- locks guard spending.

## Module Declaration

Start with a stable module name:

```cellscript
module cellscript::demo
```

Bundled examples use the `cellscript::` namespace:

```cellscript
module cellscript::timelock
```

Module names are not decoration. They are part of source identity and appear in
metadata, so use names you are willing to keep stable.

## Scalar and Fixed Types

Common field and parameter types include:

```cellscript
u8
u16
u32
u64
u128
bool
Address
Hash
[u8; 8]
```

Use fixed-size byte arrays when a value must live in a predictable persistent
schema or CKB data layout.

`Signature` is not a built-in scalar. If a contract needs to carry a signature,
model it explicitly:

```cellscript
struct Signature {
    signer: Address
    signature: [u8; 64]
}
```

That `signer` field is only data until a lock verifies it. Names do not create
authority.

For dynamic payloads that cross ABI or persistent schema boundaries, the
documented production surface includes targeted `Vec<u8>`, `Vec<Address>`,
`Vec<Hash>`, and concrete fixed-width struct-vector paths. Generic collection
ownership is intentionally narrower than "all collections are supported". Use
the collections support matrix before presenting a collection shape as
production-ready.

## Structs

Use `struct` for ordinary typed data that is not itself a persistent Cell:

```cellscript
struct Config {
    threshold: u64
}
```

A struct is a shape. It does not create on-chain storage by itself. A local
`Config` value is transaction-local unless you embed it in a `resource`,
`shared`, or `receipt`.

## Resources

Use `resource` for linear Cell-backed assets. If your protocol should not be
able to duplicate or silently drop a value, it probably belongs in a resource.

```cellscript
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}
```

Resources are linear values. When an action receives one, the action must say
where it goes: consume it, create a replacement, transfer it, return it, claim
it, settle it, or destroy it.

## Shared State

Use `shared` for contention-sensitive state such as pools, launch state, or
registries:

```cellscript
shared Pool has store {
    token_reserve: u64
    ckb_reserve: u64
}
```

Shared state tells tools and schedulers that multiple transactions may care
about the same Cell-backed value. Reads and writes remain visible in metadata.

## Receipts

Use `receipt` for single-use proof Cells. A receipt is useful when one action
creates a right and another action later consumes that right.

```cellscript
receipt VestingGrant has store, claim {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}
```

Receipts are a good fit for deposits, vesting grants, voting records,
settlement proofs, and claim flows.

## Actions

Use `action` for type-script style transition logic. An action says what inputs
are required, what checks must pass, and what output Cell state is produced.

```cellscript
action transfer_token(token: Token, to: Address) -> Token {
    assert_invariant(token.amount > 0, "empty token")
    consume token

    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}
```

Read this as a Cell transition: spend one token input, then create a replacement
token output under a new lock.

## Locks

Use `lock` for CKB spend-boundary predicates. A lock should make its data
sources obvious:

- `protected` marks the typed input Cell guarded by this lock invocation;
- `witness` marks decoded transaction witness data;
- `require` marks a condition that fails the current script validation.

```cellscript
shared Wallet has store {
    owner: Address
    nonce: u64
}

lock owner_only(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    require wallet.owner == claimed_owner
}
```

Locks return `bool`. `protected Wallet` means a typed view of one selected input
Cell in the current script group whose spend is guarded by this lock
invocation. It is not an output Cell, not a transaction-wide scan, and not all
same-type Cells unless the language explicitly adds such multiplicity syntax.

`witness Address` means decoded transaction witness data only. It is not a
signer or ownership proof.

## Lock Boundary Primitives

The lock-boundary keywords are meant to expose CKB's transaction model instead
of hiding it behind account-style authorization language.

| Primitive | Meaning in CellScript | CKB-facing interpretation |
|---|---|---|
| `protected T` | Typed view of the Cell state guarded by this lock invocation. | One selected input Cell in the current script group, not an output Cell and not a transaction-wide scan. |
| `witness T` | Typed value decoded from transaction witness data. | User-supplied witness bytes decoded by the entry ABI. It is not a signer proof. |
| `require expr` | Lock predicate failure point. | If `expr` is false, the current script validation fails. |
| `lock_args T` | Reserved spelling for typed script args. | Future typed decoding of the executing lock script's args; currently fail-closed until binding is implemented. |

Use `require` inside locks. Use `assert_invariant` inside actions for state
transition checks. This keeps authorization predicates separate from business
state invariants.

This lock checks equality between protected Cell state and witness data:

```cellscript
lock owner_only(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    require wallet.owner == claimed_owner
}
```

That comparison may be useful, but it does not prove that `claimed_owner` signed
the transaction. A misleading parameter name does not make it safer:

```cellscript
// Unsafe as an authorization claim: `signer` is only a witness value here.
lock misleading(wallet: protected Wallet, signer: witness Address) -> bool {
    require wallet.owner == signer
}
```

Real CKB authorization needs explicit binding to script args, transaction digest
scope, witness layout, and signature verification. The intended future shape is
deliberately explicit:

```cellscript
lock signed_owner(
    wallet: protected Wallet,
    owner: lock_args Address,
    sig: witness Signature
) -> bool {
    require verify_sighash_all(sig, owner)
    require wallet.owner == owner
}
```

Until those primitives are available, treat `Address` and `witness Address` as
data only. They are useful for expressing and testing lock predicates, but they
are not cryptographic authorization by themselves.

## Assertions

Use assertions for action-side verifier conditions:

```cellscript
assert_invariant(amount > 0, "amount must be positive")
```

Assertions make state-transition rules visible in source and metadata. They are
not a substitute for lock authorization checks.

## Comments

CellScript supports line comments and nested block comments:

```cellscript
// Explain Cell movement or security boundaries.

/*
   Block comments may contain nested /* inner */ comments.
*/
```

Use comments where they help the reader understand Cell lifecycle, witness
scope, builder obligations, or a security boundary. Avoid comments that merely
repeat arithmetic.

## Next

With the source shape in mind, continue with
[Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects.md).
