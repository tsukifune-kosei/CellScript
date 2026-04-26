CellScript source reads best when you think of it as a small Cell story. First you name the module. Then you describe the state that can exist on chain. Finally you write the actions and locks that say how that state may change or be authorized.

## What You Will Learn

- how a `.cell` file is organized;
- when to use `struct`, `resource`, `shared`, and `receipt`;
- what `action` entries do;
- what `lock` entries do;
- which type shapes are part of the documented production surface.

A source file normally contains:

- one `module` declaration;
- persistent declarations such as `resource`, `shared`, and `receipt`;
- optional ordinary `struct`, `enum`, and `const` declarations;
- executable `action` and `lock` entries.

## Module Declaration

```cellscript
module cellscript::demo
```

Prefer a stable namespace path for package code because module names are
included in metadata and source identity. Bundled examples use the
`cellscript::` namespace:

```cellscript
module cellscript::timelock
```

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

Use fixed-size byte arrays when a value must be part of a persistent Molecule-compatible schema or a predictable CKB data layout.

`Signature` is not a built-in scalar. Model signatures as a `struct` or byte field when a contract needs to carry them:

```cellscript
struct Signature {
    signer: Address
    signature: [u8; 64]
}
```

For dynamic payloads that cross ABI or persistent schema boundaries, the documented production surface includes targeted `Vec<u8>`, `Vec<Address>`, `Vec<Hash>`, and concrete fixed-width struct-vector paths. Generic collection ownership is intentionally narrower than "all collections are supported"; use the collections support matrix before advertising a collection shape as production-ready.

## Structs

Use `struct` for ordinary typed data that is not itself a persistent Cell. A struct is a shape; it does not by itself create on-chain storage.

```cellscript
struct Config {
    threshold: u64
}
```

Local struct values are transaction-local unless they are embedded in a persistent `resource`, `shared`, or `receipt`.

## Resources

Use `resource` for linear Cell-backed assets. If your contract should not be able to duplicate or lose a value silently, it probably belongs in a resource.

```cellscript
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}
```

Resources cannot be silently copied or dropped. The compiler tracks them as linear values.

## Shared State

Use `shared` for contention-sensitive state such as pools or registries. Shared state tells tools and schedulers that multiple transactions may care about the same Cell-backed value.

```cellscript
shared Pool has store {
    token_reserve: u64
    ckb_reserve: u64
}
```

Shared state reads and writes remain visible in metadata so schedulers and policy checks can reason about transaction access.

## Receipts

Use `receipt` for single-use proof Cells. A receipt is useful when one action creates a right and another action later consumes that right.

```cellscript
receipt VestingGrant has store, claim {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}
```

Receipts are useful for deposits, vesting grants, voting records, settlement proofs, and claim flows.

## Actions

Use `action` for type-script style transition logic. An action says what inputs are required, what checks must pass, and what new Cell state is produced.

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

## Locks

Use `lock` for CKB spend-boundary predicates. Keep locks literal: mark the typed
input Cell guarded by this lock invocation with `protected`, mark decoded
transaction witness data with `witness`, and use `require` for conditions that
should fail the current script validation.

```cellscript
shared Wallet has store {
    owner: Address
    nonce: u64
}

lock owner_only(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    require wallet.owner == claimed_owner
}
```

Locks must return `bool`. `protected Wallet` means a typed view of one selected
input Cell in the current script group whose spend is guarded by this lock
invocation. It is not an output Cell, not a transaction-wide scan, and not all
same-type Cells unless the language explicitly adds such multiplicity syntax.
`witness Address` means decoded transaction witness data only; it is not a
signer or ownership proof. Target-profile policy determines which runtime
helpers are allowed. For example, unsupported helper syscalls are rejected under
the CKB profile, and CKB signature/witness verification must be represented
through explicit script-args and sighash verification primitives once those
primitives are implemented.

## Assertions

Use assertions for verifier conditions. They make the rule visible in source and in compiler metadata.

```cellscript
assert_invariant(amount > 0, "amount must be positive")
```

Assertions lower into script checks and appear in metadata as part of verifier analysis.

## Comments

CellScript supports line comments and nested block comments:

```cellscript
// Explain Cell movement or security boundaries.

/*
   Block comments may contain nested /* inner */ comments.
*/
```

Use comments sparingly. In examples, comments should explain Cell lifecycle,
protected/witness scope, or builder obligations rather than restating ordinary
arithmetic.

## Next

With the source shape in mind, continue with [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects.md).
