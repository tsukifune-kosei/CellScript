CellScript modules describe typed Cell state and executable transition logic. A source file normally contains:

- one `module` declaration;
- persistent declarations such as `resource`, `shared`, and `receipt`;
- optional ordinary `struct`, `enum`, and `const` declarations;
- executable `action` and `lock` entries.

## Module Declaration

```cellscript
module spora::demo
```

Some older examples use a semicolon form:

```cellscript
module timelock_contract;
```

Prefer a stable module path for package code because module names are included in metadata and source identity.

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
Signature
[u8; 8]
```

Use fixed-size byte arrays when a value must be part of a persistent Molecule-compatible schema or a predictable CKB data layout.

## Structs

Use `struct` for ordinary typed data that is not itself a persistent Cell:

```cellscript
struct Config {
    threshold: u64
}
```

Local struct values are transaction-local unless they are embedded in a persistent `resource`, `shared`, or `receipt`.

## Resources

Use `resource` for linear Cell-backed assets:

```cellscript
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}
```

Resources cannot be silently copied or dropped. The compiler tracks them as linear values.

## Shared State

Use `shared` for contention-sensitive state such as pools or registries:

```cellscript
shared Pool has store {
    token_reserve: u64
    spora_reserve: u64
}
```

Shared state reads and writes remain visible in metadata so schedulers and policy checks can reason about transaction access.

## Receipts

Use `receipt` for single-use proof Cells:

```cellscript
receipt VestingGrant has store, claim {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}
```

Receipts are useful for deposits, vesting grants, voting records, settlement proofs, and claim flows.

## Actions

Use `action` for type-script style transition logic:

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

Use `lock` for authorization logic:

```cellscript
lock owner_only(owner: Address, signature: Signature) {
    assert_invariant(verify_signature(owner, signature), "invalid signature")
}
```

Target-profile policy determines which verification helpers are allowed. For example, Spora-only helper syscalls are rejected under the CKB profile.

## Assertions

Use assertions for verifier conditions:

```cellscript
assert_invariant(amount > 0, "amount must be positive")
```

Assertions lower into script checks and appear in metadata as part of verifier analysis.

## Next

Continue with [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects).

