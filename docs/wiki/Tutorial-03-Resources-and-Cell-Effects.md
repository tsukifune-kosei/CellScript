CellScript is built around explicit Cell movement. An effect is not just a
helper call. It is a statement about the transaction you expect to build: which
inputs are consumed, which outputs are created, which dependencies are read, and
which state transition is being proved.

If you come from account-style smart contracts, this is the chapter where the
mental model changes. In CellScript, persistent state does not quietly update in
place. A transaction spends Cells and creates new Cells.

## What You Will Learn

- how linear resources move through an action;
- why `create`, `consume`, `destroy`, `claim`, and `settle` are explicit;
- how `&mut` source syntax still maps to replacement-output style transitions;
- why unsupported CKB runtime behavior should fail closed.

## The Main Effects

| Effect | Read it as |
|---|---|
| `consume value` | Spend an input-backed linear value. |
| `create T { ... }` | Create a typed output Cell. |
| `read_ref T` | Read dependency-backed state without consuming it. |
| `transfer value to` | Move a value to a new lock or owner. |
| `destroy value` | Consume a value without replacement, if the type allows `destroy`. |
| `claim receipt` | Consume a receipt and materialize the claim path. |
| `settle receipt` | Finalize a receipt-backed process. |

The effects are deliberately visible. They make the source read like a
transaction plan instead of a hidden storage mutation.

## Linear Values

Resources are linear. In plain terms: if an action receives a resource, the
action must say where it goes.

```cellscript
action burn(token: Token) {
    assert_invariant(token.amount > 0, "cannot burn zero")
    destroy token
}
```

The `Token` cannot simply disappear. It must be consumed, returned, transferred,
claimed, settled, or destroyed. Silent loss is rejected because silent loss would
make the Cell lifecycle unclear.

## Creating Output Cells

`create` constructs typed output data and a corresponding Cell output:

```cellscript
create Token {
    amount,
    symbol: auth.token_symbol
} with_lock(to)
```

Persistent state is created only by explicit `create`. Local variables are just
local variables. They do not become on-chain storage unless they are placed into
a created Cell.

The `with_lock(to)` part matters. It says which lock will guard the newly
created Cell. If a later transaction wants to spend that Cell, the lock must
accept the spend.

## Consuming And Replacing State

A common CellScript pattern is:

1. read or consume an input Cell;
2. check the transition;
3. create a replacement output Cell.

For example, a transfer consumes one token and creates a replacement token under
a different lock:

```cellscript
action transfer_token(token: Token, to: Address) -> Token {
    consume token

    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}
```

This is closer to CKB than an account-style assignment. The old Cell is spent;
the new Cell is created.

## Mutating Existing State

CellScript also supports mutable references for readable source code:

```cellscript
action mint(auth: &mut MintAuthority, to: Address, amount: u64) -> Token {
    assert_invariant(auth.minted + amount <= auth.max_supply, "exceeds max supply")
    auth.minted = auth.minted + amount

    create Token {
        amount,
        symbol: auth.token_symbol
    } with_lock(to)
}
```

The source says `auth.minted = ...`, but the CKB-facing model still needs an
input Cell and a replacement output Cell for `MintAuthority`. Metadata records
the runtime requirements and checked subconditions so reviewers can see that the
mutation is not pretending CKB has account storage.

When you read `&mut` in examples, translate it mentally as "this state must be
replaced consistently."

## Read-Only Dependencies

Some data is consulted but not spent: configuration, registry entries, reference
state, or dependency-backed protocol facts. Use read-only forms for that kind of
data.

On CKB, this usually maps to CellDep-style access in the target transaction
model. The compiler records read-only accesses so builders, schedulers, wallets,
and policy checks can decide which dependencies must be present.

## Receipts As Flow Control

Receipts are useful when a protocol needs a two-step or multi-step flow. One
action creates a right, and another action later consumes it.

For example:

- a vesting action creates a claimable grant;
- a later claim action consumes the grant;
- a settlement action consumes proof that a process completed.

This makes intermediate protocol state explicit instead of hiding it in a
generic event log.

## CKB Profile Notes

The CKB profile is intentionally strict. If the compiler rejects a shape that
depends on unsupported runtime behavior, that is usually the correct outcome.

For CKB code, prefer:

- fixed persistent schemas;
- explicit action parameters;
- explicit locks for authorization boundaries;
- explicit capacity, witness, and dependency review;
- metadata-backed explanations for every runtime obligation.

Avoid assuming that a helper, syscall, or collection shape is supported just
because it is convenient. If the profile cannot lower it safely, it should fail
closed.

## Next

After you know how values move, continue with
[Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow.md).
