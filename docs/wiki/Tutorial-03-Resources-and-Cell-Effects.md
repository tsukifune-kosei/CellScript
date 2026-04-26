CellScript is built around explicit Cell transaction effects. An effect is not just a helper call. It is a statement about the transaction you expect to build: which inputs are consumed, which outputs are created, which dependencies are read, and which state transition is being proved.

## What You Will Learn

- how linear resources move through an action;
- why `create`, `consume`, `destroy`, `claim`, and `settle` are explicit;
- how mutable state turns into replacement-output style transitions;
- what to avoid when the same source must stay portable to CKB.

## The Main Effects

| Effect | Meaning |
|---|---|
| `consume value` | Spend an input-backed linear value. |
| `create T { ... }` | Create a new output Cell with typed data. |
| `read_ref T` | Read a CellDep-backed value without consuming it. |
| `transfer value to` | Move a value to a new lock or owner. |
| `destroy value` | Consume a value without replacement, if the type has `destroy`. |
| `claim receipt` | Consume a receipt and materialize the claim path. |
| `settle receipt` | Finalize a receipt-backed process. |

## Linear Values

Resources are linear. This means the compiler expects each value to have a clear lifecycle. In plain terms: if an action receives a resource, the action must say where it goes.

```cellscript
action burn(token: Token) {
    assert_invariant(token.amount > 0, "cannot burn zero")
    destroy token
}
```

If an action receives a `Token`, it must consume, return, transfer, claim, settle, or destroy it. Silent loss is rejected.

## Creating Output Cells

`create` constructs typed output data and a corresponding Cell output:

```cellscript
create Token {
    amount: amount,
    symbol: auth.token_symbol
} with_lock(to)
```

Persistent state is created only by explicit `create`. Local variables are not persistent storage.

## Mutating Existing State

Use mutable references for replacement-output style transitions. You change the logical state in source; the transaction model still needs an input and a matching replacement output.

```cellscript
action mint(auth: &mut MintAuthority, to: Address, amount: u64) -> Token {
    assert_invariant(auth.minted + amount <= auth.max_supply, "exceeds max supply")
    auth.minted = auth.minted + amount

    create Token {
        amount: amount,
        symbol: auth.token_symbol
    } with_lock(to)
}
```

Under the hood, mutable Cell-backed state must be tied to transaction inputs and replacement outputs. Metadata records the runtime requirements and checked subconditions.

## Read-Only Dependencies

Use read-only forms for configuration, registry data, or dependency-backed state. The value is consulted, but it is not spent. On CKB, this should become CellDep-style access in the target transaction model.

The compiler records read-only accesses so schedulers, wallet builders, and policy checks can decide which CellDeps must be present.

## CKB Portability Notes

The CKB profile is intentionally strict. If the compiler rejects a shape that depends on unsupported runtime behavior, that is the right outcome:

- CKB syscall numbers and source constants;
- CKB-style ELF packaging;
- CKB Molecule/BLAKE2b conventions where applicable;
- unsupported stateful shapes must fail closed.

For portable code, keep persistent schemas fixed and avoid target-specific scheduler, time, and helper features.

## Next

After you know how values move, continue with [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow).
