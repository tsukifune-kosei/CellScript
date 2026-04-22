CellScript is built around explicit Cell transaction effects. These operations are not ordinary function calls; they describe how a transaction consumes inputs, creates outputs, reads dependencies, and proves state transitions.

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

Resources are linear. This means the compiler expects each value to have a clear lifecycle:

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

Use mutable references for replacement-output style transitions:

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

Use read-only forms for configuration, registry data, or dependency-backed state. These should become CellDep-style access in the target transaction model.

The compiler records read-only accesses so schedulers, wallet builders, and policy checks can decide which CellDeps must be present.

## CKB Portability Notes

The CKB profile is strict:

- no Spora-only helper syscalls;
- CKB syscall numbers and source constants;
- CKB-style ELF packaging with no Spora ABI trailer;
- CKB Molecule/BLAKE2b conventions where applicable;
- unsupported stateful shapes must fail closed.

For portable code, keep persistent schemas fixed and avoid Spora-only scheduler, DAA, and helper features.

## Next

Continue with [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow).

