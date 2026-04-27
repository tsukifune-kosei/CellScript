This page is a practical companion to the tutorials. Each recipe gives you a
small goal, the code or command to start from, and the boundary you should keep
in mind.

Read the main tutorials first if the concepts are unfamiliar. Use this page when
you already know what you want to do.

## Recipe: Compile One File For CKB

Use this when you have a single `.cell` file and want a CKB-profile artifact.

```bash
cellc examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.elf
cellc verify-artifact /tmp/token.elf --expect-target-profile ckb
```

This proves that the artifact and metadata agree under the CKB profile. It does
not prove that a complete CKB transaction has been built or accepted.

## Recipe: Create A Linear Resource

Use a `resource` when a value should not be duplicated or silently dropped.

```cellscript
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}
```

The compiler tracks `Token` as a linear value. An action that receives a token
must consume, return, transfer, claim, settle, or destroy it.

## Recipe: Mint A New Output Cell

Use `create` when an action materializes new Cell state.

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

The field shorthand `amount` means `amount: amount`. The `with_lock(to)` part is
the lock on the created output Cell.

## Recipe: Replace State Instead Of Updating In Place

Use `&mut` when the source should read like mutation, but remember the CKB model:
the transaction still needs an input Cell and a replacement output Cell.

```cellscript
action bump_nonce(wallet: &mut Wallet) {
    wallet.nonce = wallet.nonce + 1
}
```

When reviewing this pattern, inspect metadata and builder evidence for the
replacement-output obligations. Do not treat it as account storage.

## Recipe: Write An Honest Lock Predicate

Use `protected`, `witness`, and `require` to make the CKB boundary readable.

```cellscript
lock owner_only(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    require wallet.owner == claimed_owner
}
```

Read this carefully:

- `wallet` is the protected input Cell view;
- `claimed_owner` is witness data;
- `require` fails validation if the comparison is false;
- the comparison does not prove that `claimed_owner` signed the transaction.

## Recipe: Avoid Fake Signer Semantics

Do not use names such as `signer` unless the value is actually produced by
signature verification.

```cellscript
// Misleading: this is still only witness data.
lock bad_owner_check(wallet: protected Wallet, signer: witness Address) -> bool {
    require wallet.owner == signer
}
```

Prefer names such as `claimed_owner` or `provided_owner` until the language has
explicit script-args and sighash verification primitives.

## Recipe: Reserve Script Args For Future Binding

The intended shape for real signature authorization is explicit:

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

This is a teaching shape for the future. `lock_args` is reserved and fail-closed
until typed CKB script-args binding is implemented.

## Recipe: Use Empty Vec Literals Safely

Use `[]` only where the expected `Vec<T>` type is known.

```cellscript
let mut keys: Vec<Hash> = []

create Proposal {
    proposal_id,
    proposer,
    data: [],
    signatures: []
}
```

`[]` is empty `Vec<T>` sugar in a typed context. It is not a generic collection
model, and it does not enable cell-backed collection ownership.

## Recipe: Inspect Entry ABI And Witness Layout

Use ABI and entry-witness reports before building transaction code.

```bash
cellc abi . --target-profile ckb --action transfer
cellc entry-witness . --target-profile ckb --action transfer --json
```

These reports tell builders and reviewers what data the entry expects. They do
not prove that the transaction has been assembled correctly.

## Recipe: Check A Package Before Building

Use this loop while developing a package:

```bash
cellc fmt --check
cellc check --target-profile ckb --all-targets --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

This is a compiler/package gate. Use it before asking for deeper CKB evidence.

## Recipe: Run The CKB Production Gate

Use this only from the CellScript repository root:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

This is the boundary where compiler evidence becomes builder-backed local CKB
evidence for the bundled suite.

## Recipe: Choose An Example To Read

Start with the smallest example that teaches the idea you need:

| Goal | Read |
|---|---|
| Linear resource lifecycle | `examples/token.cell` |
| Unique assets and ownership | `examples/nft.cell` |
| Time-gated releases | `examples/timelock.cell` |
| Threshold proposals | `examples/multisig.cell` |
| Claim receipts | `examples/vesting.cell` |
| Shared liquidity state | `examples/amm_pool.cell` |
| Composition patterns | `examples/launch.cell` |
| Local bounded vectors | `examples/registry.cell` |

Read one example for one idea. The examples are easier to learn from when you do
not treat them as one large feature checklist.
