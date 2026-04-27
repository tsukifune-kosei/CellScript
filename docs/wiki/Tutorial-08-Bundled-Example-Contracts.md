The repository includes seven bundled examples. Treat them as guided reading,
not just files to compile. Each one teaches a different part of the language:
linear resources, shared state, receipts, locks, proposal flows, time checks,
and CKB production evidence.

This chapter helps you choose what to read first and what to learn from each
example.

## The Examples

| Example | What it teaches |
|---|---|
| `examples/token.cell` | Minting, transfer, burn, and guarded token merge. |
| `examples/nft.cell` | Unique assets, metadata, ownership transitions, and owner locks. |
| `examples/timelock.cell` | Time-gated state transitions, release requests, and approval flow. |
| `examples/multisig.cell` | Threshold policy, proposals, signatures-as-data, and lock-boundary predicates. |
| `examples/vesting.cell` | Vesting grants, receipts, claim lifecycle, and admin-boundary comments. |
| `examples/amm_pool.cell` | Shared pool state, swap logic, liquidity receipts, and settlement effects. |
| `examples/launch.cell` | Launch/pool composition patterns. |

The top-level `examples/*.cell` files are the clean business reading surface.
`examples/business/*.cell` mirrors that clean surface explicitly.
`examples/acceptance/*.cell` carries production/profile metadata such as
`#[effect(...)]` and `#[scheduler_hint(...)]`; the CKB acceptance script uses
those profiled copies when generating release evidence.

Subdirectory copies use `cellscript::business::*` and
`cellscript::acceptance::*` module namespaces so they can coexist with the
top-level examples during module loading.

`examples/registry.cell` is intentionally outside the bundled production matrix.
It is a bounded-collection language example for local `Vec<Address>` and
`Vec<Hash>` helpers, covered by compiler/tooling tests rather than CKB
production action acceptance.

For a visual business-flow map of every bundled example, see
[`CELLSCRIPT_EXAMPLE_BUSINESS_FLOWS.md`](../CELLSCRIPT_EXAMPLE_BUSINESS_FLOWS.md).

## A Good Reading Order

If you are learning the language, read them in this order:

1. `token.cell`: start here. It is the smallest example with a clear resource
   lifecycle.
2. `nft.cell`: learn unique assets and ownership-style locks.
3. `timelock.cell`: learn time guards and replacement state.
4. `multisig.cell`: learn proposal lifecycle and threshold logic.
5. `vesting.cell`: learn receipt-style claim flows.
6. `amm_pool.cell`: learn shared pool state after you understand resources.
7. `launch.cell`: read this last because it composes multiple patterns.

Do not try to learn everything from the densest example first. The examples are
more useful when each one adds one new idea.

## Compile All Examples

From the repository root:

```bash
for f in examples/*.cell; do
  echo "==> $f"
  cellc "$f" --target riscv64-elf --target-profile ckb -o "/tmp/$(basename "$f" .cell).elf"
done
```

This is a compile pass, not a full CKB production claim. It is useful while
learning because it shows that the examples fit the compiler and CKB profile.

## Token Walkthrough

Start with the token example. It is small enough to keep in your head.

The token example declares two resources:

```cellscript
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

resource MintAuthority has store {
    token_symbol: [u8; 8]
    max_supply: u64
    minted: u64
}
```

`Token` is the asset. `MintAuthority` is the state that limits how much can be
minted.

`mint` mutates authority state and creates a new token:

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

Read `auth: &mut MintAuthority` as a replacement-output obligation. The source
is pleasant to read, but CKB still needs an input state Cell and a replacement
state Cell.

`transfer_token` consumes an input token and creates a replacement output under
a new lock:

```cellscript
action transfer_token(token: Token, to: Address) -> Token {
    consume token

    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}
```

`burn` consumes the token and destroys it:

```cellscript
action burn(token: Token) {
    assert_invariant(token.amount > 0, "cannot burn zero")
    destroy token
}
```

These three actions show the basic resource lifecycle: create, replace, destroy.

## Locks In The Examples

The bundled locks use `protected` to show the input Cell guarded by the current
lock invocation and `witness` to show decoded transaction witness data. Those
markers do not make an `Address` a signer proof.

When you see a lock like this:

```cellscript
lock owner_only(asset: protected NFT, claimed_owner: witness Address) -> bool {
    require asset.owner == claimed_owner
}
```

read it carefully:

- `asset` is the protected input Cell view;
- `claimed_owner` is decoded witness data;
- `require` fails the script if the comparison is false;
- the comparison does not prove that `claimed_owner` signed the transaction.

Real signature authorization still needs explicit script-args binding, sighash
verification, and its own positive and negative CKB transaction matrix.

## CKB Production Expectations

The CKB profile is strict, and the bundled suite has a defined production
boundary:

- bundled examples strict-admit under the CKB profile;
- bundled business actions have scoped CKB production harnesses;
- bundled locks have builder-backed valid-spend and invalid-spend matrices;
- valid CKB transactions are builder-generated and dry-run;
- malformed transactions are rejected for non-policy/non-capacity reasons;
- transaction size, cycles, and occupied-capacity evidence are retained;
- bundled examples are deployed in the CKB production acceptance report;
- the final production hardening gate must pass.

This does not mean arbitrary new contracts are automatically production-ready.
Use the examples as patterns, then run your own constraints review, entry ABI
review, builder evidence, security review, and chain acceptance evidence.

## Production Checklist

Before treating an example-derived contract as deployable, run the compiler-side
checks:

```bash
cellc fmt --check
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile ckb --production
cellc examples/nft.cell --entry-action transfer --target riscv64-elf --target-profile ckb --production
# --entry-action selects a single action entry point for targeted inspection
```

For release-facing CKB evidence, run the CellScript acceptance gate:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

Do not use compile-only or bounded diagnostic runs as production release
evidence. They are helpful during development, but they do not replace the chain
acceptance boundary.
