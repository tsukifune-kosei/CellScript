The repository includes bundled examples that exercise the v1 language surface and compiler gates.

| Example | Purpose |
|---|---|
| `examples/token.cell` | Minting, transfer, burn, and guarded token merge. |
| `examples/timelock.cell` | Time-gated state transitions and release flows. |
| `examples/multisig.cell` | Threshold authorization and signature-oriented locks. |
| `examples/nft.cell` | Unique assets, metadata, and owner transitions. |
| `examples/vesting.cell` | Vesting grants, receipts, and claim lifecycle. |
| `examples/amm_pool.cell` | Shared pool state, swap, and liquidity effects. |
| `examples/launch.cell` | Launch/pool composition patterns. |

## Compile All Examples

From the repository root:

```bash
for f in examples/*.cell; do
  echo "==> $f"
  cellc "$f" --target riscv64-elf --target-profile spora -o "/tmp/$(basename "$f" .cell).elf"
done
```

## Token Walkthrough

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

`mint` mutates authority state and creates a new token:

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

`transfer_token` consumes an input token and creates a replacement output under a new lock:

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

## What to Learn from Each Example

- Start with `token.cell` to learn linear resources and creation.
- Read `nft.cell` to learn fixed ownership and unique-asset state.
- Read `timelock.cell` to learn time guards and state replacement.
- Read `multisig.cell` to learn lock-style authorization.
- Read `vesting.cell` to learn receipt-style claim flows.
- Read `amm_pool.cell` after you understand `shared`, because pools introduce contention-sensitive state.
- Read `launch.cell` last; it composes multiple protocol patterns.

## Spora vs CKB Expectations

Spora profile should compile the bundled examples as Spora artifacts.

CKB profile is stricter. Pure or admitted subsets should compile to CKB ELF without a Spora ABI trailer. Complex examples may be rejected by policy if they require unsupported runtime or Spora-only behavior. A policy rejection is preferable to producing an artifact with incorrect CKB assumptions.

## Production Checklist

Before treating an example-derived contract as deployable:

```bash
cellc fmt --check
cellc check --all-targets --production
cellc build --target riscv64-elf --target-profile spora --production
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile spora --production
```

For CKB:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile ckb --production
```

