The repository includes seven bundled examples that exercise the CellScript 0.12 language surface and production gates.

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

Spora profile should compile and deploy the bundled examples as Spora artifacts under the current local production suite.

CKB profile is stricter than Spora, but the current bundled-example suite is closed for the 0.12 production boundary:

- all seven bundled examples strict-admit under the CKB profile;
- all 43 bundled business actions have scoped CKB production harnesses;
- all 15 bundled locks strict-compile;
- valid CKB transactions are builder-generated and dry-run;
- malformed transactions are rejected for non-policy/non-capacity reasons;
- tx-size, cycle, and occupied-capacity evidence is retained;
- all seven bundled examples are deployed in the CKB production acceptance report;
- the final production hardening gate must pass.

This does not mean arbitrary new contracts are automatically production-ready. New contracts still need their own constraints review, entry ABI review, builder evidence, and chain acceptance evidence.

## Production Checklist

Before treating an example-derived contract as deployable:

```bash
cellc fmt --check
cellc check --all-targets --production
cellc build --target riscv64-elf --target-profile spora --production
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile spora --production
```

For CKB compiler-side review:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile ckb --production
cellc examples/nft.cell --entry-action transfer --target riscv64-elf --target-profile ckb --production
```

For release-facing evidence, run the parent Spora repository acceptance gates:

```bash
./scripts/spora_cellscript_acceptance.sh --profile production
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_spora_production_evidence.py target/devnet-acceptance/<run>/production-evidence.json
python3 scripts/validate_ckb_cellscript_production_evidence.py target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

Do not use compile-only or bounded diagnostic runs as production release evidence.
