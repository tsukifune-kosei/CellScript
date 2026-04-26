The repository includes seven production bundled examples. Treat them as guided
reading, not just sample files. Each one shows a different part of the
CellScript language surface and the current production gates.

## What You Will Learn

- which example to read first;
- how the token example maps resources to actions;
- what the bundled suite currently proves for the CKB profile;
- what extra evidence your own contract still needs.

| Example | Purpose |
|---|---|
| `examples/token.cell` | Minting, transfer, burn, and guarded token merge. |
| `examples/timelock.cell` | Time-gated state transitions and release flows. |
| `examples/multisig.cell` | Threshold authorization and signature-oriented locks. |
| `examples/nft.cell` | Unique assets, metadata, and owner transitions. |
| `examples/vesting.cell` | Vesting grants, receipts, and claim lifecycle. |
| `examples/amm_pool.cell` | Shared pool state, swap, and liquidity effects. |
| `examples/launch.cell` | Launch/pool composition patterns. |

`examples/registry.cell` is intentionally outside this seven-example production
matrix. It is a 0.13 bounded-collection language example for local
`Vec<Address>` and `Vec<Hash>` helpers, covered by compiler/tooling tests rather
than CKB production action acceptance.

For a visual business-flow map of every bundled example, see
[`CELLSCRIPT_EXAMPLE_BUSINESS_FLOWS.md`](../CELLSCRIPT_EXAMPLE_BUSINESS_FLOWS.md).

## Compile All Examples

From the repository root:

```bash
for f in examples/*.cell; do
  echo "==> $f"
  cellc "$f" --target riscv64-elf --target-profile ckb -o "/tmp/$(basename "$f" .cell).elf"
done
```

## Token Walkthrough

Start with the token example. It is the smallest bundled contract that still shows the resource lifecycle clearly.

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

Read the examples in this order if you are learning the language:

- Start with `token.cell` to learn linear resources and creation.
- Read `nft.cell` to learn fixed ownership and unique-asset state.
- Read `timelock.cell` to learn time guards and state replacement.
- Read `multisig.cell` to learn lock-style authorization.
- Read `vesting.cell` to learn receipt-style claim flows.
- Read `amm_pool.cell` after you understand `shared`, because pools introduce contention-sensitive state.
- Read `launch.cell` last; it composes multiple protocol patterns.

## CKB Production Expectations

The CKB profile is strict, and the current bundled-example suite is closed for the 0.12 production boundary:

- all seven bundled examples strict-admit under the CKB profile;
- all 43 bundled business actions have scoped CKB production harnesses;
- all 16 bundled locks strict-compile; this is not an on-chain lock spend matrix;
- valid CKB transactions are builder-generated and dry-run;
- malformed transactions are rejected for non-policy/non-capacity reasons;
- tx-size, cycle, and occupied-capacity evidence is retained;
- all seven bundled examples are deployed in the CKB production acceptance report;
- the final production hardening gate must pass.

This does not mean arbitrary new contracts are automatically production-ready. Use the examples as patterns, then run your own constraints review, entry ABI review, builder evidence, and chain acceptance evidence.

## Production Checklist

Before treating an example-derived contract as deployable, run the compiler-side checks:

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
python3 scripts/validate_ckb_cellscript_production_evidence.py target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

Do not use compile-only or bounded diagnostic runs as production release evidence.
