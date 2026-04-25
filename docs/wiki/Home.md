CellScript is a domain-specific language for Cell-based smart contracts on Spora and CKB. It compiles `.cell` source into ckb-vm compatible RISC-V assembly or ELF artifacts and emits metadata for schema auditing, target-profile policy checks, artifact verification, and Spora scheduler-aware execution.

This wiki is a practical tutorial set. It focuses on writing contracts, compiling them, checking portability, and preparing artifacts for Spora or CKB deployment.

## Tutorial Path

1. [Getting Started](Tutorial-01-Getting-Started)
2. [Language Basics](Tutorial-02-Language-Basics)
3. [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects)
4. [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow)
5. [Spora and CKB Target Profiles](Tutorial-05-Spora-and-CKB-Target-Profiles)
6. [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates)
7. [LSP and Tooling](Tutorial-07-LSP-and-Tooling)
8. [Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts)

## Current Scope

CellScript 0.12 supports:

- `.cell` modules with typed declarations and executable `action` / `lock` entries.
- Cell-native persistent values through `resource`, `shared`, and `receipt`.
- Explicit Cell effects: `consume`, `create`, `read_ref`, `transfer`, `destroy`, `claim`, and `settle`.
- RISC-V assembly and ELF output for ckb-vm compatible execution.
- `spora`, `ckb`, and `portable-cell` target profiles.
- Metadata sidecars and artifact verification.
- Local package workflows based on `Cell.toml`, local source roots, path dependencies, lockfile checks, build/check/doc/fmt, and production policy flags. Remote registry workflows remain experimental/fail-closed.
- LSP and VS Code tooling for diagnostics, hover, completion, definitions, references, rename, formatting, signature help, folding, document symbols, and compiler-backed reports.
- Production-facing constraints and evidence surfaces for runtime error codes, entry witness ABI, CKB capacity/tx-size requirements, CKB `hash_type`/DepGroup policy, and Spora scheduler metadata.

## Production Boundary

`cellc verify-artifact` proves that an artifact matches its metadata sidecar and selected policy flags. It is not the whole production gate by itself.

Release-facing production evidence also comes from the Spora and CKB acceptance scripts in the parent Spora repository:

- `scripts/spora_cellscript_acceptance.sh --profile production`
- `scripts/ckb_cellscript_acceptance.sh --production`
- `scripts/validate_spora_production_evidence.py`
- `scripts/validate_ckb_cellscript_production_evidence.py`

The current bundled example suite is seven contracts: `amm_pool.cell`, `launch.cell`, `multisig.cell`, `nft.cell`, `timelock.cell`, `token.cell`, and `vesting.cell`.

## Recommended First Run

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile spora -o /tmp/token.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile spora
```

Use the CKB profile for CKB artifacts:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.ckb.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.ckb.elf --expect-target-profile ckb
```

The bundled examples are covered by the current local production evidence suite. New external contracts still need their own metadata review, builder evidence, and chain acceptance evidence before they should be called production-ready.
