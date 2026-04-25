CellScript is a small language for Cell-based smart contracts on Spora and CKB. You describe the Cell state you want to protect, the actions that may change it, and the lock rules that authorize it. The compiler turns that `.cell` source into ckb-vm compatible RISC-V assembly or ELF artifacts and writes metadata that explains what was built.

This wiki is meant to be read as a guided path. Each chapter introduces one idea, shows the smallest useful commands, and then points to the production checks that matter before deployment.

## How to Read This Wiki

If you are new to CellScript, read the tutorials in order. The early chapters focus on the language itself: modules, resources, actions, locks, and Cell effects. The later chapters focus on packaging, target profiles, metadata, release evidence, editor tooling, and the bundled examples.

If you already have a contract, jump to the page that matches your current question:

- writing source: start with language basics and Cell effects;
- building a package: use the package workflow chapter;
- targeting Spora or CKB: read the target-profile chapter before compiling;
- preparing a release: use the metadata and production gates chapter;
- learning by example: read the bundled examples last, after the core language model is clear.

## Tutorial Path

1. [Getting Started](Tutorial-01-Getting-Started): build the compiler, compile one example, and verify the artifact.
2. [Language Basics](Tutorial-02-Language-Basics): learn the shape of a `.cell` file.
3. [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects): understand how values move through a Cell transaction.
4. [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow): create a package, build it, check it, and inspect reports.
5. [Spora and CKB Target Profiles](Tutorial-05-Spora-and-CKB-Target-Profiles): choose the right runtime assumptions.
6. [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates): know what artifact verification proves and what it does not prove.
7. [LSP and Tooling](Tutorial-07-LSP-and-Tooling): use editor feedback and command-backed reports.
8. [Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts): study the examples in a useful order.

## What 0.12 Gives You

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

CellScript 0.12 is also the first release aimed at an initial stable foundation. That does not mean every future language feature is frozen. It means the current compiler, profiles, examples, metadata, LSP, and package workflow are being documented and tested as a coherent base.

## Before You Call It Production

`cellc verify-artifact` proves that an artifact matches its metadata sidecar and selected policy flags. It is not the whole production gate by itself.

For a real release, keep two levels of evidence separate:

- compiler evidence: the source, artifact, metadata, and policy flags agree;
- chain evidence: the artifact has been built into transactions, dry-run or deployed, measured, and checked by the Spora or CKB acceptance reports.

Release-facing production evidence comes from the Spora and CKB acceptance scripts in the parent Spora repository:

- `scripts/spora_cellscript_acceptance.sh --profile production`
- `scripts/ckb_cellscript_acceptance.sh --production`
- `scripts/validate_spora_production_evidence.py`
- `scripts/validate_ckb_cellscript_production_evidence.py`

The current bundled example suite is seven contracts: `amm_pool.cell`, `launch.cell`, `multisig.cell`, `nft.cell`, `timelock.cell`, `token.cell`, and `vesting.cell`.

## First Run

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
