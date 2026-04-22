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

CellScript v1 supports:

- `.cell` modules with typed declarations and executable `action` / `lock` entries.
- Cell-native persistent values through `resource`, `shared`, and `receipt`.
- Explicit Cell effects: `consume`, `create`, `read_ref`, `transfer`, `destroy`, `claim`, and `settle`.
- RISC-V assembly and ELF output for ckb-vm compatible execution.
- `spora`, `ckb`, and `portable-cell` target profiles.
- Metadata sidecars and artifact verification.
- A beta package manager based on `Cell.toml`, local source roots, and local path dependencies.
- LSP support for editor diagnostics, hover, completion, references, rename, formatting, and lowering metadata.

## Recommended First Run

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile spora -o /tmp/token.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile spora
```

Use the CKB profile for admitted portable/pure contracts:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.ckb.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.ckb.elf --expect-target-profile ckb
```

Some complex examples intentionally exercise Spora-only or runtime-required shapes. The compiler should reject unsupported CKB shapes by policy instead of silently producing an unsafe artifact.

