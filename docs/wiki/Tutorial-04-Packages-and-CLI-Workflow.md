Small experiments can be compiled as single `.cell` files. Once a contract has more than one source file, dependency, or release target, use a package.

CellScript packages are described by `Cell.toml`. The 0.12 workflow is production-style for local source roots, path dependencies, build/check/doc/fmt flows, lockfile validation, and release policy checks. Registry publishing and remote package workflows are intentionally experimental/fail-closed until a trusted registry path is ready.

## What You Will Learn

- how to create a package;
- what belongs in `Cell.toml`;
- how to build, check, format, and document a package;
- which reports help during audit and release preparation;
- where the current package workflow intentionally stops.

## Create a Package

```bash
cellc init my_contract
cd my_contract
```

This creates a `Cell.toml` manifest and a source entry. Use this when you want repeatable builds instead of one-off compiler commands.

Library package:

```bash
cellc init my_lib --lib
```

Machine-readable init summary:

```bash
cellc init my_contract --json
```

## Example Manifest

```toml
[package]
name = "my_contract"
version = "0.1.0"
edition = "2021"
entry = "src/main.cell"

[build]
target = "riscv64-elf"
target_profile = "spora"
out_dir = "build"

[dependencies]
my_lib = { path = "../my_lib" }
```

The package manager currently supports local path dependencies for production-style workflows. Registry dependencies are fail-closed until the registry path is ready.

## Build

```bash
cellc build
```

Useful flags:

```bash
cellc build --target riscv64-asm
cellc build --target riscv64-elf
cellc build --target-profile spora
cellc build --target-profile ckb
cellc build --production
cellc build --json
```

`build` reads `Cell.toml`, compiles the package entry, and writes the artifact plus metadata sidecar under the configured output directory.

## Check Without Writing Artifacts

```bash
cellc check
cellc check --all-targets
cellc check --target-profile portable-cell
cellc check --production
cellc check --deny-runtime-obligations
cellc check --json
```

Use `check --all-targets` when you want fast feedback across assembly and ELF-compatible paths without producing files.

## Format

```bash
cellc fmt
cellc fmt --check
cellc fmt --json
```

## Documentation

```bash
cellc doc
cellc doc --json
```

Generated docs summarize modules, actions, resources, receipts, locks, lifecycle rules, and lowering metadata.

## Audit and Evidence Reports

When a package is ready for review, ask the compiler for the facts it already knows. These commands are useful when reviewing a package boundary or preparing release evidence:

```bash
cellc metadata . --target riscv64-elf --target-profile spora -o build/main.metadata.json
cellc constraints . --target riscv64-elf --target-profile spora -o build/main.constraints.json
cellc abi . --target-profile spora
cellc scheduler-plan . --target-profile spora --json
cellc opt-report . --target riscv64-elf --target-profile spora --json
```

For CKB-specific builder and deployment review:

```bash
cellc constraints . --target riscv64-elf --target-profile ckb --json
cellc abi . --target-profile ckb --action transfer
cellc entry-witness . --target-profile ckb --action transfer --json
cellc ckb-hash --file build/main.elf
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

`metadata` and `constraints` expose the compiler-side production contract. They do not replace chain acceptance reports, builder-generated transactions, occupied-capacity evidence, or Spora/CKB production gates.

## Local Dependencies

Add a local dependency:

```bash
cellc add my_lib --path ../my_lib
```

Remove it:

```bash
cellc remove my_lib
```

The lockfile is updated so stale path dependencies can be detected.

## Package Information

```bash
cellc info
cellc info --json
```

## Experimental Commands

The CLI contains command entries for future package workflows such as publish, update, login, install, run, and repl. Treat these as future-facing commands until they report a completed, supported path in your current build.

## Next

With a repeatable package workflow in place, continue with [Spora and CKB Target Profiles](Tutorial-05-Spora-and-CKB-Target-Profiles).
