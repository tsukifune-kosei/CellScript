# Tutorial 04: Packages and CLI Workflow

CellScript includes a beta package manager. It is stable enough for local package workflows, local path dependencies, build/check/doc/fmt flows, and lockfile validation. Registry publishing and remote package workflows should still be treated as experimental.

## Create a Package

```bash
cellc init my_contract
cd my_contract
```

This creates a `Cell.toml` manifest and a source entry.

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

`build` writes the artifact and metadata sidecar under the configured output directory.

## Check Without Writing Artifacts

```bash
cellc check
cellc check --all-targets
cellc check --target-profile portable-cell
cellc check --production
cellc check --deny-runtime-obligations
cellc check --json
```

Use `check --all-targets` to verify both assembly and ELF-compatible paths without producing files.

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

The CLI contains command entries for future package workflows such as publish, update, login, install, run, and repl. Treat these as experimental unless the command reports a completed workflow in your current build.

## Next

Continue with [Spora and CKB Target Profiles](Tutorial-05-Spora-and-CKB-Target-Profiles).

