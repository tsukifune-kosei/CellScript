Small experiments can be compiled as single `.cell` files. Once a contract has
more than one source file, a dependency, or a release target, use a package.

A package gives the compiler a stable place to find the entry file, build
settings, dependencies, and lockfile. That makes builds repeatable for you, and
reviewable for someone else.

## What You Will Learn

- how to create a package;
- what belongs in `Cell.toml`;
- how to build, check, format, and document a package;
- which reports are useful during review;
- where the current package workflow intentionally stops.

## Create a Package

Create an application-style package:

```bash
cellc init my_contract
cd my_contract
```

This creates a `Cell.toml` manifest and a source entry. Use this form when you
want a contract package with a concrete entry.

Create a library-style package:

```bash
cellc init my_lib --lib
```

Ask for a machine-readable summary when scripting:

```bash
cellc init my_contract --json
```

## Read The Manifest

A minimal manifest looks like this:

```toml
[package]
name = "my_contract"
version = "0.1.0"
edition = "2021"
entry = "src/main.cell"

[build]
target = "riscv64-elf"
target_profile = "ckb"
out_dir = "build"

[dependencies]
my_lib = { path = "../my_lib" }
```

Read the manifest as a build promise:

- `entry` tells the compiler where the package starts;
- `target` chooses assembly or ELF-style output;
- `target_profile` chooses the runtime assumptions;
- `out_dir` chooses where artifacts are written;
- path dependencies keep local packages explicit.

Registry publishing and registry dependency resolution are intentionally
experimental/fail-closed until a trusted registry path is ready. Local path
dependencies are the supported workflow for repeatable local development.

## Build

Run the package build:

```bash
cellc build
```

Useful flags:

```bash
cellc build --target riscv64-asm
cellc build --target riscv64-elf
cellc build --target-profile ckb
cellc build --production
cellc build --json
```

`build` reads `Cell.toml`, compiles the current package entry, and writes the
artifact plus metadata sidecar under the configured output directory.

For a one-off source file, use the top-level compiler form instead:

```bash
cellc path/to/file.cell
```

That form is great for quick experiments. Packages are better when you need
repeatability.

## Check Without Writing Artifacts

Use `check` when you want fast feedback:

```bash
cellc check
cellc check --all-targets
cellc check --target-profile ckb
cellc check --production
cellc check --deny-runtime-obligations
cellc check --json
```

`check --all-targets` is useful before committing. It catches source and profile
problems without producing build artifacts.

## Format And Generate Docs

Format the package:

```bash
cellc fmt
cellc fmt --check
cellc fmt --json
```

Generate package docs:

```bash
cellc doc
cellc doc --json
```

Generated docs summarize modules, actions, resources, receipts, locks,
lifecycle rules, and lowering metadata.

## Audit And Evidence Reports

When a package is ready for review, ask the compiler for the facts it already
knows:

```bash
cellc metadata . --target riscv64-elf --target-profile ckb -o build/main.metadata.json
cellc constraints . --target riscv64-elf --target-profile ckb -o build/main.constraints.json
cellc abi . --target-profile ckb
cellc scheduler-plan . --target-profile ckb --json
cellc opt-report . --target riscv64-elf --target-profile ckb --json
```

For CKB-specific builder and deployment review:

```bash
cellc constraints . --target riscv64-elf --target-profile ckb --json
cellc abi . --target-profile ckb --action transfer
cellc entry-witness . --target-profile ckb --action transfer --json
cellc ckb-hash --file build/main.elf
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

These reports are not busywork. They answer questions reviewers will ask:

- what is the entry ABI;
- what witness layout is expected;
- what capacity or runtime obligations remain;
- what CKB hash policy is being used;
- whether the artifact still matches the source and metadata.

They do not replace chain acceptance reports, builder-generated transactions,
occupied-capacity evidence, or CKB production gates.

## Local Dependencies

Add a local dependency:

```bash
cellc add my_lib --path ../my_lib
```

`add --path` records the dependency in `Cell.toml`. To resolve the dependency
graph and write `Cell.lock`, run:

```bash
cellc install
```

You can also add and lock a local dependency in one command:

```bash
cellc install my_lib --path ../my_lib
```

Remove it:

```bash
cellc remove my_lib
```

`install`, `update`, and normal dependency removal refresh the lockfile so
direct and transitive local path dependencies stay consistent.

## Package Information

```bash
cellc info
cellc info --json
```

Use `info` when you want a quick view of the package boundary before building or
debugging dependency resolution.

## Experimental Commands

Registry publishing, registry package installation, `login`, `run`, and `repl`
remain experimental/future-facing. Local `install --path` and `update` are
supported as lockfile helpers for local path dependency workflows.

## Next

With a repeatable package workflow in place, continue with
[CKB Target Profiles](Tutorial-05-CKB-Target-Profiles.md).
