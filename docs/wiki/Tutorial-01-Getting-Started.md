This chapter gets you from a fresh checkout to one compiled CellScript artifact.
Do not worry about learning the whole language yet. The goal is smaller: build
the compiler, compile one example, and see how the executable artifact and its
metadata sidecar belong together.

By the end, you should be able to answer three questions:

- did the compiler run;
- where did the artifact go;
- how do I check that the artifact matches the metadata I expected?

## Prerequisites

You need a Rust toolchain with Cargo support for the repository MSRV. You do not
need an external RISC-V toolchain for the built-in assembler path used here.

Start by cloning the repository and running the test suite:

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
```

If this fails, fix the local Rust or repository setup before continuing. It is
much easier to understand compiler errors after the checkout itself is known to
be healthy.

## Build the Compiler

Build the `cellc` binary:

```bash
cargo build --locked --bin cellc
```

You can invoke it through Cargo:

```bash
cargo run --locked --bin cellc -- --help
```

Or call the built binary directly:

```bash
./target/debug/cellc --help
```

Both forms are useful. `cargo run` is convenient while developing the compiler.
The direct binary is closer to how users call `cellc` after installation.

## Compile One Source File

Start with `examples/token.cell`. It is small, but it already shows the main
language ideas: a resource, actions, explicit Cell movement, and CKB-compatible
output.

Compile it to RISC-V assembly:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-asm --target-profile ckb -o /tmp/token.s
```

Then compile the same source to ELF:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.elf
```

After the ELF build, look for the metadata sidecar:

```text
/tmp/token.elf
/tmp/token.elf.meta.json
```

Treat the `.meta.json` file as part of the build result. The ELF is what runs.
The metadata explains the source identity, target profile, schema, runtime
requirements, and verification obligations that belong to that ELF.

## Verify the Artifact

Now ask a narrow but important question: does this artifact match its metadata
sidecar and the CKB profile you expected?

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile ckb
```

When you want the metadata source hashes checked against files on disk, add
source verification:

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --verify-sources --expect-target-profile ckb
```

This is still compiler-side evidence. It is not a CKB transaction test. Later
chapters explain the difference, but this check is the right first habit.

## Use the CKB Profile Consistently

For CKB artifacts, keep the profile explicit:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.ckb.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.ckb.elf --expect-target-profile ckb
```

If a source depends on an unsupported CKB runtime shape, the CKB profile should
reject it instead of silently producing an artifact with unclear assumptions.
That fail-closed behavior is intentional.

## Next

Once you can compile and verify one file, continue with
[Language Basics](Tutorial-02-Language-Basics.md). The next chapter explains
what you are looking at inside a `.cell` file.
