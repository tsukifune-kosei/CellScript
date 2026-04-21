# Tutorial 01: Getting Started

This page gets you from a fresh checkout to a compiled CellScript artifact.

## Prerequisites

- Rust toolchain with Cargo support for the repository MSRV.
- CellScript source checkout.
- No external RISC-V toolchain is required for the built-in assembler path.

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
```

## Build the Compiler

```bash
cargo build --locked --bin cellc
```

You can then invoke the compiler through Cargo:

```bash
cargo run --locked --bin cellc -- --help
```

Or through the built binary:

```bash
./target/debug/cellc --help
```

## Compile a Single File

Compile the bundled token example to RISC-V assembly:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-asm --target-profile spora -o /tmp/token.s
```

Compile the same source to ELF:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile spora -o /tmp/token.elf
```

Compilation writes a metadata sidecar next to the artifact:

```text
/tmp/token.elf
/tmp/token.elf.meta.json
```

## Verify the Artifact

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile spora
```

Use source verification when you want the metadata sidecar to be checked against files on disk:

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --verify-sources --expect-target-profile spora
```

## CKB Quick Check

The CKB profile emits raw ELF bytes without the Spora ABI trailer and uses CKB syscall/profile rules.

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.ckb.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.ckb.elf --expect-target-profile ckb
```

If a source uses a Spora-only feature or an unsupported CKB stateful shape, the CKB profile should fail closed with a target-profile policy error.

## Next

Continue with [Language Basics](Tutorial-02-Language-Basics).

