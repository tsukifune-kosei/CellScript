This chapter takes you from a fresh checkout to one compiled CellScript artifact. The goal is not to learn the whole language yet. The goal is to see the compiler, artifact, and metadata sidecar working together.

## What You Will Do

- clone the repository and run the test suite;
- build the `cellc` compiler;
- compile the bundled token example to assembly and ELF;
- verify that the ELF matches its metadata;
- repeat the same check with the CKB target profile.

## Prerequisites

- Rust toolchain with Cargo support for the repository MSRV.
- CellScript source checkout.
- No external RISC-V toolchain is required for the built-in assembler path.

```bash
git clone https://github.com/tsukifune-kosei/CellScript.git
cd CellScript
cargo test --locked
```

If this fails, fix the local Rust or repository setup before continuing. A broken checkout makes later compiler errors much harder to read.

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

Start with `examples/token.cell`. It is small enough to read in one sitting, but it uses the basic ideas you will see throughout the rest of the wiki.

Compile the token example to RISC-V assembly:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-asm --target-profile ckb -o /tmp/token.s
```

Compile the same source to ELF:

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.elf
```

Compilation writes a metadata sidecar next to the artifact:

```text
/tmp/token.elf
/tmp/token.elf.meta.json
```

Treat the `.meta.json` file as part of the build output. The ELF is what runs; the metadata explains the source identity, target profile, schema, runtime requirements, and verification obligations that belong to that ELF.

## Verify the Artifact

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile ckb
```

This command answers a narrow but important question: does this artifact match its sidecar and the target profile you expected? It is the first gate before you start thinking about transaction builders or chain acceptance.

Use source verification when you want the metadata sidecar to be checked against files on disk:

```bash
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --verify-sources --expect-target-profile ckb
```

## CKB Quick Check

When targeting CKB, compile the same source again with the CKB profile. The CKB profile emits raw ELF bytes without the ABI trailer and uses CKB syscall/profile rules.

```bash
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb -o /tmp/token.ckb.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.ckb.elf --expect-target-profile ckb
```

If a source uses an unsupported feature or an unsupported CKB stateful shape, the CKB profile should fail closed with a target-profile policy error.

## Next

Once you can compile and verify one file, continue with [Language Basics](Tutorial-02-Language-Basics.md).
