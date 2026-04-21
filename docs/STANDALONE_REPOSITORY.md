# Standalone Repository

CellScript is maintained as a standalone Rust crate and CLI package. The
canonical standalone repository is:

```text
https://github.com/tsukifune-kosei/CellScript
```

The standalone repository root is this `cellscript/` package directory from the
Spora workspace. It contains the compiler library, the `cellc` binary, bundled
examples, integration tests, and editor assets.

## Compatibility Contract

CellScript must continue to support both target profiles:

- `spora`: Spora-native CellScript artifacts, Spora hashing, Spora scheduler
  witness metadata, and Spora `SPORABI` ELF trailer behavior.
- `ckb`: CKB-profile artifacts for the admitted v1 subset, CKB syscall/source
  constants, CKB Molecule/BLAKE2b conventions, and no Spora `SPORABI` trailer.

The CKB profile remains bounded by target-profile policy. Stateful examples that
are not yet admitted to the CKB v1 subset must fail closed for policy reasons,
while smoke artifacts and pure baseline artifacts must still compile and verify.

## Local Validation

From the standalone repository root:

```bash
CARGO_TARGET_DIR=/tmp/cellscript-standalone-target cargo test --locked --manifest-path Cargo.toml -- --test-threads=1
```

Using an explicit `CARGO_TARGET_DIR` keeps standalone validation separate from a
parent workspace target directory.
