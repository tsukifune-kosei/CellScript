# Tutorial 06: Metadata, Verification, and Production Gates

Every artifact should be treated as a pair:

```text
artifact
artifact.meta.json
```

The artifact is executable RISC-V assembly or ELF. The metadata sidecar records source identity, target profile, artifact hash, schema layout, runtime requirements, scheduler information, and verifier obligations.

## Emit Metadata

Compile normally:

```bash
cellc build --json
```

Or request metadata directly:

```bash
cellc metadata src/main.cell --target riscv64-elf --target-profile spora -o /tmp/main.meta.json
```

## Verify an Artifact

```bash
cellc verify-artifact build/main.elf
```

Pin the target profile:

```bash
cellc verify-artifact build/main.elf --expect-target-profile spora
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

Verify source units on disk:

```bash
cellc verify-artifact build/main.elf --verify-sources
```

Use production checks:

```bash
cellc verify-artifact build/main.elf --production
cellc verify-artifact build/main.elf --deny-fail-closed
cellc verify-artifact build/main.elf --deny-runtime-obligations
```

## Check Before Build

Use check mode for CI:

```bash
cellc check --all-targets --production
cellc check --target-profile portable-cell --json
cellc check --target-profile ckb --json
```

Important policy flags:

| Flag | Purpose |
|---|---|
| `--production` | Reject unsafe or incomplete lowering paths. |
| `--deny-fail-closed` | Reject metadata that contains fail-closed runtime features or obligations. |
| `--deny-symbolic-runtime` | Reject symbolic Cell/runtime features. |
| `--deny-ckb-runtime` | Reject CKB runtime features when they are not allowed for the workflow. |
| `--deny-runtime-obligations` | Reject runtime-required verifier obligations. |

## What to Inspect in Metadata

Useful fields include:

- `target_profile`
- `artifact_format`
- `artifact_hash_blake3`
- `artifact_size_bytes`
- `source_hash_blake3`
- `source_content_hash_blake3`
- `source_units`
- `metadata_schema_version`
- `actions`
- `locks`
- `schema`
- `runtime`
- `verifier_obligations`
- scheduler witness metadata for Spora profile builds

## Suggested CI Gate

For a package that must remain portable:

```bash
cellc fmt --check
cellc check --target-profile portable-cell --all-targets --production
cellc build --target riscv64-elf --target-profile spora --production
cellc verify-artifact build/main.elf --expect-target-profile spora --verify-sources --production
```

For CKB:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

## Next

Continue with [LSP and Tooling](Tutorial-07-LSP-and-Tooling).

