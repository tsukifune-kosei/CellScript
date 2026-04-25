Every CellScript artifact should be treated as a pair:

```text
artifact
artifact.meta.json
```

The artifact is executable RISC-V assembly or ELF. The metadata sidecar records source identity, target profile, artifact hash, schema layout, runtime requirements, scheduler information, and verifier obligations.

## What You Will Learn

- why the metadata sidecar is part of the artifact boundary;
- how to verify an artifact against its metadata;
- which compiler flags are useful for CI;
- how compiler evidence differs from chain release evidence.

The main rule is simple: compiler verification is necessary, but it is not the same thing as a deployed transaction or chain acceptance report.

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

Artifact verification is a compiler artifact gate. It verifies the artifact, metadata, source hash expectations, and selected policy flags. It does not prove that a concrete Spora or CKB transaction has been built, deployed, dry-run, indexed, or measured.

This distinction matters during release work. If a report says only "verify-artifact passed", you know the compiler output is internally consistent. You do not yet know that a chain transaction builder can spend the right inputs, serialize the right witness, fit capacity rules, pass dry-run, or commit successfully.

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

You do not need to memorize the whole sidecar on the first pass. Start with these fields:

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
- `constraints`
- `runtime_error_registry`
- `constraints.artifact`
- `constraints.entry_abi`
- `constraints.ckb.capacity_evidence_contract`
- `constraints.ckb.hash_type_policy`
- `constraints.ckb.dep_group_manifest`
- scheduler witness metadata for Spora profile builds

## Suggested Compiler CI Gate

For a package that must remain portable, a useful compiler CI gate is:

```bash
cellc fmt --check
cellc check --target-profile portable-cell --all-targets --production
cellc build --target riscv64-elf --target-profile spora --production
cellc verify-artifact build/main.elf --expect-target-profile spora --verify-sources --production
```

For CKB, make the profile explicit in every step:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

These gates are suitable for a compiler/package CI loop. They are not enough for a release claim that says a contract is production-ready on a chain.

## CKB Release Evidence Gate

When you are ready to make a CKB production claim, move from compiler evidence
to chain evidence. Run the CKB acceptance gate from the CellScript repository
root:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

The CKB validator requires strict original bundled-example coverage, scoped action and lock compile coverage, builder-backed action runs, valid transaction dry-runs, committed valid transactions, malformed rejection, measured cycles, consensus-serialized tx size, occupied-capacity evidence, no under-capacity outputs, all seven bundled examples deployed, and a passed final production hardening gate.

`--compile-only` and bounded diagnostic runs can help development, but they are not external production release evidence.

## Next

Once the verification boundary is clear, continue with [LSP and Tooling](Tutorial-07-LSP-and-Tooling).
