Every CellScript artifact should be treated as a pair:

```text
artifact
artifact.meta.json
```

The artifact is executable RISC-V assembly or ELF. The metadata sidecar is the
explanation: source identity, target profile, artifact hash, schema layout,
runtime requirements, scheduler information, and verifier obligations.

This chapter is about trust boundaries. It teaches you what compiler evidence
can prove, and where you still need CKB transaction evidence.

## The Main Rule

Compiler verification is necessary, but it is not the same thing as a deployed
transaction or chain acceptance report.

If `verify-artifact` passes, you know the artifact and metadata agree. You do
not yet know that a transaction builder can provide the right inputs, serialize
the right witness, satisfy capacity, pass dry-run, and commit.

That distinction prevents overclaiming.

## Emit Metadata

Compile normally:

```bash
cellc build --json
```

Or request metadata directly:

```bash
cellc metadata src/main.cell --target riscv64-elf --target-profile ckb -o /tmp/main.meta.json
```

Open the metadata when something is unclear. It is often easier to understand a
compiler decision by reading the emitted facts than by guessing from the source
alone.

## Verify an Artifact

Start with the basic check:

```bash
cellc verify-artifact build/main.elf
```

Pin the target profile:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

Verify source units on disk:

```bash
cellc verify-artifact build/main.elf --verify-sources
```

Use production checks when preparing release evidence:

```bash
cellc verify-artifact build/main.elf --production
cellc verify-artifact build/main.elf --deny-fail-closed
cellc verify-artifact build/main.elf --deny-runtime-obligations
```

Read this gate narrowly: it verifies the artifact, metadata, source hash
expectations, and selected policy flags. It does not prove that a concrete CKB
transaction has been built, deployed, dry-run, indexed, or measured.

## Check Before Build

Use check mode for CI and local feedback:

```bash
cellc check --all-targets --production
cellc check --target-profile ckb --json
```

Important policy flags:

| Flag | Purpose |
|---|---|
| `--production` | Reject unsafe or incomplete lowering paths. |
| `--deny-fail-closed` | Reject metadata that contains fail-closed runtime features or obligations. |
| `--deny-ckb-runtime` | Reject CKB runtime features when they are not allowed for the workflow. |
| `--deny-runtime-obligations` | Reject runtime-required verifier obligations. |

These flags are useful because they turn "remember to inspect this later" into a
compiler-visible failure.

## What To Inspect First

You do not need to memorize the whole sidecar. Start with these fields:

- `target_profile`
- `artifact_format`
- `artifact_hash`
- `artifact_size_bytes`
- `source_hash`
- `source_content_hash`
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
- `scheduler`

When reviewing a contract, ask simple questions first:

- which action or lock is the entry;
- what witness does it expect;
- which Cells are consumed or created;
- which runtime obligations remain;
- which CKB profile assumptions are recorded.

## Suggested Compiler CI Gate

For CKB packages, a useful compiler CI gate is:

```bash
cellc fmt --check
cellc check --target-profile ckb --all-targets --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

For CKB, make the profile explicit in every step:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

These gates are suitable for a compiler/package CI loop. They are not enough for
a release claim that says a contract is production-ready on a chain.

## CKB Release Evidence Gate

When you are ready to make a CKB production claim, move from compiler evidence
to chain evidence. Run the CKB acceptance gate from the CellScript repository
root:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```

The CKB validator requires strict bundled-example coverage, scoped action and
lock compile coverage, builder-backed action runs, builder-backed lock
valid-spend and invalid-spend matrices, valid transaction dry-runs, committed
valid transactions, malformed rejection, measured cycles, consensus-serialized
transaction size, occupied-capacity evidence, no under-capacity outputs, bundled
example deployment, and a passed final production hardening gate.

The production gate compiles `examples/acceptance/*.cell` when present. Those
files intentionally retain scheduler and effect-profile metadata while
`examples/*.cell` and `examples/business/*.cell` remain the cleaner business
reading surface.

Lock behavior coverage is machine-readable through
`lock_acceptance_scope.onchain_lock_spend_matrix_scope`; each listed lock must
have both valid-spend and invalid-spend evidence.

`examples/registry.cell` is a bounded-collection language example covered by
compiler/tooling tests, not by the bundled CKB production matrix.

`--compile-only` and bounded diagnostic runs can help development, but they are
not external production release evidence.

## Next

Once the verification boundary is clear, continue with
[LSP and Tooling](Tutorial-07-LSP-and-Tooling.md).
