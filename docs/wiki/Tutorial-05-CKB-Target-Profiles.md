A target profile answers a simple question: which chain runtime are you preparing this source for?

CellScript now supports CKB as its only target profile. The CKB profile controls syscalls, source constants, header/runtime rules, artifact packaging, metadata policy, and verification boundaries.

## What You Will Learn

- how to use the `ckb` profile consistently;
- why unsupported CKB runtime assumptions fail closed;
- how to check both assembly and ELF-compatible output paths;
- which CKB-specific details need review before deployment.

## CKB Profile

Use this for CKB artifacts. This is the right choice when the output must follow CKB syscall, ELF, witness, Molecule, capacity, and builder expectations:

```bash
cellc build --target riscv64-elf --target-profile ckb
```

The CKB profile enforces:

- CKB syscall numbers;
- CKB source constants;
- CKB header ABI restrictions;
- raw ELF packaging without ABI trailer;
- Molecule-facing schema and entry witness metadata;
- CKB Blake2b release/deployment hash helper support;
- manifest-level `hash_type`, CellDep, and DepGroup reporting;
- capacity, tx-size, and builder-evidence requirements in constraints;
- CKB policy checks for unsupported runtime/stateful shapes.

Verify the result:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

## Typical Checks

```bash
cellc check --target-profile ckb --json
cellc check --all-targets --target-profile ckb --json
cellc build --target riscv64-elf --target-profile ckb --json
```

If the source cannot build for CKB, inspect the policy violation. A failure is correct when the source depends on unsupported CKB behavior.

## Practical CKB Rules

CKB work is usually easiest when the schema and transaction entry points are explicit from the beginning:

- prefer fixed-size persistent schema fields;
- keep action entry parameters explicit;
- use `env::current_timepoint()` for time-aware checks;
- record CKB `hash_type`, CellDeps, and DepGroups in `Cell.toml`;
- inspect `cellc constraints --target-profile ckb --json` before deployment;
- inspect witness layout with `cellc abi` or `cellc entry-witness`;
- avoid scheduler witness ABI;
- avoid unsupported signature/hash helper syscalls;
- use metadata and `verify-artifact` to confirm target profile and packaging.

For release-facing CKB evidence, also run the CellScript repository's CKB acceptance/final-hardening gate. Compiler metadata is necessary, but it is not a substitute for builder-backed transaction evidence, dry-run cycles, serialized tx-size evidence, and occupied-capacity checks.

## Next

After choosing a profile, continue with [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates.md).
