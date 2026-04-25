CellScript must support both Spora and CKB without mixing their runtime assumptions. The selected target profile controls syscalls, source constants, header/runtime rules, artifact packaging, metadata policy, and verification boundaries.

## Profiles

| Profile | Purpose |
|---|---|
| `spora` | Spora-native CellTx artifacts and scheduler-aware metadata. |
| `ckb` | CKB-compatible artifacts for the admitted subset. |
| `portable-cell` | Source-level portability checking before choosing a concrete artifact target. |

## Spora Profile

Use this for Spora-native deployment:

```bash
cellc build --target riscv64-elf --target-profile spora
```

The Spora profile may use:

- Spora CellTx conventions;
- Spora-specific helper syscalls;
- Spora scheduler witness metadata;
- Spora DAG/header/runtime features;
- Spora ABI trailer for ELF artifacts.

## CKB Profile

Use this for CKB artifacts:

```bash
cellc build --target riscv64-elf --target-profile ckb
```

The CKB profile enforces:

- CKB syscall numbers;
- CKB source constants;
- CKB header ABI restrictions;
- no Spora-only helper syscalls;
- raw ELF packaging without the Spora ABI trailer;
- Molecule-facing schema and entry witness metadata;
- CKB Blake2b release/deployment hash helper support;
- manifest-level `hash_type`, CellDep, and DepGroup reporting;
- capacity, tx-size, and builder-evidence requirements in constraints;
- CKB policy checks for unsupported runtime/stateful shapes.

Verify the result:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

## Portable Profile

Use the portable profile to keep source inside a shared Cell subset:

```bash
cellc check --target-profile portable-cell
```

This is a source policy check. It is not a deployment target by itself. Build the final artifact with `spora` or `ckb`.

## Typical Matrix

```bash
cellc check --target-profile portable-cell --json
cellc build --target riscv64-elf --target-profile spora --json
cellc build --target riscv64-elf --target-profile ckb --json
```

If the same source cannot build for CKB, inspect the policy violation. A failure is correct when the source depends on Spora-only behavior.

## Practical CKB Rules

For better CKB portability:

- prefer fixed-size persistent schema fields;
- keep action entry parameters explicit;
- use `env::current_timepoint()` instead of Spora DAA APIs when source must cross profiles;
- record CKB `hash_type`, CellDeps, and DepGroups in `Cell.toml`;
- inspect `cellc constraints --target-profile ckb --json` before deployment;
- inspect witness layout with `cellc abi` or `cellc entry-witness`;
- avoid Spora scheduler witness ABI;
- avoid DAA score APIs in CKB-targeted code;
- avoid Spora-only signature/hash helper syscalls;
- use metadata and `verify-artifact` to confirm target profile and packaging.

For release-facing CKB evidence, also run the parent Spora repository's CKB acceptance/final-hardening gate. Compiler metadata is necessary, but it is not a substitute for builder-backed transaction evidence, dry-run cycles, serialized tx-size evidence, and occupied-capacity checks.

## Next

Continue with [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates).
