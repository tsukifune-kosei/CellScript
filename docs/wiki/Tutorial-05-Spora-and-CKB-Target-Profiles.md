A target profile answers a simple question: which chain runtime are you preparing this source for?

CellScript supports both Spora and CKB, but those environments do not have the same runtime assumptions. The selected target profile controls syscalls, source constants, header/runtime rules, artifact packaging, metadata policy, and verification boundaries.

## What You Will Learn

- when to choose `spora`, `ckb`, or `portable-cell`;
- why a source can be valid for one profile and rejected by another;
- how to run a small profile matrix;
- which CKB-specific details need review before deployment.

## Profiles

| Profile | Purpose |
|---|---|
| `spora` | Spora-native CellTx artifacts and scheduler-aware metadata. |
| `ckb` | CKB-compatible artifacts for the admitted subset. |
| `portable-cell` | Source-level portability checking before choosing a concrete artifact target. |

## Spora Profile

Use this for Spora-native deployment. This is the right choice when the contract is meant to use Spora CellTx conventions, scheduler metadata, or Spora helper features:

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

Use this for CKB artifacts. This is the right choice when the output must follow CKB syscall, ELF, witness, Molecule, capacity, and builder expectations:

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

Use the portable profile before choosing a final artifact target when you want the source to stay inside a shared Cell subset:

```bash
cellc check --target-profile portable-cell
```

This is a source policy check. It is not a deployment target by itself. Build the final artifact with `spora` or `ckb`.

## Typical Matrix

For source that is meant to remain cross-profile, run the checks in this order:

```bash
cellc check --target-profile portable-cell --json
cellc build --target riscv64-elf --target-profile spora --json
cellc build --target riscv64-elf --target-profile ckb --json
```

If the same source cannot build for CKB, inspect the policy violation. A failure is correct when the source depends on Spora-only behavior.

## Practical CKB Rules

CKB work is usually easiest when the schema and transaction entry points are explicit from the beginning. For better CKB portability:

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

After choosing a profile, continue with [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates).
