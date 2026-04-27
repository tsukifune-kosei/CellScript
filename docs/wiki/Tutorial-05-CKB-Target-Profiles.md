A target profile answers a practical question: which runtime are you preparing
this source for?

For CKB work, the answer should be explicit. The CKB profile controls syscall
choices, source constants, header/runtime rules, artifact packaging, metadata
policy, and verification boundaries.

## What You Will Learn

- how to use the `ckb` profile consistently;
- why unsupported CKB assumptions fail closed;
- which commands check assembly and ELF-compatible paths;
- which CKB details deserve review before deployment.

## Why The Profile Matters

Without a target profile, it is too easy to talk about a contract in abstract
terms. CKB is not abstract. It has Cells, script groups, witness data, Molecule
layouts, capacity, CellDeps, DepGroups, hash types, and ckb-vm execution.

The CKB profile keeps those assumptions visible:

```bash
cellc build --target riscv64-elf --target-profile ckb
```

Use this profile when the artifact is intended for CKB or for CKB-like local
acceptance testing.

## What The CKB Profile Enforces

The profile checks and records:

- CKB syscall numbers;
- CKB source constants;
- CKB header ABI restrictions;
- raw ELF packaging without ABI trailer;
- Molecule-facing schema and entry witness metadata;
- CKB Blake2b release/deployment hash helper support;
- manifest-level `hash_type`, CellDep, and DepGroup reporting;
- capacity, tx-size, and builder-evidence requirements in constraints;
- CKB policy checks for unsupported runtime or stateful shapes.

The point is not to make compilation harder. The point is to avoid producing an
artifact whose CKB assumptions are vague.

Verify the result:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

## Typical Checks

For quick feedback:

```bash
cellc check --target-profile ckb --json
```

For a broader local check:

```bash
cellc check --all-targets --target-profile ckb --json
```

For a concrete artifact:

```bash
cellc build --target riscv64-elf --target-profile ckb --json
```

If the source cannot build for CKB, inspect the policy violation. A failure is
often the right result when the source depends on unsupported runtime behavior.
Failing closed is better than pretending an unsupported assumption is safe.

## Practical CKB Habits

CKB work is easier when the schema and transaction entry points are explicit
from the beginning:

- prefer fixed-size persistent schema fields;
- keep action entry parameters explicit;
- use `env::current_timepoint()` for time-aware checks;
- record CKB `hash_type`, CellDeps, and DepGroups in `Cell.toml`;
- inspect `cellc constraints --target-profile ckb --json` before deployment;
- inspect witness layout with `cellc abi` or `cellc entry-witness`;
- avoid scheduler witness ABI unless you are deliberately using that surface;
- avoid unsupported signature/hash helper syscalls;
- use metadata and `verify-artifact` to confirm target profile and packaging.

The lock-boundary keywords from the previous chapter also matter here.
`protected` tells readers which input Cell is guarded. `witness` tells readers
which values come from witness data. Neither one silently verifies a signature.

## Evidence Beyond Compilation

Compiler metadata is necessary, but it is not a substitute for builder-backed
transaction evidence. For release-facing CKB evidence, also run the repository's
CKB acceptance gate. That gate checks concrete transactions, dry-run cycles,
serialized transaction size, occupied capacity, and positive/negative behavior
where the bundled suite provides it.

You can think of the layers like this:

- target profile: "can this source be lowered under CKB rules";
- artifact verification: "does this artifact match its metadata";
- CKB acceptance: "can builder-generated transactions use the artifact as
  claimed."

## Next

After choosing a profile, continue with
[Metadata, Verification, and Production Gates](https://github.com/tsukifune-kosei/CellScript/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates).
