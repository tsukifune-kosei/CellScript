# Tutorial 05: CKB Target Profiles

A target profile answers a practical question: which runtime are you preparing
this source for?

For CKB work, the answer should be explicit. The CKB profiles control syscall
choices, source constants, header/runtime rules, artifact packaging, metadata
policy, verification boundaries, and whether deployment binds exact data bytes
or a Type-hash upgrade line.

Edition and target profile are related, but they are not duplicate settings.
`edition = "2026"` selects source-language semantics. The independently
versioned `ckb` or `ckb-type-hash` target profile selects CKB-facing runtime
and deployment rules. The resolved
compatibility profile combines both identities with primitive assurance,
metadata schemas, and wire ABIs. Changing the target cannot opt out of the
edition, and passing `--target-profile ckb` cannot repair a package with a
missing or non-2026 edition.

## What You Will Learn

- how to choose the exact-data `ckb` or upgrade-line `ckb-type-hash` profile;
- how Edition 2026 and the CKB profile combine;
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
acceptance testing and its Script will use `hash_type = data2`.

Use the separate profile when the artifact is deployed in a Type ID code Cell
and the consuming Script locates it by that Cell's Type Script hash:

```bash
cellc build --target riscv64-elf --target-profile ckb-type-hash
```

`ckb-type-hash` changes the admitted deployment hash type from `data2` to
`type` and gives the resulting metadata a different target-profile identity.
Each code version still needs exact checked artifact evidence, a stable Type ID
lineage, and an explicit compatibility and authorization policy.

## What The CKB Profiles Enforce

Both profiles check and record:

- CKB syscall numbers;
- CKB source constants;
- CKB header ABI restrictions;
- raw ELF packaging without ABI trailer;
- Molecule-facing schema, canonical `WitnessArgs.input_type` entry placement,
  and typed lock args ABI;
- CKB Blake2b release/deployment hash helper support;
- `args_parts` lock-args partition metadata for typed builders;
- manifest-level `hash_type`, CellDep, and DepGroup reporting;
- manifest-backed CellDep binding evidence through `cell_data_codec_manifest`;
- action-aware scan-selector evidence for builder-side Cell discovery;
- TemplateLayout metadata for verifier root/path shape analysis;
- declared capacity floors, occupied-capacity checks, tx-size requirements, and
  builder-evidence requirements in constraints;
- CKB policy checks for unsupported runtime or stateful shapes.

The point is not to make compilation harder. The point is to avoid producing an
artifact whose CKB assumptions are vague.

Verify the result:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

For an upgrade-line artifact, require the distinct identity:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb-type-hash
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
- use `env::current_timepoint()` only when epoch-number semantics are intended
  under the CKB profile; it maps to HeaderDep#0 epoch number, not a Unix
  timestamp;
- use `with_capacity_floor(shannons)` when a typed output has a known minimum
  capacity requirement;
- record CKB `hash_type`, CellDeps, and DepGroups in `Cell.toml`;

### The VM2 deployment contract (0.26 artifacts)

Starting with the 0.26 economic backend closure, generated artifacts use Zbb
rotate instructions (`rori`/`roriw`) in their hash cores. Those instructions
are only guaranteed to decode on CKB VM version 2, and on chain the Script
`hash_type` selects that version for data-hash deployments: `data2` selects
VM2 (Zbb guaranteed), while `data1` does not. The compiler therefore emits and
pins an explicit exact-data contract for `ckb`:

```text
minimum_vm_version = 2
riscv_isa = "rv64imac_zbb"
deployment_hash_types = ["data2"]
```

Consequences for deployment review:

- The compiler default is now `data2`; a package declaring
  `deploy.ckb.hash_type = "data"` or `"data1"` is rejected instead of
  silently producing an artifact that some verifiers cannot execute.
- Existing Data1 code Cells are not upgraded in place. Rebuild the ELF and
  its sidecars, deploy the new bytes under `data2`, and update every code
  hash, dependency, and acceptance fixture that references the old identity.
- External CellDeps keep their own declared hash types: their bytes, not the
  generated CellScript ELF, determine their VM requirement.
- The independent artifact checker rejects any bundle whose metadata weakens
  the VM2/Zbb/`data2` contract after production.

### The Type-hash deployment contract (0.30 development branch)

The `ckb-type-hash` profile uses the same CKB VM2 RISC-V backend and ABIs, but
pins a separate deployment contract:

```text
minimum_vm_version = 2
riscv_isa = "rv64imac_zbb"
deployment_hash_types = ["type"]
```

CKB resolves a Type-hash Script through the Type Script hash of a live code
CellDep. A Type ID on that code Cell supplies singleton lineage, while the code
Cell Lock supplies upgrade authorization. The compiler and standalone checker
keep the profile identity and `type` deployment policy hash-bound to the
artifact sidecars. They do not infer compatibility from Type ID: deployment
line receipts and admission evidence must bind the exact selected bytes and
checked interface before signing and at runtime.

Type-hash execution follows the VM version selected by the active CKB consensus
rules. This profile retains `minimum_vm_version = 2` and is valid only for a
chain identity where VM2 is active.

For either profile:

- inspect `cellc constraints --target-profile ckb --json` before deployment;
- inspect witness layout with `cellc abi` or `cellc entry-witness`;
- place the reported `CSARGv1` entry payload in
  `WitnessArgs.input_type` on the first witness of the active script group;
- preserve `WitnessArgs.lock` and `output_type` when constructing or signing a
  transaction;
- avoid scheduler witness ABI unless you are deliberately using that surface;
- avoid unsupported signature/hash helper syscalls;
- use metadata and `verify-artifact` to confirm target profile and packaging.

The lock-boundary keywords from the previous chapter also matter here.
`protected` tells readers which input Cell is guarded. `witness` tells readers
which values come from witness data. `lock_args` tells readers which values come
from CKB `Script.args`. None of them silently verifies a signature.

Under placement ABI `cellscript-witnessargs-input-type-v2`, CellScript entry
parameters are not decoded from arbitrary raw witness bytes. The wrapper
selects `GroupInput#0`, or `GroupOutput#0` for an output-only script group,
parses a Molecule `WitnessArgs`, and reads `input_type`. Raw `CSARGv1`, malformed
tables, absent `input_type`, and placement in `lock` or `output_type` fail
closed. Edition 2026 is recorded alongside this independently versioned ABI in
the resolved compatibility profile. See the
[Entry Witness ABI](../CELLSCRIPT_ENTRY_WITNESS_ABI.md).

Capacity has the same boundary discipline. `with_capacity_floor(...)` is a
source-level floor, and `occupied_capacity("TypeName")` makes capacity policy
visible to reports. The final transaction still needs builder-side occupied
capacity measurement, enough output capacity, and tx-size evidence.

CellScript 0.21 records more CKB-facing builder evidence, but the boundary is
still precise. `args_parts`, action scan selectors, manifest-backed CellDeps,
and TemplateLayout make transaction construction auditable. TemplateLayout is
metadata-only in 0.21: it can say a root/path claim is represented in metadata,
or that a claim still needs runtime-helper coverage, but it does not by itself
prove a consensus Merkle path.

## Fiber Is An Interoperability Path, Not A Target Profile

CellScript 0.22 can derive a narrow `fungible-type-group-v1` artifact for native
Fiber UDT channels. This does not add a `fiber` compiler profile. The adapter
starts from the ordinary `ckb` profile and binds compiler metadata to a concrete
deployment, live asset Script, CellDeps, and operator-controlled Fiber
configuration.

Use the separate `cellscript-fiber` binary and follow the
[bounded Fiber interoperability guide](https://github.com/CellScript-Labs/CellScript/blob/nightly-0.24/examples/fiber/README.md). A successful
offline compatibility check proves only that the source matches the closed
fungible contract. Production readiness still needs live CKB identity, node
configuration, restart, announcement, and lifecycle/negative evidence.

## Evidence Beyond Compilation

Compiler metadata is necessary, but it is not a substitute for builder-backed
transaction evidence. For release-facing CKB evidence, also run the repository's
CKB acceptance gate. That gate checks concrete transactions, dry-run cycles,
serialized transaction size, occupied capacity, and positive/negative behavior
where the bundled suite provides it.

You can think of the layers like this:

- target profile: "can this source be lowered under CKB rules";
- artifact verification: "does this artifact match its metadata";
- strict primitive gates: "does this release line reject evidence gaps at the
  intended policy boundary";
- CKB acceptance: "can builder-generated transactions use the artifact as
  claimed."

## Next

After choosing a profile, continue with
[Metadata, Verification, and Production Gates](https://github.com/CellScript-Labs/CellScript/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates).
