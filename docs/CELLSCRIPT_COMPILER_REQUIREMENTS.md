# CellScript Package Compiler Requirements

Status: active 0.30 development contract for issue #18.

## Manifest Contract

`[package].cellscript_version` is a SemVer requirement over `cellc` releases:

```toml
[package]
edition = "2026"
name = "order_policy"
version = "1.4.0"
cellscript_version = ">=0.26.0, <0.31.0"
```

The field controls which compiler releases may load the package. It is not the
package version, source edition, compatibility-profile identity, or exact
compiler build identity.

The accepted spelling follows the Rust `semver` requirement parser. Explicit
operators such as `=`, `>`, `>=`, `<`, `<=`, `^`, `~`, wildcard components,
and comma-separated intersections retain their standard meaning. Historical
bare values such as `0.16` are interpreted as minimum requirements
(`>=0.16`). This preserves the intent of existing CellScript manifests instead
of turning them into exact or Cargo-compatible ranges after the field becomes
enforced.

Omitting the field means `*` for legacy manifests. `cellc init` and
`cellc new` write an explicit minimum using the active compiler release. An
explicit empty string, malformed requirement, or range that excludes the
active compiler fails with `E2600 package-compiler-incompatible`. CellScript
does not currently provide an ignore or force override.

Standard SemVer pre-release matching applies. A package that intends to admit
a pre-release must name a compatible pre-release comparator; an exact
`=0.30.0-alpha.1` does not admit `0.30.0-alpha.2`.

## Validation Order

The root package requirement is checked immediately after `Cell.toml` is
decoded and before any `.cell` source is collected or parsed. Dependency
requirements are checked while their manifests are resolved and before their
source modules are loaded.

Dependency preflight continues across sibling and readable transitive
manifests after an incompatibility. The final E2600 JSON report contains an
`incompatible_packages` array. Every entry carries the package, declared
requirement, active compiler, explanatory message, and the incoming edge's
parent package, dependency alias, and target package. No partial dependency
graph is retained after the aggregate failure.

Path, Git, and Registry packages use the same manifest rule. Registry
selection first removes compiler-incompatible versions, then applies the
existing release-status and package-version policy. A range selects the newest
remaining compatible version deterministically. An exact pin with no
compiler-compatible candidate fails with E2600 rather than downloading and
parsing incompatible source.

## Registry Evidence

A CellScript source release carries two distinct Registry fields:

- `compiler_requirement` is copied from the source package manifest and
  controls source compatibility during candidate selection;
- `cellscript_version` is the exact compiler release recorded by the publish
  build and remains build evidence rather than a compatibility range.

The selected Registry index, checked-out tag or immutable snapshot, and its
`Cell.toml` must agree on `compiler_requirement`. A declaration mismatch fails
closed. Registry metadata does not prove that an artifact was actually built
by the compiler named in `cellscript_version`; reproducible build evidence owns
that stronger claim.

## Cell.lock v5

Lockfile version 5 uses schema
`cellscript-lock-v0.30-single-package-coordinate-v1`. The root package and every
dependency node record:

```toml
compiler_requirement = ">=0.26.0"
resolver_compiler_version = "0.26.0"
```

`compiler_requirement` is the source compatibility contract copied from the
manifest. `resolver_compiler_version` records which release constructed the
locked graph; it does not force exact-compiler pinning. Canonical dependency
node IDs also bind the requirement, so changing it changes graph identity even
when source location and package version stay constant.

Locked and frozen builds re-read each manifest, revalidate its requirement
against the active compiler, compare it with the locked requirement, recompute
the requirement-bound node ID, and never select a replacement version. A
changed requirement requires an explicit `cellc update`.

The v5 root also declares
`resolver_model = "single-package-coordinate-v1"`; compiler requirements are
therefore carried inside the same explicit one-instance-per-coordinate graph
contract.

Normal build, check, and test commands reject lock versions 1 through 4. An
explicit `cellc lock` or `cellc update` may migrate them by resolving a fresh
v5 graph. This is an intentional repin: it does not infer missing requirement
evidence into the old lock.

## Independent Compatibility Axes

Compiler compatibility never substitutes for the other versioned contracts:

| Axis | Question answered |
| --- | --- |
| Package version | Which package API/source release was selected? |
| `cellscript_version` | May this `cellc` release load the package? |
| Edition | Which source-language semantics apply? |
| Lock schema | Can this compiler interpret the frozen dependency graph? |
| Target/profile | Which VM, ABI, syscall, and assurance boundary applies? |
| Metadata/checker schema | Can downstream tools interpret and independently check the evidence? |
| Exact compiler/build identity | Which executable and build inputs produced the artifact? |

Matching the compiler range establishes only source-tool compatibility. It is
not semantic equivalence between compiler releases and is not reproducible or
deployment evidence.
