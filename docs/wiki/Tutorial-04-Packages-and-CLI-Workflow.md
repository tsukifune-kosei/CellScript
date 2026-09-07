# Tutorial 04: Packages and CLI Workflow

Small experiments can be compiled as single `.cell` files. Once a contract has
more than one source file, a dependency, or a release target, use a package.

A package gives the compiler a stable place to find the entry file, build
settings, dependencies, and lockfile. That makes builds repeatable for you, and
reviewable for someone else.

## What You Will Learn

- how to create a package;
- what belongs in `Cell.toml`;
- how to build, check, format, and document a package;
- which reports are useful during review;
- where the current package workflow intentionally stops.

## Create a Package

Create an application-style package:

```bash
cellc init my_contract
cd my_contract
```

This creates a `Cell.toml` manifest and a source entry. Use this form when you
want a contract package with a concrete entry.

Create a library-style package:

```bash
cellc init my_lib --lib
```

Ask for a machine-readable summary when scripting:

```bash
cellc init my_contract --json
```

## Read The Manifest

A minimal manifest looks like this:

```toml
[package]
edition = "2026"
name = "my_contract"
version = "0.1.0"
entry = "src/main.cell"
source_roots = ["src"]

[build]
target = "riscv64-elf"
target_profile = "ckb"
out_dir = "build"

[dependencies]
my_lib = { path = "../my_lib" }
```

Read the manifest as a build promise:

- `edition = "2026"` selects the source-language semantic epoch. It is
  mandatory; CellScript does not infer, migrate, or accept any other edition,
  and the year does not imply an annual release cadence;
- `entry` tells the compiler where the package starts;
- `source_roots` tells the compiler which package directories contain `.cell`
  modules;
- `target` chooses assembly or ELF-style output;
- `target_profile` chooses the runtime assumptions;
- `out_dir` chooses where artifacts are written;
- path, git, and registry source-package dependencies keep package inputs
  explicit and lockable.

Production Registry source-package resolution selects an accepted version from
the public API, downloads its immutable source snapshot, and verifies object
SHA-256, safe paths, per-file BLAKE2b, `Cell.toml`, Edition/profile identity,
and the whole-tree `source_hash`. `registry.json` plus tag-pinned Git remain the
explicit offline/mirror authority. Local path dependencies remain the fastest
repeatable development workflow, and non-CellScript registry artifact profiles
still fail closed until they have their own resolver contracts.

The edition is one input to the emitted compatibility profile. Target,
primitive assurance, metadata schemas, and wire ABIs keep independent version
identities, so they can advance without creating a new source edition. The
profile hash commits to the complete combination in every downstream
build/deployment identity. See
[CellScript Edition Policy](../CELLSCRIPT_EDITION_POLICY.md).

As a rule of thumb, compiler SemVer answers “which implementation produced
this output?”, Edition answers “how is this source understood?”, and the
resolved compatibility profile answers “which complete source/target/ABI/schema
contract was used?”.

## Multi-file Packages

Package builds are entry-driven, but the frontend loads the full package source
set before compiling the entry artifact. The compiler walks `source_roots`
(defaulting to `src`), parses every `.cell` file it finds, registers each file's
`module` declaration, and validates every `use path::Symbol` import against the
loaded module graph. Path dependencies are loaded the same way, so shared schema
packages can provide common Cell types without copying them into every contract.

There is no `mod` keyword and no implicit basename lookup. The module declared
inside the file is the source identity. Duplicate module declarations fail, bad
imports fail, and invalid package modules fail during `build` or `check` even
when the entry file does not reference them directly.

This is not a contract linker. Each CKB script remains an independent RISC-V
artifact. Cross-file helper calls are resolved at compile time and inlined into
the entry artifact, but there is no ELF linker and no cross-script runtime
coupling. Use multi-file packages for schema reuse, shared helper functions,
reviewable module organization, and repeatable source/package hashes.

For registry resolution, `cellc add` must remain a dependency
resolver, not a code-snippet finder. Anything reachable by `cellc add` must be
safe to participate in the package, build, deployment, or declared TCB identity
chain. Template-only material belongs behind copy/scaffold commands instead.

## Build

Run the package build:

```bash
cellc build
```

Useful flags:

```bash
cellc build --target riscv64-asm
cellc build --target riscv64-elf
cellc build --target-profile ckb
cellc build --locked
cellc build --frozen
cellc build --offline
cellc build --features audit,metrics
cellc build --all-features
cellc build --no-default-features
cellc build --environment mainnet
cellc build --production
cellc build --json
```

Dependency builds are lock-authoritative. Run `cellc lock` or `cellc update`
when dependency selection is intended; `build`, `check`, and `test` otherwise
consume only the existing graph. `--locked` makes that assertion explicit,
`--frozen` also disables network access and every lockfile write, and
`--offline` permits only already materialized exact source pins.

`build` reads `Cell.toml`, compiles the current package entry, and writes the
artifact plus metadata sidecar under the configured output directory. A CKB
ELF build also writes canonical verified-artifact sidecars:

```text
build/main.elf
build/main.elf.meta.json
build/main.elf.lowering.json
build/main.elf.sourcemap.json
```

The lowering record and source map are checked against final ELF bytes during
compilation. They are structural/binding evidence, not a complete
source-equivalence or chain-execution claim.

For a one-off source file, use the top-level compiler form instead:

```bash
cellc path/to/file.cell
```

That form is great for quick experiments. Packages are better when you need
repeatability.

## Execute Package Scenarios

Executable tests are versioned `*.scenario.json` files under `tests/`. Name a
backend explicitly:

```bash
cellc test --backend simulator
cellc test --backend ckb-vm
cellc test --backend all --json
```

`simulator` is fast development evidence. `ckb-vm` executes the emitted ELF and
is local authoritative runtime evidence. Use `cellc test --no-run` only when
compile-only checking is intentional. Without `--no-run`, an omitted backend
or an empty scenario set is an error rather than a false pass.

The v1 scenario format rejects unknown fields and validates named live Cells,
replacement steps, Scripts, deps, headers, `since`, witnesses, capacity and
size limits, and exact runtime error code/name pairs. Its multi-step Cell set
is a local bookkeeping oracle; the CKB-VM backend currently supports
no-argument entries and does not inject those declared Cells into syscalls.
Transaction-syscall scenarios remain with the repository's stateful CKB
oracle. See [Verified Artifacts and Executable Tests](Tutorial-14-Verified-Artifacts-and-Executable-Tests.md).

## Check Without Writing Artifacts

Use `check` when you want fast feedback:

```bash
cellc check
cellc check --all-targets
cellc check --target-profile ckb
cellc check --production
cellc check --deny-runtime-obligations
cellc check --json
```

`check --all-targets` is useful before committing. It catches source and profile
problems without producing build artifacts.

## Diagnostic Output Formatting

Use the global `--json` flag when a CI job or agent loop needs structured
results without parsing human text:

```bash
cellc check --target-profile ckb --json
cellc build --json
```

Colour is controlled separately:

```bash
cellc check --color=auto
cellc check --color=always
cellc check --color=never
NO_COLOR=1 cellc check
```

`--json` and `--color` are global flags and may appear before or after every
subcommand. `--json` emits one stdout document for success or failure, so a
caller can always parse the same stream. The old `--message-format=json`
spelling remains a hidden deprecated alias during the compatibility window.

Structured failures include an error category and the process exit code.
Usage errors exit with `2`, ordinary compilation failures with `1`, I/O with
`74`, network availability failures with `69`, authentication failures with
`77`, and internal failures with `70`.

Backend failures use stable `E2xxx` codes. `cellc explain E2202 --json` returns
the rule name, description, and recovery hint; LSP diagnostics expose the same
code and a `codeDescription` link.

## Format And Generate Docs

Format the package:

```bash
cellc fmt
cellc fmt --check
cellc fmt --json
```

Generate package docs:

```bash
cellc doc
cellc doc --json
```

Generated docs summarize modules, actions, resources, receipts, locks,
flow rules, and lowering metadata.

## Audit And Evidence Reports

When a package is ready for review, ask the compiler for the facts it already
knows:

```bash
cellc metadata . --target riscv64-elf --target-profile ckb -o build/main.metadata.json
cellc expand . --target riscv64-elf --target-profile ckb --json -o build/main.semantic.json
cellc constraints . --target riscv64-elf --target-profile ckb -o build/main.constraints.json
cellc abi . --target-profile ckb
cellc scheduler-plan . --target-profile ckb --json
cellc opt-report . --target riscv64-elf --target-profile ckb --json
```

`cellc expand` exposes the canonical semantic foundation used by the 0.26b
checker boundary. Its JSON form is machine-checkable; the default text form is
only a diagnostic rendering and is not a semantic hash input.

To request a bounded, non-mutating Edition 2027 candidate from an Edition 2026
package:

```bash
cellc migrate . --to 2027
cellc --json migrate . --to 2027 -o build/migration-report.json
```

The preview recognizes only a self-contained module with one final entry. A
Type Script must already be an exact sequence of source `require` conditions,
exhaustive `std::lifecycle::transfer`, and matching
`std::cell::preserve_capacity`; a Lock Script must contain only source
`require` conditions and explicit `protected`, `lock_args`, or `witness`
parameters. The command preserves every byte outside the entry and emits
nothing until the old and candidate `CoreSemanticId` values and generated
RISC-V ELF bytes match. It does not edit `Cell.toml`, `Cell.lock`, source,
deployment state, or dependencies. Unsupported input stops with a diagnostic;
there is no partial migration. Explicit visibility and mutable/reference role
forms also stop until the native container can preserve those interface
semantics exactly.

For CKB-specific builder and deployment review:

```bash
cellc constraints . --target riscv64-elf --target-profile ckb --json
cellc abi . --target-profile ckb --action transfer
cellc entry-witness . --target-profile ckb --action transfer
cellc ckb-hash --file build/main.elf
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

Builder-facing contract commands expose the metadata that transaction builders
consume. Prefer the canonical 0.21 nested forms:

```bash
cellc action build . --action transfer --json
cellc entry-witness . --target-profile ckb --action transfer
cellc explain assumptions . --target-profile ckb --json
cellc tx solve . --target-profile ckb --json
cellc tx validate --against build/main.elf.meta.json --tx tx.json --json
cellc tx trace --against build/main.elf.meta.json --tx tx.json --json
cellc deploy plan . --target-profile ckb --json
cellc deploy verify --plan Deployed.toml --json
cellc registry verify --json
cellc package verify --json
cellc auth capability create --principal-id <principal_id> \
  --scope publish:cellscript/my_contract \
  --expires 90d --json
cellc gen-builder . --target typescript --target-profile ckb --json
```

`package verify` checks build identity as well as the dependency graph. A
freshly cloned example intentionally carries a graph-only `Cell.lock`; run
`cellc build --locked` first to populate `[package.build]`. A frozen build
cannot add that local evidence because `--frozen` suppresses every lockfile
write.

Legacy flat aliases such as `solve-tx`, `deploy-plan`, and
`explain-assumptions` remain executable for compatibility, but they are hidden
from public discovery. Prefer `--json` where a command offers it, and reserve
human summaries for interactive review.

0.21 builder/deployment review also records action-aware scan selector
evidence, variable-length `args_parts`, and manifest-backed CellDep completion
where the adapter has enough deployment metadata to resolve them. Missing or
mismatched live-cell scan evidence fails closed.

These reports are not busywork. They answer questions reviewers will ask:

- what is the entry ABI;
- what witness layout is expected;
- what capacity or runtime obligations remain;
- what CKB hash policy is being used;
- whether the artifact still matches the source and metadata.

They do not replace chain acceptance reports, builder-generated transactions,
occupied-capacity evidence, or CKB production gates.

## Local Dependencies

Add a local dependency:

```bash
cellc add my_lib --path ../my_lib
```

`add --path` records the dependency in `Cell.toml`. To resolve the dependency
graph and write `Cell.lock`, run:

```bash
cellc lock
```

You can also add and lock a local dependency in one command:

```bash
cellc install my_lib --path ../my_lib
```

The current CLI can record a Git dependency URL:

```bash
cellc add math --git https://example.com/math.git
cellc install math --git https://example.com/math.git
```

For reviewable package identity, a manifest may name a branch or tag during
development, but `cellc lock`/`update` immediately normalizes it to a full
40-hex commit and immutable cache. A later branch movement does not affect
builds until the next explicit repin.

Remove it:

```bash
cellc remove my_lib
```

`add`, `install`, `update`, and normal dependency removal refresh the lockfile so
direct and transitive local path dependencies stay consistent.

`Cell.lock` v3 is a graph rather than a flat list. It binds the exact root
manifest digest, each dependency manifest and whole source tree, outgoing
alias-to-node edges, feature/test modes, and named CKB environments. Local
projects should commit it to version control: the lockfile is reviewed build
input, not a local cache, and normal build/check/test commands do not silently
repin it. Dependency aliases can differ from declared package names:

```toml
[dependencies.math]
package = "canonical_math"
version = "^1.2.0"
```

Optional dependencies are activated through versioned feature roots:

```toml
[dependencies.audit]
version = "^1.0.0"
optional = true

[features]
default = []
auditing = ["dep:audit"]
```

`[dev_dependencies]` are present only in the `cellc test` graph. Feature
cycles, unknown features, alias collisions, and unknown `dep:` targets fail
closed. `[build.dependencies]` is reserved until CellScript has an isolated
build-script execution contract.

For chain-dependent selection, declare the chain, not an implicit label:

```toml
[environments.mainnet]
chain_id = "ckb"
genesis_hash = "0x...32-byte-genesis-hash..."

[dependency_overrides.mainnet.registry_types]
version = "=2.0.0"
namespace = "cellscript"
```

When overrides exist, `--environment mainnet` is mandatory. The environment
root in `Cell.lock` binds both `chain_id` and genesis hash.

For a transitive package, the name `mainnet` has no special meaning and is not
inherited. CellScript selects the unique dependency-local environment with the
same chain identity, or you can make the edge policy explicit:

```toml
[dependencies.protocol]
path = "deps/protocol"
use_environment = "production"

[dependencies.codec]
path = "deps/codec"
environment_independent = true
```

The first mapping is accepted only when `production` has the same `chain_id`
and genesis hash as the root selection. The second skips dependency-local
overrides while preserving the root identity for later transitive edges.
`cellc add` exposes the corresponding `--use-environment NAME` and
`--environment-independent` flags.

The portable checked-in example exercises these inputs together:

```bash
cd examples/package_graph
cellc check --frozen --offline --environment mainnet
cellc check --frozen --offline --environment testnet --features full
cellc test --no-run --frozen --offline --environment testnet --all-features
```

Its local dependency alias is distinct from the declared package name, and its
testnet override resolves a different exact version of the same declared
package. Omitting `--environment` is an intentional fail-closed example.

Advanced ecosystems may declare a hash-pinned bounded resolver. It runs only
during explicit lock/update, without a shell or inherited environment, and
must normalize its versioned JSON response to an exact Registry version or Git
commit. Locked builds never invoke it:

```toml
[resolvers.vendor]
command = "/absolute/path/to/vendor-resolver"
sha256 = "sha256:<resolver-executable-digest>"
args = ["resolve"]

[dependencies.math]
package = "canonical_math"
version = "^1.2.0"
resolver = "vendor"
```

## Registry Resolver Boundaries

CellScript's registry design follows the same split as the package identity
model:

- package identity answers which source was referenced;
- build identity answers which artifact and metadata were produced;
- deployment identity answers which CKB Cell, CellDep, or runtime artifact is
  being used.

Registry discovery is broad. It indexes CellScript source packages,
runtime verifiers, deployed CKB artifacts, reproducible artifacts, and even
external CKB tooling artifacts such as bootstrapper outputs. Resolver profiles
must stay narrower: an object can be discovered without being installable by
`cellc add`.

That means registry resolution is stricter than discovery. The versioned
`cellscript-registry-profile-catalog-v1` marks only the
`cellscript_source` + `dependency` contract as dependency-resolving. `cellc add`
and `cellc install` reject every other profile.
Other profiles use explicit `cellc artifact` commands and fail closed on
unknown fields, identities, roles, or lifecycle state:

| Kind | `cellc add` | Current explicit boundary |
| --- | --- | --- |
| `source_library` / `profile_library` | yes | Compiler-backed source and API identity are pinned in `Cell.lock`. |
| `runtime_verifier` | no | `artifact fetch`, `verify`, and `pin`; verifier ID, IPC ABI, artifact, build, security, and production CellDep remain explicit TCB facts. |
| `deployable_contract` | no | `artifact fetch`, `verify`, `pin`, `record-deployment`, and `cell-dep` bind build and live mainnet deployment identity; `artifact ls-idl` validates, binds, bundles, or resolves a Lock Script interface without making it a source dependency. |
| `reproducible_binary` | no | `artifact reproduction-evidence` binds independent builders to source, recipe, environment, executable, and logs before verified use. |
| `template` | no | `artifact copy` authenticates a bounded file map, rejects traversal and overwrite, and then leaves local project source. |

The rule is intentionally blunt:

```text
Discovery can be broad; dependency resolution is narrow.

Anything reachable by cellc add must be dependency-safe, artifact-safe,
deployment-fact-safe, or declared-TCB-safe.

Anything scaffold-only must be copied, not resolved.
```

For example, a BIP340 verifier package can have no business parameters and
still be resolver-safe because it is a runtime verifier artifact. Its manifest
or registry record must identify the verifier capability, IPC ABI, artifact
hashes, build profile, TCB/security status, and any production CellDep pins.

A NovaSeal starter project, by contrast, is not dependency-safe merely because
it contains useful `.cell` code. If users are expected to copy it and edit terms,
authorities, manifests, or deployment pins, it belongs in a cookbook or template
flow, not in dependency resolution. Use `cellc artifact copy`, then treat the
authenticated result as local project source.

It should not be installed with:

```text
cellc add novaseal/mvb-starter
```

This keeps the registry as a verifiable dependency and artifact discovery layer,
not a general examples marketplace.

For mixed projects, keep the records separate. A CellScript app may depend on a
CellScript library, reference a deployed verifier as TCB evidence, use a
reproducible bootstrapper artifact during its build process, and copy a cookbook
starter into local source. Those are four different profile boundaries. They
may share one registry service and one `namespace/name` style, but they must not
share one unchecked dependency path.

## Package Information

```bash
cellc info
cellc info --json
```

Use `info` when you want a quick view of the package boundary before building or
debugging dependency resolution.

## Registry Commands

Registry source-package installation and registry-backed `update` are supported
for the CellScript source-package profile. The preferred interactive first-use
path is `cellc publish --authorise`: it creates a 15-minute browser session,
authorises a wallet-rooted delegated key, and resumes the publish after the
Registry returns the matching key ID. `--no-open` supports remote terminals.
Later `cellc publish` calls use the active scoped key.

For CI, recovery, or an external-wallet handoff, `cellc auth capability create
--principal-type <joyid_ckb|ckb_secp256k1> --principal-id <principal_id>` creates
the wallet payload; submit the wallet signature and claim the namespace before
publishing. Inside a package directory, omitting `--scope` infers only the exact
`publish` scope. Add `deployment` or `availability` scopes explicitly when that
delegated key genuinely needs those actions; none implies another.
The `principal_id` is cryptographically derived from the signer, not from a
display label. The same metadata can still be
mirrored with `cellc publish --offline` to `registry.json` and Git tags for
audit, local fixtures, and offline fallback. `cellc registry add` manages discovery/claim metadata rather than
ordinary version publication.

Non-CellScript profiles publish with `Artifact.toml` and
`cellc publish --artifact-manifest Artifact.toml`. Consumers use the explicit
`cellc artifact fetch`, `verify`, `pin`, `copy`, `reproduction-evidence`,
`record-deployment`, `cell-dep`, `commitment`, and `set-availability` commands;
none silently turns an executable, TCB object, or template into a source
dependency. `run`, `repl`, and cryptographic audit-signature verification
retain their separate documented assurance boundaries.

For LS-IDL Lock Scripts, `cellc artifact ls-idl validate|bind|bundle` prepares
the byte-exact interface contract and `fetch` resolves it by chain-verified
Script identity. The raw IDL SHA-256/executable-suffix relationship is an
identity check, not proof of implementation correctness.

## Next

With a repeatable package workflow in place, continue with
[CKB Target Profiles](https://github.com/CellScript-Labs/CellScript/wiki/Tutorial-05-CKB-Target-Profiles).
