# CellScript Package Provenance and Deployment Identity

**Status**: implementation contract for the current CellScript CKB profile.
Phase 1 landed in the 0.19 line; Phase 2 source-package, generated-builder,
deployment identity, and trust-metadata checks extend through 0.20 and the
0.21 RC. The 0.23 line deploys the public read/write service and makes its
accepted package status the default CLI resolution authority. The 0.24
development line adds compiler-independent structural admission for complete
CellScript CKB artifact bundles without changing source-package resolution.

**Scope**: Source package registry, deployment registry, lockfile binding, and
builder verification for CellScript on CKB

**Historical scope anchors**: v0.12 stable developer surface, v0.17 CKB
protocol semantics, and v0.18 first-class ScriptRef / ScriptArgs work.

**Forum thread**: <https://talk.nervos.org/t/cellscript-package-and-deployment-registry-early-design-discussion/10210>

**Production boundary ADR**:
[`CELLSCRIPT_REGISTRY_PRODUCTION_BOUNDARY_ADR.md`](CELLSCRIPT_REGISTRY_PRODUCTION_BOUNDARY_ADR.md)

**0.23 production authority**: `https://api.registry.cellscript.dev` owns public
discovery and accepted status. The source repository and its `registry.json`
remain mandatory verification inputs after selection. References below to the
`cellscript-registry` Git discovery index describe the explicit
`CELLSCRIPT_REGISTRY_URL` offline/private-mirror path unless a historical phase
is being discussed; they are not an automatic production fallback.

## Motivation

For ordinary development, a package registry can look like crates.io or npm:
resolve a package name and version, download source, build it, and use it.

For smart contracts, that is not enough.

A production CellScript dependency eventually needs to answer questions such as:

1. Which source package was used?
2. Which compiler version produced the artifact?
3. What schema and ABI commitments were used?
4. What constraints report was generated?
5. What exact RISC-V artifact was deployed?
6. Which CKB CellDep, OutPoint, data_hash, dep_type, lock/type identity, or
   type-id lineage corresponds to that artifact?
7. Can a wallet or builder verify that the package used in a transaction is the
   same one the developer intended?

A source package version is useful for development, but production use also needs
deployment truth.

## Core Principle

> CellScript packages should be distributed like development packages, but
> verified like smart-contract deployments.

The off-chain registry optimizes for source distribution and developer
experience. CKB records only compact, verifiable deployment truth where it is
actually useful. The lockfile binds the two.

## Profile Compatibility Boundary

`namespace/name/version` is a stable naming layer, not proof that every named
object is a CellScript source package. The current Phase 1 implementation uses
one concrete profile:

```text
cellscript_source_package_v1
  carrier: Cell.toml + registry.json + Cell.lock + Deployed.toml
  resolver: cellc package/dependency resolver
  source hash: Cell.toml plus .cell source roots and explicit entry parent
  deployment identity: CKB script cell facts when the package is deployed
```

Future registry services may discover other CKB ecosystem artifacts under the
same naming convention, such as verifier binaries, deployed script records,
profile libraries, or reproducible build outputs like `ckb-bootstrapper`.
Those objects must use explicit artifact profiles. They must not be silently
accepted by the CellScript package resolver merely because they have a
`namespace/name` and a Git URL.

The compatibility rule is:

```text
Discovery can be broad.
Resolution is profile-specific.
No resolver may coerce one profile into another.
```

The 0.24 verified-artifact boundary is an additional admission contract, not a
new dependency profile. A CKB ELF build binds `artifact`, `metadata`,
`lowering_record`, and `source_map`. Registry bundles that opt into this
boundary must provide the complete verified sidecar set; the least-privilege
artifact worker runs the standalone checker and records
`structurally_verified` evidence. Generic source/executable/ABI bundles remain
`hash_bound`, and neither result proves deployment, chain acceptance, or a
security audit.

Edition 2026 does not infer a missing compatibility profile. It identifies
source semantics only. Current CellScript source packages must declare
`edition = "2026"`, while registry, lockfile, deployment, and builder records
bind the resolved profile hash across the independent target, primitive,
metadata-schema, and entry/witness ABI axes. A future registry proxy or
discovery index may expose multiple profiles for the same `namespace/name`,
but the selected profile must remain explicit.

## Publisher Identity Model

CellScript Registry uses a **wallet-rooted publisher identity** without a
separate registry account system. It accepts JoyID and standard recoverable CKB
secp256k1 message-signing principals; ordinary publish operations use a
delegated local credential:

```text
principal_type = joyid_ckb | ckb_secp256k1
principal_id = <normalized signer public-key binding>

CKB wallet identity
  -> root publisher principal
  -> authorises local publisher credential
  -> credential signs scoped registry requests
```

The data model stays principal-typed instead of hard-coding wallet-product
policy into every record. `principal_id` is derived from the signer key, and
the Registry verifies that signature scheme, key type, recovered or supplied
public key, and principal binding agree. Display addresses are presentation
data only.

The preferred interactive flow is:

```text
cellc publish --authorise
  -> CLI creates a P-256 publishing key as pending in the OS keychain
  -> CLI opens a 15-minute exact-coordinate browser session
  -> browser/CCC wallet signs the Registry-built challenge
  -> Registry atomically registers the key, claims/reviews the namespace,
     completes the session, and records audit events
  -> CLI activates only the matching returned key ID and resumes publishing
```

The explicit `auth capability create/submit` plus `auth namespace claim`
commands remain the CI, recovery, and external-wallet path. Daily publishing
then avoids wallet signing prompts and never exposes root
publisher authority to CI:

```text
cellc publish
  -> signs the concrete publish payload with the local publisher credential
  -> registry verifies signature, nonce, expiry, origin, and ACL scope
  -> registry accepts the entry and returns its canonical URL
```

The wallet authorisation payload must bind the local capability key:

```text
protocol: cellscript-registry-auth-v1
action: authorize_capability
registry_origin: https://api.registry.cellscript.dev
principal_type: joyid_ckb | ckb_secp256k1
principal_id: <normalized signer public-key binding>
capability_pubkey: ...
requested_scopes:
  - publish:cellscript/amm_pool
  - deployment:cellscript/amm_pool
  - availability:cellscript/amm_pool
capability_expires_at: ...
nonce: ...
issued_at: ...
expires_at: ...
cli_version: ...
```

The daily publish payload must bind the action and package identity:

```text
action: publish
namespace: cellscript
package: amm_pool
version: 1.2.0
source_hash: ...
manifest_hash: ...
registry_origin: https://api.registry.cellscript.dev
nonce: ...
expires_at: ...
```

The central ACL model is namespace/package ownership:

```text
namespace -> owner principals
package   -> maintainer principals
credential -> scoped permissions
```

Current write scopes:

```text
publish:cellscript/amm_pool
deployment:cellscript/amm_pool
availability:cellscript/amm_pool
publish:cellscript/*
```

The actions are independent. `publish` admits an immutable release,
`deployment` attaches chain-checked CKB deployment evidence, and
`availability` deprecates, yanks, or restores a release. Namespace wildcards
are accepted, but granting one action never grants another.

This keeps the user-facing identity simple — "my connected CKB wallet is my
CellScript publisher identity" — while the engineering surface remains
revocable, scoped, CI-safe, and auditable.

## Three-Layer Identity Model

CellScript packages exist in three identity layers, each with a distinct
verification scope:

```
┌─────────────────────────────────────────────────────────────┐
│  Package Identity                                           │
│  namespace / name / version / source_hash                  │
│  Carrier: Cell.toml + source registry index                │
│  Verified: compile time                                     │
├─────────────────────────────────────────────────────────────┤
│  Build Identity                                             │
│  compiler_version / metadata_schema / schema_hash /        │
│  abi_hash / artifact_hash / constraints_hash                │
│  Carrier: Cell.lock [package_build]                        │
│  Verified: build time                                       │
├─────────────────────────────────────────────────────────────┤
│  Deployment Identity                                        │
│  chain / network / code_cell / out_point / data_hash /      │
│  dep_type / type_id_lineage / script_role                   │
│  Carrier: Deployed.toml                                     │
│  Verified: runtime / production                             │
└─────────────────────────────────────────────────────────────┘
```

Each layer is independently meaningful but cryptographically bound to the
layers above and below through the lockfile.

### Package States and Visibility

A CellScript package can exist in several operational states:

**Source-published / indexed-pending package.** `cellc publish` has admitted a
new version into the registry. The entry is addressable by direct URL and
visible to the author, but it may be excluded from default search until basic
schema, hash, quota, and abuse checks pass.

**Source-only / undeployed package.** A normal development package containing
`.cell` source files, interfaces, schemas, docs, tests, examples, and
reproducible build metadata. It can be imported, compiled, tested, audited, and
used as a library dependency. However, it does not by itself claim any
production deployment identity on CKB.

**Deployment-bound package.** A package version whose built artifact has been
deployed, and whose deployment identity can be verified. For CKB, this means
binding the package version to facts such as CellDep, OutPoint, data_hash,
dep_type, script/code hash, schema/ABI commitments, constraints report,
compiler version, and possibly type-id lineage.

A deployment-bound package is what wallets and production builders should rely
on when constructing real transactions.

**On-chain-committed package.** A sufficiently confirmed live mainnet Cell
commits the exact Registry release/deployment tuple under the configured
Registry Type Script and custody Lock. This is a current discoverability and
integrity statement, not an attestation of source quality or authorship. It does
not replace source, build, deployment, and live-chain verification.

**Deprecated, yanked, or quarantined package.** Historical entries remain
addressable for reproducibility, but default search and recommendation surfaces
may suppress them. Quarantine is for abuse or high-risk packages; yanking is a
maintainer action that preserves exact-pin warning metadata.

The same source package version may have zero, one, or many deployment
bindings. For example, `amm@1.2.0` may start as a source-only package and later
gain one or more CKB mainnet deployment bindings. The production Registry
accepts only mainnet deployment evidence. The isolated Pudge Registry accepts
only testnet evidence under separate origins, storage, signing state, wallet
state, RPC identity, and retention policy. These are separate deployment
records attached to the same source/package identity, not separate source
packages.

```
amm@1.2.0
  ├─ source:  blake2b:0xabcd...
  ├─ build:   artifact=0x1234... abi=0xdef0...
  ├─ deployed:
  │   ├─ aggron4:  out_point=0xaaaa...:0  status=active
  │   └─ mainnet:  status=candidate
  └─ (same source version, multiple deployment bindings)
```

### Mixed Profile Cases

The following cases are intentionally different, even when they share a
namespace:

| Case | Correct modelling | Must not be modelled as |
|---|---|---|
| A CellScript package imports a CellScript library | `[dependencies]` entry resolved by the CellScript source-package profile | A generic artifact record |
| A CellScript package needs a deployed verifier CellDep | Deployment or verifier artifact profile with code/data hash, OutPoint, status, and ABI/IPC identity | A source library dependency merely because it lives in Git |
| A CellScript build uses an external reproducible tool output | Build-input or reproducible-artifact profile that records recipe hash, toolchain/input lock, and output hashes | A `.cell` source dependency |
| `ckb-bootstrapper` proves a CKB binary | Reproducible-binary profile with source, build recipe, pinned inputs, output binary hashes, and optional CKB commitment/index facts | `cellscript_source_package_v1` |
| A cookbook/template is copied and edited | Copy/scaffold flow; after copying, the files become local project source | A registry dependency that can affect the verified dependency graph |
| A generic artifact references a CellScript deployment | Artifact profile may cite CellScript package/deployment identity as evidence | Automatic cross-profile dependency resolution |

This keeps Janx's `ckb-bootstrapper` use case compatible with the architecture:
it can reuse the registry service, naming convention, proxy/cache layer, and
hash-bound identity chain, but it needs its own profile contract. That profile
would answer "which reproducible binary did this recipe produce?" rather than
"which `.cell` source package did `cellc` import?".

## Why Not Pure On-Chain Packages?

It is unlikely that publishing every CellScript source package directly to CKB
is the right default.

Source archives, docs, examples, tests, schema manifests, and editor metadata
are development artifacts, not consensus-critical state. Frequent package
releases would create unnecessary permanent state churn, and CKB capacity costs
make source-package storage especially unattractive.

The chain should probably record compact deployment facts and commitments, not
replace the whole source distribution system.

## Why Not Pure Off-Chain Packages?

A pure off-chain registry also seems insufficient.

For production CKB contracts, builders and wallets need concrete deployment
identity: CellDep, OutPoint, data_hash, dep_type, script/code hash checks,
schema/ABI commitments, and ideally provenance back to the source package,
compiler version, and constraints report.

A compromised or stale source registry should not be enough to trick a
production builder into using the wrong deployed artifact.

## File Responsibility Split

Inspired by Move/Sui's `Move.toml` / `Move.lock` / `Published.toml` separation,
but adapted to CKB's CellDep/OutPoint-based deployment model rather than Sui's
native package-object model.

### Cell.toml — Source Package Declaration (Extended)

`Cell.toml` gains a `namespace` field in `[package]` and a `namespace` field
in detailed dependencies. No other structural changes are required.

```toml
[package]
name = "amm_pool"
version = "1.2.0"
namespace = "cellscript"          # NEW: must match the module declaration
entry = "src/main.cell"

[dependencies]
# Simple: version-only, auto-resolve namespace from discovery index
token = "0.3.0"

# Detailed with explicit namespace (recommended for production)
token = { version = "0.3.0", namespace = "cellscript" }

# Path dependency (unchanged, bypasses registry)
token = { version = "0.3.0", path = "../token" }

# Git dependency (unchanged, bypasses registry)
token = { version = "0.3.0", git = "https://github.com/cellscript/token", tag = "v0.3.0" }

[build]
target_profile = "ckb"

[deploy.ckb]
hash_type = "data2"
dep_type = "code"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x...:0"
dep_type = "dep_group"
hash_type = "type"
```

#### `[package]` namespace Field

The `namespace` field in `[package]` must match the namespace used in the
module declaration. For a source file that begins with `module cellscript::amm_pool`,
the `[package]` section must have `namespace = "cellscript"`.

This field serves three purposes:

1. **Publishing**: `cellc publish` uses `namespace` to select the registry ACL
   scope and canonical `namespace/name` coordinate.
2. **Verification**: The resolver checks that the declared namespace matches
   the `module` declaration in source files.
3. **Ambiguity resolution**: When a `Simple` dependency (version-only string)
   matches packages in multiple namespaces, the resolver uses the consuming
   package's own namespace as the default.

If `namespace` is absent, the package is treated as a local-only package
that cannot be published to the registry.

#### Dependency Syntax and Registry Resolution

The dependency key (e.g., `token`) is a **local alias** used to identify the
dependency in the project. The resolver maps this alias to a registry package
through the `namespace` field:

| Syntax | Resolution |
|---|---|
| `token = "0.3.0"` | Auto-resolve: search discovery index for `token`; if ambiguous, default to the consuming package's namespace |
| `token = { version = "0.3.0", namespace = "cellscript" }` | Explicit: look up `cellscript/token` in discovery index |
| `local_token = { package = "token", version = "0.3.0", namespace = "cellscript" }` | Resolve declared package `token` under local alias `local_token` |
| `token = { version = "0.3.0", path = "../token" }` | Local path, bypasses registry |
| `token = { version = "0.3.0", git = "...", tag = "v0.3.0" }` | Git clone, bypasses registry |
| `token = { package = "token", version = "^0.3.0", resolver = "vendor" }` | Invoke a declared bounded resolver only during explicit lock/update, then normalize to Registry or exact Git source |
| `token = { version = "0.3.0", use_environment = "production" }` | Use the dependency-local `production` environment after verifying its chain ID and genesis hash against the root selection |
| `codec = { version = "0.3.0", environment_independent = true }` | Do not apply a dependency-local override on this edge; retain the root chain identity for later edges |

The resolution priority is: `path` > `git` > `registry`. If `path` or `git`
is specified, the dependency is resolved locally and the `namespace` field
is ignored for resolution (but may still be used for display purposes).

**Relationship to source `use` statements**: The dependency key is a local alias.
Source code references types via their full module path (e.g.,
`use cellscript::fungible_token::Token`). The resolver maps the dependency alias
`token` to the package whose `[package] name = "fungible_token"` and
`namespace = "cellscript"`, so that the `use` statement resolves correctly.

**Key invariant**: `Cell.toml` describes deployment *intents* (what hash_type
should be), not deployment *facts* (which specific out_point was deployed to).
Intents are determined at compile time; facts are determined after deployment.

### Cell.lock — Graph, Package Unification, Compiler Compatibility, And Build Identity Lock

`Cell.lock` v5 separates mutable resolution from compilation. It records the
resolver model,
root manifest digest, root and dependency compiler requirements, the resolving
compiler release, canonical dependency nodes and outgoing alias edges,
runtime/test and environment roots, exact source/content identity, build
identity hashes, and deployment references. For an environment-selected graph,
each canonical node ID also binds the root environment name, dependency-local
environment name, selection policy, `chain_id`, and normalized genesis hash.
An outgoing edge therefore identifies both the package instance and the exact
environment decision used to build its transitive dependency set.

**Lockfile schema**:

```toml
version = 5
schema = "cellscript-lock-v0.30-single-package-coordinate-v1"
resolver_model = "single-package-coordinate-v1"

[package]
edition = "2026"
name = "amm_pool"
version = "1.2.0"
namespace = "cellscript"
source_hash = "blake2b:0xabcd..."
compiler_requirement = ">=0.26.0, <0.31.0"
resolver_compiler_version = "0.26.0"

[package_build]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
compiler_version = "0.24.0"
target_profile = "ckb"
artifact_hash = "blake2b:0x1234..."
metadata_hash = "blake2b:0x5678..."
schema_hash = "blake2b:0x9abc..."
abi_hash = "blake2b:0xdef0..."
constraints_hash = "blake2b:0x1111..."

[root]
manifest_digest = "sha256:..."

[root.dependencies]
token = "token@0.3.0|registry:...|env=default|features=default"

[root.dev_dependencies]
test_helper = "test_helper@0.1.0|path:...|env=default|features=default"

# Each entry under [dependencies] is keyed by canonical node ID and records:
# name, namespace, version, exact Path/Git/Registry source, source_hash,
# manifest_digest, compiler_requirement, resolver_compiler_version,
# outgoing alias-to-node dependencies, and optional build facts.

[environments.mainnet]
chain_id = "ckb"
genesis_hash = "0x..."

[environments.mainnet.dependencies]
token = "token@0.3.0|registry:...|env=inherit-by-chain-identity:root=...:local=...:chain=...:genesis=...|features=default"

[deployment.ckb.aggron4]
status = "deployed"
record = "ckb-testnet:0x5678..."
record_hash = "blake2b:0x9a9a..."

[deployment.ckb.mainnet]
status = "undeployed"
```

#### Package coordinates, selected instances, and unification

A package coordinate is the pair `(declared namespace, declared package
name)`. An absent namespace is a real coordinate component and does not equal
any named namespace. Dependency keys are local edge aliases, so two aliases
that reach the same coordinate do not create two package identities. Two
packages with the same name under different namespaces remain distinct.

Each selected runtime or test graph, including its feature root and CKB
environment, may contain at most one instance of a coordinate. That instance
binds one package version, one exact source identity, one manifest and source
digest, one compiler requirement, one feature selection, and one environment
selection. `resolver_model = "single-package-coordinate-v1"` makes this rule a
lockfile contract rather than an implementation assumption.

Resolution is deterministic and conservative:

- Registry resolution chooses the newest acceptable candidate for the first
  incoming edge. A later edge reuses it only when its version requirement is
  satisfied and its Registry authority is identical.
- The resolver does not backtrack. If the selected version cannot satisfy a
  later requirement, resolution fails with `E2601` and reports the coordinate,
  selected instance, conflict kind, and every incoming edge collected so far.
- Path, Git, and Registry are different source authorities. A path or Git
  checkout never silently substitutes for a Registry coordinate. Git commit,
  Registry snapshot, manifest, or compiler-requirement drift also changes the
  selected source identity.
- Feature activation is exact for this resolver generation. Incoming edges for
  one coordinate must request the same named-feature set, default-feature
  state, and all-features state. CellScript does not implicitly union divergent
  feature roots.
- Environment selection must produce the same canonical chain-identity-bound
  node identity on every incoming edge.

A source change is explicit only after the owning manifests or selected
environment overrides name the same replacement on every incoming edge and an
explicit `cellc lock` writes the new graph, or a reviewed `cellc update-plan`
is applied with `cellc update --apply-plan`. Aliases do not authorize
substitutions. Supporting multiple versions of one coordinate would
require a new resolver model, lock schema, and package-qualified source-module
identity; v5 rejects such graphs instead of silently introducing that future
semantic change.

#### LockedSource::Registry Extension

The existing `LockedSource::Registry { name, version }` is extended to carry
full git provenance, enabling re-verification without re-querying the
discovery index:

| Field | Purpose | Phase |
|---|---|---|
| `namespace` | Which namespace the package belongs to | Phase 1 |
| `registry` | Full registry path `namespace/name` | Phase 1 |
| `url` | Git repository URL (from discovery index) | Phase 1 |
| `revision` | Exact git commit hash | Phase 1 |
| `version` | Package version string | Phase 1 (existing) |

The `url` and `revision` fields make the lockfile self-sufficient for exact
materialization without re-querying discovery or selecting versions. Public
Registry revisions are snapshot SHA-256 identities; Git revisions are full
40-hex commits. Whole-tree and manifest digests are verified after
materialization.

The existing `LockedSource::Path { path }` and `LockedSource::Git { url, revision }`
are unchanged.

#### Chain-identity-safe dependency environments

Environment names are local aliases. They never propagate across package
boundaries by string equality. When the root selects `--environment`, every
dependency edge makes one deterministic choice:

```toml
# Select this exact name from the dependency's own Cell.toml. Its chain_id and
# genesis_hash must equal the root selection.
[dependencies.order]
path = "deps/order"
use_environment = "production"

# Apply no dependency-local overrides on this edge. The root chain identity is
# still carried to transitive edges and bounded external resolvers.
[dependencies.codec]
path = "deps/codec"
environment_independent = true
```

Without either field, the resolver inherits by identity: exactly one
dependency environment must match the root `chain_id` and genesis hash. A
dependency with no environment-specific overrides is safely recorded as
environment-independent when no local environment matches. A dependency that
has overrides but no match fails. Multiple matches are ambiguous and require
`use_environment`. The two fields are mutually exclusive.

Locked and frozen builds recompute this decision from the locked dependency
manifest and require the resulting canonical node ID to match the edge in
`Cell.lock`. This catches renamed or removed mappings without invoking a
resolver or choosing a replacement. External resolver requests use the
validated identity directly and never use `expect` on a dependency-controlled
environment name. Request schema `cellscript-dependency-resolver-request-v2`
separates `root_name` from the optional dependency-local `local_name`; neither
label substitutes for `chain_id` plus genesis hash.

**Cross-file binding**: The `record` field references the deployment by network
and identifier. The `record_hash` field is the Blake2b-256 hash of the
corresponding `[[deployments]]` entry in `Deployed.toml`, serialized as
**canonical JSON** (not canonical TOML). TOML has no standardized canonical
serialization; JSON does. This is consistent with the existing `metadata_hash`
computation in `src/cli/commands.rs`, which uses `ckb_blake2b256(serde_json::to_vec(&metadata))`.

The `record_hash` computation:
1. Deserialize the `[[deployments]]` TOML entry into a Rust struct.
2. Serialize the struct to canonical JSON (`serde_json::to_string` with sorted
   keys, compact, no whitespace).
3. `record_hash = ckb_blake2b256(canonical_json_bytes)`.

Phase 1 makes `record_hash` optional: if present, `cellc registry verify`
checks that it matches the actual `Deployed.toml` entry; if absent, the
verification step is skipped with a warning. Future phases may require
`record_hash` for production packages.

**No implicit backward compatibility**: readers accept only lockfile version 5
and schema `cellscript-lock-v0.30-single-package-coordinate-v1`. Explicit
`cellc lock`/`update` may replace a version 1, 2, 3, or 4 lock; build/check/test
never migrate or repin it.
`[package]` is required. When `[package_build]` exists, both `edition` and
`compatibility_profile_hash` are required fields; readers do not infer them.
The `[deployment.*]` sections may remain absent until a deployment exists.

**Key invariants**:

- `Cell.lock` is the cryptographic bind point between source and deployment.
- Any hash mismatch between `Cell.lock`, compiled artifacts, and `Deployed.toml`
  records causes fail-closed rejection.
- The `[deployment.*]` section references deployment records in `Deployed.toml`
  by network. It does not duplicate the full deployment facts; those live in
  `Deployed.toml`.
- Stale or mismatched artifact/metadata/deployment hashes fail closed.

### Deployed.toml — Deployment Fact Record (New)

`Deployed.toml` is the CKB analogue of Move/Sui's `Published.toml`. It is
generated from locally verified deployment evidence after the externally signed
transaction is confirmed, and records immutable deployment facts derived from
the chain.

#### Who Generates and Manages Deployed.toml

`Deployed.toml` must be generated by deployment orchestration after wallet
signing, broadcast, commitment, and live-output verification. The current
`cellscript-deploy build-deploy` command only builds an unsigned transaction;
it does not claim to generate a committed deployment record.

The adapter architecture is headless-first: artifact and transaction facts are
computed locally before signing. Chain identity, input liveness, the committed
transaction, and the resulting live output still have to be verified against
RPC; a returned `tx_hash` alone is not sufficient chain evidence.

**Generation flow**:

```
1. cellc build
   → produces artifact, metadata, constraints, schema, ABI
   → all build hashes computed locally (artifact_hash, metadata_hash,
     schema_hash, abi_hash, constraints_hash)

2. resolve live input + build_deploy_transaction(spec)
   → verifies mainnet genesis and a live pure-capacity input
   → headless builder computes the immutable data2 hash, code_hash,
     occupied capacity, change output locally
   → returns (TransactionView, ResolvedDeployEvidence)
   → evidence already contains: code_hash, hash_type, type_id_args,
     artifact_hash, occupied_capacity, tx_size

3. external wallet signing + submit + wait_for_commitment
   → wallet replaces the standard zeroed secp witness placeholder
   → sends the signed transaction through full node RPC
   → waits for committed status
   → receives tx_hash from the node response

4. verify committed transaction + live output
   → re-reads the transaction and code Cell from mainnet RPC
   → checks output index, lock, optional Type Script, artifact bytes, and data hash

5. build_deployment_manifest_from_evidence(evidence, tx_hash, output_index)
   → constructs DeploymentManifest only after the chain checks succeed
   → extends to Deployed.toml by adding network, chain_id, build section,
     and Cell.lock record_hash
```

**Why committed-output verification is required**: local construction proves
what the tool intended to build, not what a wallet ultimately signed or what
the chain committed. `get_transaction` and `get_live_cell` close that gap and
make the deployment record independently checkable.

**Verification path**: `cellc registry verify` checks that `Deployed.toml`
matches the package/build identity recorded in `Cell.lock`; `cellc registry
verify --live --rpc-url <URL>` additionally calls `get_live_cell` and verifies
the referenced live code Cell. Deployment orchestration must run the live mode
before treating a newly generated record as chain evidence.

**Data source requirement**: off-chain registry verification does not require a
CKB RPC endpoint. Mainnet deployment construction, commitment evidence, and
live-chain verification do require one. Light-client support remains a possible
later enhancement.

**Immutability**: Once generated, `Deployed.toml` must not be modified. Any
re-deployment or upgrade produces a new `[[deployments]]` entry with a distinct
set of chain facts, not an edit to an existing entry.

```toml
version = 2
schema = "cellscript-deployed-v0.23-edition-2026"

[package]
edition = "2026"
name = "amm_pool"
version = "1.2.0"
source_hash = "blake2b:0xabcd..."

[build]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
compiler_version = "0.21.0"
artifact_hash = "blake2b:0x1234..."
metadata_hash = "blake2b:0x5678..."
schema_hash = "blake2b:0x9abc..."
abi_hash = "blake2b:0xdef0..."
constraints_hash = "blake2b:0x1111..."

[[deployments]]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
network = "mainnet"
chain_id = "ckb-mainnet"
script_role = "type"
tx_hash = "0xaaaa..."
output_index = 0
code_hash = "0xbbbb..."
hash_type = "data2"
dep_type = "code"
out_point = "0xaaaa...:0"
data_hash = "0xcccc..."

[[deployments.cell_deps]]
name = "secp256k1"
tx_hash = "0xeeee..."
output_index = 1
dep_type = "dep_group"
hash_type = "type"

[[deployments]]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
network = "ckb-mainnet"
chain_id = "ckb-mainnet"
script_role = "type"
status = "candidate"
```

**Relationship to existing `DeploymentManifest`**: The current
`DeploymentManifest` type in `crates/cellscript-ckb-adapter/src/lib.rs` has
`DeploymentRef` with `name/code_hash/hash_type/args/dep_type/out_point`.
`Deployed.toml` is an enhanced deployment manifest that adds:

- `network` and `chain_id` — which chain this deployment targets
- `script_role` — lock, type, dual-role, or helper dependency
- `data_hash` — the data hash of the deployed code cell
- `type_id` — TYPE_ID upgrade lineage where applicable
- `status` — deployment lifecycle state
- The full `[build]` section — binding the deployment to build identity

The adapter crate's `DeploymentManifest` is a separate transaction-adapter
configuration format. Package `Deployed.toml` readers accept only version 2
with schema `cellscript-deployed-v0.23-edition-2026`; they do not reinterpret
the adapter's historical `cellscript-ckb-deployment-manifest-v0.19` identity as
a package deployment record.

## End-to-End Package Lifecycle

This section traces a package through its complete lifecycle, showing how
`Cell.toml`, `registry.json`, `Cell.lock`, and `Deployed.toml` interact at
each stage.

### Stage 1: Authoring

A developer creates a new package:

```bash
cellc init amm_pool --namespace cellscript
```

This generates:

```toml
# Cell.toml
[package]
name = "amm_pool"
version = "0.1.0"
namespace = "cellscript"
entry = "src/main.cell"
```

Source code uses the module declaration consistent with the namespace:

```
// src/main.cell
module cellscript::amm_pool

use cellscript::fungible_token::Token
```

At this stage, there is no `Cell.lock`, no `registry.json`, and no
`Deployed.toml`. The package is purely local.

### Stage 2: Adding Dependencies

The developer adds a registry dependency:

```toml
# Cell.toml
[dependencies]
token = { version = "0.3.0", namespace = "cellscript" }
```

Running `cellc build` triggers dependency resolution:

1. Read `Cell.toml` `[dependencies]` → find `token` with `namespace = "cellscript"`.
2. Query `https://api.registry.cellscript.dev/v1/artifacts/cellscript/token`.
3. Require the `cellscript_source` profile and `dependency` consumption mode,
   then select an eligible verified release.
4. Download its immutable source snapshot from the static Registry origin.
5. Verify the snapshot object identity, package coordinate, file hashes,
   Edition, compatibility-profile identity, and whole-tree source hash.
6. Materialize the verified source into the dependency cache.
7. Parse the dependency's `Cell.toml` → resolve transitive dependencies.
8. Write `Cell.lock` with resolved versions and git provenance.

`CELLSCRIPT_REGISTRY_URL` deliberately selects the legacy Git/offline discovery
authority for private mirrors, tests, and audits. It is not an automatic
fallback when the production API is unavailable.

Generated `Cell.lock`:

```toml
version = 2

[package]
edition = "2026"
name = "amm_pool"
version = "0.1.0"
namespace = "cellscript"
source_hash = "blake2b:0xabcd..."

[package_build]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
compiler_version = "0.21.0"
target_profile = "ckb"
artifact_hash = "blake2b:0x1234..."
metadata_hash = "blake2b:0x5678..."
schema_hash = "blake2b:0x9abc..."
abi_hash = "blake2b:0xdef0..."
constraints_hash = "blake2b:0x1111..."

[dependencies.token]
version = "0.3.2"
namespace = "cellscript"
source = { registry = "cellscript/token", url = "https://registry.cellscript.dev/source-snapshots/cellscript/token/0.3.2/<sha256>.json", revision = "sha256:<snapshot-hash>" }
source_hash = "blake2b:0x2222..."
build = { artifact_hash = "blake2b:0x3333...", abi_hash = "blake2b:0x4444..." }
```

Key property: `Cell.lock` is **self-sufficient** for re-verification. For the
public Registry, `url` names the immutable source snapshot and `revision` is its
`sha256:` identity. Explicit Git/offline resolution retains a Git URL and
commit revision. Neither path needs to re-query a mutable discovery index to
identify the already locked bytes.

### Stage 3: Publishing

The developer publishes a new version:

```bash
cellc publish --authorise  # first interactive publish
cellc publish              # later publishes with the active delegated key
```

This automatically:

1. For `--authorise`, registers a wallet-authorised delegated capability key
   and claims or reviews the namespace through the short-lived browser session.
2. Reads `Cell.toml` -> gets `name`, `namespace`, `version`.
3. Computes `source_hash` from the current source tree.
4. Reads build artifacts for `artifact_hash`, `abi_hash`, `schema_hash`, etc.
5. Signs a concrete publish payload with the local capability key from the OS
   keychain, or with an externally supplied CI signature.
6. Uploads an immutable source snapshot.
7. Submits the entry to the registry write API for ACL, schema, hash, size,
   idempotency, quota, and duplicate checks.
8. Creates a canonical registry entry in `source_published` or
   `indexed_pending` state.

Capability revocation is also wallet-bound:

```bash
cellc auth capability revoke --principal-id <principal_id> --capability-key-id <capability_key_id> --json > revoke-payload.json
cellc auth capability revoke --payload revoke-payload.json --wallet-signature wallet-signature.json --reason "rotate delegated key"
```

The explicit signing flow is:

```bash
cellc publish --print-payload --json > publish-payload.json
# sign the canonical_payload field with the authorised capability key
cellc publish --payload publish-payload.json --capability-signature <signature>
```

The same version entry can be mirrored into `registry.json` in the source repo
for audit, offline fixtures, and direct-Git fallback:

```json
{
  "name": "amm_pool",
  "namespace": "cellscript",
  "versions": [
    {
      "version": "1.2.0",
      "tag": "v1.2.0",
      "source_hash": "blake2b:0xabcd...",
      "cellscript_version": "0.24.0",
      "dependencies": {
        "token": { "namespace": "cellscript", "version": "0.3.0" }
      },
      "abi_index": "blake2b:0xdef0...",
      "schema_hash": "blake2b:0x9abc...",
      "license": "MIT",
      "released_at": "2026-05-06T00:00:00Z",
      "yanked": false
    }
  ]
}
```

Then the developer may commit and tag the mirrored metadata:

```bash
cellc publish --offline
git add registry.json
git commit -m "publish v1.2.0"
git tag v1.2.0
git push --tags
```

No separate registry account is needed. The wallet-rooted publisher identity
authorises the local credential, and the registry ACL decides whether that
credential may publish to the namespace/package. No PR to the
`cellscript-registry` discovery index is needed for ordinary version updates;
discovery changes are for package claims, source-location changes, and
ownership metadata.

### Stage 4: Deploying

The current adapter CLI builds a mainnet transaction candidate for external
wallet signing:

```bash
cellscript-deploy --rpc <MAINNET_RPC> --json build-deploy \
  --artifact <ARTIFACT_ELF> \
  --lock-arg <SECP_BLAKE160> \
  --hash-type data2 \
  --capacity-out-point 0x<LIVE_PURE_CAPACITY_TX_HASH>:<INDEX>
```

This triggers the implemented construction boundary:

1. `cellc build` → produces artifact, metadata, constraints, schema, ABI.
2. The CLI verifies mainnet genesis and the selected live pure-capacity Cell.
3. `build_deploy_transaction(spec)` computes deployment facts locally and emits
   `can_submit: false` with the unsigned transaction.
4. A wallet signs and broadcasts the transaction.
5. Deployment orchestration waits for commitment, verifies the live output,
   then calls `build_deployment_manifest_from_evidence` and updates `Cell.lock`.

Steps 4–5 are external orchestration today; the CLI does not claim that an
unsigned build is a deployment or automatically write `Deployed.toml`.

Generated `Deployed.toml`:

```toml
version = 2
schema = "cellscript-deployed-v0.23-edition-2026"

[package]
edition = "2026"
name = "amm_pool"
version = "1.2.0"
source_hash = "blake2b:0xabcd..."

[build]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
compiler_version = "0.21.0"
artifact_hash = "blake2b:0x1234..."
metadata_hash = "blake2b:0x5678..."
schema_hash = "blake2b:0x9abc..."
abi_hash = "blake2b:0xdef0..."
constraints_hash = "blake2b:0x1111..."

[[deployments]]
edition = "2026"
compatibility_profile_hash = "blake2b:0xprofile..."
network = "aggron4"
chain_id = "ckb-testnet"
script_role = "type"
tx_hash = "0xaaaa..."
output_index = 0
code_hash = "0xbbbb..."
hash_type = "data2"
dep_type = "code"
out_point = "0xaaaa...:0"
data_hash = "0xcccc..."
type_id = "0xdddd..."
```

Updated `Cell.lock` deployment section:

```toml
[deployment.ckb.mainnet]
status = "deployed"
record = "ckb-mainnet:0xaaaa..."
record_hash = "blake2b:0x9a9a..."
```

### Stage 5: Consuming as a Dependency

Another developer uses `amm_pool` as a dependency:

```toml
# their project's Cell.toml
[dependencies]
amm = { version = "1.2.0", namespace = "cellscript" }
```

Resolution flow:

1. Query the public Registry API and require an accepted `cellscript/amm_pool`
   version with a source repository, tag, source hash, Edition, and profile
   identity.
2. Clone at the accepted tag `v1.2.0` → read `registry.json` → match the
   accepted identity → verify `source_hash`.
3. Read the dependency's `Cell.lock` (if present) →
   find deployment record for `mainnet` →
   `code_hash`, `out_point`, `data_hash` available for builder verification.
4. Write the consumer's `Cell.lock` with resolved versions and git provenance.

The consumer's builder can now verify the full identity chain:
source → build → deployment, all bound by cryptographic hashes in
`Cell.lock`.

### File Interaction Summary

```
                         ┌─────────────┐
                         │  Cell.toml   │
                         │  (source)    │
                         └──────┬───────┘
                                │
                    cellc build │ + cellc install
                                │
                    ┌───────────▼───────────┐
                    │      Cell.lock         │
                    │  (build identity)      │
                    │  - source_hash         │
                    │  - artifact_hash       │
                    │  - registry url+rev    │
                    └───────────┬───────────┘
                                │
                    cellc deploy│ + confirm
                                │
                    ┌───────────▼───────────┐
                    │    Deployed.toml       │
                    │  (deployment facts)    │
                    │  - code_hash           │
                    │  - out_point           │
                    │  - data_hash           │
                    └────────────────────────┘


     Public Registry API        Source Repository
     (accepted status)          (github.com/cellscript/amm_pool)
     ┌─────────────────┐       ┌──────────────────────────────────┐
     │ /v1/artifacts/  │       │ Cell.toml                        │
     │ cellscript/     │──────►│ registry.json   ← offline mirror │
     │ amm_pool        │       │ src/                             │
     └─────────────────┘       │ Cell.lock       ← cellc build    │
                               │ Deployed.toml   ← cellc deploy   │
                               └──────────────────────────────────┘
```

The public Registry maps `namespace/name` → accepted version/status and source
repository identity. The legacy Git discovery index can supply the equivalent
source map only when explicitly selected for offline/private-mirror use.
The source repository contains everything else: source code, version index
(`registry.json`), build identity (`Cell.lock`), and deployment facts
(`Deployed.toml`). The public registry service is the write authority for
`cellc publish`; the source repository and `registry.json` mirror are the
audit/offline path. This preserves the Go-style source layout without making
Git push permissions the registry's public write authority.

## Deployment Record Field Classification

Fields are classified by necessity:

### Required Fields (Phase 1 — minimum for deploy verifiable)

| Field | Purpose |
|---|---|
| `network` | Which network this deployment targets |
| `chain_id` | Chain identifier |
| `tx_hash` | Deployment transaction hash |
| `output_index` | Output index in deployment transaction |
| `code_hash` | Script identity |
| `hash_type` | data / type / data1 / data2 |
| `dep_type` | code / dep_group |
| `data_hash` | Artifact data hash |
| `out_point` | CellDep reference |

### Recommended Fields (Phase 1 — build provenance binding)

| Field | Purpose |
|---|---|
| `artifact_hash` | RISC-V binary hash |
| `metadata_hash` | Compiler metadata hash |
| `schema_hash` | Schema manifest hash |
| `abi_hash` | ABI hash |
| `constraints_hash` | Constraints report hash |
| `compiler_version` | Compiler version that produced the artifact |

### Optional Fields (Phase 2 — governance and upgrade)

| Field | Purpose |
|---|---|
| `type_id` | TYPE_ID upgrade lineage |
| `script_role` | lock / type / dual-role / helper |
| `status` | active / candidate / deprecated / revoked |
| `upgrade_lineage` | TYPE_ID upgrade chain |
| `audit_report_hash` | Audit report hash |
| `publisher_signature` | Publisher identity signature |

### Deployment Status Lifecycle

```
                 deploy to network
  (undeployed) ─────────────────────► candidate
                                      │
                          confirm +   │  revoke or
                          audit pass  │  supersede
                                      ▼               ▼
                                    active          deprecated
                                      │
                          supersede   │
                                      ▼
                                    deprecated
                                      │
                          revoke     │
                                      ▼
                                    revoked
```

A deployment record must not be treated as production-ready until its status
reaches `active`. The `candidate` state allows builders to preview and dry-run
against a deployment, but production transaction construction should require
`active` status unless explicitly overridden.

## Source Package Registry (Off-Chain)

### Design Choice: Registry Write Service, Static Read Surface

The public registry uses an authenticated write service and a static,
cache-friendly read surface. The data model remains inspired by Go's approach
(source lives in its own repo, metadata can travel with the source), but the
public write authority is the registry service, not Git push access.

1. **Public package index** — the deployed API maps `namespace/name` to public
   versions, accepted/suppressive status, source repository identity, Edition,
   profile hash, and evidence. It is updated by authenticated namespace,
   publish, governance, and promotion operations.
2. **Per-package version index** — a canonical registry entry mirrored as
   `registry.json` for audit, offline fixtures, and direct-Git fallback. The
   public entry is updated by authenticated `cellc publish`; the local mirror is
   written explicitly with `cellc publish --offline`.

Rationale:

- Does not block the v0.12 stable release.
- `cellc publish` has the expected package-registry semantics: after successful
  authentication and queue admission, the registry has a new addressable entry.
- The read path can remain CDN/static and independently verifiable.
- Git/source mirrors remain valuable for audit, local fixtures, and fallback.
- Namespace ownership, maintainer ACLs, yanking, quarantine, quotas, and abuse
  controls need one authoritative write boundary.
- The CKB ecosystem can start with a small write service because expensive
  verification work is asynchronous and bounded.

### Legacy/Offline Discovery Index Repository

A Git repository (e.g., `github.com/cellscript/cellscript-registry`) can serve
as the explicit `CELLSCRIPT_REGISTRY_URL` private/offline discovery authority.
It is not consulted automatically after a failed production API lookup. It is
organized by namespace:

```
cellscript-registry/
├── _schema.json               # { "schema_version": 1 }
├── cellscript/
│   ├── amm.json
│   └── token.json
└── other-protocol/
    └── swap.json
```

Each entry contains only the package name, namespace, and source repository
URL — no version details:

```json
{
  "name": "amm",
  "namespace": "cellscript",
  "source": "https://github.com/cellscript/amm"
}
```

This file is created or updated when a package is claimed, transferred, or
moved. Subsequent version releases do not require a discovery update unless
the source location or ownership metadata changes.

### Per-Package Version Index (registry.json)

The registry service stores the canonical per-package version entry. The same
shape can be mirrored to a `registry.json` file at the source repository root,
alongside `Cell.toml`, for audit and offline use:

```json
{
  "schema_version": 1,
  "name": "amm",
  "namespace": "cellscript",
  "versions": [
    {
      "version": "1.2.0",
      "tag": "v1.2.0",
      "source_hash": "blake2b:0xabcd...",
      "cellscript_version": "0.19.0",
      "edition": "2026",
      "compatibility_profile_hash": "42d297cd7879917ade58c89cdc5dcbbb38a5d39b720788387db80e918a3f7fd9",
      "dependencies": {
        "token": { "namespace": "cellscript", "version": "0.3.0" }
      },
      "abi_index": "blake2b:0xdef0...",
      "schema_hash": "blake2b:0x9abc...",
      "license": "MIT",
      "released_at": "2026-04-24T00:00:00Z",
      "status": "source_published",
      "yanked": false,
      "audit": {
        "report_hash": "blake2b:0x5555...",
        "acceptance_gate": "passed"
      }
    }
  ]
}
```

This is the registry's initial source-edition/profile shape. `edition` must not
be used to infer a target or ABI; `compatibility_profile_hash` binds those
independent choices. The production Registry deployed this initial schema on
2026-07-31. `migrations/0001_initial.sql` is therefore frozen; later database
changes use additive numbered migrations rather than rewriting the deployed
baseline. Every non-optional field shown above is required; readers do not fill
in omitted `dependencies`, `status`, or `yanked` values.

The `tag` field maps each version to a git tag in the source repository.
This allows `cellc install` to clone the exact commit without needing
a separate archive storage layer.

### Publishing Flow

```bash
# Interactive first use, or after credential expiry/revocation
cellc publish --authorise

# Later publish with an active delegated key
cellc publish
# → reads Cell.toml
# → computes source_hash from current source tree
# → reads build artifacts for abi_hash, schema_hash, etc.
# → signs publish payload with the local publisher credential
# → submits to the registry write API
# → returns canonical registry URL and an initial entry state

# Optional audit/offline mirror
cellc publish --offline
git add registry.json
git commit -m "publish v1.2.0"
git tag v1.2.0
git push --tags
```

No PR to an external registry repository is required for ordinary version
updates. The production Registry entry is authoritative for public discovery
and status, while the source repository mirror lets consumers audit the same
identity when `cellc install` clones the accepted tag. The legacy Git discovery
index remains an explicit offline/private-mirror override rather than an
ordinary production dependency.

Initial entry visibility is staged:

```text
source_published  -> direct URL and author dashboard visible
indexed_pending   -> waiting for asynchronous verifier/indexer workers
verified_build    -> build evidence accepted
deployed          -> deployment facts attached and verified locally
on_chain_committed -> sufficiently confirmed live Registry commitment Cell
deprecated/yanked -> historical entry retained, default resolution suppressed
quarantined       -> direct URL retained, default search suppressed
```

The default resolver must not automatically select `source_published`,
`indexed_pending`, or `quarantined` entries. Direct installs may target those
entries only with an explicit risk flag such as `--allow-unverified`; quarantine
requires a stronger explicit flag such as `--allow-quarantined`. Default search,
recommendations, and production-visible package lists only include entries that
passed the required baseline checks.

A mirrored `registry.json` version entry with no `status`, `dependencies`, or
`yanked` field is malformed. Public registry writes and offline mirrors emit
the same complete entry shape.

### Installation Flow

```bash
# Install a package from the registry
cellc install cellscript/amm@1.2.0
```

Internally:

1. Query the production public API for `cellscript/amm`.
2. Select version `1.2.0` only if its public status is accepted for ordinary
   resolution; suppressive and pre-verification states fail closed.
3. Read the immutable source-snapshot descriptor, source hash, Edition, and
   profile hash from the accepted record.
4. Download the snapshot without redirects and enforce its declared size.
5. Verify the object SHA-256, safe/unique file paths, and every file's BLAKE2b.
6. Atomically materialize the tree and verify the complete `source_hash`.
7. Parse `Cell.toml`, check package identity, and resolve transitive
   dependencies. Repository URL, tag, and mirrored `registry.json` remain audit
   material; they are used as the resolver authority only under the explicit
   Git/offline override.

### Write Path DDoS and Spam Boundary

Once `cellc publish` writes to the public registry, the write API is part of
the security boundary. The read and write paths must stay separate:

```text
registry.cellscript.dev
  -> static website
  -> cached JSON indexes
  -> immutable mirrored metadata / artifact URLs

api.registry.cellscript.dev
  -> TLS proxy body limits
  -> schema fail-fast
  -> auth, ACL, application quota and deduplication
  -> object storage
  -> bounded verification queues
```

Synchronous publish checks must remain cheap:

- signature, nonce, expiry, origin, and credential revocation;
- namespace/package ownership and scoped permission checks;
- request body size, metadata field length, tarball/artifact size caps;
- manifest/schema validation;
- `source_hash` / `manifest_hash` sanity and duplicate-hash rejection;
- idempotency keys for retry-safe publishes;
- per IP, ASN, wallet principal, credential, namespace, and package quotas.

Expensive work is asynchronous:

- source mirror fetches;
- full build reproduction;
- artifact, ABI, schema, and constraint verification;
- deployment-fact verification;
- chain RPC reads;
- search indexing and ranking.

Wallet signatures are identity evidence, not an anti-spam mechanism by
themselves. New namespace claims, high-volume publishing, typosquatting-risk
names, and on-chain deployment attestations may require cooldown, review, or
community challenge. The first production source-package write path does not
require an on-chain fee or bond, but the schema and policy hooks must allow
later fee, refundable-deposit, or challengeable-record rules for higher-risk
actions. Suspicious packages move to quarantine rather than being silently
deleted, so exact pins and incident reviews remain reproducible.

### CLI Integration

```bash
# Manual/CI authorisation path for either supported principal type
cellc auth capability create --principal-type <joyid_ckb|ckb_secp256k1> --principal-id <principal_id> \
  --scope publish:cellscript/amm \
  --scope deployment:cellscript/amm \
  --scope availability:cellscript/amm \
  --expires 90d --json > capability-payload.json
cellc auth capability submit --payload capability-payload.json --wallet-signature wallet-signature.json
cellc auth namespace claim --namespace cellscript --payload capability-payload.json --wallet-signature wallet-signature.json

# Or use the short interactive path, which resumes the publish automatically
cellc publish --authorise

# Optional local/offline discovery mirror
cellc registry add --namespace cellscript --name amm --source https://github.com/cellscript/amm

# Yank an existing version while preserving exact-pin warning metadata
cellc registry edit --yank 1.2.0 --reason "security advisory" --replaced-by 1.2.1

# Install from the source registry
cellc install cellscript/amm@1.2.0

# Verify package integrity against source and build artifacts
cellc package verify

# Verify deployment identity against chain facts
cellc registry verify
```

The `resolve_from_registry` path in `src/package/mod.rs` implements two explicit
source-package authorities. By default, the production public API supplies the
accepted status, signed identity, and immutable snapshot descriptor; the client
verifies and materializes that snapshot. An explicitly configured
`CELLSCRIPT_REGISTRY_URL` instead supplies the legacy Git/offline index, tag,
and mirrored `registry.json`. Both paths finish with `source_hash`, `Cell.toml`,
and transitive-dependency verification. A lookup failure reports the namespace,
package, requested version, and authority instead of silently downgrading to
Git discovery.

## Deployment Registry (Chain-Indexed)

### Design Choice: Off-Chain First, Chain-Indexed When Needed

**Phase 1**: Pure off-chain `Deployed.toml` records, verified through
`Cell.lock` hash binding.

**Phase 2**: Optional on-chain type script index, driven by ecosystem demand.

Rationale:

- CKB capacity costs make on-chain source-package storage unattractive.
- Deployment facts through `Deployed.toml` + `Cell.lock` hash binding are
  sufficient for builder-level verification.
- An on-chain index script adds complexity and should be driven by actual
  ecosystem demand, not speculative design.

### Builder Verification Flow

The builder must verify the full identity chain before constructing a
production transaction:

```
cellc build
  → generates artifact, metadata, schema, abi, constraints
  → writes Cell.lock [package_build]

cellc deploy plan
  → reads Cell.lock [package_build]
  → reads Cell.toml [deploy.ckb] intent
  → produces deployment plan JSON

After deployment transaction is confirmed on-chain
  → generates Deployed.toml (chain facts)
  → updates Cell.lock [deployment.ckb.<network>]

cellc registry verify
  → reads Cell.lock build hashes
  → reads Deployed.toml deployment facts
  → verifies:
    1. source_hash matches between Cell.lock and Deployed.toml
    2. artifact_hash matches between Cell.lock and Deployed.toml
    3. data_hash = blake2b(artifact) against on-chain code cell
    4. code_hash in Deployed.toml matches on-chain script
    5. out_point is reachable as CellDep
    6. schema_hash / abi_hash consistent with metadata
    7. constraints_hash consistent with constraints report
  → any mismatch → FAIL CLOSED
```

### Action Builder Integration

The CellScript Action Builder is now the v0.20 target. It consumes the 0.19
package/build/deployment identity through the `registry-client` module:

```
┌──────────────┐     ┌──────────────────┐     ┌───────────────┐
│ metadata-    │     │ registry-client  │     │ cell-resolver │
│ loader       │────►│                  │────►│               │
│              │     │ resolve package  │     │ select live   │
│ load/validate│     │ resolve deploy   │     │ cells via     │
│ metadata,    │     │ verify hashes    │     │ CCC/indexer   │
│ ABI, recipe  │     │ against lockfile │     │               │
└──────────────┘     └──────────────────┘     └───────────────┘
```

For 0.20 builder work, the `registry-client` module is responsible for:

1. Resolving package records from the source registry index.
2. Resolving deployment records from `Deployed.toml`.
3. Verifying that resolved hashes match `Cell.lock`.
4. Rejecting hash mismatches, missing ABI records, and incompatible metadata
   schema versions.

The Action Builder must not accept a package by name alone. It must verify that
the resolved source package, build artifact, constraints report, and deployment
identity all match the 0.19 lockfile/provenance records before it constructs a
transaction.

## Integration With Existing Code

### Files That Change

| Component | Current | Change |
|---|---|---|
| `PackageInfo` | In `src/package/mod.rs`, no `namespace` field | Add `namespace: String` with `#[serde(default)]`. Required for `cellc publish`; absent means local-only package. |
| `DetailedDependency` | In `src/package/mod.rs`, no `namespace` field | Add `namespace: Option<String>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`. Used for explicit registry resolution. |
| `PackageManifest` | `Cell.toml` schema | Unchanged structure. `[deploy.ckb]` already supported. `namespace` flows through `PackageInfo`. |
| `Lockfile` | `version/dependencies` only | Extend with `[package_build]`, `[deployment.*]`, `namespace`, `source_hash` on dependencies. |
| `LockedDependency` | `version` + `source` only | Add `namespace: Option<String>`, `source_hash: Option<String>`, `build: Option<LockedBuildInfo>`. All with `#[serde(default)]`. |
| `LockedSource::Registry` | `{ name, version }` only | Extend to `{ namespace, name, version, url, revision }`. Public resolution records the immutable snapshot URL and SHA-256 revision; explicit Git/offline resolution records Git provenance. |
| `DeploymentManifest` | In `crates/cellscript-ckb-adapter/src/lib.rs` | Extend to `Deployed.toml` schema: add `network`, `chain_id`, `script_role`, `data_hash`, `status`, `[build]` section. |
| `DeploymentRef` | In adapter crate | Add `network`, `chain_id`, `script_role`, `data_hash`, `status` fields as `Option<String>`. |
| `PackageManager::resolve_from_registry` | Implemented public-API accepted-status lookup → immutable snapshot size/object/file/path/source verification → atomic cache materialisation → Edition/profile and `Cell.toml` checks. The explicit Git/offline override retains tag + `registry.json` verification. | Keep non-CellScript artifact profiles fail-closed until profile-specific resolver contracts exist. |
| `build_deployment_manifest_from_evidence` | In adapter crate | Extend to populate new fields. |
| `ManifestCellDepResolver` | In adapter crate | Unchanged. Still resolves CellDeps from manifest. |

### constraints_hash Generation

The `constraints_hash` field is critical for deployment safety: it binds the
deployment to the exact set of constraints the compiler generated, preventing
a compromised constraints report from being substituted after deployment.

**Phase 1 approach — same-version stability**: `cellc build` generates
`constraints_hash` using the same method as the existing `metadata_hash`
computation:

```
constraints_hash = ckb_blake2b256(serde_json::to_vec(&constraints))
```

This matches the existing pattern in `src/cli/commands.rs` where
`metadata_hash` is computed as `ckb_blake2b256(serde_json::to_vec(&result.metadata))`.

**Determinism guarantees in Phase 1**:
- Same compiler version + same source + same compile options → same
  `ConstraintsMetadata` struct → same `serde_json::to_vec` output → same
  `constraints_hash`. This is sufficient for Phase 1 because `constraints_hash`
  is only compared within the same compiler version.
- The `ConstraintsMetadata` struct fields are ordered by Rust struct field
  definition order, which is stable within a compiler version.
- Vec fields (`entry_abi`, `runtime_errors`, `warnings`, `failures`) are
  emitted in the compiler's internal iteration order, which is deterministic
  for the same input within the same compiler version.

**Known limitation**: Cross-compiler-version `constraints_hash` comparison is
not supported and should not be attempted. The `metadata_schema_version` field
in `CompileMetadata` serves as the envelope version gate, and
`constraints_metadata_schema_version` gates the constraints surface specifically
-- if schema versions differ, verification must reject the comparison, not
attempt hash matching.

**Phase 2 enhancement**: For stronger cross-build determinism (e.g.,
verifying that two independent builds of the same source produce the same
`constraints_hash`), the `ConstraintsMetadata` struct should:
- Sort all `Vec` fields by a stable key (`entry_name`, `code`, etc.)
- Replace any `HashMap` with `BTreeMap` for key ordering
- Pin the `serde_json` serialization to compact output with sorted keys

These hashes are deterministic within their explicitly versioned schemas and
the resolved compatibility profile; they are not derived from the edition year.

### Edition 2026 Breaking Boundary

- `Cell.lock` version 5 records the package edition, compiler requirement,
  resolving compiler release, and manifest-bound source graph. A present
  `[package_build]` must use the same edition and a non-empty compatibility
  profile hash.
- `Deployed.toml` version 2 uses
  `cellscript-deployed-v0.23-edition-2026`. Package, build, and every deployment
  record must agree on edition and compatibility profile.
- Readers reject version 1 and the old deployment schema. They do not migrate,
  fill defaults, or compute both old and new hashes.
- Registry versions and generated builders bind the same edition/profile
  identity, so a partial upgrade fails closed before transaction construction.

## Version Control Audit

### Audit Findings

The document covers three layers of identity (Package, Build, Deployment) but
has gaps in version control across multiple dimensions. This section documents
the gaps and the resolutions adopted.

#### 1. Package Version Semver Rules

**Gap**: The document shows `version = "0.3.0"` in dependencies but does not
define what this means. Is it `^0.3.0` (compatible) or `=0.3.0` (exact)?
What constitutes a breaking change for a CellScript package?

**Resolution**: Adopt Cargo's semver convention:

- `"0.3.0"` means `^0.3.0` (any `0.3.x`, not `0.4.0`)
- `"=0.3.0"` means exact version
- `"*"` means any version
- `">=0.3.0, <0.4.0"` means range

The existing `VersionReq` enum in `src/package/mod.rs` already implements
this. No code change needed; the document should reference this convention.

**Breaking change definition for CellScript**:

| Change | Breaking? |
|---|---|
| New action | No |
| New shared type field | No (additive) |
| Removed action | Yes |
| Removed shared type field | Yes |
| Changed action signature | Yes |
| Changed ABI layout | Yes |
| New dependency | No |
| Changed dependency version (major) | Yes |

#### 2. Cell.lock Version — Dual Version Identifier

**Gap**: `version = 1` and `lock_schema = "cellscript-lock-v1"` are redundant.
No migration path is defined between lockfile schema generations.

**Resolution**: `Cell.lock` version 5 with
`cellscript-lock-v0.30-single-package-coordinate-v1` is the sole accepted build-time
lock generation. Readers reject older versions and never rewrite them
implicitly; explicit lock/update may repin versions 1 through 4. Edition and
compatibility profile remain part of build identity, while compiler
requirements, resolver compiler releases, root/dependency manifest digests,
the declared `single-package-coordinate-v1` resolver model, and graph edges
form dependency identity.

#### 3. Deployed.toml Schema — Dual Version Identifier

**Gap**: `version = 1` and `schema = "cellscript-deployed-v0.19"` serve
overlapping purposes. The `schema` string ties the format to a specific
cellscript version, but format evolution is independent of compiler
version.

**Resolution**: Package deployment records require both `version = 2` and
`schema = "cellscript-deployed-v0.23-edition-2026"`. The redundancy is
intentional fail-closed evidence: one identifies the structural generation and
the other the semantic edition boundary. The adapter's historical deployment
manifest is a different format and is not accepted as `Deployed.toml`.

#### 4. registry.json Dependencies Missing Namespace

**Gap**: The `dependencies` field in `registry.json` uses
`{ "token": "0.3.0" }` — no namespace information. A consumer cannot
determine which namespace `token` belongs to.

**Resolution**: Change the dependencies format to include namespace:

```json
"dependencies": {
  "token": { "namespace": "cellscript", "version": "0.3.0" }
}
```

This matches the Cell.toml dependency syntax and enables unambiguous
resolution without consulting the discovery index.

#### 5. registry.json Format Version

**Gap**: No schema version identifier in `registry.json`. If the format
needs to change (e.g., add a `replaced_by` field for yanking), the
parser cannot distinguish old vs new format.

**Resolution**: Add a `schema_version` field:

```json
{
  "schema_version": 1,
  "name": "amm_pool",
  "namespace": "cellscript",
  "versions": [...]
}
```

#### 6. Compiler Version Compatibility Window

**Gap**: No defined compatibility window. Different `cellc` versions may
produce different `constraints_hash` for the same source.

**Resolution**: Define a compatibility rule:

- Same major.minor version (e.g., `0.19.x`) → `constraints_hash` is
  expected to be identical for the same source + same compile options.
- Different major.minor → `constraints_hash` may differ; verification
  must not attempt cross-version hash comparison.
- The `metadata_schema_version` field in `CompileMetadata` serves as the
  envelope version gate, and `constraints_metadata_schema_version` gates the
  constraints surface specifically.

This is already partially documented in the `constraints_hash Generation`
section, but the rule should be stated more explicitly as a version
compatibility policy, not just a known limitation.

#### 7. ABI Compatibility Model

**Gap**: `abi_hash` and `schema_hash` are content hashes. They can tell
you two ABIs are identical, but not whether they are compatible.

**Resolution**: Phase 1 treats `abi_hash` as an exact match gate: if the
hash differs, the ABIs are considered incompatible. Phase 2 may introduce
ABI compatibility checking (e.g., structural subtyping for additive
changes). This is deferred because:

- For deployed contracts, ABI changes are always breaking — existing
  on-chain cells were created with the old ABI.
- Source-level compatibility is the semver contract, not the hash.

#### 8. Git Tag Convention

**Gap**: No defined tag naming convention. No validation that the tag
matches the `version` field.

**Resolution**:

- Tag format: `v{version}` (e.g., `v1.2.0`).
- Pre-release: `v1.2.0-rc.1`.
- `cellc publish` validates that the `version` field in `Cell.toml`
  matches the `version` in `registry.json`.
- `cellc install` validates that the git tag `v{version}` exists and
  points to the same commit as `revision` in `Cell.lock`.

#### 9. Yanking Semantics

**Gap**: `yanked` is a boolean with no replacement pointer or timestamp.

**Resolution**: Extend the yanking model for Phase 2:

```json
{
  "version": "1.2.0",
  "yanked": true,
  "yanked_at": "2026-06-01T00:00:00Z",
  "yanked_reason": "security: reentrancy in swap()",
  "replaced_by": "1.2.1"
}
```

The resolver keeps `yanked` as a boolean for normal selection (yanked versions
are filtered out by `find_matching_version`), and additionally carries the
Phase 2 metadata fields `yanked_at`, `yanked_reason`, and `replaced_by`. When a
yanked version is reached through an exact `=x.y.z` pin, the resolver emits a
warning to stderr that names the reason and suggests the `replaced_by` version
(or the latest non-yanked version when no `replaced_by` is declared). Existing
`Cell.lock` entries referencing yanked versions are not automatically broken —
the lockfile is the source of truth.

#### 10. Dependency Version Conflict Resolution

**Gap**: No defined strategy when two dependencies require different
versions of the same package.

**Resolution**: The resolver uses the versioned
`single-package-coordinate-v1` strategy:

- The package coordinate is `(declared namespace, declared package name)`, and
  a selected graph contains one instance of each coordinate. Aliases are edge
  names; they do not create instances. Different namespaces are distinct.
- If `amm` requires `token ^0.3.0` and `vesting` requires `token ^0.3.1`,
  the resolver picks `token 0.3.2` when that version is the latest version
  satisfying the first resolved constraint and also satisfies the later
  constraint.
- If a transitive request is incompatible with the selected version, source,
  exact feature root, or environment identity, resolution **fails closed**
  with `E2601` before a lock is written. Machine JSON includes the coordinate,
  conflict kind, selected node, and incoming edges.
- The current implementation does not backtrack or re-solve the whole graph
  when a later constraint would require a different still-compatible version;
  that remains future resolver work.
- Locked and frozen materialization applies the same rule without selecting or
  downloading a replacement and discards any partial graph on conflict.
- Multiple versions require a new lock schema and package-qualified module
  namespace. They cannot appear silently under this resolver model.

#### 11. Discovery Index Format Version

**Gap**: The discovery index JSON files have no version identifier.

**Resolution**: Add a top-level `schema_version` field to each namespace
directory:

```
cellscript-registry/
├── _schema.json           # { "schema_version": 1 }
├── cellscript/
│   ├── amm.json
│   └── token.json
└── other-protocol/
    └── swap.json
```

The `_schema.json` file at the repository root defines the format version.
This is a single file for the entire repository, not per-package.

#### 12. Network Identifier Mapping

**Gap**: `network` and `chain_id` are free-form strings with no canonical
mapping. The `deployment.ckb.aggron4` section key mixes platform and
network.

**Resolution**: Define a canonical network registry:

| Network | `chain_id` | `network` value |
|---|---|---|
| CKB Mainnet | `ckb-mainnet` | `mainnet` |
| CKB Testnet (Aggron4) | `ckb-testnet` | `aggron4` |
| CKB Devnet | `ckb-devnet` | `devnet` |

The `deployment` section key format is `[deployment.{platform}.{network}]`.
For Phase 1, only `ckb` platform is supported.

### Audit Summary

| # | Gap | Severity | Phase 1 Action |
|---|---|---|---|
| 1 | Semver rules | **High** | Reference existing `VersionReq` in document |
| 2 | Dual lockfile version | Medium | Remove `lock_schema`, keep `version` |
| 3 | Dual Deployed.toml version | Medium | Remove `schema` string, keep `version` |
| 4 | registry.json deps missing namespace | **High** | Add namespace to dependencies |
| 5 | registry.json format version | Medium | Add `schema_version` |
| 6 | Compiler version compatibility | **High** | Define major.minor compatibility window |
| 7 | ABI compatibility model | Low | Phase 1: exact hash match; Phase 2: structural |
| 8 | Git tag convention | Medium | Define `v{version}` convention with validation |
| 9 | Yanking semantics | Low | Phase 1: simple boolean; Phase 2: reason + replacement |
| 10 | Version conflict resolution | **High** | Define unified resolution strategy |
| 11 | Discovery index version | Low | Add `_schema.json` to repo root |
| 12 | Network identifier mapping | Medium | Define canonical network table |

## Phased Implementation

### Public Registry Publication Policy

`cellc publish` is the public registry write path: it authenticates the
publisher, checks ACL/scope/quota, admits a package entry, and returns a
canonical registry URL. Git commits, Git tags, and `registry.json` remain audit,
mirror, local-fixture, and offline-fallback surfaces; they are not the public
registry admission authority.

| Policy | Evidence |
|---|---|
| Wallet-rooted publisher identity | `cellc auth capability create --principal-type <joyid_ckb\|ckb_secp256k1> --principal-id <principal_id> --scope publish:ns/pkg --scope deployment:ns/pkg --scope availability:ns/pkg --expires 90d --json > capability-payload.json` plus `cellc auth capability submit --payload capability-payload.json --wallet-signature wallet-signature.json` uses the CCC-backed wallet flow, records the typed principal binding, and stores the delegated private key in the OS keychain |
| Scoped publisher credentials | Capability-style signing key with namespace/package/action scopes, expiry, revocation, nonce/origin checks, and CI-safe delegation |
| Namespace/package ACL | Namespace owners, package maintainers, yanking authority, commitment authority, maintainer rotation, and source-location update permissions |
| Abuse controls | Separate static read path from write API; WAF/rate limits/body caps/hash dedup/bounded queues/quarantine/cooldown; fee/bond rules remain later policy hooks |
| Entry visibility state machine | `source_published` -> `indexed_pending` -> `verified_build` -> `deployed` -> `on_chain_committed`; `deprecated`/`yanked`/`quarantined` suppress default search without deleting history |

### Phase 0 — No Block on v0.12

The v0.12 release ships without registry support. The existing
`resolve_from_registry` stub remains. `Cell.lock` version 1 continues to work.
No deployment registry records are generated.

### Phase 1 — v0.19 Scope

This phase makes the registry usable for local development and verification.
Items are ordered by dependency; each item includes its version-control
implications from the audit above.

| # | Work | Evidence | Audit Ref |
|---|---|---|---|
| 1 | Add `namespace` to `PackageInfo` and `DetailedDependency` | `Cell.toml` with `namespace` parses correctly; `cellc init --namespace` sets it | — |
| 2 | Extend `LockedSource::Registry` with `namespace`, `url`, `revision` | Historical 0.19 Git resolver records provenance; 0.23 public resolution reuses the fields for immutable snapshot URL + SHA-256 | #2 |
| 3 | Remove `lock_schema` from Cell.lock; keep `version = 1` | Single version identifier; no dual version confusion | #2 |
| 4 | Add `schema_version: 1` to `registry.json` format | `cellc publish --offline` writes `schema_version`; `cellc install` rejects unknown versions | #5 |
| 5 | Fix `registry.json` dependencies to include namespace | `dependencies: { "token": { "namespace": "cellscript", "version": "0.3.0" } }` | #4 |
| 6 | Remove `schema` string from Deployed.toml; keep `version = 1` | Single version identifier; parser accepts both old manifest and new Deployed.toml | #3 |
| 7 | Define canonical network table (mainnet/aggron4/devnet) | `cellc deploy --network aggron4` writes correct `network` + `chain_id` | #12 |
| 8 | Add `_schema.json` to discovery index repository | `{ "schema_version": 1 }` at repo root | #11 |
| 9 | `Cell.lock` with `[package_build]` hash section | `cellc build` writes artifact/metadata/schema/abi/constraints hashes to lockfile | — |
| 10 | `Deployed.toml` format definition and parsing | Adapter crate can load and validate `Deployed.toml` records | — |
| 11 | Implement the initial `resolve_from_registry` with two-tier resolution | Historical 0.19 evidence: discovery lookup → source clone → `registry.json` → `Cell.toml`; 0.23 replaces the default transport with verified Registry snapshots | — |
| 12 | Define semver compatibility rules and unified version resolution | `cellc build` fails on unsatisfiable version constraints; `"0.3.0"` means `^0.3.0` | #1, #10 |
| 13 | Define compiler major.minor compatibility window for `constraints_hash` | `cellc registry verify` rejects cross-version hash comparison; same `0.19.x` → same hash | #6 |
| 14 | Define git tag convention `v{version}` with validation | `cellc publish` validates tag matches version; `cellc install` validates tag exists | #8 |
| 15 | `cellc package verify` | Validates package metadata against source and build artifacts | — |
| 16 | `cellc registry verify` | Validates build artifacts against deployment facts; checks `record_hash` if present | — |
| 17 | Registry fixture acceptance | Local registry fixture can publish, resolve, and verify a package | — |
| 18 | Hash mismatch rejection | Resolver rejects registry schema/name/namespace/version/tag/source-hash mismatches and package/build/deployment identity mismatches | — |

### Phase 2 — v0.20 Or Later

| Work | Evidence |
|---|---|
| Deployment status lifecycle | `DeploymentStatus` enum (candidate/active/deprecated/revoked); `cellc registry verify` and generated builders fail closed unless status is `active` |
| TYPE_ID upgrade lineage tracking | `Deployed.toml` carries `upgrade_lineage`; `cellc registry verify` rejects self-referential and empty lineage (off-chain consistency; on-chain TYPE_ID upgrade-chain proof remains a live-RPC concern) |
| Publisher signature binding | `Deployed.toml` optionally carries `publisher_signature`; `cellc registry verify --require-publisher-signature` enforces presence (metadata-presence only; cryptographic verification is a later security milestone) |
| Yanking metadata | `registry.json` version entries carry `yanked_at`, `yanked_reason`, `replaced_by`; resolver warns and suggests the replacement when a yanked version is reached |
| `cellc deploy plan` / `cellc deploy verify` / `cellc deploy lock-deps` | CLI commands emit or verify deployment registry records |
| Stale-deployment rejection | Builder refuses to build when deployment record does not match package metadata |
| Registry mismatch fixtures | Wrong network, wrong code hash, stale metadata hash, missing CellDep, deprecated deployment rejection paths |
| On-chain type script index (if needed) | Deferred — optional chain-indexed deployment lookup driven by ecosystem demand |

### Phase 3 — Read-Path Scaling and Cross-Profile Registry

The registry write service is the public admission authority. The read path is
static, cacheable, and mirrorable; Git/source mirrors remain an audit and
fallback mechanism, not the public write authority.

| Work | Evidence |
|---|---|
| Static registry proxy | `registry.cellscript.dev` / `proxy.cellscript.dev` serves cached indexes, source mirrors, and immutable metadata; `cellc install` falls back to direct Git if cache entries are unavailable |
| Yanking and supersession | Index supports `yanked` flag and supersession metadata |
| Maintainer rotation | Namespace owner principal and publisher credential rotation |
| Cross-protocol CellFabric registry discovery | Registry-backed protocol discovery for multi-protocol intent composition |
| Reproducible build proofs | Optional build attestation and verification beyond hash matching |
| Audit signature requirement | Packages require audit signatures before being marked production-ready |

## Responses to Open Questions

### Should CellScript eventually have its own source registry, or reuse/adapt an existing registry protocol?

CellScript should have its own small registry write service because
`cellc publish` must create a public registry entry, enforce namespace/package
ownership, and handle yanking, quarantine, and abuse controls. The read path
should remain Go-like and cacheable: discovery maps `namespace/name` to source
URLs, per-package metadata can be mirrored as `registry.json`, and clients
verify hashes rather than trusting transport. Git/source mirrors are permanent
audit and fallback surfaces, but public write authority belongs to the registry
service.

### What is the minimal useful CKB deployment record without wasting capacity?

Seven required fields: `tx_hash`, `output_index`, `code_hash`, `hash_type`,
`dep_type`, `data_hash`, and `network`. This is approximately 200 bytes for a
single deployment record. Additional fields are recommended but not required
for Phase 1.

### Should deployment records live under one global registry type script, namespace-specific type scripts, or mostly off-chain with chain-indexed commitments?

Phase 1: purely off-chain `Deployed.toml` with `Cell.lock` hash binding.
Phase 2: optional chain-indexed commitments if ecosystem demand justifies the
capacity cost. A global registry type script is possible but should not be the
default; namespace-specific type scripts may be more appropriate for protocol
teams that want on-chain deployment discovery.

### Which fields should be considered essential for CKB deployment identity?

See the Field Classification table above. The essential set is:
`tx_hash` + `output_index` + `code_hash` + `hash_type` + `dep_type` +
`data_hash` + `network`. Build provenance fields (`artifact_hash`,
`metadata_hash`, `schema_hash`, `abi_hash`, `constraints_hash`,
`compiler_version`) are recommended but not required for Phase 1.

### How should wallets and transaction builders verify CellScript dependencies before constructing production transactions?

Through `cellc registry verify`, which performs a seven-step verification chain:
1. source_hash matches between Cell.lock and Deployed.toml
2. artifact_hash matches between Cell.lock and Deployed.toml
3. data_hash = blake2b(artifact) against on-chain code cell
4. code_hash in Deployed.toml matches on-chain script
5. out_point is reachable as CellDep
6. schema_hash / abi_hash consistent with metadata
7. constraints_hash consistent with constraints report

Any failure in this chain causes fail-closed rejection.

### Who should own namespaces and maintainer keys?

Namespace ownership is the core registry ACL. A namespace has owner principals;
packages have maintainer principals; publisher credentials are scoped to
actions such as `publish`, `yank`, `commit`, and `manage-maintainers`. The root
publisher principal is `joyid_ckb` or `ckb_secp256k1`, while daily operations use delegated
publisher credentials that can expire and be revoked. The exact bootstrap
policy for first namespace claim (review, cooldown, reserved namespaces, or
later fee/bond hooks) is an ecosystem decision.

### Should reproducible build proofs or audit signatures be required before a package is considered production-ready?

Hash matching remains the baseline for generic artifacts. A release declaring
a reproducible build additionally requires policy-approved, P-256-signed
reproduction reports from independent trust domains before it becomes
`verified` or can acquire deployment evidence. Security audit signatures remain
policy-specific; when a release declares `security.status = audited`, the
referenced audit report must at least be present and hash-bound.

### How should yanking, supersession, and maintainer rotation work?

Yanking is a scoped maintainer action over a package version. The index keeps
`yanked`, `yanked_at`, `yanked_reason`, and `replaced_by` metadata so exact pins
can warn without destroying history. Supersession metadata links a deprecated
or yanked record to its replacement. Maintainer rotation is performed by
namespace owners by adding/revoking scoped publisher credentials and package
maintainer principals. Quarantine is separate from yanking: it is an abuse or
risk-control state that suppresses default search while preserving direct URL
and audit history.

Package versions are not hard-deleted from registry history. If legal, security,
or clearly malicious content must be hidden, public access to the artifact or
source snapshot may be disabled, but the registry must retain a tombstone,
package history, audit record, actor identity, reason, and timestamps.

## Non-Goals

- Do not replace CCC. The Action Builder consumes deployment records; it does
  not become a wallet, indexer, or chain submission layer.
- Do not introduce a separate registry account system alongside wallet-rooted
  publisher identity.
- Do not require an interactive wallet signature for every `cellc publish`;
  the wallet authorises scoped publisher credentials, and credentials sign daily
  publish payloads.
- Do not introduce hidden signer authority or hidden sighash defaults.
- Do not infer transaction semantics from protocol/action names.
- Do not treat package registry resolution as deployment verification. These
  are separate layers with separate verification obligations.
- Do not make the public website or registry read path call CKB RPC for ordinary
  browsing/search. Chain checks belong in asynchronous workers or explicit
  verifier commands.
- Do not mark a deployment mainnet-certified without external audit and chain
  evidence.
- Do not make builder success a substitute for CKB VM acceptance.
- Do not claim full CellFabric intent composition in the registry release.
- Do not force on-chain deployment records when off-chain verification is
  sufficient.
- Do not claim generated Action Builder or live-chain registry certification as
  part of the 0.19 Phase 1 registry closure.

## Acceptance Gate

Phase 1 acceptance requires:

```
cellc package verify                        # source ↔ build hash binding
cellc registry verify                       # build ↔ deployment hash binding
local registry fixture: publish / resolve / verify
hash mismatch rejection fixtures
README and docs distinguish package discovery from deployment discovery
```

0.20 acceptance adds:

```
cellc registry verify --live
cellc gen-builder --target typescript
npm test for generated builders
local CKB dry-run for generated action transactions
local CKB submitted stateful flows for canonical examples
negative builder-shape rejection fixtures
deployment registry mismatch rejection fixtures
```
