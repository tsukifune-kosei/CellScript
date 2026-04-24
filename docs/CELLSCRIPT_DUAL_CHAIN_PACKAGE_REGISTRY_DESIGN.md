# CellScript Dual-Chain Package Registry Design

**Date**: 2026-04-23
**Status**: Production design proposal
**Scope**: CellScript package manager, Spora deployment registry, CKB deployment registry, lockfile provenance

## Decision

CellScript should use a two-layer package model:

1. **Off-chain source registry** for source packages, interface packages,
   schemas, tests, docs, examples, and reproducible build metadata.
2. **On-chain deployment registry** for deployed artifact identity, code cell
   identity, schema/ABI commitments, type-id lineage, and chain-specific
   execution constraints.

The lockfile binds the two layers cryptographically. A dependency is not
production-ready just because a source package resolved, and a deployed code
cell is not enough by itself unless it can be traced back to the source package,
compiler version, metadata schema, constraints report, and chain-specific
artifact identity.

Short form:

> Use an off-chain registry for distribution, an on-chain registry for
> deployment truth, and a lockfile for the binding between them.

## Why Not Pure On-Chain Packages

Publishing every CellScript package directly to Spora or CKB is the wrong
default:

- source archives, examples, docs, tests, schema manifests, and editor metadata
  are development artifacts, not consensus-critical state;
- frequent semver releases would create permanent chain state churn;
- dependency resolution would become slower and more expensive;
- CKB capacity costs make source-package storage especially unattractive;
- Spora should not put the whole development ecosystem into scheduler/storage
  accounting just to resolve ordinary source dependencies.

On-chain state should record deployment facts and commitments, not replace the
whole source distribution system.

## Why Not Pure crates.io-Style Packages

An off-chain registry alone is also insufficient:

- CKB production transactions need concrete `CellDep` identities, `OutPoint`,
  `data_hash`, `dep_type`, lock/type hashes, and type-id lineage;
- Spora production transactions need deployed artifact hash, schema hash, ABI
  hash, scheduler metadata, and mass constraints;
- wallets and builders need to verify that the package version they resolved is
  the same code identity they are about to use on-chain;
- a compromised or stale registry must be detected by checking lockfile hashes
  and on-chain deployment records.

The off-chain registry distributes source and build metadata. The chain records
the deployed artifact identity.

## Package Object Model

| Object | Default location | Contents | Mutability |
|---|---|---|---|
| Source package | Off-chain registry | `.cell` source, `Cell.toml`, docs, examples, tests, schema manifests | immutable per version; yanked but not deleted |
| Interface package | Off-chain registry | public types, actions, locks, schema/ABI, no implementation requirement | immutable per version |
| Build artifact | Artifact store plus lockfile hash | RISC-V assembly/ELF, metadata JSON, constraints JSON, build provenance | immutable |
| Deployment record | On-chain registry or chain index | code hash, data hash, OutPoint, type-id, schema hash, ABI hash, artifact hash, owner/admin lock | append/supersede; never silently mutate |

## Manifest Shape

`Cell.toml` remains the source-facing package manifest:

```toml
[package]
name = "amm"
version = "1.2.0"
edition = "2026"

[dependencies]
token = "0.11"
math = "0.4"

[build]
target = "riscv64-elf"
target_profile = "spora"

[target.spora]
profile = "spora"

[target.ckb]
profile = "ckb"

[deploy.spora]
artifact_hash = "blake3:..."
schema_hash = "blake3:..."
abi_hash = "blake3:..."
code_cell = "spora:..."

[deploy.ckb]
artifact_hash = "blake2b:..."
data_hash = "0x..."
out_point = "0x...:0"
dep_type = "code"
hash_type = "data1"
type_id = "0x..."

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x...:0"
dep_type = "dep_group"
hash_type = "type"
```

Target-specific deployment sections are optional for libraries and required for
packages that claim production deployment identity.

## Lockfile Shape

`Cell.lock` is a deployment-grade supply-chain document, not only a semver
resolution cache:

```toml
[[package]]
name = "token"
version = "0.11.0"
source = "registry+https://registry.cellscript.org"
source_hash = "blake3:..."
schema_hash = "blake3:..."
abi_hash = "blake3:..."
metadata_schema = 27
compiler = "cellscript 0.11.0"

[package.build]
artifact_hash = "blake3:..."
metadata_hash = "blake3:..."
constraints_hash = "blake3:..."
reproducible = true

[package.target.spora]
elf_hash = "blake3:..."
schema_hash = "blake3:..."
abi_hash = "blake3:..."
estimated_compute_mass = "..."
estimated_storage_mass = "..."
estimated_transient_mass = "..."
deployment = "spora:..."

[package.target.ckb]
elf_blake2b = "0x..."
data_hash = "0x..."
cell_dep = { out_point = "0x...:0", dep_type = "code" }
type_id = "0x..."
min_code_cell_capacity = "..."
```

Every production builder should be able to verify the lockfile without trusting
registry prose.

## CKB Deployment Registry

CKB should keep on-chain package data minimal and commitment-oriented.

Recommended CKB deployment record fields:

- package namespace hash;
- package name hash;
- semver;
- source hash;
- metadata hash;
- constraints hash;
- artifact data hash;
- code cell `OutPoint`;
- `dep_type`;
- optional type-id lineage root;
- schema hash;
- ABI hash;
- maintainer/admin lock hash;
- superseded/yanked flag.

The CKB registry should not store full source archives by default. Source
archives can be mirrored off-chain and verified by hash. A chain cell may store
a small manifest commitment or registry record, but code loading remains based
on normal CKB `CellDep` rules.

CKB builder resolution should produce:

```text
package version -> lockfile package -> deployment record -> CellDep -> script hash/data hash checks
```

## Spora Deployment Registry

Spora can record richer execution metadata than CKB because Spora scheduling
and mass accounting are part of production deployment:

- package namespace/name/version;
- source hash;
- artifact hash;
- schema hash;
- ABI hash;
- scheduler touch domains;
- parallelizability hints;
- accepted compute/storage/transient mass;
- code deployment mass;
- metadata schema version;
- compiler version;
- maintainer/admin lock;
- superseded/yanked flag.

Spora still should not store full source archives by default. The default
on-chain record should be a compact deployment attestation plus execution
metadata useful to builders, validators, and wallets.

## CLI Workflow

Recommended command split:

```bash
cellc publish
```

Publish source package, schema manifest, docs, and reproducible build metadata
to the off-chain registry.

```bash
cellc build --target-profile spora --release
cellc build --target-profile ckb --release
```

Build profile-specific artifacts, metadata, and constraints reports.

```bash
cellc deploy --target-profile spora
cellc deploy --target-profile ckb
```

Deploy the artifact to the target chain and produce a chain-specific deployment
record.

```bash
cellc publish-deployment --target-profile spora
cellc publish-deployment --target-profile ckb
```

Attach chain deployment identity to the package version in the off-chain
registry.

```bash
cellc verify-package token@0.11.0 --target-profile ckb
```

Verify source hash, schema hash, ABI hash, compiler version, artifact hash,
constraints hash, and chain deployment identity.

## Security Requirements

Production package management must support:

- immutable version releases;
- yank without deletion;
- namespace ownership;
- maintainer rotation;
- multisig release authority;
- reproducible build proof;
- compiler version pinning;
- metadata schema pinning;
- dependency source hash pinning;
- artifact hash pinning;
- constraints hash pinning;
- chain deployment identity pinning;
- optional audit signatures;
- registry mirror verification;
- offline lockfile verification.

## Builder Responsibilities

A production builder must not accept a package by name alone. It must verify:

1. the resolved source package hash matches `Cell.lock`;
2. the metadata hash matches the source and compiler version;
3. the artifact hash matches metadata;
4. the target-profile constraints match the intended chain;
5. the on-chain deployment record matches the artifact identity;
6. the transaction uses the expected CKB `CellDep` or Spora code cell;
7. measured cycles/mass/capacity fit the selected network policy.

## Implementation Phases

### Phase 1: Off-Chain Registry

- source package namespace;
- semver resolution;
- local path/git/registry dependency support;
- lockfile source hashes;
- immutable versions and yanking;
- package verification command.

### Phase 2: Reproducible Artifact Registry

- compiler version pinning;
- metadata schema pinning;
- schema and ABI hashes;
- artifact hashes;
- constraints hashes;
- reproducible build attestations;
- audit signatures.

### Phase 3: Chain Deployment Registry

- CKB deployment records;
- Spora deployment records;
- package version to code identity mapping;
- builder integration;
- wallet verification;
- acceptance tests that consume registry deployment records instead of
  hand-wired artifact paths.

### Phase 4: Governance and Mirrors

- namespace governance;
- maintainer keys and rotation;
- registry mirrors;
- emergency yanking;
- on-chain supersession records;
- offline verification tooling.

## Open Questions

- Whether the public off-chain registry should be CellScript-owned or reuse an
  existing Rust-style registry protocol with CellScript-specific metadata.
- Whether CKB deployment records should use one global registry type script or
  namespace-specific type scripts.
- Whether Spora should make scheduler/mass metadata consensus-enforced in the
  registry or leave it as builder admission metadata.
- How much source attestation should be optional on-chain for highly regulated
  deployments.

## Final Position

CellScript packages should be distributed like development packages but
verified like smart-contract deployments. The registry should optimize source
distribution off-chain, while the chains record compact, verifiable deployment
truth. `Cell.lock` is the bridge between the two.
