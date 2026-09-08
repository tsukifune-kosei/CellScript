# CellScript Package Resolve Graph And Build Plan

**Status**: active 0.30 contract for issue #19.

`cellc metadata` remains the compiled-program metadata command. Package source
selection and build scheduling use two separate read-only schemas:

- `cellscript-resolve-graph-v1` describes the selected package graph;
- `cellscript-build-plan-v1` describes the compilation units derived from that
  graph.

Both commands accept `--schema-version 1`. An unsupported version fails rather
than silently returning a different shape.

## Read-Only Resolution

```bash
cellc resolve-graph . --offline --json
cellc resolve-graph . --scope test --all-features \
  --environment testnet --offline --json
cellc resolve-graph path/to/workspace -p app --offline --json
```

Inspection always consumes existing authoritative `Cell.lock` files and is
effectively offline, even when `--offline` is omitted. It never invokes an
external resolver, updates a lock, writes build outputs, or refreshes cache
recency. A query that needs a missing source cache or mutable selection fails
and directs the operator to an explicit `cellc lock` or transactional
`cellc update-plan` step.

The graph records:

- package or selected workspace roots, canonical manifest identity, and
  dependency-first root order;
- stable opaque package node IDs and each root-local lock node ID;
- exact source authority, immutable revision/path identity, source hash,
  manifest digest, compiler requirement, edition, effective feature roots, and
  CKB environment identity;
- aliases, runtime/test edge kind, lock/environment provenance, and workspace
  member targets;
- unselected lock nodes and policy warnings;
- the exact lock text, parsed lock document, and SHA-256 digest for every
  authoritative root lock.

`graph_digest` identifies the complete report. `resolution_digest` identifies
the selected source graph and excludes diagnostics, absolute checkout paths,
cache state, and package build/deployment records. Build-unit identity uses the
resolution digest.

## Build Units

```bash
cellc build-plan . --target riscv64-elf --target-profile ckb \
  --release --offline --json
```

Each `cellscript-build-plan-v1` unit records the selected package root, entry,
target and artifact format, target profile, VM and witness codec identities,
complete compatibility profile, dependency scope, features, environment,
direct workspace-unit dependencies, expected artifact/metadata/verified
sidecars, production policy requirements, and a stable unit ID.

The cache record contains the compiler's actual incremental cache key and
source-set hash. Its stable status is `up-to-date`, `missing`, `stale`, or
`not-cacheable`, with a reason. Entry-action, entry-lock, and named-artifact
builds are explicitly non-cacheable because the current compiler only caches
the default package entry.

`cellc build` derives and validates the same unit identity. Its JSON output
includes the plan schema/digest, resolution digest, and unit ID; compilation
fails if the resulting artifact format, target profile, compatibility profile,
or output path differs from the plan.

## Consumers And Compatibility

Package verification consumes the same resolve graph and reports graph digests
for every checked environment. The `dev` and `ci` gates query the checked-in
package and workspace fixtures. LSP code actions and the VS Code extension
surface the two commands without reimplementing resolution.

Checked-in v1 JSON fixtures are deserialized in integration tests. V1 rejects
unknown fields, so adding or changing required fields needs a new negotiated
schema version. Resolve/build schemas do not replace semantic metadata,
ProofPlan, verified artifact metadata, deployment evidence, or ProtocolBundle.
