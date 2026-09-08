# CellScript Canonical Workspace Graph

**Status**: active 0.30 development contract for issue #15.

## Workspace Membership

A workspace manifest lists explicit directory entries:

```toml
[workspace]
members = ["app", "right", "left", "shared", "experiments"]
exclude = ["experiments"]
```

Version 1 treats `members` and `exclude` as literal directories relative to the
workspace root. It does not interpret glob patterns. Every included directory
must exist inside the canonical workspace root and contain a valid package
`Cell.toml`. Excluded directories must also resolve inside that root.

After exclusions, canonical paths and declared package names must both be
unique. `member` and `./member` are the same path and fail if both are listed.
Two members may not share a package name, even when they declare different
namespaces, because `cellc build -p <name>` selects by the unique member name.

## Authoritative Locks

Each member's `Cell.lock` is independently authoritative for that member's
source dependency graph. Workspace membership does not replace or synthesize
member locks. A member with selected dependencies must have a current v5 lock;
stale source, manifest, feature, environment, or compiler identities fail
before any member compiles.

A virtual workspace root must not contain `Cell.lock`. In particular, member
artifact hashes are never written as `LockedDependency` nodes. A root that is
also a package may keep its own package lock, but that lock has ordinary
package meaning and is not a workspace artifact list. Protocol or artifact
closure belongs in a separately versioned evidence carrier.

After the complete workspace graph validates and all selected builds succeed,
a non-frozen workspace build refreshes each successful member's own
`[package_build]` identity. A failed workspace build does not rewrite member
locks. Artifacts already emitted by successful prerequisites remain ordinary
local build outputs and do not become lock evidence.

## Resolve Graph

`cellscript-workspace-resolve-graph-v1` records:

- canonical member ID, name, namespace, version, edition, compiler requirement,
  relative path, manifest path, and manifest digest;
- the dependency selection: runtime or test scope, named/all/default features,
  CKB environment, and offline state;
- every selected member-to-member path edge, its local alias, and exact locked
  package node;
- the deduplicated resolved source nodes seen from member locks;
- a deterministic dependency-first member order.

Only an exact path dependency whose canonical source directory is an included
workspace member creates a member edge. A same-named Registry or Git package
does not silently become a workspace member. The single-package-coordinate
resolver is enforced across the selected workspace roots, so two member locks
cannot select different instances of one package coordinate.

Cycles fail with `E2700 workspace-graph-invalid` before lock materialization or
compilation. Other membership and member-lock failures also stop the graph
preflight. Member declarations are sorted by package name, so declaration order
does not influence graph or build identity.

## Build And Check Scheduling

`cellc build --workspace` and `cellc check --workspace` consume the same graph
and process members in dependency-first order. `-p app` selects `app` plus its
transitive member closure. A failed prerequisite marks its dependents blocked;
those dependents are not compiled.

Independent members are currently processed serially. Parallel scheduling may
be added later only if it preserves the same graph, member order in reports,
output bytes, lock updates, and failure aggregation.

JSON results expose the graph schema, dependency and command selections,
selected members, member edges, ordered unit results, cache hits, blocked
dependencies, and failures. The checked-in `examples/workspace_graph` fixture
is a reverse-declared four-member diamond. Both `dev` and `ci` run it frozen
and offline.

Workspace membership is a source/build organization boundary. It is not an ELF
linker, deployment authorization, or protocol-composition claim.
