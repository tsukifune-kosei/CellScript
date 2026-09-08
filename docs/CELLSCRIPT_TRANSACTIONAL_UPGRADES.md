# CellScript Transactional Upgrade Plans

**Status**: active 0.30 development contract for issue #20.

CellScript separates dependency selection from lockfile mutation. `cellc
update-plan` resolves and compiles a candidate graph in memory, then emits a
reviewable `cellscript-upgrade-plan-v1` document. `cellc update` has the same
planning behavior by default. Only `cellc update --apply-plan <file>` can
replace `Cell.lock` files.

## Plan An Upgrade

```bash
cellc update-plan . --offline --output target/upgrade-plan.json
cellc update . --offline --output target/upgrade-plan.json
cellc update-plan . --package math --precise 2.4.1 --output target/math-upgrade.json
cellc package update-plan . --environment testnet --json
```

Planning requires an existing authoritative lock for each package member that
has dependencies. It does not modify a lock, `Deployed.toml`, build output, or
cache recency. `--offline` also forbids external resolution and uses only
verified local source caches. Omitting it permits the configured update-time
Registry or Git resolver to find a candidate; the resulting lock still records
an immutable source identity.

The default scope includes runtime and test dependencies and activates all
declared feature roots, matching a complete package lock. Use `--scope runtime`,
`--features`, `--all-features`, `--no-default-features`, or `--environment` to
make a narrower selection explicit. `--package` limits replacement to one
dependency alias or package coordinate and its required descendant closure;
unrelated nodes retain their exact old records. `--precise` requires
`--package`, accepts an exact SemVer within the manifest requirement, and is
available for direct Registry or configured external-resolver dependencies.
It cannot substitute an immutable path or Git dependency.

## Review The Receipt

The plan binds its entire canonical JSON body with `plan_hash`, records the
active compiler version, and names the `cellscript-resolve-graph-v1` and
`cellscript-build-plan-v1` contracts it composes. Every affected member has:

- exact old and candidate lock text, parsed lock records, and SHA-256 hashes;
- aggregate old and candidate graph hashes;
- package-node changes classified as added, removed, upgraded, downgraded,
  source-switched, feature/environment-changed, or content-changed;
- edge additions, removals, and retargeting with owner and alias provenance;
- old and candidate build-unit identities plus reverse-dependent compilation
  evidence for every selected CKB environment;
- source API, serialized layout, runtime ABI, effects/capabilities, builder,
  and deployment compatibility as six independent interface dimensions;
- typed-semantics, builder-contract, deployment-contract, and ProtocolBundle
  input identities;
- deployment upgrade status and a separate authorization result.

The planner compiles both graphs through in-memory lock overrides. A candidate
that does not compile is a hard blocker. If the old graph can no longer be
compiled, the retained old build evidence is visible and `UPG3001` requires an
explicit acknowledgement. Breaking interface dimensions use `UPG3101` through
`UPG3106` and list the migration artifacts needed for review.

Dependency downgrades (`UPG2001`), source-authority substitutions (`UPG2002`),
and feature or environment selection changes (`UPG2003`) are separate policy
events. Deployment checks also stay separate: an immutable deployment has no
upgrade authority (`UPG4001`), malformed TYPE_ID lineage is rejected
(`UPG4002`), and valid local TYPE_ID metadata still requires an external live
authorization proof (`UPG4003`). Acknowledging one of these codes records a
review decision; it does not create a state migration, deployment transaction,
signature, or on-chain authorization.

## Apply A Reviewed Plan

```bash
cellc update --apply-plan target/upgrade-plan.json
cellc update --apply-plan target/upgrade-plan.json \
  --acknowledge UPG2003,UPG3102
```

Apply revalidates the schema, active compiler, plan hash, required
acknowledgements, every exact old lock byte sequence, and every candidate lock
hash and canonical TOML representation. Any changed old lock makes the plan
stale and aborts the whole preflight. Paths must remain confined to the planned
workspace and may not be symlinks.

After all members pass preflight, each lock is replaced through a synced
same-directory temporary file and rename. If a later replacement fails during
the operation, already replaced locks are restored from the exact old bytes.
This provides a preflighted multi-member transaction with atomic per-file
replacement and runtime rollback. It is not a cross-filesystem crash-atomic
journal.

Apply changes only the listed `Cell.lock` files. It never edits
`Deployed.toml`, deploys or publishes an artifact, signs a transaction, proves
TYPE_ID authority, or performs state migration. Those actions require their
own reviewed artifacts and release or deployment gates.

## Stable Fail-Closed Diagnostics

| Code | Meaning |
| --- | --- |
| `E2800` | Invalid plan request, selector, schema negotiation, or candidate graph |
| `E2801` | Apply is blocked by missing acknowledgement or a hard diagnostic |
| `E2802` | Plan schema/compiler/hash/path/candidate validation failed, or the old lock is stale |
| `UPG2001`–`UPG2003` | Dependency downgrade, source switch, or selection change |
| `UPG3000`–`UPG3002` | Reverse-dependent compile or interface-evidence failure |
| `UPG3101`–`UPG3106` | Breaking API, layout, ABI, effects, builder, or deployment dimension |
| `UPG4001`–`UPG4003` | Missing, malformed, or externally unproven deployment upgrade authority |

Unknown plan fields and unsupported schema versions fail closed. The v1 JSON
fixture is `tests/fixtures/upgrade_plan_v1.json`; routine gates also generate an
offline plan and prove that its source `Cell.lock` remains byte-identical.
