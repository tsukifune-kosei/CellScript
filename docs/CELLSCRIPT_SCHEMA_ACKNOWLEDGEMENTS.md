# Focused Schema Acknowledgements

## Status and boundary

The 0.30 development branch implements a versioned, off-chain review workflow
for Edition 2027 `data = same except { ... }` relations. It compares one exact
old/new package pair and one explicitly selected `action`/predecessor/successor
relation. It does not authorize a deployment, migrate existing Cell data, edit
`Cell.lock`, or edit `Deployed.toml`.

The workflow uses two canonical records:

- `cellscript-schema-change-plan-v1` binds the module, action and roles, old and
  new interface hashes, field-layout identities, canonical relation identities,
  changed field treatments, blockers, and a plan hash;
- `cellscript-schema-acknowledgement-v1` binds an eligible plan to a named
  reviewer, rationale, the exact changed-field list, and an acknowledgement
  hash.

The reviewer field is an audit label, not a cryptographic signature or an
authorization credential. A later governance system may bind a verified
receipt hash to its own authenticated approval process.

The first deployed/source baseline needs no acknowledgement. A receipt is
defined only for an explicit old-to-new comparison. Every schema change sets
`state_migration_required = true`; the acknowledgement records review of the
field policy and does not satisfy that separate migration requirement.

## New-field rule

`same except` expands every unlisted field as preserved. That is safe for an
unchanged concrete schema, but it is not evidence that an author reviewed a
field added by an upgrade. A newly added field therefore causes blocker
`SACK1001` when it remains implicit.

For example, adding `approval_nonce` to `Token` while leaving the old relation
unchanged cannot produce a receipt:

```cellscript
data = same except {
    amount = token.amount
}
```

The candidate must state the new policy explicitly:

```cellscript
data = same except {
    amount = token.amount
    approval_nonce = 0
}
```

The compiler runtime already checks the created output field against the
constant. The ProofPlan classifies fixed constant assignments as checked
successor updates, so this reset can remain executable under the production
`DenyFailClosed` policy.

## CLI workflow

Generate the review plan first:

```bash
cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --output schema-change-plan.json
```

After reviewing the field delta and fixing all blockers, create a receipt:

```bash
cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --acknowledge-by "reviewer identity" \
  --rationale "approval_nonce resets on every transfer" \
  --output schema-acknowledgement.json
```

Verify the saved receipt against the candidates that will be reviewed or used
by later upgrade tooling:

```bash
cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --verify schema-acknowledgement.json
```

Changing a bound schema, assignment expression, lock treatment, role, action,
or module changes the plan identity and makes the old receipt stale. Formatting
changes do not change the canonical relation identity.

## Remaining integration

The transactional package upgrade owner in issue #20 must consume verified
receipts together with its graph-wide source, interface, builder, deployment,
authorization, and migration decisions. A valid acknowledgement must remain a
separate review fact; it cannot turn an interface-breaking change into a
compatible change or act as Type ID/Type-hash upgrade authorization.
