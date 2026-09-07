# CellScript Operational Semantics

Status: v0.16 mechanically precise assurance spec.

This document defines the checked metadata subset that v0.16 validates against
compiler metadata. It is intentionally operational: every rule maps to
AST/type-checker behavior, IR effects, ProofPlan records, or builder
assumptions.

## Judgments

```text
E |- e => v
S |- stmt => S'
S |- action(params) => S'
S |- lock(params) => bool
M |- proof_plan => sound | issue(code)
T |- tx against assumptions => ok | reject
```

`E` is the expression environment. `S` is the linear resource state and Cell
effect log. `M` is compile metadata. `T` is a transaction JSON shape plus
schema-bound evidence consumed by `cellc tx validate`.

## Expression Evaluation

Pure expressions are deterministic big-step evaluations.

```text
E(x) = v
---------------- Identifier
E |- x => v

E |- a => va    E |- b => vb    va op vb = v
------------------------------------------- Binary
E |- a op b => v

E |- f(args) => v    f is pure
-------------------------------- CallPure
E |- f(args) => v
```

Runtime CKB calls such as `source::group_input`, `witness::lock`,
`env::sighash_all`, `env::sighash_all_zero_lock`, and `read_ref<T>()` are not
pure expression rules. They emit runtime access metadata and explicit
obligations. Canonical generic
`env::sighash_all` construction is deferred: production artifact generation
rejects `ckb-sighash-all-deferred`; audit execution terminates the process
with runtime error 66 and does not return a `Hash`. This effect must survive
unused-result elimination and helper inlining.

`env::sighash_all_zero_lock(g, i, e, b)` is a separate versioned runtime
contract. Its arguments are statically checked `u64` literals. Runtime
evaluation hashes the exact transaction hash; the length-prefixed first current
group witness with its complete `WitnessArgs.lock` payload replaced by
equal-length zero bytes; later present group witnesses; and witnesses after the
transaction input count. Exceeding `g`, `i`, `e`, or `b` terminates with error
69. Successful evaluation returns the distinct `SighashAllDigest` source
domain. This rule does not describe a prefix-preserving multisig placeholder.

## Linear Resource State

Each linear binding is in one state:

```text
Live(name, ty)
Consumed(name, ty, op)
Returned(name, ty)
Created(name, ty, output_index, op)
```

Core transition rules:

```text
S has Live(x, T)
---------------------- Consume
S |- consume x => S + Consumed(x, T, consume)

fields valid for T
------------------------------ Create
S |- create T { fields } => S + Created(_, T, output, create)

S has Live(x, T)    fields valid for T
--------------------------------------- ReplaceUnique
S |- replace_unique<T>(identity = p) x { fields }
   => S + Consumed(x, T, replace_unique) + Created(_, T, output, replace_unique)
```

Branch merge is conservative. A linear name may merge only when both branches
leave the same linear state for that name. Loops may not hide linear state
changes that cannot be statically bounded.

## Cell Effects

The IR effect log is the source of metadata truth:

```text
consume_set    input Cells consumed by consume/transfer/claim/settle/replace_unique
create_set     output Cells created by create/transfer/claim/settle/create_unique/replace_unique
read_refs      dependency-backed state read without consuming
mutate_set     input/output replacement obligations from &mut state
```

Each effect must either lower to executable verifier code, produce a
checked-runtime verifier obligation, or fail closed.

## Triggers And Scopes

Supported invariant triggers:

```text
explicit_entry
lock_group
type_group
```

Supported scopes:

```text
selected_cells
group
transaction
```

Soundness rule:

```text
trigger = lock_group    scope = transaction
--------------------------------------------- LockGroupTxScope
builder_assumption(lock group only protects matching lock inputs)
```

This rule prevents lock-group transaction scans from being presented as
transaction-wide type conservation.

## ProofPlan Meaning

Every ProofPlan field has a checked meaning:

| Field | Meaning |
|---|---|
| `origin` | Source of the obligation: action, function, lock, or invariant |
| `trigger` | Script execution trigger that can observe the obligation |
| `scope` | Cell set protected by the obligation |
| `reads` | CKB views read by generated verifier code or declared invariant |
| `coverage` | Macro provenance and generated coverage notes |
| `input_output_relation_checks` | Runtime/static checks that compare inputs and outputs |
| `group_cardinality` | Script-group cardinality model used by the proof |
| `identity_lifecycle_policy` | Identity rule applied to create/replace/destroy |
| `builder_assumptions` | Off-chain obligations that builders/indexers must satisfy |
| `codegen_coverage_status` | `covered`, `gap:*`, `fail-closed`, or builder-required |
| `on_chain_checked` | True only when generated code covers the obligation |

v0.16 soundness rule:

```text
VerifierObligation(category, feature, status) in M
ProofPlan(category, feature, status) not in M
--------------------------------------------------- MissingPlan
M |- proof_plan => issue(PP0002)
```

```text
ProofPlan(status = runtime-required) and strict_0_16
---------------------------------------------------- StrictGap
M |- proof_plan => issue(PP0150)
```

```text
ProofPlan(on_chain_checked = true, codegen_coverage_status != covered)
--------------------------------------------------------------------- Overstatement
M |- proof_plan => issue(PP0102)
```

The implementation of these rules is `proof_plan::soundness::check_metadata`.
`--primitive-strict=0.16` makes the strict rules mandatory.

## Builder Assumptions

Builder assumptions are not prose in v0.16. They are schema records with:

```text
assumption_id
kind
required_inputs
required_outputs
required_cell_deps
required_witness_fields
capacity_policy
fee_policy
change_policy
signature_policy
failure_mode
```

`cellc explain assumptions` emits this schema. `cellc tx validate --against
metadata.json --tx tx.json` checks a concrete transaction shape and requires
schema-bound evidence objects for non-structural assumptions before signing.
For manifest-bound spawn targets, validation also checks the referenced
`cell_deps[index]` object against the declared CellDep identity (`name`,
`dep_type`, and any manifest-specified `tx_hash`, `out_index`, `hash_type`,
`data_hash`, or `type_id`) instead of accepting evidence-only claims.

## Conformance Fixtures

The historical 0.16 conformance suite has been retired from the main branch;
the remaining standard-compatibility fixtures live in
`tests/compat/ckb_standard/manifest.json`. The conformance boundary checks:

- ProofPlan soundness metadata is emitted and passes for checked runtime cases;
- `--primitive-strict=0.16` rejects metadata-only ProofPlan gaps;
- schema-bound builder assumption evidence is required by `tx validate`;
- manifest-bound spawn-target CellDep identity is checked in both transaction
  deps and builder evidence;
- the standard CKB compatibility suite names accepted and rejected fixtures for
  sUDT, xUDT, ACP, Cheque, Omnilock, NervosDAO since/epoch, and Type ID.
