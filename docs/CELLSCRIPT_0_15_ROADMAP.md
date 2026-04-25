# CellScript v0.15 Roadmap

**Date**: 2026-04-25
**Status**: Draft
**Scope**: Scoped Invariants and Covenant ProofPlan
**Dependencies**: v0.13 and v0.14 complete

---

## Goal

v0.15 makes CKB script semantics explicit and auditable.

CellScript should let developers express transaction and cell invariants in a CKB-native way while making these facts visible:

- `trigger`: when the verifier runs
- `scope`: which cell universe the invariant reasons over
- `reads`: which transaction views are inspected
- `coverage`: which cells are actually protected
- `on_chain_checked`: which obligations are enforced by generated code
- `builder_assumption`: which obligations are only construction/deployment assumptions

CellScript must not hide lock/type differences behind placement syntax. Lock and type scripts are different execution triggers with different coverage models.

v0.15 still resets the primitive layer, but the user-facing theme is:

```text
Scoped Invariants & Covenant ProofPlan
```

---

## Out of Scope

Do not re-plan v0.13:

- bounded generics
- value collections
- phantom tags
- generic interfaces/templates
- specialization/inlining/DCE/const propagation
- CLI ergonomics
- hash type DSL exposure
- transaction builder MVP
- fuzz expansion

Do not re-plan v0.14:

- Spawn/IPC
- structured `WitnessArgs`
- explicit Source views
- ScriptGroup and CKB transaction-shape conformance
- TYPE_ID metadata validation MVP
- target profile formalization
- declarative capacity/time/since syntax
- dynamic BLAKE2b decision
- WASM backend
- builder integration
- advanced CellDep/DepGroup patterns
- script reference and HashType strictness

---

## P0

### 1. First-Class Script Semantics

**Problem**

CKB lock/type is not just "where a constraint is placed". It is a trigger and coverage boundary. A lock covenant can scan global inputs/outputs, but it only runs for inputs sharing that lock. A type invariant runs for the type group and naturally covers cells sharing that type script.

**Change**

Add first-class script semantics to invariant/proof metadata:

```text
trigger = lock_group | type_group | explicit_entry
scope = group | transaction | selected_cells
reads = input | output | group_input | group_output | cell_dep | header_dep | witness
coverage = covered_cells(...)
on_chain_checked = true | false
builder_assumption = none | declared(...)
```

Example:

```cellscript
invariant udt_amount_non_increase {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>, group_outputs<Token>

    assert sum(group_outputs<Token>.amount) <= sum(group_inputs<Token>.amount)
}
```

**Code Areas**

- invariant AST
- semantic analyzer
- metadata schema
- docgen audit output
- CKB strict diagnostics

**Acceptance**

- every invariant records trigger, scope, reads, coverage, and enforcement status
- strict mode rejects invariants without explicit trigger and scope
- compiler warns when `trigger = lock_group` and `scope = transaction` are used together
- diagnostics explain that transaction scans from a lock do not imply type-group conservation

---

### 2. Scoped Aggregate Invariant Primitives

**Problem**

Protocol macros for UDTs, pools, settlements, rentals, and covenant locks need aggregate transaction checks. Without scoped aggregate primitives, the compiler keeps growing protocol-specific recognizers.

**Change**

Add scoped aggregate assertions:

```text
assert_sum(group_outputs<Token>.amount) <= assert_sum(group_inputs<Token>.amount)
assert_conserved(Token.amount, scope = group)
assert_delta(Token.amount, delta, scope = selected_cells)
assert_distinct(outputs<NFT>.id, scope = transaction)
assert_singleton(type_id, scope = group)
```

Rules:

- every aggregate assertion must bind `scope`
- source view must be explicit
- field type must be fixed-width integer or fixed bytes
- overflow traps fail closed
- loops are bounded by declared group/transaction limits

**Code Areas**

- type checker field projection
- invariant lowering
- IR aggregate ops
- CKB codegen loops
- ProofPlan aggregate obligations

**Acceptance**

- UDT-style amount conservation lowers without token-specific recognizers
- pool invariant helpers lower through aggregate primitives
- generated code traps on overflow and malformed cell data
- tests cover `group`, `transaction`, and `selected_cells` scopes

---

### 3. Covenant ProofPlan

**Problem**

Verifier obligations are split between IR patterns, metadata recognizers, and codegen-specific checks. Auditors need to see not only what code was emitted, but what CKB trigger/scope/coverage semantics it has.

**Change**

Add a `ProofPlan` stage:

```text
AST / stdlib macro
  -> ProofPlan
  -> IR
  -> codegen
  -> metadata
```

`ProofPlan` must contain:

- invariant name and source span
- trigger
- scope
- reads
- coverage
- input/output relation checks
- group cardinality
- identity lifecycle policy
- preserved script/data/capacity fields
- witness fields and decoded proof payloads
- on-chain checked obligations
- builder assumptions
- codegen coverage status

Example diagnostic:

```text
constraint: udt_amount_non_increase
trigger: lock_group
scope: transaction
reads:
  - Source::Input
  - Source::Output
coverage:
  - only inputs sharing this lock script
warning:
  - Not equivalent to type-group conservation unless all relevant UDT inputs are locked by this lock.
on_chain_checked: yes
builder_assumption: none
```

**Code Areas**

- new `src/proof_plan/`
- invariant lowering
- IR builder
- metadata emitter
- codegen verifier coverage reporting
- `cellc explain-proof`

**Acceptance**

- strict CKB mode fails if any invariant obligation is metadata-only
- `cellc explain-proof` prints trigger/scope/reads/coverage/on-chain status
- dangerous trigger/scope combinations produce warnings or strict-mode errors
- tests compare ProofPlan obligations with emitted code coverage

---

### 4. Split Kernel Primitives from Protocol Macros

**Problem**

`Create`, `Consume`, `Transfer`, `Destroy`, `ReadRef`, `Claim`, and `Settle` sit at the same AST level. `create/consume/read_ref/mutate` are kernel-level. `transfer/claim/settle/shared/pool` are protocol-level.

**Change**

Keep these as kernel primitives:

```text
input<T>
output<T>
cell_dep<T>
create_output
consume_input
replace_input_with_output
read_ref
assert_data
assert_lock
assert_type
assert_absence
assert_field
assert_group_cardinality
```

Move these to stdlib proof macros:

```text
transfer
claim
settle
shared
pool.swap
pool.add_liquidity
pool.remove_liquidity
```

Protocol macros must lower through scoped invariants and ProofPlan, not protocol-name recognizers.

**Code Areas**

- `src/ast/mod.rs`
- `src/parser/mod.rs`
- `src/types/mod.rs`
- `src/ir/mod.rs`
- `src/codegen/mod.rs`
- stdlib macro expander
- metadata schema
- examples using protocol verbs

**Acceptance**

- strict CKB mode has no compiler-core lowering path for `transfer`, `claim`, `settle`, or `shared`
- stdlib macros expand into inspectable ProofPlan obligations
- codegen consumes ProofPlan, not protocol-name recognizers
- old syntax either lowers through compatibility macros or fails with a precise migration diagnostic

---

### 5. Add First-Class Cell Identity and TYPE_ID Lifecycle

**Problem**

v0.14 validates CKB TYPE_ID metadata plans and transaction-shape facts. v0.15 promotes identity into a first-class primitive policy across create, replace, and destroy flows. CKB TYPE_ID remains one supported identity backend, with verifier rules derived from first input, output index, and group cardinality.

**Change**

Add identity policies:

```text
identity none
identity ckb_type_id
identity field(path)
identity script_args
identity singleton_type
```

Add lifecycle forms:

```text
create_unique<T>(identity = ckb_type_id)
replace_unique<T>(identity = ckb_type_id)
destroy_unique<T>(identity = ckb_type_id)
preserve_identity(input, output)
assert_identity_absent(identity, scope)
```

**Code Areas**

- type identity attributes
- IR cell identity metadata
- ProofPlan identity obligations
- CKB TYPE_ID codegen
- metadata validation

**Acceptance**

- CKB TYPE_ID creation is runtime-checked or rejected in strict mode
- TYPE_ID continuation proves identity preservation, not only type-script preservation
- group cardinality follows CKB TYPE_ID rules
- tests cover create, replace, destroy, duplicate output, and unrelated same-type output

---

### 6. Replace Bare `destroy` with Explicit Destruction Policies

**Problem**

Current CKB lowering scans all outputs and rejects any output with the same TypeHash as the consumed input. That proves singleton-type absence, not instance destruction.

**Change**

Replace bare `destroy` with policy-specific forms:

```text
destroy_unique(cell, identity = type_id)
destroy_instance(cell, identity_field = id)
burn_amount(cell, field = amount)
destroy_singleton_type(cell)
forbid_replacement(cell, match = script_hash + identity)
```

**Code Areas**

- AST destroy node
- type checker resource obligations
- IR destroy pattern
- CKB output scan codegen
- metadata transaction obligations

**Acceptance**

- `destroy_instance` allows unrelated outputs with the same type script
- `destroy_singleton_type` preserves the current same-TypeHash absence behavior
- burn policies prove quantity deltas instead of output absence
- tests cover multi-instance cells sharing one type script

---

## P1

### 7. Covenant Helper Stdlib

**Problem**

Developers need ergonomic helpers for common lock covenant and type invariant patterns, but CellScript must not pretend it can automatically move constraints between lock and type without changing semantics.

**Change**

Add explicit helpers:

```text
lock_covenant(...)
type_invariant(...)
builder_assumption(...)
selected_cells(...)
```

Helpers must emit ProofPlan records with trigger/scope/coverage.

**Code Areas**

- stdlib invariant helpers
- macro expansion provenance
- ProofPlan metadata
- example contracts

**Acceptance**

- helper output is fully visible in `cellc explain-proof`
- no helper performs automatic lock/type placement
- builder-only assumptions are clearly marked and rejected by strict on-chain enforcement checks when required

---

### 8. Split Address, LockScript, and LockHash

**Problem**

`Address` currently behaves like a 32-byte lock hash. CKB lock identity is a full `Script { code_hash, hash_type, args }`; `lock_hash` is only its hash.

**Change**

Add distinct semantic types:

```text
Address
LockArgs
LockScript
LockHash
TypeScript
TypeHash
ScriptHash
```

Define explicit transfer macro targets:

```text
transfer_to_lock_hash(asset, lock_hash)
transfer_to_lock_script(asset, lock_script)
transfer_to_address(asset, address, resolver = standard_lock)
```

**Code Areas**

- builtin type table
- ABI/schema typing
- transfer macro expansion
- output lock verification
- builder metadata

**Acceptance**

- source code cannot pass `Address` where `LockHash` is required without a resolver
- full `LockScript` verification can check script fields, not only hash equality
- metadata distinguishes `recipient_address`, `expected_lock_script`, and `expected_lock_hash`

---

### 9. Make CKB Script Role Explicit

**Problem**

The compiler still has heuristic entry selection: `main`, first no-arg action, first action, then first lock. CKB artifacts need explicit role and entry identity.

**Change**

Add explicit entry declarations:

```cellscript
#[entry(lock)]
lock owner_lock(owner: LockHash) -> bool {
    ...
}

#[entry(type)]
action verify_transition(state: &mut State) {
    ...
}
```

or add first-class item kinds:

```text
lock_script
type_script
transition
```

**Code Areas**

- parser attributes
- AST item role
- entrypoint resolver
- codegen artifact metadata
- CLI scoped compile path

**Acceptance**

- strict CKB compile rejects modules with multiple possible entries and no explicit entry
- artifact metadata records `entry_name`, `entry_role`, and group scope
- lock and type entries cannot silently compete by source order

---

### 10. Rename Internal `type_hash`

**Problem**

CellScript uses BLAKE3 over source type names for internal type identity, while CKB TypeHash is BLAKE2b over packed `Script`. Both appear as `type_hash`.

**Change**

Rename public metadata fields:

```text
dsl_type_fingerprint
molecule_schema_hash
ckb_type_script_hash
ckb_lock_script_hash
ckb_type_id_args
```

**Code Areas**

- IR pattern metadata
- manifest generation
- scheduler metadata
- builder-facing JSON
- tests asserting metadata keys

**Acceptance**

- no public metadata field named `type_hash` refers to a source type-name hash
- CKB script hashes are always derived from packed `Script`
- migration diagnostics point old consumers to the new field names

---

### 11. Reset Resource Capability Vocabulary

**Problem**

`has transfer` and `has destroy` keep protocol verbs inside the resource type system. After protocol verbs move to stdlib macros, capabilities must describe kernel effects, not business actions.

**Change**

Replace protocol capabilities with effect capabilities:

```text
store
create
consume
replace
burn
relock
retarget_type
read_ref
```

Map old capabilities only in compatibility mode:

```text
transfer -> replace + relock
destroy  -> consume + burn | consume + assert_absence
```

**Code Areas**

- capability parser and formatter
- type checker linear obligations
- stdlib transfer/destroy macro requirements
- metadata type capability export
- migration diagnostics

**Acceptance**

- strict mode rejects `has transfer` and `has destroy`
- protocol macros state their required kernel capabilities explicitly
- metadata exports effect capabilities, not protocol verbs

---

### 12. Add Versioned Cell Data Layout Policies

**Problem**

CKB cells store bytes. Molecule schema metadata exists, but transition rules do not yet make data layout version and migration policy a primitive obligation.

**Change**

Add layout policies:

```text
#[data_layout(molecule, version = 1)]
preserve_layout<T>()
preserve_schema_hash<T>()
migrate_layout<T>(from = 1, to = 2)
assert_data_version<T>(version)
```

**Code Areas**

- type attributes
- Molecule schema manifest
- ProofPlan data-layout obligations
- deserialization bounds checks
- migration diagnostics

**Acceptance**

- schema-backed cell transitions declare preserve or migrate behavior
- migration requires explicit old/new layout binding
- metadata includes data layout hash, version, and migration policy
- strict mode rejects schema-backed replacement with no layout policy

---

### 13. Remove Claim/Receipt Name Heuristics

**Problem**

Claim logic recognizes fields and functions by names such as signer, beneficiary, recipient, amount, and claim variants.

**Change**

Require explicit proof bindings:

```cellscript
claim_proof(
    receipt,
    signer = receipt.signer_pubkey_hash,
    recipient = receipt.beneficiary,
    amount = receipt.amount,
    nonce = receipt.nonce
)
```

**Code Areas**

- receipt type checker
- claim macro
- metadata recognizers
- examples

**Acceptance**

- deleting or renaming a field does not silently change claim semantics
- compiler no longer uses function-name special cases for claim behavior
- claim examples emit the same checks through explicit ProofPlan bindings

---

### 14. Make Mutation Cardinality Explicit

**Problem**

Mutable params currently map to replacement input/output positions by ordering: consumed count plus mutation index, created count plus mutation index. This hides cardinality and pairing policy.

**Change**

Add explicit transition forms:

```text
replace_one(input, output)
split_one_to_many(input, outputs)
merge_many_to_one(inputs, output)
rebalance(inputs, outputs, invariant)
```

**Code Areas**

- mutate analysis
- IR `MutatePattern`
- codegen source selection
- metadata obligations

**Acceptance**

- one-to-one mutation keeps current behavior
- split/merge requires explicit invariant
- compiler diagnostics name the exact missing pairing or cardinality rule

---

### 15. Emit Macro Expansion Provenance

**Problem**

After protocol verbs become stdlib macros, audits need to see what each macro expanded into. Source-level `transfer` must not hide verifier obligations.

**Change**

Emit expansion provenance:

```text
macro_name
macro_version
source_span
expanded_kernel_ops
proof_plan_obligations
codegen_coverage
```

Add:

```text
cellc explain-macro <entry>
cellc explain-proof <entry>
```

**Code Areas**

- stdlib macro expander
- source span tracking
- metadata schema
- docgen audit output

**Acceptance**

- every protocol macro expansion appears in metadata
- audit output links source span to emitted kernel checks
- strict mode rejects opaque macro expansion

---

## P2

### 16. Move `shared` to a Scheduler Policy Library

**Problem**

`shared` is a scheduling/protocol policy, not a CKB primitive.

**Change**

Keep the core language limited to cell access and proof obligations. Implement shared-state flows as library policies:

```text
shared.read
shared.locked_update
shared.versioned_replace
shared.queue_claim
```

**Acceptance**

- no core AST item is required only for shared-state scheduling
- shared policies emit explicit ProofPlan constraints
- scheduler metadata is derived from ProofPlan, not from source-name recognition

---

### 17. Compatibility and Migration

**Change**

Add a migration mode:

```text
--primitive-compat=0.14
--primitive-strict=0.15
```

Add diagnostics:

```text
CS0150 transfer is now a stdlib proof macro
CS0151 destroy requires an explicit destruction policy
CS0152 Address cannot be used as LockHash
CS0153 CKB entry role must be explicit
CS0154 claim proof bindings must be explicit
CS0155 type_id lifecycle must be explicit
CS0156 protocol capabilities are not allowed in strict mode
CS0157 schema-backed replacement requires a layout policy
CS0158 invariant trigger and scope must be explicit
CS0159 lock_group + transaction scope requires explicit coverage acknowledgement
CS0160 builder assumption is not on-chain checked
```

**Acceptance**

- bundled examples compile in compatibility mode first
- strict mode migration PR changes examples to v0.15 syntax
- diagnostics include old syntax, new syntax, and affected proof obligation

---

## Release Gates

v0.15 cannot ship until:

- every invariant records trigger, scope, reads, coverage, and enforcement status
- `lock_group + transaction` covenant patterns produce coverage diagnostics
- strict CKB mode has zero protocol-verb codegen recognizers
- all protocol verbs lower through stdlib proof macros and scoped invariants
- every protocol macro has expansion provenance
- `cellc explain-proof` exposes trigger/scope/reads/coverage/on-chain status
- every CKB artifact has an explicit entry role
- `Address`, `LockScript`, and `LockHash` are distinct in type checking and metadata
- TYPE_ID lifecycle is covered by ProofPlan and runtime codegen
- bare `destroy` is removed or compatibility-gated
- resource capabilities use kernel effect names in strict mode
- schema-backed replacement declares preserve or migrate layout policy
- ProofPlan coverage is checked in tests
- examples pass in both compatibility and strict migration tracks
