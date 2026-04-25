# CellScript v0.16 Roadmap

**Status**: Draft
**Scope**: Formal Semantics, Standard Compatibility, and Production Tooling
**Dependencies**: v0.13, v0.14, and v0.15 complete

---

## Goal

v0.16 turns the v0.15 semantic audit layer into production-grade assurance.

v0.15 makes CKB invariants visible:

- trigger
- scope
- reads
- coverage
- on-chain checked obligations
- builder assumptions

v0.16 answers the next questions:

- Can we prove the invariant model is sound?
- Can CellScript match standard CKB contract behavior, ABI/layout, error behavior, and cycle envelopes where needed?
- Can wallets/builders/indexers honor the assumptions emitted by the compiler?
- Can developers debug, audit, deploy, and upgrade contracts without relying on ad hoc tooling?

---

## Out of Scope

Do not re-plan v0.13:

- bounded value generics
- zero-cost abstraction passes
- CLI baseline ergonomics

Do not re-plan v0.14:

- Spawn/IPC DSL
- WitnessArgs and Source views
- ScriptGroup / outputs_data / TYPE_ID metadata MVP
- capacity/time/since syntax
- script reference and HashType strictness

Do not re-plan v0.15:

- scoped invariants
- Covenant ProofPlan
- trigger/scope/reads/coverage modeling
- protocol macro lowering
- identity lifecycle primitives
- explicit destroy policies

---

## P0

### 1. Formal Operational Semantics

**Problem**

CellScript will have a rich invariant model after v0.15, but the language still lacks a formal semantics for resource states, cell effects, script triggers, scopes, and ProofPlan obligations.

**Change**

Publish a machine-checkable or mechanically precise semantics for:

- expression evaluation
- linear resource state transitions
- branch merge rules
- cell input/output/ref effects
- lock/type trigger execution
- group and transaction scopes
- ProofPlan obligation coverage
- builder assumption boundaries

**Artifacts**

- `docs/spec/CELLSCRIPT_OPERATIONAL_SEMANTICS.md`
- formal small-step or big-step rules
- executable reference checker for selected rules
- conformance fixtures linked to compiler tests

**Acceptance**

- every v0.15 ProofPlan field has a formal meaning
- resource state rules match type checker behavior
- trigger/scope/coverage examples have expected formal outcomes
- compiler tests include spec conformance fixtures

---

### 2. ProofPlan Soundness Checks

**Problem**

`ProofPlan` is auditable metadata, not a proof. v0.16 must verify that ProofPlan obligations match emitted code and cannot overstate enforcement.

**Change**

Add soundness checks:

```text
source invariant
  -> ProofPlan obligation
  -> IR operation
  -> codegen check
  -> metadata coverage record
```

Add an internal checker that rejects:

- metadata-only obligations in strict mode
- missing emitted checks
- mismatched source views
- incorrect group cardinality coverage
- unchecked builder assumptions marked as on-chain
- stale ProofPlan records after optimization

**Code Areas**

- `src/proof_plan/`
- IR validation
- codegen coverage emitter
- metadata validation
- optimization passes

**Acceptance**

- strict mode fails if ProofPlan and emitted code diverge
- optimization cannot remove checks without updating ProofPlan
- negative tests mutate metadata/codegen coverage and are rejected

---

### 3. Standard CKB Contract Compatibility Suite

**Problem**

CellScript can express CKB-native semantics, but it still needs fixture-level compatibility with standard CKB scripts and ecosystem conventions.

**Change**

Create compatibility suites for:

- sUDT
- xUDT
- ACP
- Cheque
- Omnilock-compatible lock patterns
- NervosDAO-style epoch/since fixtures
- Type ID

Each suite must cover:

- script args layout
- witness layout
- Molecule data layout
- error behavior
- accepted/rejected transaction fixtures
- cycle envelope
- script reference metadata

**Artifacts**

- `tests/compat/ckb_standard/`
- fixture transactions
- expected metadata snapshots
- cycle reports

**Acceptance**

- CellScript fixtures match standard script behavior for accepted/rejected cases
- metadata exposes exact script args/witness/data assumptions
- incompatibilities are documented as intentional and profile-gated

---

### 4. Builder Assumption Contract

**Problem**

v0.15 marks builder assumptions, but wallets, SDKs, relayers, and transaction builders need a stable contract to honor them.

**Change**

Define a builder assumption schema:

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

Add validation APIs:

- `cellc explain-assumptions`
- `cellc validate-tx --against metadata.json tx.json`
- SDK assumption validator

**Acceptance**

- every builder assumption has a stable schema record
- generated transaction templates include assumption IDs
- validation rejects transactions that violate assumptions before signing

---

## P1

### 5. Transaction Solver

**Problem**

Builder templates are not enough. Real applications need a solver for cell selection, capacity, fees, change outputs, witness placement, dep resolution, and multi-party signing flows.

**Change**

Add a transaction solver that consumes:

- action metadata
- ProofPlan
- builder assumptions
- available cells
- signing policy
- target profile

Solver responsibilities:

- cell selection
- dep resolution
- output planning
- occupied capacity calculation
- fee/change planning
- witness placement
- signature request manifest
- dry-run validation

**Acceptance**

- solver can build transactions for all bundled examples
- solver emits a deterministic signing manifest
- solver validates builder assumptions before finalization
- failure messages point to missing cells, deps, witnesses, or capacity

---

### 6. Deployment and Upgrade Governance

**Problem**

CKB deployment is a governance problem: code cells, dep groups, hash types, Type ID, audit labels, and version locks need a stable workflow.

**Change**

Add deployment governance artifacts:

- code cell manifest
- dep group manifest
- version lock file
- audit hash record
- upgrade policy
- rollback policy
- script reference registry entry

Add commands:

```bash
cellc deploy-plan
cellc verify-deploy
cellc diff-deploy
cellc lock-deps
```

**Acceptance**

- deployments are reproducible from manifests
- upgrade diffs identify script hash, args, data layout, and ProofPlan changes
- registry entries include audit status and compatibility range

---

### 7. Audit and Debug UX

**Problem**

`explain-proof` is necessary but not enough for production audits. Developers need traceable source-to-code, proof diff, cycle, and transaction execution views.

**Change**

Add audit tooling:

- source maps from CellScript to RISC-V assembly
- proof diff between versions
- cycle profiler per invariant/check
- tx trace viewer
- coverage report for invariants and assumptions
- HTML audit bundle

**Commands**

```bash
cellc explain-proof
cellc proof-diff old.json new.json
cellc profile --entry transfer
cellc trace-tx tx.json
cellc audit-bundle
```

**Acceptance**

- audit bundle links source spans, ProofPlan obligations, emitted code, and metadata
- proof diff highlights changed trigger/scope/coverage semantics
- cycle profiler identifies the most expensive generated checks

---

### 8. Standard Library Release Track

**Problem**

v0.16 should not make the standard library the main language milestone, but the compatibility suite needs curated library modules for common patterns.

**Change**

Ship audited stdlib modules as wrappers over v0.15 scoped invariants:

- `std::sudt`
- `std::xudt`
- `std::type_id`
- `std::htlc`
- `std::cheque`
- `std::acp`

Rules:

- stdlib modules must expose ProofPlan
- no hidden builder assumptions
- compatibility fixtures required before marking stable

**Acceptance**

- each stable stdlib module has compatibility fixtures
- module docs include trigger/scope/coverage explanation
- audit bundle generated for each module

---

## P2

### 9. Advanced Linear Collections

**Problem**

v0.13 intentionally avoids cell-backed generic collections, and v0.15 does not solve them. Some protocols need collections of linear or cell-backed resources.

**Change**

Design, but do not rush, bounded forms:

```text
Vec<CellRef<T>>
Map<Key, CellRef<T>>
IndexedSet<T>
```

Constraints:

- no hidden ownership transfer
- no implicit consume inside collection operations
- explicit iteration bounds
- ProofPlan records collection coverage

**Acceptance**

- design doc published
- unsafe collection forms remain fail-closed
- prototype examples show explicit ownership and coverage

---

### 10. Formal Verification Backend Exploration

**Problem**

Operational semantics and soundness checks are not full formal verification.

**Change**

Explore one or more backends:

- SMT encoding for bounded invariants
- K-framework semantics
- Lean/Coq model for core resource calculus
- model checker for transaction-shape fixtures

**Acceptance**

- one prototype proves a non-trivial invariant
- limitations are documented
- no production guarantee is claimed without proof coverage

---

## Release Gates

v0.16 cannot ship until:

- operational semantics document covers resource state, cell effects, triggers, scopes, and ProofPlan
- ProofPlan soundness checker is mandatory in strict mode
- standard CKB compatibility suites cover accepted and rejected fixtures
- builder assumption schema is stable
- `cellc validate-tx` checks builder assumptions against a transaction
- transaction solver builds all bundled examples
- deployment manifests are reproducible
- audit bundle links source, ProofPlan, emitted code, metadata, and cycles
- stdlib stable modules have compatibility fixtures and audit bundles
