# CellScript Grant Proposal Draft

**Recipient**: CKB Foundation
**Draft for**: Matt / private review first
**Author**: Arthur
**Requested support**: USD 20,000
**Initial project duration**: 8 weeks core scope, with optional 9-10 week hardening/review window
**Expected utilization**: full-time / residency-style commitment during the initial phase

---

## 1. Summary

CellScript is a DSL and compiler for building CKB-style cell contracts with compile-time safety, explicit cell transition semantics, and auditable lowering into CKB-compatible execution.

The initial grant project would focus on taking CellScript from its current working state toward a stable, ecosystem-facing release track. The work would be organized as four two-week milestone release trains: v0.13, v0.14, v0.15, and v0.16. Each milestone would produce reviewable code, examples, tests, and documentation rather than only a planning document.

The core goal is not to hide CKB's lock/type model behind a simplified abstraction. The goal is to make CKB's real safety boundaries visible:

- when a constraint runs
- what part of the transaction it reads
- which cells it actually protects
- whether it is enforced on-chain or assumed by the builder/deployment process

This directly addresses an important CKB design problem: some assertions are too rigid when forced into type scripts, some authorization logic may belong in type scripts, and lock scripts can also act as covenant-style verifiers over transaction inputs and outputs. CellScript should help developers express these distinctions clearly without pretending that lock and type scripts are interchangeable.

---

## 2. Motivation

CKB's cell model is powerful, but it is difficult to use safely. Developers need to reason about cells, locks, type scripts, witnesses, capacity, cell deps, transaction views, and script groups at the same time. Many important safety properties are not obvious from the code alone.

CellScript aims to provide a higher-level language layer that is still faithful to CKB:

- linear resource tracking for consumed cells
- explicit cell create/consume/mutate effects
- structured witness and source views
- compile-time diagnostics for unsafe cell usage
- auditable metadata showing what the generated verifier checks
- zero-cost abstractions where high-level syntax lowers to direct verifier logic

The long-term value is to make CKB contract development more approachable without weakening the security model that makes CKB unique.

---

## 3. Initial Project Scope

This proposal is for an intensive 8-week core project, with an optional 9-10 week hardening/review window if the Foundation prefers a slightly longer initial scope.

The scope is milestone-driven and focused on engineering deliverables, not ecosystem promotion.

Included:

- CellScript stable release candidate work
- existing business/protocol logic migration into DSL examples
- zero-cost abstraction hardening
- CKB semantic completeness work needed for real examples
- scoped invariant and covenant ProofPlan design/implementation
- documentation needed to review and use the initial release
- example contracts and regression fixtures

Not included in this initial grant:

- public registry construction
- ecosystem marketing or promotion
- broad cookbook/tutorial production
- long-term standard library governance
- ongoing community program management

Those areas likely need broader community participation and may be better scoped as separate follow-up proposals.

---

## 4. Main Technical Objective

The key design objective is:

> CellScript should let developers express transaction and cell invariants in a CKB-native way, while making trigger, scope, reads, coverage, builder assumptions, and on-chain enforcement explicit.

In practical terms, CellScript should not say:

```text
place this constraint in the lock script
place this constraint in the type script
```

as if those were equivalent deployment locations.

Instead, it should model the real CKB semantics:

```text
constraint = what must hold
trigger    = when the verifier runs
scope      = which cells or transaction view it reasons over
reads      = which CKB Source views it observes
coverage   = which cells are actually protected
checked    = whether this is enforced by generated on-chain code
assumption = whether this relies on builder/deployment behavior
```

Example target direction:

```cellscript
invariant udt_amount_non_increase {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>, group_outputs<Token>

    assert sum(group_outputs<Token>.amount) <= sum(group_inputs<Token>.amount)
}
```

And for covenant-style lock logic:

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
  - This is not equivalent to type-group conservation unless all relevant UDT inputs are locked by this lock.
on_chain_checked: yes
builder_assumption: none
```

This is the part of CellScript that can be especially useful for CKB: not abstracting away lock/type complexity, but making it explicit and auditable.

---

## 5. Milestones

The core 8-week plan maps cleanly to four two-week milestone releases.

These should be understood as focused release trains, not as a claim that every long-term ecosystem concern is fully solved in two weeks. Each milestone should end with reviewable code, tests, examples, metadata, and a short technical report.

### Weeks 1-2: v0.13 Stable Release Candidate

Focus:

- stabilization baseline
- existing example regression
- zero-cost abstraction hardening
- existing business/protocol logic migration into DSL examples
- release notes and status report

Deliverables:

- v0.13 release candidate checklist
- regression baseline for existing examples
- selected real business/protocol flows translated into CellScript
- evidence that high-level DSL constructs lower to direct verifier logic where possible
- metadata showing generated checks and runtime accesses
- private review package for the v0.13 stable release candidate

Outcome:

- CellScript has a credible stable release candidate foundation and realistic examples beyond toy contracts.

---

### Weeks 3-4: v0.14 CKB Semantic Completeness

Focus:

- structured witness/source views
- ScriptGroup and group-source validation
- outputs / outputs_data binding
- script reference and hash_type metadata
- TYPE_ID metadata validation MVP
- CKB-facing semantic fixtures

Deliverables:

- WitnessArgs / Source view implementation or hardening needed by examples
- ScriptGroup validation fixtures
- outputs_data binding checks
- script reference metadata table
- TYPE_ID create/continue metadata validation MVP where needed
- tests showing explicit CKB transaction semantics instead of implicit compiler assumptions

Outcome:

- CellScript exposes the CKB execution surface needed for serious lock/type/covenant examples.

---

### Weeks 5-6: v0.15 Scoped Invariants and Covenant ProofPlan

Focus:

- scoped invariant model
- aggregate invariant primitives
- trigger/scope/reads/coverage metadata
- Covenant ProofPlan
- warnings for dangerous lock/type coverage assumptions
- protocol macro lowering through scoped invariants

Deliverables:

- invariant syntax/IR model
- aggregate primitives for sum, conservation, delta, distinct field, and singleton identity
- ProofPlan records for invariants and selected protocol macros
- `cellc explain-proof` initial output
- diagnostics for `lock_group + transaction` coverage risks
- macro expansion provenance for selected protocol flows

Outcome:

- CellScript directly addresses the lock/type/covenant design issue: developers can see when constraints run, what they read, and which cells they actually protect.

---

### Weeks 7-8: v0.16 Assurance and Production Readiness Track

Focus:

- ProofPlan soundness checks
- compatibility fixtures
- builder assumption validation
- transaction validation tooling
- audit/debug package
- release candidate hardening

Deliverables:

- initial ProofPlan-to-code coverage checker
- compatibility fixture set for selected CKB-standard patterns
- builder assumption schema draft
- `cellc validate-tx --against metadata.json tx.json` prototype or equivalent validation path
- release candidate artifacts and metadata snapshots
- technical audit report for what is on-chain checked vs builder-assumed
- final private review package for Foundation/community feedback

Outcome:

- The project reaches a reviewable 0.16-oriented state: not just expressive DSL syntax, but evidence, validation, and auditability around what the DSL claims.

---

### Optional Weeks 9-10: Community Review and Hardening

If the Foundation prefers a 10-week scope, the final two weeks would focus on:

- feedback from CKB reviewers
- additional real-world example migration
- compatibility fixture expansion
- documentation tightening
- release candidate hardening
- follow-up proposal scoping for registry/cookbook/ecosystem work

---

## 6. Supporting Engineering Roadmaps

I have also prepared detailed engineering roadmaps for the v0.13-v0.16 release
train. These are separate from the main proposal so the proposal remains
readable, but they are available for technical review:

- v0.13 roadmap: https://github.com/tsukifune-kosei/CellScript/blob/cellscript-0.13/roadmap/CELLSCRIPT_0_13_ROADMAP.md
- v0.14 roadmap: https://github.com/tsukifune-kosei/CellScript/blob/cellscript-0.13/roadmap/CELLSCRIPT_0_14_ROADMAP.md
- v0.15 roadmap: https://github.com/tsukifune-kosei/CellScript/blob/cellscript-0.13/roadmap/CELLSCRIPT_0_15_ROADMAP.md
- v0.16 roadmap: https://github.com/tsukifune-kosei/CellScript/blob/cellscript-0.13/roadmap/CELLSCRIPT_0_16_ROADMAP.md
- roadmap overview: https://github.com/tsukifune-kosei/CellScript/blob/cellscript-0.13/roadmap/CELLSCRIPT_ROADMAP_OVERVIEW.md

The main proposal is intended to stand on its own; these documents are optional
supporting material for reviewers who want the detailed implementation plan.

---

## 7. Requested Support and Work Commitment

Requested grant amount:

```text
USD 20,000
```

Expected duration:

```text
8 weeks core scope, optional 9-10 week review/hardening window
```

Expected utilization:

```text
Full-time / residency-style focus during the initial phase
```

This work is intensive. It requires uninterrupted focus across compiler internals, CKB semantics, examples, documentation, and review feedback. My preference is to commit fully during the initial 2-3 month phase so the project can reach a stable release candidate and a credible ecosystem-facing technical foundation.

After the initial project, the collaboration shape can become more flexible:

- part-time maintenance
- focused follow-up milestones
- community-driven examples and cookbook work
- registry or standard library work as a separate proposal

---

## 8. Suggested Payment Structure

The Foundation mentioned a milestone-driven process with an initial payment. One possible structure:

| Payment | Amount | Trigger |
|---------|-------:|---------|
| Initial payment | USD 4,000 | Grant approval and project start |
| Milestone 1 | USD 4,000 | Weeks 1-2 complete: v0.13 stable release candidate baseline |
| Milestone 2 | USD 4,000 | Weeks 3-4 complete: v0.14 CKB semantic completeness milestone |
| Milestone 3 | USD 4,000 | Weeks 5-6 complete: v0.15 scoped invariants and Covenant ProofPlan milestone |
| Final payment | USD 4,000 | Weeks 7-8 complete: v0.16 assurance and production readiness package |

This can be adjusted to match the Foundation's process.

---

## 9. Expected Outputs

By the end of the initial grant, expected outputs include:

- stable CellScript release candidate
- four two-week milestone release trains: v0.13, v0.14, v0.15, v0.16
- migrated real-world example flows
- regression test suite for examples
- CKB semantic fixtures for source/witness/group behavior
- zero-cost abstraction evidence
- scoped invariant model
- Covenant ProofPlan output
- initial covenant diagnostics
- initial ProofPlan soundness/coverage checks
- builder assumption validation path
- release notes
- technical audit summary
- clear follow-up scope for community-facing work

---

## 10. Collaboration Needs

The main support needed from the Foundation/community side:

- review of whether the CKB semantic framing is correct
- feedback on lock/type covenant use cases
- review of examples that should matter to CKB developers
- guidance on standard script compatibility priorities
- later community participation for cookbook, docs, registry, and ecosystem packaging

I can prepare the first private draft and adapt it based on Foundation feedback before anything is made public.

---

## 11. Closing

CellScript is trying to make CKB development safer without flattening CKB's unique model.

The most important principle is:

> Do not hide lock/type complexity. Make trigger, scope, coverage, and assumptions explicit and auditable.

With focused support, the next phase can turn CellScript from a promising compiler project into a serious foundation for CKB-native contract development.
