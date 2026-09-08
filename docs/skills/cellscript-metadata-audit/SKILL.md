---
name: cellscript-metadata-audit
description: CompileMetadata, ProofPlan, builder assumptions, constraints, ABI, audit bundles, receipts, and artifact verification.
references:
  - docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md
  - docs/wiki/Tutorial-11-Scoped-Invariants-and-ProofPlan.md
  - docs/wiki/Tutorial-14-Verified-Artifacts-and-Executable-Tests.md
  - docs/CELLSCRIPT_GATE_POLICY.md
  - docs/CELLSCRIPT_VERIFIED_ARTIFACT_BOUNDARY.md
  - docs/CELLSCRIPT_POLICY_WITNESS_ABI.md
commands:
  - cellc metadata
  - cellc expand
  - cellc constraints
  - cellc explain proof
  - cellc audit-bundle
  - cellc verify-artifact
  - cellc verify-receipt
---

# CellScript Metadata Audit

Use this skill when reviewing compiler evidence. Treat metadata as an audit
stream, not consensus truth. ProofPlan rows, TemplateLayout records, receipts,
constraints, ABI, and builder assumptions explain what the compiler emitted and
what remains to be checked by builders or CKB nodes.

For the `0.30` development branch, inspect current metadata schema 71 under
Edition 2026 or the separately routed Edition 2027 preview and the resolved
compatibility profile, together with typed-semantics v8, semantic-foundation
v3, lowering-record v8, source-map v2, and the
`cellscript-ckb-runtime-view-v1` runtime contract for CKB ELF builds. Use
`cellc expand` for the deterministic diagnostic rendering; do not hash that
rendering or treat it as a source-equivalence proof. Typed transaction views, bounded
signing-message domains, bounded
quantifiers/collections, capability proofs, enum layouts, validity predicates,
borrow regions, and `fungible-type-group-v1` evidence introduced on the 0.22
line remain part of that evidence stream. The 0.25 value-generic kernel adds
`generic_instantiations` with canonical source identities, concrete internal
names, type arguments, and the closed value-ability registry.

For each executable source `require` or Edition 2027 `enforce`, audit the
semantic foundation's `entry-condition` claim together with its
`evidence_reference` and `execution` binding. The binding must identify the
condition provenance node, ordered typed success/failure blocks, and exact
fail-closed runtime error. Keep supporting `proof-plan:<name>` claims separate;
neither claim kind is a complete source-equivalence proof.

For `current-vm-process-exit-v1`, distinguish terminal `verifier_failure_exits`
from diagnostic runtime statuses and ordinary callable values. The checker
binds static error loads to an exact non-returning machine sink and rejects
interior jump targets. It does not prove every implicit guard or arbitrary
dynamic-status dataflow merely because the terminal sites validate.

For a selected persistent Type policy, inspect the canonical tag map, full
Script-hash selector, ordered common checks, group roles and parameter codec
projection together. Consult `docs/CELLSCRIPT_POLICY_WITNESS_ABI.md` for the
outer witness contract. These structural records alone do not prove machine
dispatch dataflow; `cellc verify-artifact` additionally checks the bounded v8
scanner, selector, common-check dominance and exact action adapters. A deployed
Script identity and transaction authorization remain separate evidence.

Distinguish evidence states precisely: compile-only, metadata-only,
runtime-required, helper-backed, builder-backed, node dry-run, tx-pool accepted,
submitted, and externally attested.

Validation defaults:

- run `cellc metadata . --target-profile ckb` to inspect metadata without
  writing a file;
- run `cellc explain proof . --target-profile ckb --json` for ProofPlan;
- run `cellc verify-artifact` before trusting the artifact/metadata/lowering/
  source-map identity and structural contract;
- keep the report's binding, structural, lowering-record, CKB-VM, chain, and
  semantic-equivalence fields separate.
