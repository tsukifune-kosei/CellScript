# CellScript 0.30 Business Corpus

**Status**: Candidate contract, frozen inventory; release evidence incomplete

This document defines the finite business portfolio behind the statement that
CellScript 0.30 aims to provide application-layer coverage comparable to
hand-written Rust CKB Scripts. The claim applies only to the bounded portfolio
below. It does not claim arbitrary Rust language, library, syscall, or contract
parity.

The canonical machine-readable inventory is
[`tests/fixtures/business_corpus.json`](../tests/fixtures/business_corpus.json).
`cellscript-tools check-business-corpus` validates its eight family IDs,
evidence-layer classifications, anchor requirements, referenced Git files, and
one SHA-256 digest over the complete frozen inventory. The `dev`, `ci`, and
`backend` gates run that validator. Stale, missing, untracked, duplicated, or
path-escaping evidence fails the gate.

## Frozen portfolio

| Family | Required business boundary | Principal executable evidence |
|---|---|---|
| Fungible asset | Authorized lifecycle, bounded split/merge, conservation, identity and overflow failures | `bounded_group_input.rs`, `bounded_output_plan.rs`, `entry_witness_abi.rs`, and matched Rust references |
| NFT or DOB | Unique mint, metadata/owner/capacity transitions, burn, stale and unauthorized failures | `nft.cell`, example checks, production acceptance, and the matched NFT Lock cost row |
| Order and AMM | Partial fill/cancel/settle, variable payments, price/reserve rules, ordered outputs, authenticated dependency | iCKB differential fixtures, AMM examples, cost corpus, and the composition anchor |
| Temporal | Absolute/relative locks, vesting, epochs, timestamps, blocks, headers, and `Since` | typed runtime-view and iCKB CKB-VM fixtures |
| Authorization | Standard signing, multisig, issuer and Script identity, post-signing mutation rejection | bundled multisig-v2, SDK signing, policy lifecycle, and sighash fixtures |
| Committed state | Authenticated opening, successor commitment, shared witness ownership, stale/root/index failures | bounded hash/Merkle CKB-VM cases, schema acknowledgements, and matched schema-roll reference |
| Multi-Script composition | At least three artifacts, interacting Type and Lock groups, ProtocolBundle conflicts and exact identities | `business_corpus.rs`, ProtocolBundle CLI and adapter tests |
| External verifier | Exact-identity EXEC or SPAWN/WAIT with explicit trusted boundary and substitution failures | `trusted_external.rs` and exact-handle CKB-VM cases |

The companion transaction inventory
[`tests/fixtures/business_transaction_inventory.json`](../tests/fixtures/business_transaction_inventory.json)
names the required positive and adversarial scenarios and the Rust fixture that
constructs each canonical Molecule transaction.

## Same-transaction anchor

The current executable anchor is an authenticated two-order settlement. One
CKB transaction runs three independently compiled CellScript ELFs and four
actual Script groups:

1. an authorization Lock validates the protected fungible input;
2. a fungible Type Script enforces amount conservation;
3. an order Type Script consumes two GroupInput orders and checks a two-element
   output Plan against GroupOutput order, data, Lock, Type, and capacity; and
4. the order policy binds an exact CellDep data hash.

The CKB-VM test rejects a wrong authorization credential, fungible inflation,
partial-settlement mismatch, and dependency substitution. Its pinned resource
record is 26,588 cycles, 9,384 combined ELF bytes, a 5,376-byte largest checked
stack frame, 160 witness bytes, a 1,023-byte transaction, and 24.6 CKB occupied
capacity. Budgets in
[`tests/fixtures/capability_anchor_cases.json`](../tests/fixtures/capability_anchor_cases.json)
fail on regression.

The anchor establishes real same-transaction Script interaction. The existing
ProtocolBundle and generated-builder suites independently cover artifact
admission, role/index/witness/CellDep conflict handling, canonical transaction
materialization, signing handoff, and exact transaction identity. A later
candidate change must join those paths to the anchor transaction before the
multi-Script row can be marked release-complete.

## Evidence state

Every family records parser/type/IR, metadata/checker, simulator, CKB-VM,
stateful, node-admission, builder/signing, deployment, measurement, and review
layers separately. `passed`, `not-applicable`, `pending`, and
`release-candidate-required` retain their literal meanings. A lower layer is
never treated as evidence for a higher layer.

The inventory remains `candidate` because selected-network node admission and
deployment identities, the stateful multi-action anchor lifecycle, and
independent review are still pending. `check-business-corpus --release` rejects
that state. Stable versioning, tags, package publication, editor/browser
publication, and network deployment remain outside this candidate record.

## Updating the corpus

Change a family, fixture, reference, or evidence owner only as an explicit
portfolio change. Then run:

```bash
cargo run --quiet --locked -p cellscript-tools --bin cellscript-tools -- \
  --root . check-business-corpus --write
```

Review the inventory diff, run the owning focused tests, and run the applicable
unified gates. Release validation additionally requires `status = "accepted"`,
all family layers complete or deliberately not applicable, and every release
requirement passed.
