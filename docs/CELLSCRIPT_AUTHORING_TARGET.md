# CellScript Authoring Target

## Decision and status

**Status: authoring direction adopted on 2026-09-05; detailed contracts and
grammar remain under design. This document does not describe new executable
syntax shipped by the compiler.**

The next authoring surface will retain the learning model of Edition 2026:
`resource`, `action`, `lock`, ordinary value types, helpers, and `require`.
It will make transaction roles and successor relations easier to read, and
support several actions under one persistent deployed Script policy. Routine
contracts should express business choices without spelling out physical
witness locations or every field of an internal semantic record.

The versioned typed semantic model developed on `0.26b` remains the foundation.
Its provenance, role binding, disposition, enforcement classification, and
identity records can evolve where the new contracts require it. The verbose
preview4 grammar remains an implementation reference during migration; it is
not the final authoring target or a mandatory intermediate language.

This decision updates the authoring direction and sequencing in the
[semantic-foundation RFC](CELLSCRIPT_1_0_SEMANTIC_FOUNDATION_RFC.md). The
[preview grammar](CELLSCRIPT_2027_PREVIEW_GRAMMAR.md) continues to specify
the retained bounded native grammar introduced by
`cellscript-source-semantics-2027-preview4`. The current
[implementation checklist](CELLSCRIPT_AUTHORING_IMPLEMENTATION.md) tracks the
separate `authoring1` frontend and remaining work against this complete target.
Edition 2026, existing runtime ABIs, and existing gate requirements retain their
current meaning. No new compiler, source-semantics, or ABI version is assigned
by this design decision; later implementation identities are recorded in the
[edition policy](CELLSCRIPT_EDITION_POLICY.md).

## Author experience

| Area | Adopted direction | Remaining decision |
|---|---|---|
| Vocabulary | Keep `resource`, `action`, `lock`, and `require`. | Exact action trigger and artifact declaration spelling. |
| Roles | Show input, output, witness, and read-only roles. Use defined defaults for routine physical bindings. | Selector rules, aliasing, group coverage, and read-only source categories. |
| Successors | Express preservation and updates together in one structured relation. | Final `replace` grammar and policy overrides. |
| Sections | Preserve readable branching in the existing verification model. | Whether a `verification` section remains useful; mandatory `verify`/`effects` separation is not adopted. |
| Preservation | Admit `same except` when schema changes require focused review. | Acknowledgement representation and its integration with upgrades. |
| Multiple actions | Support several operations under one declared deployed policy. | Artifact declaration, versioned dispatch, and builder contract. |
| Evidence | Keep executable conditions distinct from audit-only claims. | Optional audit spelling; authors need not learn the provenance graph. |
| Composition | Keep builders and artifact interfaces as the initial composition boundary. | Actor routing and `.celltx` remain deferred. |

Edition 2026 already defines verification as constraints on a candidate
transaction. The new surface improves that existing model. A successor
declaration generates its own checks; authors do not repeat those checks in a
second section. Ordinary `if` and `match` branches should keep conditions close
to the relations they govern. Every accepting path must account for its roles
and required obligations.

The following is a proposed fragment for evaluation, not runnable preview4:

```text
replace before -> after {
    data = same except {
        owner = recipient
    }
    lock = exact_hash(recipient_lock_hash)
    capacity = same
}
```

Here `recipient` is a data-field value. `recipient_lock_hash` denotes the
expected hash of the complete destination Lock Script, under the type contract
described below. Neither value proves authorization. The surrounding action
and its declared policy supply roles, schema identity, and authorization rules.
An explicit preservation list remains a comparison candidate:

```text
data {
    same { collection_id, token_id, metadata_hash }
    owner = recipient
}
```

The comparison must establish a canonical form without accumulating redundant
spellings. It must also test ordinary updates, branches, and schema changes.

## Direct semantic elaboration

The authoring frontend must lower directly into structured, versioned semantic
representations. Generating preview4 text and parsing it again is not the
permanent implementation architecture. `cellc expand` renders the semantic
model for inspection; its printed form is not a second source-language
requirement and is not the hash input.

Existing semantic records and checker infrastructure should be reused where
they express the required contract. If a feature needs a new relation or
enforcement rule, specify that change separately from its surface spelling.
The source AST may retain spelling and spans for formatting and diagnostics.

Equivalent cases must be compared by role bindings, obligations, failures,
and accepted/rejected transactions as well as semantic identities. Matching
IDs alone do not establish correct elaboration or machine-code generation.
Independent checking retains the bounded claims documented in the
[verified-artifact boundary](CELLSCRIPT_VERIFIED_ARTIFACT_BOUNDARY.md).

## Contracts required before grammar freeze

### A1. Multiple actions under one persistent policy

A declared artifact must select its action set and dispatch contract. Multiple
actions in a module alone do not satisfy this requirement. For actions sharing
one policy, the initial implementation target is one deployed verifier with
explicit dispatch. A different routing mechanism needs its own concrete,
verified contract before it can be substituted.

CKB locates code through the Script's `code_hash` and `hash_type`. Consequently,
an existing Cell bound to one code data hash cannot select an unrelated action
ELF merely because a builder chooses it. This requirement follows from
[CKB code location](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#code-locating).

Retain scoped `--entry-action` builds for isolated compilation, tests, and
independently deployed policies. They are not the shared-policy dispatch path.
The artifact declaration's source or manifest spelling is open; ordinary
action bodies should not contain manual selector decoding.

The dispatch contract must define the selector source, encoding, version,
unique action mapping, bounded payload schemas, and rejection of unknown tags,
malformed payloads, and ambiguous mappings. It must bind the selected action
set and common obligations into entry/interface/artifact identities and the
builder recipe. No action name, declaration reordering, or transaction-shape
heuristic may silently select or renumber a branch. A caller-controlled
selector grants no authority; every selected action must enforce its own
authorization and all applicable shared policy.

Changing the action set or ABI must report deployment impact. A new source
edition does not upgrade already deployed code or change an existing Script's
identity.

### A2. Authorization and exact Lock identity

A witness assertion such as `claimant == token.owner` checks two values. When
the owner is public, anyone can supply that witness. Provenance records its
origin but does not authenticate it.

Reference ownership policies must establish credential control using a real
authorization mechanism. A signature-based example must bind an authenticated
owner credential to a specified transaction-signing message and demonstrate
rejection of missing/invalid signatures and signed-transaction tampering.
An established external Lock may supply that authorization when its identity
and applicability are actually enforced. `audit` is never a substitute.

Keep address decoding, Script construction, Script hashing, hash comparison,
and signature verification distinct in the API and types. CKB hashes the
serialized complete Script; hashing an address string or comparing only
`code_hash` is not that operation. See the
[CKB Script hash definition](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#script-hash).

Current preview4 `exact_hash(expr)` continues to accept the legacy `Address`
representation and lowers to comparison with the expected 32-byte output Lock
Script hash. It performs no address parsing or signature verification.

The 0.30 authoring route now freezes the narrower source-value contract:
`exact_hash(expr)` requires `ScriptHash`. Complete Lock and Type Script hashes
read from typed CKB transaction views have that type. A trusted raw `Hash` must
cross the domain explicitly through `ckb::script_hash(hash)`; that conversion
does not prove that a corresponding Script exists, is deployed, or authenticates
the transaction. Verifying an already-known complete Script hash therefore does
not require constructing a Script object in source. Address decoding, hashing a
newly constructed complete Script, and signature verification remain separate
API work under the 0.30 closure plan.

The exact-artifact path is now executable through the ordinary fixed-width
`ExactScriptHandle` value. A consuming contract embeds the CKB Blake2b-256 hash
of the complete checked handle as a `Hash` literal, then calls one of the
`ckb::require_cell_*_exact_handle` helpers. The runtime checks all 202 handle
bytes and the selected full Script hash or verifier CellDep data hash. This is
an exact deployed-artifact reference; it does not perform Registry lookup,
grant Cell lifecycle authority, establish signature authorization, or accept a
compatible upgrade. See [Exact Script handles](CELLSCRIPT_EXACT_SCRIPT_HANDLES.md).

### A3. Preservation and schema evolution

For a concrete schema, `same except` can produce exhaustive checks. Accept it
under the following contract:

- Resolve the relation against an identified concrete schema, including
  imported or instantiated schema identity where applicable.
- Expand every field as preserved or explicitly assigned; reject unknown,
  duplicate, or incompatible assignments.
- When a schema change affects that expansion, require a focused migration
  acknowledgement bound to the affected action/relation and old/new schema
  identities before the candidate upgrade is accepted.
- Show the changed field treatments and policy choice. A changed semantic hash,
  formatter pass, or routine dependency repin is not acknowledgement.
- Invalidate an acknowledgement when the bound schemas or relation change.
  The acknowledgement is review evidence, not an on-chain condition.

The mechanism must be reproducible and enforceable in the affected build and
upgrade workflow. Its storage, command, and first-baseline rules remain open.
It must not silently mutate `Cell.lock` or `Deployed.toml`. A new field in source
does not alter existing deployed bytes.

The decisive fixture adds `approval_nonce` and specifies that transfer resets
it. Rebuilding the unchanged `same except` relation must not silently accept
automatic preservation as a reviewed upgrade. After an explicit reset and
acknowledgement, the new relation must pass; the old preservation behavior
must fail the new protocol's negative transaction test.

### A4. Independent relations and scoped responsibility

Identity continuity, asset accounting, capacity, and authorization can apply
simultaneously to the same Cells. The core must express those obligations
separately, while surface constructors offer useful combinations. A role's
unique lifecycle accounting must not prevent it from participating in several
independent checks. Distinctness rules must prevent counting one Cell twice in
the same accounting relation.

The existing envelope separates several dimensions and `AuthorizationOnly`
already marks some as unconstrained by the Lock artifact. Extend that approach
with precise responsibility and coverage. Do not infer individual persistent
identity for fungible Cells simply because their schema is a resource.

Each obligation must state whether the current verifier checks it, a specific
chain rule supplies it, it is outside this policy's scope, or an authenticated
external mechanism supplies it. The existing evidence taxonomy remains
authoritative. An external-mechanism claim must establish the exact identity,
applicability, and required guarantee; a name or owner label is insufficient.
Placing a required business condition outside scope must not silently satisfy
it. Builder-computed capacity does not prove an artifact-local equality.

### A5. Constructor and role defaults

| Construct | Contract that must be determined by source or its declared context |
|---|---|
| `replace` | One successor for this relation, exact correspondence, declared identity policy if any, complete data treatment, and Type Script policy. Define allowed additional group members separately. |
| Lock omission | Decide whether omission preserves the complete Lock Script or is rejected. A change must be explicit; omission cannot silently release the constraint. |
| Capacity | `same` means exact equality. Define permitted alternatives and their enforcement. Keep lock/capacity choices visible locally or through a named, inspectable policy. |
| `pool` | Authenticated asset domain, supported arithmetic and overflow behavior, distinct members, input/output coverage, and capacity policy. A matching data schema alone is insufficient asset identity. |
| Retirement and creation | Exact retirement/absence and creation/identity rules. Separate logical retirement from fungible quantity destruction and its authorization. |
| Implicit ordinals | Indexed source, membership, ordering, alias rejection, and coverage. Fixed local declaration order may be the defined default; other selectors need an explicit contract. |

All omitted choices must have a single defined meaning under the resolved
context. Reject a constructor when its meaning cannot be determined. A
relation-local one-to-one successor must not accidentally declare the whole
transaction or Script group to contain exactly one input and one output.
Unexpected group members must either be covered by the declared policy or
rejected. These are per-accepting-path checks, including conditional relations.

### A6. Witness placement belongs to the entry ABI

The `witness` qualifier should identify logical argument provenance. The entry
ABI defines its physical location for the invocation context and exposes that
location in expansion, interfaces, and builder metadata.

The current placement ABI already loads `GroupInput#0` and falls back to
`GroupOutput#0` when the active group has no inputs; both use the specified
`WitnessArgs.input_type` envelope. Preserve that existing behavior when claiming
compatibility. See the [entry witness ABI](CELLSCRIPT_ENTRY_WITNESS_ABI.md).

Before freezing the new contract, cover Type entries with inputs, output-only
Type creation, Lock entries, multi-action payloads, and overlapping groups
sharing a witness. Define ownership, bounds, and multiplexing so argument,
signature, plan, and proof bytes cannot overwrite each other or be moved after
signing. Change payload or placement identities explicitly when needed;
source-edition selection alone cannot change the wire format.

## Evaluation and acceptance

The authoring comparison uses Edition 2026 with a narrow successor refinement
and the fuller preview-style section structure. Ask a developer to explain the
obligations, add a branch, change a field, and reorder an output. Record
misunderstandings, duplicated decisions, missing checks, and the diagnostics
needed to make each edit. Choose the simpler form only when its checked meaning
is equally clear.

| Fixture | Required positive evidence | Required negative or change evidence |
|---|---|---|
| One deployed Token policy | Authorized mint of enough Cells, transfer, merge, and final burn, all under the same Token Type Script identity and declared dispatch. | Unknown/ambiguous selector, wrong payload, unauthorized mint/burn, and attempted substitution of a separate action ELF. |
| Ownership Lock | Actual owner authorization bound to the transaction. | Copied public owner value, missing/invalid proof, and tampering after signing. |
| Token schema evolution | Upgrade adds `approval_nonce`; transfer explicitly resets it after focused acknowledgement. | Unchanged-source preservation cannot silently pass upgrade review; stale acknowledgement is rejected. |
| Persistent NFT policy | Transfer, explicitly permitted capacity adjustment, and retirement under one policy; identity retained where required. | Duplicate successors, wrong identity, and an unpermitted capacity change. |
| Fungible accounting | Split/merge within one authenticated asset domain, with explicit issuance/destruction policy. | Same-layout foreign asset, arithmetic overflow, two names bound to one input, and missing or extra unaccounted outputs. |
| Partial order | Continuing order state, payment, and change have distinct, composable obligations. | Underpayment, unauthorized cancellation, missing branch accounting, and reused payment roles. |
| Dependencies and groups | An authenticated oracle dependency and several Script groups compose with the declared witness layout. | Substituted dependency, reordered/aliased bindings, and overlapping payload ownership. |

The Token lifecycle must use the actual generated policy as its Type Script;
an `always_success` resource Type Script with separately run action ELFs does
not satisfy this fixture. Record deployed code identity, executed selector,
transaction, consumed/live Cells, and the applicable VM/chain evidence at every
step. These are future acceptance requirements, not results claimed here.

For existing equivalent behavior, compare canonical obligations, role binding,
public interfaces, runtime errors, and positive/negative CKB-VM results. Record
deliberate semantic tightening separately. Changing dispatch, witness bytes,
or deployment identity is not a source-only migration even if some action
conditions remain identical.

## Work order and ownership

| Work | Owning boundary | Acceptance artifact |
|---|---|---|
| Define A1-A6 | Language semantics, ABI, and artifact contracts | Reviewable rules, rejected cases, and identity/compatibility impact. |
| Compare authoring candidates | Frontend, formatter, and language services | Same representative contracts and observed editing/readability results. |
| Implement existing-meaning shorthand | Frontend and semantic lowering | Exact expansion plus differential execution evidence. |
| Implement dispatch and missing relations | Entry ABI, typed semantics, backend, checker, and builders | Shared-policy lifecycle and independent negative checks. |
| Add schema acknowledgement | Schema/interface compatibility and upgrade workflow | Reviewed field-policy delta with stale/missing acknowledgement rejection. |
| Freeze authoring grammar | Language and tooling maintainers | Accepted corpus and coherent parser/types/lowering/checker/editor/docs behavior. |

These are component responsibilities, not assignments to named people or a
release schedule. Existing gates apply: `dev` before commit, `backend` for
runtime/IR/ABI changes, `ci` for merge readiness, and the applicable release
evidence before production claims.

Inventory and pin the exact existing contracts needed by each change.
Prototyping a faithful shorthand need not wait for a blanket freeze of every
0.26 subsystem or every future semantic identity scheme. Unsupported semantics
require a separate contract before implementation. Preserve Edition 2026's
meaning and classify source, layout, ABI, effects, builder, and deployment
changes independently.

## Issue reconciliation

This table applies the RFC's recorded issue scope to the new direction. It is
a local design reconciliation on 2026-09-05, not a refresh of GitHub status or
an assertion that any issue is closed.

| Issues | Constraint on this target |
|---|---|
| #7, #8 | Reconcile default selectors, unique role accounting, asset domains, and output coverage. Existing bounded 0.26 runtime support does not establish the new native contract. |
| #9 | Artifact composition and builders retain ownership of transaction construction. Same-policy dispatch is required here and cannot be deferred as optional `.celltx` work. |
| #10, #11 | Reuse authenticated role/Script identity for external guarantees. Ordinary source types and audit labels do not grant foreign authority. |
| #12, #13, #22 | Temporal, opening, and ZK surfaces remain separate work. Any payload they introduce must obey the shared entry ABI. |
| #14 | Record authoring target, implemented preview, shared-policy runtime, and product/release evidence as distinct states. |
| #15-#20 | Respect graph, compiler, chain identity, and upgrade contracts. Schema acknowledgement must compose with interface and upgrade review; it does not implicitly repin, publish, or deploy. |
| #21 | Keep diagnostic spans and generated-code provenance available without treating their text as semantic identity. |
