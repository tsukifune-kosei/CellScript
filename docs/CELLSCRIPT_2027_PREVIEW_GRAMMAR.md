# CellScript Edition 2027 Preview Grammar

## Status

**Implemented experimental preview from branch `0.26b`, retained on `0.30`.
Not a frozen CellScript 1.0 grammar, migration promise, production-equivalence
claim, or release commitment.**

The [authoring target adopted on 2026-09-05](CELLSCRIPT_AUTHORING_TARGET.md)
retains `resource`, `action`, `lock`, and `require` and calls for concise
successor relations and multiple actions under one deployed policy. This
document remains the exact implemented preview4 reference. Its verbose text
is not the final authoring grammar or a required intermediate language.

This document is the source contract for the bounded native syntax introduced
by `cellscript-source-semantics-2027-preview4`, recorded under
`cellscript-source-semantics-2027-authoring1`, and retained by
`cellscript-source-semantics-2027-0.30-dev1`. It records what the native parser
accepts now so parser, formatter, lowering, metadata, LSP, editor tooling,
examples, and tests can agree while the broader 1.0 design remains under
review.

The strategic design and issue reconciliation remain in the
[CellScript 1.0 Semantic Foundation RFC](CELLSCRIPT_1_0_SEMANTIC_FOUNDATION_RFC.md).
Nothing here marks that RFC's grammar-freeze, implementation-acceptance, or
release gates as passed.

## Activation

The native surface is package-selected:

```toml
[package]
name = "example"
version = "0.1.0"
edition = "2027"
entry = "src/main.cell"
```

Edition 2026 remains the stable default semantic epoch. Edition 2026 rejects
the native `type_script` and `lock_script` surfaces. An Edition 2027 package
uses a separately routed frontend and records
`cellscript-source-semantics-2027-0.30-dev1` in its resolved compatibility
profile. Ordinary `action`/`lock` modules now use the separately routed familiar
authoring grammar described in the [edition policy](CELLSCRIPT_EDITION_POLICY.md);
this native-container reference does not restrict that surface.

The compiler release, source edition, payload ABI, witness placement ABI,
metadata schema, target profile, and artifact identity remain independent
compatibility axes. Selecting Edition 2027 does not change the current
`CSARGv1` payload or `WitnessArgs.input_type` placement.

## Canonical Example

```cellscript
module cellscript::examples::semantic_foundation_2027

resource Token has store, replace, relock {
    owner: Address,
    amount: u64,
}

type_script TokenTransfer on type_group<Token> {
    entry transfer(
        input token: Token from group_input[0],
        witness recipient: Address from group_witness.input_type,
        output next: Token from group_output[0],
    ) {
        verify {
            enforce token.amount > 0
        }

        effects {
            replace token -> next {
                data {
                    owner = same
                    amount = same
                }
                identity = same
                type_script = same
                lock_script = exact_hash(recipient)
                capacity = same
                cardinality = one_to_one
            }
        }
    }
}
```

The runnable Type Script package is
[`examples/semantic-foundation-2027`](../examples/semantic-foundation-2027/README.md).
Use `cellc expand` to inspect the canonical provenance, role, disposition,
claim, entry-contract, and layered-identity records generated from the source.

The same Type Script container may instead account for explicit many-to-many,
retirement, and creation roles. A bounded pooled relation uses the following
total spelling:

```cellscript
audit settlement_policy {
    expected_evidence = external_policy(recipient)
}

effects {
    pool value_flow {
        inputs { left, right }
        outputs { merged }
        data {
            owner { merged = recipient }
            amount = conserve
        }
        identity = pooled
        type_script = same
        lock_script { merged = exact_hash(recipient) }
        capacity = builder_computed
        cardinality = declared
    }
}
```

`amount = conserve` generates an on-chain checked sum relation; the `audit`
does not. Retirement uses `retire role` plus an exact `field(...)`,
`ckb_type_id`, or `singleton_type` absence policy. Creation uses `fresh role`
with exhaustive field expressions, an explicit identity policy, declared Type
Script, exact lock hash, builder-computed capacity, and one declared output.

### Native Lock Script

The same preview also implements a bounded Lock Script container:

```cellscript
module cellscript::examples::lock_script_2027

resource Vault has store {
    owner: Address,
}

lock_script VaultOwner on lock_group {
    entry unlock(
        protected vault: Vault from group_input[0],
        lock_args owner: Address from current_script.args,
        witness claimed_owner: Address from group_witness.input_type,
    ) {
        verify {
            enforce vault.owner == owner
            enforce claimed_owner == owner
        }
    }
}
```

The runnable Lock Script syntax fixture is
[`examples/lock-script-2027`](../examples/lock-script-2027/README.md).
Its equality predicates demonstrate parameter provenance and checking only.
Both owner values are public, so copying the owner into the witness satisfies
the comparison without proving credential control. This is not a reference
ownership lock. Real ownership authorization requires an actual proof bound to
the transaction and an authenticated owner credential.

Its protected role has an explicit `AuthorizationOnly` disposition recording
the Lock boundary. That classification alone proves neither owner authentication
nor that another particular policy checks successor, retirement, data, identity,
Type Script, or capacity rules. See authoring contract A2 for reference-policy
requirements.

## Implemented Grammar

The EBNF below specifies only the implemented preview slice. `NL` and `;` are
statement separators where `separator` appears. Expressions and types reuse
the existing CellScript expression and type grammar.

```ebnf
preview-module       = legacy-non-entry-declaration*, native-script ;
native-script        = type-script | lock-script ;

type-script          = "type_script", identifier,
                       "on", "type_group", "<", cell-type, ">",
                       "{", type-entry, "}" ;

type-entry           = "entry", identifier, "(", type-port-list?, ")",
                       "{", verify-block, audit-declaration*, effects-block, "}" ;

type-port-list       = type-port, (",", type-port)*, ","? ;
type-port            = input-port | output-port | witness-port ;
input-port           = "input", identifier, ":", cell-type,
                       "from", "group_input", "[", ordinal, "]" ;
output-port          = "output", identifier, ":", cell-type,
                       "from", "group_output", "[", ordinal, "]" ;
witness-port         = "witness", identifier, ":", type,
                       "from", "group_witness", ".", "input_type" ;

lock-script          = "lock_script", identifier, "on", "lock_group",
                       "{", lock-entry, "}" ;
lock-entry           = "entry", identifier, "(", lock-port-list, ")",
                       "{", verify-block, audit-declaration*, "}" ;
lock-port-list       = lock-port, (",", lock-port)*, ","? ;
lock-port            = protected-port | witness-port | lock-args-port ;
protected-port       = "protected", identifier, ":", cell-type,
                       "from", "group_input", "[", "0", "]" ;
lock-args-port       = "lock_args", identifier, ":", type,
                       "from", "current_script", ".", "args" ;

verify-block         = "verify", "{", enforce-statement*, "}" ;
enforce-statement    = "enforce", expression, separator? ;
audit-declaration    = "audit", identifier, "{",
                       "expected_evidence", "=", "external_policy",
                       "(", expression, ")", separator?, "}" ;

effects-block        = "effects", "{", disposition+, "}" ;
disposition          = replacement | pool | retirement | fresh-output ;
replacement          = "replace", identifier, "->", identifier, "{",
                         data-plan,
                         "identity", "=", "same", separator,
                         "type_script", "=", "same", separator,
                         "lock_script", "=", "exact_hash", "(", expression, ")", separator,
                         "capacity", "=", "same", separator,
                         "cardinality", "=", "one_to_one", separator?,
                       "}" ;

data-plan            = "data", "{", field-preservation+, "}" ;
field-preservation   = identifier, "=", "same", (separator | ",")? ;

pool                 = "pool", identifier, "{",
                         "inputs", name-block,
                         "outputs", name-block,
                         pool-data-plan,
                         "identity", "=", "pooled", separator,
                         "type_script", "=", "same", separator,
                         "lock_script", "{", output-lock+, "}", separator?,
                         "capacity", "=", "builder_computed", separator,
                         "cardinality", "=", "declared", separator?,
                       "}" ;
name-block           = "{", identifier,
                       ((separator | ","), identifier)*,
                       (separator | ",")?, "}" ;
pool-data-plan       = "data", "{", pool-field-plan+, "}" ;
pool-field-plan      = identifier, "=", "conserve", separator?
                     | identifier, "{", output-field+, "}", separator? ;
output-field         = identifier, "=", expression, separator? ;
output-lock          = identifier, "=", "exact_hash", "(", expression, ")", separator? ;

retirement           = "retire", identifier, "{",
                         "absence", "=", absence-policy, separator,
                         "data", "=", "discarded", separator,
                         "lock_script", "=", "none", separator,
                         "type_script", "=", "absent", separator,
                         "capacity", "=", "released", separator,
                         "cardinality", "=", "one", separator?,
                       "}" ;
absence-policy       = "field", "(", identifier, ")"
                     | "ckb_type_id" | "singleton_type" ;

fresh-output         = "fresh", identifier, "{",
                         fresh-data-plan,
                         "identity", "=", identity-policy, separator,
                         "type_script", "=", "declared", separator,
                         "lock_script", "=", "exact_hash", "(", expression, ")", separator,
                         "capacity", "=", "builder_computed", separator,
                         "cardinality", "=", "one", separator?,
                       "}" ;
fresh-data-plan      = "data", "{", fresh-field+, "}" ;
fresh-field          = identifier, "=", expression, separator? ;
identity-policy      = "none" | "ckb_type_id" | "script_args"
                     | "singleton_type" | "field", "(", identifier, ")" ;

separator            = NL | ";" ;
ordinal              = decimal-integer ;
cell-type            = identifier ;
```

In addition to this grammar, the frontend enforces the following structural
rules:

- exactly one native `type_script` or `lock_script` is present and it is the
  final top-level declaration;
- no legacy `action` or `lock` declaration appears in the same module;
- the container contains exactly one `entry`, producing a `SingleEntry`
  artifact;
- for a Type Script, every `input` and `output` has the declared trigger Cell
  type; group ordinals are zero-based, sequential, and explicit; every role
  appears in exactly one `replace`, `pool`, `retire`, or `fresh` disposition;
  output-producing dispositions follow declared `group_output` order so the
  checked backend index and source role cannot diverge;
  every schema field and fixed envelope clause appears exactly once in
  canonical order; every `exact_hash(...)` subject has type `Address`; and
  `effects` is final and non-empty;
- a `pool` has non-empty, unique, explicitly named input and output sets; at
  least one unsigned numeric schema field uses `= conserve`, which generates
  an overflow-checked `u128` sum-equality over the declared roles; every other
  field and every output lock
  is assigned exactly once in output order; capacity remains visibly
  builder-computed and chain-checked rather than being mislabelled as an
  artifact-local equality;
- `retire` requires an exact field, CKB Type ID, or singleton absence policy;
  `fresh` requires exhaustive field initialization, a declared identity
  policy, an exact output role, and an exact output lock hash;
- every `audit` name is unique; its subject is pure and type-checked, cannot
  capture a Cell-backed linear value directly, is recorded as metadata-only
  external-policy evidence, and never creates an accepting execution path;
- for a Lock Script, exactly one Cell-backed `protected` role is bound to
  `group_input[0]`; witness and current-script arguments use only the explicit
  sources shown above; and the entry contains `verify` plus optional
  metadata-only `audit` declarations, but no lifecycle effects; and
- a module cannot mix the two native container kinds in this preview.

The formatter emits the canonical example style. Alternate accepted separator
choices do not define semantic identity.

## Lowering Contract

The frontend preserves the native surface in the AST for formatting and source
diagnostics, then lowers it into the same checked semantic path used by the
Edition 2026 equivalent subset:

| Native source | Existing checked lowering |
|---|---|
| `enforce condition` | `require condition` |
| exhaustive `replace before -> after` | `std::lifecycle::transfer(before, after, lock) { fields... }` |
| `capacity = same` | `std::cell::preserve_capacity(after, before)` |
| `pool name` with `field = conserve` | exact output creation plus an overflow-checked `u128` sum-equality over all declared input/output roles, followed by explicit input discharge |
| `retire input` with an absence policy | policy-specific checked `destroy` lowering |
| `fresh output` | exact targeted `create` / `create_unique` lowering for the declared output ordinal |
| `audit name { expected_evidence = external_policy(subject) }` | typed metadata-only claim with no executable operation or branch |
| `on type_group<Token>` | entry trigger `type-group<Token>` |
| one `entry transfer` | exact entry `action:transfer`, `SingleEntry` dispatch |
| `lock_script ... on lock_group` | checked legacy `lock` semantic path |
| one `entry unlock` | exact entry `lock:unlock`, `lock-group`, `SingleEntry` dispatch |

This is a semantic lowering, not textual macro expansion. `cellc expand`
renders canonical typed records and is not itself a hash input.

For the equivalent one-to-one subset, native and explicit Edition 2026 sources are tested
to produce the same `CoreSemanticId`, typed entry, ProofPlan, and fail-closed
runtime-feature set. Their `EntryContractId` intentionally differs because the
native syntax commits to the exact `type-group<Token>` trigger while the legacy
surface retains the generic `type-group` entry contract. The bounded native
and explicit legacy Lock Script forms share the same `lock-group` entry
contract and are tested to produce the same layered semantic identities and
byte-identical ELF lowering.

The pooled form is deliberately bounded by explicit local roles. `conserve`
is not a documentation tag: the frontend generates an overflow-checked `u128`
runtime equality between the sum of that unsigned numeric field across every
named input and output. Non-conserved
fields generate exact output-field checks, and each output lock generates an
exact lock-hash check. The source disposition survives separately in shared IR
so typed expansion records `Pooled` and `PoolResult` instead of re-inferring
ambiguous legacy consumption from those executable operations.

## Semantic Obligations

The preview implements the language constitution from the umbrella RFC:

1. Every external value has canonical provenance.
2. Every local trigger Cell role has one explicit disposition or authorization
   boundary.
3. Every `enforce` claim records its enforcement tier, on-chain status, and
   exact typed execution branch.
4. Every artifact has one explicit entry-selection contract.

The generated semantic foundation records:

- witness, GroupInput, and GroupOutput provenance roots and derived nodes;
- local input/output/protected roles with exact ordinal selectors and declared
  correspondence;
- Type Script `Successor`/`SuccessorOf`, `Pooled`/`PoolResult`, `Retired`, and
  `Fresh` disposition variants;
- Lock Script `AuthorizationOnly` dispositions naming the Type Script or an
  explicit transaction policy as the business-disposition owner;
- exhaustive data, logical identity, Lock Script, Type Script, capacity,
  cardinality, and correspondence treatment;
- executable `entry-condition` claims that bind the canonical condition text,
  condition-provenance node, typed condition/success/failure blocks, and
  `assertion-failed` runtime error;
- supporting ProofPlan-linked claims, kept separate from source conditions;
- metadata-only audit claims, kept visibly off-chain and without execution
  bindings; and
- separate core, entry-contract, artifact-contract, deployable-artifact,
  verified-bundle, source, and source-map identities.

An `AuthorizationOnly` record is not a successor, retirement, or preservation
claim. Its envelope says which dimensions the Lock artifact does not constrain,
while recording that spend authorization is checked at runtime.

Source paths and spans live in source-map v2 and are excluded from semantic
node hashes. Executable claims map to the originating condition or generated
sugar range when the frontend supplies a non-empty span, with the containing
entry as the fail-safe diagnostic fallback. The independent artifact checker
validates exact Type and Lock
entry contracts, executable-claim branch/provenance/error links, and all
semantic-foundation hashes without loading the compiler frontend or code
generator. Changing an enforced condition changes its semantic claim and
therefore `CoreSemanticId`; the equivalent Edition 2026 `require` and Edition
2027 `enforce` forms retain the same claim projection.

## Diagnostics and Fail-Closed Cases

The preview rejects, with source-linked diagnostics:

- native syntax under Edition 2026;
- missing, duplicate, reordered, or non-schema `data` fields;
- omitted or reordered Cell-envelope clauses;
- implicit, repeated, skipped, or out-of-order group indexes;
- a disposition that names an undeclared or already-accounted role;
- an input or output without exactly one exhaustive disposition;
- a pool with empty/repeated roles, no conserved unsigned numeric field, incomplete or
  reordered output-field assignments, or incomplete output locks;
- a retirement without an exact absence policy, or a fresh output with an
  incomplete field/identity/lock plan;
- an audit with a duplicate name, impure subject, or direct Cell-backed linear
  capture;
- zero Type Script dispositions, multiple entries, multiple or mixed native
  containers, or a declaration after the container;
- a Lock Script without exactly one Cell-backed `protected` role at
  `group_input[0]`, with an implicit or unsupported port source, or with an
  `effects` block;
- mixing native containers with legacy `action` or `lock` entries;
- ambiguous legacy `consume` or `consume_each` under Edition 2027; and
- implicit-source parameters in the Edition 2027 legacy compatibility subset.

Unsupported forms must not lower to a clean accepting path.

## Legacy Compatibility Subset

Edition 2027 temporarily continues to accept a single legacy-style `action` or
`lock` when all transaction-facing parameters have explicit sources. This
exists only for differential testing and staged migration. It is not the
canonical Edition 2027 spelling and may be removed or narrowed before grammar
freeze.

The compatibility subset rejects ambiguous `consume` and `consume_each`.
Migration must choose a successor, pooled-accounting, or retirement meaning; a
tool may not infer that decision from the word “consume.”

## Bounded Migration Preview

`cellc migrate INPUT --to 2027` generates review-only candidate source; it does
not edit `INPUT`. The accepted legacy subset is deliberately narrower than the
Edition 2027 compatibility parser:

- one self-contained module with no imports and exactly one final legacy
  action or lock;
- an action whose parameters have explicit `input` or `witness` provenance,
  whose input/output roles share one locally declared Cell-backed type, and
  whose body is leading message-free `require` conditions followed by exact
  exhaustive `std::lifecycle::transfer` / `std::cell::preserve_capacity`
  pairs; or
- a bool Lock with exactly one Cell-backed `protected` role, only explicit
  `protected`, `lock_args`, and `witness` parameters, and only message-free
  `require` conditions.

The tool preserves every byte outside the final entry. Before emitting source,
it compiles both versions, requires identical `CoreSemanticId`, and requires
byte-identical RISC-V ELF. `--json` includes both entry-contract identities so
the expected exact-Type-trigger refinement remains visible. Unsupported or
lossy constructs—including explicit visibility and mutable/reference roles
that the native container cannot yet preserve—fail before any output file is
created. The command never
changes the manifest, lockfile, dependency graph, deployment state, or chain.
This does not constitute graph-wide migration or the RFC's Phase 3 acceptance.

## Deliberately Deferred Surface

The following remain outside `preview4`:

- multi-role or variable-cardinality Lock Script entries and Lock Script
  disposition policy beyond spend authorization;
- multiple entries and explicit versioned dispatch syntax;
- variable-cardinality/native collection pools, custom pooled accounting
  beyond numeric field-sum conservation, and non-local pooled roles;
- foreign/open roles, Script handles, ProtocolBundle, or `.celltx`
  choreography;
- non-positional selectors and bounded variable-cardinality native roles;
- Script-valued lock construction beyond the current Address-based transfer
  primitive;
- audit evidence kinds beyond the metadata-only `external_policy(subject)`
  declaration;
- typed temporal, digest-opening, and zero-knowledge-verifier surfaces;
- a new entry payload, witness placement, builder, or deployment ABI; and
- graph-wide or lossy automatic migration, lockfile mutation, publication, deployment, signing, or
  transaction submission.

These are design decisions, not parser TODOs that may be added independently.

## GitHub Issue Reconciliation

The issue list was reviewed on 2026-09-04. The full issue-by-issue analysis is
maintained in the umbrella RFC; the table below marks the constraints that
directly shape this preview.

| Issues | Marker | Preview consequence |
|---|---|---|
| #7 | **[ALIGNED] [PARTIAL]** | Type Scripts distinguish successor, bounded checked pool participation, retirement, and fresh output origin; ambiguous `consume` remains rejected. Lock authorization is recorded separately and does not choose a business disposition. Variable-cardinality/native collection pools remain deferred. |
| #8 | **[ALIGNED] [PARTIAL]** | Requires explicit group-relative ordinals and exhaustive disposition/output correspondence. Variable-cardinality output plans remain on the 0.26 surface. |
| #9 | **[SCOPE]** | No transaction choreography or `.celltx`; artifact composition remains ProtocolBundle-owned. |
| #10-#11 | **[PREREQUISITE] [SCOPE]** | Only local roles exist. Foreign roles and exact Script/interface handles must stabilize before new syntax is admitted. |
| #12 | **[DEFERRED]** | No temporal spelling or raw-`u64` reinterpretation is introduced. |
| #13 | **[CONFLICT] [DEFERRED]** | `commit` remains reserved for cryptographic commitments; it is not the effects terminator. Opening payloads must share the versioned entry envelope. |
| #14 | **[REQUIRED]** | The feature is labelled experimental/partial. “Implemented” in this document means only the enumerated preview slice. |
| #15-#20 | **[PREREQUISITE]** | No graph-wide migration or release promise. Compiler requirements, chain identity, mixed editions, introspection, and transactional upgrades remain separate gates. |
| #21 | **[ALIGNED]** | Semantic source mappings use source-map v2; generated-assembly provenance remains a distinct future layer. |
| #22 | **[SCOPE]** | No ZK verifier surface. Proof bytes may not claim a second top-level witness codec. |

The preview must be revised if the accepted resolutions of #7, #8, #10, #11,
#13, or #14 contradict its lowering contract. Issues #15-#20 are not blockers
to experimenting with this local grammar, but they are blockers to broad
migration and release claims.

## Tooling Coverage

The implemented closure includes:

- native parsing, diagnostics, type checking, flow checking, IR lowering,
  ProofPlan, metadata, ASM/ELF generation, and independent artifact checking;
- canonical formatting and formatter idempotence tests;
- `cellc check`, `cellc expand`, `cellc fmt`, and JSON CLI coverage;
- manifest-aware native LSP diagnostics, completion, hover/metadata paths, and
  formatting;
- an explicit-edition virtual-document LSP entry for WASM consumers;
- VS Code grammar and snippet coverage for the container/entry baseline;
- Type Script, Lock Script, pool, retirement, fresh-output, and audit
  syntax-combination seeds that build
  isolated Edition 2027 packages;
- runnable locked example packages for both native containers; and
- positive, negative, cross-frontend semantic-identity, and artifact-checker
  tests.

The checked-in public website Playground bundle and UI remain on the stable
Edition 2026 release asset until a coordinated WASM rebuild and product-level
preview selector are approved. The source WASM API can compile Edition 2027
when its caller passes `"2027"`; this does not silently change the public
Playground default.

## Freeze Criteria

This preview can inform, but cannot satisfy by itself, the RFC grammar-freeze
gate. Before a stable next edition, the project must still:

- resolve the remaining normative issue conflicts and extend the implemented
  disposition algebra to accepted variable-cardinality and non-local roles;
- decide the full artifact-container and selector model;
- accept or revise the bounded metadata-only `audit` contract and define or
  omit all remaining claim syntax;
- provide total migration mappings or required diagnostics for every Edition
  2026 construct;
- close differential builder and CKB-VM evidence, not only typed lowering;
- coordinate the website preview product and generated WASM asset; and
- accept a complete EBNF and canonical formatter contract through review.

Until then, changes to this preview may be breaking and must advance its source
semantics identifier.
