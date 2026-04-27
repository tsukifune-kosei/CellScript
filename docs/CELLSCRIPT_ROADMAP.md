# CellScript Roadmap

**Updated**: 2026-04-27

This roadmap is the high-level planning map for CellScript. It links the
release-specific trackers and the deeper design notes so the project does not
split into unrelated TODO files.

The current project direction is simple:

1. keep the CKB Cell model visible in the language;
2. keep release claims tied to compiler evidence and builder-backed CKB
   evidence;
3. make the language surface easier to teach without hiding authorization,
   capacity, witness, or lock-group boundaries.

## Current State

| Area | Current status | Detailed document |
|---|---|---|
| 0.13 release scope | Beta released; implementation scope closed. | [0.13 roadmap](CELLSCRIPT_0_13_ROADMAP.md), [0.13 release tracker](CELLSCRIPT_0_13_TODOLIST.md), [0.13 release notes draft](CELLSCRIPT_0_13_RELEASE_NOTES_DRAFT.md) |
| 0.14 release scope | Active implementation branch for CKB semantic completeness and bounded verifier composition. | [0.14 roadmap](CELLSCRIPT_0_14_ROADMAP.md) |
| CKB language fit | CKB-first design is confirmed; remaining gaps are signer binding, continuity policy, capacity policy, and declarative time policy. | [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md) |
| Surface syntax | Low-risk syntax pass is implemented; authority-sensitive syntax remains staged. | [Surface elegance RFC](CELLSCRIPT_SURFACE_ELEGANCE_RFC.md) |
| Collections | Stack-backed fixed-width `Vec<T>` helper surface is implemented; cell-backed and generic map ownership remain fail-closed. | [Collections support matrix](CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md), [0.13 roadmap](CELLSCRIPT_0_13_ROADMAP.md) |
| CKB production evidence | Bundled actions and locks have builder-backed local CKB evidence; production claims still require report validation. | [Metadata and production gates wiki](wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md) |
| Documentation and wiki | Wiki is version-neutral, cookbook-oriented, and published separately to GitHub Wiki. | [GitHub Wiki](https://github.com/tsukifune-kosei/CellScript/wiki) |

## Release Tracks

### 0.13: Closed Implementation Scope

0.13 is the current release gate. It focuses on three themes:

- executable stack-backed `Vec<T>` helper support for fixed-width values;
- low-risk surface syntax improvements and cleaner example organization;
- CKB lock-boundary classification with `protected`, `witness`, and `require`.

0.13 deliberately does not introduce hidden signer authority, hidden sighash
defaults, full generic maps, or cell-backed collection ownership.

Detailed status:

- [0.13 roadmap](CELLSCRIPT_0_13_ROADMAP.md)
- [0.13 release tracker](CELLSCRIPT_0_13_TODOLIST.md)
- [0.13 release notes draft](CELLSCRIPT_0_13_RELEASE_NOTES_DRAFT.md)

### 0.14: CKB Semantic Completeness

0.14 exposes more of CKB's concrete execution surface without hiding lock/type
boundaries:

- Spawn/IPC builtins for bounded verifier reuse;
- explicit Source views, typed fixed-width lock args, and structured
  WitnessArgs field access;
- target profile metadata for witness ABI, lock args ABI, Source encoding,
  Spawn/IPC ABI, since semantics, CellDep ABI, script reference ABI,
  outputs/outputs_data ABI, capacity floor ABI, TYPE_ID ABI, and tx version;
- declarative since/time and capacity surfaces;
- fail-closed dynamic BLAKE2b policy until a real linked implementation exists.

Detailed status:

- [0.14 roadmap](CELLSCRIPT_0_14_ROADMAP.md)

### Next Authorization Hardening Track

The next security-sensitive track should make CKB authorization literal before
it becomes ergonomic.

Planned order:

1. typed `lock_args` binding to the executing script args;
2. explicit sighash verification primitive with digest mode, script group scope,
   witness layout, and replay assumptions;
3. stable metadata and report fields for signature verification obligations;
4. first-class verified signer values only after explicit primitives are proven;
5. optional `protects T { self ... }` sugar only after protected-input
   selection and lock-group aggregation semantics are exact.

Non-goals:

- no implicit signer derivation from `Address`;
- no hidden sighash defaults;
- no parameter-name-based authority.

Source documents:

- [Surface elegance RFC](CELLSCRIPT_SURFACE_ELEGANCE_RFC.md)
- [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md)

### CKB Evidence Hardening Track

The CKB acceptance surface should continue moving from broad acceptance evidence
to predicate-specific evidence.

Priorities:

- keep action acceptance builder-backed and report-validated;
- keep lock valid-spend and invalid-spend matrices mandatory for bundled locks;
- require invalid-spend cases to match stable script failure paths, not generic
  transaction rejection;
- keep cycles, serialized transaction size, occupied capacity, and malformed
  rejection evidence in reports;
- extend the matrix when new bundled locks enter production scope.

Source documents:

- [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md)
- [Capacity and builder contract](CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md)
- [Metadata and production gates wiki](wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md)

### Collections And Ownership Track

The collections roadmap stays conservative because CKB Cell ownership is not a
generic heap model.

Completed:

- stack-backed fixed-width `Vec<T>` helper support;
- typed/contextual `Vec<T>` literals for local stack vectors;
- metadata and `cellc explain-generics` visibility for checked instantiations.

Deferred:

- full generic `HashMap<K, V>` and `HashSet<T>`;
- `Vec<Cell<T>>` and other cell-backed linear ownership collections;
- source-level `Option<T>` lowering;
- explicit `Vec<T, N>[...]` bounded-vector literal syntax.

Source documents:

- [0.13 roadmap](CELLSCRIPT_0_13_ROADMAP.md)
- [Collections support matrix](CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md)
- [Linear ownership](CELLSCRIPT_LINEAR_OWNERSHIP.md)

### Declarative CKB Policy Track

Some CKB facts are currently visible in metadata and builder evidence rather than
first-class source policy.

Future work:

- declarative capacity requirements where the compiler can check them;
- declarative since/header/timepoint assumptions for timelock-like protocols;
- explicit continuity policy for `&mut` Cell replacement, including type id,
  lock, data schema, and capacity continuity;
- clearer builder obligations in action builder plans.

Source documents:

- [Capacity and builder contract](CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md)
- [Mutate and replacement outputs](CELLSCRIPT_MUTATE_AND_REPLACEMENT_OUTPUTS.md)
- [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md)

### Documentation And Developer Experience Track

The docs should stay useful to new readers and strict enough for reviewers.

Completed:

- GitHub Wiki is version-neutral and cookbook-oriented;
- `_Sidebar.md` gives a book-like navigation structure;
- cookbook recipes and CKB glossary exist;
- LSP and VS Code grammar/snippets cover the new lock-boundary syntax.

Future work:

- keep wiki links rendered through GitHub Wiki URLs;
- add recipes when new stable language patterns land;
- keep release notes and roadmap docs separate from tutorial pages;
- keep examples split by audience: business, language, and acceptance.

Source documents:

- [GitHub Wiki](https://github.com/tsukifune-kosei/CellScript/wiki)
- [Surface elegance RFC](CELLSCRIPT_SURFACE_ELEGANCE_RFC.md)

## Roadmap Discipline

Roadmap entries should follow these rules:

- completed work must point to tests, release notes, or evidence reports;
- deferred work must say why it is deferred;
- security-sensitive syntax must distinguish data source from authority;
- CKB production claims must distinguish compiler evidence from chain evidence;
- wiki pages should teach the current stable surface, not act as release notes.
