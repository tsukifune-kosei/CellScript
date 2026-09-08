# CellScript Collections Support Matrix

**Status**: production boundary document for the current CellScript CKB profile.

CellScript supports dynamic data in several different layers. These layers must
not be collapsed into one generic "collections are supported" claim.

## Support By Layer

| Feature | Schema/ABI | IR construction | Runtime verifier helper | Production status |
|---|---:|---:|---:|---|
| `Vec<u8>` | Yes | Targeted | Targeted create/update-output verification | Supported for documented witness and cell-data paths |
| `String` | Yes | Targeted | Byte-vector verification | Supported as UTF-8 bytes at the schema boundary |
| `Vec<Address>` | Yes | Targeted | Fixed-element vector verification | Supported where metadata marks a Molecule dynamic field |
| `Vec<Hash>` | Yes | Targeted | Fixed-element vector verification | Supported where metadata marks a Molecule dynamic field |
| Fixed byte arrays | Yes | Yes | Exact-size verification | Supported |
| Stack-backed local `Vec<T: FixedWidth>` | Local-only | Yes | Codegen stack-backed lowering | Supported for verifier-local scalar, fixed-byte, and fixed-width named values |
| `Vec<Vec<u8>>` | Boundary | Boundary | No generic helper | Must fail closed unless a concrete lowering is added |
| Generated allocation-backed collection helpers | No | No | Fail-closed entry symbols | Not a production allocator ABI |
| `HashMap<u64, u64>` | Limited | Limited | No production helper surface | Unsupported/fail-closed for production contracts |
| `HashMap<Hash, Token>` | No | No | No | Unsupported; must fail closed |
| `HashSet<T>` | Limited | Limited | No production helper surface | Unsupported/fail-closed for production contracts |
| Fixed-width `BoundedCellSet<Resource, N>` + `consume_each` | `input` source; `1 <= N <= 1024` | Checked loop, predicates, and numeric outer `+=` accumulators | `bounded-type-group-inputs-v1` scans exact `GroupInput` order, decodes exact data, and checks runtime count | Supported for fixed-width resource data of 1–512 bytes; other sources and dynamic layouts fail closed |
| Fixed-width `BoundedList<Plan, N>` + `create_each` | `witness` source; versioned plan bytes | Checked loop, predicates, numeric outer `+=` accumulators, and one complete create template | `bounded-output-plan-v1` decodes the plan and verifies the same relative `GroupOutput`, output lock, data, capacity floor, and final count | Supported only when `12 + N * plan_width <= 4084`, the output is fixed-width with no custom identity, and lock/capacity policy is explicit; other shapes fail closed |
| Generic Cell-backed resource collections | No executable ownership model | No | No | Unsupported |

## Stack-Backed Local Vec Rule

The current backend supports bounded local `Vec<T>` operations only when `T`
has a known fixed width and the vector is verifier-local. These operations are
compiler-recognized stack-backed codegen lowering, not calls into a production
allocator ABI. The supported helper surface is:

```text
new, with_capacity, capacity, push, extend_from_slice, len, is_empty,
indexing, first, last, contains, set, remove, pop, insert, reverse, truncate,
swap, clear
```

`Vec::capacity()` reports the fixed stack backing capacity
(`256 / element_width`), not the requested `Vec::with_capacity(n)` argument.
`cellc explain generics` exposes each checked instantiation, including element
type, element width, backing model, helper set, and constructor provenance.

Generated public collection symbols in `src/stdlib/collections.rs` are kept as
fail-closed stubs unless a concrete checked runtime ABI exists. Do not document
or use those symbols as production allocation-backed `Vec`, `HashMap`, or
`HashSet` helpers.

`examples/registry.cell`, `examples/language/collections/registry.cell`, and
`examples/language/collections/order_book.cell` are
compiler/tooling examples for this local helper surface. They are not part of
the bundled CKB production action acceptance matrix.

## Production Rule

Supported dynamic values must have deterministic Molecule metadata and verifier
evidence:

- `molecule_schema_manifest` entry
- dynamic field declaration where applicable
- generated create or update-output verifier marker
- constraints or production-gate evidence for the entrypoint that uses it

Unsupported generic collections must not silently compile into a weaker runtime
shape. They must produce one of:

- compile-time diagnostic
- structured blocker in metadata/constraints
- explicit fail-closed runtime path with a registered runtime error

Every selected consensus-relevant ProofPlan status beginning with `gap:` is a
production blocker, including `gap:runtime-helper-required`,
`gap:builder-evidence-required`, and `gap:metadata-only`. A transaction builder
can supply evidence for construction, but that evidence cannot authorize a
consensus operation the emitted Script does not check.

## Bounded Lifecycle Runtime Boundary

0.26 implements two deliberately narrow consensus contracts. A supported
`consume_each` scans the current Type Script's canonical `GroupInput` view. It
accepts only exact fixed-width data, checks that every selected Cell is acting
in the Type Script role, executes the body once per element, treats only
`CKB_INDEX_OUT_OF_BOUND` as the end of the group, and probes index `N` so an
`N + 1` member cannot be hidden. Zero elements are vacuous only when the Script
is invoked by an output-side group member.

A supported `create_each` reads a `bounded-output-plan-v1` payload from the
entry witness. The payload is the eight-byte `CSBPLv1\0` magic, a little-endian
Molecule FixVec count, and fixed-width plan elements. Plan element `i` must
match relative `GroupOutput[i]`; the generated verifier checks the complete
Cell data template, exact output lock, declared non-zero capacity floor, and
that no additional group output exists. The outer entry payload remains
`CSARGv1\0` plus the ordinary four-byte dynamic argument length.

Both bodies may use pure `require` predicates and mutable numeric variables
declared outside the body through `+=`. That restricted accumulator surface is
what makes count conservation, amount conservation, and many-to-one merge
checks expressible without admitting arbitrary loop side effects.

The positive contract does not cover dynamic or recursive element layouts,
transaction-wide scans, Lock Script groups, custom output identities, omitted
locks, implicit capacity policy, or arbitrary mutation inside a bounded body.
Those shapes keep the 0.25 fail-closed behavior: production stops with E2105
and permissive artifacts return runtime error 24.

The accepted 0.30 source-selection, ordering, identity, stable-error,
independent-checker, shared-fixture, and maximum-resource rules for the input
half are fixed in the
[bounded GroupInput contract](CELLSCRIPT_BOUNDED_GROUP_INPUT_CONTRACT.md).

## Authoring Guidance

Use dynamic vectors for data that is still a single cell field, such as signer
lists, proposal payload bytes, NFT attributes, or launch distributions.

Use `BoundedCellSet`/`BoundedList` only for the checked shape above. The four
0.26 language examples cover variable-cardinality claims, 1–16 order
settlement, fragmented-Cell merging, and bridge/rollup batches. Generic
Cell-backed vectors and maps, dynamic element data, and non-group membership
proofs remain outside the production surface.
