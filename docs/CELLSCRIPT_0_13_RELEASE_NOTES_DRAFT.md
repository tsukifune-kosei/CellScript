# CellScript 0.13 Release Notes Draft

**Status**: Release-gate draft for the 0.13 implementation now merged to
`main`.

**Updated**: 2026-04-27.

## Collections Scope

CellScript 0.13 adds executable stack-backed `Vec<T>` helper support for
bounded value vectors where element width is known. This is separate from the
0.12 schema/ABI work.

Already present before 0.13:

- `Vec<u8>`, `Vec<Address>`, `Vec<Hash>`, and supported nested witness payload
  vectors in Molecule schema/ABI and entry-witness paths.
- `Vec<Address>` declarations in examples such as multisig/timelock.
- Read-oriented dynamic Molecule vector support where the runtime has schema
  metadata and witness/cell bytes.

New in 0.13:

- Stack-backed local `Vec<u64>` helpers.
- Stack-backed local fixed-byte helpers for `Vec<Address>` and `Vec<Hash>`
  width-compatible values.
- Stack-backed fixed-width named schema values, covered by the `Vec<Snapshot>`
  helper matrix plus field reads from popped/indexed elements.
- Runtime lowering for `new`, `with_capacity`, `capacity`, `push`,
  `extend_from_slice`, `len`, `is_empty`, indexing, `first`, `last`,
  `contains`, `set`, `remove`, `pop`, `insert`, `reverse`, `truncate`,
  `swap`, and `clear`.
- Negative type-check coverage for unsupported helper/type combinations.
- Stable fail-closed metadata names for unsupported collection paths.
- `examples/registry.cell` documents supported local `Vec<Address>` /
  `Vec<Hash>` helper usage without implying full `HashMap<K, V>` support. It is
  a compiler/tooling language example, not part of the seven-example CKB
  production action acceptance matrix.
- The canonical business examples are now mirrored under `examples/business/`,
  while production/profile metadata lives under `examples/acceptance/`. The CKB
  acceptance script compiles the profiled copies when present, keeping
  `#[effect(...)]` and `#[scheduler_hint(...)]` out of reader-facing business
  files without dropping release evidence. Subdirectory copies use scoped module
  namespaces so they can coexist with the canonical top-level examples during
  module loading.
- Runtime and constraints metadata expose each checked stack-backed
  fixed-width `Vec<T>` instantiation, including scope, element type/width,
  backing capacity, status, and helper set. Constructor helpers now preserve
  `Vec::new` versus `Vec::with_capacity` instead of collapsing both to `new`.
- `cellc explain-generics` exposes the checked bounded `Vec<T>` instantiation
  set in text or JSON form for local audit.
- Metadata schema version is now 30.

Important boundaries:

- `Vec::capacity()` reports the fixed stack backing capacity
  (`256 / element_width`), not the requested `Vec::with_capacity(n)` value.
- Full generic `HashMap<K, V>` / `HashSet<T>` runtime support is not part of
  0.13.
- `Vec<Cell<T>>`, `Vec<Resource<T>>`, and other cell-backed / linear ownership
  collections remain fail-closed until an executable ownership model exists.
- `Option<T>` is still reserved for a future explicit error/optional-value
  model and is not implemented in 0.13.
- 0.13 must not re-count 0.12 `Vec<Address>` / `Vec<Hash>` schema and ABI
  support as new work.

## Surface Syntax And Example Canonicalization

The 2026-04-26 surface pass is a syntax and example-organization pass, not an
authorization redesign. It makes the canonical examples shorter and makes CKB
lock data sources more visible while keeping authority-sensitive features
explicit or fail-closed.

Completed in 0.13:

- Bundled examples use namespace-style `module cellscript::...` declarations
  and DSL-native `has` capability declarations.
- `create` and ordinary struct literals support field shorthand; examples use
  it where the field name and source binding are identical.
- Typed empty `Vec<T>` literals such as `let mut keys: Vec<Hash> = []` and
  contextual field literals such as `data: []` lower through the existing
  `Vec::new()` path when the expected `Vec<T>` type is known.
- Bundled locks use `protected`, `witness`, and `require` to distinguish the
  guarded input Cell view, transaction witness data, and script failure
  predicate.
- Clean business examples are separated from profiled acceptance examples, while
  the flat `examples/*.cell` files remain compatibility mirrors.
- LSP completions plus VS Code grammar and snippets are refreshed for the new
  lock-boundary syntax.

Important boundaries:

- `lock_args` is reserved and fail-closed until typed CKB script-args binding is
  implemented.
- 0.13 does not introduce first-class signer values, implicit `Address` signer
  semantics, or hidden sighash defaults.
- `witness Address` means decoded witness data only; it is not a cryptographic
  authorization proof.
- `protects T { self ... }` remains deferred until protected-input selection and
  lock-group aggregation semantics are exact.
- Acceptance/profiled copies still carry scheduler and effect metadata because
  they are part of release evidence.

## Verification

Current release-gate commands:

```bash
cargo fmt --all
cargo clippy --locked -p cellscript --all-targets -- -D warnings
cargo test --locked -p cellscript -- --test-threads=1
git diff --check
```

## CLI Ergonomics

New in 0.13:

- `cellc build` uses O1 for non-release builds and still uses O3 for
  `--release`.
- `cellc new` provides a Cargo-style package creation workflow with `--path`,
  `--lib`, `--vcs git`, `--vcs none`, and JSON summaries.
- `cellc new --lib` and `cellc init --lib` now keep generated package layout and
  `Cell.toml` aligned: the entry is `src/lib.cell`, and no stale
  `src/main.cell` entry file is left behind.
- `cellc explain <error-code>` reports runtime error registry entries.
- `cellc explain-generics [--json]` reports checked stack-backed
  `Vec<T: FixedWidth>` instantiations, including element width, fixed backing
  capacity, backing model, status, and exact helper set.
- CLI stderr uses `error[E####]` plus a `cellc explain E####` hint when a
  policy or compile error maps to the runtime error registry.

## Lock Boundary Surface

New in 0.13:

- Lock parameters can classify CKB data sources with `protected` and `witness`.
  `protected T` is a typed view of one selected input Cell in the current script
  group whose spend is guarded by the lock invocation. `witness T` is decoded
  transaction witness data.
- `require` is available as the canonical lock predicate form. A false
  condition fails the current script validation; it does not create
  authorization by itself.
- `lock_args` is reserved as the spelling for typed script-args data. The parser
  recognizes it, but type checking rejects it until explicit CKB script-args
  binding is implemented.
- The bundled production locks now have builder-backed local CKB valid-spend and
  invalid-spend matrix coverage in the production acceptance report.

Important boundaries:

- `Address` is not a signer proof by name.
- `witness Address` is not witness-sighash authorization.
- Hidden sighash defaults are not part of 0.13. Future signature verification
  syntax must expose digest mode, script group scope, witness layout, and replay
  assumptions.

## Backend Shape Baseline

The current 0.13 implementation still passes the bundled example backend-shape
budget test.
Snapshot from `bundled_examples_backend_shape_report_serializes`:

| Example | Assembly lines | Text bytes | Machine blocks | CFG edges | Call edges |
|---|---:|---:|---:|---:|---:|
| `amm_pool.cell` | 8778 | 33912 | 1393 | 2400 | 326 |
| `launch.cell` | 5677 | 21320 | 763 | 1309 | 216 |
| `multisig.cell` | 19836 | 76048 | 3414 | 5421 | 266 |
| `nft.cell` | 12655 | 47388 | 2375 | 3933 | 305 |
| `timelock.cell` | 10109 | 38284 | 1797 | 2976 | 243 |
| `token.cell` | 2628 | 9748 | 478 | 787 | 85 |
| `vesting.cell` | 3853 | 14372 | 566 | 989 | 189 |
