# CellScript 0.13 Release Notes Draft

**Status**: Draft for the `codex/cellscript-0.13` implementation branch.

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

New in 0.13 branch work:

- Stack-backed local `Vec<u64>` helpers.
- Stack-backed local fixed-byte helpers for `Vec<Address>` and `Vec<Hash>`
  width-compatible values.
- Runtime lowering for `new`, `with_capacity`, `capacity`, `push`,
  `extend_from_slice`, `len`, `is_empty`, indexing, `first`, `last`,
  `contains`, `set`, `remove`, `pop`, `insert`, `reverse`, `truncate`,
  `swap`, and `clear`.
- Negative type-check coverage for unsupported helper/type combinations.
- Stable fail-closed metadata names for unsupported collection paths.
- `examples/registry.cell` documents supported local `Vec<Address>` /
  `Vec<Hash>` helper usage without implying full `HashMap<K, V>` support.
- Runtime and constraints metadata expose each checked stack-backed
  fixed-width `Vec<T>` instantiation, including scope, element type/width,
  backing capacity, status, and helper set.
- `cellc explain-generics` exposes the checked bounded `Vec<T>` instantiation
  set in text or JSON form for local audit.
- Metadata schema version is now 30.

Important boundaries:

- `Vec::capacity()` reports the fixed stack backing capacity
  (`256 / element_width`), not the requested `Vec::with_capacity(n)` value.
- Full generic `HashMap<K, V>` / `HashSet<T>` runtime support is not part of
  this 0.13 branch.
- `Vec<Cell<T>>`, `Vec<Resource<T>>`, and other cell-backed / linear ownership
  collections remain fail-closed until an executable ownership model exists.
- `Option<T>` is still reserved for a future explicit error/optional-value
  model and is not implemented in this 0.13 branch.
- 0.13 must not re-count 0.12 `Vec<Address>` / `Vec<Hash>` schema and ABI
  support as new work.

## Verification

Current release-gate commands for this branch:

```bash
cargo fmt --all
cargo clippy --locked -p cellscript --all-targets -- -D warnings
cargo test --locked -p cellscript -- --test-threads=1
git diff --check
```

## CLI Ergonomics

New in 0.13 branch work:

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
  capacity, backing model, status, and helper set.
- CLI stderr uses `error[E####]` plus a `cellc explain E####` hint when a
  policy or compile error maps to the runtime error registry.

## Backend Shape Baseline

The current branch still passes the bundled example backend-shape budget test.
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
