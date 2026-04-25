# CellScript v0.13 TODO List

**Date**: 2026-04-25  
**Branch**: `codex/cellscript-0.13`  
**Status**: Live implementation tracker, not a design promise

This file tracks the actual 0.13 branch progress. Use it as the working TODO
list for implementation status. The roadmap remains the broader design context.

---

## ✅ Completed

### Roadmap audit cleanup

- [x] Corrected collections overlap: 0.12 already supports documented
  schema/ABI dynamic vector paths such as `Vec<u8>`, `Vec<Address>`,
  `Vec<Hash>`, and entry-witness payload vectors.
- [x] Removed the false timelock blocker: `timelock.cell` can declare
  `approvers: Vec<Address>`.
- [x] Corrected CLI scope: `cellc init` is already 0.12 work; 0.13 CLI work is
  `cellc new`/workflow polish rather than first-time scaffolding.
- [x] Re-scoped BLAKE2b: no mandatory 0.13 on-chain stdlib work; generic
  in-script CKB BLAKE2b remains P3/conditional.

### Stack-backed `Vec<T>` runtime helpers

Implemented for stack-backed value vectors when element width is known
(`u64`, fixed bytes, `Address`, `Hash`, and fixed-width schema values covered
by existing fixed-width machinery):

- [x] `Vec::new`
- [x] `Vec::with_capacity`
- [x] `Vec::capacity`
- [x] `Vec::push`
- [x] `Vec::extend_from_slice`
- [x] `Vec::len`
- [x] `Vec::is_empty`
- [x] indexing, e.g. `values[i]`
- [x] `Vec::first`
- [x] `Vec::last`
- [x] `Vec::contains`
- [x] `Vec::set`
- [x] `Vec::remove`
- [x] `Vec::pop`
- [x] `Vec::insert`
- [x] `Vec::reverse`
- [x] `Vec::truncate`
- [x] `Vec::swap`
- [x] `Vec::clear`

### Coverage and verification already added

- [x] Regression tests for scalar `Vec<u64>` runtime helpers.
- [x] Regression tests for fixed-byte `Vec<Address>` runtime helpers.
- [x] Metadata fail-closed checks for supported stack-backed helper paths.
- [x] Cell-backed / linear collection paths remain metadata-visible and
  fail-closed.
- [x] Latest branch verification has passed:
  - `cargo fmt --all`
  - targeted helper tests for each new helper
  - `cargo clippy --locked -p cellscript --all-targets -- -D warnings`
  - `cargo test --locked -p cellscript -- --test-threads=1`
  - `git diff --check`

---

## 🟡 In Progress / Needs Release-Gate Hardening

- [x] Add a compact support matrix for each `Vec<T>` helper.

### Current `Vec<T>` Support Matrix

| Source / element category | `new` / `with_capacity` / `capacity` | `push` / `extend_from_slice` / `set` / `clear` | `len` / `is_empty` / index / `first` / `last` | `contains` | `remove` / `pop` / `insert` | `reverse` / `truncate` / `swap` | Status |
|---|---:|---:|---:|---:|---:|---:|---|
| Stack-backed `Vec<u64>` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | implemented and tested |
| Stack-backed fixed bytes / `Address` / `Hash` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | implemented and tested |
| Stack-backed fixed-width schema values | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | supported where fixed-width layout is known; release-gate coverage still needed |
| Molecule dynamic fields / entry-witness vectors | ❌ local construction | ❌ local mutation | ✅ read-oriented paths | 🟡 read/compare paths only | ❌ local mutation | ❌ local mutation | 0.12 foundation, not new 0.13 generic runtime |
| Cell-backed / linear vectors | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | fail-closed until ownership proof exists |

Notes:

- `Vec<Address>` / `Vec<Hash>` schema and entry-witness use is 0.12 foundation.
- 0.13 work is executable stack-backed value-vector helper support.
- Full generic `HashMap<K, V>` remains out of scope for 0.13.

- [ ] Add explicit negative tests for unsupported helper/type combinations.
- [ ] Audit all `collection-*` fail-closed feature names for stable metadata
  naming before 0.13 release.
- [ ] Confirm `Vec::capacity` semantics are acceptable as fixed backing buffer
  capacity (`256 / element_width`) and not source-requested capacity.
- [ ] Add release notes that distinguish 0.12 schema/ABI vector support from
  0.13 executable stack-backed vector helper support.
- [ ] Check generated assembly/code-size impact after the helper set expansion.

---

## ⏭️ Next Candidate Work

- [ ] Improve docs for bounded collection runtime behavior.
- [ ] Add examples showing supported local `Vec<Address>` / `Vec<Hash>` helper
  usage without implying full generic collection support.
- [ ] Consider `Vec<T: FixedWidth>` monomorphization metadata output, with every
  instantiation visible in ABI/constraints metadata.
- [ ] Investigate a bounded `Option<T: FixedWidth>` representation.
- [ ] Continue CLI 0.13 work:
  - `cellc new`
  - build default/profile polish
  - diagnostic presentation improvements

---

## ❌ Explicit Non-Goals For v0.13

- [ ] Full generic `HashMap<K, V>` runtime support.
- [ ] `Vec<Cell<T>>` ownership semantics.
- [ ] `HashMap<Hash, Resource<T>>` / cell-backed generic maps.
- [ ] Hidden generic lowering that changes witness layout or schema
  commitments without metadata.
- [ ] Treating 0.12 `Vec<Address>` / `Vec<Hash>` schema/ABI support as new 0.13
  work.
- [ ] Mandatory on-chain generic CKB BLAKE2b stdlib implementation.
