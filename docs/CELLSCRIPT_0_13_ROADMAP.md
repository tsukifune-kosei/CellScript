# CellScript 0.13 Roadmap

**Updated**: 2026-04-27

0.13 is a closed implementation-scope release track. The code has been merged to
`main`; this document explains what 0.13 includes, what it intentionally leaves
out, and where each subtopic is tracked in more detail.

For the broader plan, see [CellScript Roadmap](CELLSCRIPT_ROADMAP.md).

## 0.13 Goals

0.13 has four concrete goals:

1. add executable stack-backed `Vec<T>` helper support for fixed-width values;
2. improve the source surface without changing core CKB semantics;
3. make lock-boundary data sources visible with `protected`, `witness`, and
   `require`;
4. keep CKB production evidence strict enough to support release claims for the
   bundled suite.

## Status Summary

| Track | Status | Notes |
|---|---|---|
| Stack-backed `Vec<T>` helpers | Done | Covers fixed-width local vectors and helper matrix. |
| Contextual `Vec<T>` literals | Done | `[]` and `[x, y]` work only when the expected type is `Vec<T>`; empty `[]` lowers through the existing `Vec::new()` path. |
| Field shorthand | Done | `field` lowers as `field: field` for create and struct literals. |
| Example canonicalization | Done | Business, language, and acceptance examples are split by audience. |
| Lock classification syntax | Done | `protected`, `witness`, and lock-only `require` are implemented and documented. |
| `lock_args` | Reserved | Parser spelling exists; type checking rejects it until typed script-args binding is implemented. |
| Explicit sighash verification | Deferred | Requires digest mode, script group scope, witness layout, and replay assumptions. |
| First-class signer values | Deferred | Must wait for explicit verification primitives. |
| Generic maps / cell-backed collections | Out of scope | Remain fail-closed until ownership semantics are executable. |

## Stack-Backed Collections

0.13 adds executable helper support for fixed-width stack-backed local vectors.

Implemented helper coverage:

- `Vec::new`
- `Vec::with_capacity`
- `Vec::capacity`
- `Vec::push`
- `Vec::extend_from_slice`
- `Vec::len`
- `Vec::is_empty`
- indexing
- `Vec::first`
- `Vec::last`
- `Vec::contains`
- `Vec::set`
- `Vec::remove`
- `Vec::pop`
- `Vec::insert`
- `Vec::reverse`
- `Vec::truncate`
- `Vec::swap`
- `Vec::clear`

Supported element categories:

- `u64`;
- fixed-byte values such as `Address` and `Hash`;
- fixed-width schema values covered by the fixed-width layout machinery.

Important boundaries:

- this is not full generic collection support;
- cell-backed linear collections remain fail-closed;
- generic maps and sets remain out of scope;
- `Option<T>` remains reserved for a later explicit optional/error model.

Detailed tracker:

- [0.13 release tracker](CELLSCRIPT_0_13_TODOLIST.md)
- [Collections support matrix](CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md)

## Surface Syntax And Examples

0.13 completes the low-risk syntax pass from the surface elegance RFC.

Implemented:

- namespace-style bundled example modules;
- DSL-native `has` capability declarations;
- create and struct field shorthand;
- contextual `Vec<T>` literals;
- cleaner top-level and `examples/business` examples;
- profiled `examples/acceptance` copies for release evidence;
- `examples/language/registry.cell` for collection helper coverage;
- LSP and VS Code grammar/snippet updates.

Design boundary:

- the syntax pass must not hide Cell lifecycle;
- examples must not imply signer authority from `Address` values;
- acceptance/profiled examples keep production metadata where evidence needs it.

Detailed design:

- [Surface elegance RFC](CELLSCRIPT_SURFACE_ELEGANCE_RFC.md)
- [Wiki cookbook](wiki/Cookbook-Recipes.md)

## Lock Boundary Surface

0.13 adds classification syntax for locks:

```cellscript
lock owner_only(wallet: protected Wallet, claimed_owner: witness Address) -> bool {
    require wallet.owner == claimed_owner
}
```

Meaning:

- `protected T` is a typed view of one selected input Cell in the current script
  group whose spend is guarded by the lock invocation;
- `witness T` is decoded transaction witness data;
- `require` fails current script validation when false;
- `require` is lock-only and should not be used for action invariants.

Important boundary:

- `witness Address` is not a signer;
- `Address` is not an authorization proof by name;
- `lock_args` is reserved but not active;
- hidden sighash defaults are rejected.

Deferred authorization roadmap:

1. typed `lock_args` binding;
2. explicit sighash verification primitive;
3. metadata/report obligations for signature verification;
4. first-class verified signer values;
5. optional `protects T { self ... }` sugar only after binding semantics are exact.

Detailed design:

- [Surface elegance RFC](CELLSCRIPT_SURFACE_ELEGANCE_RFC.md)
- [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md)
- [CKB glossary](wiki/CKB-Glossary.md)

## CKB Production Evidence

0.13 keeps the release boundary tied to builder-backed CKB evidence.

Required evidence for the bundled suite:

- strict CKB profile admission;
- scoped action compile and builder-backed action runs;
- scoped lock compile and builder-backed valid-spend / invalid-spend matrices;
- stable invalid-spend script failure evidence;
- valid transaction dry-runs and committed valid transactions;
- malformed rejection;
- measured cycles;
- consensus-serialized transaction size;
- occupied-capacity evidence;
- no under-capacity outputs;
- final production hardening gate pass.

Detailed evidence docs:

- [Metadata verification and production gates wiki](wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md)
- [Capacity and builder contract](CELLSCRIPT_CAPACITY_AND_BUILDER_CONTRACT.md)
- [CKB language audit](CELLSCRIPT_CKB_LANGUAGE_AUDIT.md)

## Documentation And Tooling

0.13 documentation and tooling work includes:

- version-neutral GitHub Wiki tutorials;
- cookbook recipes and CKB glossary;
- rendered GitHub Wiki links instead of raw markdown links;
- LSP completions and VS Code grammar/snippets for new lock-boundary syntax;
- release notes that separate 0.12 schema/ABI foundation from 0.13 executable
  collection helper work.

Detailed docs:

- [GitHub Wiki](https://github.com/tsukifune-kosei/CellScript/wiki)
- [0.13 release notes draft](CELLSCRIPT_0_13_RELEASE_NOTES_DRAFT.md)

## Explicit Non-Goals

0.13 does not include:

- first-class signer or witness-sighash authorization syntax;
- hidden signer derivation from `Address`, witness data, or parameter names;
- hidden sighash defaults;
- typed `lock_args` binding;
- `protects T { self ... }` sugar;
- full generic `HashMap<K, V>` or `HashSet<T>`;
- `Vec<Cell<T>>` or other cell-backed generic ownership collections;
- source-level `Option<T>` lowering;
- fully declarative capacity and since/header policy.

These are not accidental omissions. Each item either needs stronger CKB binding
semantics, stronger ownership semantics, or more release evidence before it
should be exposed as stable source syntax.

## Verification Commands

The release-gate command set remains:

```bash
cargo fmt --all
cargo clippy --locked -p cellscript --all-targets -- -D warnings
cargo test --locked -p cellscript -- --test-threads=1
git diff --check
```

For CKB production evidence:

```bash
./scripts/ckb_cellscript_acceptance.sh --production
python3 scripts/validate_ckb_cellscript_production_evidence.py \
  target/ckb-cellscript-acceptance/<run>/ckb-cellscript-acceptance-report.json
```
