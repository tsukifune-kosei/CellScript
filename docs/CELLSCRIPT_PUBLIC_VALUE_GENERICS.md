# CellScript Public Value Generics

**Status**: accepted and implemented for the `0.30` development line

**Decision owner**: [issue #23](https://github.com/CellScript-Labs/CellScript/issues/23)

## Decision

CellScript selects issue #23 **Proposal A: restricted public generics**.
Public generic value structs, fixed-width payload enums, and pure functions may
be imported across package boundaries. The compiler specializes every concrete
use in the template's owning module before IR, so CKB-VM artifacts contain only
bounded concrete code and layouts.

This preserves the dependency-facing Edition 2026 capability already exercised
by the cross-package generic library fixture. Selecting package-local-only
generics would remove that supported capability and violate the 0.30 requirement
to retain the Edition 2026 surface.

The decision does not add generic Cells, generic actions or locks, traits,
dynamic dispatch, higher-kinded types, runtime type reflection, or runtime
linkage. Cell lifecycle authority stays separate from value abilities.

## Canonical source profile

`fixed_value` is the compact constraint profile for an ordinary fixed-width,
serializable, non-Cell value:

```cellscript
public struct Pair<T: fixed_value> {
    left: T
    right: T
}

public fn first<T: fixed_value>(pair: Pair<T>) -> T {
    return pair.left
}
```

The parser expands `fixed_value` to this exact closed set and order:

```text
copy + drop + store + fixed + serializable + non_linear
```

The profile is valid in a type-parameter constraint list. It is not a new
ability and does not appear in canonical metadata. Combining it with one of its
expanded abilities is a duplicate-constraint error. Combining `cell` and
`non_linear` remains invalid.

The expanded spelling remains accepted. Compact and expanded source forms
produce the same AST constraints, public interface, interface hash, typed
instantiation evidence, IR, and artifact. The formatter writes the compact
profile.

## Visibility and layout boundary

- `public` templates are dependency-facing and may be specialized by an
  importing package.
- `public(package)` templates are visible only inside the declaring package.
- `private` templates stay module-local.
- Edition 2026 retains its historical public-by-default behavior, although new
  package APIs should spell visibility explicitly.

Every non-phantom parameter of a public generic struct or enum must declare at
least `fixed + serializable + non_linear`. `fixed_value` is the normal spelling
when the parameter also supports copy, drop, and store. Missing public layout
requirements fail with `E2110` and point to `fixed_value`.

A phantom parameter contributes to canonical type identity and occupies no
serialized bytes. Using a phantom parameter in a field remains `E2110`.
Instantiating an ordinary generic layout with a resource, shared Cell, receipt,
or transitively Cell-backed value remains `E2111`.

## Structural ability derivation

When a generic struct or enum omits a redundant `has` clause, the compiler
derives the abilities guaranteed for every permitted specialization by
intersecting the guarantees of all serialized fields:

- a type parameter contributes only its declared constraints;
- fixed scalar, address, hash, and unit fields contribute `fixed_value`;
- an array contributes its element guarantees;
- a tuple contributes the intersection of its element guarantees;
- a reference contributes `copy + drop + non_linear`;
- `String` and `Vec` contribute `copy + drop + store + serializable +
  non_linear`, without `fixed`;
- an empty value layout contributes `fixed_value`; and
- a named field whose template guarantee cannot be proven locally contributes
  no inferred ability. Authors may use an explicit `has` clause, which is
  checked again for every concrete specialization.

`cell` is always removed from a derived ordinary-value ability set. The
algorithm is closed and deterministic; source code cannot override its meaning.
The formatter omits an explicit `has` clause when it exactly repeats the
derived result.

## Interface and compatibility contract

`cellc interface INPUT` prints the compact human view by default:

```text
package tutorial::pairs
interface <ckb-blake2b-256>
runtime ckb
exports
  public struct Pair<T: fixed_value>  [layout <layout-identity>]
  public function first<T: fixed_value>(pair: Pair<T>) -> T
```

`cellc interface INPUT --json` and `--output FILE` retain the complete
canonical machine record. JSON always contains expanded constraints, phantom
flags, resulting abilities, layouts, ABI/profile identities, builder hashes,
and deployment identity. Interface hashing uses that canonical expanded form.

Compatibility follows these rules:

| Change | Classification |
| --- | --- |
| Compact versus exactly equivalent expanded spelling | Same semantic interface identity |
| Private/package-local instantiation change | No public interface change |
| Add a public export | Compatible; exact interface hash changes |
| Remove or rename a public export | Breaking |
| Change parameter count, name, order, or phantom status | Breaking |
| Tighten any public generic constraint | Breaking |
| Relax a constraint | Source-compatible only when layout, runtime ABI, effects/capabilities, builder, and deployment dimensions independently remain compatible |
| Change a resulting value ability or serialized layout | Breaking in its corresponding dimension |

The Rust compiler validates the canonical generic interface before accepting
metadata. The Registry API applies the same canonical-order and public-layout
checks before publication and mirrors the relax-versus-tighten upgrade rule.
The parser-free artifact checker independently recomputes `interface_hash`,
validates expanded public generic records, and retains the complete checked
monomorphization identities in typed semantics.

## Migration

The existing expanded nightly spelling remains source-compatible. Run
`cellc fmt` to convert an exact six-constraint list to `fixed_value` and remove
an explicit generic `has` clause when it exactly matches structural derivation.
The formatter round-trip test proves this rewrite is deterministic and does not
change the canonical interface identity.

Packages with public generic layouts that omit `fixed`, `serializable`, or
`non_linear` must add the missing contract or make the template
`public(package)`/`private`. This is an intentional stabilization error rather
than an implicit change to the accepted type set.

## Evidence boundary

The syntax-combination seed, cross-package resolver fixture, metadata and
interface tests, CKB-VM generic value fixture, Registry tests, independent
checker mutation, WASM Playground compile test, LSP hover/completion, and VS
Code grammar/snippet validation exercise the same profile. The `dev`, `ci`, and
`backend` gates are required before this decision is treated as closed for the
0.30 branch.
