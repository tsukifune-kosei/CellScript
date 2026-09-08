# Tutorial 16: Generics, Public Interfaces, and Typed Artifacts

This tutorial covers the stabilized 0.30 reusable-value and package boundary.
It shows how to write a bounded generic value, choose visibility, inspect the
canonical interface, compare an upgrade, and check the typed record bound to an
ELF.

## 1. Write A Fixed Generic Value

```cellscript
module tutorial::pairs

public struct Pair<T: fixed_value> {
    left: T
    right: T
}

public fn swap<T: fixed_value>(pair: Pair<T>) -> Pair<T> {
    return Pair<T> { left: pair.right, right: pair.left }
}

private fn internal_identity(value: u64) -> u64 {
    return value
}
```

`fixed_value` is the source shorthand for the canonical expanded constraint set
`copy + drop + store + fixed + serializable + non_linear`. Machine-readable
interfaces always contain the expanded list. When a generic struct or enum
omits `has`, the compiler derives its abilities from the field contract; the
formatter therefore removes an equivalent redundant `has` clause.

CellScript monomorphizes concrete value uses before IR lowering. The compiler
records every instantiation and applies fixed nesting, count, and identity-size
budgets. Ordinary generic containers cannot hide a Cell-backed value.
Public generic layouts require every non-phantom type parameter to be fixed,
serializable, and non-linear. Public templates may be imported from
dependencies; specializations remain in the owning module and do not become
public-interface entries in the consumer.

Value abilities are not Cell authority. `copy`, `drop`, `fixed`,
`serializable`, and `non_linear` describe ordinary values; `create`, `consume`,
`replace`, and other Cell capabilities remain on Cell-backed declarations.

## 2. Use `Option<T>` And Complete Patterns

```cellscript
public fn unwrap_or_zero(value: Option<u64>) -> u64 {
    return match value {
        Option::Some(inner) => { inner }
        Option::None => { 0 }
    }
}
```

Fixed payload enums support recursive tuple, struct, enum, wildcard, and
binding-free or-patterns. Exhaustiveness and linear-value rules are checked
before lowering.

## 3. Use Explicit Loop Control

```cellscript
label outer: for i in 0..10 {
    for j in 0..10 {
        if j == 0 {
            continue
        }
        if i == 5 {
            break outer
        }
    }
}
```

An unlabelled `break` or `continue` targets the nearest loop. A labelled form
must name a visible enclosing `label name: for ...` or `label name: while ...`
loop. The type checker rejects loop control outside a loop, while lowering
records the exact CFG jump checked against the final machine artifact.

## 4. Emit And Compare Interfaces

```bash
cellc interface .
cellc interface . --json
cellc interface . --output target/current.interface.json
cellc interface-diff \
  --old target/released.interface.json \
  --new . \
  --json
```

The default `interface` view is a concise human summary. Use `--json` or
`--output` for the complete canonical record used by automation and the
Registry. `fixed_value` and its fully expanded spelling produce the same
interface hash.

Read the six compatibility dimensions independently: source API, serialized
layout, runtime ABI, effects/capabilities, builder contract, and deployment
contract. Removing constraints from a type parameter is a compatible
relaxation. Adding constraints, changing parameter shape or order, or changing
phantom status is breaking. A breaking report exits with `E2501`.

## 5. Review A `same except` Schema Change

An Edition 2027 schema upgrade that changes the expansion of a
`data = same except` relation needs focused review. Generate a plan for one
exact relation:

```bash
cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --output target/token-schema-plan.json
```

If `token-v2` adds `approval_nonce`, leaving it unlisted produces `SACK1001`.
State the new policy explicitly, such as `approval_nonce = 0`, review the plan,
then create and verify the receipt:

```bash
cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --acknowledge-by "reviewer identity" \
  --rationale "approval_nonce resets on transfer" \
  --output target/token-schema-ack.json

cellc schema-ack \
  --old ./token-v1 \
  --new ./token-v2 \
  --action transfer \
  --before token \
  --after next \
  --verify target/token-schema-ack.json
```

The receipt becomes stale if the schema or relation changes. It records review
only: every schema delta still requires a state-migration decision, and the
receipt does not make an interface compatible or authorize deployment.

## 6. Build And Verify The Typed Artifact

```bash
cellc build --target riscv64-elf --target-profile ckb
cellc verify-artifact build/main.elf --json
```

Metadata schema 71 includes:

- `public_interface` and `interface_hash`;
- `typed_semantics` and `typed_semantics_hash`;
- generic instantiation records; and
- the existing verified lowering and source-map bindings for ELF output.

The independent checker recomputes the canonical public-interface hash,
validates the complete generic parameter records and exact typed constants and
operations, and recomputes layout/identity, definite-definition joins,
ownership/borrow state, and the machine ABI link. It does not reconstruct
semantics from source. It uses `V2419` for an invalid typed semantic record and
`V2420` for a typed-to-machine mismatch.

This still does not mean the checker ran CKB-VM or observed a deployment. Keep
compiler, independent-checker, CKB-VM, deployment, commitment, and mainnet
evidence distinct.

## 7. Inspect It In The Playground

The browser compiler remains metadata-only: it emits no ELF. The Playground
accepts the `fixed_value` profile and highlights generics, abilities,
visibility, bitwise/shift operations, and
loop control. Its default size-bounded compiler returns an authoring summary
for Cell Flow, actions, and types. Generate the complete public-interface and
typed-semantics records with native `cellc`; the browser summary is not a
substitute for those records, semantic equivalence, or CKB-VM execution. Use
the VS Code extension for full semantic completion, hover, and definition
support.

## 8. Keep Unsupported Runtime Semantics Out Of Production

Generics alone do not make a Cell-backed collection executable. 0.26 promotes
only the fixed-width, source-qualified shapes whose runtime contracts are
explicit: `BoundedCellSet<T, N>` scans the current Type Script `GroupInput`,
and `BoundedList<P, N>` decodes `bounded-output-plan-v1` and verifies the same
relative `GroupOutput` data, lock, capacity, and exact count. The typed
semantics v3 record carries the dedicated load/verify/end operations so the
standalone checker can bind them to machine blocks.

Dynamic or recursive element layouts, other sources, custom identities,
incomplete output templates, missing locks or capacity floors, and arbitrary
body mutation still lower to the explicit fail-closed boundary. Permissive
artifacts return runtime error 24; `--production` and `--deny-fail-closed`
stop with E2105 before ASM or ELF is written.
