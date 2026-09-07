# CellScript Public Interfaces And Compatibility

**Status**: v2 implemented on `nightly-0.26`; v3 implemented on the `0.30`
development branch

**Schemas**: `cellscript-package-interface-v3` (current),
`cellscript-package-interface-v2` (read compatibility), and
`cellscript-interface-compatibility-v1`

## What The Interface Represents

Every successful compile now constructs a canonical public package interface.
It is stored in compile metadata as `public_interface`; its CKB BLAKE2b-256
identity is stored as `interface_hash`.

The interface contains only exported items and records the contracts that a
consumer or Registry upgrade must preserve:

- canonical module, type, constant, action, lock, and function identities;
- explicit `public`, `public(package)`, and `private` visibility;
- type parameters, phantom parameters, value abilities, and Cell lifecycle
  capabilities as separate fields;
- fields, enum variants, fixed layouts, and type identities;
- callable parameters, source qualifiers, outputs, return types, effects, and
  entry witness ABI;
- source generic templates and applied types in exported signatures, without
  implementation-only monomorphizations;
- target, VM, witness, lock-args, source-encoding, Spawn/IPC, and compatibility
  profile identities;
- the `cellscript-ckb-temporal-interface-v1` fixed representation, RFC0017
  constructor/decoder inventory, distinct domain names, `since_abi`, and
  mechanical migration identity; and
- generated-builder and deployment-contract hashes.

Edition 2026 keeps the historical public-by-default behavior for an item with
no modifier. New reusable packages should spell visibility explicitly so a
future edition migration does not silently change the exported surface.

On the experimental `0.26b` branch, the bounded native Edition 2027
`type_script` entry lowers to the existing action interface while its semantic
foundation separately records the exact `type-group<T>` trigger. The native
`lock_script` entry likewise lowers to the checked lock interface and records
its exact `lock-group` authorization boundary. The source edition, public
interface, core semantics, and entry contract remain distinct identities; see
the
[`Edition 2027 preview grammar`](CELLSCRIPT_2027_PREVIEW_GRAMMAR.md).

The experimental `cellc migrate --to 2027` command does not decide public API
compatibility or rewrite visibility. It replaces only the one final legacy
entry in a self-contained module, preserves all surrounding source bytes, and
requires the old and candidate core semantic identities and ELF bytes to
match. Full six-dimensional public-interface comparison remains a later
migration gate.

```cellscript
module example::math

public struct Pair<T: copy + drop + store + fixed + serializable + non_linear>
    has copy, drop, store, fixed, serializable, non_linear {
    left: T
    right: T
}

public(package) fn sum_pair(pair: Pair<u64>) -> u64 {
    return pair.left + pair.right
}

private fn implementation_detail(value: u64) -> u64 {
    return value
}
```

`public(package)` items are visible to modules in the same package but are not emitted
as dependency-facing exports. `private` items are local to their module.
Imported public generic templates may be specialized across package boundaries;
the specialization is generated in the template's owning module and linked by
a compiler-internal import. It is never a source-level export.

Edition 2026 compatibility remains public-by-default. When a module mixes an
explicit modifier with declarations that still rely on that default, compiler,
CLI metadata, and editor diagnostics emit `W2500` and list the declarations to
classify.

## Emit An Interface

For a source file or package:

```bash
cellc interface path/to/package --json
cellc interface path/to/package --output target/package.interface.json
```

The JSON envelope contains both `interface` and `interface_hash`. The hash is
computed over canonical JSON; reordering source declarations does not change
the identity after the compiler's canonical sort.

## Compare Two Releases

```bash
cellc interface-diff \
  --old target/old.interface.json \
  --new path/to/candidate-package \
  --json
```

The report classifies changes across six independent dimensions:

| Dimension | Examples of breaking changes |
| --- | --- |
| `source_api` | removing an export; changing a type parameter, parameter, return type, or output |
| `serialized_layout` | changing fields, variants, offsets, fixed sizes, or type identity |
| `runtime_abi` | changing an entry ABI, witness placement, target, or versioned VM contract |
| `effects_capabilities` | changing callable effects, value abilities, or Cell lifecycle capabilities |
| `builder` | changing the generated transaction-builder contract |
| `deployment` | changing the deployment/runtime identity contract |

A breaking report exits with stable compiler code `E2501`. Additive exports are
reported as compatible changes; they still change `interface_hash`, so a
consumer can choose whether it accepts a new exact identity.

The v3 reader accepts a v2 JSON interface with an empty default temporal
contract so `interface-diff` can compare an older release. Moving from that
empty contract to the v3 typed contract is a `runtime_abi` and deployment
break. Changing an exported callable from raw `u64` to a temporal domain is
also a `source_api` and call-ABI break. Registry publication validates the
canonical v3 temporal fields instead of trusting an arbitrary interface hash.

## Registry Admission

CellScript source publication includes the canonical interface and hash in the
signed publish payload. The Registry API recomputes the hash, rejects a
mismatch, requires monotonically increasing SemVer, and compares a candidate
with the greatest predecessor on the same compatibility line. A new major
version (or new `0.minor` line before 1.0) may intentionally break the old
interface; an incompatible change within a line is rejected. The standalone
Registry verifier also checks that the stored interface and `interface_hash`
agree.

This is package compatibility evidence, not proof that an artifact is safe or
deployed. Registry verification, the typed semantic checker, CKB-VM execution,
deployment evidence, and chain commitment remain separate states.

## Typed Semantics Relationship

The public interface answers “what can a dependency rely on?” The
`cellscript-typed-semantics-v8` record answers “what typed operations and
control-flow facts were lowered?” Its embedded
`cellscript-semantic-foundation-v3` additionally answers where values came
from, which transaction roles they bind, how Cells are disposed, where claims
are enforced, and how entry/artifact contracts are identified. These remain
distinct from the package interface hash. Its fixed-Cell binding table records
the resolved source, ordinal, local identity and Script-group membership;
syntactic parameter sources are not physical selectors or authentication.
An explicit policy's tagged export set and outer witness ABI are bound by its
entry contract. The package interface hash does not by itself select or prove a
particular deployed policy; deployment and builder consumers must retain the
selected artifact contract as well.
Typed semantics v8 can also name an exact, manifest-declared external verifier
under the `trusted-external` evidence tier. That record binds the selected
CellDep data hash and delegation operation; it is not part of the package
interface hash and is not a proof of the external program's implementation.
ELF builds additionally bind the typed record to the verified lowering and machine
records described in
[CellScript Verified Artifact Boundary](CELLSCRIPT_VERIFIED_ARTIFACT_BOUNDARY.md).
