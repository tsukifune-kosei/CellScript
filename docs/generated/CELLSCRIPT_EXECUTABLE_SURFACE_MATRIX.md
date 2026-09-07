# CellScript Executable Surface Matrix

**Status**: generated from the compiler-owned 0.26 executable-surface registry

This file is generated. Run `cellscript-tools check-executable-surface --write` after changing the registry.

Production compilation means `--production` or `--deny-fail-closed`; both stop before codegen when a selected shape reports any listed fail-closed feature. Metadata-only compilation remains available for diagnostics and Playground inspection.

| ID | Layer | Status | Production policy | Conditions | Fail-closed features |
|---|---|---|---|---|---|
| `runtime:gather-hash-arguments` | runtime | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Experimental gathered hashes require proven local byte/offset vectors and checked transaction span bounds. | `gather-hash-materialization` |
| `runtime:spawn-hex4-arguments` | runtime | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Experimental returning four-argument hex SPAWN/WAIT requires a proven local Vec<u8>; the external child verifier remains separately unresolved. | `spawn-argv-materialization` |
| `runtime:exec-hex4-arguments` | runtime | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Experimental four-argument hex EXEC requires a proven local Vec<u8>; external-verifier delegation remains separately unresolved. | `exec-argv-materialization` |
| `runtime:trusted-external-delegation` | runtime | bounded | accepted only when the shape classifier reports no fail-closed feature | EXEC or SPAWN/WAIT is admitted only through a trusted_* intrinsic with a compile-time 32-byte DATA_HASH, an exact versioned Cell.toml declaration, an emitted pre-delegation identity check, and a trusted-external evidence record that never claims to prove the verifier's internals. | `none` |
| `type:u8` | type | complete | accepted | One-byte unsigned scalar with checked source representability. | `none` |
| `type:u16` | type | complete | accepted | Two-byte little-endian unsigned scalar. | `none` |
| `type:u32` | type | complete | accepted | Four-byte little-endian unsigned scalar. | `none` |
| `type:i32` | type | complete | accepted | Four-byte signed scalar with signed comparison, division, and remainder. | `none` |
| `type:u64` | type | complete | accepted | Eight-byte little-endian unsigned scalar. | `none` |
| `type:u128` | type | bounded | accepted only when the shape classifier reports no fail-closed feature | Sixteen-byte value with full-range decimal literals plus checked add, subtract, multiply, divide, remainder, comparison, casts, calls, parameters, and returns. | `none` |
| `type:bool` | type | complete | accepted | Canonical boolean scalar. | `none` |
| `type:unit` | type | compile-time-only | not materialized as a runtime value | Control-flow and no-value result marker. | `none` |
| `type:Address` | type | complete | accepted | Fixed 32-byte address value. | `none` |
| `type:Hash` | type | complete | accepted | Fixed 32-byte hash value. | `none` |
| `type:Array` | type | bounded | accepted only when the shape classifier reports no fail-closed feature | Compile-time length and recursively fixed element layout. | `none` |
| `type:GenericValue` | type | bounded | accepted only when the shape classifier reports no fail-closed feature | Struct, enum, and function templates monomorphize before IR under explicit value abilities, deterministic budgets, and hidden-Cell rejection. | `none` |
| `type:Option` | type | bounded | accepted only when the shape classifier reports no fail-closed feature | Built-in Option<T> uses the ordinary fixed-width generic enum and tagged-union lowering path. | `none` |
| `type:Tuple` | type | bounded | accepted only when the shape classifier reports no fail-closed feature | Non-recursive aggregate with deterministic field offsets. | `none` |
| `type:Named` | type | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Concrete struct, enum, or Cell schema with a deterministic metadata layout. | `none` |
| `type:Ref` | type | compile-time-only | not materialized as a runtime value | Read-only view with field-path, canonical-root reborrow, lifecycle-crossing, and non-escape checks before lowering. | `none` |
| `type:MutRef` | type | reserved | rejected by current semantic checks | No executable general mutable-reference ABI. | `none` |
| `semantic:value-pattern` | semantic | bounded | accepted | Recursive fixed enum, tuple, and struct patterns plus binding-free or-patterns with exhaustiveness and linear wildcard checks. | `none` |
| `semantic:borrow-region` | semantic | compile-time-only | not materialized as a runtime value | Field-path and reborrow regions retain one canonical Cell root and cannot materialize, escape, or cross a lifecycle operation. | `none` |
| `semantic:loop-control` | semantic | complete | accepted | Nearest and labeled break/continue targets lower to explicit CFG jumps after compile-time target validation. | `none` |
| `ir-item:type-def` | ir-item | bounded | accepted only when the shape classifier reports no fail-closed feature | Concrete fixed-layout type definition. | `none` |
| `ir-item:invariant` | ir-item | compile-time-only | not materialized as a runtime value | Proof-planning invariant record. | `none` |
| `ir-item:action` | ir-item | bounded | accepted only when the shape classifier reports no fail-closed feature | Executable transaction action entry. | `none` |
| `ir-item:pure-fn` | ir-item | bounded | accepted only when the shape classifier reports no fail-closed feature | Resolved helper callable. | `none` |
| `ir-item:lock` | ir-item | bounded | accepted only when the shape classifier reports no fail-closed feature | Executable lock predicate entry. | `none` |
| `ir-terminator:return` | terminator | complete | accepted | Typed return with an optional value. | `none` |
| `ir-terminator:jump` | terminator | complete | accepted | Validated direct CFG edge. | `none` |
| `ir-terminator:branch` | terminator | complete | accepted | Validated boolean conditional CFG edge. | `none` |
| `ir:load-const` | instruction | complete | accepted | Materializes supported scalar and fixed-byte constants. | `none` |
| `ir:load-var` | instruction | complete | accepted | Loads a checked local binding. | `none` |
| `ir:store-var` | instruction | complete | accepted | Stores a checked local binding without changing Cell authority. | `none` |
| `ir:binary` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Scalar arithmetic, bitwise, shifts, and complete u128 operators execute directly; dynamic shifts have width guards and fixed-byte equality requires addressable operands. | `fixed-byte-comparison` |
| `ir:unary` | instruction | bounded | accepted | Boolean not, scalar negation, and compile-time reference conversions. | `none` |
| `ir:field-access` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Requires a fixed schema, aggregate pointer, or tuple-call-return layout. | `field-access` |
| `ir:index` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Fixed aggregates and bounded stack collections with known element layout. | `index-access` |
| `ir:length` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Static lengths or validated bounded collection length words. | `dynamic-length` |
| `ir:type-hash` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Schema parameter or verified output Type Script hash. | `type-hash` |
| `ir:collection-new` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack buffer or verifier-covered create-output vector. | `collection-new` |
| `ir:collection-capacity` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection; hidden Cell ownership is rejected. | `collection-capacity, cell-backed-collection-capacity` |
| `ir:collection-push` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Fixed-width bounded value or verified output-vector construction. | `collection-push, cell-backed-collection-push` |
| `ir:collection-extend` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded fixed-width stack collection or verified output vector. | `collection-extend, cell-backed-collection-extend` |
| `ir:collection-clear` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection only. | `collection-clear, cell-backed-collection-clear` |
| `ir:collection-contains` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with comparable fixed-width elements. | `collection-contains, cell-backed-collection-contains` |
| `ir:collection-remove` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with fixed-width elements. | `collection-remove, cell-backed-collection-remove` |
| `ir:collection-insert` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with checked capacity and index. | `collection-insert, cell-backed-collection-insert` |
| `ir:collection-set` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with checked index. | `collection-set, cell-backed-collection-set` |
| `ir:collection-pop` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with fixed-width result. | `collection-pop, cell-backed-collection-pop` |
| `ir:collection-reverse` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with fixed-width elements. | `collection-reverse, cell-backed-collection-reverse` |
| `ir:collection-truncate` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with checked target length. | `collection-truncate, cell-backed-collection-truncate` |
| `ir:collection-swap` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Bounded stack collection with checked indexes. | `collection-swap, cell-backed-collection-swap` |
| `ir:bounded-cell-load` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Exact current Type Script group input scan with runtime cardinality, identity, role, and fixed-width decode checks. | `none` |
| `ir:bounded-plan-load` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Canonical bounded-output-plan-v1 Molecule FixVec decoding with exact length and runtime cardinality checks. | `none` |
| `ir:bounded-output-verify` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Plan-relative GroupOutput data, lock, Type Script role, and declared capacity-floor verification. | `none` |
| `ir:bounded-output-end` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Exact plan-count to current Type Script GroupOutput-count correspondence. | `none` |
| `ir:call` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Resolved typed callable with a closed ABI and effect summary. | `none` |
| `artifact:ckb-sighash-all` | artifact-policy | reserved | rejected by production policy | Canonical transaction sighash construction is deferred. Audit artifacts unconditionally exit with runtime error 66 when called, including discarded results and helper calls. | `ckb-sighash-all-deferred` |
| `ir:read-ref` | instruction | bounded | accepted | Explicit Input or CellDep read-only Cell view. | `none` |
| `ir:move` | instruction | complete | accepted | Typed local move; ownership validity is checked before lowering. | `none` |
| `ir:tuple` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Deterministic fixed aggregate construction. | `none` |
| `ir:enum-construct` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Concrete fixed-width payload enum construction, including pre-IR generic enum monomorphizations. | `none` |
| `ir:enum-tag` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Validated concrete payload enum tag. | `none` |
| `ir:enum-payload` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Fixed-width concrete enum payload field. | `none` |
| `ir:consume` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Explicit Cell-backed input consumption. | `consume-expression, non-cell-consume` |
| `ir:create` | instruction | bounded | accepted only when the shape classifier reports no fail-closed feature | Output construction covered by create-set verification. | `none` |
| `ir:transfer` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Verifier-covered output construction and lock replacement. | `transfer-expression` |
| `ir:destroy` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Explicit destructible Cell-backed operand. | `destroy-expression` |
| `ir:claim` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Verifier-covered receipt claim output. | `claim-expression` |
| `ir:settle` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Verifier-covered settlement output. | `settle-expression` |
| `ir:create-unique` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Verifier-covered output plus executable identity policy. | `create-unique-expression` |
| `ir:replace-unique` | instruction | shape-gated | accepted only when the shape classifier reports no fail-closed feature | Verifier-covered replacement plus executable identity policy. | `replace-unique-expression` |
| `ir:cell-metadata-equality` | instruction | complete | accepted | Lock-hash or capacity equality over validated Cell views. | `none` |
| `artifact:create-output-verification` | artifact-policy | shape-gated | accepted only when the shape classifier reports no fail-closed feature | All constructed output fields and output lock must be materializable by the verifier. | `output-verification-incomplete, output-lock-verification-incomplete` |
| `artifact:cell-backed-collection-return` | artifact-policy | reserved | rejected by production policy | Returning a hidden Cell-backed collection has no linear ownership ABI. | `cell-backed-collection-return` |
| `artifact:bounded-consume-each-runtime` | artifact-policy | bounded | accepted only when the shape classifier reports no fail-closed feature | The bounded-type-group-inputs-v1 fixed-width shape is executable; all other BoundedCellSet sources and element shapes remain fail-closed. | `bounded-consume-each-runtime` |
| `artifact:bounded-create-each-runtime` | artifact-policy | bounded | accepted only when the shape classifier reports no fail-closed feature | The bounded-output-plan-v1 fixed-width shape is executable when the output has a complete create template, explicit lock, no custom identity, and a declared capacity floor; all other shapes remain fail-closed. | `bounded-create-each-runtime` |
