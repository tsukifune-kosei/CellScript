# CellScript Mutate And Replacement Outputs

**Status**: production semantics for CellScript 0.12.

CellScript `&mut Shared` does not mean physical in-place mutation on CKB or
Spora. Cells are immutable. A mutable shared parameter lowers to:

```text
Input#N old cell  ->  Output#M replacement cell
```

The compiler-generated verifier proves that the replacement output is the only
accepted state transition for the action.

## Required Checks

For each mutable cell, generated code and metadata record:

- input cell data load
- output cell data load
- type hash preservation unless the transition explicitly permits rebinding
- lock hash preservation unless the transition explicitly permits rebinding
- preserved field equality
- transition field validation
- scheduler-visible mutate input/output access

Fixed-struct layouts are checked by byte offsets and exact field sizes. Molecule
table layouts are checked through the table-aware dynamic verifier path and the
schema manifest.

## Transition Shapes

Current production transition classes include:

| Shape | Meaning |
|---|---|
| `Set` | Output field equals an expected expression or parameter |
| `Add` | Output field equals input field plus delta |
| `Sub` | Output field equals input field minus delta |
| `Append` | Output vector field equals input vector plus appended payload |

Unsupported transition shapes must remain fail-closed and must use a registered
runtime error code.

## AMM Pool Example

`examples/amm_pool.cell` is the canonical advanced mutate example:

- `swap_a_for_b` mutates reserves through add/sub transitions
- `add_liquidity` mutates reserves and LP supply through proportional updates
- `remove_liquidity` mutates reserves and LP supply through subtraction

The generated metadata exposes the mutation in `mutate_set`, runtime
requirements, CKB runtime accesses, and scheduler witness access operations.

## Builder Contract

The transaction builder must place the consumed shared cell and its replacement
output at the indexes declared by metadata. Production reports must retain:

- action name
- input and output indexes
- occupied-capacity measurement for the replacement output
- serialized transaction size
- dry-run or VM execution evidence

If the builder cannot prove this mapping, the artifact is not production-ready
even if it compiles.

