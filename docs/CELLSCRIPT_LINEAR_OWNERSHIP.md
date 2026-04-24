# CellScript Linear Ownership

**Status**: production semantics for CellScript 0.12.

CellScript treats cell-backed resources as linear values. A linear value cannot
be copied, silently dropped, or used after it has been consumed, transferred,
destroyed, claimed, settled, or moved into a replacement transition.

## Compile-Time Rules

The type checker enforces:

- values are unavailable after `consume`, `transfer`, `destroy`, `claim`, or
  `settle`
- both branches of `if` and `match` must leave linear values in compatible
  ownership states
- loops cannot hide linear state changes that would make ownership depend on
  runtime iteration count
- a linear value cannot be stored in an ordinary local aggregate and then escape
  the checked ownership path
- references rooted in linear values cannot outlive the root value

These are compile-time checks. Generated verifier code may also clear consumed
stack slots as a runtime defense, but stack clearing is not the primary
ownership model.

## Required End States

Every acquired cell-backed value must reach an explicit terminal operation:

- `transfer`
- `destroy`
- `claim`
- `settle`
- `mutate` replacement
- another verified operation documented in metadata

Silent end-of-scope loss is rejected.

## Cell-Backed Collections

Generic ownership of collections of linear cells is not a production feature in
0.12. A `Vec<Token>` or `HashMap<Hash, NFT>` would require a verifier-backed
membership and consumption model. Until that model exists, such cases must
remain compile-time rejected or represented as structured runtime blockers.

Future design candidates:

- `consume_each`
- typed collection destructuring
- verifier-backed membership proofs
- schema-level ownership witnesses

