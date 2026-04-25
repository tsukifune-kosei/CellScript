# Collections Matrix Example

CellScript documents collection support as a matrix, not as a claim of fully
generic collection runtime support.

Recommended authoring rule:

- use fixed structs and fixed arrays when possible
- use stack-backed local `Vec<T: FixedWidth>` helpers only for bounded
  verifier-local value work
- use schema/ABI vectors such as `Vec<u8>`, `Vec<Address>`, and `Vec<Hash>`
  for Molecule/witness payloads
- use profile-gated checks for dynamic cell layouts
- expect unsupported nested dynamic containers and cell-backed collection
  ownership to fail closed

0.13 stack-backed runtime helpers are deliberately bounded. `Vec::capacity()`
reports the fixed backing capacity (`256 / element_width`), not the requested
`Vec::with_capacity(n)` argument, and `cellc explain-generics` records each
checked instantiation with the concrete element type, width, backing model, and
helper set. The helper set preserves whether the value was constructed through
`Vec::new` or `Vec::with_capacity`.

Examples:

```cellscript
struct Snapshot {
    owner: Address,
    amount: u64,
}

action local_value_helpers(owner: Address, candidate: Address, snapshot: Snapshot) -> bool {
    let mut owners = Vec::with_capacity(2)
    owners.push(owner)
    owners.insert(0, candidate)
    owners.swap(0, 1)

    let mut snapshots = Vec::new()
    snapshots.push(snapshot)

    return owners.contains(owner) && snapshots.len() == 1
}

resource Blob has store, transfer {
    owner: Address,
    data: Vec<u8>,
}

resource FixedVotes has store, transfer {
    owner: Address,
    votes: [u64; 4],
}
```

Avoid claiming production support for shapes like:

```cellscript
resource NestedDynamic has store, transfer {
    rows: Vec<Vec<u8>>,
}

resource Token has store, transfer {
    owner: Address,
    amount: u64,
}

action hidden_ownership(tokens: Vec<Token>) -> u64 {
    return tokens.len()
}
```

Use the support matrix for the current status:

```text
docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md
```
