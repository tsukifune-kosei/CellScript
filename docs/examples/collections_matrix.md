# Collections Matrix Example

CellScript 0.12 documents collection support as a matrix, not as a claim of
fully generic collection runtime support.

Recommended authoring rule:

- use fixed structs and fixed arrays when possible
- use `Vec<u8>` for byte payloads
- use profile-gated checks for dynamic layouts
- expect unsupported nested dynamic containers to fail closed

Examples:

```cellscript
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
```

Use the support matrix for the current status:

```text
docs/CELLSCRIPT_COLLECTIONS_SUPPORT_MATRIX.md
```

