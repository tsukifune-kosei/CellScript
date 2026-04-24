# Mutate Append Example

CellScript `mutate` is modeled as a replacement output. It is not physical
in-place mutation of a CKB or Spora cell.

Conceptual source shape:

```cellscript
resource Log has store, transfer {
    owner: Address,
    bytes: Vec<u8>,
}

action append(log: Log, suffix: Vec<u8>) {
    let next = log.bytes;
    next.extend(suffix);
    mutate log {
        bytes: next
    };
}
```

Expected transaction shape:

- one input consumes the old `Log`
- one output creates the replacement `Log`
- preserved fields such as `owner` must match
- changed fields such as `bytes` must satisfy the compiled transition checks

Relevant inspection commands:

```bash
cellc check contract.cell --target-profile spora
cellc check contract.cell --target-profile ckb
cellc constraints contract.cell --target-profile ckb --json
```

For CKB, the builder must also provide occupied-capacity and transaction-size
evidence for the replacement output.

