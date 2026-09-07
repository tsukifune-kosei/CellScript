# Cookbook Recipes

This page is a practical companion to the tutorials. Each recipe gives you a
small goal, the code or command to start from, and the boundary you should keep
in mind.

Read the main tutorials first if the concepts are unfamiliar. Use this page when
you already know what you want to do.

## Recipe: Compile One File For CKB

Use this when you have a single `.cell` file and want a CKB-profile artifact.

```bash
cellc examples/token.cell --target riscv64-elf --target-profile ckb --primitive-strict 0.16 -o /tmp/token.elf
cellc verify-artifact /tmp/token.elf --expect-target-profile ckb
```

This proves that the ELF, metadata, lowering record, and source map agree under
the bounded structural checker and CKB profile. It does not prove complete
source equivalence or that a CKB transaction has been built or accepted.

## Recipe: Create A Linear Resource

Use a `resource` when a value should not be duplicated or silently dropped.

```cellscript
resource Token has store, create, consume, replace, burn, relock {
    amount: u64
    symbol: [u8; 8]
}
```

The compiler tracks `Token` as a linear value. An action that receives a token
must consume, return, destroy, validate a named successor output, or pass it
through an explicit stdlib lifecycle pattern such as
`std::lifecycle::transfer`, `std::receipt::claim`, or
`std::lifecycle::settle`.

## Recipe: Mint With Authority

Use `create` when an action materializes new Cell state.

```cellscript
action mint_with_authority(auth_before: MintAuthority, to: Address, amount: u64) -> (auth_after: MintAuthority, token: Token) {
    transition auth_before -> auth_after

    verification
        require auth_before.minted + amount <= auth_before.max_supply, "exceeds max supply"
        require auth_after.token_symbol == auth_before.token_symbol
        require auth_after.max_supply == auth_before.max_supply
        require auth_after.minted == auth_before.minted + amount

        create token = Token {
            amount,
            symbol: auth_before.token_symbol
        } with_lock(to)
}
```

The field shorthand `amount` means `amount: amount`. The `with_lock(to)` part is
the lock on the created output Cell.

## Recipe: Mint And Replace A Unique Cell

Use an identity policy plus `create_unique` and `replace_unique` when a Cell
lineage must be explicit in source and metadata.

```cellscript
resource Badge has store, create, replace
    identity(field(badge_id))
{
    badge_id: [u8; 32]
    owner: Address
}

action issue_badge(badge_id: [u8; 32], owner: Address) -> Badge {
    verification
        create_unique<Badge>(identity = field(badge_id)) {
            badge_id,
            owner
        } with_lock(owner)
}

action transfer_badge(badge: Badge, new_owner: Address) -> Badge {
    verification
        replace_unique<Badge>(identity = field(badge_id)) badge {
            badge_id: badge.badge_id,
            owner: new_owner
        }
}
```

`replace_unique` consumes the named input before the field initializer block.
For `field(...)`, the generated verifier compares the fixed-width identity field
between input and output. `create_unique` emits a local output anchor and
records full create-time uniqueness as runtime-required; field identity
uniqueness still needs builder or indexer evidence.

## Recipe: Update State Without Updating In Place

Use an input-to-output action signature when the transaction updates state. The
input and output names are ordinary bindings; `require` clauses prove continuity
and the allowed field changes.

```cellscript
action bump_nonce(wallet_before: Wallet) -> wallet_after: Wallet {
    transition wallet_before -> wallet_after

    verification
        require wallet_after.owner == wallet_before.owner
        require wallet_after.nonce == wallet_before.nonce + 1
}
```

When reviewing this pattern, inspect metadata and builder evidence for the input
and output binding. Do not treat it as account storage.

## Recipe: Choose A Destruction Policy

Use the destruction form that says what the verifier should prove:

```cellscript
#[type_id("cookbook::Config:v1")]
resource Config has store, consume, burn
    identity(ckb_type_id)
{
    value: u64
}

#[type_id("cookbook::Asset:v1")]
resource Asset has store, consume, burn
    identity(ckb_type_id)
{
    amount: u64
}

resource Badge has store, consume, burn
    identity(field(badge_id))
{
    badge_id: u64
}

resource Token has store, consume, burn
    identity(field(amount))
{
    amount: u64
}

action retire(config: Config, asset: Asset, badge: Badge, token: Token) {
    verification
        destroy_singleton_type(config)
        destroy_unique(asset, identity = type_id)
        destroy_instance(badge, identity_field = badge_id)
        burn_amount(token, field = amount)
}
```

The resource declarations are part of the recipe: strict modes require
`consume + burn` before a value may be destroyed. In
`--primitive-compat=0.15` legacy compatibility mode, bare `destroy value` also
requires `consume + burn` instead of the legacy `destroy` attribute. Keep the
policy explicit when reviewers must distinguish output absence, identity
consumption, instance consumption, and quantity burn.

## Recipe: Write An Honest Lock Predicate

Use `protected`, `witness`, and `require` to make the CKB boundary readable.

```cellscript
lock owner_only(protected wallet: Wallet, witness claimed_owner: Address) -> bool {
    require wallet.owner == claimed_owner
}
```

Read this carefully:

- `wallet` is the protected input Cell view;
- `claimed_owner` is witness data;
- `require` fails validation if the comparison is false;
- the comparison does not prove that `claimed_owner` signed the transaction.

## Recipe: Avoid Fake Signer Semantics

Do not use names such as `signer` unless the value is actually produced by
signature verification.

```cellscript
// Misleading: this is still only witness data.
lock bad_owner_check(protected wallet: Wallet, witness signer: Address) -> bool {
    require wallet.owner == signer
}
```

Prefer names such as `claimed_owner` or `provided_owner` unless the value is
bound to an explicit verifier result.

## Recipe: Bind A Lock Predicate To Script Args

Use `lock_args` when a lock predicate depends on the executing script's args:

```cellscript
lock owner_boundary(
    wallet: protected Wallet,
    owner: lock_args Address,
    claimed_owner: witness Address
) -> bool {
    let input = source::group_input(0)
    let witness_lock = witness::lock(input)
    let digest = env::sighash_all(input)
    require wallet.owner == owner
    require claimed_owner == owner
    require witness_lock == digest
}
```

This makes the data source visible: `owner` comes from CKB `Script.args`, while
`claimed_owner` and `witness_lock` come from witness data. It still does not
turn either value into signer authority by name. Keep signature verification
explicit; do not treat `Address` as a signature proof.

This particular example is inspectable only: canonical `env::sighash_all`
construction is deferred. Production compilation rejects
`ckb-sighash-all-deferred`, and audit artifacts exit with runtime error 66
instead of producing a digest. For executable authorization, use a standard
authenticated Lock or define and verify a complete explicit message policy.

For a custom verifier whose complete first `WitnessArgs.lock` placeholder is
zero-filled, construct the bounded 0.30 domain explicitly:

```cellscript
let digest = env::sighash_all_zero_lock(4, 8, 4, 4096)
verifier::btc::bip340::require_signature_from_cell_dep(
    3,
    digest,
    xonly_pubkey,
    signature,
)
```

The four literals bound current-group inputs, transaction inputs, extra
witnesses, and each included witness. This domain commits to the transaction
hash, later group witnesses, and witnesses after the input count. It replaces
the complete first lock payload with equal-length zeros, so it is not the
message contract for a multisig placeholder that preserves a configuration
prefix.

## Recipe: Pin And Spawn A BIP340 Verifier

Use an explicit resolved CellDep index and bind its data hash before the VM2
spawn:

```cellscript
lock verify_authority(
    lock_args pinned_verifier_hash: Hash,
    witness message_hash: Hash,
    witness xonly_pubkey: [u8; 32],
    witness signature: [u8; 64],
) -> bool {
    verification
        ckb::require_cell_data_hash(source::cell_dep(3), pinned_verifier_hash)
        verifier::btc::bip340::require_signature_from_cell_dep(
            3,
            message_hash,
            xonly_pubkey,
            signature,
        )
        true
}
```

In production, `pinned_verifier_hash` must come from reviewed package
configuration, not witness authority. The builder also pins the out point and
`dep_type`. The verifier checks the supplied BIP340 prehash; the application
still owns the domain, ScriptGroup/WitnessArgs selection, sighash, key binding,
and replay policy. See the
[BIP340 verifier ABI](../CELLSCRIPT_SIGNATURE_VERIFIER_ABI.md).

## Recipe: Find A Pinned CellDep Within A Bound

Use the bounded scan when the resolved dependency index is builder-selected:

```cellscript
ckb::require_bounded_cell_dep_data_hash(8, expected_data_hash)
```

The bound must be a literal in `1..=64`. The helper scans the resolved CellDep
sequence and fails if the hash is not found. It cannot recover the original
DepGroup container identity; keep out point and dep type in manifest/builder
evidence.

## Recipe: Check A Small SHA256d Merkle Path

For a fixed path of at most 16 siblings:

```cellscript
ckb::require_sha256d_merkle_root(
    leaf,
    siblings,
    12,
    leaf_index,
    expected_root,
)
```

`siblings` has type `[Hash; 16]`; only the first `depth` entries are read. The
depth must be a literal in `0..=16`. Each node is raw
`SHA256d(left_32 || right_32)`, with ordering selected by the corresponding
`leaf_index` bit. This verifies one bounded Merkle path, not Bitcoin headers,
difficulty, confirmations, reorg policy, or RGB++ witnesses.

## Recipe: Compose With Spore Or RGB++

Start with the compile-checked packages under
`examples/ecosystem/spore-identity-adapter` and
`examples/ecosystem/rgbpp-identity-adapter`. They bind exact script identities
and transaction positions while leaving protocol rules to the maintained SDKs
and deployed scripts. Read
[Spore and RGB++ Interoperability Boundaries](Spore-and-RGBPP-Interop-Boundaries.md)
before extending them; neither package is a production-compatibility claim.

## Recipe: Use Empty Vec Literals Safely

Use `[]` only where the expected `Vec<T>` type is known.

```cellscript
let mut keys: Vec<Hash> = []

create proposal = Proposal {
    proposal_id,
    proposer,
    data: [],
    approvals: []
}
```

`[]` is empty `Vec<T>` sugar in a typed context. It is not a generic collection
model, and it does not enable cell-backed collection ownership.

## Recipe: Inspect Entry ABI And Witness Layout

Use ABI and entry-witness reports before building transaction code.

```bash
cellc abi . --target-profile ckb --action transfer
cellc entry-witness . --target-profile ckb --action transfer
```

These reports tell builders and reviewers what data the entry expects. They do
not prove that the transaction has been assembled correctly. Under Edition
2026, place the reported `CSARGv1` payload in the selected group witness's
Molecule `WitnessArgs.input_type`. Preserve `lock` and `output_type`, and fail
if `input_type` is already occupied; a raw payload is not a supported alias.

## Recipe: Sign And Verify A Compile Receipt

Use receipts when you need an authenticated envelope for build evidence:

```bash
cellc receipt src/main.cell --output target/main.receipt.json
cellc sign-receipt target/main.receipt.json --role publisher --key publisher.ed25519.pkcs8
cellc verify-receipt target/main.receipt.json \
  --metadata target/main.elf.meta.json \
  --artifact target/main.elf
cellc verify-artifact target/main.elf --receipt target/main.receipt.json
```

A receipt binds source, metadata, ProofPlan, ProtocolGraph, TemplateLayout, and
artifact hashes. A receipt signature authenticates that evidence envelope; it
does not prove transaction freshness, capacity sufficiency, dry-run success, or
submission.

## Recipe: Check A Package Before Building

Use this loop while developing a package:

```bash
cellc fmt --check
cellc check --target-profile ckb --all-targets --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

This is a compiler/package gate. Use it before asking for deeper CKB evidence.

## Recipe: Run The CKB Production Gate

Use this only from the CellScript repository root:

```bash
./scripts/cellscript_gate.sh release
```

This is the boundary where compiler evidence becomes builder-backed local CKB
evidence for the bundled suite.

## Recipe: Choose An Example To Read

Start with the smallest example that teaches the idea you need:

| Goal | Read |
|---|---|
| Linear resource effects | `examples/token.cell` |
| Unique assets and ownership | `examples/nft.cell` |
| Time-gated releases | `examples/timelock.cell` |
| Non-cryptographic threshold approvals | `examples/multisig.cell` |
| Claim receipts | `examples/vesting.cell` |
| Shared liquidity state | `examples/amm_pool.cell` |
| Composition patterns | `examples/launch.cell` |
| Local bounded vectors | `examples/language/collections/registry.cell` |
| Local order-vector helpers | `examples/language/collections/order_book.cell` |

Read one example for one idea. The examples are easier to learn from when you do
not treat them as one large feature checklist.

For Spore or RGB++ work, do not start from a simplified local clone of the
protocol schema. First read the
[Spore and RGB++ interoperability boundaries](Spore-and-RGBPP-Interop-Boundaries.md),
then pin the maintained SDK, contract identities, deployments, and fixtures in
an adapter package.
