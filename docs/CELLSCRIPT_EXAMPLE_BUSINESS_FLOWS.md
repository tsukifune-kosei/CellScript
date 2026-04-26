# CellScript Example Business Flows

This document explains the business flow for each bundled `.cell` example.

## On-Chain Acceptance Boundary

The latest CKB production acceptance run exercises the seven production bundled
examples on a local CKB chain:

- `amm_pool.cell`
- `launch.cell`
- `multisig.cell`
- `nft.cell`
- `timelock.cell`
- `token.cell`
- `vesting.cell`

For those examples, all 43 business actions are strict-compiled, deployed, dry-
run, committed, and measured with builder-generated CKB transactions. The report
also records cycles, consensus transaction size, occupied capacity, malformed
transaction rejection, and output-capacity sufficiency.

Lock coverage is different: all 16 bundled locks strict-compile under the CKB
profile, but they are not yet covered by builder-backed on-chain spend and deny-
spend matrices. The production report keeps that remaining work explicit in
`lock_acceptance_scope.pending_onchain_lock_spend_matrix`.

`registry.cell` is not part of the seven-example CKB production action matrix.
It is a 0.13 language/tooling example for bounded local `Vec<Address>` and
`Vec<Hash>` helper behavior.

## `token.cell`

Business purpose: a simple fungible token with mint authority, transfer, burn,
and same-symbol merge flows.

```mermaid
flowchart TD
    A["MintAuthority input Cell"] --> B["mint"]
    B --> C["Check minted plus amount <= max_supply"]
    C --> D["Mutate MintAuthority.minted"]
    D --> E["Create Token output Cell for recipient"]

    F["Token input Cell"] --> G["transfer_token"]
    G --> H["Consume old Token"]
    H --> I["Create replacement Token locked to recipient"]

    J["Token input Cell"] --> K["burn"]
    K --> L["Check amount > 0"]
    L --> M["Destroy Token"]

    N["Token A input Cell"] --> O["merge"]
    P["Token B input Cell"] --> O
    O --> Q["Check symbols match"]
    Q --> R["Consume both inputs"]
    R --> S["Create merged Token output Cell"]
```

CKB acceptance status: all four actions are builder-backed and run on-chain.
There are no lock entries in this example.

## `amm_pool.cell`

Business purpose: a constant-product AMM pool with LP receipts and mutable pool
state.

```mermaid
flowchart TD
    A["Token A input Cell"] --> B["seed_pool"]
    C["Token B input Cell"] --> B
    B --> D["Check distinct symbols and nonzero liquidity"]
    D --> E["Consume both seed tokens"]
    E --> F["Create Pool shared Cell"]
    E --> G["Create LPReceipt for provider"]

    H["Pool input Cell"] --> I["swap_a_for_b"]
    J["Token A input Cell"] --> I
    I --> K["Check input symbol and slippage"]
    K --> L["Consume input token"]
    L --> M["Replace Pool reserves"]
    M --> N["Create Token B output Cell"]

    O["Pool input Cell"] --> P["add_liquidity"]
    Q["Token A input Cell"] --> P
    R["Token B input Cell"] --> P
    P --> S["Check token symbols"]
    S --> T["Replace Pool reserves and total LP"]
    T --> U["Create LPReceipt output Cell"]

    V["Pool input Cell"] --> W["remove_liquidity"]
    X["LPReceipt input Cell"] --> W
    W --> Y["Check receipt pool id"]
    Y --> Z["Destroy LPReceipt"]
    Z --> AA["Replace Pool reserves and total LP"]
    AA --> AB["Create Token A and Token B outputs"]
```

CKB acceptance status: all six actions are builder-backed and run on-chain,
including the helper actions `isqrt` and `min` as scoped entries. There are no
lock entries in this example.

## `launch.cell`

Business purpose: token launch composition, optionally seeding an AMM pool.

```mermaid
flowchart TD
    A["Launch parameters"] --> B["launch_token"]
    C["Paired pool token input Cell"] --> B
    B --> D["Check initial mint, pool seed, and distribution totals"]
    D --> E["Create MintAuthority output Cell"]
    E --> F["Create recipient Token outputs"]
    F --> G["Create pool seed Token"]
    G --> H["Call seed_pool pattern"]
    H --> I["Create Pool and LPReceipt outputs"]

    J["Simple launch parameters"] --> K["simple_launch"]
    K --> L["Check initial mint and recipient totals"]
    L --> M["Create MintAuthority output Cell"]
    M --> N["Create recipient Token outputs"]
    N --> O["Create creator remainder Token if needed"]
```

CKB acceptance status: both actions are builder-backed and run on-chain. There
are no lock entries in this example.

## `multisig.cell`

Business purpose: threshold wallet creation, proposal lifecycle, signature
collection, execution, cancellation, and signer/threshold governance proposals.

```mermaid
flowchart TD
    A["Signer list and threshold"] --> B["create_wallet"]
    B --> C["Check signer count, threshold, and duplicates"]
    C --> D["Create MultisigWallet Cell"]

    D --> E["propose_transfer"]
    E --> F["Check proposer is signer"]
    F --> G["Increment wallet nonce"]
    G --> H["Create transfer Proposal receipt"]

    H --> I["add_signature"]
    D --> I
    I --> J["Check signer, expiry, and no duplicate signature"]
    J --> K["Append Signature to Proposal replacement"]
    K --> L["Create SignatureConfirmation receipt"]

    H --> M["execute_proposal"]
    D --> M
    M --> N["Check executor signer, not expired, threshold met"]
    N --> O["Destroy Proposal"]
    O --> P["Create ExecutionRecord receipt"]

    H --> Q["cancel_proposal"]
    D --> Q
    Q --> R["Check proposer cancels matching proposal"]
    R --> S["Destroy Proposal"]

    D --> T["governance proposal actions"]
    T --> U["Create AddSigner, RemoveSigner, or ChangeThreshold Proposal"]
```

Strict-compiled locks:

```mermaid
flowchart LR
    A["is_signer_lock"] --> B["Signer membership predicate"]
    C["can_execute"] --> D["Threshold and expiry predicate"]
    E["can_cancel"] --> F["Proposer predicate"]
    G["has_enough_signatures"] --> H["Threshold predicate"]
    I["not_expired"] --> J["Expiry predicate"]
```

CKB acceptance status: all eight actions are builder-backed and run on-chain.
The five locks strict-compile, but still need on-chain valid-spend and invalid-
spend cases.

## `nft.cell`

Business purpose: NFT minting, transfer, listing, offer, royalty payout, burn,
and batch mint flows.

```mermaid
flowchart TD
    A["Collection input Cell"] --> B["mint"]
    B --> C["Check supply below max"]
    C --> D["Replace Collection total_supply"]
    D --> E["Create NFT output Cell"]

    F["NFT input Cell"] --> G["transfer"]
    G --> H["Check recipient differs from owner"]
    H --> I["Replace NFT.owner"]

    F --> J["create_listing"]
    J --> K["Check positive price"]
    K --> L["Create Listing receipt"]

    L --> M["cancel_listing"]
    M --> N["Destroy Listing"]

    F --> O["buy_from_listing"]
    L --> O
    O --> P["Check payment covers price"]
    P --> Q["Replace NFT.owner with buyer"]
    Q --> R["Destroy Listing"]
    R --> S["Create royalty and seller payment receipts"]

    T["Offer parameters"] --> U["create_offer"]
    U --> V["Create Offer receipt"]

    F --> W["accept_offer"]
    V --> W
    W --> X["Check offer not expired"]
    X --> Y["Replace NFT.owner with buyer"]
    Y --> Z["Destroy Offer"]
    Z --> AA["Create royalty and seller payment receipts"]

    F --> AB["burn"]
    AB --> AC["Destroy NFT"]

    A --> AD["batch_mint"]
    AD --> AE["Check capacity for four new NFTs"]
    AE --> AF["Replace Collection total_supply"]
    AF --> AG["Create four NFT output Cells"]
```

Strict-compiled locks:

```mermaid
flowchart LR
    A["nft_ownership"] --> B["NFT owner predicate"]
    C["listing_seller"] --> D["Listing seller predicate"]
    E["offer_buyer"] --> F["Offer buyer predicate"]
    G["valid_royalty"] --> H["Royalty basis-points predicate"]
    I["collection_creator"] --> J["Collection creator predicate"]
```

CKB acceptance status: all nine actions are builder-backed and run on-chain. The
five locks strict-compile, but still need on-chain valid-spend and invalid-spend
cases.

## `timelock.cell`

Business purpose: absolute and relative time locks, locked assets, normal
release, emergency release, extension, and batch lock creation.

```mermaid
flowchart TD
    A["Owner and height parameters"] --> B["create_absolute_lock"]
    B --> C["Check unlock height bounds"]
    C --> D["Create absolute TimeLock Cell"]

    E["Owner and period parameters"] --> F["create_relative_lock"]
    F --> G["Check period bounds"]
    G --> H["Create relative TimeLock Cell"]

    D --> I["lock_asset"]
    H --> I
    I --> J["Check amount > 0"]
    J --> K["Create LockedAsset Cell bound to lock hash"]

    D --> L["request_release"]
    L --> M["Check lock is unlockable"]
    M --> N["Create ReleaseRequest receipt"]

    D --> O["execute_release"]
    K --> O
    N --> O
    O --> P["Check owner, unlock height, and hash matches"]
    P --> Q["Destroy TimeLock, LockedAsset, and ReleaseRequest"]
    Q --> R["Create ReleaseRecord receipt"]

    D --> S["request_emergency_release"]
    S --> T["Check owner and not already unlockable"]
    T --> U["Create EmergencyRelease receipt"]

    U --> V["approve_emergency_release"]
    V --> W["Check approver not duplicated"]
    W --> X["Append approver to replacement EmergencyRelease"]

    D --> Y["execute_emergency_release"]
    K --> Y
    U --> Y
    Y --> Z["Check owner, approvals, and hash matches"]
    Z --> AA["Destroy locked inputs"]
    AA --> AB["Create ReleaseRecord receipt"]

    D --> AC["extend_lock"]
    AC --> AD["Check owner and still locked"]
    AD --> AE["Replace TimeLock.unlock_height"]

    AF["Four owner and height pairs"] --> AG["batch_create_locks"]
    AG --> AH["Create four TimeLock Cells"]
```

Strict-compiled locks:

```mermaid
flowchart LR
    A["can_unlock_lock"] --> B["Height reached predicate"]
    C["is_owner"] --> D["Owner predicate"]
    E["asset_matches"] --> F["Locked asset hash predicate"]
    G["emergency_approved"] --> H["Approval count predicate"]
    I["not_expired"] --> J["Still locked predicate"]
```

CKB acceptance status: all ten actions are builder-backed and run on-chain. The
five locks strict-compile, but still need on-chain valid-spend and invalid-spend
cases.

## `vesting.cell`

Business purpose: vesting configuration, grant creation, vested claims, and
revocation with explicit admin predicate visibility.

```mermaid
flowchart TD
    A["Admin configuration parameters"] --> B["create_vesting_config"]
    B --> C["Check cliff < total period"]
    C --> D["Create VestingConfig shared Cell"]

    D --> E["grant_vesting"]
    F["Token input Cell"] --> E
    E --> G["Check token symbol and nonzero amount"]
    G --> H["Read current timepoint"]
    H --> I["Consume grant tokens"]
    I --> J["Create VestingGrant receipt"]

    J --> K["claim_vested"]
    K --> L["Check cliff reached and not fully claimed"]
    L --> M["Compute vested and claimable amount"]
    M --> N["Consume old VestingGrant"]
    N --> O["Create claim Token output"]
    O --> P["Create updated VestingGrant receipt"]

    D --> Q["revoke_grant"]
    J --> Q
    Q --> R["Check revocable and admin predicate"]
    R --> S["Compute vested and unvested split"]
    S --> T["Consume VestingGrant"]
    T --> U["Create employee Token output"]
    T --> V["Create admin Token output"]
```

Strict-compiled lock:

```mermaid
flowchart LR
    A["vesting_admin"] --> B["claimed_admin equals config.admin"]
```

CKB acceptance status: all four actions are builder-backed and run on-chain. The
`vesting_admin` lock strict-compiles, but still needs on-chain valid-spend and
invalid-spend cases. The `claimed_admin` action parameter is not, by itself, a
signature authorization proof.

## `registry.cell`

Business purpose: bounded local collection helper coverage for `Vec<Address>`
and `Vec<Hash>`.

```mermaid
flowchart TD
    A["owner and candidate Address values"] --> B["local_registry_membership"]
    B --> C["Create local Vec with capacity"]
    C --> D["push, insert, swap, remove, truncate, set"]
    D --> E["Check contains and first"]
    E --> F["Return membership result"]

    G["first and second Hash values"] --> H["local_registry_key_roundtrip"]
    H --> I["Create local Vec"]
    I --> J["push, pop, swap, reverse"]
    J --> K["Check first and last"]
    K --> L["Return roundtrip result"]
```

CKB acceptance status: this example is intentionally outside the production CKB
action matrix. It is covered by compiler and tooling tests for bounded local
collection behavior.
