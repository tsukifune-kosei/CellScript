# Spora DSL Design Proposal v2

## 1. Executive Summary

This memo proposes a new Spora-native DSL named **Hypha**.

Hypha is not intended to be a general smart contract language. It is a **state-transition DSL for cell lineage**: a language for defining assets, objects, receipts, shared-state flows, and settlement flows as explicit effectful transitions over discrete state objects. Pool and launch flows are important protocol patterns, but they should be modeled over the core Cell primitives rather than promoted into separate language declaration classes. The unit of programming is not “a contract with storage”; it is “a typed transition over consumed, read, shared-written, and created objects.”

This DSL should exist because Spora is already no longer just “CKB but DAG.” It already has DAG-aware scheduling, lineage-sensitive state, and a growing need for protocol-visible effect summaries. Raw CKB contract authoring is too low-level for the protocol surface Spora wants to support: receipts, shared-state protocols, settlement, lifecycle transitions, high-velocity asset creation, and post-v1 transaction-builder patterns such as launch flows. The scheduler also needs declared touch-sets and effect classes. A generic VM-first language hides too much.

Why not Solidity:
- Solidity assumes an account/storage world.
- It optimizes for arbitrary code mutating shared contract state.
- It is scheduler-hostile unless heavily restricted after the fact.

Why not Move directly:
- Move’s resource model is strong, but its storage/object model is not cell-lineage native.
- It is still too package/module-global and less explicit about transaction touch surfaces than Spora needs.
- Shared-state discipline is not naturally expressed as a scheduler-facing effect manifest.

Why not Sway directly:
- Sway is closer on explicit execution surfaces, but it is still VM-first and account-contract shaped.
- It lacks a first-class notion of receipts, settlement classes, and lifecycle-typed lineage objects.

The design direction is:
- Rust-like syntax for clarity and explicitness
- Move-like linear resources and ownership intuition
- Sway-like touched-state explicitness and execution discipline
- lowered into Spora-native effect manifests plus `ckbvm`-compatible verification artifacts

The intended result is a language that feels native to:
- assets
- objects
- receipts
- shared-state updates
- shared-state protocol patterns, including pools
- post-v1 launch-builder flows
- settlement
- lifecycle-aware state transitions

## 2. Architectural Fit

Hypha fits current Spora well because Spora already thinks in cells, diffs, DAG-visible conflicts, and verifier execution on top of `ckbvm`.

### 2.1 Fit with Current Spora

Grounded against the current codebase:
- `CellTx`, `CellInput`, `CellOutput`, `OutPoint`, `Script` already exist as the execution substrate.
- The scheduler already builds a DAG from declared cell dependencies and conflicts.
- Parallel execution is already layer-oriented.
- The protocol direction is already moving toward effect-style processing for virtual-state composition.

Relevant code and docs:
- [exec/src/celltx/types.rs](/Users/arthur/RustroverProjects/Spora/exec/src/celltx/types.rs)
- [exec/src/scheduler/dag.rs](/Users/arthur/RustroverProjects/Spora/exec/src/scheduler/dag.rs)
- [exec/src/scheduler/executor.rs](/Users/arthur/RustroverProjects/Spora/exec/src/scheduler/executor.rs)
- [docs/MPE_VIRTUAL_PROCESSOR_PARALLELIZATION_DESIGN.md](/Users/arthur/RustroverProjects/Spora/docs/MPE_VIRTUAL_PROCESSOR_PARALLELIZATION_DESIGN.md)

### 2.2 Fit with Cell / State Ontology

Every CellStateTree-backed Hypha value lowers to one or more typed Cells with:
- a canonical object header
- a typed payload
- a lock policy
- an optional type policy
- explicit lineage metadata

Consumption and creation remain explicit. Hypha does not erase the Cell model. It raises it into a typed object model.

### 2.3 Fit with DAG-Oriented Execution

Each Hypha `action` compiles to an effect summary:
- `consume_set`
- `read_refs`
- `write_intents`
- `create_set`
- `effect_class`
- `lifecycle_rules`

That is precisely the kind of surface Spora needs for:
- pre-execution conflict detection
- DAG construction
- parallel scheduling
- deterministic mergeset effect composition

### 2.4 Fit with Scheduler / Execution Graph

The scheduler should not have to infer all relevant state touches from opaque VM code. Hypha gives it a declared state-touch contract.

That means:
- owned resource consumption is visible before execution
- shared writes are explicit and versioned
- receipt-claim paths are visible as consume/create transitions
- independent actions can parallelize naturally

### 2.5 Fit with `ckbvm`

Hypha does not require a new VM first.

Short term:
- compile Hypha into canonical cell layouts
- generate effect manifests and witness formats
- generate verifier code that runs through current `ckbvm`

Medium term:
- introduce a Spora-native object verifier ABI on top of `ckbvm`
- keep source-level Hypha stable while improving backend efficiency

### 2.6 Compatibility: Keep vs Break

#### Remain compatible with current Spora structure

- `OutPoint`, `CellInput`, `CellOutput`, lock/type/data decomposition
- `since` / timelock mechanics
- dep groups and code cells
- witness-oriented verification
- `ckbvm` execution path
- scheduler DAG over RW-sets
- cell diff / cell root / block effect model

#### Break away from current CKB-like design

- stop making raw byte-packed cells the primary developer abstraction
- stop making developers hand-assemble all lock/type/data conventions by hand
- stop treating “one script equals one contract API” as the main programming model
- introduce compiler-owned object headers, lifecycle states, effect manifests, and standard object classes

## 3. Language Philosophy

### 3.1 What the Language Is For

Hypha is for:
- defining typed assets and typed state objects
- expressing lifecycle-aware transitions
- declaring touched state explicitly enough for scheduling
- building launch, pool, receipt, vesting, wrapping, and settlement flows

### 3.2 What the Language Is Not For

Hypha is not for:
- unrestricted arbitrary computation
- recreating a general-purpose host language on-chain
- dynamic dispatch heavy systems
- hidden mutable global storage
- open-ended runtime call graphs

### 3.3 Protocol-Designer Freedom vs Application-Level Freedom

#### Protocol-designer freedom

Protocol designers should be able to:
- define object classes
- define lifecycle states
- define invariant rules
- define settlement classes
- define standard transitions
- introduce new native primitives if they truly deserve scheduler/runtime visibility

#### Application-level freedom

Application builders should be able to:
- compose protocol-provided objects and transitions
- define app-specific payload schemas
- define app-specific invariants inside the object/effect model
- extend behavior without escaping the scheduler-visible transition discipline

### 3.4 Intentional Expressiveness Sacrifices

Compared with EVM/Solidity, Hypha intentionally gives up:
- unrestricted reentrancy
- hidden storage slot mutation
- dynamic maps as the default persistence primitive
- arbitrary inter-contract call graphs as the primary composition mechanism
- opaque runtime behavior that the scheduler can only discover after execution

This is not a bug. It is a design choice. Spora should trade some generic expressiveness for:
- predictable state transitions
- schedulable execution
- clean lineage semantics
- better fit for asset-heavy systems

## 4. Core Semantic Model

### 4.1 `resource`

What it means:
- A linear owned value that must move, split, merge, consume, or persist exactly once.

Why it exists:
- To make asset flow statically checkable.
- To prevent accidental duplication or silent dropping of economically meaningful values.

What problems it solves:
- Hidden inflation by logic bugs
- Ambiguous ownership
- Implicit value creation or destruction

How it maps to Spora:
- Cell-backed resources lower to Cells or sets of Cells.
- Transaction-local resource values may exist during action execution but must either be consumed or materialized.

How it differs:
- Versus Solidity: stronger than balance accounting.
- Versus Move: similar linearity intuition, but anchored to cell lineage.
- Versus Sway: more semantic than plain structs and explicit outputs.

### 4.2 `shared`

What it means:
- A CellStateTree-backed object that may be read by many transactions but written only through an explicit shared-write discipline.

Why it exists:
- Spora needs shared state, but only in a scheduler-visible form.

What problems it solves:
- Hidden contention
- Opaque runtime write conflicts
- Unbounded contract-global mutation

How it maps to Spora:
- A shared object is a canonical shared-cell lineage with:
  - stable `object_id`
  - version
  - lifecycle state
  - write policy

How it differs:
- Versus Solidity: shared state is explicit and version-gated, not arbitrary storage mutation.
- Versus Move: shared objects exist, but Spora requires more scheduler-visible write intent.
- Versus Sway: more object-lineage explicit, less contract-storage shaped.

### 4.3 `receipt`

What it means:
- A typed claim ticket proving a prior effect and authorizing later follow-up.

Why it exists:
- Delayed rights are central to launches, vesting, vest-claim, queue-settlement, and deferred redemption.

What problems it solves:
- Using logs/events for rights
- Ad hoc delayed-claim encodings
- Loss of provenance across multi-step flows

How it maps to Spora:
- A receipt is a cell-backed linear object with provenance fields and one-shot or partial-consume rules.

How it differs:
- Versus Solidity: stronger than events, because it is state not metadata.
- Versus Move: closer to resource tickets, but more explicitly tied to lineage and follow-up actions.
- Versus Sway: more first-class than app-specific structs.

### 4.4 `launch`

What it means:
- A post-v1 transaction-builder pattern that instantiates an asset plus initial distribution and optionally initial pool state.

Why it exists:
- Launches are not just constructors. They are protocol-significant multi-output transaction templates with repeatable semantics.

What problems it solves:
- Re-implementing asset genesis and initial liquidity setup in every app
- Inconsistent launch mechanics
- Weak scheduler visibility for launch-related effects

How it maps to Spora:
- A future transaction-builder lowering producing:
  - asset root object
  - optional pool object
  - optional receipts
  - lifecycle state transitions

How it differs:
- Versus Solidity: not a constructor on contract storage.
- Versus Move/Sway: more native to asset genesis and liquidity bootstrapping.

### 4.5 Pool Pattern

What it means:
- A protocol pattern built from a shared object carrying liquidity state plus invariant rules.

Why it exists:
- Pools are a core economic state object and deserve a standard semantic frame in libraries, metadata, and tooling.

What problems it solves:
- Ad hoc pool encodings
- Hidden shared-state mutation
- Invariant enforcement scattered across arbitrary code

How it maps to Spora:
- A shared object cell with:
  - reserves
  - invariant parameters
  - fee parameters
  - state/lifecycle
  - shared-write discipline

How it differs:
- Versus Solidity: more scheduler-visible than “a contract with balances.”
- Versus Move/Sway: more explicitly modeled as a shared lineage object.
- Versus language primitives: not a separate declaration class; AMM curves and pool admission rules are protocol-specific.

### 4.6 `settle`

What it means:
- Deterministic finalization of accumulated claims, deltas, or queued effects into CellStateTree state.

Why it exists:
- Spora needs a clean path for high-throughput flows that cannot safely mutate every shared object directly in every action.

What problems it solves:
- Shared-state write amplification
- Ambiguous multi-step finalization logic
- Runtime-heavy contention handling

How it maps to Spora:
- An action class over receipts and/or shared objects producing a new lineage tip for the settled state.

How it differs:
- Not “just another function call.”
- It is a named effect class with protocol-visible meaning.

### 4.7 Transaction-Local Values and CellStateTree Commit

What it means:
- Ordinary local values are transaction-scoped and cannot cross the transaction boundary unless they are explicitly materialized through `create`.
- A value created through `create` becomes a live lineage object after commit.

Why it exists:
- Spora needs a clear distinction between local computation and chain state without adding marker keywords for behavior already implied by `let` and `create`.

What problems it solves:
- Fuzzy state-commit boundaries
- Ad hoc serialization discipline
- Confusion between computation values and lineage objects

How it maps to Spora:
- Witness-only or VM-local values are erased after verification.
- Output Cells carry canonical object headers plus payloads.

How it differs:
- Unlike generic contract storage, state commitment is explicit and object-shaped.

## 5. Type System Proposal

### 5.1 Minimum Useful Type System

Recommended minimum:
- Scalars: `u8`, `u16`, `u32`, `u64`, `u128`, `u256`, `bool`
- Fixed bytes: `[u8; N]`
- Dynamic bytes: explicit witness/data slices only, not persisted schema fields
- Vectors: controlled local `Vec<T>` notation for bounded collection APIs; persisted schemas use fixed arrays
- Domain scalars: `address`, `hash`, `amount`
- Product types: `struct`
- Small sum types: `enum`
- Declaration classes:
  - `asset`
  - `receipt`
  - `object`
  - `shared object`

### 5.2 Ownership / Linearity / Capability

Recommended rules:
- `asset`, `receipt`, and `object` are linear by default.
- `plain` values may copy and drop.
- `shared` values cannot be moved out.
- `shared` values may be borrowed immutably or mutably only within action discipline.

Do not copy Move’s full ability system.

Instead, use a simpler declaration-class model:
- `plain`
- `resource`
- `shared`

That is enough for v1.

### 5.3 Post-v1 Templates, Not Core Generics

Generic authoring is useful, but it should not be part of the v1 executable language core.

Recommended:
- reject user-defined generic type definitions and instantiations in v1 CellScript source
- put parametric authoring in a post-v1 package/codegen/template layer
- generate concrete `.cell` modules with concrete schema names, concrete fields, concrete lifecycle rules, and stable `#[type_id("...")]` metadata
- keep `Vec<T>` as a controlled builtin collection notation, not as evidence of a general user-defined generic type system

Do not build:
- `resource Vault<T>` / `receipt Claim<TAsset>` as v1 executable syntax
- higher-kinded abstractions
- trait-heavy typeclass machinery
- meta-programming systems inside consensus-facing source

### 5.4 Object Identity Model

Every CellStateTree object should carry a canonical header:

```text
ObjectHeader {
  kind_id: hash,
  object_id: hash,
  lineage_root: hash,
  version: u64,
  lifecycle: u8,
  owner_mode: enum { Owned, Shared, Receipt, System },
  policy_hash: hash
}
```

Recommended semantics:
- `kind_id`: schema/object class identity
- `object_id`: stable identity for shared object continuation, or fresh identity for newly materialized owned objects
- `lineage_root`: original ancestor root for ancestry queries
- `version`: monotonic version for shared continuations
- `lifecycle`: current lifecycle state
- `policy_hash`: binds to the governing verifier rules

### 5.5 Shared Object Representation

Shared objects should be represented as CellStateTree objects with:
- stable `object_id`
- explicit `version`
- lifecycle state
- optional settlement epoch / sequence domain

Mutating actions must declare:
- `write shared Foo@expected_version`

### 5.6 Lifecycle Representation

Lifecycle should be explicit, not implicit.

Use:
- small enums for lifecycle states
- `transition` declarations to define legal source and destination transitions

Example:

```hypha
enum LaunchState { Planned, Open, Seeded, Live, Settled, Closed }
```

Compiler responsibility:
- reject illegal lifecycle transitions statically where possible
- emit runtime lifecycle checks where needed

## 6. Syntax Proposal

The syntax should feel inspired by Rust + Move + Sway, but remain original. The language must stay small.

### 6.1 Core Syntax Shape

Structural forms:
- `module`
- `asset`
- `receipt`
- `object`
- `shared object`
- `action`
- `transition`
- `requires`
- `ensures`
- `touches`

### 6.2 Example Syntax

#### Fungible asset

```hypha
module meme.launchpad;

asset Meme {
    symbol: [u8; 8],
    decimals: u8,
    total_supply: u128,
}
```

#### Receipt object

```hypha
receipt MemeVestingClaim {
    beneficiary: address,
    remaining: u128,
    cliff_daa: u64,
    interval_daa: u64,
}
```

#### Shared pool object

```hypha
shared object MemePool {
    base_reserve: u128,
    quote_reserve: u128,
    lp_supply: u128,
    fee_bps: u16,
    state: PoolState,
}

enum PoolState { Seeded, Live, Frozen, Settled }
```

#### Launch action

```hypha
action launch_meme(
    admin: signer,
    quote_seed: QuoteCoin,
    cfg: LaunchConfig
) -> (Meme, shared MemePool, receipt MemeVestingClaim)
touches {
    consume quote_seed,
    read cfg.template,
    create Meme,
    create shared MemePool,
    create receipt MemeVestingClaim,
    effect launch,
}
requires {
    cfg.initial_supply > 0,
    cfg.seed_quote > 0,
}
ensures {
    Meme.total_supply == cfg.initial_supply,
    MemePool.state == PoolState::Seeded,
}
```

#### Settle action

```hypha
action settle_pool(
    admin: signer,
    pool: &mut shared MemePool,
    batch: SettlementBatch
) -> SettlementResult
touches {
    write pool,
    read batch,
    effect settle,
}
requires {
    pool.state == PoolState::Live,
}
```

#### Transaction-local value

```hypha
struct Quote {
    base_in: u128,
    quote_out: u128,
    fee_paid: u128,
}

fn quote_swap(pool: &MemePool, base_in: u128) -> Quote {
    let fee = (base_in * pool.fee_bps as u128) / 10_000;
    let net = base_in - fee;
    let out = (net * pool.quote_reserve) / (pool.base_reserve + net);
    Quote { base_in, quote_out: out, fee_paid: fee }
}
```

### 6.3 Key Design Point

The original core syntax feature is:
- `touches { ... }`

That is the scheduler contract. It is not decorative metadata.

## 7. Compilation Model

### 7.1 Compiler Pipeline

Recommended pipeline:

```text
source
-> AST
-> semantic model
-> effect-checked model
-> Spora IR
-> ckbvm-compatible target artifacts
```

Compiler stages:
1. Parse modules and declarations.
2. Resolve names and types.
3. Perform ownership/linearity checking.
4. Validate lifecycle rules and transitions.
5. Validate and complete touch declarations.
6. Lower into Spora IR.
7. Emit target artifacts.

### 7.2 What Spora IR Should Look Like

Spora IR should be effect-first, not bytecode-first.

Suggested node shape:

```text
ActionIR {
  action_id,
  params,
  consume_set: [ObjectUse],
  read_refs: [ObjectRead],
  write_intents: [SharedWrite],
  create_set: [ObjectCreate],
  constraints: [Constraint],
  lifecycle_checks: [LifecycleCheck],
  conservation_checks: [ConservationCheck],
  effect_class: enum,
  scheduler_hints: SchedulerHints,
  verifier_plan: VerifierPlan
}
```

Suggested supporting records:

```text
ObjectUse {
  object_id,
  mode: enum { Consume, BorrowRead, BorrowWrite },
  expected_kind,
  expected_policy_hash
}

SharedWrite {
  object_id,
  expected_version,
  write_domain,
  effect_class
}

ObjectCreate {
  kind_id,
  owner_mode,
  initial_lifecycle,
  payload_schema,
  policy_hash
}
```

### 7.3 Lowering Targets

Hypha should lower into:

#### `consume set`

Owned resources / receipts / obsolete shared versions to spend.

#### `read refs`

Immutable dependencies:
- config objects
- price refs
- templates
- proofs
- supporting objects

#### `write intents`

Shared object mutation declarations:
- target `object_id`
- expected version
- write domain
- effect class

#### `create set`

New CellStateTree objects:
- assets
- receipts
- updated shared objects
- wrapped forms
- settlement outputs

#### `effect class`

Compiler-known action class:
- `transfer`
- `mint`
- `burn`
- `wrap`
- `unwrap`
- `claim`
- `settle`

Compiler-visible protocol patterns:
- launch builders
- pool/AMM flows
- `seed_pool`
- `swap`

#### `lifecycle rules`

Source and destination lifecycle checks for:
- launches
- claims
- settlement transitions
- pool state transitions

#### `scheduler hints`

Hints should include:
- estimated cycles
- shared-write domains
- object-kind domains
- deterministic conflict keys
- expected output count / object count

### 7.4 Final Backend Artifacts

Output artifacts should include:
- canonical object schema descriptors
- effect manifest schema
- generated verifier code
- cell layout spec
- transaction-building metadata
- witness manifest format

### 7.5 How This Differs from Other Compilation Models

Versus Move bytecode:
- Move compiles primarily to executable bytecode over abstract storage.
- Hypha compiles primarily to effect manifests plus verifier plans.

Versus Sway/Fuel:
- Sway is still centered around code execution against a VM runtime.
- Hypha is centered around explicit transition summaries over lineage objects.

Versus Solidity:
- Solidity compiles opaque code that mutates storage.
- Hypha compiles transparent state-transition summaries and generated verifiers.

## 8. Runtime / Execution Model

### 8.1 New VM or `ckbvm`

Recommendation:
- do not build a new VM first
- stay on top of `ckbvm` for now

Short term runtime:
- object header decoding
- effect manifest decoding
- lifecycle and version checks
- generated verifier logic
- conservation checks
- shared-write conflict validation

### 8.2 On-Chain vs Off-Chain Runtime

#### On-chain runtime responsibilities

- manifest verification
- object decoding
- lifecycle validation
- conservation validation
- policy/verifier execution
- shared write validation

#### Off-chain runtime responsibilities

- transaction construction
- object discovery
- read-set filling
- local simulation
- quote generation
- scheduling pre-classification

Keep the on-chain runtime small. Push orchestration outward.

### 8.3 Scheduler-Aware Execution

The transaction envelope should expose:
- `consume_set`
- `read_refs`
- `write_intents`
- `create_set`
- `effect_class`
- scheduler hints

The scheduler then constructs conflict structure before VM execution where possible.

VM execution confirms semantic validity. The scheduler does not need to reverse-engineer the touch surface from opaque code.

### 8.4 Atomic Units vs System-Level Parallelism

Recommended rule:
- a single `action` execution unit is atomic
- parallelism happens across actions/transactions with non-conflicting declared effects

That preserves simple reasoning while still exploiting Spora’s DAG-friendly execution model.

### 8.5 Shared-State Contention

Use optimistic versioned writes.

Each shared write names:
- `object_id`
- `expected_version`
- `effect_class`

Implications:
- conflicting writes may coexist in mempool
- only one lineage continuation can commit against a given shared version
- read-only shared access remains parallel

## 9. Standard Operations And Protocol Patterns

Most primitives should be **stdlib APIs with compiler-known lowering tags**, not special syntax. Syntax must stay small.

### 9.1 `launch`

Guarantee:
- asset genesis plus initial lifecycle and optional initial receipts/pool created atomically

Why standard:
- launches are common and structurally important

Placement:
- post-v1 transaction builder + stdlib template

### 9.2 `mint`

Guarantee:
- controlled supply expansion under declared policy

Why standard:
- supply conservation requires uniform checking

Placement:
- stdlib + compiler-known conservation rule

### 9.3 `burn`

Guarantee:
- provable supply reduction

Why standard:
- same conservation reasons as mint

Placement:
- stdlib + compiler-known conservation rule

### 9.4 `transfer`

Guarantee:
- ownership move without hidden state mutation

Why standard:
- most common resource operation

Placement:
- syntax sugar or stdlib intrinsic over `consume` + `create` with preserved fields and a new lock

### 9.5 `seed_pool`

Guarantee:
- initial pool creation with invariant initialization

Why standard:
- pools need canonical shape and initialization semantics

Placement:
- stdlib/protocol pattern with compiler-visible metadata

### 9.6 `swap`

Guarantee:
- invariant-preserving exchange against shared pool state

Why standard:
- scheduler/runtime should recognize this shared-write pattern

Placement:
- stdlib/protocol pattern over shared state with compiler-visible metadata

### 9.7 `wrap`

Guarantee:
- lock external or base asset into wrapped representation

Why standard:
- common wrapper pattern

Placement:
- stdlib

### 9.8 `unwrap`

Guarantee:
- destroy wrapped representation and release backing

Why standard:
- pairs with wrapping

Placement:
- stdlib

### 9.9 `claim`

Guarantee:
- consume a receipt and materialize entitled resource(s)

Why standard:
- receipt-driven flows are native to Spora

Placement:
- obligation-classifying intrinsic or stdlib helper with lifecycle metadata

### 9.10 `settle`

Guarantee:
- finalize queued or computed deltas into CellStateTree state

Why standard:
- critical for high-throughput shared flows

Placement:
- compiler-known effect class + stdlib

## 10. Comparison Matrix

| Dimension | Solidity | Move | Sway | Hypha |
|---|---|---|---|---|
| general expressiveness | High | Medium-high | Medium-high | Intentionally medium-low |
| asset expressiveness | Indirect | Strong | Medium | Very strong |
| scheduler-friendliness | Poor | Medium | Good | Excellent |
| shared-state control | Weak by default | Better | Better | Explicit and versioned |
| developer ergonomics | Familiar but misleading for Spora | Good but foreign to Cells | Clean but VM-centric | Best fit if scoped well |
| cold-start friendliness | High mindshare, wrong model | Moderate | Moderate | Good for Spora-native builders |
| fit for Spora architecture | Poor | Partial | Partial | Strong |

## 11. Practical Build Strategy

### 11.1 Phase 1

Build first:
- canonical object header and payload schema
- Hypha parser
- type checker
- linearity checker
- `touches` checker
- effect manifest generation
- codegen targeting current `ckbvm`

### 11.2 Phase 2

Then build:
- standard library for `asset`, `receipt`, `claim`, `settle`, and shared-state protocol patterns
- compiler-known conservation checks
- compiler-known lifecycle checks
- post-v1 transaction-builder support for launch flows
- wallet/indexer support for typed object discovery and decoding

### 11.3 Phase 3

Then integrate deeply:
- effect manifests into mempool/scheduler
- shared-object version gating
- contention-aware scoring
- reference sequential runner vs parallel runner equivalence tests

### 11.4 What Should Stay on `ckbvm`

- script execution
- witness verification
- existing syscall/data-loading path
- code cell / dep-group packaging model

### 11.5 What Must Be Custom

- object header schema
- effect manifest format
- Hypha compiler
- standard primitive semantics
- shared-object version rules
- lifecycle/state-transition checker
- envelope-aware scheduler integration

### 11.6 What Should Be Deferred

- new VM
- dynamic dispatch systems
- heavy generics/traits
- actor-like async models
- unrestricted cross-action callback models

### 11.7 Highest-Risk Engineering Areas

- shared-object version rules under DAG merges
- envelope honesty: declared touch-set versus actual verifier behavior
- canonical object identity and lineage semantics
- keeping generated `ckbvm` verifiers compact enough
- deterministic `settle` semantics across effect merging

## 12. Example Programs

### 12.1 Meme Asset Launch with First-Pool Seeding

```hypha
module meme.launch;

asset Meme {
    symbol: [u8; 8],
    decimals: u8,
    total_supply: u128,
}

shared object MemeQuotePool {
    meme_reserve: u128,
    quote_reserve: u128,
    lp_supply: u128,
    fee_bps: u16,
    state: PoolState,
}

enum PoolState { Seeded, Live }

action launch_and_seed(
    admin: signer,
    quote_seed: QuoteCoin,
    cfg: LaunchCfg
) -> (Meme, shared MemeQuotePool)
touches {
    consume quote_seed,
    read cfg.template,
    create Meme,
    create shared MemeQuotePool,
    effect launch,
}
requires {
    cfg.supply > 0,
    cfg.quote_seed > 0,
}
ensures {
    Meme.total_supply == cfg.supply,
    MemeQuotePool.meme_reserve == cfg.pool_meme,
    MemeQuotePool.quote_reserve == cfg.quote_seed,
}
```

### 12.2 Vesting Receipt / Claim Flow

```hypha
module meme.vesting;

asset Meme {
    symbol: [u8; 8],
    decimals: u8,
    total_supply: u128,
}

receipt Vesting {
    beneficiary: address,
    remaining: u128,
    step_amount: u128,
    next_daa: u64,
    end_daa: u64,
}

action issue_vesting(admin: signer, grant: MemeCoin, plan: VestPlan) -> receipt Vesting
touches {
    consume grant,
    create receipt Vesting,
    effect mint,
}

action claim(beneficiary: signer, vest: Vesting, now_daa: u64) -> (MemeCoin, receipt VestingRemainder)
touches {
    consume vest,
    read now_daa,
    create MemeCoin,
    create receipt VestingRemainder,
    effect claim,
}
requires {
    beneficiary.addr == vest.beneficiary,
    now_daa >= vest.next_daa,
}
```

### 12.3 Shared-State Settlement Flow

```hypha
module dex.settlement;

shared object BatchPool {
    reserve_a: u128,
    reserve_b: u128,
    pending_a_in: u128,
    pending_b_in: u128,
    pending_a_out: u128,
    pending_b_out: u128,
    version: u64,
}

receipt SwapFill {
    trader: address,
    a_out: u128,
    b_out: u128,
}

action queue_swap(
    trader: signer,
    pool: &shared BatchPool,
    in_coin: TokenACoin,
    min_out: u128
) -> receipt SwapFill
touches {
    consume in_coin,
    read pool,
    create receipt SwapFill,
    effect swap,
}

action settle_batch(
    sequencer: signer,
    pool: &mut shared BatchPool,
    fills: [SwapFill; 64]
) -> [SettlementCoin; 64]
touches {
    write pool@version,
    consume fills,
    create SettlementCoin,
    effect settle,
}
requires {
    fills.len > 0,
}
```

## 13. Final Recommendation

Build **Hypha** as a **narrow transition DSL**, not a general-purpose contract language.

The core bet should be:
- typed objects over raw cells
- effect manifests over opaque code
- lifecycle transitions over generic method calls
- shared-write discipline over hidden storage mutation
- `ckbvm` compatibility now, native Spora runtime semantics later

### 13.1 Do Not Do These Things

- Do not start by inventing a new VM.
- Do not port Solidity semantics into a Cell wrapper.
- Do not copy Move’s ability system wholesale.
- Do not let developers bypass effect declarations for shared objects.
- Do not make receipts and settlement “just libraries” if the scheduler/runtime benefit from knowing them.
- Do keep pools as shared-state protocol patterns with structured metadata rather than a language keyword; AMM invariant families belong to libraries, generated verifiers, or transaction-builder policy.

### 13.2 Encoding Split: Envelope vs Object Model vs Compiler vs Runtime

#### Transaction envelope

Should encode:
- consume set
- read refs
- shared write intents
- effect class
- expected shared versions
- witness/auth bundle
- scheduler hints

#### Object model

Should encode:
- canonical object header
- lifecycle state
- identity/version fields
- payload schema

#### Compiler

Should encode and enforce:
- type checking
- linearity
- lifecycle legality
- effect manifest generation
- lowering to cells/scripts/witness formats

#### Runtime

Should enforce:
- manifest verification
- version checks
- conservation checks
- generated verifier execution
- commitment of lineage transitions

### 13.3 Opinionated Recommendation

If Spora wants a native contract language that can actually become protocol-default, the right path is not “Spora Solidity” and not “Move on Cells.” The right path is a language built around:
- lineage
- resource flow
- shared object discipline
- effect manifests
- settlement-aware transitions

That is why **Hypha** is likely to be strong enough to become the native contract language of Spora:
- it matches the architecture Spora already has
- it exposes exactly the surfaces Spora’s scheduler needs
- it gives developers far better ergonomics than raw Cell scripting
- it avoids dragging account/storage assumptions into a system built around discrete lineage objects

In one sentence:

**Hypha should become for Spora what raw Cell scripts are today, except typed, lifecycle-aware, scheduler-visible, and built for receipt/settlement flows plus explicit shared-state protocol patterns instead of forcing every protocol to re-invent them in byte payloads.**
