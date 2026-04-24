# CellScript: A Domain-Specific Language for the Spora Blockchain

**Status**: Draft RFC  
**Date**: 2026-04-13  
**Authors**: Spora Core Team  
**Category**: Language Design / Protocol Engineering  
**Requires**: ckbvm (RISC-V), CellTx envelope, GhostDAG consensus  

---

## 1. Executive Summary

### 1.1 What This Document Proposes

This document proposes **CellScript**, a narrow, asset-lifecycle-oriented domain-specific language for the Spora blockchain. CellScript compiles to RISC-V ELF binaries that run on the existing ckbvm infrastructure. It does not introduce a new virtual machine. It does not replace the CellTx envelope. It layers a type-safe, linearity-enforced programming model on top of the existing execution stack.

### 1.2 Why This DSL Should Exist

Spora's Cell model is powerful but low-level. Today, writing a Spora script means:

1. Hand-encoding witness data in raw bytes
2. Manually managing Cell lifecycle (creation, consumption, data layout)
3. Writing RISC-V C or assembly that calls syscalls by number (2061, 2071, 2075, etc.)
4. Having no compiler-enforced guarantees about linear resource usage
5. Having no way to express scheduler hints for DAG-parallel execution

This is roughly equivalent to writing Ethereum contracts in EVM bytecode. It works, but it does not scale to an ecosystem of contract authors.

CellScript exists to close this gap: give protocol designers a language that understands Cells, understands linearity, understands DAG scheduling, and compiles down to the same RISC-V ELF binaries that ckbvm already executes.

### 1.3 Why Not Solidity / Move / Sway Directly

**Solidity** assumes an account-based storage model. Every `SSTORE`/`SLOAD` targets a 256-bit slot in a contract's durable storage. Spora has no such model. Cells are discrete objects with OutPoint identity, consumed and created atomically. Adapting Solidity to Cell semantics would require gutting its storage model, at which point you no longer have Solidity.

**Move** is closer. It has resource types with linear semantics. But Move's module system assumes a global module store with named addresses, and its bytecode is stack-based with no concept of CellDep, OutPoint, or DAG scheduling. Move on Sui adds shared objects, but Sui's execution model (Narwhal/Bullshark) differs fundamentally from GhostDAG mergeset processing. Porting Move would mean forking the language and diverging permanently.

**Sway** (Fuel) is UTXO-aware and Rust-like, but it targets FuelVM predicates, not RISC-V ELF. Fuel's UTXO model is simpler than Cell (no type scripts, no CellDep, no since-based time locks). Sway has no concept of shared state objects or DAG-parallel scheduling hints.

**Conclusion**: None of these languages were designed for {Cell model + GhostDAG + ckbvm + 3-dimensional mass}. Building on top of any of them would require more adaptation work than building a focused DSL from scratch. CellScript is intentionally narrow — it does fewer things, but those things map perfectly to Spora.

### 1.4 Proposed Name

**CellScript**. The name is direct, descriptive, and positions the language relative to its primary abstraction: the Cell. Alternative names considered and rejected:

- *SporaLang*: Too generic, says nothing about what the language does
- *CellLisp*: Wrong paradigm association
- *SporeScript*: Cute but not professional

CellScript. Source files use the `.cell` extension.

---

## 2. Architectural Fit

### 2.1 How CellScript Fits Spora's Cell/State Ontology

Spora's state model is organized around discrete Cell objects:

```
CellTx {
    ver: u16 (0xC001),
    inputs: Vec<CellInput>,          // Cells to consume
    deps: Vec<CellDep>,            // Read-only Cell references
    header_deps: Vec<[u8;32]>,     // Block header references
    outputs: Vec<CellOutput>,         // New Cells to create
    outputs_data: Vec<Vec<u8>>,    // Data attached to outputs
    witnesses: Vec<Vec<u8>>,       // Signatures, proofs
}
```

CellScript's type system maps directly onto this structure:

| CellScript Concept | CellTx Mapping |
|---|---|
| `resource` declaration | `CellOutput` + `outputs_data[i]` |
| `consume expr` | Entry in `inputs` as `CellInput` |
| `create expr` | Entry in `outputs` + `outputs_data` |
| `read_ref expr` | Entry in `deps` as `CellDep` |
| `shared` declaration | Cell accessed via `CellDep` (read) or `CellInput` (write) |
| local `let` binding | Witness data or intermediate computation; never in CellStateTree |
| `action` function | Type script logic compiled to RISC-V ELF |
| `lock` function | Lock script logic compiled to RISC-V ELF |

This is not a metaphorical mapping. The compiler literally produces CellTx-shaped output. A `create` expression generates a `CellOutput` struct. A `consume` expression generates a `CellInput`. The programmer writes in CellScript; the compiler emits valid CellTx components and RISC-V ELF scripts.

### 2.2 How CellScript Fits DAG-Oriented Execution

In a single-chain blockchain, transactions execute sequentially within a block. In Spora's GhostDAG model:

- Multiple blocks can be mined concurrently
- A mergeset of blue blocks is processed in canonical order
- VirtualProcessor accumulates CellDiffs from each block
- Parallel execution is possible within a block (P1, completed) and potentially across blue blocks (MPE, in design)

CellScript supports this by:

1. **Effect classification**: Every `action` is tagged with an effect class (`Pure`, `ReadOnly`, `Mutating`, `Creating`, `Destroying`). The compiler infers this from the action body.

2. **Access summary emission**: The compiler emits a `BlockAccessSummary`-compatible metadata blob in a designated witness field, listing:
   - `spent_outpoints`: OutPoints consumed
   - `created_outpoints`: OutPoints created (predicted from deterministic OutPoint derivation)
   - `read_deps`: OutPoints read via `read_ref`
   - `touches_shared`: type_hashes of shared objects accessed

3. **Scheduler hint embedding**: The metadata includes `parallelizable: bool` and `estimated_cycles: u64`, enabling the block template builder and MPE execution DAG to make scheduling decisions without re-analyzing script code.

The important design choice is that this touch surface should be **inferred by default** from the action body:
- `consume` implies consumed inputs
- `create` implies created outputs
- `read_ref` implies dependency reads

Only the non-obvious part should need explicit annotation:
- shared-state write domains
- effect-class disambiguation
- rare cases where the compiler cannot infer an adequate scheduler surface on its own

This directly supports the MPE design document's Phase 2 (`BlockAccessSummary`) and Phase 3 (`block-level execution DAG`) without requiring changes to GhostDAG itself.

### 2.3 How CellScript Fits the MPE Parallelization Design

The MPE design document identifies the core requirement: blue block processing must be decomposed into **pure effect generation** followed by **sequential commit**. CellScript aligns with this by design:

```
                    CellScript Source
                          │
                          ▼
                  ┌───────────────┐
                  │   Compiler    │
                  └───────┬───────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
        RISC-V ELF   Typed Data   Scheduler
        (lock/type   Layouts      Metadata
         scripts)                 (witness)
              │           │           │
              └───────────┼───────────┘
                          ▼
              ┌───────────────────────┐
              │   ckbvm Execution     │
              │   (existing infra)    │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  BlockExecutionEffect │
              │  (pure, composable)   │
              └───────────────────────┘
```

Each CellScript action produces a deterministic effect. The scheduler metadata lets the execution layer identify independent actions that can run in parallel within the same block, and across blocks in a mergeset.

### 2.4 How CellScript Fits ckbvm Integration

CellScript does **not** introduce a new VM. It compiles to standard RISC-V ELF binaries that execute on ckbvm with the existing syscall interface:

| Syscall | Number | CellScript Usage |
|---|---|---|
| `LOAD_TX_HASH` | 2061 | Implicit in sighash computation |
| `LOAD_SCRIPT_HASH` | 2062 | Used by `self.script_hash()` |
| `LOAD_CELL` | 2071 | Used by `consume`, `create`, `read_ref` |
| `LOAD_HEADER` | 2072 | Used by `header_dep` access |
| `LOAD_INPUT` | 2073 | Used by `consume` internals |
| `LOAD_WITNESS` | 2074 | Used by witness data access |
| `LOAD_SCRIPT` | 2075 | Used by `self.script()` |
| `LOAD_CELL_BY_FIELD` | 2081 | Used by field-level Cell access |
| `LOAD_CELL_DATA` | 2092 | Used by `cell.data()` |
| `CURRENT_CYCLES` | 2042 | Used by `remaining_cycles()` |
| `DEBUG_PRINT` | 2177 | Used by `debug!()` macro |
| `BLAKE3` (Spora ext) | 3001 | Used by `hash()` builtin |

The compiler links a thin CellScript stdlib into each ELF binary. This stdlib provides:
- Molecule/schema encoding and decoding for typed Cell data
- Syscall wrappers with safe Rust-like APIs
- Linearity enforcement at runtime (debug mode) and compile time (always)
- Scheduler metadata serialization

The resulting ELF binary is indistinguishable from a hand-written ckbvm script. Existing raw scripts and CellScript-compiled scripts can coexist in the same transaction.

---

## 3. Language Philosophy

### 3.1 What CellScript IS FOR

CellScript is a language for expressing **asset lifecycle and state transition logic** on Spora. Specifically:

- **Asset definition**: Declaring fungible and non-fungible asset types with enforced supply rules
- **State transitions**: Defining valid state changes for Cells (creation, mutation, destruction)
- **Pool mechanics**: Expressing liquidity pool invariants (constant product, weighted reserves)
- **Settlement logic**: Defining how pending states (receipts, vesting schedules) resolve to final states
- **Authorization**: Expressing lock conditions (signature verification, multi-sig, time locks)
- **Lifecycle management**: Encoding state machine transitions (Created → Active → Settled → Destroyed)

### 3.2 What CellScript is NOT FOR

CellScript intentionally does not target:

- **General computation**: No loops over unbounded data. No arbitrary string processing. No floating point. If you need to run a neural network, CellScript is the wrong tool.
- **Off-chain logic**: CellScript has no networking, no file I/O, no randomness. It executes deterministically inside ckbvm.
- **UI/Frontend**: CellScript does not generate client-side code. SDKs in Rust/TypeScript/Go interact with CellScript-compiled scripts through RPC plus transaction-construction/planning APIs.
- **Cross-chain messaging**: CellScript validates state transitions within Spora. Bridge logic requires off-chain relayers that construct CellScript-compatible transactions.

### 3.3 Protocol-Designer Freedom vs Application-Level Freedom

CellScript occupies a middle ground:

- **More constrained than Solidity**: You cannot write arbitrary programs. The type system enforces linearity. The compiler rejects code that copies resources or drops them without explicit destruction.
- **More expressive than Bitcoin Script**: You have structured types, control flow, concrete helper functions, and protocol-visible Cell operations. You can express complex AMM invariants, vesting schedules, and multi-party settlement protocols.
- **Similar level to Move**: Resource-oriented, with explicit lifecycle management. But narrower — no general-purpose module system, no dynamic dispatch, no unbounded collections.

The target user is a **protocol designer** who thinks in terms of "I have an asset with these rules, a pool with these invariants, and a settlement process with these steps." CellScript makes these thoughts directly expressible and compiler-verifiable.

### 3.4 What Expressiveness Is Intentionally Sacrificed

| Feature | Solidity Has It | CellScript Omits It | Why |
|---|---|---|---|
| Unbounded loops | Yes (`for`, `while`) | No (bounded iteration only) | Cycle budget is hard: 10M max per tx. Unbounded loops are a DoS vector. |
| Dynamic dispatch | Yes (interfaces) | No | Type scripts are statically resolved by code_hash. Dynamic dispatch adds indirection without benefit in Cell model. |
| Inheritance | Yes | No | Composition over inheritance. CellScript uses trait-like capabilities instead. |
| Reentrancy | Yes (and regrets it) | Impossible by construction | Cell model consumes inputs atomically. No callback pattern exists. |
| Arbitrary storage | Yes (mapping/array) | No (Cell data is fixed-layout) | Cells have typed, fixed-size data. "Growing" storage means creating new Cells. |
| String manipulation | Yes | No | Scripts validate state transitions, not process text. |

---

## 4. Core Semantic Model

### 4.1 `resource` — Linear Cell Type

**What it means**: A `resource` is a linear type representing a Cell. It cannot be copied. It cannot be silently dropped. Every resource instance must be explicitly consumed (spent), transferred (moved to a new owner), or destroyed (burned). This is enforced at compile time.

**Why it exists**: The Cell model's fundamental property is that Cells are consumed and created atomically. A Cell cannot exist in two places. It cannot be spent twice. CellScript's `resource` type makes this property a compile-time guarantee rather than a runtime invariant that programmers must manually maintain.

**What problems it solves**:
- Prevents double-spend bugs at the language level
- Prevents "lost Cells" (resources created but never used)
- Makes asset supply invariants checkable by the compiler

**Commit details**:

```
resource FungibleToken {
    amount: u64,
    symbol: [u8; 8],
}
```

Maps to:
- `CellOutput.type_` = Script pointing to the FungibleToken type script
- `outputs_data[i]` = Molecule/schema encoded `{ amount: u64, symbol: [u8; 8] }`
- `CellOutput.capacity` = minimum required capacity for this data layout
- `CellOutput.lock` = owner's lock script (set by `transfer` target)

**How it differs from Solidity/Move/Sway**:
- **Solidity**: Has no linear types. ERC-20 balances are `mapping(address => uint256)` — a mutable storage slot, not a discrete object. Nothing prevents the mapping from being read/written arbitrarily.
- **Move**: Has resources with `key`, `store`, `copy`, `drop` abilities. CellScript's model is simpler: resources have capabilities (`store`, `transfer`, `destroy`) but no `copy` or `drop`. Move resources live in a global store addressed by `(address, module, type)`; CellScript resources live as Cells addressed by `OutPoint`.
- **Sway**: Has native assets at the protocol level but no user-defined linear types. Sway predicates validate UTXO spending conditions but don't define typed resource objects.

### 4.2 `shared` — Shared-State Cell

**What it means**: A `shared` object is a Cell that can be read by multiple transactions concurrently (via `CellDep`) but written exclusively (via `CellInput` consumption + re-creation). This models shared protocol state like liquidity pools, registries, or configuration Cells.

**Why it exists**: Many DeFi protocols require shared mutable state. In an account-based model, this is implicit (every contract has shared state). In a Cell model, shared state must be explicitly designed. The `shared` keyword marks a Cell as protocol-shared and triggers the compiler to:
1. Emit read-via-CellDep patterns for readers
2. Emit consume-and-recreate patterns for writers
3. Include `type_hash` in scheduler metadata for contention detection

**How it maps to Spora**:
- Reading: Transaction includes the shared Cell as a `CellDep` with `dep_type: Code`
- Writing: Transaction consumes the shared Cell as an input (`CellInput`) and creates a new Cell with updated data as an output (`CellOutput`)
- Identification: The shared Cell is identified by its `type_hash` (blake3 hash of Script)
- Contention: Multiple transactions writing to the same shared Cell conflict — only one can succeed per block, resolved by canonical ordering

**How it differs**:
- **Solidity**: All contract state is implicitly shared. No opt-in, no contention awareness.
- **Move (Sui)**: Has explicit `shared` objects with consensus-ordered access. Similar concept, but Sui uses a different consensus mechanism (not GhostDAG).
- **Sway**: No shared state concept. UTXOs are either spent or not.

### 4.3 `receipt` — Single-Use Proof-of-Action

**What it means**: A `receipt` is a single-use proof that some action occurred. It is a Cell with a special type script that enforces: (1) it can only be created by a specific action, and (2) it must be consumed exactly once. Receipts are the Cell model's equivalent of "events" in account-based systems, but with a crucial difference: they are stateful objects that must be explicitly claimed.

**Why it exists**: Many protocols need to prove that something happened (deposit made, vesting period started, vote cast) and then act on that proof later. In account-based systems, this is done via event logs or storage flags. In the Cell model, receipts are first-class objects with lifecycle guarantees.

**How it maps to Spora**:
- A receipt is a `CellOutput` with a type script that encodes:
  - Creator: the action that produced this receipt
  - Claim conditions: time lock, signature requirement, or other predicate
  - Payload: whatever data the receipt proves (amount deposited, vesting schedule, etc.)
- The type script enforces that the receipt Cell can only be consumed by a valid claim action
- Once consumed, the receipt is gone — it cannot be replayed

### 4.4 `launch` — Post-v1 Transaction-Builder Pattern

**What it means**: A `launch` is a post-v1 transaction-builder pattern that bundles the creation of a new asset type with its initial configuration. It combines:
1. Creating the asset's type script Cell (deploying the contract)
2. Minting initial supply
3. Optionally seeding a liquidity pool
4. Distributing initial tokens to specified addresses

**Why it exists**: In practice, launching a new token on any chain involves multiple coordinated outputs. A future CellScript transaction builder can make this a single atomic CellTx, reducing the surface for partial-deployment bugs.

**How it maps to Spora**: A future `launch` lowering would compile to a single CellTx with:
- Output 0: Type script Cell (the asset's code, deployed as a Cell with data = ELF binary)
- Output 1..N: Initial token Cells (minted supply distributed to recipients)
- Output N+1: Optional pool Cell (seeded with initial liquidity)
- Output N+2: Optional LP receipt Cells (proof of initial liquidity provision)

Current status: `launch` is not part of the v1 language core. Until transaction-builder lowering exists, examples should model launches explicitly with `create` operations and ordinary actions.

### 4.5 Pool Pattern — Shared Liquidity Object

**What it means**: A pool is a protocol pattern built from a `shared` Cell, action logic, invariants, and receipt/resource outputs. It is not a separate language keyword or declaration class.

**Why it exists**: AMM pools are the most common shared-state pattern in DeFi. They deserve standard metadata and tooling support, but their invariant family is protocol-specific rather than language-core semantics:
- Scheduler metadata can still include the underlying shared Cell's type_hash for contention detection
- Audit metadata can expose pool-specific runtime obligations
- Standard libraries can provide AMM templates without hard-coding AMM math into the language

**How it maps to Spora**: A pool is a shared Cell where:
- `CellOutput.type_` = pool type script (enforces AMM invariant)
- `outputs_data[i]` = Molecule/schema encoded pool state: `{ reserve_a: u64, reserve_b: u64, total_lp: u64, fee_rate: u16 }`
- Swap transactions consume the pool Cell and create a new pool Cell with updated reserves
- LP add/remove transactions modify reserves and create/consume LP receipt Cells

### 4.6 `settle` — Finalization Action

**What it means**: A `settle` action converts pending states to final states. It consumes receipt Cells, evaluates their claim conditions, and produces final asset Cells. Settlement is the "closing bracket" of a protocol interaction.

**How it maps to Spora**: A settle action compiles to a CellTx that:
- Consumes one or more receipt/pending Cells (inputs)
- Verifies claim conditions (time locks, signatures, invariants)
- Produces final asset Cells (outputs)
- Transitions lifecycle state from `Pending` to `Settled`

### 4.7 Transaction-Local Values and CellStateTree Commit

**What it means**: Ordinary local bindings exist only during a transaction's execution. They are not committed to CellStateTree. Intermediate computation, witness parsing, and temporary state use normal `let` bindings.

**How it maps to Spora**:
- Witness data (`CellTx.witnesses`) is transaction-local by nature
- Intermediate computation results live in ckbvm memory
- Only `create` produces Cell outputs that enter CellStateTree
- Linear resource checks ensure cell-backed values are consumed, returned, or explicitly materialized

**CellStateTree commit**: When a `resource`, `shared`, or `receipt` object is created via `create`, it becomes a Cell in the CellStateTree, tracked by MuHash for O(1) incremental root computation. No separate keyword is required for this behavior.

**How it maps to Spora**:
- CellStateTree stores `CellEntry { capacity, data_bytes, lock_hash, type_hash, data_hash, block_daa_score, is_cellbase }`
- MuHash accumulator provides the `cell_root` used in block commitment: `cell_commitment = H("spora/cell_commitment/v0" || cell_root)`
- CellDiff tracks additions and removals per block

---

## 5. Type System Proposal

### 5.1 Minimum Useful Type System

CellScript's type system is intentionally minimal. It includes:

**Primitive types**:
- `u8`, `u16`, `u32`, `u64`, `u128`: Unsigned integers
- `bool`: Boolean
- `[u8; N]`: Fixed-size byte arrays (N ≤ 256)
- `Hash`: Alias for `[u8; 32]`
- `Address`: Lock script reference (encoded as Script)

**Compound types**:
- `resource T { ... }`: Linear type (no copy, no implicit drop)
- `shared T { ... }`: Shared-state type (linear, with contention semantics)
- `receipt T { ... }`: Single-use proof type (linear, with claim semantics)
- `struct T { ... }`: Non-linear data type (can be copied, embedded in resources)

**Collection types**:
- `[T; N]`: Fixed-size array (N must be a compile-time constant)
- No `Vec`, no `HashMap`. Variable-size collections do not exist in CellScript. If you need variable-size data, you create multiple Cells.

### 5.2 Ownership and Linearity

Resources are **linear**: they must be used exactly once. The compiler tracks resource ownership through the program and rejects code that:

1. **Copies a resource**: `let b = a;` where `a: resource T` moves ownership. `a` is no longer usable.
2. **Drops a resource**: Letting a resource go out of scope without consuming, transferring, or destroying it is a compile error.
3. **Aliases a resource**: `&resource T` references are read-only borrows with restricted lifetime. You cannot extract a resource through a borrow.

```
resource Token { amount: u64 }

action bad_example(t: Token) {
    // ERROR: Token `t` is never consumed, transferred, or destroyed.
    // This is a compile error, not a warning.
}

action good_example(t: Token) {
    destroy t;  // Explicit destruction — compiler is satisfied
}
```

### 5.3 Capability Model

CellScript uses three capabilities instead of Move's four abilities:

| Capability | Meaning | Default |
|---|---|---|
| `store` | Can be persisted as a Cell in CellStateTree | Yes for `resource`, `shared` |
| `transfer` | Can change owner (lock script) | Yes for `resource` |
| `destroy` | Can be explicitly burned | Must be declared |

Capabilities are declared on the resource type:

```
resource Token has store, transfer, destroy {
    amount: u64,
}

resource SoulBound has store {
    // No transfer, no destroy — permanently bound to creator
    identity: Hash,
}
```

Why not Move's abilities (`key`, `store`, `copy`, `drop`)?
- `copy` does not exist. Resources are never copyable. Period.
- `drop` does not exist as an implicit ability. Destruction must be explicit via `destroy` capability.
- `key` is replaced by `store`. All stored resources are indexed by OutPoint, not by a separate key.

### 5.4 Post-v1 Templates, Not Core Generics

CellScript v1 does not support user-defined generic type parameters in executable source. This is an intentional boundary: CellScript is a Cell lifecycle language, and every persisted schema that reaches the verifier should be concrete, auditable, and metadata-addressable.

The following is not v1 executable syntax:

```
resource Vault<T: store> {
    content: T,
    unlock_at_daa: u64,
}
```

Parametric authoring belongs in a post-v1 package/codegen/template layer. A template may generate specialized `.cell` modules such as `TokenVault` or `NftVault`, but the generated CellScript must contain concrete field types, concrete lifecycle rules, and stable schema metadata such as `#[type_id("...")]`.

Implementation note: generic-looking user type definitions and user-defined instantiations such as `Vault<Token>` are rejected by the parser/type checker. `Vec<T>` remains a controlled builtin collection notation for local bounded collection APIs and compiler/runtime metadata; it is not a general user-defined generic type system.

### 5.5 Object Identity

Every CellStateTree object has an identity: its `OutPoint` (`tx_hash || index`). When a resource is consumed and re-created (e.g., updating shared state), the OutPoint changes. CellScript provides a `type_id` pattern for stable identity:

```
// stable type identity for tooling/schema metadata
#[type_id("spora::registry::Registry:v1")]
shared Registry has store {
    entries: [RegistryEntry; 64],
}
```

Current implementation note: `#[type_id("...")]` is an item-level attribute for `resource` / `shared` / `receipt` / `struct`. The compiler parses it, rejects duplicate values in the same module, preserves it in IR, and emits `types[].type_id` plus `types[].type_id_hash_blake3` in metadata schema v26. Under the `ckb` profile, persistent Cell types also emit `types[].ckb_type_id` with the CKB built-in TYPE_ID script contract. Direct `create` outputs of those types also emit `create_set[].ckb_type_id` output plans with concrete Output indexes. Wallet builders can explicitly install TYPE_ID scripts by final output index, native/WASM generator settings can consume CellScript action metadata profile-aware so Spora metadata attaches the Molecule scheduler witness while CKB metadata installs TYPE_ID scripts, and native/WASM generator settings can carry explicit CKB deps/header deps. Higher-level CellScript transaction builders still need to pass metadata/action/deps automatically.

### 5.6 Shared Object Representation

Shared objects are indexed by `type_hash`:

```
                ┌─────────────────┐
                │  ScriptIndex    │
                │  (RocksDB)      │
                ├─────────────────┤
                │ type_hash →     │
                │   Vec<OutPoint> │
                └────────┬────────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
    ┌───────────────┐        ┌───────────────┐
    │ CellDep read  │        │ CellInput write │
    │ (concurrent)  │        │ (exclusive)   │
    └───────────────┘        └───────────────┘
```

Readers include the shared Cell as a `CellDep`. Writers consume it and recreate it. The scheduler metadata includes `touches_shared: Vec<type_hash>` to enable conflict detection.

### 5.7 Lifecycle Representation

Resources can have lifecycle states, encoded as a state machine:

```
#[lifecycle(Created -> Active -> Settled -> Destroyed)]
resource VestingGrant {
    state: LifecycleState,
    beneficiary: Address,
    amount: u64,
    cliff_daa: u64,
    end_daa: u64,
}
```

The lifecycle attribute generates type script logic that:
1. Validates state transitions (only forward transitions allowed)
2. Enforces transition conditions (e.g., `Active -> Settled` requires `current_daa >= end_daa`)
3. Prevents invalid states (cannot go from `Settled` back to `Active`)

The `state` field is stored in the Cell data. The type script reads the input Cell's state, reads the output Cell's state, and verifies the transition is valid.

---

## 6. Syntax Proposal

### 6.1 Design Principles

CellScript syntax follows these rules:
- **Rust-like expression syntax**: `let`, `if`, `match`, block expressions
- **Move-like resource semantics**: `move`, explicit consume/create
- **Original keywords** for Cell-specific concepts: `resource`, `shared`, `action`, `consume`, `create`, `read_ref`
- **No semicolons at statement ends** (like Kotlin/Swift) — reduced noise
- **Explicit over implicit**: Every Cell lifecycle operation is visible in source code

### 6.2 Example: Fungible Asset

```cellscript
// fungible_token.cell — A minimal fungible token with mint, transfer, burn

module spora::fungible_token

/// A fungible token resource. Linear: must be consumed or transferred.
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

/// Authority cell — whoever holds this can mint new tokens.
resource MintAuthority has store {
    token_symbol: [u8; 8]
    max_supply: u64
    minted: u64
}

/// Mint new tokens. Only the MintAuthority holder can call this.
action mint(auth: &mut MintAuthority, to: Address, amount: u64) -> Token {
    assert_invariant(auth.minted + amount <= auth.max_supply,
        "exceeds max supply")

    auth.minted = auth.minted + amount

    create Token {
        amount: amount,
        symbol: auth.token_symbol
    } with_lock(to)
}

/// Transfer tokens to a new owner. Consumes input, creates output.
action transfer_token(token: Token, to: Address) -> Token {
    consume token
    create Token {
        amount: token.amount,
        symbol: token.symbol
    } with_lock(to)
}

/// Split a token into two parts.
action split(token: Token, split_amount: u64, 
             owner_a: Address, owner_b: Address) -> (Token, Token) {
    assert_invariant(split_amount < token.amount, "split exceeds balance")
    consume token

    let a = create Token {
        amount: split_amount,
        symbol: token.symbol
    } with_lock(owner_a)

    let b = create Token {
        amount: token.amount - split_amount,
        symbol: token.symbol
    } with_lock(owner_b)

    (a, b)
}

/// Merge two tokens of the same type into one.
action merge(a: Token, b: Token, to: Address) -> Token {
    assert_invariant(a.symbol == b.symbol, "symbol mismatch")
    let total = a.amount + b.amount
    consume a
    consume b

    create Token {
        amount: total,
        symbol: a.symbol
    } with_lock(to)
}

/// Burn tokens. Requires the `destroy` capability.
action burn(token: Token) {
    assert_invariant(token.amount > 0, "cannot burn zero")
    destroy token
}
```

### 6.3 Example: Receipt Object

```cellscript
// vesting_receipt.cell — Proof of deposit with time-locked claim

module spora::vesting

use spora::fungible_token::Token

/// A vesting receipt. Proof that tokens were deposited for time-locked release.
receipt VestingReceipt has store {
    beneficiary: Address
    amount: u64
    token_symbol: [u8; 8]
    cliff_daa_score: u64    // Cannot claim before this DAA score
    vesting_end_daa: u64    // Fully vested after this DAA score
    deposited_at_daa: u64   // When the deposit was made
}

/// Create a vesting receipt by depositing tokens.
action deposit_for_vesting(
    token: Token,
    beneficiary: Address,
    cliff_daa: u64,
    vesting_end_daa: u64
) -> VestingReceipt {
    assert_invariant(cliff_daa < vesting_end_daa, "cliff must precede end")
    
    let current_daa = env::current_daa_score()
    
    // Lock the tokens (consumed, not yet claimable)
    consume token

    create VestingReceipt {
        beneficiary: beneficiary,
        amount: token.amount,
        token_symbol: token.symbol,
        cliff_daa_score: cliff_daa,
        vesting_end_daa: vesting_end_daa,
        deposited_at_daa: current_daa
    } with_lock(beneficiary)
}

/// Claim vested tokens. Consumes the receipt, creates tokens.
action claim(receipt: VestingReceipt) -> Token {
    let current_daa = env::current_daa_score()
    
    assert_invariant(current_daa >= receipt.cliff_daa_score,
        "cliff not reached")
    
    // Calculate vested amount (linear vesting)
    let vested = if current_daa >= receipt.vesting_end_daa {
        receipt.amount
    } else {
        let elapsed = current_daa - receipt.cliff_daa_score
        let total_period = receipt.vesting_end_daa - receipt.cliff_daa_score
        receipt.amount * elapsed / total_period
    }

    consume receipt

    create Token {
        amount: vested,
        symbol: receipt.token_symbol
    } with_lock(receipt.beneficiary)
}
```

### 6.4 Example: Shared Pool Object

```cellscript
// amm_pool.cell — Constant-product AMM pool

module spora::amm

use spora::fungible_token::Token

/// LP (Liquidity Provider) receipt — proof of liquidity provision.
receipt LPReceipt has store {
    pool_id: Hash
    lp_amount: u64
    provider: Address
}

/// AMM pool with constant-product invariant (x * y = k).
shared Pool has store {
    token_a_symbol: [u8; 8]
    token_b_symbol: [u8; 8]
    reserve_a: u64
    reserve_b: u64
    total_lp: u64
    fee_rate_bps: u16       // Fee in basis points (e.g., 30 = 0.3%)
}

/// Seed a new pool with initial liquidity.
action seed_pool(
    token_a: Token,
    token_b: Token,
    fee_rate_bps: u16,
    provider: Address
) -> (Pool, LPReceipt) {
    assert_invariant(token_a.symbol != token_b.symbol, "same token")
    assert_invariant(token_a.amount > 0 && token_b.amount > 0, "zero liquidity")
    
    let initial_lp = math::isqrt(token_a.amount * token_b.amount)
    
    consume token_a
    consume token_b

    let pool = create Pool {
        token_a_symbol: token_a.symbol,
        token_b_symbol: token_b.symbol,
        reserve_a: token_a.amount,
        reserve_b: token_b.amount,
        total_lp: initial_lp,
        fee_rate_bps: fee_rate_bps
    }

    let receipt = create LPReceipt {
        pool_id: pool.type_hash(),
        lp_amount: initial_lp,
        provider: provider
    } with_lock(provider)

    (pool, receipt)
}

/// Swap token A for token B through the pool.
action swap_a_for_b(pool: &mut Pool, input: Token, min_output: u64, 
                     to: Address) -> Token {
    assert_invariant(input.symbol == pool.token_a_symbol, "wrong input token")
    
    let fee = input.amount * pool.fee_rate_bps as u64 / 10000
    let net_input = input.amount - fee
    
    // Constant product: (reserve_a + net_input) * (reserve_b - output) = reserve_a * reserve_b
    let output = pool.reserve_b * net_input / (pool.reserve_a + net_input)
    
    assert_invariant(output >= min_output, "slippage exceeded")
    assert_invariant(output < pool.reserve_b, "insufficient reserves")
    
    consume input
    
    pool.reserve_a = pool.reserve_a + input.amount
    pool.reserve_b = pool.reserve_b - output

    create Token {
        amount: output,
        symbol: pool.token_b_symbol
    } with_lock(to)
}

/// Add liquidity to the pool.
action add_liquidity(
    pool: &mut Pool,
    token_a: Token,
    token_b: Token,
    provider: Address
) -> LPReceipt {
    assert_invariant(token_a.symbol == pool.token_a_symbol, "wrong token a")
    assert_invariant(token_b.symbol == pool.token_b_symbol, "wrong token b")
    
    // Calculate LP tokens proportional to contribution
    let lp_from_a = token_a.amount * pool.total_lp / pool.reserve_a
    let lp_from_b = token_b.amount * pool.total_lp / pool.reserve_b
    let lp_amount = math::min(lp_from_a, lp_from_b)
    
    consume token_a
    consume token_b
    
    pool.reserve_a = pool.reserve_a + token_a.amount
    pool.reserve_b = pool.reserve_b + token_b.amount
    pool.total_lp = pool.total_lp + lp_amount

    create LPReceipt {
        pool_id: pool.type_hash(),
        lp_amount: lp_amount,
        provider: provider
    } with_lock(provider)
}
```

### 6.5 Example: Launch Action

```cellscript
// launch.cell — Atomic asset launch with pool seeding

module spora::launch

use spora::fungible_token::{Token, MintAuthority}
use spora::amm::{Pool, LPReceipt, seed_pool}

/// Launch a new token with initial distribution and pool seeding.
action launch_token(
    symbol: [u8; 8],
    max_supply: u64,
    initial_mint: u64,
    pool_seed_amount: u64,
    pool_paired_token: Token,
    fee_rate_bps: u16,
    creator: Address,
    distribution: [(Address, u64); 4]
) -> (MintAuthority, Pool, LPReceipt) {
    assert_invariant(initial_mint <= max_supply, "initial exceeds max")
    assert_invariant(pool_seed_amount <= initial_mint, "pool seed exceeds mint")
    
    // Calculate distribution total
    let dist_total = distribution[0].1 + distribution[1].1 
                   + distribution[2].1 + distribution[3].1
    assert_invariant(dist_total + pool_seed_amount <= initial_mint,
        "allocation exceeds mint")

    // Create mint authority
    let auth = create MintAuthority {
        token_symbol: symbol,
        max_supply: max_supply,
        minted: initial_mint
    } with_lock(creator)

    // Create distribution tokens
    for (addr, amount) in distribution {
        if amount > 0 {
            create Token {
                amount: amount,
                symbol: symbol
            } with_lock(addr)
        }
    }

    // Create pool seed token
    let pool_token = create Token {
        amount: pool_seed_amount,
        symbol: symbol
    } with_lock(creator)

    // Seed the pool atomically
    let (pool, lp_receipt) = seed_pool(
        pool_token,
        pool_paired_token,
        fee_rate_bps,
        creator
    )

    (auth, pool, lp_receipt)
}
```

### 6.6 Example: Settle Action

```cellscript
// settle.cell — Finalize vesting and claim receipts

module spora::settle

use spora::fungible_token::Token
use spora::vesting::VestingReceipt

/// Batch-settle multiple vesting receipts.
action batch_settle(
    receipts: [VestingReceipt; 4],
    beneficiary: Address
) -> Token {
    let current_daa = env::current_daa_score()
    
    let mut total_amount: u64 = 0

    for receipt in receipts {
        assert_invariant(current_daa >= receipt.vesting_end_daa,
            "not fully vested")
        assert_invariant(receipt.beneficiary == beneficiary,
            "wrong beneficiary")
        total_amount = total_amount + receipt.amount
        consume receipt
    }

    settle create Token {
        amount: total_amount,
        symbol: receipts[0].token_symbol
    } with_lock(beneficiary)
}
```

### 6.7 Example: Transaction-Local Intermediate

```cellscript
// swap_router.cell — Multi-hop swap with transaction-local intermediate state

module spora::router

use spora::fungible_token::Token
use spora::amm::Pool

/// Route a swap through two pools (A -> B -> C).
action multi_hop_swap(
    pool_ab: &mut Pool,
    pool_bc: &mut Pool,
    input: Token,
    min_final_output: u64,
    to: Address
) -> Token {
    // Intermediate token B — transaction-local and never committed as an output
    let intermediate: Token = swap_a_for_b(pool_ab, input, 0, to)
    
    // The intermediate token exists only in this transaction's scope.
    // The compiler verifies it is consumed before the action ends.
    
    let output = swap_a_for_b(pool_bc, intermediate, min_final_output, to)
    output
}
```

### 6.8 Key Syntax Decisions Summary

| Syntax Element | Keyword | Rationale |
|---|---|---|
| Linear type | `resource` | Clearly communicates "this is a Cell-backed asset, not a plain struct" |
| Shared state | `shared` | Marks contention-sensitive objects for scheduler awareness |
| State transition | `action` | Distinguishes Cell lifecycle operations from utility functions |
| Cell consumption | `consume` | Explicit keyword prevents accidental "use after spend" |
| Cell creation | `create` | Mirrors `consume`; makes Cell lifecycle visually symmetric |
| CellDep access | `read_ref` | Clarifies that this is a non-consuming read |
| Constraint check | `assert_invariant` | Stronger than `assert` — compiler verifies all paths |
| Transaction-scoped values | `let` | Local bindings never hit CellStateTree unless explicitly materialized through `create` |
| Lifecycle attribute | `#[lifecycle(...)]` | State machine as metadata, not syntax pollution |
| Owner assignment | `with_lock(addr)` | Makes lock script assignment explicit |
| Destruction | `destroy` | Capability-gated; requires `destroy` ability |

---

## 7. Compilation Model

### 7.1 Compiler Pipeline

```
Source (.cell)
    │
    ▼
┌─────────────┐
│  Lexer      │  Tokenize source into CellScript token stream
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Parser     │  Produce AST (modules, resources, actions, expressions)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Name       │  Resolve module imports, type references, action calls
│  Resolution │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│  Type Checker    │  Verify types, enforce linearity, check capabilities,
│  + Linearity     │  validate lifecycle transitions, check assert_invariant
│    Checker       │  completeness
└──────┬───────────┘
       │
       ▼
┌─────────────┐
│  Spora IR   │  Lower to intermediate representation with explicit
│  Emission   │  Cell operations (consume_set, create_set, etc.)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Optimizer  │  Dead code elimination, constant folding, inline small
│             │  functions, merge redundant syscalls
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  RISC-V     │  Lower Spora IR to RISC-V machine code, link CellScript
│  Codegen    │  stdlib, emit ELF binary
└──────┬──────┘
       │
       ├──── Lock Script ELF (authorization logic)
       ├──── Type Script ELF (state transition validation)
       ├──── Typed Data Layouts (Molecule schemas for Cell data)
       └──── Scheduler Metadata (witness-encoded hints)
```

### 7.2 Spora IR

The Spora IR is a mid-level representation that describes Cell operations abstractly before lowering to RISC-V. Each action compiles to an IR function with explicit Cell lifecycle operations:

```rust
// Spora IR (conceptual Rust-like pseudocode)

struct SporaIR {
    /// Cells to consume (become inputs)
    consume_set: Vec<CellPattern>,

    /// Cells to read without consuming (become CellDeps)
    read_refs: Vec<CellPattern>,

    /// New Cells to create (become outputs + outputs_data)
    create_set: Vec<(CellOutputPattern, DataLayout)>,

    /// Effect classification for scheduler
    effect_class: EffectClass,

    /// Lifecycle transition rules validated by this script
    lifecycle_rules: Vec<StateTransition>,

    /// Scheduler hints emitted as witness metadata
    scheduler_hints: SchedulerHints,

    /// The actual computation (basic blocks, SSA form)
    body: Vec<BasicBlock>,
}

enum EffectClass {
    /// No Cell reads or writes (pure computation)
    Pure,
    /// Only reads Cells via CellDep
    ReadOnly,
    /// Reads and writes Cells (consume + create)
    Mutating,
    /// Only creates new Cells (no inputs consumed)
    Creating,
    /// Only consumes Cells (no new outputs)
    Destroying,
}

struct SchedulerHints {
    /// Can this action run in parallel with other actions?
    parallelizable: bool,
    /// Type hashes of shared objects touched
    touches_shared: Vec<[u8; 32]>,
    /// Estimated cycle cost (for template builder prioritization)
    estimated_cycles: u64,
}

struct StateTransition {
    from: LifecycleState,
    to: LifecycleState,
    condition: TransitionCondition,
}
```

Important constraint:
- Spora IR must **not** assume a universal mandatory object header for all DSL-produced Cells.
- Typed layout remains primarily a property of the type script plus compiler-generated schema.
- If the language later standardizes a header for specific high-level patterns such as `shared`, `receipt`, or `settle`, that header must be **optional and pattern-specific**, not a protocol-wide prefix imposed on every Cell.
- Touch information should be **compiler-inferred by default**. IR should preserve both:
  - inferred touch sets from explicit Cell operations
  - optional developer annotations only where shared-write or effect-domain intent needs clarification

This matters because Spora should preserve the Cell model’s core advantage:
- arbitrary byte layout
- script-level self-validation
- no protocol-level ORM forced on all state

The compiler may emit standardized layouts where they buy real value, but the protocol should not require “all DSL Cells begin with fixed header bytes.”

### 7.3 How This Differs from Other Compilation Targets

**vs. Move Bytecode**:
- Move compiles to a stack-based bytecode executed by the Move VM. Modules are stored in a global namespace addressed by `(address, module_name)`.
- CellScript compiles to RISC-V machine code. There is no intermediate bytecode. Scripts are stored as Cell data, referenced by `code_hash`. No global module namespace exists — scripts are identified by content hash.
- Move's verifier runs at module publish time. CellScript's type checker runs at compile time. The output ELF is already verified.

**vs. Sway/Fuel**:
- Sway compiles to FuelVM bytecode (a register-based VM). FuelVM has native asset support but no concept of CellDep or shared state.
- CellScript compiles to RISC-V ELF for ckbvm. The compilation target is a general-purpose ISA, not a blockchain-specific bytecode. This means CellScript can potentially run on any RISC-V execution environment, not just ckbvm.
- Sway's predicate model validates spending conditions. CellScript's type script model validates state transitions on both inputs and outputs, which is strictly more expressive.

**vs. Solidity/EVM**:
- Solidity compiles to EVM bytecode (stack-based, 256-bit word size). Storage is modeled as `(contract_address, slot) -> 256-bit value`.
- CellScript has no durable storage slots. State is stored in Cells. "Updating state" means consuming an old Cell and creating a new one. This is fundamentally different from `SSTORE`.
- EVM has no concept of linearity, effect classes, or scheduler hints. Parallelization (if any) must be inferred externally.

---

## 8. Runtime / Execution Model

### 8.1 No New VM

CellScript runs on top of the existing ckbvm. The "runtime" is a thin stdlib linked into each compiled ELF binary. There is no separate runtime process, no interpreter layer, no bytecode VM.

```
┌─────────────────────────────────────────┐
│              ckbvm (RISC-V)             │
│  ┌───────────────────────────────────┐  │
│  │  CellScript stdlib (linked in)    │  │
│  │  - Borsh ser/de                   │  │
│  │  - Syscall wrappers              │  │
│  │  - Linearity runtime checks      │  │
│  │  - Invariant assertion support    │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │  Compiled action logic            │  │
│  │  (RISC-V machine code)            │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### 8.2 Script Types

CellScript produces two kinds of scripts:

**Type Script** = CellScript-compiled state transition validator
- Runs for both consumed inputs and newly created outputs
- Validates data layout transitions (old state → new state)
- Enforces lifecycle rules
- Enforces invariants (AMM constant product, supply caps, etc.)
- Grouped by `type_hash` — all inputs and outputs with the same type script run in one group

**Lock Script** = CellScript-compiled authorization logic
- Runs only for inputs (proves right to spend)
- Verifies signatures, time locks, multi-sig conditions
- Grouped by `lock_hash` — all inputs with the same lock script run in one group

### 8.3 Scheduler Awareness

The compiler emits scheduler metadata in a designated witness field. The metadata format:

```
// Witness[N] for scheduler metadata (ordinary transaction witness slot)
//
// Format: Borsh-encoded SchedulerWitness. The first bytes are the little-endian
// magic 0xCE11 (`11 ce`) followed by version 1, so transaction policy can
// discover candidate witnesses before full decode.
struct SchedulerWitness {
    magic: u16,                  // 0xCE11
    version: u8,                 // 1
    effect_class: u8,           // 0=Pure, 1=ReadOnly, 2=Mutating, 3=Creating, 4=Destroying
    parallelizable: bool,
    touches_shared_count: u32,
    touches_shared: Vec<[u8; 32]>,  // type_hashes of shared objects
    estimated_cycles: u64,
    access_count: u32,
    accesses: Vec<SchedulerAccessWitness>,
}

struct SchedulerAccessWitness {
    operation: u8,               // consume/transfer/destroy/claim/settle/read_ref/create/mutate-*
    source: u8,                  // Input=1, CellDep=2, Output=3
    index: u32,
    binding_hash: [u8; 32],
}
```

Current implementation note: schema v26 keeps scheduler witness access records
limited to scheduler-visible Input/CellDep/Output cell-state accesses. Runtime-only
claim witness/signature syscalls stay in `ckb_runtime_accesses`, not in the compact
scheduler witness. `spora-exec` can attach/discover/decode/admit these witnesses
and rejects invalid ids, illegal operation/source pairs, and out-of-bounds
transaction source indexes before scheduler policy consumes them. It also has an
exact operation/source/index/binding_hash multiset check for comparing decoded
witnesses against trusted transaction-builder or compiled-metadata summaries.
Consensus MPE `BlockAccessSummary` now consumes transaction-admitted witnesses:
scheduler-visible Input/CellDep/Output accesses are merged into block summaries,
and `touches_shared` is classified as shared read domains for `Pure`/`ReadOnly`
effects and shared write domains for mutating/creating/destroying effects. Shared
read/read overlap remains parallelizable; shared write/read or write/write overlap
creates an execution-DAG dependency. Mempool validation and template prefiltering
now reject malformed CellScript scheduler metadata before acceptance/selection,
and template policy tests cover missing or mismatched trusted summaries. Compiled
metadata exposes witness bytes through `ActionMetadata::scheduler_witness_bytes()`;
`CellTx::push_cellscript_compiled_scheduler_witness(...)` admits those bytes against
a concrete transaction, appends the witness, and returns the trusted access
summary for strict policy. A strict
MPE `BlockAccessSummary` path can already require a trusted
transaction-builder or compiled-metadata operation/source/index/binding_hash
multiset and reject missing or mismatched summaries before witness data is merged.
Mining mempool entries and template selectors can now carry producer-backed trusted
summaries into the strict template policy path, including trusted empty summaries.
Wallet transaction generation can now attach one compiled scheduler witness to the
final transaction and expose the returned trusted summary on `PendingTransaction`.
Focused mining coverage proves a producer-returned summary survives sidecar
insertion into selector exposure. Focused consensus coverage proves
selector-provided builder summaries are consumed/rejected by strict template
prefiltering. An explicit external submission surface for trusted summaries
remains open.

Source-level policy:
- `touches` is not intended to be a verbose hand-written manifest
- the compiler should infer normal consume/read/create behavior automatically
- explicit `touches` syntax is only needed where the scheduler-relevant surface is not obvious from syntax alone, especially:
  - writes to `shared` objects
  - effect-class overrides or disambiguation
  - intentionally narrowed or clarified contention domains

So the model is:
- default inferred
- necessary cases explicit

The block template builder reads this metadata to:
1. Filter conflicting transactions before including them in a block (P2a, already completed)
2. Determine which transactions can execute in parallel within a block (P1, already completed)
3. Provide `BlockAccessSummary` shared read/write contention domains for MPE mergeset-level parallelization (started)

This metadata is still not a complete v1 consensus declaration contract. The current MPE path admits witness bytes before consuming shared-touch conflict domains, and the strict path can compare them against trusted access-set summaries before merge. Malicious, missing, or inconsistent metadata still needs transaction-builder, mempool, and adversarial-test closure. The execution layer always performs full validation, so scheduler hints do not replace verifier semantics.

This trust boundary is intentional.

CellScript uses:
- optimistic hints
- pessimistic validation

That means:
- honest nodes can use the metadata to improve scheduling and template construction
- dishonest or incorrect metadata can at worst reduce optimization quality
- the chain still relies on full `ckbvm` execution and existing Cell validity rules for final judgment

The language should therefore avoid turning `touches`, `SchedulerHints`, or any future effect metadata into a consensus-enforced declaration contract in v1. Doing so would require cross-validating “declared touch surface” versus “actual runtime behavior,” which increases runtime complexity and consensus risk without a commensurate payoff at this stage.

### 8.4 Shared-State Contention

When multiple transactions in the same block touch the same shared object (same `type_hash`):

1. **Template builder** (P2a): Detects conflict via scheduler metadata. Includes at most one writer per shared object per block. Multiple readers can coexist.
2. **Block validation** (P1): Validates transactions in parallel where possible. Transactions touching the same shared object are serialized.
3. **Virtual processor** (MPE path): Multiple blue blocks in a mergeset may each contain a write to the same shared object. The canonical ordering resolves this: the first blue block (in GhostDAG order) wins, subsequent conflicting writes are skipped.

CellScript does not solve the contention problem at the language level. It makes contention visible (via `shared` keyword and scheduler metadata) so that the execution stack can handle it efficiently.

Just as importantly, CellScript should preserve **lowering transparency**:
- `consume` maps to `inputs`
- `read_ref` maps to `deps`
- `create` maps to `outputs + outputs_data`
- shared writes map to consume-and-recreate patterns over ordinary Cells

Developers must be able to inspect the generated CellTx shape directly. This is not optional ergonomics polish. It is necessary for:
- debugging capacity usage
- debugging Mass behavior
- understanding state growth
- understanding scheduler conflicts
- keeping the DSL honest to the underlying protocol model

### 8.5 Atomic Execution Unit

One CellTx = one atomic execution unit. All inputs are consumed, all outputs are created, all scripts pass, or the entire transaction fails. There is no partial execution. This is inherited from the Cell model and not changed by CellScript.

System-level parallelism comes from multiple CellTx in the same block (P1) or across blue blocks in a mergeset (MPE).

---

## 9. Standard Operations And Protocol Patterns

### 9.1 `launch` — Create New Asset Type

**Semantic guarantees**: Atomically creates a type script Cell, mints initial supply, and optionally seeds a pool. Either all outputs are created or none are.

**Why standard**: Token launch is the most common first action on any blockchain. Making it atomic prevents partial-deployment states (type script deployed but no tokens minted, or tokens minted but pool not seeded).

**Implementation level**: **Post-v1 transaction-builder feature**. It is a deterministic multi-`create` CellTx template, not a v1 core expression. Current implementations should reject `launch` in executable expression position until builder lowering exists.

### 9.2 `mint` — Create New Units

**Semantic guarantees**: Creates new resource instances, validated by the type script against an authority Cell. Supply invariant is enforced on-chain.

**Why native/standard**: Mint operations require authority verification. The stdlib provides a standard authority pattern (MintAuthority resource) that the type script can verify.

**Implementation level**: **Stdlib**. The `mint` action is a library function in the CellScript stdlib. The type script validates that the authority Cell is consumed and re-created with updated `minted` counter.

### 9.3 `burn` — Destroy Units

**Semantic guarantees**: Destroys resource instances. The `destroy` capability must be declared on the type. The type script verifies that the destruction is authorized.

**Implementation level**: **Stdlib**. Standard destruction pattern: consume the resource Cell, do not create a replacement, verify `destroy` capability.

### 9.4 `transfer` — Move Asset Between Owners

**Semantic guarantees**: Consumes a resource Cell with one lock script, creates a new resource Cell with a different lock script. Data is preserved. The `transfer` capability must be declared.

**Implementation level**: **Language sugar over `consume` + `create`**. `transfer token to address` preserves the resource fields and changes only the output lock. It remains useful because it is high-frequency and lets verifier tooling recognize lock rebinding.

```cellscript
transfer my_token to recipient_address
// Equivalent to:
// consume my_token
// create Token { ...my_token fields... } with_lock(recipient_address)
```

### 9.5 `seed_pool` — Initialize Liquidity Pool Pattern

**Semantic guarantees**: Creates a shared pool Cell with initial reserves. Returns LP receipts. The constant-product invariant is established at creation time.

**Implementation level**: **Stdlib/protocol pattern with compiler-visible metadata**. This should not be a language primitive. The compiler may expose structured pool obligations for audit and policy tooling, but AMM math belongs to libraries, generated verifiers, or transaction-builder policy.

### 9.6 `swap` — Exchange Through Pool

**Semantic guarantees**: Atomically exchanges one asset for another through a pool. The pool's invariant (x·y ≥ k after fees) is verified by the type script.

**Implementation level**: **Stdlib/protocol pattern**. The swap action is a library function over a `shared` pool value. The pool type script or generated verifier performs the invariant check.

### 9.7 `wrap` / `unwrap` — Native Capacity Conversion

**Semantic guarantees**: `wrap` converts native capacity (SAU) to a wrapped asset token. `unwrap` converts back. The total wrapped supply equals the locked capacity.

**Implementation level**: **Stdlib**. Standard wrapping pattern: lock capacity in a wrapper Cell, create a wrapped-asset Cell. Unwrap reverses this.

### 9.8 `claim` — Consume Receipt for Asset

**Semantic guarantees**: Consumes a receipt Cell, verifies claim conditions, produces an asset Cell. The receipt's type script enforces single-use.

**Implementation level**: **Obligation-classifying syntax or intrinsic**. `claim receipt` lowers to consume receipt Cell + verify conditions + create output Cell. Its value is not a new CellTx primitive; it is the metadata anchor for `claim-conditions` obligations.

```cellscript
let tokens = claim vesting_receipt
// Compiler verifies: receipt.type_script enforces single-use
// Compiler verifies: claim conditions (DAA score >= cliff) are checked
```

### 9.9 `settle` — Finalize Pending State

**Semantic guarantees**: Transitions a resource from a pending lifecycle state to a final state. Consumes pending Cells, produces final Cells.

**Implementation level**: **Obligation-classifying syntax or intrinsic**. `settle` marks a finalization path so metadata and policy tooling can distinguish settlement from an ordinary consume/create update. It should remain generic and lifecycle-oriented, not business-specific.

---

## 10. Comparison Matrix

| Dimension | CellScript | Solidity | Move | Sway |
|---|---|---|---|---|
| **Execution target** | RISC-V ELF (ckbvm) | EVM bytecode | Move bytecode | FuelVM bytecode |
| **State model** | Cell (UTXO-like, typed) | Account + storage slots | Resources in global store | UTXO + native assets |
| **General expressiveness** | Narrow (asset-focused) | Wide (Turing-complete) | Medium (module-scoped) | Medium (predicate-aware) |
| **Asset expressiveness** | Native (resource types, lifecycle, shared pool patterns) | Manual (ERC-20 pattern) | Native (resource types) | Partial (native assets, no type scripts) |
| **Linear types** | Yes (enforced by compiler + capability model) | No | Yes (abilities: key/store/copy/drop) | No |
| **Shared state** | Explicit (`shared` keyword, CellDep/CellInput) | Implicit (all storage is shared) | Explicit (Sui shared objects) | No (pure UTXO) |
| **Scheduler hints** | Native (IR emission, effect classes, witness metadata) | None (sequential EVM) | None | Partial (predicates) |
| **DAG awareness** | Native (designed for GhostDAG mergeset) | None (single-chain) | None (single-chain or Narwhal) | None (single-chain) |
| **Parallelization support** | Native (effect class, access summary, contention detection) | None | Partial (Sui object-level) | Partial (predicate independence) |
| **Cold-start friendliness** | Medium now; high after post-v1 launch builder (atomic deploy + mint + pool) | Low (deploy → init → approve → add liquidity = 4+ txs) | Medium (publish module → init) | Medium (deploy predicate) |
| **Developer ergonomics** | Good (Rust-like syntax, narrow domain) | High (well-known, huge ecosystem) | Good (but new concepts, steep learning curve) | Good (Rust-like, but Fuel-specific) |
| **Ecosystem maturity** | None (greenfield) | Massive | Growing | Small |
| **Reentrancy risk** | Impossible (Cell model, no callbacks) | High (delegate calls, external calls) | Low (no dynamic dispatch by default) | Low (no callbacks in predicates) |
| **Storage cost model** | 3-dimensional mass (compute + transient + storage) | Gas (single dimension) | Gas (single dimension) | Gas (single dimension) |
| **Time lock support** | Native (since field: bit63=relative, bit62=daa) | Manual (block.timestamp comparison) | Manual | Manual |
| **Fit for Spora** | Perfect (designed for Cell + DAG + ckbvm + mass) | Poor (account model, no DAG) | Partial (resources yes, DAG no, ckbvm no) | Partial (UTXO yes, DAG no, FuelVM) |

### Why CellScript Wins for Spora

The critical differentiators are:

1. **Cell-native**: CellScript's semantic model maps 1:1 to Spora's CellTx. No impedance mismatch.
2. **DAG-aware**: Scheduler hints are emitted by the compiler, enabling P1/P2a/MPE optimizations.
3. **ckbvm-targeted**: Compiles to RISC-V ELF. No new VM needed. Backward-compatible with existing raw scripts.
4. **Mass-aware**: The compiler can estimate mass contributions (compute, transient, storage) at compile time, enabling fee estimation before transaction construction.

---

## 11. Execution Plan

This section replaces a generic compiler roadmap with a more opinionated execution plan.

The key decision is:

- **implementation path**: build with the current CellScript-style backend model
- **semantic target**: steer the language surface toward the Hypha model

In practical terms:
- keep `ckbvm`
- keep `CellTx`
- keep lock/type/data decomposition
- keep witness-oriented execution
- introduce a narrow DSL whose semantic center is:
  - `resource`
  - `shared`
  - `receipt`
  - `settle`
  - transaction-local computation
  - post-v1 launch builder patterns

This gives Spora a path that is implementable now without trapping it forever in “better raw CKB scripting.”

### 11.1 Execution Principle

Do not try to choose between:
- “pure CellScript forever”
- “full Hypha from day one”

That is the wrong fork.

The correct path is:

**CellScript-style compiler architecture + Hypha-style semantic surface**

Meaning:
- the compiler and runtime path stay close to current Spora reality
- the language and IR are designed around resource/object/effect semantics from day one

### 11.2 Public Name vs Internal Framing

Recommended naming split:
- **public language name**: `Hypha`
- **internal implementation framing**: CellScript backend

Reason:
- “Hypha” is a better long-term semantic brand
- “CellScript backend” accurately describes the implementation path and reduces internal confusion

### 11.3 Non-Negotiable Constraints

The v1 execution plan must preserve these boundaries:

#### Keep unchanged

- `ckbvm`
- RISC-V ELF target
- current syscall surface
- `CellTx` envelope
- `CellOutput` / `CellInput` / `CellDep`
- witness verification
- lock/type/data decomposition
- current state commitment model
- current scheduler DAG model

#### Introduce as new custom layers

- DSL parser and compiler
- optional standardized object-layout conventions for specific patterns
- effect manifest conventions
- Spora IR
- compiler-known lifecycle rules
- compiler-known standard operations and protocol-pattern metadata

#### Explicitly defer

- new VM
- general-purpose contract runtime
- dynamic dispatch ecosystem
- language features that exist mainly to impress language people
- unrestricted storage abstractions that hide state touch surfaces

#### Hard design rules

- no mandatory universal object header for all DSL Cells
- no consensus enforcement of scheduler hints in v1
- no black-box lowering that obscures `CellTx.inputs / outputs / deps / witnesses`

### 11.4 Workstream Structure

The work should be split into six workstreams and built in this order.

#### Workstream A — Semantic Kernel

Goal:
- freeze the minimal language core before backend work expands.

Scope:
- define declaration classes:
  - `resource`
  - `shared`
  - `receipt`
  - `object`
- define primitive action classes:
  - `mint`
  - `burn`
  - `transfer`
  - `wrap`
  - `unwrap`
  - `claim`
  - `settle`
- define protocol-pattern metadata for:
  - launch builders
  - pool/AMM flows
  - `seed_pool`
  - `swap`
- define ownership, linearity, and lifecycle rules
- define `touches` syntax and effect declaration grammar
- explicitly define that `touches` is:
  - inferred by default
  - explicit only when shared-write or effect-domain clarity is needed

Exit criteria:
- one short semantic spec
- one canonical AST schema
- one canonical error model for linearity/lifecycle failures

#### Workstream B — Spora IR

Goal:
- create the layer that keeps source semantics separate from `ckbvm` codegen.

Scope:
- define:
  - `consume_set`
  - `read_refs`
  - `write_intents`
  - `create_set`
  - `effect_class`
  - `lifecycle_rules`
  - `scheduler_hints`
- define object identity and shared-object version handling in IR
- define these in a way that does not require a universal protocol-level object header
- define verifier plan representation

Exit criteria:
- IR schema version `v0`
- round-trip fixtures from source examples to IR JSON or Borsh form
- clear distinction between consensus-relevant IR and advisory scheduler metadata

#### Workstream C — Compiler Frontend

Goal:
- get source to validated IR.

Scope:
- hand-written parser
- AST construction
- symbol resolution
- type checking
- linearity checking
- lifecycle checking
- `touches` inference and validation

Recommended choices:
- prefer a hand-written recursive descent parser over Tree-sitter as the compiler parser
- Tree-sitter can be added later for editor tooling, not as the canonical frontend

Exit criteria:
- compile example programs into validated Spora IR
- reject invalid programs with deterministic diagnostics

#### Workstream D — `ckbvm` Backend

Goal:
- lower validated IR into artifacts the current chain can actually execute.

Scope:
- canonical typed cell layouts
- optional object-layout templates for selected patterns
- witness manifest encoding
- generated verifier code
- lock/type script emission
- RISC-V ELF generation and linking

Recommended strategy:
- do not start with a custom SSA optimizer
- start with a simple structured IR lowering path and predictable codegen
- prefer correctness and inspectability over fancy backend architecture in v1

Exit criteria:
- compile a minimal asset module to ELF
- construct a valid CellTx using the generated artifacts
- execute successfully under current `ckbvm` integration

#### Workstream E — Runtime Integration

Goal:
- make compiler output a first-class participant in Spora execution and scheduling.

Scope:
- transaction builder support
- witness packing support
- object discovery / typed decoding
- effect manifest extraction
- scheduler metadata extraction
- mempool and template-builder consumption of effect metadata

Important rule:
- advisory scheduler metadata may start off non-consensus
- object validity, lifecycle checks, and verifier logic remain consensus-enforced

Exit criteria:
- node can ingest and simulate compiler-produced transactions
- mempool can inspect effect surfaces without decompiling script code

#### Workstream F — Tooling and SDK

Goal:
- make the system usable beyond core protocol engineers.

Scope:
- formatter
- linter
- tests
- CLI compiler
- Rust SDK
- TypeScript SDK
- example package templates

Exit criteria:
- external developer can write, compile, build, and submit a transaction without reading raw syscall docs

### 11.5 Phase Plan

The workstreams above should be delivered through four phases.

### Phase 0 — Freeze the Contract of the System

Objective:
- define the narrow language you are actually willing to support.

Build:
- semantic kernel
- standard operation list
- object header format
- effect manifest format
- first draft of Spora IR

Do not build yet:
- optimizer
- LSP
- user-defined generics in executable source
- advanced macro system

Gate:
- core team can read the spec and answer, without ambiguity, what `resource`, `shared`, `receipt`, `transfer`, `destroy`, `claim`, and `settle` mean, and why `launch` and pool flows sit outside the v1 language core.

### Phase 1 — Compiler MVP

Objective:
- source to validated IR to working `ckbvm` artifacts.

Build:
- parser
- AST
- type checker
- linearity checker
- IR emission
- backend codegen
- minimal stdlib

Supported surface:
- `resource`
- `action`
- `consume`
- `create`
- `transfer`
- `mint`
- `burn`
- typed payloads

Milestone demo:
- a fungible asset with mint, transfer, and burn executing end-to-end through current `ckbvm`

### Phase 2 — Asset Lifecycle and Shared-State Core

Objective:
- make the language useful for real Spora-native protocols.

Build:
- `shared`
- `receipt`
- lifecycle transitions
- `claim`
- `settle`
- scheduler hint emission
- protocol-pattern metadata for pool examples

Milestone demo:
- one complete launch flow:
  - deploy asset
  - mint supply
  - seed first pool
  - create vesting receipt
  - claim from receipt
  - settle shared state
- marked as a controlled transaction-builder/protocol-pattern demo, not evidence that `launch` or `pool` are v1 language primitives

### Phase 3 — Node/Scheduler Integration

Objective:
- make effect surfaces matter to the chain, not just the compiler.

Build:
- mempool effect inspection
- scheduler hint consumption
- shared-write contention analysis
- effect-driven template construction hooks
- IR/effect equivalence tests versus sequential execution

Milestone demo:
- compiler-generated transactions participate in block construction with scheduler-visible conflict domains

### Phase 4 — Production Hardening

Objective:
- reduce operational and security risk.

Build:
- optimizer passes
- extensive differential tests
- property-based tests for linearity and lifecycle
- external security audit
- formatter, linter, docs generator, SDK stabilization

Milestone demo:
- audited compiler toolchain with stable example packages and release process

### 11.6 Concrete Deliverables by Layer

| Layer | Must Build in v1 | Can Wait |
|---|---|---|
| Language | parser, type checker, linearity, lifecycle core, inferred `touches` with optional explicit annotations | post-v1 template/codegen generics, macro system |
| IR | effect model, object model, scheduler hints | optimizer-grade SSA |
| Backend | typed layout lowering, witness format, ELF output | aggressive optimization passes, global object header schemes |
| Runtime | manifest parsing, object validation, tx builder integration | full on-chain effect VM |
| Scheduler | metadata ingestion, conflict-domain support | deep automatic cross-block scheduling |
| Tooling | CLI, tests, examples | LSP polish, debugger, docs generator |

### 11.7 What Gets Encoded Where

This split must stay crisp.

| Concern | Where it belongs | Notes |
|---|---|---|
| transaction wire structure | `CellTx` envelope | keep unchanged |
| object payload schema | object model + compiler output | Borsh-encoded typed payloads |
| object identity/version/lifecycle | type-script-defined layout, with optional standardized header templates where useful | do not force a universal protocol-wide header on all Cells |
| resource linearity | compiler | compile-time guarantee |
| lifecycle legality | compiler + verifier | static when possible, runtime when needed |
| shared-write intent | envelope metadata + IR | scheduler-visible, but not a consensus declaration contract in v1 |
| final validity | generated verifier + existing runtime | still enforced on execution path |
| scheduler hints | compiler output, advisory witness metadata | optimization-only unless explicitly promoted by later protocol work |
| mass estimation | compiler estimate + consensus authority | compiler is approximate, chain is final |

### 11.8 Recommended Technology Choices

Recommendations:
- parser: hand-written recursive descent
- encoding: Borsh
- IR format for tests/debugging: JSON mirror plus canonical binary form
- backend: simple custom lowering first, no LLVM dependency unless later justified
- stdlib: thin and explicit, with syscall wrappers and typed layout helpers

Do not overbuild:
- do not start with LLVM
- do not start with Cranelift unless you have clear proof it reduces risk
- do not make the compiler architecture depend on a future optimizer that does not exist yet

### 11.9 Acceptance Milestones

The execution plan should be managed by milestone, not by “compiler percentage complete.”

#### Milestone M1

- parse and type-check a minimal asset module
- emit Spora IR for `mint`, `transfer`, `burn`

#### Milestone M2

- generate `ckbvm`-compatible verifier artifacts
- run compiled token flow inside integration tests

#### Milestone M3

- support `shared`, `receipt`, and lifecycle transitions
- compile pool and vesting examples

#### Milestone M4

- compiler emits scheduler-visible effect metadata
- node tooling can read and inspect it

#### Milestone M5

- end-to-end explicit create/shared/claim/settle example works in a controlled test environment, with launch/pool behavior exposed as protocol-pattern metadata

### 11.10 Risks and Mitigations

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| backend becomes a disguised new VM effort | Critical | Medium | keep `ckbvm` fixed, treat DSL as compiler + verifier generator only |
| language surface drifts back into generic smart-contract design | High | Medium | freeze semantic kernel early and reject off-model features |
| shared object semantics are underspecified | Critical | Medium | define versioning and write discipline in IR before pool-pattern/settle work |
| compiler/runtime boundary gets blurry | High | Medium | keep envelope/object/compiler/runtime split explicit in spec and tests |
| scheduler metadata is inaccurate or dishonest | High | Medium | keep validity in verifier path; use differential checks between metadata and executed object set |
| code size or cycle cost grows too fast | High | Medium | keep stdlib minimal, profile generated ELF early, optimize only after end-to-end flows work |

### 11.11 Explicit Do-Not-Do List

Do not do these in v1:
- general-purpose contract platform features
- arbitrary runtime call graphs
- contract inheritance
- dynamic storage collections as a default abstraction
- full Move ability system
- full Sway/Fuel execution semantics
- protocol changes just to make the compiler feel elegant

### 11.12 Final Execution Recommendation

If execution started immediately, the most defensible path is:

1. keep the backend close to current Spora and `ckbvm`
2. freeze Hypha-style semantics early
3. build Spora IR before ambitious code generation
4. ship a narrow compiler that handles resources, receipts, shared-state flows, claim/settle obligations, and pool-pattern metadata well
5. let generality wait

---

## 12. Example Programs

### Example 1: Meme Asset Launch with Pool Seeding

This example shows a complete flow: define an asset, launch it with initial supply, seed an AMM pool, and enable trading.

```cellscript
// meme_launch.cell — Launch a meme token with instant AMM trading

module spora::meme

use spora::fungible_token::{Token, MintAuthority}
use spora::amm::{Pool, LPReceipt}

// ─── Asset Definition ───

resource MemeToken has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]    // e.g., b"DOGE\0\0\0\0"
}

// ─── Launch: Create token + seed pool ───

/// Launch a meme token. Atomic: either everything happens or nothing does.
///
/// Flow:
///   1. Create MintAuthority with capped supply
///   2. Mint initial supply
///   3. Split: 80% to pool, 10% to creator, 10% to community
///   4. Seed AMM pool with 80% of supply + paired SOL/USDC
///   5. Return authority + pool + LP receipt
///
action launch_meme(
    symbol: [u8; 8],
    paired_token: Token,         // e.g., wrapped SOL
    creator: Address,
    community_addr: Address
) -> (MintAuthority, Pool, LPReceipt) {
    
    let total_supply: u64 = 1_000_000_000_00  // 1B tokens, 2 decimal places
    let pool_share: u64   = total_supply * 80 / 100
    let creator_share: u64 = total_supply * 10 / 100
    let community_share: u64 = total_supply - pool_share - creator_share

    // 1. Create mint authority (locked to creator)
    let auth = create MintAuthority {
        token_symbol: symbol,
        max_supply: total_supply,
        minted: total_supply    // All minted at launch
    } with_lock(creator)

    // 2. Create distribution tokens
    create MemeToken {
        amount: creator_share,
        symbol: symbol
    } with_lock(creator)

    create MemeToken {
        amount: community_share,
        symbol: symbol
    } with_lock(community_addr)

    // 3. Create pool seed tokens
    let pool_tokens = create MemeToken {
        amount: pool_share,
        symbol: symbol
    } with_lock(creator)

    // 4. Seed AMM pool (constant product: x * y = k)
    consume pool_tokens
    consume paired_token

    let initial_lp = math::isqrt(pool_share * paired_token.amount)

    let pool = create Pool {
        token_a_symbol: symbol,
        token_b_symbol: paired_token.symbol,
        reserve_a: pool_share,
        reserve_b: paired_token.amount,
        total_lp: initial_lp,
        fee_rate_bps: 30       // 0.3% fee
    }

    let lp_receipt = create LPReceipt {
        pool_id: pool.type_hash(),
        lp_amount: initial_lp,
        provider: creator
    } with_lock(creator)

    (auth, pool, lp_receipt)
}

// ─── Trading ───

/// Buy meme tokens using paired token through the pool.
action buy_meme(
    pool: &mut Pool,
    payment: Token,
    min_meme_out: u64,
    buyer: Address
) -> MemeToken {
    assert_invariant(payment.symbol == pool.token_b_symbol, "wrong payment token")
    
    let fee = payment.amount * pool.fee_rate_bps as u64 / 10000
    let net_input = payment.amount - fee
    let output = pool.reserve_a * net_input / (pool.reserve_b + net_input)
    
    assert_invariant(output >= min_meme_out, "slippage exceeded")
    assert_invariant(output < pool.reserve_a, "insufficient pool reserves")
    
    consume payment
    pool.reserve_b = pool.reserve_b + payment.amount
    pool.reserve_a = pool.reserve_a - output

    create MemeToken {
        amount: output,
        symbol: pool.token_a_symbol
    } with_lock(buyer)
}

/// Sell meme tokens for paired token through the pool.
action sell_meme(
    pool: &mut Pool,
    meme: MemeToken,
    min_paired_out: u64,
    seller: Address
) -> Token {
    assert_invariant(meme.symbol == pool.token_a_symbol, "wrong meme token")
    
    let fee = meme.amount * pool.fee_rate_bps as u64 / 10000
    let net_input = meme.amount - fee
    let output = pool.reserve_b * net_input / (pool.reserve_a + net_input)
    
    assert_invariant(output >= min_paired_out, "slippage exceeded")
    assert_invariant(output < pool.reserve_b, "insufficient pool reserves")
    
    consume meme
    pool.reserve_a = pool.reserve_a + meme.amount
    pool.reserve_b = pool.reserve_b - output

    create Token {
        amount: output,
        symbol: pool.token_b_symbol
    } with_lock(seller)
}
```

### Example 2: Vesting Receipt / Claim Flow

This example shows a complete vesting protocol: create a vesting schedule, issue receipts, time-locked claims, and final settlement.

```cellscript
// vesting_protocol.cell — Employee token vesting with cliff + linear release

module spora::vesting_protocol

use spora::fungible_token::Token

// ─── Vesting Types ───

/// Vesting schedule parameters, stored in a shared config Cell.
shared VestingConfig has store {
    admin: Address
    token_symbol: [u8; 8]
    cliff_period: u64          // DAA score delta before first claim
    total_vesting_period: u64  // DAA score delta for full vesting
    revocable: bool            // Admin can revoke unvested tokens
}

/// Vesting grant receipt. One per employee.
#[lifecycle(Granted -> Claimable -> FullyClaimed)]
receipt VestingGrant has store {
    state: u8                  // 0=Granted, 1=Claimable, 2=FullyClaimed
    beneficiary: Address
    total_amount: u64
    claimed_amount: u64
    grant_daa_score: u64       // When the grant was created
    cliff_daa_score: u64       // When cliff is reached
    end_daa_score: u64         // When fully vested
    token_symbol: [u8; 8]
}

// ─── Actions ───

/// Admin creates a vesting config.
action create_vesting_config(
    admin: Address,
    token_symbol: [u8; 8],
    cliff_period: u64,
    total_period: u64,
    revocable: bool
) -> VestingConfig {
    assert_invariant(cliff_period < total_period, "cliff >= total")
    
    create VestingConfig {
        admin: admin,
        token_symbol: token_symbol,
        cliff_period: cliff_period,
        total_vesting_period: total_period,
        revocable: revocable
    } with_lock(admin)
}

/// Admin grants vesting tokens to an employee.
/// Tokens are locked — employee cannot access until cliff.
action grant_vesting(
    config: read_ref VestingConfig,
    tokens: Token,
    beneficiary: Address
) -> VestingGrant {
    assert_invariant(tokens.symbol == config.token_symbol, "wrong token")
    assert_invariant(tokens.amount > 0, "zero grant")
    
    let now = env::current_daa_score()
    
    consume tokens  // Lock tokens in vesting
    
    create VestingGrant {
        state: 0,  // Granted
        beneficiary: beneficiary,
        total_amount: tokens.amount,
        claimed_amount: 0,
        grant_daa_score: now,
        cliff_daa_score: now + config.cliff_period,
        end_daa_score: now + config.total_vesting_period,
        token_symbol: config.token_symbol
    } with_lock(beneficiary)
}

/// Employee claims vested tokens. Partial claims allowed after cliff.
action claim_vested(grant: VestingGrant) -> (Token, VestingGrant) {
    let now = env::current_daa_score()
    
    assert_invariant(now >= grant.cliff_daa_score, "cliff not reached")
    assert_invariant(grant.state < 2, "already fully claimed")
    
    // Calculate vested amount (linear interpolation)
    let vested_total = if now >= grant.end_daa_score {
        grant.total_amount
    } else {
        let elapsed = now - grant.cliff_daa_score
        let period = grant.end_daa_score - grant.cliff_daa_score
        grant.total_amount * elapsed / period
    }
    
    let claimable = vested_total - grant.claimed_amount
    assert_invariant(claimable > 0, "nothing to claim")
    
    consume grant
    
    // Determine new state
    let new_state: u8 = if vested_total == grant.total_amount { 2 } else { 1 }
    
    let tokens = create Token {
        amount: claimable,
        symbol: grant.token_symbol
    } with_lock(grant.beneficiary)
    
    let updated_grant = create VestingGrant {
        state: new_state,
        beneficiary: grant.beneficiary,
        total_amount: grant.total_amount,
        claimed_amount: grant.claimed_amount + claimable,
        grant_daa_score: grant.grant_daa_score,
        cliff_daa_score: grant.cliff_daa_score,
        end_daa_score: grant.end_daa_score,
        token_symbol: grant.token_symbol
    } with_lock(grant.beneficiary)
    
    (tokens, updated_grant)
}

/// Admin revokes unvested tokens (if config allows).
action revoke_grant(
    config: read_ref VestingConfig,
    grant: VestingGrant,
    admin: Address
) -> (Token, Token) {
    assert_invariant(config.revocable, "not revocable")
    assert_invariant(grant.state < 2, "already fully claimed")
    
    let now = env::current_daa_score()
    
    // Calculate what employee has earned
    let vested = if now >= grant.end_daa_score {
        grant.total_amount
    } else if now >= grant.cliff_daa_score {
        let elapsed = now - grant.cliff_daa_score
        let period = grant.end_daa_score - grant.cliff_daa_score
        grant.total_amount * elapsed / period
    } else {
        0
    }
    
    let unclaimed_vested = vested - grant.claimed_amount
    let unvested = grant.total_amount - vested
    
    consume grant
    
    // Employee gets their vested portion
    let employee_tokens = create Token {
        amount: unclaimed_vested,
        symbol: grant.token_symbol
    } with_lock(grant.beneficiary)
    
    // Admin recovers unvested portion
    let admin_tokens = create Token {
        amount: unvested,
        symbol: grant.token_symbol
    } with_lock(admin)
    
    (employee_tokens, admin_tokens)
}
```

### Example 3: Shared-State Settlement Flow

This example shows a multi-party deposit pool with accumulating state, final settlement, and cleanup.

```cellscript
// settlement.cell — Multi-party deposit pool with settlement

module spora::settlement

use spora::fungible_token::Token

// ─── Types ───

/// Shared deposit pool. Accumulates deposits from multiple parties.
shared DepositPool has store {
    token_symbol: [u8; 8]
    total_deposited: u64
    num_depositors: u32
    settlement_daa: u64          // When settlement becomes possible
    admin: Address
    is_settled: bool
}

/// Deposit receipt — proof of individual deposit.
receipt DepositReceipt has store {
    pool_type_hash: Hash
    depositor: Address
    amount: u64
    deposited_at_daa: u64
}

/// Settlement record — final distribution proof.
struct SettlementEntry {
    recipient: Address
    amount: u64
    share_bps: u16              // Basis points of total
}

// ─── Pool Creation ───

/// Create a new deposit pool.
action create_pool(
    token_symbol: [u8; 8],
    settlement_daa: u64,
    admin: Address
) -> DepositPool {
    assert_invariant(settlement_daa > env::current_daa_score(), 
        "settlement must be in future")
    
    create DepositPool {
        token_symbol: token_symbol,
        total_deposited: 0,
        num_depositors: 0,
        settlement_daa: settlement_daa,
        admin: admin,
        is_settled: false
    } with_lock(admin)
}

// ─── Deposits ───

/// Deposit tokens into the pool. Returns a receipt.
action deposit(
    pool: &mut DepositPool,
    tokens: Token,
    depositor: Address
) -> DepositReceipt {
    assert_invariant(!pool.is_settled, "pool already settled")
    assert_invariant(tokens.symbol == pool.token_symbol, "wrong token")
    assert_invariant(tokens.amount > 0, "zero deposit")
    assert_invariant(env::current_daa_score() < pool.settlement_daa,
        "deposit window closed")
    
    consume tokens
    
    pool.total_deposited = pool.total_deposited + tokens.amount
    pool.num_depositors = pool.num_depositors + 1

    create DepositReceipt {
        pool_type_hash: pool.type_hash(),
        depositor: depositor,
        amount: tokens.amount,
        deposited_at_daa: env::current_daa_score()
    } with_lock(depositor)
}

// ─── Settlement ───

/// Settle the pool. Admin triggers after settlement_daa.
/// This marks the pool as settled and distributes tokens proportionally.
action settle_pool(
    pool: &mut DepositPool,
    receipts: [DepositReceipt; 8]  // Up to 8 depositors per settlement tx
) {
    assert_invariant(!pool.is_settled, "already settled")
    assert_invariant(env::current_daa_score() >= pool.settlement_daa,
        "settlement time not reached")
    
    // Calculate each depositor's share and distribute
    let mut distributed: u64 = 0
    
    for receipt in receipts {
        assert_invariant(receipt.pool_type_hash == pool.type_hash(),
            "receipt from wrong pool")
        
        // Pro-rata distribution
        let share = receipt.amount  // In simplest case: get back what you put in
        // More complex: share = receipt.amount * pool.total_reward / pool.total_deposited
        
        consume receipt
        
        settle create Token {
            amount: share,
            symbol: pool.token_symbol
        } with_lock(receipt.depositor)
        
        distributed = distributed + share
    }
    
    pool.total_deposited = pool.total_deposited - distributed
    
    if pool.total_deposited == 0 {
        pool.is_settled = true
    }
}

// ─── Emergency Withdrawal ───

/// Emergency withdraw before settlement (forfeits any rewards).
action emergency_withdraw(
    pool: &mut DepositPool,
    receipt: DepositReceipt
) -> Token {
    assert_invariant(!pool.is_settled, "already settled")
    
    consume receipt
    
    pool.total_deposited = pool.total_deposited - receipt.amount
    pool.num_depositors = pool.num_depositors - 1

    create Token {
        amount: receipt.amount,
        symbol: pool.token_symbol
    } with_lock(receipt.depositor)
}
```

---

## 13. Final Recommendation

### 13.1 Strong Recommendation: Build CellScript

CellScript should be built. The reasoning is:

1. **Spora's Cell model is too low-level for ecosystem growth.** Hand-writing RISC-V scripts with raw syscalls is viable for core developers but not for a broader protocol designer community. CellScript bridges this gap without sacrificing any of the Cell model's power.

2. **No existing language fits.** As analyzed in Section 1.3, Solidity/Move/Sway each require fundamental modifications to target Spora's execution model. CellScript, designed from scratch, avoids the technical debt of adapting an ill-fitting language.

3. **The compilation target already exists.** ckbvm is operational. The syscall interface is stable. RISC-V toolchains are mature. CellScript needs to generate valid ELF binaries and nothing more. This is a compiler project, not a VM project.

4. **DAG scheduling demands language-level support.** The MPE parallelization design requires `BlockAccessSummary` and `BlockExecutionEffect` metadata. CellScript's scheduler hints provide this metadata automatically, accelerating the MPE roadmap.

### 13.2 Name Justification

**CellScript** because:
- The Cell is Spora's fundamental state unit. The language is about programming Cell behavior.
- "Script" aligns with CKB/Bitcoin tradition (lock scripts, type scripts). It communicates scope: this is not a general-purpose language.
- The `.cell` extension is clean, unique, and unlikely to collide with existing tools.

### 13.3 Why This Design Is Strong

- **Minimal surface area**: CellScript does one thing (Cell lifecycle management) and does it well. The language is learnable in a day by anyone who knows Rust.
- **Zero impedance mismatch**: Every CellScript concept maps directly to a Spora runtime concept. There is no translation layer, no adaptor pattern, no "but the underlying model doesn't really work that way."
- **Compiler-enforced safety**: Linear types prevent double-spend bugs at compile time. Lifecycle attributes prevent invalid state transitions at compile time. These are guarantees that raw script programming cannot provide.
- **Forward-compatible with MPE**: The scheduler hint system is designed today for the parallelization model being built tomorrow, but it remains advisory. When MPE lands, CellScript-compiled scripts can benefit without moving scheduling declarations into the consensus trust boundary.
- **Transparent to the Cell layer**: The language is only useful if developers can still see how source code lowers into `inputs`, `outputs`, `deps`, and witnesses. CellScript keeps that mapping inspectable.
- **Low annotation burden**: Developers should not have to hand-write complete touched-state manifests. The compiler infers the obvious parts, and explicit `touches` is reserved for shared-write and ambiguous cases.

### 13.4 What Should Remain Compatible with Current Spora

**Do not change**:
- CellTx envelope format (`ver: 0xC001`, `inputs`, `outputs`, `deps`, `header_deps`, `outputs_data`, `witnesses`)
- ckbvm execution model (RISC-V ELF, syscall numbers 2061–2177, plus Blake3 extension)
- Script model (`code_hash`, `hash_type`, `args`)
- CellMeta indexing (`lock_hash`, `type_hash`, `data_hash`)
- Capacity model (occupied capacity calculation)
- 3-dimensional mass model (compute + transient + storage)
- Blake3 hashing with domain separation (`spora-cell/txid`, `spora-cell/wtxid`, `spora-cell/sig`, `spora-cell/data`)
- MuHash-based CellStateTree and cell_commitment
- GhostDAG consensus model (blue/red/selected-parent/mergeset)

CellScript is a compiler that targets the existing infrastructure. It adds capability without modifying the foundation.

### 13.5 What Should Break from CKB Design

**Intentionally diverge from**:

1. **Raw byte-level programming**: CKB encourages writing scripts in C/assembly. CellScript replaces this with a typed language. Raw scripts remain supported but are not the recommended path.

2. **Manual witness encoding**: CKB scripts parse witnesses byte-by-byte. CellScript's compiler generates Molecule-based public scheduler witness encoding/decoding automatically. Legacy Borsh decoding remains only for migration/private tooling paths.

3. **Untyped Cell data**: CKB Cell data is `Vec<u8>` with no enforced schema. CellScript enforces typed data layouts at compile time and generates Molecule schemas for fixed-width persistent Cell types. Type scripts validate data layout transitions.

   Important limitation:
   CellScript should not replace this with a mandatory universal object header. Typed layout should remain compiler- and script-defined, with optional standardized layout templates only where the abstraction clearly pays for itself.

4. **No lifecycle awareness**: CKB has no concept of resource lifecycle states. CellScript adds `#[lifecycle(...)]` attributes that generate type script logic for state machine enforcement.

5. **No scheduler hints**: CKB scripts provide no metadata for parallel execution. CellScript emits `SchedulerWitness` data in a witness field, enabling the block template builder and virtual processor to make informed scheduling decisions.

   Important trust boundary:
   these hints are advisory only. The chain must not depend on them for consensus validity in v1.

6. **Molecule serialization**: CKB uses Molecule for on-chain encoding. Spora now keeps the public VM and CellScript ABI aligned with Molecule too. Borsh remains only for legacy/private migration paths, not new public Cell data or scheduler witness surfaces.

### 13.6 How CellScript Replaces CoBuild / OTX / tx-builder Mental Models

CellScript should not be misunderstood as a proposal to eliminate transactions, witnesses, signatures, or collaborative transaction construction. Those functions remain necessary. What changes is where they live and how they are exposed.

In the old model, an application action does not map directly to an on-chain state transition. Something in the middle must still:

1. query live Cells
2. select inputs
3. materialize outputs and change
4. resolve deps and header_deps
5. organize input groups
6. lay out witnesses
7. estimate fees and storage obligations
8. produce signable messages
9. coordinate partial construction across multiple actors

That is why ecosystems grow bespoke `tx-builder` layers, witness helpers, OTX packets, CoBuild-like coordination formats, wallet-specific signing flows, and script-specific glue code. These are not fake complexity. They are compensation for the lack of a blessed high-level coordination contract.

CellScript's value is to internalize this coordination stack into one canonical pipeline:

```text
App Intent
 └─ CellScript compiler
     └─ Cell Plan
         └─ Tx Plan
             └─ Witness Obligations
                 └─ Auth / Wallet adapters
                     └─ Execution proofs / signatures
                         └─ chain
```

This changes the role of each legacy component:

| Legacy Tooling Concern | CellScript Replacement |
|---|---|
| `tx-builder` | The standard `Cell Plan -> Tx Plan` planner stage |
| witness helpers | The `Witness Obligations` layer |
| CoBuild-style coordination formats | Canonical IR plus a standard obligation protocol |
| OTX packets | Partial intents, unresolved obligations, and mergeable tx plans |

The key shift is that witness handling is no longer primarily a byte-layout problem presented directly to application developers. It becomes an obligation problem:

- which actor must authorize which action
- which auth adapter is responsible
- whether the proof is Schnorr, ECDSA, multisig, passkey, or something else
- which transaction fields are actually being authorized

Wallets and signers still matter. They still handle key custody, user consent, hardware signing, multisig coordination, passkey flows, and proof generation. CellScript does not replace auth adapters, and it does not remove fee payers, storage sponsors, or verifier-facing data providers. What it does is replace fragmented ecosystem protocols with a standard internal stack that hands those components semantically clear inputs instead of ad hoc transaction skeletons and witness conventions.

Stated precisely: CellScript does not erase the underlying functions behind CoBuild, OTX, or tx-builders. It removes the need for them to remain front-stage developer burdens and fragmented external coordination formats.

### 13.7 What Goes Where

| Concern | Location | Rationale |
|---|---|---|
| Transaction structure | CellTx envelope (unchanged) | CellScript compiles INTO valid CellTx. The envelope is the protocol's wire format. |
| Object data layout | Cell data (outputs_data) | CellScript generates Molecule/schema encoded typed data. Type scripts validate layout. |
| Optional object header templates | compiler convention for selected patterns | useful for some `shared` / `receipt` / `settle` patterns, but not globally mandatory |
| State transition rules | Type script ELF (compiler output) | The type script IS the compiled CellScript action. It runs in ckbvm. |
| Authorization logic | Lock script ELF (compiler output) | Lock scripts compiled from CellScript lock functions. |
| Scheduler metadata | Witness field (compiler output) | Advisory data for template builder / virtual processor. Not consensus-enforced. |
| Linearity enforcement | Compiler type checker | Compile-time guarantee. No runtime cost for linearity checking in production. |
| Lifecycle enforcement | Type script logic (runtime) | Lifecycle transitions validated by type script during execution. |
| Mass estimation | Compiler + consensus MassCalculator | Compiler estimates mass; consensus layer computes authoritative mass. |
| CellStateTree commitment | Consensus layer (unchanged) | MuHash accumulator, cell_commitment hash. CellScript does not touch this. |

### 13.8 Closing Note

CellScript is not an attempt to build "Spora's Solidity." It is an attempt to build the language that Spora's architecture implies but does not yet have. The Cell model, the DAG consensus, the RISC-V execution, the 3-dimensional mass — these are strong, well-designed foundations. What is missing is the layer that lets protocol designers think in terms of assets, pools, receipts, and lifecycles instead of syscall numbers, witness byte offsets, and raw ELF binaries.

CellScript fills that gap. It compiles to the same RISC-V that ckbvm already runs. It respects the same CellTx envelope that the network already processes. It adds safety (linearity, lifecycle enforcement) and capability (scheduler hints, typed data) without requiring any consensus-level changes.

Just as important, it should do so without:
- imposing a universal protocol-level object header on all Cells
- turning scheduler declarations into consensus law
- obscuring how source constructs lower into actual Cell operations

The language is narrow by design. It does not aspire to be general-purpose. It aspires to be the best possible language for expressing the operations that Spora was built to perform: creating assets, managing their lifecycle, ensuring their integrity, and settling their final state — all within a DAG-parallel, Cell-based, RISC-V-executed blockchain.

Build it.

---

*End of document.*
