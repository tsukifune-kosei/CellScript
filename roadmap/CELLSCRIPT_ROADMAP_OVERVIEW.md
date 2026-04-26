# CellScript Roadmap: v0.12 → v0.16
> From Production Foundation to Formal Assurance

**Status**: Living Document
**Audience**: CKB Smart Contract Developers

---

## 1. The Big Picture

CellScript's mission is to make the power of CKB's Cell model — linear resources, capacity gating, script-based verification — accessible through compile-time type safety. Each release addresses a core question in that journey.

| Version | Theme | One-liner | Status |
|---------|-------|-----------|--------|
| v0.12 | Production Foundation | "Write real CKB contracts safely" | ✅ Released |
| v0.13 | Performance & Expressiveness | "Write less, run faster" | 🚧 In Progress |
| v0.14 | CKB Semantic Completeness | "Expose CKB surface and bounded verifier reuse" | 📋 Planned |
| v0.15 | Scoped Invariants & Covenant ProofPlan | "Show when constraints run, what they read, and who they protect" | 📋 Planned |
| v0.16 | Formal Semantics & Production Tooling | "Prove, validate, deploy, and audit" | 📋 Planned |

**Evolution arc**:
- **v0.12** — *Can we use it?* Prove CellScript can compile production-grade CKB contracts.
- **v0.13** — *Is it good to use?* Make contracts smaller, faster, and the CLI friendlier.
- **v0.14** — *Is the CKB surface complete?* Cover Spawn as bounded verifier composition, WitnessArgs, Source views, ScriptGroup, outputs_data binding, TYPE_ID metadata validation, script references, capacity, and time constraints.
- **v0.15** — *Is the safety boundary auditable?* Model scoped invariants, covenant triggers, coverage, builder assumptions, and ProofPlan output without hiding lock/type semantics.
- **v0.16** — *Can we trust it in production?* Add formal semantics, ProofPlan soundness checks, standard CKB compatibility suites, transaction solving, deployment governance, and audit tooling.

---

## 2. v0.12 — Production Foundation (Released)

**What it delivered**: A production-ready compiler that turns CellScript source into optimized RISC-V ELF binaries for CKB VM, with compile-time safety guarantees no existing CKB toolchain provides.

### 2.1 Linear Type System for Cell Safety

CellScript models Cells with three type classes:

| Type Class | CKB Mapping | Capabilities |
|-----------|-------------|-------------|
| `resource` | Consumed Cell (CellInput) | `has store, transfer, destroy` |
| `shared` | Reference Cell (CellDep) | read-only, no consumption |
| `receipt` | Proof / witness artifact | one-time claim |

Compile-time safety guarantees:
- **Double-spend prevention**: Linear state tracking (`Available → Consumed / Transferred / Destroyed`) — the compiler rejects any code path that uses a Cell after consumption.
- **Branch consistency**: Both sides of an `if-else` must leave every resource in the same state.
- **Capability gating**: Only resources declaring `has destroy` can be destroyed; the compiler enforces this statically.

### 2.2 Cell Effect Operations

```cellscript
consume token                                       // consume Cell input, reclaim capacity
create Token { amount: 100 } with_lock(recipient)   // create Cell output
transfer token to recipient                         // atomic consume + create
destroy token                                       // destroy (requires destroy capability)
read_ref OracleData                                 // non-consuming read from CellDep
mutate pool { reserve_a: pool.reserve_a + delta }   // atomic in-place update
```

### 2.3 Entry Witness ABI (CSARGv1)

- Structured parameter passing via Witness field
- Serialization of scalars, fixed bytes, and schema-backed dynamic data
- CellScript entry witness ABI; structured CKB `WitnessArgs` field access lands in v0.14

### 2.4 CKB Syscall Integration

- Complete coverage of CKB VM syscalls (`load_cell`, `load_header`, `load_witness`, `load_cell_data`, etc.)
- Standard Lock Script verification (secp256k1 signature)
- Four timelock patterns: absolute/relative × block-height/timestamp

### 2.5 Production Evidence

- **43/43** production actions compiled and accepted
- **7 example contracts**: `token`, `amm_pool`, `vesting`, `timelock`, `multisig`, `nft`, `launch`
- Occupied-capacity evidence recorded per action

---

## 3. v0.13 — Performance & Expressiveness (In Progress)

**Theme**: Write less code, generate faster contracts.

### 3.1 Bounded Value-Vector Helpers (P0)

- Stack-backed `Vec<Address>`, `Vec<Hash>`, `Vec<u64>` and other fixed-width value-vector helpers
- Helps simple registries, whitelists, fixed membership sets, and AMM helper patterns
- Proof-backed maps, order books, and cell-backed collection ownership remain explicit future work
- Compile-time monomorphization with zero runtime overhead
- Value-level generics only — linear/cell-backed ownership remains explicit and fail-closed

### 3.2 Zero-Cost Abstractions (P0)

| Optimization | Expected Improvement |
|-------------|---------------------|
| Deserialization specialization | −20% ELF size |
| Function inlining (core lib) | −15% instruction count |
| Dead code elimination | −10-20% ELF size |
| Constant propagation | −5-10% instruction count |

Target: `token.elf` 15 KB → 12 KB; AMM `swap` cycles −30%.

### 3.3 CLI Ergonomics (P0)

- `cellc new` — project scaffolding (Cargo-compatible workflow)
- `cellc build` — default O1 optimization
- Error code system + `cellc explain <code>` — Rustc-style diagnostics with `codespan-reporting`
- Code formatting support (future milestone)

---

## 4. v0.14 — CKB Semantic Completeness (Planned)

**Theme**: Expose CKB's full execution surface before redesigning higher-level primitives.

### 4.1 Spawn/IPC Bounded Verifier Composition (P0)

```cellscript
// Delegate verification: Lock Script spawns a child verifier
action verify_with_delegate(proof: Proof) {
    let result = spawn("secp256k1_verifier", args: [proof.pubkey, proof.signature])
    assert_invariant(result == 0, "verification failed")
}

// Pipe-based multi-step verification chain
action multi_step_verify(data: VerifyData) {
    let (read_fd, write_fd) = pipe()
    spawn("hash_checker", fds: [read_fd])
    pipe_write(write_fd, data.payload)
    let result = wait()
    assert_invariant(result == 0, "hash check failed")
}
```

- Maps to CKB VM v2 Spawn syscalls (2601–2606)
- Type-safe inter-process communication
- Compile-time cycle budget static analysis
- Does not make a CKB cell's type script slot multi-tenant; full protocol composability remains a v0.15+ ProofPlan/scoped-invariant concern

### 4.2 Structured WitnessArgs & Source Views (P0)

```cellscript
lock standard_lock {
    let sig = witness::lock<Signature>(source: source::group_input(0))
    let proof = witness::input_type<ProofData>(source: source::group_input(0))

    let pubkey_hash = env::lock_args()
    assert_invariant(
        secp256k1_verify(pubkey_hash, sig, env::tx_hash()),
        "signature verification failed"
    )
}
```

- Function-style witness field access
- Dual source views: full Transaction view vs ScriptGroup view
- `SOURCE_GROUP_INPUT` / `SOURCE_GROUP_OUTPUT` compile-time switching

### 4.3 CKB Transaction Shape & ScriptGroup Consistency (P0)

- ScriptGroup metadata for lock/type entries
- `outputs[i]` ↔ `outputs_data[i]` binding obligations
- Source conformance fixtures for global and group views
- TYPE_ID metadata validation MVP: output index, first-input args source, group cardinality, duplicate/missing-plan rejection
- Explicit boundary: no v0.15 identity lifecycle redesign in v0.14

### 4.4 Script Reference & HashType Strictness (P1)

- CKB script reference metadata: `code_hash`, `hash_type`, `args`, dep source, resolved profile
- CKB profile rejects unsupported or profile-incompatible hash types
- Every script reference used by spawn, lock/type metadata, or `read_ref` must link to a CellDep/DepGroup path
- Audit output includes a script reference table

### 4.5 Declarative Capacity Syntax (P1)

```cellscript
@capacity_floor(61_00000000)  // minimum 61 CKB (in Shannons)
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}

action transfer_with_fee(token: Token, fee: u64) {
    let freed = consume token
    assert_invariant(freed >= occupied_capacity(Token) + fee, "insufficient")
    create Token { amount: token.amount } with_lock(recipient)
}
```

### 4.6 Declarative Time Constraints (P1)

```cellscript
action claim_after_ckb_timeout(htlc: HtlcReceipt) {
    require_maturity(blocks: 100)               // CKB block-number lock
    require_time(after: Timestamp(1714000000))  // CKB timestamp since
    claim htlc
}
```

### 4.7 Conditional hash_blake2b() Support (P1)

> **Note:** `hash_blake2b()` will be provided conditionally — only when a concrete v0.14 contract requires CKB-native BLAKE2B hashing and passes the production gate. Otherwise, the compiler will emit a profile-level diagnostic and reject on-chain usage.

- CKB-native BLAKE2B hash function (with `"ckb-default-hash"` personalization)
- Configurable hash function support: `hash_blake2b()` and `hash_blake3()` selected automatically by deployment target configuration

---

## 5. v0.15 — Scoped Invariants & Covenant ProofPlan (Planned)

**Theme**: Make CKB safety boundaries explicit instead of hiding lock/type differences.

v0.15 is not an automatic constraint-placement system. Lock and type scripts have different execution triggers and coverage models, so CellScript should expose those semantics directly:

```text
constraint = what must hold
trigger    = when the verifier runs
scope      = which cell universe it reasons over
reads      = which transaction views it observes
coverage   = which cells are actually protected
```

### 5.1 First-Class Script Semantics (P0)

```cellscript
invariant udt_amount_non_increase {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>, group_outputs<Token>

    assert sum(group_outputs<Token>.amount) <= sum(group_inputs<Token>.amount)
}
```

- `trigger = lock_group | type_group | explicit_entry`
- `scope = group | transaction | selected_cells`
- `reads = input | output | group_input | group_output | cell_dep | header_dep | witness`
- `coverage` is emitted in metadata and audit output
- `lock_group + transaction` produces a coverage warning unless explicitly acknowledged

### 5.2 Scoped Aggregate Invariants (P0)

```cellscript
assert_sum(group_outputs<Token>.amount) <= assert_sum(group_inputs<Token>.amount)
assert_conserved(Token.amount, scope = group)
assert_delta(Token.amount, delta, scope = selected_cells)
assert_distinct(outputs<NFT>.id, scope = transaction)
assert_singleton(type_id, scope = group)
```

- Every aggregate invariant must bind an explicit scope
- Field types must be fixed-width integers or fixed bytes
- Overflow and malformed cell data fail closed
- UDT, pool, settlement, and covenant helpers lower through these primitives

### 5.3 Covenant ProofPlan (P0)

`cellc explain-proof` becomes the key audit surface:

```text
constraint: udt_amount_non_increase
trigger: lock_group
scope: transaction
reads:
  - Source::Input
  - Source::Output
coverage:
  - only inputs sharing this lock script
warning:
  - Not equivalent to type-group conservation unless all relevant UDT inputs are locked by this lock.
on_chain_checked: yes
builder_assumption: none
```

ProofPlan records:

- invariant name and source span
- trigger / scope / reads / coverage
- input/output relation checks
- group cardinality
- identity lifecycle policy
- on-chain checked obligations
- builder assumptions
- codegen coverage status

### 5.4 Protocol Macros Lower Through Scoped Invariants (P0)

Protocol verbs move out of compiler-core recognizers:

- `transfer`
- `claim`
- `settle`
- `shared`
- pool/AMM flows

They become stdlib proof macros that expand into:

- kernel cell operations
- scoped aggregate invariants
- explicit ProofPlan obligations
- macro expansion provenance

### 5.5 Identity, Destroy, and Script-Type Precision (P0/P1)

v0.15 promotes identity and script semantics beyond the v0.14 metadata MVP:

- First-class cell identity policies: `ckb_type_id`, field identity, script args, singleton type
- TYPE_ID lifecycle across create / replace / destroy
- Explicit destruction policies: `destroy_unique`, `destroy_instance`, `burn_amount`, `destroy_singleton_type`
- Address type split: `Address`, `LockScript`, `LockHash`, `TypeScript`, `TypeHash`, `ScriptHash`
- Public metadata rename: `dsl_type_fingerprint` vs `ckb_type_script_hash`

### 5.6 Covenant Helper Stdlib and Migration (P1/P2)

Ergonomic helpers are allowed, but they must not perform automatic lock/type placement:

```text
lock_covenant(...)
type_invariant(...)
builder_assumption(...)
selected_cells(...)
```

Migration support:

- `--primitive-compat=0.14`
- `--primitive-strict=0.15`
- diagnostics for implicit trigger/scope, protocol capabilities, metadata-only obligations, and builder-only assumptions

---

## 6. v0.16 — Formal Semantics & Production Tooling (Planned)

**Theme**: Turn v0.15's semantic audit layer into production assurance.

v0.16 does not add another large DSL surface. It proves, validates, and operationalizes the v0.14/v0.15 model:

- formal semantics
- ProofPlan soundness checks
- CKB standard compatibility suites
- builder assumption validation
- transaction solving
- deployment governance
- audit/debug tooling

### 6.1 Formal Operational Semantics (P0)

- Formal rules for expression evaluation, linear resource states, branch merge, cell effects, lock/type triggers, scopes, and ProofPlan obligations
- Spec artifact: `docs/spec/CELLSCRIPT_OPERATIONAL_SEMANTICS.md`
- Conformance fixtures linked to compiler tests

### 6.2 ProofPlan Soundness Checks (P0)

Strict mode must prove the chain:

```text
source invariant
  -> ProofPlan obligation
  -> IR operation
  -> codegen check
  -> metadata coverage record
```

Rejected cases:

- metadata-only obligations marked as on-chain
- stale ProofPlan after optimization
- mismatched Source views
- unchecked builder assumptions
- missing emitted checks

### 6.3 Standard CKB Compatibility Suite (P0)

Compatibility fixtures for:

- sUDT / xUDT
- ACP
- Cheque
- Omnilock-compatible lock patterns
- NervosDAO-style epoch/since cases
- Type ID

Each suite covers script args, witness layout, Molecule layout, accepted/rejected transactions, cycles, and script reference metadata.

### 6.4 Builder Assumption Contract and Transaction Solver (P0/P1)

Builder assumptions become a stable machine-readable contract:

```text
assumption_id
required_inputs
required_outputs
required_cell_deps
required_witness_fields
capacity_policy
fee_policy
change_policy
signature_policy
```

Tooling:

```bash
cellc explain-assumptions
cellc validate-tx --against metadata.json tx.json
cellc solve-tx
```

The solver handles cell selection, dep resolution, output planning, occupied capacity, fee/change planning, witness placement, signing manifests, and dry-run validation.

### 6.5 Deployment Governance and Audit UX (P1)

Deployment artifacts:

- code cell manifest
- dep group manifest
- version lock file
- audit hash record
- upgrade policy
- script reference registry entry

Audit tooling:

- source maps
- proof diff
- cycle profiler per invariant/check
- tx trace viewer
- HTML audit bundle

### 6.6 Standard Library Release Track (P1)

v0.16 can ship stable stdlib modules only when they are backed by compatibility fixtures and audit bundles:

- `std::sudt`
- `std::xudt`
- `std::type_id`
- `std::htlc`
- `std::cheque`
- `std::acp`

---

## 7. Delivery Cadence

The grant proposal is the authoritative schedule. This roadmap overview defines
scope, dependencies, and release gates only; it intentionally avoids separate
dates, quarters, week counts, and effort estimates.

---

## 8. For CKB Developers: What This Means For You

**Today (v0.12)**: You can write safe CKB contracts in CellScript right now. The compiler prevents double-spend at compile time, records capacity evidence, and generates optimized RISC-V ELF binaries. Seven example contracts cover token, AMM, vesting, timelock, multisig, NFT, and launch patterns.

**Soon (v0.13)**: Your contracts will be smaller and faster. Bounded value-vector helpers make whitelists, fixed membership sets, simple registries, and AMM helper code easier to write. Proof-backed maps and order books stay explicit future work instead of being hidden inside generic collection syntax.

**Next (v0.14)**: CellScript will cover CKB's complete execution surface. Spawn/IPC enables bounded verifier reuse and delegated checks within explicit lock/type boundaries; it is not a promise of multi-tenant type-script composition. WitnessArgs, Source views, ScriptGroup, outputs_data binding, TYPE_ID metadata validation, script references, Capacity, and time constraints become explicit and testable.

**Future (v0.15)**: CellScript becomes a semantic auditing layer for CKB transaction invariants. It does not hide lock/type differences; it shows when each invariant runs, what it reads, which cells it protects, which obligations are checked on-chain, and which are builder assumptions.

**After that (v0.16)**: CellScript turns those visible semantics into production assurance. It checks ProofPlan soundness, validates transactions against builder assumptions before signing, ships CKB compatibility fixtures, and produces audit bundles that link source, proof, generated code, metadata, and cycles.

---

## 9. Appendix: CKB Concept Mapping

| CKB Concept | CellScript Primitive | Since |
|-------------|---------------------|-------|
| Cell (UTXO) | `resource` / `shared` / `receipt` | v0.12 |
| Lock Script | `lock { ... }` block | v0.12 |
| Type Script | implicit via `action` | v0.12 |
| CellInput (consume) | `consume expr` | v0.12 |
| CellOutput (create) | `create T { ... } with_lock(addr)` | v0.12 |
| CellDep (read) | `read_ref T` | v0.12 |
| Witness | Entry Witness ABI (CSARGv1) | v0.12 |
| OutPoint | Implicit via `consume` (input) / `create` (output) | v0.12 |
| Capacity (Shannon) | `occupied_capacity(T)` + freed capacity | v0.12 |
| WitnessArgs | `witness::lock<T>()` / `witness::input_type<T>()` | v0.14 |
| `@capacity_floor` | `@capacity_floor(shannons)` annotation | v0.14 |
| Since (timelock) | `require_maturity` / `require_time` | v0.14 |
| ScriptGroup | explicit group metadata + Source views | v0.14 |
| outputs_data | output-data index binding obligations | v0.14 |
| TYPE_ID metadata | CKB TYPE_ID create/continue validation MVP | v0.14 |
| Spawn | `spawn("verifier", args: [...])` | v0.14 |
| hash_type | `hash_type(Data1)` / `with_default_hash_type(Data1)` DSL | v0.13 |
| code_hash | script reference metadata with `code_hash + hash_type + args` | v0.14 |
| Scoped invariant | `invariant { trigger; scope; reads; assert ... }` | v0.15 |
| Lock covenant | `trigger: lock_group`, explicit reads and coverage diagnostics | v0.15 |
| Type invariant | `trigger: type_group`, group-scoped invariants | v0.15 |
| ProofPlan | `cellc explain-proof` trigger/scope/reads/coverage report | v0.15 |
| Builder assumption | `builder_assumption(...)` marked as not on-chain checked | v0.15 |
| TypeID lifecycle | `identity ckb_type_id`, `preserve_identity`, `destroy_unique` | v0.15 |
| Formal semantics | operational semantics spec + conformance fixtures | v0.16 |
| Proof soundness | ProofPlan-to-code coverage checker | v0.16 |
| Standard compatibility | CKB standard script fixture suites | v0.16 |
| Transaction solving | `cellc solve-tx` / `cellc validate-tx` | v0.16 |
| Deployment governance | deploy plan, dep locks, proof diff, audit bundle | v0.16 |

---

*Document End.*
*Status: Living Document*
