# CellScript v0.14 Roadmap

**Date**: 2026-04-25
**Status**: Draft (Pending Team Review)
**Scope**: CKB Semantic Completeness, Source/Witness Ergonomics, and Script Composability
**Dependencies**: v0.13 released (bounded generics, zero-cost abstractions, CLI ergonomics)

---

## 📊 Executive Summary

**v0.14 Theme**: **CKB Semantic Completeness and Script Composability**

CellScript's evolution follows a deliberate maturity curve:

- **v0.12** — Production closure: proved CellScript can run on both Spora and CKB chains (43/43 actions, 7/7 examples, entry witness ABI, mutate replacement outputs, low-level time helpers, dep cell reads).
- **v0.13** — Performance and expressiveness: bounded generics, zero-cost abstractions (deserialization specialization, inlining, DCE, const propagation), CLI ergonomics.
- **v0.14** — CKB semantic completeness and composability: structured `WitnessArgs`, profile-aware `since`/epoch time constraints, explicit Source views, ScriptGroup/transaction-shape conformance, script-to-script composition via Spawn/IPC, formalized cross-chain profiles, declarative capacity syntax, and WASM simulation backend.

v0.14 closes the remaining DSL-level semantic gaps between CKB/Spora VM reality and CellScript source code: CKB witness structure, CKB epoch-based `since`, Source transaction/group views, ScriptGroup/outputs_data conformance, TYPE_ID metadata validation MVP, and Spawn/IPC. It should not re-plan v0.13 bounded generics, repeat v0.12 production evidence, or start the v0.15 primitive-kernel reset.

---

## 📋 What v0.14 Does NOT Redo

The following capabilities are already delivered and will not be re-planned:

### v0.12 Deliverables (Production Closure)

- ✅ Entry witness ABI (CSARGv1) for CellScript action/lock parameters
- ✅ Scheduler witness ABI and claim witness runtime loading/signature metadata
- ✅ secp256k1 signature verification
- ✅ MutatePattern + MutateTransitionOp (Set/Add/Sub/Append)
- ✅ type_hash / lock_hash preservation
- ✅ Low-level `ckb::input_since()` and CKB header epoch helper APIs
- ✅ Spora timelock fixtures and runtime since validation for DAA/timestamp
- ✅ Dep cell typed reads for declared `read_ref<T>` CellDep paths
- ✅ 43/43 production actions, 7/7 bundled examples deployed
- ✅ Molecule ABI manifest, metadata schema 29
- ✅ Package manager local workflow (registry fail-closed)
- ✅ LSP: JSON-RPC stdio + VS Code integration

### v0.13 Deliverables (Performance + Expressiveness)

- ✅ Bounded generics: `Vec<T: FixedWidth>`, `Option<T: FixedWidth>`, phantom asset tags
- ✅ Generic interfaces/templates: `interface FungibleToken<Asset>`
- ✅ Trait constraints: FixedWidth, Hashable, MoleculeSchema, NonLinear
- ✅ Inspectable monomorphization (`cellc explain-generics`)
- ✅ Deserialization code specialization (20-30% instruction reduction)
- ✅ Function inlining (core library math_*)
- ✅ Dead code elimination + constant propagation
- ✅ CLI: `cellc new`, `build` default O1, error codes with `cellc explain`
- ✅ Hash type DSL exposure (`with_default_hash_type`)

---

## 📋 Feature List (By Priority)

### P0 - Blocking (Must Complete in v0.14)

#### 1. Spawn/IPC Script Composition 🔴

**This is one of the core new features in v0.14.**

**Problem**: The VM layer already implements Spawn/IPC syscalls (2601-2608), but the DSL has no first-class support. Developers must drop to raw syscall numbers to compose scripts, which is error-prone, untyped, and unauditable.

**Why It Matters**: Script composition is the fundamental building block for:
- Delegate verification patterns (lock script spawns a verifier)
- Multi-step validation pipelines (hash → signature → authorization)
- Modular script architecture (shared utility scripts)
- CKB VM v2 compatibility

**DSL Design**:

**Basic spawn — launch a child script for verification**:
```cellscript
action verify_with_delegate(proof: Proof) {
    let result = spawn("secp256k1_verifier", args: [proof.pubkey, proof.signature])
    assert_invariant(result == 0, "delegate verification failed")
}
```

**Pipe composition — multi-step verification chain**:
```cellscript
action multi_step_verify(data: VerifyData) {
    let (read_fd, write_fd) = pipe()
    spawn("hash_checker", fds: [read_fd])
    pipe_write(write_fd, data.payload)
    let hash_result = wait()
    assert_invariant(hash_result == 0, "hash check failed")
}
```

**Implementation Path**:

| Layer | Change | Details |
|-------|--------|---------|
| Lexer | New keywords | `spawn`, `pipe`, `pipe_write`, `pipe_read`, `wait`, `process_id`, `inherited_fd`, `close` added to TokenKind or stdlib builtin table |
| AST | New nodes | `SpawnExpr`, `PipeExpr`, `WaitExpr` with typed fields |
| Type checker | Argument validation | Verify spawn target is string literal or const, args are byte-serializable; fd usage tracking (no double-read, no use-after-close) |
| IR | New instructions | `IrInstruction::Spawn`, `IrInstruction::Pipe`, `IrInstruction::PipeWrite`, `IrInstruction::PipeRead`, `IrInstruction::Wait`, `IrInstruction::Close` |
| Codegen | Syscall mapping | `spawn` -> 2601, `wait` -> 2602, `process_id` -> 2603, `pipe` -> 2604, `pipe_write` -> 2605, `pipe_read` -> 2606, `inherited_fd` -> 2607, `close` -> 2608 |

**Safety Constraints**:
- Max VM spawn depth enforced at compile time (configurable, default 4)
- Cycle budget allocation: shared budget model (parent + children share a total cycle limit, matching CKB's existing semantics)
- File descriptor lifetime tracking: compiler warns on leaked fds
- Spawn target resolution: must reference a known script (dep cell or inline)

**Effort**: 7-10 days
**Risk**: **MEDIUM** — Syscalls are stable; complexity is in DSL ergonomics and fd tracking
**Depends on**: v0.13 generics (for typed spawn arguments)

---

#### 2. Structured CKB WitnessArgs and Source Views 🔴

**Problem**: CellScript has entry witness bytes and claim witness loading, but CKB's standard `WitnessArgs { lock, input_type, output_type }` structure is still not a first-class DSL concept. CKB lock/type scripts also rely on precise Source selection (`Input`, `Output`, `CellDep`, `HeaderDep`, and group-scoped variants). Today this is mostly implicit in lowering.

**Why It Matters**:
- Standard lock scripts read signatures from `WitnessArgs.lock`.
- Type scripts may use `input_type` / `output_type` for protocol-specific proofs.
- Advanced scripts need to choose transaction-global vs script-group views intentionally.
- Profile-correct Source encodings differ between CKB strict mode and Spora legacy compatibility paths, so the compiler must own this boundary.

**DSL Design**:

```cellscript
lock standard_lock(pubkey_hash: Hash160) -> bool {
    let sig = witness::lock<RecoverableSignature>(source: source::group_input(0))
    let sighash = env::sighash_all(source: source::group_input(0))
    return secp256k1_verify(pubkey_hash, sig, sighash)
}

action prove_type_transition(state: &mut State) {
    let proof = witness::input_type<TransitionProof>(source: source::group_input(0))
    assert_invariant(verify_transition(proof, state), "bad transition proof")
}
```

**Implementation Items**:

| Item | Details | Days |
|------|---------|-----:|
| `source::*` DSL | `input(n)`, `output(n)`, `cell_dep(n)`, `header_dep(n)`, `group_input(n)`, `group_output(n)` with profile-correct encoding | 1 |
| `witness::*` DSL | `raw<T>`, `lock<T>`, `input_type<T>`, `output_type<T>` with CKB Molecule `WitnessArgs` decoding | 3 |
| Metadata exposure | Emit runtime access records with witness field, source view, index, ABI, and expected byte bounds | 1 |
| Profile gates | CKB profile requires `WitnessArgs` decoding for structured fields; Spora profile keeps raw/entry witness ABI unless an explicit compatibility mode is selected | 1 |
| Tests | Secp256k1-style lock fixture, type-script input/output witness fixture, source view mismatch tests | 2 |

**Effort**: 7-8 days
**Risk**: **HIGH** — This changes author-facing authentication/proof semantics and must fail closed
**Depends on**: Cross-chain Profile Formalization (#3)

---

#### 3. Cross-chain Profile Formalization 🔴

**Problem**: The dual-chain target architecture (Spora profile vs CKB profile) has existed implicitly since v0.12, but the semantics are not formally documented or enforced. Developers encounter surprising differences (BLAKE3 vs BLAKE2B domains, DAA Score vs CKB block/epoch time, since encoding, and Source group encoding) without clear guidance.

**Profile Semantic Reference**:

| Feature | Spora Profile | CKB Profile | Portable Cell |
|---------|---------------|-------------|---------------|
| Hash function | BLAKE3 + V1 domain separation | BLAKE2B | configurable |
| Time reference | DAA Score | Block Number / EpochNumberWithFraction | abstract |
| Since metric | `daa` / `timestamp` | `block_number` / `epoch` / `timestamp` | N/A |
| Script hash / identity | BLAKE3 V1 domain-separated | BLAKE2B standard | profile-declared |
| Witness structure | Raw bytes + CellScript entry/scheduler ABI | Molecule `WitnessArgs` + raw bytes fallback | explicit |
| Source encoding | Spora extended + legacy group aliases | CKB strict high-bit group flag | explicit |
| Spawn/IPC | Available | Available (VM v2+) | not available |
| Tx version | 0xC001 | 0 | N/A |

**Key Design Decision**: Spora uses DAA Score as its time abstraction. Epoch is a CKB-specific concept that does **not** exist in Spora's DAG consensus. The profile system handles this divergence cleanly — no epoch emulation in Spora profile.

**Implementation Items**:

**3a. TargetProfile Enum Specification** (1 day)
- Formalize `TargetProfile::Spora`, `TargetProfile::Ckb`, `TargetProfile::PortableCell` with complete semantic contracts
- Document which builtins, syscalls, and constraints each profile enables
- Publish as `docs/wiki/CELLSCRIPT_TARGET_PROFILES.md`

**3b. Profile-gated hash policy** (1 day)
- Keep existing hash-domain metadata explicit; do not silently make portable code depend on different hash algorithms.
- Add `hash_chain(data)` only for code that intentionally wants the active profile's canonical data hash.
- Keep explicit variants (`hash_blake3`, `hash_blake2b`) profile-gated by linked implementation availability.

**3c. Dynamic CKB BLAKE2b implementation decision** (1 day design gate)
- v0.13 scoped BLAKE2b to builder/release tooling, not a guaranteed in-script stdlib.
- v0.14 must decide whether any bundled v0.14 example truly needs dynamic in-script BLAKE2b.
- If yes, promote the real RISC-V implementation to P1 with test vectors and cycle limits; if no, defer it and reject `hash_blake2b()` in on-chain code with a precise diagnostic.

**3d. Cross-chain Script Mapping Registry Design** (1-2 days)
- Standard scripts (secp256k1, multisig, etc.) have different `code_hash` values on Spora vs CKB
- Design a registry format: `scripts.toml` mapping `(script_name, profile) → code_hash`
- Compiler resolves spawn targets and dep cell references through this registry

**Effort**: 4-6 days
**Risk**: **LOW** — Formalizing existing implicit behavior
**Depends on**: None

---

#### 4. CKB Transaction Shape and ScriptGroup Conformance 🔴

**Problem**: v0.14 Source/Witness APIs expose CKB views at the DSL level, but the compiler must also prove that emitted metadata and strict-mode checks match CKB's concrete transaction model: lock/type ScriptGroups, `outputs` ↔ `outputs_data` indexing, standard TYPE_ID creation constraints, and script reference hash types.

**Why It Matters**:
- CKB lock groups are formed from input lock scripts; type groups are formed from input and output type scripts.
- `source::group_input(n)` and `source::group_output(n)` are only meaningful relative to the active script group.
- Every `outputs_data[i]` belongs to `outputs[i]`; data obligations cannot be tracked independently from output cell indexes.
- Standard TYPE_ID has consensus-level verifier rules: args derive from the first input and output index, and the group must not contain multiple created/consumed instances.

**Implementation Items**:

| Item | Details | Days |
|------|---------|-----:|
| ScriptGroup metadata | Emit `entry_group_kind`, input/output group index sets, selected Source view, and source-to-group mapping for every CKB entry | 1 |
| Source conformance tests | Cover `Input`, `Output`, `CellDep`, `HeaderDep`, `GroupInput`, `GroupOutput`, out-of-bounds access, and wrong-profile access | 2 |
| Output data binding | Emit output-data index obligations for every create/mutate output; reject metadata where output data is detached from the output cell index | 1 |
| TYPE_ID metadata validation MVP | For `#[type_id]` under CKB profile, validate output index, first-input args source, one-input/one-output group rule, duplicate output rejection, and missing-plan rejection | 2 |
| Acceptance fixtures | Add positive/negative fixture transactions for ScriptGroup views, outputs_data mismatch, and TYPE_ID create/continue failure cases | 2 |

**Boundary**: This is not the v0.15 identity lifecycle redesign. v0.14 validates CKB transaction-shape facts and existing TYPE_ID metadata plans. It does not add new identity primitives, destruction policies, or protocol macro lowering.

**Effort**: 6-8 days
**Risk**: **HIGH** — Mis-modeling ScriptGroup or TYPE_ID behavior creates false confidence in CKB strict mode
**Depends on**: Structured CKB WitnessArgs and Source Views (#2), Cross-chain Profile Formalization (#3)

---

### P1 - Important (Strongly Recommended)

#### 5. Declarative Capacity Syntax 🟡

**Problem**: Capacity management is the most common source of CKB/Spora transaction failures. The compiler, builder, and acceptance layers expose capacity evidence, but the DSL has no declarative capacity policy — developers still reason about byte counts and change outputs outside the source contract.

**DSL Design**:

**Annotation form — compile-time static capacity floor**:
```cellscript
@capacity_floor(shannons: 6_100_000_000)  // minimum 61 CKB
resource Token has store, transfer, destroy {
    amount: u64
    symbol: [u8; 8]
}
```

**Action-level explicit capacity control**:
```cellscript
action transfer_with_fee(token: Token, fee: u64) {
    let freed_cap = consume token
    assert_invariant(freed_cap >= occupied_capacity(Token) + fee, "insufficient for fee")
    create Token { amount: token.amount } with_lock(recipient)
    // remaining capacity implicitly becomes miner fee
}
```

**Implementation Items**:

| Item | Details | Days |
|------|---------|------|
| `@capacity_floor(...)` annotation | Parser + AST attribute node + validation; support explicit shannons and compiler-computed floors | 1 |
| `occupied_capacity(T)` const fn | Compile-time constant: field sizes + overhead | 0.5 |
| Capacity floor check insertion | Compiler auto-inserts `assert(capacity >= floor)` on every `create` | 1 |
| Builder integration | Auto change-output generation when excess capacity exists | 1 |

**Effort**: 3-4 days
**Risk**: **LOW** — Additive syntax, no breaking changes
**Depends on**: Transaction Builder Integration (#10) for full change-output automation; standalone static checks can land earlier

---

#### 6. Declarative Time and Since Constraints 🟡

**Problem**: Time-based constraints (`since` encoding) differ between Spora and CKB profiles. Spora supports DAA/timestamp locks, while CKB supports block-number, epoch-with-fraction, and timestamp metrics. The low-level `ckb::input_since()` and header epoch APIs work, but they expose raw encoding details and do not express policy at the DSL level.

**DSL Design**:

```cellscript
action claim_after_timeout(htlc: HtlcReceipt) {
    require_maturity(blocks: 100)          // Spora: DAA delta; CKB: block_number delta
    require_time(after: Timestamp(target)) // Both: absolute timestamp
    require_epoch(relative: EpochFraction(10, 0, 1)) // CKB-only epoch since
    claim htlc
}
```

**Profile-gated Compilation**:

| Primitive | Spora Profile | CKB Profile |
|-----------|---------------|-------------|
| `require_maturity(blocks: N)` | Relative DAA Score since | Relative block-number since |
| `require_time(after: Timestamp(T))` | Absolute timestamp since | Absolute timestamp since |
| `require_epoch(after: EpochFraction(...))` | Compile error | Absolute epoch since |
| `require_epoch(relative: EpochFraction(...))` | Compile error | Relative epoch since |

**Implementation Items**:

- `require_maturity(blocks: N)` → AST node + profile-gated IR lowering
- `require_time(after: Timestamp(T))` → AST node + shared lowering (both profiles use timestamp)
- `EpochFraction(number, index, length)` value type with well-formedness checks and CKB `EpochNumberWithFraction` encoding
- Compiler static check: `require_time` / `require_maturity` / `require_epoch` must appear at action entry (before state mutations)
- Coexistence: `ckb::input_since()` low-level API remains available (not removed)

**Effort**: 4-5 days
**Risk**: **MEDIUM** — CKB epoch since semantics must match consensus exactly
**Depends on**: Cross-chain Profile Formalization (#3)

---

#### 7. Conditional `hash_blake2b()` Stdlib 🟡

> Tracked as part of Cross-chain Profile Formalization (#3c) but listed separately for effort accounting if promoted.

- Add `hash_blake2b()` to stdlib only if a v0.14 bundled example or CKB compatibility target requires dynamic in-script BLAKE2b.
- Must link a real RISC-V BLAKE2b implementation; stubs are forbidden.
- Must pass production gates: known test vectors, cycle reporting, and CKB profile fail-closed behavior when unavailable.

**Effort**: 3-5 days if promoted; 1 day for diagnostic/profile-gate only
**Risk**: **MEDIUM**
**Depends on**: Cross-chain Profile Formalization (#3)

---

#### 8. Script Reference and HashType Strictness 🟡

**Problem**: v0.13 exposes hash type configuration, but v0.14 CKB semantic completeness needs strict script-reference records for deployed artifacts and dep cells. A CKB script reference is not just a hash string; it is `code_hash + hash_type + args` plus the dep-cell path that makes the script loadable.

**Implementation Items**:

| Item | Details | Days |
|------|---------|-----:|
| Script reference metadata | Emit `code_hash`, `hash_type`, `args`, dep source, and resolved profile for lock/type/spawn targets | 1 |
| HashType validation | Accept only CKB-supported hash types under CKB profile; reject unknown or profile-incompatible values | 1 |
| Dep-cell linkage checks | Verify every script reference used by `spawn`, lock/type metadata, or `read_ref` has a resolvable CellDep/DepGroup path | 1 |
| Audit output | Include script reference table in generated audit docs and metadata validation errors | 1 |

**Boundary**: This does not split `Address`, `LockScript`, and `LockHash` in the type system. That is v0.15. v0.14 only makes CKB artifact references precise and auditable.

**Effort**: 3-4 days
**Risk**: **MEDIUM** — Incorrect hash_type or dep linkage can produce artifacts that look valid but cannot execute on CKB
**Depends on**: Cross-chain Profile Formalization (#3), Advanced CellDep Patterns (#11) for full DepGroup coverage

---

### P2 - Optimization (v0.14 Stretch or Later)

#### 9. WASM Script Execution Backend 🟢

**Problem**: The current WASM backend is an audit-only scaffold. Developers cannot run CellScript contracts in browsers for simulation and testing.

**Goal**: CellScript → WASM compilation for browser-side script simulation and testing.
**Non-Goal**: On-chain WASM execution. RISC-V remains the on-chain target.

**Implementation Items**:
- WASM codegen backend (parallel to existing RISC-V backend)
- Syscall shim layer: mock `spawn`, `pipe`, `read`, `write`, `wait` in JS/WASM environment
- Browser test harness: load compiled WASM, inject mock cells/witnesses, run actions
- Integration with existing `wasm/` SDK package

**Effort**: 5-8 days
**Risk**: **MEDIUM** — Syscall shimming complexity
**Depends on**: Spawn/IPC DSL (#1)

---

#### 10. Transaction Builder Language Integration 🟢

**Continued from v0.13 P2 stretch goal.**

**Problem**: Building transactions that exercise CellScript actions requires manual JSON/SDK construction. The compiler knows the full transaction shape — it should generate builder templates.

**Implementation Items**:
- `cellc build --emit-builder-template` outputs a transaction skeleton
- Builder auto-capacity planning: compute minimum capacity per output from type layout
- CellDep auto-resolution: resolve script references to dep cells from registry

**Effort**: 5-8 days
**Risk**: **HIGH** — Transaction builder correctness is critical
**Depends on**: Declarative Capacity Syntax (#5)

---

#### 11. Advanced CellDep Patterns 🟢

**Problem**: Complex scripts depend on multiple dep cells (shared libraries, data cells, verifier scripts). Current dep cell handling is manual and flat.

**Implementation Items**:
- DepGroup dynamic composition: declare a group of related dep cells
- Multi-module CellDep dependency graph: compiler resolves transitive deps
- Shared code cell version locking: pin dep cell `out_point` in manifest

**Effort**: 2-3 days
**Risk**: **LOW**
**Depends on**: None

---

## 🔧 Peripheral Tool Coordination

v0.14 introduces Spawn/IPC and profile formalization at the DSL layer. Peripheral tools need targeted updates:

| Component | Path | v0.14 Work |
|-----------|------|------------|
| **Wallet** | `wallet/` | Already supports witness/timelock/signing. v0.14: sync spawn-aware transaction construction (pass child script deps, allocate cycle budget) |
| **SDK Adaptor** | `sdk/adaptor/` | Add spawn transaction construction examples, capacity planning API |
| **WASM SDK** | `wasm/` | Sync new syscall bindings (spawn/pipe/wait/read/write/close) |
| **Standard Scripts** | `exec/src/scripts/` | Add spawn composition example scripts: delegate verifier, multi-step pipeline |
| **CLI** | `cli/` | v0.13 covered CLI enhancements. v0.14 adds `cellc spawn-test` for local spawn simulation |
| **CI** | `.github/workflows/` | Mandatory dual-profile testing for all new features |

---

## 📊 Timeline and Effort Estimates

### Summary Table

| Priority | Feature | Days | Dependencies |
|----------|---------|-----:|--------------|
| P0 | Spawn/IPC DSL | 7-10 | v0.13 generics (for typed spawn args) |
| P0 | Structured CKB WitnessArgs + Source Views | 7-8 | Cross-chain Profile (#3) |
| P0 | Cross-chain Profile Formalization | 4-6 | None |
| P0 | CKB Transaction Shape + ScriptGroup Conformance | 6-8 | WitnessArgs/Source (#2), Cross-chain Profile (#3) |
| P1 | Declarative Capacity Syntax | 3-4 | Tx Builder Integration (#10) for full automation |
| P1 | Declarative Time/Since Constraints | 4-5 | Cross-chain Profile (#3) |
| P1 | Conditional `hash_blake2b()` stdlib | 1-5 | Cross-chain Profile (#3) |
| P1 | Script Reference + HashType Strictness | 3-4 | Cross-chain Profile (#3), Advanced CellDep (#11) |
| P2 | WASM Script Backend | 5-8 | Spawn/IPC DSL (#1) |
| P2 | Tx Builder Integration | 5-8 | Capacity Syntax (#5) |
| P2 | Advanced CellDep | 2-3 | None |
| **Total P0** | | **24-32** | |
| **Total P0+P1** | | **35-50** | |
| **Total All** | | **47-69** | |

### Phased Timeline

#### Phase 1: P0 Core (5-6 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W1-2 | Spawn/IPC DSL: lexer + AST + type checker | `spawn`, `pipe`, `wait`, fd lifecycle parse and type-check |
| W2-3 | Spawn/IPC DSL: IR + codegen + safety constraints | End-to-end spawn compilation to syscalls 2601-2608 |
| W3 | Cross-chain Profile baseline | TargetProfile semantics, Source encoding contract, time/hash policy baseline |
| W3-4 | WitnessArgs + Source DSL | `witness::lock/input_type/output_type`, `source::group_input` etc. compile and fail closed |
| W4-5 | CKB transaction shape conformance | ScriptGroup metadata, outputs_data binding, TYPE_ID metadata validation fixtures |
| W5-6 | Cross-chain Profile registry + gates | Script registry, BLAKE2b decision gate, and profile docs published |

**Milestone**: v0.14.0-alpha1 (Spawn/IPC, WitnessArgs, transaction-shape conformance, and profiles usable)

#### Phase 2: P1 Enhancement (4-5 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W7 | Declarative Capacity Syntax | `@capacity_floor`, `occupied_capacity(T)`, static floor checks |
| W7-8 | Declarative Time/Since Constraints | `require_maturity`, `require_time`, `require_epoch`, profile-gated lowering |
| W8 | BLAKE2b decision gate | Either real `hash_blake2b()` with vectors/cycles or precise fail-closed diagnostic |
| W8-9 | Script Reference + HashType Strictness | CKB script reference table, hash_type validation, dep linkage checks |
| W9 | Spawn/Witness/Time/Shape examples + dual-profile CI | 5+ semantic-completeness examples, dual-profile green |

**Milestone**: v0.14.0-beta1 (All P0+P1 features complete)

#### Phase 3: P2 + Stabilization (3-4 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W10-11 | WASM Script Backend | Browser-side simulation working |
| W11-12 | Tx Builder Integration | `cellc build --emit-builder-template` with capacity planning |
| W12-13 | Advanced CellDep + peripheral sync | DepGroup, version locking, SDK/wallet updates |
| W13-14 | Regression + documentation + release | All examples updated, CHANGELOG, release |

**Milestone**: v0.14.0-rc1 → **v0.14.0 Release**

---

## 🎯 Success Metrics

### Feature Completeness

| Metric | Target |
|--------|--------|
| All 43+ production actions compile under **both** Spora and CKB profiles | ✅ Required |
| At least 2 spawn-based examples in bundled examples | ✅ Required |
| Structured `WitnessArgs.lock/input_type/output_type` examples pass under CKB profile | ✅ Required |
| Source global/group view tests pass under CKB strict and Spora extended modes | ✅ Required |
| ScriptGroup metadata matches CKB lock/type group fixtures | ✅ Required |
| `outputs` ↔ `outputs_data` binding tests reject detached or mismatched output data | ✅ Required |
| CKB TYPE_ID metadata validation covers create/continue/duplicate/missing-plan cases | ✅ Required |
| CKB `require_epoch` absolute and relative since tests match consensus encoding | ✅ Required |
| Capacity static verification covers 100% of `create` operations | ✅ Required |
| Script reference metadata includes `code_hash`, `hash_type`, `args`, and CellDep linkage | ✅ Required |
| Zero regression on v0.12 production evidence | ✅ Required |
| Profile hash policy rejects unavailable dynamic BLAKE2b cleanly | ✅ Required |
| `hash_blake2b()` passes known test vectors if promoted | Conditional |
| Profile semantic spec published | ✅ Required |

### Dual-Profile CI Gate

All features introduced in v0.14 must pass CI under both profiles:
```bash
cellc build examples/*.cell --target-profile spora   # All pass
cellc build examples/*.cell --target-profile ckb      # All pass
```

---

## 🚫 Non-Goals for v0.14

| Non-Goal | Rationale |
|----------|-----------|
| Epoch support in Spora profile | DAA Score is the correct time abstraction for DAG consensus. Epoch is CKB-specific and must not leak into Spora semantics. |
| On-chain WASM execution | RISC-V remains the on-chain target. WASM is for browser simulation only. |
| Breaking changes to existing DSL syntax | All new features are additive. Existing `.cell` files must compile without modification. |
| Primitive kernel reset | v0.15 owns protocol-macro lowering, ProofPlan unification, and core primitive redesign. |
| Moving `transfer` / `claim` / `settle` / `shared` out of the compiler core | v0.14 may improve metadata and strict-mode checks, but does not change the primitive surface. |
| `Address` / `LockScript` / `LockHash` type-system split | v0.14 records precise CKB script references; v0.15 owns semantic type separation. |
| Destruction-policy redesign | Bare `destroy` behavior is not redefined in v0.14; explicit destruction policies are v0.15 scope. |
| Formal verification | Future milestone (v0.16+). v0.14 focuses on composability, not proof. |
| `T: CellBacked` / `T: Linear` generic constraints | Deferred to v0.15+ per the phased generics plan from v0.13. |
| Full generic `HashMap<K, V>` | Remains fail-closed per v0.13 boundary. |

---

## ⚠️ Risks and Mitigations

### Risk 1: Spawn Cycle Budget Allocation 🟡

**Scenario**: Parent script spawns children that consume unbounded cycles, making total cycle cost unpredictable.

**Mitigation**: Use CKB's existing shared budget model — parent and children share a total cycle limit. The compiler emits a configurable `max_cycles` parameter on `spawn()`. Default is "inherit remaining budget". CI tests verify that spawn-heavy examples stay within expected cycle bounds.

---

### Risk 2: Profile Divergence on New Features 🟡

**Scenario**: New features (spawn, WitnessArgs, Source views, capacity syntax, time constraints) behave subtly differently across Spora and CKB profiles, creating portability bugs.

**Mitigation**: **Mandatory dual-profile CI testing**. Every new feature must include test cases for both profiles. The `cellscript-dual-chain.yml` workflow is extended to cover v0.14 features. Profile-specific behavior must be explicitly documented in the semantic reference table.

---

### Risk 3: WitnessArgs and Source View Misbinding 🔴

**Scenario**: A lock or type script reads the wrong witness slot, wrong `WitnessArgs` field, or wrong transaction/group Source view. That can turn a signature or proof check into a false positive or false negative.

**Mitigation**:
- Structured witness APIs must always include source view and index in metadata.
- CKB profile decodes Molecule `WitnessArgs` fields explicitly and rejects malformed tables.
- Tests must include mismatched global/group indexes, missing fields, extra witnesses, and wrong field placement.
- Spora profile must not pretend raw witness bytes are CKB `WitnessArgs` unless compatibility mode is explicit.

---

### Risk 4: CKB Epoch Since Semantics Drift 🔴

**Scenario**: `require_epoch` compiles but encodes or compares CKB `EpochNumberWithFraction` incorrectly, breaking DAO-style or epoch-maturity contracts.

**Mitigation**:
- Reuse CKB-compatible bit encoding and well-formedness rules in tests.
- Include absolute and relative epoch cases against fixture vectors.
- Keep `require_epoch` unavailable in Spora profile; do not emulate epoch on DAG consensus.

---

### Risk 5: Capacity Proof Completeness 🟢

**Scenario**: Compile-time capacity floor checks may be too conservative (rejecting valid transactions) or too lenient (missing edge cases like dynamic-length fields).

**Mitigation**:
- Conservative default: compiler checks based on fixed-width layout only
- Dynamic-length fields: emit runtime fallback check with compiler warning
- `@capacity_floor(...)` allows developer override when compiler estimate is insufficient
- Builder integration provides a second safety net at transaction construction time

---

### Risk 6: Dynamic BLAKE2b Scope Creep 🟡

**Scenario**: Dynamic in-script BLAKE2b becomes a default v0.14 requirement even though v0.13 explicitly scoped CKB BLAKE2b to builder/release tooling unless a concrete contract needs it.

**Mitigation**: Keep a design gate. If no v0.14 example needs dynamic BLAKE2b, only ship diagnostics/profile policy. If promoted, require real RISC-V implementation, test vectors, cycle reporting, and production gate evidence.

---

### Risk 7: WASM Syscall Shim Fidelity 🟢

**Scenario**: WASM simulation environment diverges from actual on-chain behavior, giving false confidence.

**Mitigation**: WASM shim is explicitly labeled as "simulation only". Shim implementations are tested against the same test vectors as RISC-V codegen. Known divergences (timing, cycle counting) are documented.

---

### Risk 8: ScriptGroup and Transaction Shape Drift 🔴

**Scenario**: CellScript metadata claims a group/source/output-data relation that CKB would not actually provide to the running script.

**Mitigation**:
- Test lock and type ScriptGroup fixtures against CKB-compatible resolved transaction layouts.
- Treat `outputs[i]` and `outputs_data[i]` as one indexed pair in metadata validation.
- Include negative tests for wrong group source, empty group output on lock scripts, and detached output data.

---

### Risk 9: TYPE_ID MVP Scope Creep 🟡

**Scenario**: v0.14 TYPE_ID validation turns into a full identity/lifecycle primitive redesign.

**Mitigation**: v0.14 only validates existing `#[type_id]` metadata plans and CKB transaction-shape facts. New identity policies, explicit lifecycle primitives, and destruction-policy redesign remain v0.15 scope.

---

## 📝 Integration with Existing Plans

### CELLSCRIPT_DUAL_CHAIN_PRODUCTION_PLAN.md

v0.14 **extends** the dual-chain production plan:

- ✅ Spora production gate remains 43/43+ actions
- ✅ CKB production gate remains 43/43+ actions
- ✅ 7+ bundled examples remain regression test suite (extended with spawn examples)
- ✅ Molecule ABI remains public format
- ✅ Registry remains fail-closed
- **New**: Profile semantic spec becomes a mandatory production artifact
- **New**: CKB ScriptGroup, outputs_data, and TYPE_ID validation fixtures become mandatory CKB strict-mode evidence
- **New**: Dual-profile CI becomes a release gate

### v0.13 Stretch Goals Carried Forward

| v0.13 P2 Item | v0.14 Status |
|----------------|-------------|
| Transaction Builder MVP | → v0.14 P2 (#10), extended with capacity planning |
| Loop Unrolling | Completed in v0.13 or deferred to v0.15 |
| Broader Fuzz Testing | Ongoing, not version-gated |

---

## 🚀 Quick Start

### Development Commands

```bash
# Run all CellScript tests
cargo test -p cellscript -- --test-threads=1

# Compile all examples (Spora profile)
cargo run -p cellscript -- build examples/*.cell --target-profile spora

# Compile all examples (CKB profile)
cargo run -p cellscript -- build examples/*.cell --target-profile ckb

# Test spawn simulation locally
cargo run -p cellscript -- spawn-test examples/delegate_verify.cell

# Check profile-specific compilation
cargo run -p cellscript -- explain-profile spora
cargo run -p cellscript -- explain-profile ckb
```

### New Examples to Ship with v0.14

| Example | Pattern | Features Exercised |
|---------|---------|-------------------|
| `delegate_verify.cell` | Lock script spawns external verifier | `spawn`, `wait`, `assert_invariant` |
| `multi_step_pipeline.cell` | Pipe-connected verification chain | `spawn`, `pipe`, `pipe_write`, `wait` |
| `witness_args_lock.cell` | CKB-style lock reads `WitnessArgs.lock` | `witness::lock<T>`, `source::group_input(0)`, signature verification |
| `script_group_type_transition.cell` | Type script reads group input/output views | ScriptGroup metadata, `source::group_input`, `source::group_output` |
| `ckb_type_id_create.cell` | TYPE_ID creation and rejection fixtures | `#[type_id]`, output index plan, duplicate/missing-plan validation |
| `capacity_aware_token.cell` | Token with capacity floor annotation | `@capacity_floor`, `occupied_capacity(T)` |
| `cross_chain_htlc.cell` | HTLC with profile-gated time constraints | `require_maturity`, `require_time`, `require_epoch`, dual-profile |
| `script_reference_manifest.cell` | Script reference table and dep linkage | `code_hash`, `hash_type`, `args`, CellDep/DepGroup linkage |

---

## 📅 Key Dates

| Date | Event |
|------|-------|
| 2026-04-25 | v0.14 roadmap draft |
| 2026-05-01 | Team review + priority adjustment |
| 2026-06-28 | v0.13.0 released (prerequisite) |
| 2026-08-07 | v0.14.0-alpha1 (Spawn/IPC + WitnessArgs + transaction shape + profiles) |
| 2026-09-04 | v0.14.0-beta1 (All P0+P1 complete) |
| 2026-10-02 | v0.14.0-rc1 (Feature freeze) |
| **2026-10-09** | **v0.14.0 Official Release** |

**Note**: Dates assume v0.13.0 ships on schedule (~2026-06-28). Slip in v0.13 delays v0.14 proportionally.

---

## 🎉 Summary

**v0.12 proved CellScript can run on both chains.**
**v0.13 proved CellScript runs efficiently with strong developer ergonomics.**
**v0.14 will prove CellScript scripts can compose, and the dual-chain model is formally complete.**

v0.14 delivers:

- **Composability**: First-class `spawn`/`pipe`/`wait`/fd operations in DSL, mapped to VM syscalls 2601-2608
- **CKB Semantic Completeness**: Structured `WitnessArgs`, explicit Source views, CKB epoch since, and formalized profiles (Spora/CKB/Portable)
- **CKB Transaction Conformance**: ScriptGroup metadata, outputs_data binding, TYPE_ID metadata validation MVP, and strict script-reference records
- **Declarative Safety**: `@capacity_floor`, `occupied_capacity(T)`, `require_maturity`, `require_time`, `require_epoch`
- **Hash Policy Clarity**: Profile-aware hash-domain metadata and conditional dynamic BLAKE2b support only when production-gated
- **Simulation**: WASM backend for browser-side testing (P2)

**Expected Outcomes**:
- Script composition patterns unlocked (delegate verify, multi-step pipelines)
- CKB lock/type witness patterns become source-level, typed, and auditable
- CKB transaction shape assumptions become fixture-tested instead of implicit
- Profile divergence becomes explicit instead of implicit
- Capacity-related transaction failures reduced to near zero
- Foundation laid for the v0.15 primitive-kernel reset and later formal verification

---

*Document End.*
*Date: 2026-04-25*
*Status: Draft (Pending Team Review)*
*Prerequisites*: CELLSCRIPT_0_13_ROADMAP.md, CELLSCRIPT_DUAL_CHAIN_PRODUCTION_PLAN.md
