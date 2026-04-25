# CellScript v0.13 Roadmap

**Date**: 2026-04-24  
**Status**: Draft (Pending Team Review)  
**Scope**: Zero-cost Abstractions, Bounded Collection Runtime Gaps, CLI Ergonomics
**Dependencies**: v0.12 released (dual-chain production closure)
**Live TODO**: [CELLSCRIPT_0_13_TODOLIST.md](CELLSCRIPT_0_13_TODOLIST.md)

---

## 📊 v0.12 Achievements

v0.12 achieved **production-grade dual-chain support**:

- ✅ Spora production gate: 43/43 actions, 7/7 examples deployed
- ✅ CKB production gate: 43/43 actions on-chain, 0 expected fail-closed
- ✅ Molecule ABI: schema manifest complete, metadata schema 29
- ✅ Backend shape gates: code size/branch/CFG metrics published
- ✅ Package manager: local workflow complete, registry fail-closed
- ✅ LSP: JSON-RPC stdio + VS Code LanguageClient integration
- ✅ Constraints reporting: capacity/cycles/mass/hash_type all exposed

**v0.12 Core Achievement**: **Proved CellScript can run production on both chains.**

---

## 🎯 v0.13 Core Objectives

**v0.13 Theme**: **Make CellScript faster, stronger, and more usable.**

From "can run" to "runs well", from "feature-complete" to "excellent UX".

### Three Pillars

1. **Zero-Cost Abstractions** - Eliminate known runtime overhead (30-40% perf improvement)
2. **Collections Generics** - Unlock complex protocol development (AMM/Registry/OrderBook)
3. **Developer Experience** - CLI ergonomics, diagnostic presentation, and DSL features

---

## 📋 Feature List (By Priority)

### P0 - Blocking (Must Complete in v0.13)

#### 1. Bounded Generics for CKB Design Patterns 🔴

**Philosophy**: **Generic patterns, not unconstrained generics.**

> "Generics that serve design patterns are valuable; generics that hide cell ownership are disastrous."

**Problem**: 0.12 supports several schema/ABI dynamic vector paths, but runtime
collection helpers and cell-backed collection ownership remain intentionally
bounded. `Vec<Address>` can be declared and used for documented Molecule
dynamic-field and entry-witness paths; the remaining gap is generic executable
runtime support such as `HashMap<Hash, Order>`, `HashSet<Address>`, local
`Vec<T>` operations beyond the verified paths, and verifier-backed ownership for
cell-backed `Vec<Resource>` values.

**Real Demand Analysis**:

**Actual Usage in Bundled Examples**:
```cellscript
// timelock.cell - Line 55
approvers: Vec<Address>,  // ✅ Used in production example

// multisig.cell - Line 29, 72
signers: Vec<Address>,    // ✅ Used in production example

// multisig.cell - Line 45
signatures: Vec<Signature>,  // ✅ Custom struct vector

// nft.cell
attributes: Vec<(String, String)>,  // ✅ Tuple vector
```

**Industry Comparison**:
- **Sway (Fuel)**: ✅ Full generics (structs, enums, functions, traits)
- **Move (Sui/Aptos)**: ✅ Full generics + phantom types (`Coin<phantom T>`)
- **CellScript**: ⚠️ Partial (schema/ABI paths only, not runtime operations)

**Why CellScript Cannot Copy Sway/Move Directly**:

CKB/Spora's core is **NOT** account storage or native object packages. It's:
- cell transition / lock-type script / witness / builder / deployment identity

**Generic risks specific to CellScript**:

1. **Resource semantics erasure** 🔴
   - `Vec<u64>` / `Vec<Hash>` / `Vec<Address>` ✅ Safe (value types)
   - `Vec<Cell<T>>` / `HashMap<Hash, Token>` / `Option<LinearAsset<T>>` 🔴 Dangerous
   - Questions: Who owns? Who consumes? Are all resources in collection transferred/destroyed?

2. **Opaque lowering** 🔴
   - Generic `transfer<T>()` is dangerous if some `T` lowers to lock, some to type, some to witness
   - Must maintain **inspectable lowering** (per discussion with Matt)

3. **Codegen/ABI explosion** 🔴
   - Monomorphization for `T = Address/Hash/Pool/Token/Vec<u8>` creates code bloat
   - Impacts: code size, cycles, branch distance, witness layout, schema commitments
   - Recent branch relaxation/codegen bloat issue (Jan's review) shows this risk is real

4. **Ecosystem standardization too early** 🟡
   - If 0.12 claims "generic collections supported", it becomes a promise
   - 0.12 plan correctly bounded: `Vec<u8>`, `Vec<Address>` schema/ABI dynamic types OK;
     runtime collection helpers NOT fully generic; cell-backed collection ownership must fail-closed

**CKB/Spora Need**:
- ✅ **CKB**: Multisig/timelock need `Vec<Address>` schema/ABI support and local helper parity for common value-vector patterns
- ✅ **Spora**: AMM/Registry/OrderBook need bounded executable collection patterns (`Vec<Hash>`, `Vec<Address>`, fixed-width values, and explicit map-like representations), not full generic `HashMap<K, V>`
- ⚠️ **CKB raw scripts**: Usually rely on Rust -> RISC-V generics; CellScript must expose bounded patterns explicitly instead of inheriting unconstrained Rust generics

**v0.13 Goal**: **Bounded generics / reusable pattern layer**, NOT full Rust/Sway-style generics.

> "0.13 引入受限泛型，用来复用 CKB 设计模式，但不把 cell-backed / linear ownership 问题偷偷藏进泛型里。"

**What v0.13 WILL do** (bounded generics):

**1. Value-level generics only** (no linear ownership)
```cellscript
fn require_eq<T: FixedWidth>(a: T, b: T)
fn contains<T: FixedWidth>(xs: Vec<T>, x: T) -> bool
```
Supported types:
- `u8`, `u64`
- `Hash`
- `Address`
- fixed bytes
- simple ABI/schema-backed values

**DOES NOT support**: `T: CellBacked` or `T: Linear`

---

**2. Phantom-style asset tags** (Move-inspired, CKB-native)
```cellscript
resource Token<phantom Asset>
```
Use cases:
```cellscript
Token<USDI>
Token<MyDAO>
Token<LPToken>
```
Benefits:
- Helps UDT / xUDT / custom asset patterns
- Does NOT require generic runtime collections fully working

---

**3. Generic interfaces / templates** (most valuable for 0.13)
```cellscript
interface FungibleToken<Asset>
interface Pool<TokenA, TokenB>
interface Timelock<Asset>
```
Benefits:
- Directly serves cookbooks / AI-assisted workflows / reusable CKB patterns
- More valuable than generic functions

---

**4. Minimal trait constraints**

**Allowed in 0.13** (with explicit definitions):

```text
FixedWidth:     value has statically known ABI width.
Hashable:       value has a canonical hash representation.
MoleculeSchema: value has a schema-backed serialization layout.
NonLinear:      value does not carry consume/transfer/destroy obligations.
```

**Why NonLinear is critical**: It is the safety valve that separates generics from ownership semantics. Without it, `Vec<T>` could accidentally become `Vec<LinearResource<T>>`, blurring consumption/transfer boundaries.

**NOT allowed in 0.13** (too risky, drags into ownership/builder verification):
```
Consumable
CellBacked
Store
ResourceCollection
```

---

**5. Bounded generic collections**
Current branch status after the first 0.13 collection-runtime patches:
- `Vec::new`, `with_capacity`, `capacity`, `push`, `extend_from_slice`, `len`, `first`, `last`, indexing, `set`, `remove`, `pop`, `insert`, `reverse`, `truncate`, `swap`, `clear`,
  `is_empty`, and `contains` execute for stack-backed value vectors where the
  element width is known (`u64`, fixed bytes, `Address`, `Hash`, and fixed-width
  schema values covered by existing fixed-width machinery).
- `Vec<Address>` / `Vec<Hash>` Molecule dynamic fields and entry-witness payloads
  are v0.12 foundations, not new v0.13 scope.
- Cell-backed / linear collection ownership remains explicit and fail-closed.

Compact support matrix:

| Source / element category | `len` / `is_empty` / index / `first` / `last` | local stack mutation helpers | removal / reordering helpers | Status |
|---|---:|---:|---:|---|
| Stack-backed `Vec<u64>` | ✅ | ✅ | ✅ | 0.13 implemented and tested |
| Stack-backed fixed bytes / `Address` / `Hash` | ✅ | ✅ | ✅ | 0.13 implemented and tested, including fixed-byte `remove` |
| Stack-backed fixed-width schema values | 🟡 | 🟡 | 🟡 | supported where fixed-width layout is known; release-gate coverage still needed |
| Molecule dynamic fields / entry-witness vectors | ✅ read-oriented paths | ❌ local mutation helpers | ❌ local mutation helpers | 0.12 foundation; not counted as new 0.13 generic runtime |
| Cell-backed / linear vectors | ❌ | ❌ | ❌ | fail-closed until ownership proof exists |

Implemented in the current branch for checked stack-backed fixed-width
collection helper paths:
```cellscript
Vec<T: FixedWidth>
```

Runtime and constraints metadata expose each concrete `Vec<T>` instance with
scope, element type/width, fixed backing capacity, status, and helper set.

`Option<T: FixedWidth>` remains an investigation item, not a current 0.13
release claim.

**NOT supported in 0.13** (continue fail-closed or experimental):
```cellscript
Vec<Cell<T>>
HashMap<Hash, Token<T>>
Vec<Linear<T>>
HashMap<K, V>  // full generic
```

---

**What v0.13 WILL NOT do**:

- ❌ arbitrary generic collections
- ❌ generic linear resources  
- ❌ generic cell-backed maps
- ❌ higher-order trait jungle
- ❌ fancy type inference
- ❌ `T: CellBacked` / `T: Linear` constraints
- ❌ full generic `HashMap<K, V>`
- ❌ `Vec<Cell<T>>` / `HashMap<Hash, Resource<T>>`

---

**6. Inspectable monomorphization** (MANDATORY - Release Gate)

**Release gate requirement**:
> 0.13 must expose every generic instantiation in ABI/metadata/constraints output.
> No generic instantiation may silently change witness layout, schema commitment, or lock/type lowering.

**Core principle**: 
> **We support generics without hiding what they become on-chain.**

**Mandatory tooling**:
```bash
cellc explain-generics    # Show what T instantiates to
cellc abi                 # Show witness ABI changes
cellc constraints         # Show code size impact
```

**Must expose**:
- What `T` was instantiated to
- Which specialized functions were generated
- How witness ABI changed
- How schema hash / ABI hash changed
- How much code size increased
- Which generic instantiations were rejected

**Otherwise generics will break inspectability** (a core CellScript principle).

**v0.13 Character**:
> reusable patterns, visible lowering, bounded ownership semantics.

**Translation**: 
> Not "adding generics to show off", but "adding reusable templates for CKB design patterns".

This aligns with AI-assisted workflows / cookbooks: AI needs **bounded cookbook primitives**, not unrestricted generics.

---

**v0.12 Boundary** (from `CELLSCRIPT_0_12_COMPREHENSIVE_PLAN.md`):
> "0.12 does not claim full generic `HashMap<K, V>` runtime support."
> "Kept generic runtime collection support bounded and explicit."
> "0.12 does not claim complete linear ownership for cell-backed collections."

**Impact**:
- ❌ Cannot implement Registry address mappings as executable `HashMap<Address, Entry>`
- ❌ Cannot implement Order Book order lists as generic runtime maps/lists
- ❌ Cannot return or mutate `Vec<Resource>` without a linear collection ownership model
- ❌ Cannot claim production support for unsupported generic helpers without fail-closed metadata

**Effort**: 7-10 days  
**Risk**: **HIGH** (but bounded - see strategy below)

**Risk Assessment**:

**Risk 4: Generics May Break Cell/Resource Semantics** 🔴

**Scenario**: Generic collections blur ownership boundaries:
```cellscript
// Dangerous: Who owns these cells?
Vec<Cell<T>>    → Each cell must be consumed/transferred
HashMap<Hash, Token<T>>  → What happens on hash collision?
Option<LinearAsset<T>>  → Is the asset consumed when None?
```

**Mitigation**: **Strictly bounded to value-level generics in 0.13**
- ✅ stack-backed fixed-width `Vec<T>` helper patterns - Safe when `T` has no ownership obligations
- ✅ `Vec<Address>`, `Vec<Hash>` - Safe (value types)
- ❌ executable `Vec<Cell<T>>` / `Vec<Resource<T>>` ownership semantics - NOT supported in 0.13; must remain fail-closed
- ❌ `T: Linear` constraints - NOT supported in 0.13 source semantics

---

**Risk 5: Generic Lowering Becomes Opaque** 🔴

**Scenario**: `transfer<T>()` hides too much magic:
- Some `T` lowers to lock script
- Some `T` lowers to type script  
- Some `T` depends on builder
- Some `T` depends on witness ABI

**Per discussion with Matt**: "language should not hide too much magic"

**Mitigation**: **Mandatory inspectable lowering**
```bash
cellc explain-generics  # Show exactly what T lowers to
cellc abi               # Show witness ABI changes
```

---

**Risk 6: Codegen/ABI Explosion** 🔴

**Scenario**: Monomorphization creates too many specialized versions:
```cellscript
Vec<Address>    → vec_address_push/pop/len
Vec<Token>      → vec_token_push/pop/len
Vec<Signature>  → vec_signature_push/pop/len
Vec<Pool>       → vec_pool_push/pop/len
...
```

**Impact**:
- ELF size increase: 2-3x per type instantiation
- Compile time increase: 1.5-2x
- Audit difficulty: Each monomorphized instance needs verification
- **Recent branch relaxation/codegen bloat issue (Jan's review) shows this risk is real**

**Mitigation**:
1. **Minimal trait constraints** (only 4 in 0.13: FixedWidth, Hashable, MoleculeSchema, NonLinear)
2. **Monomorphize only actually used types** (not all possible types)
3. **Use DCE to eliminate unused instances** (v0.13 P1 feature #6)
4. **Set monomorphization count limit** (warn at 5, fail at 10)
5. **Consider type-erased collections** for simple operations (push/pop/len)

---

**Risk 7: Ecosystem Standardizes Too Early** 🟡

**Scenario**: If 0.13 claims "generic collections supported", it becomes a promise that's hard to change.

**Mitigation**: **Clear boundary documentation**
- ✅ Document what's supported: current stack-backed fixed-width `Vec<T>` helper paths and any later explicitly implemented `Vec<T: FixedWidth>` metadata
- ✅ Document what's NOT supported: `Vec<Cell<T>>`, `HashMap<K, V>`
- ✅ Continue fail-closed for unsupported generic patterns
- ✅ Explicit metadata for bounded generic support

---

**Phased Approach** (Recommended):

**Phase 1 (v0.13)**: Value-level generics only
- current stack-backed fixed-width `Vec<T>` helper paths
- `Vec<T: FixedWidth>` monomorphization metadata for checked stack-backed helper paths with explicit constraints output
- Phantom-style asset tags (`Token<phantom Asset>`)
- Generic interfaces/templates (`interface FungibleToken<Asset>`)
- Minimal trait constraints (FixedWidth, Hashable, MoleculeSchema, NonLinear)
- `Option<T: FixedWidth>` remains an investigation item unless implemented and tested before release

**Phase 2 (v0.14)**: Interface/package-level generics
- Generic interfaces with more constraints
- Schema-level type parameters
- Move-style phantom types for CKB-native asset patterns

**Phase 3 (v0.15+)**: Constrained generics with capabilities
- `T: CellBacked` (only after ownership model is mature)
- `T: Consumable` (only after builder verification is stable)
- `T: Store` (only after linear ownership is proven)

**Phase 4 (Future)**: Linear/cell-backed collection generics
- `Vec<Cell<T>>` / `HashMap<Hash, Resource<T>>`
- Must wait for: ownership model, consume_each, membership proof, builder verification, witness proof

**v0.13 One-Sentence Goal**:

> CellScript 0.13 introduces bounded generics for reusable CKB design patterns, while keeping linear/cell-backed ownership explicit and fail-closed.

---

#### 2. Deserialization Code Specialization 🔴

**Problem**: Compiler knows type layouts at compile-time, but codegen computes offsets at runtime.

**v0.12 Boundary**: Not mentioned in 0.12 scope - genuine new feature.

**Current Overhead**: 2-3 extra instructions per field access (20-30% instruction waste).

**Expected Benefits**:
- 20-30% instruction reduction
- 10-15% ELF size reduction
- 15-25% cycle reduction

**Effort**: 3-4 days  
**Risk**: Low (compile-time optimization only)

---

#### 3. CLI Ergonomics Improvements 🟡

**Problem**: Multiple CLI UX gaps affecting developer experience.

**Current branch status**: `cellc init` already exists from 0.12. The 0.13
branch now has O1 dev-build defaults and a Cargo-style `cellc new` workflow
with `--vcs git|none`; `--lib` package creation now writes `src/lib.cell` into
`Cell.toml` and does not leave a stale `src/main.cell` entry file. Remaining
work is diagnostic presentation polish on top of the existing runtime error
registry.

**Sub-tasks**:

**3a. Change `build` Default to O1** ✅
```rust
// Current
let opt_level = if args.release { 3 } else { 0 };  // O0 default

// Change to
let opt_level = if args.release { 3 } else { 1 };  // O1 default
```

**Impact**: Potentially more representative dev builds. The previous 30-40% speedup claim needs benchmark evidence before it is used as a release target.

---

**3b. Add `cellc new` Subcommand / Cargo-Compatible Init Workflow** ✅
```bash
cellc new my_project      # Create a new project, including git initialization when requested
cellc init my_project     # Already exists in 0.12; preserve and document compatibility
```

**Implemented behavior**: `cellc new` creates a package directory, supports
`--path`, `--lib`, `--vcs git`, `--vcs none`, and JSON summaries. `cellc init`
compatibility is preserved without double-counting the original 0.12
scaffolding implementation.

---

**3c. Improve Error Messages with Codes** (3-5 days)
```bash
# Current
error: fixed-byte comparison unresolved

# Target
error[E0018]: fixed-byte comparison unresolved
   --> examples/token.cell:15:5
    |
15  |     assert_invariant(a.symbol == b.symbol, "symbol mismatch")
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: use schema-backed parameters or fixed-byte values that the verifier can address
    = note: runtime error code 18, see docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md
```

**Implementation**:
- Use `codespan-reporting` crate
- Add CLI diagnostic codes (E0001, E0002, ...) that map to the existing runtime error registry where applicable
- Add `cellc explain <error-code>` subcommand

**Impact**: 5x debug experience improvement

---

**Total CLI Effort**: 5-7 days  
**Risk**: Low

---

### P1 - Important (Strongly Recommended)

#### 4. Function Inlining (Core Library) 🟡

**Problem**: `math_min/max/isqrt` compiled as function calls (6-10 instruction overhead).

**v0.12 Boundary**: From `CELLSCRIPT_0_12_COMPREHENSIVE_PLAN.md`:
> "a large optimizer pass suite" is explicitly a 0.12 non-goal.

**Expected Benefits**: 10-15% instruction reduction for compute-heavy contracts.

**Effort**: 2-3 days  
**Risk**: Low

---

#### 5. Hash Type DSL Exposure 🟡

**Problem**: CKB `hash_type` visible in constraints/metadata but not directly expressible in DSL.

**v0.12 Status**: v0.12 added `deploy.ckb.hash_type` in manifest (Track B), but NOT DSL-level declaration.
**This is a genuine enhancement**, not overlap.

**Target Syntax**:
```cellscript
create Token { amount: 100 }
with_lock(addr)
hash_type(Data1)

resource Token has store, transfer, destroy
with_default_hash_type(Data1)
{
    amount: u64,
}
```

**Effort**: 2-3 days  
**Risk**: Low

---

#### 6. Dead Code Elimination (DCE) 🟡

**Problem**: Unused variables/functions still compiled into ELF.

**v0.12 Boundary**: Not mentioned in 0.12 scope - genuine new feature.

**Expected Benefits**: 10-20% ELF size reduction.

**Effort**: 3-5 days  
**Risk**: Medium

---

#### 7. Compile-time Constant Propagation 🟡

**Problem**: `const X = 1; X + 2` doesn't fold to `3`.

**v0.12 Boundary**: Not mentioned in 0.12 scope - genuine new feature.

**Expected Benefits**: 5-10% instruction reduction.

**Effort**: 2-3 days  
**Risk**: Low

---

### P2 - Optimization (v0.13 Stretch or v0.14)

#### 8. Loop Unrolling (Small Loops) 🟢

**v0.12 Boundary**: Not mentioned in 0.12 scope - genuine new feature.

**Effort**: 2-3 days  
**Risk**: Low

---

#### 9. Action Transaction Builder MVP 🟢

**Source**: Dual-chain plan Phase C.

**v0.12 Status**: Not implemented in 0.12 - genuine new feature.

**Effort**: 5-8 days  
**Risk**: High

---

#### 10. Broader Malformed/Fuzz Testing 🟢

**Source**: Dual-chain plan Phase F.

**v0.12 Status**: v0.12 has basic malformed matrix (43/43 actions), but not broader fuzzing.
**This is an enhancement**, not overlap.

**Effort**: 5-7 days  
**Risk**: Medium

---

## 📊 Timeline Estimates

### Phase 1: P0 Core (4-5 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W1-2 | Collections Generics | Generic stdlib + monomorphization + tests |
| W2 | CLI: `build` default O1 + `cellc new` | Immediate UX improvement |
| W3 | Deserialization Specialization | Type layout cache + codegen specialization |
| W3-4 | CLI: Error Codes + `explain` | `codespan-reporting` integration |

**Milestone**: v0.13.0-alpha1 (Collections generics usable)

---

### Phase 2: P1 Enhancement (2-3 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W6 | Function Inlining | math_* inlining + AMM perf test |
| W6-7 | Hash Type DSL | AST/IR/codegen full chain + CKB test |
| W7-8 | Dead Code Elimination | DCE pass + ELF size benchmark |
| W8 | Constant Propagation | Cross-statement constant folding |

**Milestone**: v0.13.0-beta1 (Performance optimizations complete)

---

### Phase 3: P2 + Stabilization (3-4 weeks)

| Week | Task | Deliverable |
|------|------|-------------|
| W9-10 | Loop Unrolling | Small loop unrolling + tests |
| W10 | Transaction Builder MVP | `cellc action build` plan/explain |
| W11 | Fuzz/Adversarial Testing | Broader malformed matrix |
| W11-12 | Regression Tests | All bundled examples updated |
| W12-13 | Documentation + Release | CHANGELOG + release announcement |

**Milestone**: v0.13.0-rc1 → **v0.13.0 Release**

---

## 🎯 Success Metrics

### Performance Metrics (vs v0.12)

| Metric | v0.12 Baseline | v0.13 Target | Improvement |
|--------|---------------|--------------|-------------|
| Token ELF Size | ~15 KB | ~12 KB | **-20%** |
| AMM ELF Size | ~25 KB | ~18 KB | **-28%** |
| Token Instructions | ~500 | ~350 | **-30%** |
| AMM `swap` Cycles | ~10,000 | ~7,000 | **-30%** |
| Debug Time | 1 hour | 5 minutes | **-92%** |

---

### Feature Metrics

| Feature | v0.12 | v0.13 |
|---------|-------|-------|
| Collections Runtime / Bounded Generics | 🟡 Schema/ABI vectors supported; runtime helpers bounded | 🟡 Stack-backed value Vec helpers are being implemented; broader bounded generics remain explicit, metadata-visible follow-up work |
| Error Code Docs | ✅ Registry only | ✅ CLI + docs |
| Hash Type Visibility | 🟡 Manifest only | ✅ DSL declarative |
| Deserialization Overhead | ❌ Runtime compute | ✅ Compile-time specialize |
| Function Inlining | ❌ None | ✅ Core lib |
| Dead Code Elimination | ❌ None | ✅ Functions + vars |
| CKB Blake2b Compiler/CLI | ✅ Builder/release helper complete | ✅ Keep complete; document boundary |
| Generic in-script CKB Blake2b | ❌ Not claimed | ⏸️ P3 conditional |
| CLI `cellc new` | 🟡 `cellc init` foundation existed | ✅ Cargo-compatible workflow implemented and tested |
| CLI Error Messages | 🔴 Unfriendly | ✅ Rustc-style |

---

## ⚠️ Risks and Mitigations

### Risk 1: Collections Generics Monomorphization Causes ELF Bloat

**Scenario**: `HashMap<Hash, Order>` + `HashMap<Address, Entry>` + `HashSet<Address>` generates multiple helper instances.

**Mitigation**:
- Only monomorphize actually used types
- Use DCE to eliminate unused monomorphized instances
- Set monomorphization count limit (warn)

---

### Risk 2: Generic In-script CKB Blake2b Is Mistaken for a v0.13 Requirement

**Scenario**: The existing builder/release helper is confused with a missing on-chain stdlib requirement.

**Mitigation**:
- Current bundled examples do not require generic dynamic in-script Blake2b.
- CKB identity checks use `type_hash()` and `lock_hash()` where appropriate.
- Compiler and CLI CKB Blake2b helper tools are already complete for builder/release evidence.
- Keep generic in-script Blake2b as P3 conditional work: only implement it when a concrete contract needs it, and require a real RISC-V Blake2b implementation plus production-gate coverage.

---

### Risk 3: Optimizer Complexity Increases Compile Time

**Scenario**: 5 new optimization passes doubles compile time.

**Mitigation**:
- Make optimization passes configurable (`opt_level`)
- Default `opt_level=1` (only critical optimizations)
- `opt_level=2` enables all optimizations
- Set compile time upper bound (warn)

---

## 📝 Integration with Existing Plans

### CELLSCRIPT_DUAL_CHAIN_PRODUCTION_PLAN.md

v0.13 **does not change** dual-chain production plan, only enhances it:

- ✅ Spora production gate remains 43/43 actions
- ✅ CKB production gate remains 43/43 actions
- ✅ 7 bundled examples remain regression test suite
- ✅ Molecule ABI remains public format
- ✅ Registry remains fail-closed (v0.13 doesn't touch)

**v0.13 New Deliverables**:
- `examples/registry.cell` - Exercises executable address membership/mapping beyond the 0.12 schema-vector boundary
- `examples/order_book.cell` - Uses `HashMap<Hash, Order>` or an explicitly verifier-backed map representation
- Performance benchmark reports
- CLI diagnostic presentation backed by existing runtime error documentation

---

### CLI_ERGONOMICS_AND_BLAKE2B_AUDIT.md

All audit findings integrated into v0.13 roadmap:

**CLI Improvements** (Section 3):
- ✅ Change `build` default to O1
- ✅ Add `cellc new` subcommand
- ✅ Improve error messages with codes
- ✅ Add `cellc explain` subcommand

**CKB Blake2b Boundary**:
- ✅ CKB Blake2b helper correctly scoped to builder/release CLI and Rust tooling (complete)
- ⏸️ Generic in-script CKB Blake2b is not claimed for v0.13 unless a concrete contract requires it

---

## 🚀 Quick Start

### How Developers Can Contribute

1. **Collections Generics** - Review `stdlib/collections.rs`, contribute runtime helper monomorphization and ownership logic
2. **CLI Improvements** - Add `cellc new`, integrate `codespan-reporting`
3. **Performance Benchmarks** - Run `scripts/benchmark_cellscript.sh` (TBD)
4. **New Examples** - Extend `examples/registry.cell` to test bounded executable collection patterns (`Vec<Address>`/`Vec<Hash>` helpers and explicit map-like representations)

### Test Commands

```bash
# Run all tests
cargo test -p cellscript -- --test-threads=1

# Run performance benchmarks
cargo bench -p cellscript

# Compile all examples
cargo run -p cellscript -- build examples/*.cell --target-profile ckb

# Check ELF sizes
ls -lh examples/*.elf

# Verify existing CKB hash helper (not mandatory v0.13 on-chain scope)
cargo run -p cellscript -- ckb-hash --hex 00
```

---

## 📅 Key Dates

| Date | Event |
|------|-------|
| 2026-04-24 | v0.13 roadmap draft + audit findings |
| 2026-05-01 | Team review + priority adjustment |
| 2026-05-15 | v0.13.0-alpha1 (Collections generics) |
| 2026-06-01 | v0.13.0-beta1 (Performance optimizations) |
| 2026-06-22 | v0.13.0-rc1 (Feature freeze) |
| **2026-06-28** | **v0.13.0 Official Release** |

**Note**: Release date delayed by ~1 week vs original plan due to CLI improvements.

---

## 📊 Updated Effort Summary

**Original Plan**:
- Total effort: ~60 days
- Release date: 2026-06-22

**Updated Plan**:
- CLI improvements: +5-7 days (new + explain + error messages)
- BLAKE2b: no mandatory v0.13 on-chain stdlib work; generic in-script CKB Blake2b remains P3 conditional
- **New total: ~66 days**
- **New release date: 2026-06-28** (delayed by ~1 week)

---

## 🎉 Summary

v0.13 goal: Evolve CellScript from "**can run in production**" to "**excellent in production**":

- **Faster**: 30-40% performance improvement (zero-cost abstractions)
- **Stronger**: Collections generics unlock complex protocols
- **More Usable**: CLI ergonomics + error codes + declarative syntax

**Expected Outcomes**:
- Developer experience improved 50% (debug time 1 hour → 5 minutes)
- Execution cost reduced 30% (cycle consumption)
- Deployment cost reduced 20% (ELF size)
- Support complex protocols (AMM/Registry/OrderBook)

**v0.12 proved CellScript can run on both chains.**  
**v0.13 will prove CellScript is the best production-grade smart contract language.**

---

## 🔍 v0.12/v0.13 Overlap Audit

**Audit Date**: 2026-04-24  
**Audit Scope**: Strict comparison of v0.13 features vs v0.12 accepted deliverables  
**Source Documents**:
- `CELLSCRIPT_0_12_COMPREHENSIVE_PLAN.md` (v0.12 acceptance record)
- `CELLSCRIPT_0_12_RELEASE_EVIDENCE.md` (v0.12 evidence checklist)

### ⚠️ Audit Result: Partial Overlap Corrected

The original roadmap collapsed distinct collection layers into one generic
"collections are unsupported" claim. That was incorrect. 0.12 already supports
documented schema/ABI dynamic vectors such as `Vec<Address>` and `Vec<Hash>`.
v0.13 work must target the remaining runtime generic helper and cell-backed
ownership gaps.

### Detailed Findings

| v0.13 Feature | v0.12 Status | Overlap? | Notes |
|---------------|--------------|----------|-------|
| Collections Generics | 🟡 Partial | ⚠️ Partial | `Vec<Address>`/`Vec<Hash>` schema and ABI paths are 0.12; runtime generic `HashMap<K,V>`, `HashSet<T>`, broader local `Vec<T>`, and cell-backed ownership are v0.13 candidates |
| Deserialization Specialization | ❌ Not mentioned | ✅ No | Genuine new optimization |
| CLI: `build` default O1 | ✅ Implemented in branch | ✅ No | Genuine UX fix; `cellc build` JSON exposes `opt_level = 1` for dev builds |
| CLI: `cellc new` | ✅ Implemented in branch on top of `cellc init` foundation | ⚠️ Partial | New work is the Cargo-style `new` workflow, optional git behavior, and `--lib` manifest/file-layout correctness, not initial project scaffolding from scratch |
| CLI: Error codes + explain | 🟡 Runtime registry exists | ⚠️ Partial | New work is source diagnostic presentation and `cellc explain`; runtime error codes/docs are 0.12 |
| Generic in-script CKB Blake2b | ⏸️ P3 conditional | ✅ No | v0.12 completed builder/release helper; on-chain dynamic hashing requires a real linked RISC-V implementation and production gates |
| Function Inlining | ❌ Explicit non-goal | ✅ No | v0.12: "a large optimizer pass suite" is non-goal |
| Hash Type DSL | 🟡 Partial | ✅ No | v0.12: manifest only, not DSL declaration |
| Dead Code Elimination | ❌ Not mentioned | ✅ No | Genuine new optimization |
| Constant Propagation | ❌ Not mentioned | ✅ No | Genuine new optimization |
| Loop Unrolling | ❌ Not mentioned | ✅ No | Genuine new optimization |
| Transaction Builder | ❌ Not implemented | ✅ No | Genuine new feature |
| Broader Fuzz Testing | 🟡 Basic only | ✅ No | v0.12: 43/43 matrix, not broader fuzz |

### v0.12 Explicit Non-Goals (v0.13 Starting Points)

From `CELLSCRIPT_0_12_COMPREHENSIVE_PLAN.md` Section 6:

> 0.12 explicitly does not claim:
> - full generic `HashMap<K, V>` runtime support ← **v0.13 Collections Generics**
> - complete linear ownership for cell-backed collections
> - in-script dynamic CKB Blake2b lowering ← **P3 conditional, not part of current bundled-example requirement**
> - a consensus-level scheduler rewrite
> - a large optimizer pass suite ← **v0.13 Function Inlining, DCE, etc.**
> - a third-party security audit closure
> - arbitrary-contract mainnet risk elimination

### Conclusion

**v0.13 roadmap is viable after scope correction**:
- ✅ Runtime generic collection helpers and cell-backed collection ownership remain valid future work
- ✅ `Vec<Address>` declaration, Molecule dynamic fields, and entry-witness payloads are 0.12 work and must not be counted again
- ✅ `cellc init`, runtime error registry docs, and CKB Blake2b builder/release helpers are 0.12 work and must be treated as foundations
- ✅ Remaining optimizer, DSL, transaction-builder, and fuzzing tracks still build on the 0.12 production boundary

---

*Document End.*  
*Author: AI Code Audit Assistant*  
*Date: 2026-04-24*  
*Status: Draft (Pending Team Review)*  
*Audit Sources*: CLI_ERGONOMICS_AND_BLAKE2B_AUDIT.md, CELLSCRIPT_0_12_COMPREHENSIVE_PLAN.md
