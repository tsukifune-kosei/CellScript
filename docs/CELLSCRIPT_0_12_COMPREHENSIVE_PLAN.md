# CellScript 0.12 Comprehensive Plan

**Date**: 2026-04-24  
**Target release**: CellScript 0.12  
**Scope**: Language surface, compiler correctness, CKB profile authoring, diagnostics, ABI transparency, examples, documentation, and release gates.

---

## 1. Release Positioning

CellScript 0.12 should not be framed as another pass to make the bundled examples run. The current Spora and CKB bundled-example production gates are already locally closed. The 0.12 goal is broader:

> Move CellScript from "production gates pass for the bundled suite" to "external developers can author, debug, inspect, and release CellScript contracts safely."

The release should preserve the existing production closure while making hidden compiler/runtime semantics explicit:

- Keep the current Spora and CKB production gates from regressing.
- Promote critical CKB safety concepts from metadata-only surfaces into authoring/reporting surfaces.
- Document semantics that currently live mostly in codegen, metadata, or acceptance scripts.
- Improve fail-closed diagnostics so failures are actionable.
- Draw clear boundaries around partially supported features such as collections, scheduler hints, and linear collection ownership.

---

## 2. Required Outcomes

### 2.1 Runtime Error Registry

CellScript currently emits many fail-closed numeric codes through `emit_fail(N)`. 0.12 must replace scattered magic numbers with a stable registry.

Deliverables:

- Add `CellScriptError`, `CellScriptRuntimeError`, or an equivalent registry.
- Map every codegen fail code to a symbolic name, description, trigger condition, and debugging hint.
- Make CLI/report output include both numeric code and symbolic name.
- Add tests for the main fail-closed paths.

Example shape:

```rust
pub enum CellScriptRuntimeError {
    AssertFailed = 2,
    CellLoadFailed = 3,
    MutateTransitionMismatch = 14,
    DynamicFieldBoundsInvalid = 16,
    FixedByteComparisonUnresolved = 18,
    ClaimSignatureFailed = 19,
    ConsumeInvalidOperand = 22,
    DestroyInvalidOperand = 23,
    CkbProfileRejectedSyscall = 25,
}
```

The exact names must be derived from the current codegen semantics rather than guessed from a few call sites.

Exit criteria:

- `emit_fail(<number>)` has no unregistered numeric literal use.
- Documentation includes a runtime error table.
- At least five representative fail-closed paths have tests or CLI snapshots.

### 2.2 CKB Profile Authoring Upgrade

The current CKB path is production-gate closed through metadata, constraints, builder behavior, and acceptance evidence. 0.12 should improve the authoring surface without breaking current defaults.

Deliverables:

- Add CKB Blake2b stdlib/helper support, such as `ckb::blake2b256(data: Vec<u8>) -> Hash`.
- Add a source-level or manifest-level `hash_type` authoring surface.
- Promote DepGroup support from generator-only configuration into package/deployment manifest support.
- Convert `since` usage from a generic warning into structured timelock policy reporting.
- Make the capacity builder contract a hard release gate.

Exit criteria:

- CKB Blake2b test vectors use `ckb-default-hash` personalization.
- Explicit `hash_type` declarations are validated against builder/deployment output.
- DepGroup-configured transactions are covered in tests or CKB acceptance.
- Missing occupied-capacity or tx-size evidence fails the production gate.

### 2.3 Collections Boundary Clarity

The current implementation supports dynamic schema/ABI types such as `Vec<Address>` in examples and witness metadata, but the runtime collection helper library is still largely U64-oriented.

0.12 must document and test the distinction between:

1. **Schema/ABI dynamic types**
   - `Vec<Address>`, `Vec<u8>`, `String`, and other Molecule-backed dynamic values.

2. **IR construction**
   - `CollectionNew`, `CollectionPush`, and `CollectionExtend`.

3. **Runtime collection helpers**
   - `vec_push`, `hashmap_insert`, and `hashset_insert`, which should not be advertised as fully generic until implemented.

Deliverables:

- Add a collections support matrix.
- Add positive tests for `Vec<u8>` and `Vec<Address>`.
- Add explicit fail-closed or diagnostic tests for unsupported cell-backed collections.
- Do not claim full generic `HashMap<K, V>` runtime support in docs.

Exit criteria:

- `Vec<Address>` is documented as supported where it is actually supported.
- `HashMap<Hash, Token>` and similar cell-backed generic collection cases are either implemented or rejected with a stable diagnostic.
- Nested dynamic values such as `Vec<Vec<u8>>` are either covered or explicitly fail closed.

### 2.4 Mutate Primitive Productization

The mutate system is stronger than the current public documentation suggests. It should become a first-class documented feature in 0.12.

Important wording:

- Mutate is **not** physical in-place cell mutation on CKB.
- Mutate is Input -> Output replacement with type/lock preservation and field transition checks.

Deliverables:

- Document `&mut Shared` lowering.
- Document `preserved_fields`, `transitions`, `preserve_type_hash`, and `preserve_lock_hash`.
- Use AMM `&mut Pool` as the official advanced example.
- Add dedicated tests or examples for `Add`, `Sub`, `Set`, and `Append` transition shapes.

Exit criteria:

- AMM mutate metadata remains stable.
- Docs explain the Input#N -> Output#N replacement model.
- Append transition has at least one positive and one fail-closed test.

### 2.5 Entry Witness ABI Documentation

The entry witness ABI is already structured, but the developer-facing documentation needs to explain the format.

Deliverables:

- Document the `CSARGv1\0` magic.
- Document fixed-width parameter encoding.
- Document schema-backed dynamic parameter encoding.
- Explain length-prefixed dynamic bytes and Molecule schema manifests.
- Explain runtime-bound parameters that do not consume witness payload bytes.
- Add or improve `cellc abi` / metadata output so developers can inspect expected witness layout.

Exit criteria:

- `Vec<Address>` witness encoding has a test.
- `Vec<u8>` or `String` dynamic layout has a test.
- Missing payload and wrong-width payload errors are clear.

### 2.6 Linear Ownership and Linear Collection Boundary

The compiler already has a type-level linear state checker. Codegen stack zeroing in `emit_consume` is an additional fail-closed defense, not the only ownership mechanism.

0.12 should preserve the existing checker and make the real remaining gap explicit: cell-backed collection ownership.

Deliverables:

- Document compile-time linear ownership checks.
- Document codegen consume zeroing as a runtime defense.
- Keep unsupported cell-backed collection ownership cases fail-closed.
- Define a path toward future `consume_each` or equivalent collection ownership primitives.

Exit criteria:

- Existing linear ownership tests keep passing.
- `linear-collection-ownership-gap` remains a stable blocker class where applicable.
- Unsupported resource collections are not silently accepted.

### 2.7 Release Gate Stability

0.12 must not regress the current production closure.

Required preserved evidence:

- Spora production gate passes.
- CKB final hardening gate passes.
- Builder-backed CKB action coverage remains complete for the bundled suite.
- Occupied-capacity measurement remains complete for CKB actions.
- Tx-size measurement remains complete for CKB actions.
- Bundled examples continue to compile and run through their acceptance paths.

---

## 3. Work Tracks

## Track A: Diagnostics and Error Codes

### A1. Error Registry

Implement a single source of truth for CellScript runtime/codegen fail codes.

Tasks:

- Add the registry in the CellScript crate.
- Replace direct numeric usage where practical.
- Add a helper for symbolic lookup.
- Add tests ensuring all emitted codes are known.

### A2. CLI and Report Integration

Tasks:

- Add symbolic names in `cellc check`, `cellc constraints`, and relevant metadata/report views.
- Add docs for common errors.
- Where acceptance captures failure codes, include symbolic names.

### A3. Documentation

Add `Runtime Error Codes` documentation under `cellscript/docs`.

---

## Track B: CKB Profile Authoring

### B1. CKB Blake2b Helper

Add a profile-aware helper:

```cellscript
ckb::blake2b256(data)
```

Potential follow-up:

```cellscript
ckb::blake160(data)
```

The implementation must match CKB's Blake2b-256 with `ckb-default-hash` personalization.

### B2. Hash Type Visibility

0.12 should introduce one of these:

- Manifest-level `hash_type` declaration.
- Attribute-level `#[ckb(hash_type = "type")]`.

Do not force a full `script {}` DSL in 0.12 unless the design is already clear.

### B3. DepGroup Manifest Support

Add deployment/package manifest support for named CKB cell deps:

- `dep_type = "code"`
- `dep_type = "dep_group"`
- outpoint validation
- builder integration
- metadata/report output

### B4. Since Policy Reporting

Keep `ckb::input_since()` as the runtime primitive, but add structured policy reporting:

- action uses input since
- action depends on header epoch
- timelock policy is runtime/assert-based
- declarative timelock syntax is not yet first-class

### B5. Capacity Contract

Do not pretend the compiler statically proves full occupied capacity. Instead, make the builder contract explicit and enforce evidence retention.

Required report fields:

- code cell capacity lower bound
- occupied-capacity measurement requirement
- measured occupied capacity
- tx-size measurement requirement
- measured tx size

---

## Track C: Collections and Dynamic Data

### C1. Support Matrix

Document support by layer:

| Feature | Schema/ABI | IR construction | Runtime helper | 0.12 status |
|---|---:|---:|---:|---|
| `Vec<u8>` | Yes | Targeted | Partial | Must test |
| `Vec<Address>` | Yes | Targeted | Partial | Must test |
| `Vec<Hash>` | Yes | Targeted | Partial | Should test |
| `Vec<Vec<u8>>` | Unclear | Unclear | No | Decide/test or fail closed |
| `HashMap<u64, u64>` | Limited | Limited | U64-oriented | Document |
| `HashMap<Hash, Token>` | No production guarantee | No | No | Fail closed |
| cell-backed collection ownership | No executable ownership model | No | No | Stable blocker |

### C2. Minimal Generic Vec Scope

For 0.12, prioritize fixed-width non-linear element types:

- `u8`
- `u64`
- `Address`
- `Hash`
- fixed byte arrays

Do not make broad claims about cell-backed linear elements.

### C3. Fail-Closed Unsupported Cases

Unsupported generic collections must produce:

- compile-time error, or
- structured blocker in constraints/check output, or
- explicit fail-closed metadata.

Silent acceptance is not acceptable.

---

## Track D: Mutate and Replacement Outputs

### D1. Guide

Add a guide explaining:

- mutable parameters
- replacement output indexes
- preserved fields
- transition fields
- lock hash preservation
- type hash preservation
- fixed struct vs Molecule table verification paths

### D2. AMM Example

Use `amm_pool.cell` as the canonical example:

- `swap_a_for_b`: reserve add/sub transitions
- `add_liquidity`: reserve and LP supply transitions
- `remove_liquidity`: reserve and LP supply subtraction

### D3. Append Transition

Add tests and docs for dynamic append:

- append to a dynamic field
- replacement output field equals input field plus appended value
- unsupported append shapes fail closed

---

## Track E: Linear Ownership

### E1. Existing Compile-Time Checks

Document:

- unavailable-after-consume behavior
- branch ownership consistency
- loop ownership restrictions
- required consume/transfer/destroy for linear values
- restrictions on storing references rooted in linear values

### E2. Cell-Backed Collection Ownership

0.12 should not try to solve the full model unless the design is ready. It must, however, keep the boundary explicit.

Future design candidates:

- `consume_each`
- typed collection destructuring
- verifier-backed collection membership proofs
- schema-level ownership witnesses

---

## Track F: Entry Witness ABI

### F1. Specification

Document:

- magic bytes: `CSARGv1\0`
- parameter order
- scalar/fixed-width layout
- fixed byte layout
- schema-backed dynamic payload layout
- stack spill behavior
- runtime-bound parameters
- schema manifest linkage

### F2. CLI Explain

Add or improve:

```bash
cellc abi <file> --action <name>
```

Expected output should show:

- parameter name
- type
- fixed/dynamic classification
- witness byte layout
- runtime-bound status
- example payload shape

---

## Track G: Scheduler Hint Consumption

Scheduler hints are currently credible metadata and scheduler witness summary fields. 0.12 should add at least one real consumer beyond serialization/validation.

Acceptable 0.12 consumers:

- admission simulator
- wallet/generator grouping policy
- devnet acceptance conflict probe

Minimum behavior:

- `parallelizable = false` is respected by the simulator/policy.
- shared touch-set conflicts are detected.
- `estimated_cycles` contributes to a budget summary.

Consensus-level scheduler changes can wait for a later release.

---

## Track H: Optimizer and Measurement

Do not start with aggressive optimization. Start with measurement.

Deliverables:

- artifact size baseline for bundled examples
- CKB cycle baseline
- Spora mass baseline
- opt-level comparison report

Allowed low-risk passes:

- local constant propagation
- unreachable block cleanup
- local algebraic simplification
- redundant bounds-check cleanup only when verifier obligations remain visible

Deferred passes:

- loop unrolling
- global CSE
- cross-action inlining
- resource/cell operation reordering

Exit criteria:

- verifier obligations do not change unexpectedly after optimization
- production gates do not regress
- size/cycle impact is measured rather than guessed

---

## Track I: Documentation and Examples

### I1. Documentation Set

Add or update these docs under `cellscript/docs`:

- `Runtime Error Codes`
- `CKB Profile Authoring`
- `Mutate and Replacement Outputs`
- `Entry Witness ABI`
- `Collections Support Matrix`
- `Capacity and Builder Contract`
- `Scheduler Hints`
- `0.12 Migration Notes`

### I2. Example Set

Keep the current examples:

- `token.cell`
- `nft.cell`
- `timelock.cell`
- `multisig.cell`
- `vesting.cell`
- `amm_pool.cell`
- `launch.cell`

Add or strengthen:

- `ckb_hashing.cell`: CKB Blake2b helper
- `mutate_append.cell`: append transition
- `collections_matrix.cell`: supported and unsupported dynamic collection cases
- deployment manifest example: `hash_type` and DepGroup

### I3. Documentation Accuracy Rules

Do not claim:

- "CellScript supports generic collections" unless runtime helpers are actually generic.
- "mutate updates cells in place" without explaining replacement outputs.
- "scheduler hints are enforced by the VM scheduler" unless a real scheduler policy consumes them.
- "capacity is statically guaranteed by the compiler."

---

## 4. Milestones

### Milestone 0: Baseline Freeze

Goal: freeze the current production-closed baseline.

Deliverables:

- current Spora production report
- current CKB final hardening report
- builder-backed action count
- occupied-capacity measurement count
- tx-size measurement count
- artifact size and cycle baseline

Exit criteria:

- bundled examples compile
- Spora production gate passes
- CKB final hardening gate passes
- baseline evidence is archived

### Milestone 1: Diagnostics and Documentation Foundation

Goal: make hidden semantics inspectable.

Deliverables:

- error registry
- runtime error docs
- mutate docs
- entry witness ABI docs
- collections support matrix
- CLI/report symbolic error names

Exit criteria:

- no unregistered fail codes
- documentation matches registry
- every major documented capability has a test or metadata evidence path

### Milestone 2: CKB Authoring Upgrade

Goal: expose critical CKB concepts to authors.

Deliverables:

- `ckb::blake2b256`
- `hash_type` manifest or attribute support
- DepGroup manifest support
- structured since policy report
- capacity builder contract gate

Exit criteria:

- Blake2b, hash_type, and DepGroup tests exist
- production gates enforce measurement evidence
- default behavior remains backward compatible

### Milestone 3: Dynamic Data and Mutate Hardening

Goal: make dynamic data and mutate behavior clear and bounded.

Deliverables:

- `Vec<u8>` and `Vec<Address>` tests
- nested dynamic support decision
- append transition tests
- linear collection ownership diagnostics

Exit criteria:

- unsupported generic collections do not silently compile as production-ready
- AMM mutate metadata remains stable
- dynamic witness layout is tested

### Milestone 4: Scheduler and Optimizer Evidence

Goal: move from metadata to measured policy.

Deliverables:

- scheduler admission simulator or wallet policy consumer
- optimizer baseline report
- selected low-risk optimizer pass
- size/cycle diff report

Exit criteria:

- at least one component consumes scheduler hints for policy
- optimization does not hide verifier obligations
- production gates do not regress

### Milestone 5: Release Candidate

Goal: close the 0.12 release.

Deliverables:

- changelog
- migration notes
- release evidence bundle
- final production reports
- docs index update

Exit criteria:

- `cargo test -p cellscript`
- relevant `spora-exec` tests
- Spora production acceptance
- CKB CellScript acceptance
- release evidence validation

---

## 5. Priority Matrix

| Work item | Priority | Reason |
|---|---:|---|
| Error registry and docs | P0 for 0.12 | Required for actionable fail-closed debugging |
| Production baseline freeze | P0 for 0.12 | Prevents regressions during broad changes |
| CKB Blake2b stdlib | P1 | Small, clear authoring capability gap |
| `hash_type` source/manifest surface | P1 | Critical CKB safety concept should not remain hidden |
| Collections support matrix | P1 | Prevents documentation and implementation mismatch |
| Mutate docs and examples | P1 | Existing strong feature needs product-quality docs |
| Entry Witness ABI docs/explain | P1 | Dynamic params must be transparent |
| Capacity builder contract hard gate | P1 | Keeps current production closure enforceable |
| Since policy structured report | P1 | Turns warning-only surface into consumable policy |
| DepGroup manifest support | P1/P2 | Builder exists; authoring surface is missing |
| Linear collection ownership | P2 | Important but design-heavy; fail-closed first |
| Scheduler policy consumer | P2 | First step beyond metadata serialization |
| Optimizer extra passes | P2 | Must be measurement-driven |

---

## 6. Non-Goals for 0.12

0.12 should not promise:

- full generic `HashMap<K, V>` runtime support
- complete linear collection ownership model
- large optimizer pass suite
- one-shot redesign of capacity/since/hash_type DSL
- consensus-level scheduler rewrite
- third-party mainnet-grade security audit closure
- breaking rewrites of existing examples

These are candidates for 0.13 or later once the 0.12 foundations are stable.

---

## 7. Final Deliverables

### Code

- error code registry
- CKB Blake2b helper
- `hash_type` manifest or attribute support
- DepGroup manifest/builder bridge
- scheduler admission simulator or wallet policy consumer
- selected low-risk optimizer improvements

### Tests

- registry consistency tests
- CKB Blake2b vectors
- `hash_type` mismatch fail-closed case
- DepGroup configured transaction path
- `Vec<u8>` and `Vec<Address>` ABI tests
- nested dynamic support or fail-closed tests
- mutate append tests
- linear collection diagnostics
- production acceptance hard gates

### Documentation

- runtime error code table
- CKB profile authoring guide
- mutate guide
- entry witness ABI specification
- collections support matrix
- capacity/builder contract
- scheduler hint semantics
- 0.12 migration notes

### Release Evidence

- Spora production report
- CKB final hardening report
- artifact size/cycle baseline and diff
- occupied-capacity and tx-size evidence
- docs/test coverage summary

---

## 8. Success Criteria

CellScript 0.12 is ready when:

1. Current production closure does not regress.
2. Critical safety concepts have clear authoring, reporting, or debugging surfaces.
3. Unfinished capabilities have stable fail-closed behavior and documented boundaries.
4. Developers can understand witness layout, hash type, capacity, mutate behavior, and collection support without reading codegen internals.
5. CellScript 0.13 can build on clear boundaries for full tx-shape DSL, scheduler policy, and generic collections.

In one sentence:

> CellScript 0.12 should turn a production-gated compiler into a developer-facing, inspectable, and release-ready contract toolchain.
