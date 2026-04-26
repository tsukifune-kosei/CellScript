# CellScript CKB Language Fit Audit

This note records the 0.13 audit summary for the CellScript language design and
its fit with the CKB execution model.

## Audit Note 1: Language Fit With CKB

CellScript is now shaped as a CKB-first language rather than a general smart
contract DSL with a CKB backend. Its main abstractions map directly to CKB
concepts:

| CellScript construct | CKB-facing meaning |
|---|---|
| `resource` | Linear Cell-backed asset, represented by input/output Cells and typed data. |
| `shared` | Contention-sensitive state Cell, read through CellDeps or updated by consume/create. |
| `receipt` | Single-use proof Cell for lifecycle, claim, settlement, or protocol evidence. |
| `consume` | Spend an input Cell. |
| `create` | Materialize a typed output Cell. |
| `read_ref` | Load read-only CellDep-backed state. |
| `action` | Transaction-shaped state transition entrypoint. |
| `lock` | Authorization predicate entrypoint compiled to ckb-vm RISC-V. |

The strongest design point is that persistent state is explicit. Ordinary local
values do not silently become chain state; only `create` materializes Cells, and
linear values must be consumed, destroyed, transferred, claimed, settled, or
returned. This is a good fit for CKB because it keeps the transaction input,
output, data, witness, and dependency shape visible to the compiler and release
evidence.

The 0.13 compiler also exposes CKB-specific evidence instead of hiding it behind
a generic artifact:

- CKB Blake2b hash policy and supported script `hash_type` values.
- Molecule-facing schema and ABI metadata.
- Entry witness ABI and witness-size accounting.
- DepGroup and deployment-manifest policy surfaces.
- Runtime error registry and fail-closed production policy.
- Capacity, tx-size, and measured-cycle evidence requirements.
- Scheduler/access metadata for shared or mutable state.

The current production acceptance evidence is therefore meaningful: the seven
production bundled examples strict-compile under the CKB profile, every bundled
business action is builder-backed on a local CKB chain, and the production gate
requires dry-run cycles, committed valid transactions, consensus tx size, and
occupied-capacity checks.

## Audit Note 2: Remaining Semantic Gaps

The current design is CKB-aligned, but the language does not yet fully encode
the complete CKB security model as first-class syntax. Some guarantees are still
split across compiler metadata, builders, and production evidence.

| Gap | Current status | Required direction |
|---|---|---|
| Signer authorization | `Address` parameters can prove equality only when paired with an explicit lock predicate such as `vesting_admin`; they still do not prove witness-sighash ownership by themselves. | Add first-class signer, lock-args, script-hash, or witness-sighash binding. |
| Lock behavior | Locks are strict-compiled under the CKB profile. | Add builder-backed on-chain spend and deny-spend matrices for lock entries. |
| `&mut` Cell updates | Metadata exposes mutate input/output access, but syntax can look like in-place account storage. | Add explicit continuity policy for type id, lock, data schema, and capacity. |
| Capacity policy | Capacity evidence is builder/runtime-required and validated by reports. | Promote common capacity requirements into declarative DSL policy where practical. |
| Timelock policy | since/header/runtime features are visible in metadata. | Make since/header assumptions more directly declarative and statically auditable. |
| Collection examples | `registry.cell` covers bounded local Vec language behavior. | Keep it outside production CKB scope unless promoted into builder-backed chain evidence. |

The most important correction is to avoid overstating what action coverage
proves. The current production run proves transaction shape, Cell data layout,
builder integration, capacity sufficiency, and runtime acceptance for all bundled
business actions. Authorization-sensitive examples should expose their authority
checks as lock predicates, as `vesting_admin` does for vesting revocation, but
the current release still does not prove every lock as a real authorization
surface with positive and negative on-chain spend cases.

For 0.13 follow-up, the recommended order is:

1. Add a real authorization abstraction that ties parameters to CKB lock args,
   script hashes, and witness signatures.
2. Extend CKB acceptance with lock spend and deny-spend matrices for multisig,
   NFT, and timelock locks.
3. Make mutable Cell transitions declare continuity requirements explicitly.
4. Turn common capacity and timelock assumptions from report-only evidence into
   DSL-level policy where the compiler can check them.
5. Promote collection-heavy examples to production scope only after they have
   builder-backed CKB transactions and capacity evidence.

Bottom line: CellScript's language shape is correct for CKB. The next hardening
step is to move more of CKB's authorization and continuity model from evidence
surfaces into first-class language rules.
