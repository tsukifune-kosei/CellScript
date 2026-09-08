# Branch Context

## 0.30

`0.30` is the active capability-closure implementation branch, forked from
`0.26b` at `08c0ef38`. The current planning target permits the next stable
release after 0.25 to be 0.30. The experimental `0.26b` work may be absorbed
into that release without a published 0.26 stable line. No stable tag, Cargo
version, source edition, metadata schema, ABI, or deployment identity exists
merely because the branch and roadmap use the 0.30 name. See
[`docs/CELLSCRIPT_0_30_CAPABILITY_CLOSURE_RFC.md`](docs/CELLSCRIPT_0_30_CAPABILITY_CLOSURE_RFC.md)
for the issue coverage, bounded Rust-comparable business portfolio, missing work
owners, staging, and release acceptance criteria.

The first Stage 1 slice gives authoring successor relations a precise complete
Script-hash domain: `lock = exact_hash(value)` accepts only `ScriptHash`, typed
CKB transaction-view hash fields produce that type, and
`ckb::script_hash(hash)` performs an explicit conversion from a trusted raw
`Hash`. This conversion does not establish Script existence, deployment, or
authorization. Real CKB-VM tests cover matching and substituted output Lock
Script hashes while the existing `lock = exact(address)` form remains intact.

The temporal Stage 1 work now adds concrete CKB domains for typed HeaderDep
fields, opaque and decoded input `since`, and all six absolute/relative
block-number, epoch-fraction, and timestamp combinations. It preserves the
existing raw Edition 2026 functions, requires checked raw decoding or explicit
conversion, emits canonical rational epoch-fraction comparisons, and rejects
malformed flags, metrics, fractions, scalar bounds, timestamp overflow, and
mode/metric narrowing. `EpochDuration` construction and EpochNumber add/sub are
checked against the 24-bit CKB epoch domain with overflow and underflow
rejection. Fixed-size full-header decoding now supplies typed block number and
millisecond timestamp reads. Targeted `W3012` migration warnings and an LSP
workspace edit preserve raw-result compatibility, while package-interface v3
binds the temporal constructors, decoders, domains, wire format, and migration
identity. The v2 reader and cross-edition interface comparison preserve the
old-edition boundary. Formatter, VS Code, generated-builder, package, WASM, and
Playground parity are implemented, and the six-family temporal business corpus
uses typed HeaderDep and Since operations. Full candidate gates and independent
review remain before issue #12 and the release gate can close.

Until this branch passes those criteria, treat it as development work, use
`0.26b` only as its experimental implementation baseline, and retain 0.25 as
the predecessor release contract. Do not publish a 0.26 tag solely to preserve
sequential version numbering.

## 0.26b

`0.26b` is the experimental implementation branch for the post-0.26 semantic
foundation. It starts from `origin/nightly-0.26` and adds versioned provenance,
role, disposition, claim, entry-selection, source-map, and layered-identity
records plus a separately routed Edition 2027 preview frontend and
`cellc expand`. The `cellscript-source-semantics-2027-authoring1` route now
shares the complete 2026 declaration/value/statement grammar, accepts ordinary
multi-entry source modules, makes the action/lock `verification` marker
optional, and accepts branch-local `replace before -> after` successor
relations with schema-resolved `same except` expansion, explicit
lock/capacity/identity treatments and source-level path completeness,
including relations in each branch of an `if`. `exact_hash` now consumes the
dedicated complete `ScriptHash` value contract. It also exposes bounded
real-contract byte/span/preimage primitives and exact u8/hex EXEC plus hex
SPAWN/WAIT adapters. External calls remain fail-closed by default; an admitted
call must use a `trusted_*` intrinsic, pin a compile-time CellDep data hash, and
match an exact versioned `Cell.toml` declaration. Generated code checks that
hash before delegation, and metadata/ProofPlan/checker evidence uses the
separate `trusted-external` tier with no claim over external code internals.
See `docs/CELLSCRIPT_TRUSTED_EXTERNAL_VERIFIERS.md`. A separate bounded
Type-policy artifact path now dispatches explicitly tagged actions from full
Script-hash keyed witness records. An authenticated issuer lifecycle now
executes locally in CKB-VM under one persistent policy; complete product and
chain closure, executable
branch-alternative successors, remaining relation policies and schema
acknowledgement remain implementation work. The branch retains the bounded native
`type_script` and
`lock_script` surfaces specified in
`docs/CELLSCRIPT_2027_PREVIEW_GRAMMAR.md`, including fixed-role checked pools,
exact retirement/fresh-output plans, and metadata-only external-policy audits.
These native forms were introduced by `cellscript-source-semantics-2027-preview4`.
It is implementation evidence for
the umbrella RFC, not a
stable release, accepted grammar, production-equivalence claim, or 1.0
readiness claim. Edition 2026 remains the stable source-semantics default.
The branch may feed the planned 0.30 capability release directly; that possible
promotion does not turn `0.26b` itself into a stable 0.26 release candidate.

The [adopted authoring target](docs/CELLSCRIPT_AUTHORING_TARGET.md) preserves
`resource`, `action`, `lock`, and `require` while requiring concise successor
relations and multiple actions under one persistent deployed policy. It is
design direction for the next iteration, not functionality already provided
by preview4. The versioned semantic model remains reusable; the verbose
preview4 text is not the final authoring target.

## nightly-0.26

`nightly-0.26` is the active consensus-runtime development line for bounded
Cell-group consumption and bounded output-plan correspondence. The first
supported shape is deliberately limited to exact Type Script groups with a
compile-time cardinality bound, canonical Molecule decoding, deterministic
group-relative order, and independently checked machine evidence. Treat the
line as non-production until the positive CKB-VM/stateful fixtures, mutation
checks, resource measurements, independent security review, and the `dev`,
`ci`, and `backend` gates agree.

## nightly-0.25

`nightly-0.25` is the language-completeness predecessor. It adds
bounded value generics, explicit visibility and package interfaces, exhaustive
IR-surface classification, and the typed-semantics v2 / lowering-record v3
boundary. Treat it as merge-ready only when compiler, independent checker,
Registry, editor/Playground, docs, and the `dev`, `ci`, and `backend` gates all
agree. It is not a stable release or production CKB evidence claim; the crate
version identifies the 0.25 development line but is not a substitute for a
signed release tag or the coordinated release gate.

## 0.12-era proposal baseline

The 0.12-era work is the formal proposal baseline for grant-style acceptance
discussions. Do not use that historical baseline to describe the current
`main` branch state.

## nightly-0.24

`nightly-0.24` is the closed maintenance line for independently verified
artifacts and executable package evidence. It builds on the closed 0.23
Edition 2026 and native-tooling boundary. The stable release boundary is the
exact `v0.24.0` tag; later commits on the branch are not implicitly part of
that release. External Myelin, Fiber, and RGB++ claims remain separately
evidence gated as described in the 0.24 release notes.

## nightly-0.23

`nightly-0.23` is the implementation-complete predecessor for Edition 2026,
resolved target/assurance/ABI/schema profiles, the deployed Registry path, and
the native release-tooling migration. It deliberately rejects older package,
lock, deployment, receipt, builder, and raw entry-witness identities rather
than migrating them. Its release notes are a development-scope record, not a
stable release certificate or production CKB evidence.

## nightly-0.22

`nightly-0.22` is the historical implementation line for the 0.22 type-and-set
theory release. The stable release boundary is the `v0.22.0` tag, not the
nightly branch name.

## main

`main` is the integration baseline. Use an exact release tag for stable-release
comparisons and an exact nightly branch for development-scope comparisons;
do not infer release evidence from `main` alone.

## v0.24.0

`v0.24.0` is the current stable release for the verified-artifact checker,
executable package scenarios, lock-authoritative package graph, and LS-IDL
Registry path. Use the exact tag ref `refs/tags/v0.24.0` for stable
comparisons. The release does not promote the separately pending Myelin,
Fiber, or RGB++ external evidence boundaries.

## v0.23.0

`v0.23.0` is the historical stable baseline for Edition 2026, the Registry,
and native release tooling. Use the exact tag ref `refs/tags/v0.23.0` when
reproducing that release.

## v0.22.0

`v0.22.0` is the historical stable baseline for the type-and-set-theory line.
Use the exact tag ref `refs/tags/v0.22.0` when reproducing that release rather
than treating a later nightly branch as equivalent evidence.

## 0.16

0.16 is an audit-hardening preview. It is useful for tracing how earlier review
findings were handled, but it should not be treated as the current iCKB
differential-evidence branch.

## research/protocol-equivalence

`research/protocol-equivalence` is the 0.17 research and differential-evidence
branch. It moves the iCKB benchmark from model-only evidence into broad partial
CKB VM differential evidence for selected normalized fixtures.

Current active matrix counts:

- `DIFFERENTIAL_CKB_VM_EXECUTED`: 66
- `CELL_SCRIPT_CKB_VM_EXECUTED`: 14
- `ORIGINAL_ICKB_CKB_VM_EXECUTED`: 8
- `MODEL`: 0

The branch still keeps `equivalence_status = NOT_PROVEN` and
`production_equivalence_claim = false`. Do not describe it as production
equivalent until the gate has complete evidence-manifest closure and the
non-executable assumptions registry is empty.
