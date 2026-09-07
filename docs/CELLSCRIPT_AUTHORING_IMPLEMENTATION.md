# Authoring Implementation and Production Acceptance

## Objective and current state

Implement the [adopted authoring target](CELLSCRIPT_AUTHORING_TARGET.md) to
production quality, with no loss of Edition 2026's supported functionality or
feature completeness. This includes the complete language and toolchain, not
only a Token example or acceptance of old source text.

Work is in progress on `0.30`. No production-completion claim is made here. The
first capability slice advances the experimental source contract from the
recorded `cellscript-source-semantics-2027-authoring1` baseline to
`cellscript-source-semantics-2027-0.30-dev1`; the workspace release version and
existing single-entry payload/placement ABIs are unchanged. Explicit persistent
Type policies have a separate, opt-in `cellscript-policy-witness-v1` envelope.
The implementation may become the next stable release without publishing a
stable 0.26 line. The 0.30 scope and its broader Rust-comparable business
acceptance portfolio are tracked in the
[0.30 capability closure RFC](CELLSCRIPT_0_30_CAPABILITY_CLOSURE_RFC.md); neither
the release name nor this development evidence changes a compatibility identity.

The first implementation step restores familiar authoring over the shared
declaration, type, value, and statement grammar. Ordinary action/lock bodies
may omit `verification`; the formatter currently emits the established explicit
marker. Multiple source entries, default parameter provenance, read references,
and existing lifecycle operations are retained. A legacy consume keeps its
existing semantics and evidence classification. It does not acquire a native
retirement or pooled-accounting guarantee.

The bounded native preview4 grammar remains accepted as an implementation
reference. It is not the final authoring surface. Complete shared-policy product
support, executable branch-alternative successors, the remaining relation
policies, and schema acknowledgement are still required. Neither reuse of the
2026 parser kernel nor successful scoped action ELFs satisfies those
requirements.

## Completion requirements

Every row needs current-state evidence before the objective can be called
complete. A passing test must actually exercise the stated behavior. Missing
evidence, a metadata label, and an unsupported construct that rejects safely
are not implementation of a required supported feature.

| Requirement | Required implementation and evidence | Current disposition |
|---|---|---|
| Complete authoring language | Shared declarations, expressions, statements, types, and full callable bodies; meaningful edits and readable diagnostics on the adopted corpus. | Shared kernel, optional marker and ordinary-action `replace` successor relations are implemented; remaining relation forms, acknowledgements and corpus evaluation are pending. |
| No 2026 feature regression | Positive and negative cross-edition source, typed obligation, format, artifact, and runtime checks for the feature families below. | Dedicated differential tests, the cross-edition syntax matrix and the 2026 `replace`-as-identifier boundary pass the 2026-09-06 `dev` gate; `ci` and release evidence remain pending. |
| Direct semantic elaboration | Structured relation nodes with spans, typed schema resolution, and checked lowering; no generated preview4 text reparsing. | Implemented for `replace`: parser, AST, type checking and IR elaborate the relation directly, including concrete-schema `same except`; other constructor forms remain pending. |
| Path-sensitive successor relations | Assigned/preserved fields, identity, lock, capacity and output correspondence compose inside ordinary `if`/`match`; every accepting path accounts for roles. | Implemented for authoring relations: source-level completeness (conditional skip, double disposal and loop disposal rejected) and relations in each branch of an `if` compile and validate after sibling arms stopped reusing non-dominating schema-field materializations. |
| `same except` and upgrades | Concrete schema identity, exhaustive expansion, reproducible focused acknowledgement, changed/stale/missing acknowledgement rejection, no implicit repin. | `data = same except` expands against the resolved concrete schema with unknown/duplicate-field rejection; the schema acknowledgement workflow remains pending. |
| Constructor defaults | A1-A6 policies are total under resolved context; lock omission, capacity alternatives, identity, group coverage, alias rejection and pool domains have one checked meaning. | Relations require explicit data, lock, capacity and identity treatments (omission is rejected, not defaulted); `lock = exact(address)`, `lock = exact_hash(script_hash)`, and `lock = same` are executable with checked conservation. `exact_hash` requires the dedicated `ScriptHash` domain; other constructors remain pending. |
| Exact artifact entry | Codegen, semantic metadata, CLI execution and explicit entry scoping agree, including selected actions calling other retained actions. | Shared selection, terminal scalar/Unit helper failure and VM regressions implemented; policy Cell-bearing and complex-ABI callee closure remains pending. |
| Resolved physical bindings | One typed per-binding source/ordinal/identity plan drives codegen, provenance, roles and independent checks; mixed Cell/read/witness/Script.args layouts cannot disagree. | Fixed-Cell runtime plan and typed projection checks implemented; full ABI and machine-dataflow closure remain pending. |
| One deployed multi-action policy | Declared action set and explicit versioned dispatch bind selectors, payloads, common checks, artifact identity and builders. | Bounded fixed-role Type policy implemented in compiler/VM, metadata/expansion and package/builders; full consumer and deployment closure remains pending. |
| Dispatch rejection | Reject unknown/duplicate/ambiguous tags, wrong versions, malformed/oversized/trailing payload, branch confusion and missing policy checks. | Focused real VM negatives implemented for the bounded envelope and all four fixed cardinalities; independent machine dispatch verification remains pending. |
| Lock authorization | Actual transaction-bound credential proof; reject copied owner values, missing/invalid proof and signed-transaction tampering. | Real multisig spending and the issuer-authorized mint/transfer/merge/burn VM lifecycle are implemented with credential and post-signing tamper negatives; the precise source-level Script identity/authorization API and chain evidence remain pending. |
| Script identity API | Distinguish address decoding, full Script construction/hash comparison and signature verification; wrong-domain values fail typing or checked conversion. | Partially implemented: typed transaction views expose complete hashes as `ScriptHash`; `ckb::script_hash(Hash)` is an explicit domain conversion; and authoring `exact_hash` rejects `Address` and raw `Hash`. Address parsing, source-level complete Script hashing, deployment/existence proof, and signature verification remain pending. |
| Orthogonal obligations | Compose lifecycle, identity, asset accounting, capacity and authorization without double counting; scope and authenticated external guarantees remain distinct. | Executable relation sugar produces the same typed obligation set as its spelled-out 2026 form for data, capacity, identity and exact-lock treatment. Bounded trusted-external EXEC/SPAWN now binds exact CellDep data identity and scoped guarantee claims under a separate evidence tier; broader constructor composition remains pending. |
| Witness ABI contexts | Type input/output-only entries, Lock entries and shared witnesses have bounded, non-overlapping ownership; preserve old ABI bytes where compatible. | Empty-group fallback, canonical bounded multi-record Type envelope, independent host/adapter codecs and pre-signing placement implemented; full signed shared-policy integration remains pending. |
| Token lifecycle | Execute generated Token Type Script under one persistent policy through authorized mint, transfer, merge and burn, with positive/negative VM and chain evidence. | Real CKB-VM coverage executes the complete issuer-authorized lifecycle under identical policy bytes, using earlier verified outputs as later inputs, across both editions and optimization levels 0-3; node admission, chain confirmation and deployment evidence remain pending. |
| Schema-change lifecycle | Add `approval_nonce`, require reviewed reset on transfer, reject unchanged preservation and stale acknowledgement; retain old deployed-byte meaning. | Pending. |
| Remaining business corpus | NFT capacity adjustment, fungible splits/merges, partial order, authenticated dependencies and interacting Script groups. | Pending. |
| Independent artifact checking | Version and validate any new records, recompute identities, bind selected entries/relations/dispatch to machine evidence, and add adversarial mutations. | Typed policy, declaration/ABI and builder parameter projection checks implemented. Trusted-external records are independently bound to an ordered same-CellDep hash-check/delegation sequence with mutation negatives; independent policy selector/adapter machine proof remains pending. |
| Language services and products | Parser, recovering diagnostics, formatter, LSP, editor, native CLI, WASM, package loading, public interfaces and builders agree. | Shared parser diagnostics, formatter round-trip, syntax matrix and VS Code snippet cover `replace`; trusted external calls use ordinary call formatting plus LSP completions and package-manifest loading. Typed temporal domains now have interface, builder, editor and Playground parity, and the canonical bounded-summary WASM is 544,037 bytes gzip. Complete product closure for the remaining 0.30 workstreams remains pending. |
| Reproducibility and compatibility | Source/cache/profile versions, package locks, mixed editions, interfaces and deployment changes are explicit and reproducible. | Source/cache identity advanced; later ABI/dispatch/schema migration pending. |
| Production acceptance | Applicable `dev`, `ci`, `backend` and clean-source release evidence, exact artifacts, runtime negatives, cycle/size/capacity measurements and required independent review. | The relation and economic backend tranches pass their focused VM, parity, checker and cost-corpus suites. Clean-source production acceptance passes 43 action cases, 17 Lock cases and all 26 stateful scenarios / 46 committed steps after the three-layer identity rebind. The canonical WASM rebuild passes its budget; `ci`, release and independent-review evidence remain pending. |

The target includes all A1-A6 contracts, all acceptance fixtures in the authoring
target, and the applicable RFC gates. This checklist does not remove their
requirements or turn an experimental source identity into a release identity.
Public publication or a mainnet deployment is not implied by local acceptance.

## Edition 2026 parity inventory

The authoritative baseline is the current Edition 2026 implementation and its
positive/negative evidence, not an older minimal tutorial. Preserve existing
supported behavior and the exact unsupported boundaries. An already unsupported
dynamic collection does not become a new parity obligation; a supported
bounded 0.26 collection cannot be downgraded to a fixed-role preview.

| Feature family | Evidence to retain and extend |
|---|---|
| Modules and interfaces | Imports and aliases, qualified names, project resolution, public/package/private visibility, stable interface extraction and compatibility diagnostics. |
| Declarations | Resources, shared Cells, receipts, structs, enums, constants, invariants, flows, helpers, actions and locks; attributes and documentation survive. |
| Types and generics | Scalars, fixed bytes, tuples/arrays, value abilities, phantom identity, bounded monomorphization, imported generic instantiation and unsupported-layout rejection. |
| Policies | Capabilities and entailment, identity and destruction policies, type/hash declarations, capacity floors, validity and effect annotations. |
| Values and control flow | Checked arithmetic, wide integers, bitwise/shifts, casts, calls, assignments, aggregates, nested patterns/guards, branching, loops, labels, early returns and borrow regions. |
| Entry roles | Existing value, witness, input/output, protected, lock-args and read-only sources, rich ABI marshalling and named outputs; provenance is not authorization. |
| Verification | Individual/block `require`, custom failures, pure/read-only helper calls, flow transitions, terminal evidence, invariants and bounded quantifiers. |
| Lifecycle | Create, consume, destroy, claim, settle, unique creation/replacement and continuity; equivalent new forms must exist before any old supported operation is removed. |
| Bounded collections | Exact GroupInput scanning, fixed-width decoding, zero/one/N/N+1, checked accumulation, output-plan codec and complete output correspondence, including negative cases. |
| Consumers and evidence | Metadata, ProofPlan, scheduler/effects, source maps, checker, CLI/builders, project/lock handling, formatter, LSP, editor and WASM. |

`tests/authoring_parity.rs` provides representative differential and runtime
cases. `tests/syntax_combo/matrix.toml` drives the generated cross-edition
combination audit. Neither corpus by itself proves the whole table: imported
packages, runtime ABI, deployment and product evidence need their matching
integration suites and gates.

## Authoring successor relations

The authoring route now accepts `replace before -> after { ... }` as a
statement inside ordinary actions. The declaration is the sole authority for
its checks: `data { f = same | f = expr }` and `data = same except { f = expr }`
resolve against the concrete schema of the bound predecessor (exhaustive
coverage, unknown and duplicate fields rejected), `capacity = same` and
`identity = same` lower to the canonical capacity and type-identity
preservation checks. `lock = exact(address)` binds the successor through the
create kernel exactly like `std::lifecycle::transfer`.
`lock = exact_hash(script_hash)` uses the same machine comparison but accepts
only the dedicated `ScriptHash` source domain. Complete Lock and Type Script
hashes read through typed CKB transaction views already inhabit this domain;
`ckb::script_hash(hash)` explicitly treats a trusted raw `Hash` as a complete
Script hash without claiming that the Script exists, is deployed, or provides
authorization. An `Address` or unconverted `Hash` fails typing.

Elaboration stays at the structured AST/IR level — no preview4 text is
generated or reparsed — and `tests/authoring_replace.rs` holds the relation to
the spelled-out Edition 2026 form (identical obligation set, formatter
round-trip) plus real CKB-VM positives and negatives for address and complete
hash locks. The 2026 grammar keeps `replace` as an ordinary identifier.

A relation whose successor would need to bind more than the relation states is
rejected rather than defaulted. Source-level successor completeness is enforced
for the authoring route: a role disposed anywhere must be disposed exactly once
on every accepting path, and disposal inside loops is rejected.

`lock = same` is executable: conservation recognizes the updated-successor
shape, where every field is either a verbatim alias of the consumed input or
a verifier-checked u64 update whose provenance roots in it (constant offsets
keep field provenance, mirroring subtraction). Branch-local relations work
in both `if` arms: cached schema-field reads now carry a branch depth and
epoch, and sibling arms or loop bodies re-materialize when the defining
context does not dominate, which removes an unsound cross-arm reuse that
previously failed the typed-record dataflow check. Existing generated code
is unchanged; only the previously invalid branch-local shapes differ.

## Binding correctness found during parity work

The comparison exposed existing truthfulness gaps. The fixed-Cell implementation
now addresses these rather than copying inaccurate records as reference semantics:

- Ordinary consume and Cell-backed parameter/output lowering retains transaction
  `Input`/`Output` positions and reports them accurately. Native ports use actual
  GroupInput/GroupOutput locations with membership and complete fixed-group
  coverage checks. Nonzero-group VM regressions reject foreign same-layout
  Cells disguising an invalid active group.
- Ordinary and native `protected` Lock parameters use the current Lock group,
  correcting the implementation against the documented contract. They do not
  impose a new exact lock-group cardinality requirement. The role guard rejects
  ambiguous Cells whose Lock and Type hashes both equal the executing Script
  hash; this is a deliberate acceptance-set tightening, not unchanged behavior.
- Explicit `read` parameters use positional CellDep loads. These loads do not
  implicitly authenticate a deployed Type Script identity. Provenance and role
  records now classify that membership as `unproven`.
- Read parameters and standalone `read_ref` expressions share one CellDep
  ordinal allocation. Four-dependency VM cases check each slot and reject the
  previous parameter/expression alias bypass. Repeated generated names and
  source aliases do not replace local binding identity.
- Anonymous creates retain distinct output/local identities and distinct
  role/disposition records even when generated names repeat.
- Witness arguments omit runtime-bound parameters from their encoded sequence,
  and Script.args uses byte offsets. Signature parameter indexes alone do not
  describe either physical layout. Full shared-layout ABI contracts remain
  part of production acceptance.

The mandatory fixed-Cell table introduced in typed semantics v5 is retained in
`cellscript-typed-semantics-v8`. The
independent checker cross-checks typed locals, roles and provenance, including
hash-rebound source/ordinal/identity and missing-record mutations. This does
not establish general syscall dataflow equivalence. The source-set artifact
cache identity now uses `project-source-set-v27-verifier-failure`.
Fixed membership checks share a demand-driven runtime helper with an explicit
96-byte frame in lowering evidence. This avoids repeating the full hash and
role checks in every callable; it does not relax membership or group coverage.

The bounded migration command preserves ordinary Type Script `action` syntax
instead of silently rewriting absolute locations into native group ports.
Its existing equivalence checks remain mandatory; graph-wide migration is
still outside that command's bounded contract.

These findings are grounded in the compiler binding paths, not a complete
security assessment. The implementation must distinguish preserved ordinary
2026 behavior, fixes to inaccurate records, and deliberate new group semantics.
Hash equality with an inaccurate record is not a reason to retain the error.

## Fatal verification and ordinary helper values

The helper call boundary previously allowed a numeric verification error to
return as an ordinary value, which a caller could discard or compare as business
data. Generated fatal checks now use a demand-driven current-process EXIT sink.
Explicit typed failures end in `verifier-failure`; ordinary values and deliberate
raw statuses keep their existing channels. The [artifact boundary](CELLSCRIPT_VERIFIED_ARTIFACT_BOUNDARY.md#fatal-verifier-failures)
specifies the new typed, core-identity and machine records and their limits.

Optimization must preserve an expression unless it is both side-effect-free
and proven non-failing. Unused checked arithmetic, casts, indexing, schema
reads and transitive failing calls therefore remain evaluations. A bounded
constant specialization can still fold proven-total literal helper calls;
it cannot substitute a partial callee expression into a differently typed
caller context. The optimizer regressions changed from four failing families
to 16 passing tests, including existing controls. The lexical-shadowing test
is defensive AST coverage: ordinary type checking already rejects duplicate
bindings, so it is not evidence of an accepted-source shadowing vulnerability.

Real VM regression work covers both editions and optimization levels 0–3,
including discarded/used calls, Unit action chains, imported aliases and
malformed dependency reads. That corpus also exposed and now covers fixes for
ordinary tuple projection and locally constructed schema-reference ABI failures.
Repeated tuple projections, reference aliases, and valid/truncated/trailing
external schema forwarding pass in both editions at all four optimization
levels. The 11-family ordinary VM suite and three policy helper/common-check
families pass; full gates on the final source are still required.
These fixes do not complete branch-local successor relations,
schema acknowledgements or the complete persistent policy product.

## Deferred signing-message boundary

Authorization integration also exposed a pre-existing unsupported path:
`env::sighash_all` did not construct a canonical transaction digest. It could
reach a runtime placeholder returning a zero pointer instead. This is not an
implemented signing primitive and cannot be used as an authorization reference.

The shared deferred-call classification now reports
`ckb-sighash-all-deferred`. Production policy rejects it before artifact
generation. Audit artifacts terminate the process with runtime error 66 at the
call, rather than treating an error integer as a Hash or returning through a
helper whose caller could ignore the result. Optimizer call-purity checks retain
deferred, unresolved and imported evaluations; argument substitution cannot
erase or duplicate an evaluation without the required purity evidence.

Real VM tests cover direct verifier arguments, discarded and wildcard results,
local wrappers, imported aliases and Lock execution in both editions. The
existing explicit-message BIP340 and real signed-multisig routes remain distinct
supported controls. Browser metadata exposes module-wide scoped fail-closed
reasons, and LSP diagnostics include defining helpers as well as actions/locks.

The independent checker rejects reclassification of this known deferred helper
after outer-hash rebinding. Its terminal-failure records now independently check
the recorded static error assignment and jump to the exact current-process EXIT
sink. That does not establish that every deferred call reaches the required
failure site: complete call-to-failure machine binding remains an explicit
checker completion requirement. The deferred-call behavior has direct VM
evidence, separate from the classification and static-site checks.

## Bounded persistent Type policy

An explicit package `[[artifacts]]` declaration selects a concrete resource,
numeric action tags, `policy-witness-v1` dispatch and ordered common checks.
There is no inferred selector, implicit export from source order, or builder
choice that can replace a stored Cell's verifier. Package, in-memory and virtual
source APIs use the same checked policy resolver; executable and metadata-only
paths retain the same selected contract. Explicit builds do not read or overwrite
the default entry's artifact cache.

The first implementation has deliberately bounded executable scope:

- A policy has 1–64 exported Unit actions and at most 16 ordered zero-argument
  Unit common-check actions. Numeric tags are unique `u32` values, including
  zero and the maximum value; canonical serialization sorts tags numerically.
  Common-check order is preserved because the first failure is observable.
- Exactly one concrete Cell-backed schema owns the non-dependency roles.
  Those roles become current Type-group inputs/outputs with exact dense
  cardinality, membership, alias and coverage checks. Read-only CellDeps keep
  their independent ordinals and unproven asset identity. A 0-to-0 variant
  cannot prove invocation membership and is rejected.
- Fixed lifecycle operations must account for the same roles on every
  successful path. Bounded collections, mixed-resource physical roles,
  Cell-bearing action reuse and complex callee ABIs are not
  supported by this initial policy path. They remain available through their
  existing supported ordinary/scoped paths. These restrictions are unfinished
  feature work, not satisfaction of the Edition 2026 parity requirement.
- Retained scalar/Unit helpers and actions may perform checked arithmetic,
  narrowing and `require` in acyclic bodies. They use terminal verification
  failure, preserving ordinary results such as `5`, `20`, `49` and `false`.
  Immutable concrete-schema reference parameters remain supported; reference
  returns remain forbidden by the existing public type-checking contract.
  Field/index access, physical Cell operations, mutable/wide/aggregate call
  ABIs and recursive calls remain outside this bounded policy callee contract.
- Common checks run once before a selected action and may call the same
  retained bounded graph; unknown generic calls are rejected. Every common
  check remains a zero-parameter Unit action. A Bool predicate is used by
  `require predicate(...)`; simply returning false is not an authorization
  check. Common checks are not exported variants. The independent checker
  validates their retained call contracts and excludes physical Cell effects,
  unsupported operations and cycles; full machine dispatch proof is pending.

The [policy ABI](CELLSCRIPT_POLICY_WITNESS_ABI.md) uses a bounded canonical
Molecule envelope keyed by Script role and complete Script hash. It validates
the entire record vector before selection, rejects duplicate or unsorted keys,
and leaves each selected action's existing `CSARGv1` payload unchanged. The
whole WitnessArgs limit is 4,096 bytes with at most eight records. Host and CKB
adapter codecs are independently implemented; placement preserves other fields,
rejects occupied `input_type`, and must occur before signing.

Metadata schema 69, `cellscript-typed-semantics-v8` and
`cellscript-semantic-foundation-v3` bind the declared policy, selector provenance,
resource layout, variant payload schemas, fixed counts and ordered common
checks. Runtime metadata also binds `cellscript-ckb-runtime-view-v1`, the
closed typed CKB view contract used by 0.30 runtime field access. Lowering
record v6 includes separate terminal-failure sites and requires the exact new
nested versions. The parser-free checker also derives builder encoding flags
and parameter order/source/type from the typed record. This is not independent
proof of machine scanner/adapter dataflow or deployment authentication.

Typed semantics v8 additionally records versioned trusted external verifier
dependencies. That record is admissible only when emitted code checks the
selected CellDep's exact data hash before EXEC or SPAWN/WAIT. Its separate
`trusted-external` evidence tier binds identity and delegation while explicitly
denying any compiler proof of the external verifier's internals; see
[Trusted External Verifiers](CELLSCRIPT_TRUSTED_EXTERNAL_VERIFIERS.md).

Focused CKB-VM tests execute mint, transfer, merge and burn against the same
compiled policy bytes, including optimization levels 0–3, nonzero group
positions, output-only creation, shared witness positions for two complete
Script identities, and rejection cases for role/hash/tag/version/length errors,
extra or missing group members and failing common checks. These are mechanics
fixtures without issuance or ownership authentication. They are not the
required authenticated, stateful Token lifecycle acceptance fixture.

`tests/policy_authorization.rs` separately spends a Token under a real bundled
multisig-v2 Lock at a nonzero input position. Transfer and burn reject missing,
partial and wrong-key signatures. Post-signing changes to the selector, action
memo and sibling record change the actual signing message without changing the
raw transaction hash, and fail specifically at the owner Lock. Permitted memo
and sibling-record edits succeed after legitimate re-signing. This establishes
spending authorization for that witness group, not authorization of arbitrary
other groups, issuer-authorized minting or the full required Token lifecycle.

`tests/policy_lifecycle.rs` separately runs the issuer-authorized Token
lifecycle in real CKB-VM: positive Token Cells are always outputs of earlier
verified transactions, and every action runs under the identical persistent
policy Script. Six committed transactions per edition and optimization level
cover authorized mint, transfer, merge and burn, replay rejection, wrong
amounts, missing/extra outputs and wrong-key credentials. Its negatives also
pin the issuer bound itself: an attacker Cell, an issuer Cell reachable only
through CellDeps, and out-of-range issuer indexes must all fail. The last case
exposed a generated-code defect now fixed: the runtime SourceView helper added
an unchecked dynamic index to the tagged view word, so an index at or above
2^32 carried into the view tag and re-routed an `Input` request to an
`Output` view, letting an issuer-locked output counterfeit input authority.
The helper now fails closed with `ckb-source-view-invalid` (44) before
encoding. This is local live-Cell bookkeeping against the workspace SDK, not
node admission, chain confirmation or clean-tag release evidence, and the
complete required lifecycle fixture remains pending.

`build`, `check`, `metadata`, `expand`, `gen-builder` and `entry-witness` accept
explicit artifact selection. Metadata/expansion use the checked metadata-only
path and do not generate an ELF. Builders expose only declared variants. The
CLI encodes typed action arguments; generated TypeScript's policy helper takes
pre-encoded inner argument bytes and leaves typed materialization, shared-index
aggregation, placement and signing to its runtime contract. Native full/metadata
transport tests cover scalar, fixed-byte, nested aggregate, schema, enum and
Unit payloads. Imported concrete resources and failure-free helpers have
file/virtual-source differential coverage in both editions. The Rust
WASM-feature path retains bounded policy metadata without serializing native
typed/machine evidence; it is not a browser ELF compiler. A public browser
policy-selection binding and editor integration remain product work.

The next independent machine-proof increment must begin at the actual ELF entry
and derive instruction successors/call returns, not trust source labels or
declared reachability. It must bind canonical witness parsing to the selected
tag and argument range, numeric tag branches to actual adapter targets, ordered
common calls to unchanged nonzero rejection, and adapter pointer/length/copy
and decoding behavior to the typed parameter contract. Callee memory effects
and predicate semantics remain separate obligations: proving a call dominates
dispatch does not prove what that call checks. Fixed, dynamic and enum payload
families need explicit verification coverage without silently removing accepted
language features to obtain a simpler proof.

## Next implementation boundaries

The next vertical slices must share an explicit resolved entry context. They
must not infer group ownership from the source edition or from the presence of
the retained preview AST annotation.

- A policy declaration is the sole authority for its exported variants,
  explicit tags, common checks, group resource and versioned dispatch ABI.
  Package, in-memory and virtual-source compilation must resolve the same
  declaration model before producing executable or metadata-only products.
  Builders must not expose retained helper actions as dispatch variants.
- Group rebinding applies to the exact resolved policy resource, not every
  resource-shaped parameter. Read dependencies keep their CellDep locations.
  Mixed absolute/group lifecycle roles need physical alias and coverage checks;
  changing every role to GroupInput is not a substitute. Unsupported combinations
  in the new policy path need explicit diagnostics without removing the existing
  ordinary/scoped compilation path.
- Internal calls and entry adapters are distinct. Current action preludes can
  reload transaction Cells instead of using passed Cell pointers. A retained
  action must not silently acquire either a public tag or a new binding context.
  Cell-bearing action reuse needs caller-anchored bindings, not merely disabling
  one parameter-loading flag.
- Direct successor nodes must carry individual occurrence identity and their
  actual CFG position. Every successful path must cover its lifecycle roles;
  no successful path may dispose of one role twice. Explicit failure exits need
  not finish a transition. A global union of branch dispositions cannot prove
  those properties. Field, identity, capacity and authorization obligations remain
  separate from unique lifecycle accounting.
- `same except` expands after concrete schema resolution and instantiation.
  Every field treatment must be explicit in the resulting semantic record.
  Schema acknowledgement remains separate review evidence bound to the relation
  and old/new schema identities. Existing preview envelope labels are not a
  substitute for deriving policies from the actual relation and its checks.
- The policy witness encoder must preserve existing single-entry CSARGv1 bytes.
  Introduce a separate bounded, versioned multi-record envelope for overlapping
  Script groups, with explicit field ownership and rejection of duplicate or
  unknown selectors. Assemble it before signing; never silently overwrite or
  merge an occupied signature or argument field.

The signed multisig fixture in `tests/entry_witness_abi.rs` is a useful existing
authorization anchor: it combines a real Lock and generated Type Script at a
nonzero input position and rejects witness tampering after signing. It is not
yet the shared-policy lifecycle fixture. Its current local SDK dependency is
not clean-tag release evidence; release validation must use the required pinned
SDK without overwriting unrelated checkout changes.

## Local differential-evidence refresh

The fixed-binding runtime and exact-size guard optimization satisfy the existing
example size and machine-shape budgets without increasing them. The ensuing
backend gate exposed stale measured iCKB snapshots. The supported refresh path
reran all 218 `ickb_diff` tests; each retained its asserted transaction outcome.
A recursive comparison of the 187 matrix rows found no added or removed scenario,
fixture change, accepted/rejected outcome change, original binary change, or
capacity, fee or transaction-size change.

There are 92 changed generated-artifact hashes and eight lower CellScript cycle
measurements: two deposit positives each save eight cycles, and six limit-order
positives each save 22. Error-URL code hashes and dynamic transaction context
hashes also change. Three malformed-deposit negatives require an explicit
additional qualification:

- Nonzero DAO data previously reported the DAO Script at `Outputs[0].Type` with
  error -19; it now reports the generated policy at `Outputs[1].Type` with error 11.
- Short and long DAO data previously reported the DAO Script with error -4;
  each now reports the generated policy with error 11.

The pinned `ckb-script` 1.1.0 verifier iterates Script groups by full Script hash
and returns the first failure. The changed generated ELF changes its Script
identity and moves its explicit malformed-deposit rejection before the DAO
rejection. These are first-reported-error changes, not identical exit-code
evidence. The named failure modes and rejection outcomes remain unchanged.

This is a working-tree evidence refresh, not a new production-equivalence claim
for the authoring target. The matrix's pre-existing `cellscript_source_commit`
marker still names `0be86497a0c1918a9b11bd74f9ccbf234f6c49fe`; the refresh command
does not update it or prove current-source reproducibility. The compiler source
pin and locally refreshed benchmark submodule must be closed together before
release. No benchmark submodule publication is authorized by this refresh.

### Terminal-failure snapshot refresh

A second supported refresh after the terminal-failure backend changes passed
all 218 tests. Compared with the preceding working-tree matrix, all 187
differential outcomes remain unchanged: 37 accepting and 150 rejecting rows.
The 22 supporting evidence rows are unchanged. Fees, capacities and transaction
sizes are unchanged. The new matrix SHA-256 is
`1d7e3d07797b96fbbfe080981b1fad1a16963f01327e3c9974a0f93c770756bb`.

All 37 measured positive transactions use fewer cycles on both sides of the
comparison: the CellScript-side reductions range from 238 to 480 cycles,
totaling 9,540, and the original-side reductions total 5,310. These are complete
transaction measurements, including shared generated auxiliary Scripts, not
isolated measurements of either principal verifier. Rejecting rows retain zero
cycle placeholders, not measured zero-cycle executions. The matrix does not
record ELF byte sizes, so this comparison supplies no iCKB ELF-size delta.

Generated artifact and shared auxiliary hashes change. Four normalized fixtures
change only their derived related-Type hashes; the wrong-Type relationships and
checked data-rule failures remain intact. Fourteen expected patched Owned-Owner
artifacts also change with their embedded related-Type hash. Source pins,
pinned original binary inputs, test assertions and failure-mode classifications
are unchanged.

One negative changes its first reported failure: the receipt wrong-XUDT-owner
case previously reported generated error 48 at `Inputs[0].Type`, and now reports
standard XUDT error -52 at `Outputs[0].Type`. Recomputed full Script hashes put
the unchanged XUDT group between the old and new generated group in the pinned
verifier's ordered map. Thus this transaction still rejects, but this row no
longer independently executes the later generated failure. A separate
receipt-group wrong-XUDT case still reaches generated error 48. This is a
qualified diagnostic change, not identical exit-code evidence or a new
production-equivalence claim. The earlier source-pin and submodule-publication
limitations continue to apply.

### Source-view bound snapshot refresh

A third supported refresh after the SourceView index-bound fix passed all 218
tests. All 187 differential rows keep their scenario, normalized fixture,
fee, capacity and transaction-size values, and all accepting/rejecting
outcomes are unchanged: 37 accepting and 150 rejecting rows. The new matrix
SHA-256 is
`899eb2844bd940132a3936f17aca264ac7fc57c55599b1e1dbb2eebd74c2725d`.

Every generated artifact hash changes because each measured artifact
references the hardened SourceView helper. The 37 measured positive
transactions use more cycles to execute the added bounds check: increases
range from 15 to 83 cycles, totaling 1,926. Rejecting rows keep their zero
cycle placeholders. The 150 rejecting rows' diagnostic URLs embed the new
Script hashes; error codes and reported sources are otherwise unchanged.

One negative again changes its first reported failure, reversing the earlier
qualified direction: the receipt wrong-XUDT-args case previously reported
standard XUDT error -52 at `Outputs[0].Type`, and now reports generated error
48 at `Inputs[0].Type`. The recomputed full Script hashes reorder the pinned
verifier's ordered group map back. The transaction still rejects on both
sides with the recorded `wrong_xudt_binding` failure mode. This is a
qualified diagnostic change, not identical exit-code evidence or a new
production-equivalence claim. The earlier source-pin and
submodule-publication limitations continue to apply.

### Acceptance recipe identity closure

The audited transaction recipes (`transactions-v0.23.json`) still recorded the
pre-0.26b artifact identities, so the CKB acceptance live replay aborted at
its first `artifact_data_hash` comparison. Following the established refresh
precedent, the rebind closes three distinct CKB identity layers as one audited
set:

- all sixty action/Lock case artifacts and 417 exact code-hash references name
  the final VM2 output;
- all 253 Script selectors that reference generated artifacts use Data2, while
  external dependencies retain their original hash type;
- 143 embedded full-Script-hash payload occurrences across 30 generated
  identities are recomputed from the final code hash, Data2 tag and empty
  args.

The third layer is necessary because the recipes carry complete Script hashes
inside witnesses and Cell data as resource identities. Updating an outer
`code_hash` and selector does not update those values. The intermediate replay
therefore passed every `token.cell` action but stopped at
`nft.cell:create_collection` with `CellLoadFailed`: the transaction selected
the new Data2 artifact while its payload still named the old Data1 Script.
Recomputing these values from the last full-pass recipe preserves transaction
shape and business payloads while changing only the cryptographically derived
identity bytes. The clean-source production replay accepts the rebound set and
passes all 43 action cases, 17 Lock cases and 26 stateful scenarios / 46
committed steps. Its seven end-to-end lifecycles and 19 action-branch scenarios
all commit their valid transactions and retain their required negative
rejections.

### Compact deployed ELF layout and immediate encoding

The cost audit measured that 50.82% of the audited transfer ELF was zero
padding before `.text`: its payload started at file offset 4,096. The payload
now starts at 128, while the LOAD segment still starts at file offset 0 with
`p_vaddr = 0xff80`, `p_align = 128`, and entry `0x10000`. This preserves
`p_vaddr % p_align = p_offset % p_align` and saves 3,968 padding bytes.
A shared size/encoding classifier selects single ADDI or representable LUI
forms for `li`, saving another 464 bytes in the audited relation. Its ELF
drops from 7,824 to 3,392 bytes; the token-transfer example drops to 2,576.
After the complete economic tranche, all 37 recorded positive iCKB transactions
remain faster: 805,060 CellScript cycles versus 1,952,526 original-contract
cycles in aggregate. These rows include shared auxiliary Script work and are
transaction-level measurements, not isolated principal-Script savings. The
[0.26 release notes](releases/CELLSCRIPT_0_26_RELEASE_NOTES.md#major-backend-optimization-compact-elf-and-immediate-encoding)
give the byte decomposition, matched Rust scope, and multi-action comparison.
The start trampoline keeps its fixed 20-byte ABI shape; the independent
checker's exit-site decoder already understood both immediate forms, and its
mutation corpus was updated for the new sink layout (corrupting the ECALL itself now trips the
instruction allowlist). Remaining size work from the audit — redundant
schema-size checks, large stack-offset materialization, and compressed
16-bit encodings — is tracked separately.

### Matched cost corpus

`tests/cost_corpus.rs` compares three named CellScript scenarios against
hand-written Rust CKB references with the same checked scope, built under
the audited profile (no_std, ckb-std 1.1.0, opt-level z, thin LTO, one
codegen unit, aborting panics, llvm-strip). Both sides run on the same VM
fixtures and must agree on every accept/reject outcome.

| Scenario | CellScript | stripped Rust | ratio | cycles CS / Rust |
| --- | ---: | ---: | ---: | ---: |
| Pool merge (2-in, checked sum, lock binding) | 2,512 B | 2,816 B | 0.89x | 6,000 / 9,232 |
| Schema roll (2 fields, one updated) | 2,272 B | 2,760 B | 0.82x | 8,661 / 10,350 |
| Ownership-claim Lock | 2,232 B | 2,304 B | 0.97x | 5,583 / 6,333 |

Reading: the original corpus exposed three byte-size counterexamples against
tight hand-written references. The complete economic-backend tranche closes
all three while preserving the same VM accept/reject fixtures, and also lowers
the measured positive cycles. Real system-script deployments for context: DAO 7,896 B,
secp256k1 sighash 52,048 B, secp-data 1,048,576 B, xUDT (iCKB original)
33,696 B — different feature scopes, not matched comparisons. The corpus is
cost evidence for named samples, not a theorem about arbitrary future programs.
The full mechanisms, Spore/Fiber measurements, and mandatory VM2/Data2
deployment contract are recorded in the
[0.26 release notes](releases/CELLSCRIPT_0_26_RELEASE_NOTES.md#economic-backend-closure-and-vm2-deployment-contract).

### WASM playground bundle budget

Rebuilding the canonical playground bundle in the pinned container
(rust 1.97.1, wasm-bindgen 0.2.121, binaryen 131) after the 0.26b tranches
produces a 1,730,601-byte module that gzips to 659,050 bytes (643 KB) —
44,650 bytes over the 600 KB budget that `website/scripts/build-wasm.sh`
enforces, so the script correctly refuses. The committed bundle, last built
within budget before these tranches, gzips to 590,700 bytes (576 KB) and was
left in place; the over-budget output was not committed. The growth is real
surface: the policy, artifact, binding and authoring modules are reachable
from the metadata-only compile path and cannot currently be dead-stripped
from the wasm build. Binaryen 131 metrics on the rebuilt module attribute it
to aggregate compiler code (3,389 functions, ~690K wasm-opt units, ~190 KB
of memory data) rather than a single outlier block, so the trim is a
feature-gating and surface-reduction work item, not a one-line fix. The `ci` website check does not rebuild the bundle,
which is why this stayed latent. Until the wasm path trims or gates the new
surface, the release gate's `check_wasm_release_bundle` will fail; resolving
it is part of the pending language-services/product row, not a budget
change.

## Verification workflow

The successor-relation tranche passed the complete `dev` gate on 2026-09-06.
Current evidence includes all 892 compiler unit tests, the six-case
`authoring_replace` suite, authoring parity, entry selection, both policy
suites, the artifact checker and clippy with warnings denied. The registered
syntax seed is included in the passing quick matrix: 67 accepted and 56
rejected cases out of 123 generated, with zero failures. The strict quick
report is
`target/cellscript-strict-backend-audit/strict-backend-audit-quick-20260906-162715.json`.
This is current development evidence; it does not promote the documented
WASM, full-backend, chain or release boundaries.

The policy tranche passed the complete `dev` gate on 2026-09-05. Its strict
quick audit report is
`target/cellscript-strict-backend-audit/strict-backend-audit-quick-20260905-205049.json`;
the accompanying quick syntax audit accepted 66 and rejected 56 of 122 generated
cases, with zero failures. Focused evidence also includes 868 compiler unit
tests, native compiler/checker clippy, real policy VM/authorization tests,
outer-hash-rebound checker mutations, CLI/builders, imports, native transport
parity and the metadata-only WASM-feature test. Generated TypeScript typechecks
and all nine generated Node tests pass. These are working-tree development
results; `ci` and clean-source production evidence are
separate requirements.

The policy tranche's full backend run also passed compiler, checker and Fiber
tests, clippy, both package scenario backends, and the strict audit checks except
the final clean-source stateful stage. Its report is
`target/cellscript-strict-backend-audit/strict-backend-audit-full-20260905-205657.json`.
That stage stopped before scenario execution because the source tree is dirty.
Both policy gate runs predate the terminal-verifier-failure changes; they are
not evidence for those newer bytes.

The pre-policy backend run on 2026-09-05 passed compiler tests (including the
218-case iCKB suite), checker/Fiber tests, clippy, both package scenario backends,
and the 166-case syntax combination audit. Its final stateful CKB stage rejected
the dirty source tree before scenario execution. The report is
`target/cellscript-strict-backend-audit/strict-backend-audit-full-20260905-202015.json`.
That is an incomplete backend gate, predates the policy tranche, and cannot be
reused as current-source production evidence. Existing user-owned worktree and
external SDK changes have not been cleared to bypass the gate.

Focused tests are development feedback. They do not replace the unified gates:

```bash
cargo test --locked -p cellscript --test authoring_parity
cargo test --locked -p cellscript --test entry_selection
cargo test --locked -p cellscript --test native_group_binding --test protected_group_binding
cargo test --locked -p cellscript --test read_ref_binding --test resolved_binding_metadata
cargo test --locked -p cellscript --test policy_artifact_checker --test policy_artifact_cli --test policy_imports
cargo test --locked -p cellscript --test policy_authorization --test policy_witness_codec_parity
cargo test --locked -p cellscript-tools syntax_combo::tests
./scripts/cellscript_gate.sh dev
./scripts/cellscript_gate.sh backend
./scripts/cellscript_gate.sh ci
```

The release gate remains subject to its clean-source, pinned-toolchain,
artifact, external-tooling and chain-evidence requirements. Do not weaken a gate
or clear unrelated worktree changes to obtain a passing result. Current test
outputs and gate reports, rather than this command list, are the evidence.
