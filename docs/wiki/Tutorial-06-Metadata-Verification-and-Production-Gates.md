# Tutorial 06: Metadata Verification and Production Gates

Every CellScript CKB ELF build should be treated as one four-file bundle:

```text
artifact
artifact.meta.json
artifact.lowering.json
artifact.sourcemap.json
```

The artifact is executable RISC-V ELF. The metadata sidecar is the explanation:
source identity, target profile, artifact hash, schema layout, runtime
requirements, scheduler information, and verifier obligations. The canonical
lowering record exposes a bounded typed-semantics, CFG, ABI, stack, ProofPlan,
syscall, runtime exit, and final machine-range contract. The canonical source
map binds source spans and lowering blocks to final ELF instruction ranges. On
`0.26b`, source-map v2 also maps semantic node IDs to diagnostic spans, while a
separate `SourceDigest` identifies source bytes. Assembly output does not claim
this verified-artifact boundary.

It also carries the mandatory package edition and the fully resolved
compatibility profile. Edition contributes source semantics only.
The profile combines that with independently versioned target,
primitive-assurance, entry payload, witness placement, and metadata-schema
axes. Verification rejects a sidecar whose profile does not resolve from those
inputs; it never guesses another contract. Current `0.30` outputs use metadata
schema 71, source schema 2, artifact schema 1, and constraints schema 4. Runtime
metadata binds the closed `cellscript-ckb-runtime-view-v1` contract and the
structured `cellscript-ckb-runtime-access-provenance-v1` source/index/range
contract.
Schema 71 also records `runtime.signing_message_domains`. For
`cellscript-ckb-sighash-all-zero-lock-v1`, verify the current input Script-group
scope, complete first-lock zero transform, witness ordering, `SighashAllDigest`
result type, and four literal bounds as one contract. The independent checker
cross-checks the record against typed semantics and runtime provenance. This
record does not cover prefix-preserving multisig placeholders.
Metadata includes canonical `public_interface` / `interface_hash` and
`typed_semantics` / `typed_semantics_hash` pairs. Typed semantics v6 embeds the
semantic-foundation v2 record and resolved fixed-Cell binding tables. Registry,
lock, deployment, receipt, and generated-builder readers require the same
resolved-profile identity.

The distinction matters during review: compiler SemVer can advance for
compatible implementation work, and a wire ABI or metadata schema can advance
for an urgent fix, without forcing a new calendar-year source edition. A new
Edition is reserved for a change to the meaning of existing source.

This chapter is about trust boundaries. It teaches you what compiler evidence
can prove, and where you still need CKB transaction evidence.

## The Main Rule

Compiler verification is necessary, but it is not the same thing as a deployed
transaction or chain acceptance report.

If `verify-artifact` passes for an ELF, you know all four files agree and that
the standalone checker independently accepted the bounded typed and structural
contracts.
You do not yet know that a transaction builder can provide the right inputs,
serialize the right witness, satisfy capacity, pass dry-run, and commit. The
checker does not claim complete source-to-machine semantic equivalence.

That distinction prevents overclaiming.

## Emit Metadata

Compile normally:

```bash
cellc build --json
```

For a persistent Type policy explicitly declared in the package's
`[[artifacts]]`, select that declaration for both checks and builds:

```bash
cellc check --artifact token-policy --all-targets
cellc build --artifact token-policy --target riscv64-elf --json
```

The build flag is mutually exclusive with `--entry-action` and `--entry-lock`.
It selects the versioned policy envelope, not the old single-entry witness ABI.
Inspect `runtime.policy_artifact` and the compatibility profile in the emitted
metadata. A valid declaration is not authentication or deployment evidence;
see the [policy witness contract](../CELLSCRIPT_POLICY_WITNESS_ABI.md) before
constructing and signing a transaction. `entry-witness --artifact` requires an
exported action and a full Script hash and emits only the policy payload;
`gen-builder --artifact` exports the declared variants and records the runtime's
aggregation, placement, and signing responsibilities. Its raw-inner-argument
helper does not replace typed argument encoding.

Or request metadata directly:

```bash
cellc metadata src/main.cell --target riscv64-elf --target-profile ckb -o /tmp/main.meta.json
```

Add `--artifact token-policy` to inspect the explicitly selected policy through
the metadata-only compiler path. This does not produce an ELF, assembly,
sidecars, or a machine artifact hash; `--output` writes only the inspection JSON.
Without the flag, the existing default-entry path remains unchanged.

Open the metadata when something is unclear. It is often easier to understand a
compiler decision by reading the emitted facts than by guessing from the source
alone.

Inspect the canonical semantic foundation separately:

```bash
cellc expand src/main.cell
cellc --json expand src/main.cell
cellc expand --artifact token-policy
cellc expand --artifact token-policy --json
```

The foundation exposes value provenance, artifact entry selection, transaction
roles, Cell dispositions, enforcement-classified claims, and layered semantic
IDs. The human rendering is deterministic but is not hashed. Source paths and
spans are intentionally excluded from `CoreSemanticId`.

The selected-policy view includes exported numeric tags, entry IDs, payload
schema hashes, exact group input/output counts, selector bounds, and common
checks in declaration order. It does not treat retained helper actions as
dispatch variants. Like selected `metadata`, selected `expand` does not invoke
machine-code generation.

For an executable source `require` or Edition 2027 `enforce`, inspect its
`entry-condition` claim. `evidence_reference` selects the typed
`branch-condition`; `execution` records the condition-provenance node, ordered
success and failure blocks, and exact fail-closed runtime-error code. Supporting
ProofPlan obligations use `proof-plan:<name>` references and no execution
binding. The independent checker validates these structural links, while still
making no complete source-to-machine equivalence claim.

## Verify an Artifact

Start with the basic check:

```bash
cellc verify-artifact build/main.elf
```

The command automatically loads `build/main.elf.meta.json`,
`build/main.elf.lowering.json`, and `build/main.elf.sourcemap.json`. Use
`--metadata`, `--lowering-record`, and `--source-map` only for custom paths.

Pin the target profile:

```bash
cellc verify-artifact build/main.elf --expect-target-profile ckb
```

Verify source units on disk:

```bash
cellc verify-artifact build/main.elf --verify-sources
```

Use production checks when preparing release evidence:

```bash
cellc verify-artifact build/main.elf --production
cellc verify-artifact build/main.elf --deny-fail-closed
cellc verify-artifact build/main.elf --deny-runtime-obligations
```

Read this gate narrowly: it verifies binding, structural ELF/lowering/source-map
invariants, source hash expectations, and selected policy flags. Its JSON report
keeps `binding_verification`, `structural_verification`,
`lowering_record_verification`, `ckb_vm_evidence`, and `chain_evidence`
separate, and keeps `semantic_equivalence_claimed = false`. It does not prove
that a concrete CKB transaction has been built, deployed, dry-run, indexed, or
measured.

## Check Before Build

Use check mode for CI and local feedback:

```bash
cellc check --all-targets --production
cellc check --target-profile ckb --json
```

Important policy flags:

| Flag | Purpose |
|---|---|
| `--production` | Reject unsafe or incomplete lowering paths. |
| `--deny-fail-closed` | Reject metadata that contains fail-closed runtime features or obligations. |
| `--deny-ckb-runtime` | Reject CKB runtime features when they are not allowed for the workflow. |
| `--deny-runtime-obligations` | Reject runtime-required verifier obligations. |

These flags are useful because they turn "remember to inspect this later" into a
compiler-visible failure.

## What To Inspect First

You do not need to memorize the whole sidecar. Start with these fields:

- `target_profile`
- `artifact_format`
- `artifact_hash`
- `artifact_size_bytes`
- `source_hash`
- `source_content_hash`
- `source_units`
- `metadata_schema_version`
- `source_metadata_schema_version`
- `artifact_metadata_schema_version`
- `constraints_metadata_schema_version`
- `actions`
- `locks`
- `schema`
- `runtime`
- `verifier_obligations`
- `runtime.proof_plan`
- `runtime.proof_plan_soundness`
- `runtime.transaction_view_handles`
- `capability_registry`
- `types[].capability_set_version`
- `runtime.capability_proofs`
- `runtime.builder_assumptions`
- `template_layouts`
- `constraints`
- `runtime_error_registry`
- `constraints.artifact`
- `constraints.entry_abi`
- `constraints.ckb.capacity_evidence_contract`
- `constraints.ckb.declared_capacity_floors`
- `constraints.ckb.hash_type_policy`
- `constraints.ckb.dep_group_manifest`
- `scheduler`

When reviewing a contract, ask simple questions first:

- which action or lock is the entry;
- what witness does it expect;
- which Cells are consumed or created;
- which runtime obligations remain;
- which CKB profile assumptions are recorded.

The top-level `metadata_schema_version` is the envelope version. The component
schema fields split review risk by surface: source/package identity,
artifact-binding facts, and CKB constraint summaries can now move independently
in future schema revisions. `verify-artifact` still rejects a mismatch in any of
these versions.

Schema 53 includes `runtime.transaction_view_handles`. Each record identifies the
callable scope, source (`Input`, `GroupOutput`, `CellDep`, and so on), public
handle type, and evidence tiers. A conforming record is a read-only view with
`lifecycle_authority = false`; it is evidence of a transaction read surface,
not evidence that a Cell was consumed or an output was created.

Schema 53 also makes capability authority auditable. The top-level
`capability_registry` fixes both the closed vocabulary and entailment version;
each persistent type repeats `capability_set_version`. For every accepted
`destroy` or `replace_unique`, inspect `runtime.capability_proofs`: `required`,
`provided`, `entailed`, and `missing` must agree, `missing` must be empty, and
the proof's versions must match the registry. `replace_unique` additionally
records the exact `identity(...)` condition declared by the same resource.
No proof may source authority from a container or another Cell type.

Top-level `enum_layouts` for concrete payload ADTs first appeared in schema 53
and remain in current metadata schema 71 on the `0.30` development branch. Audit the
`packed-tagged-union-v1` layout, one-byte tag, sequential variant tags, packed
field offsets, encoded size, ownership, storage, and ABI together. A
`linear-cell-handle` field is exactly eight bytes and forces
`local-linear-handle-v1` storage; it is never a persistent serialization claim.
Non-linear fixed payloads use `serializable-fixed-width`. Pure helpers may
return layouts of at most 16 bytes through
`fixed-bytes-pointer-v1+register-pair-return-v1`; larger layouts remain local or
parameter values. Generic and variable-width payload enums are compile errors.

Bounded `forall` and `count` invariant clauses appear as
`bounded-source-quantifier` ProofPlan records. Review `reads`, `coverage`,
`group_cardinality`, and `evidence_tier`: coverage names the source scan,
complexity, declared field reads, runtime cardinality, vacuous-zero behavior,
and count overflow policy. A `runtime-helper-required` record is a known helper
contract, not proof that the selected artifact emitted or executed that helper.

`runtime.collection_instantiations` also distinguishes local stack collections
from source-aware bounded Cell collections. For a checked
`BoundedCellSet<T, N>`, verify `source = input`,
`ownership = linear-cell-set`, `status = checked-runtime`, finite
`max_elements`, and helper `bounded-type-group-inputs-v1`. The matching
ProofPlan must say `actual_scanned_cardinality:runtime-observed`,
`group_input_count<=N`, and `on_chain_checked = true`.

For a checked `BoundedList<P, N>` driving `create_each`, verify
`source = witness`, `ownership = bounded-output-plan`, helper
`bounded-output-plan-v1`, `output_cardinality_max = N`, and
`capacity_builder_evidence_required = false`. Its ProofPlan must bind exact
plan/output count, fixed-width codec, canonical `GroupOutput` order, output
data, lock, and capacity floor. A `builder-evidence-required` record instead
means the selected create shape did not qualify for the 0.26 runtime contract.

Treat every selected consensus ProofPlan whose `codegen_coverage_status`
begins with `gap:` as a production blocker. Unsupported bounded shapes still
emit runtime error 24 in permissive artifacts and stop at E2105 under the
production policy; a static `N` alone is never evidence that a scan ran.

The validity record first appeared in schema 55 during the 0.22 line and is
retained by current metadata schema 71 on the `0.30` development branch as
`types[].validity_predicates`. Review each predicate's
`expression`, `dependencies`, `evidence_tier`,
`runtime_checked_on_create`, `create_paths_selected`,
`create_paths_checked`, `update_paths_selected`, `create_path_status`,
`update_path_status`, and `source_span` together. `checked-runtime` means every
selected constructor/create path emitted a fail-closed predicate before its
output instruction. Partial path coverage is
`partial-runtime-helper-required`, never `checked-runtime`. A named output or
update path without concrete predicate lowering stays
`runtime-helper-required`; it is not silently promoted by metadata.

`env::block_number()` is the only approved validity environment read in this
line. CKB-VM does not expose an ambient current-tip block-number syscall, so
CellScript records `builder-evidence-required` with explicit header-dep builder
evidence instead of emitting a fictional runtime call. Unknown `env::*` reads
are compile errors. Pure imported helpers are retained transitively and receive
module-qualified dependency names; lifecycle helpers and transaction-view
reads are rejected in validity predicates.

Explicit borrow blocks first appeared in schema 55 and current metadata schema
64 records them in
`runtime.borrow_regions`. Review
`root`, `binding`, `view_type`, `storage`, `abi`, `allowed_effects`,
`evidence_tier`, and `source_span`. A canonical record has `View<T>`,
`storage = none`, `abi = none`, `allowed_effects = [Pure, ReadOnly]`, and
`checked-static` evidence. Its matching `borrow-region` ProofPlan entry proves
compiler rejection of escape, root lifecycle crossing, and incompatible
callee effects; it does not describe a runtime allocation or persistent CKB
Cell reference.

## Assurance Layer

CellScript 0.16 added a checked assurance layer over ProofPlan metadata, and
0.21 extends the same evidence stream with ProtocolGraph, TemplateLayout, and
compile receipt binding:

```bash
cellc explain proof src/main.cell --json
cellc explain assumptions src/main.cell --json
cellc tx validate --against build/main.elf.meta.json --tx tx.json --json
```

`runtime.proof_plan_soundness` tells you whether verifier obligations and
ProofPlan records agree. `--primitive-strict=0.16` rejects metadata-only or
runtime-required ProofPlan gaps. The soundness key includes origin/scope,
category, feature, status, and detail; local and runtime ProofPlan records are
compared by full semantic content, including trigger, reads, coverage, and
source spans.

`runtime.builder_assumptions` is the machine-readable contract for transaction
builders. `tx validate` checks a transaction JSON shape against that contract,
rejects bare evidence tokens, and requires indexed evidence objects for
non-structural assumptions before signing. Evidence indexes are range-checked
against the transaction, and concrete fields such as outpoints, hashes,
capacity, dep metadata, witness bytes, and TYPE_ID args must match when present.
For `exact_script_handle`, the validator additionally checks the complete
202-byte handle against its compile-time hash, class and role; recomputes the
selected Lock/Type Script or verifier CellDep data identity; decodes
`WitnessArgs.input_type`; and binds the handle to its compiled `CSARGv1`
parameter position. Exact-handle source items therefore need resolved Script,
Script-hash, data, or data-hash fields in addition to their transaction index.
This is still pre-chain evidence: dry-run, capacity, cycles, and commit checks
remain required for production claims.

Additional audit reports are available for audit and deployment workflows:

```bash
cellc tx solve src/main.cell --json   # emits can_submit=false template output
cellc explain graph src/main.cell --format mermaid
cellc deploy plan src/main.cell --json
cellc proof-diff old.meta.json new.meta.json --json
cellc audit-bundle src/main.cell --output target/audit
```

ProtocolGraph role labels are explanatory metadata. For each action, inspect
`actions[].protocol_role_candidates`; for each graph edge, inspect `role`,
`role_source`, `role_source_used`, `role_candidates`, `role_status`, and
`role_warnings`. The deterministic precedence is:

1. a direct verification equality between an Address-valued Cell field and an
   Address supplied by witness, default entry witness, or `lock_args`;
2. a participant-like witness or `lock_args` Address binding;
3. a participant-like Address field name.

The third form is deliberately weak. Renaming `participant` to a neutral field
name yields `PG-ROLE-MISSING`; it never silently creates authority. Conflicting
roles yield `PG-ROLE-CONFLICT` while preserving all sources. Every role record
is `metadata-only` with `authorization_proven = false`, and no role appears as
authorization evidence in ProofPlan. Authorization still has to be enforced by
the lock/type Script and its generated runtime checks.

## 0.21 Compile Receipts

Compile receipts bind the same evidence stream to deterministic hashes:

```bash
cellc receipt src/main.cell --output target/main.receipt.json
cellc sign-receipt target/main.receipt.json --role publisher --key publisher.ed25519.pkcs8
cellc verify-receipt target/main.receipt.json \
  --metadata target/main.elf.meta.json \
  --artifact target/main.elf
cellc verify-artifact target/main.elf --receipt target/main.receipt.json
```

Receipt signatures authenticate metadata/artifact evidence and derived report
hashes. They do not prove transaction validity, live-cell freshness, dry-run
success, capacity sufficiency, or successful submission.

## 0.21 TemplateLayout Metadata

`template_layouts` is metadata-only in the current compiler: records are derived
from resource/shared/receipt type metadata, use a `Flat` layout by default, and
set `consensus_checked = false` until a backend verifier explicitly enforces a
template commitment. Cyclic flow state machines are marked with
`cycle_policy = RootRequired`; acyclic layouts use `PathOnlyAllowed`.

The compiler rejects unsupported `consensus_checked = true` claims in this RC.
That keeps TemplateLayout from looking consensus-enforced before generated
verifier code actually checks the template commitment.

ProofPlan coverage states are intentionally explicit:

| State | Meaning |
|---|---|
| `gap:metadata-only` | The claim is preserved for audit but has no executable verifier coverage. |
| `gap:runtime-helper-required` | The claim maps to a runtime helper, but the selected entry did not emit matching helper coverage. |
| `checked-runtime` | Generated runtime access backs the claim for the selected entry. |

Introduced on the 0.22 line and retained by the current compiler, invariant
read ranges and aggregate operands are
parsed once into a closed typed target: a source view (`inputs`, `outputs`,
`group_inputs`, `group_outputs`, `cell_deps`, `header_deps`, `witness`, or
`lock_args`) plus optional cell type and field. The formatter emits canonical
plural source-view names, while ProofPlan keeps the same readable target text.
Unknown generic source views fail in the parser; later compiler phases do not
recover their meaning by splitting strings.

The evidence tiers introduced on the 0.22 line still record who must discharge
every obligation:

| Evidence tier | Discharged by |
|---|---|
| `checked-static` | Compiler or static analysis. |
| `checked-runtime` | Generated verifier code. |
| `runtime-helper-required` | A known helper contract that is not emitted for the selected entry. |
| `builder-evidence-required` | Transaction-builder or indexer evidence. |
| `metadata-only` | Audit metadata with no executable enforcement. |
| `chain-evidence-required` | Dry-run, tx-pool, commit, capacity, or cycle evidence. |

The tier is serialized as `evidence_tier` in each ProofPlan record and is also
shown by `cellc explain proof`. `--production` rejects metadata-only records
whose invariant, terminal, or assert/check/enforce/require/validate/verify
naming promises executable enforcement. This does not turn builder or chain
evidence into compiler proof; those tiers remain external obligations.

For the review-finding closure matrix, see
`docs/archive/0.17/CELLSCRIPT_0_17_REVIEW_FINDINGS_CLOSURE.md`.

## Effect And Terminal Evidence

Introduced on the 0.22 line and retained by the current compiler, function
helpers can publish the same stable effect contract as actions:

```cellscript
#[effect(ReadOnly)]
fn read_threshold(config: &Config) -> u64 {
    config.threshold
}
```

Function metadata distinguishes `declared_effect_class`,
`inferred_effect_class`, and the effective `effect_class`. The compiler walks
the call graph transitively and recomputes imported helpers from loaded package
source. An imported `#[effect(Pure)] fn` that wraps a creating or mutating
action is rejected; the attribute is not treated as an unauthenticated promise.
`effect_evidence_tier = checked-static` records that this contract is discharged
by the compiler.

Canonical terminal flows use enum-backed states:

```cellscript
flow SwapLock.state {
    initial Pending;
    terminal Claimed, Refunded;

    Pending -> Claimed;
    Pending -> Refunded;
}
```

Inspect these type metadata fields together:

- `flow_initial_state` and `flow_terminal_states` describe the local state
  contract;
- `flow_terminal_discharge = terminal-by-output-state` identifies the only
  implemented 0.22 discharge model;
- `flow_terminal_evidence_tier = checked-runtime` records generated verifier
  discharge;
- `flow_state_model = enum-backed` distinguishes the canonical surface from
  migration-only numeric flows;
- `flow_audit_warnings` reports legacy declarations or an initial state with no
  outgoing edge.

An action edge that reaches a declared terminal emits a `flow-terminal` /
`terminal-by-output-state` verifier obligation and matching ProofPlan record.
That record proves the selected transaction's output-state check. It is not a
global liveness, chain inclusion, capacity, or eventual-termination proof.

## Suggested Compiler CI Gate

For CKB packages, a useful compiler CI gate is:

```bash
cellc fmt --check
cellc check --target-profile ckb --all-targets --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

For CKB, make the profile explicit in every step:

```bash
cellc check --target-profile ckb --production
cellc build --target riscv64-elf --target-profile ckb --production
cellc verify-artifact build/main.elf --expect-target-profile ckb --verify-sources --production
```

These gates are suitable for a compiler/package CI loop. They are not enough for
a release claim that says a contract is production-ready on a chain.

## Syntax-Combination Preflight

Syntax and lowering bugs can pass ordinary example compilation when the risky
shape is hidden in an uncommon combination. The reusable syntax-combination
audit exists to catch those bugs before chain evidence is generated:

```bash
./scripts/cellscript_syntax_combo_audit.sh quick
./scripts/cellscript_syntax_combo_audit.sh ci
```

The syntax-combination audit is a release acceptance preflight. It exercises
parser, formatter, type checking, lowering, metadata, codegen, and negative
obsolete-syntax oracles with compact reports under
`target/syntax-combo-audit/`.

On success, the generated cases and their metadata/assembly are reproducible
from the recorded mode, seed, matrix, and checked-in seeds, so the runner keeps
only `report.json` and `report.jsonl`. Failed and explicit `repro` runs keep the
complete intermediate tree. Each mode has a small `latest-<mode>.json` index,
and local managed history defaults to the most recent three runs. Use
`CELLSCRIPT_KEEP_GATE_WORKDIRS=1` for a successful debugging run that needs all
intermediates, or `CELLSCRIPT_EVIDENCE_KEEP_RUNS=all` when another process will
archive every run.

For CellScript releases, `quick` is part of the pre-push gate and `ci` runs
before builder-backed CKB acceptance. A direct CKB acceptance run does not
replace this preflight because it only proves selected concrete transactions.

The required syntax origins include both comma-terminated canonical type
fields and comma-free compatibility input. The formatter must converge both to
the comma-terminated form; lifecycle field blocks remain newline-separated
field names without commas.

## Unified Gate Entry Points

For repository work, use the unified gate wrapper instead of hand-picking
component scripts:

```bash
./scripts/cellscript_gate.sh dev
./scripts/cellscript_gate.sh ci
./scripts/cellscript_gate.sh backend
./scripts/cellscript_gate.sh release
./scripts/cellscript_gate.sh release-quick
```

`dev` is the local fast path. `ci` is the pull-request gate. `backend` is for
IR/codegen/RISC-V changes. `release` is the production CKB evidence gate.
`release-quick` is a compile-only release preflight, not external live/devnet
evidence. See `docs/CELLSCRIPT_GATE_POLICY.md` for the exact command contract.

In `dev` and `ci`, the wrapper also checks that
`examples/language/core/canonical_style.cell` is already formatter-clean and that
the checked atomic-swap, NFT, timelock, and multi-phase-DAO example pairs use
named `U64_MAX` boundary expressions. CI's CKB-VM integration tests encode
CellScript entry payloads in canonical `WitnessArgs.input_type`; a raw
`CSARGv1` witness is a negative ABI case, not a valid test shortcut.

Fiber's no-profile compatibility harness is deliberately separate from these
unified gates:

```bash
./scripts/cellscript_fiber_acceptance.sh --static
```

This runs the dedicated invariant-entry CKB-VM matrix plus adapter tests. A
passing result means the exact compiled entry accepts and rejects the covered
CKB transaction shapes; it does not mean a Fiber node has loaded or announced
the generated UDT configuration. Full mode validates a complete externally
produced lifecycle report against an exact Fiber revision. Completed rows and
certified topology reports reference files under an explicit evidence root by
normalized relative path plus CKB Blake2b-256 digest; missing, empty,
symlinked, path-escaping, or modified evidence fails closed. This proves bundle
integrity, not the identity of its operator. Full mode never manages node
processes or signing keys. Treat `StaticallyCompatible`,
`LocalNodeConfiguredRestartRequired`, `LocalNodeAdvertised`, `ChannelReady`,
and `TopologyCertified` as distinct monotonic evidence states.

The entry accepts either legacy 32-byte Type Script args containing an input
Lock Script hash, or tagged 33-byte args containing `0x01` followed by an input
Type Script hash. Issuance or destruction requires a matching absolute input.
The tagged form lets a stateful policy Type Script enforce caps, reserves, or
bridge accounting while that policy Cell's Lock independently carries
single-owner, multisig, or governance authorisation. Every ordinary Fiber
channel transaction instead takes the unauthorised path and must have
non-empty, checked-`u128`, conserved Type Script groups. A 2026-07-20 bounded
devnet run observed the exact config through `node_info` and passed Fiber's
official routed-payment and pending-TLC watchtower suites, but it did not
produce a signed-announcement report or the complete pinned matrix and is not
full or release evidence.

## CKB Release Evidence Gate

When you are ready to make a CKB production claim, move from compiler evidence
to chain evidence. Run the CKB acceptance gate from the CellScript repository
root:

```bash
./scripts/cellscript_gate.sh release
```

For pre-push checks, the development gate runs the compiler checks, strict
backend quick audit, syntax-combination quick audit, and diff checks:

```bash
./scripts/cellscript_gate.sh dev
```

If you specifically need the old compile-only production acceptance pass,
`./scripts/cellscript_ckb_release_gate.sh quick` remains supported and delegates
to `./scripts/cellscript_gate.sh release-quick`. The legacy
`./scripts/cellscript_ckb_release_gate.sh full` command is also supported as a
compatibility wrapper for `./scripts/cellscript_gate.sh release`. The production
mode is the release-facing gate because it first runs compiler and
backend-contract evidence, then runs pinned local CKB acceptance transactions,
public builder-contract generation, and mandatory stateful scenario/action
coverage.

The CKB validator records primitive-strict original bundled-example coverage,
including strict v0.16 PP0150 fail-closed records, then requires scoped action
and lock compile coverage, public `action build`/`gen-builder` contracts,
source-bound acceptance provenance, acceptance-harness action and lock
valid-spend/invalid-spend matrices, valid
transaction dry-runs, committed valid transactions, malformed rejection,
measured cycles, consensus-serialized transaction size, occupied-capacity evidence,
exact-artifact build reports, live code-cell data-hash linkage, no
under-capacity outputs, bundled example deployment, and a passed final
production hardening gate. Fail-closed PP0150 records are evidence of a strict
boundary, not deployable production acceptance.

The report must explicitly record a passed final production hardening gate and
source provenance for the repository commit, tracked source file list, tracked
source hash, acceptance runner hash, and evidence validator hash. It must also
record `cellscript_build_reports`: each row binds the compiled RISC-V ELF,
`verify-artifact` result, the exact 20-byte ELF entry trampoline, CKB data hash, and any live
devnet code-cell deployment whose data hash equals that compiled artifact hash.
Compile-only reports keep the live deployment list empty and are not external
release evidence.

Release evidence is accepted only from a completely clean CellScript checkout.
The full run also binds the local CKB checkout to
`scripts/ckb_acceptance_pin.json`: exact revision, clean worktree, version
string, executable hash, source and effective template hashes, and genesis
hash. Production does not accept a supplied or cached CKB binary: it builds the
pinned source in a fresh dedicated Cargo target directory and archives that
executable with the report. Each stateful step must also carry a committed
transaction, dead consumed inputs, live declared outputs, measured cycles,
serialized size, and occupied-capacity evidence. Tagged GitHub releases cannot
build or publish until this full gate has passed, and the tag/version must match
the workspace version.

The report's builder-backed action runs, lock cases, and stateful transactions
come from the native Rust recipe replayer and are labelled that way. The
separate public-builder contract gate proves that every production action is
exposed by `cellc action build` and `cellc gen-builder`; it does not claim those
generated packages constructed the acceptance transactions. Likewise,
`always_success` resource Type Scripts are fixture-only. They prove scoped
verifier behaviour and transaction shape, not the production resource-identity
deployment story.

Registry artifact evidence remains another independent boundary. A
`verified_build` record may carry compiler-backed CellScript verification, the
declared hash-bound generic profile level, or `structurally_verified` evidence
from the least-privilege artifact checker. Generic CKB bundles remain
`hash_bound`; structural admission requires the complete metadata, lowering
record, and source map set, and partial verified sidecars fail closed. None of
those levels is deployment or chain evidence. A reproducible profile is not
`verified` until `reproduced_build` evidence binds at least two independent
builders to the signed source, recipe, environment, executable, and logs.
Likewise, a wallet-ready Registry commitment file is not chain evidence. Only a
sufficiently confirmed live mainnet Cell matching the configured Registry Type
Script, commitment custody Lock, exact commitment data, and both live Script
code CellDeps can produce current `on_chain_committed` state. Scheduled
reconciliation demotes that current state when the commitment or deployment
Cell is spent or no longer sufficiently confirmed.

LS-IDL introduces another narrow Registry evidence layer. The interface
verifier checks a bounded IDL schema, `SHA-256` of the exact ABI object bytes,
and the executable's final 32-byte commitment. A chain-verified lookup also
binds those bytes to a deployed Script identity. This is still not proof that
the Lock Script implements the decoder correctly and is not a security audit.
Do not promote `schema-and-suffix-bound` into semantic, VM, or chain-execution
evidence.

Package resolution is an earlier, separate gate. `Cell.lock` v4 binds the
exact `Cell.toml` digest, root and dependency compiler requirements, the
resolving compiler release, dependency graph edges, dependency manifests,
whole-tree hashes, exact Git/Registry source pins, feature/test modes, and CKB
environment genesis identity. Build/check/test never perform mutable version
selection. A changed manifest or source requires explicit `cellc lock` or
`cellc update`; `--frozen` additionally forbids network access and lockfile
writes. The Registry's versioned profile catalog allows only
`cellscript_source` to enter this graph. Executable, reproducible, TCB, and copy
artifacts retain their separate evidence and consumption paths.

For the current NovaSeal profile set, production-ready source-package evidence
means the live local devnet runners pass for core, Agreement, and the six
planned profiles: BTC transaction commitment, BTC UTXO seal, dual seal, Fiber
candidate, Fungible xUDT, and RWA receipt. Public/mainnet deployment evidence is
separate: profile docs must still name any required CellDep attestation,
external BIP340 TCB review, public BTC SPV/indexer report, or RWA legal/registry
review.

The production gate compiles the seven production checked-in top-level example
contracts directly: token, NFT, timelock, multisig, vesting, AMM pool, and
launch. Those files are the single canonical production business source and the
cleaner reading surface; there are no checked-in `examples/business` or
`examples/acceptance` mirrors. Acceptance-only profile/effect/scheduler
metadata belongs in runner configuration or generated files under `target/`.

Lock behavior coverage is machine-readable through
`lock_acceptance_scope.onchain_lock_spend_matrix_scope`; each listed lock must
have both valid-spend and invalid-spend evidence.

`examples/registry.cell`, `examples/atomic_swap.cell`,
`examples/multi_phase_dao.cell`, and every checked-in `examples/language/*.cell`
file are non-production examples covered by compiler/tooling tests, not by the
bundled CKB production matrix.

`--compile-only` and bounded diagnostic runs can help development, but they are
not external production release evidence.

## Next

Once the verification boundary is clear, continue with
[LSP and Tooling](https://github.com/CellScript-Labs/CellScript/wiki/Tutorial-07-LSP-and-Tooling).
