# CellScript Gate Policy

CellScript uses one top-level gate entry point:

```bash
./scripts/cellscript_gate.sh <dev|ci|backend|release|release-quick>
```

The lower-level audit scripts remain available for focused debugging, but they
are implementation details of the gate policy. Prefer the unified gate when
deciding whether a change is ready.

## Gate Modes

| Mode | When to run | Evidence boundary |
|---|---|---|
| `dev` | Local development before pushing | Native source-policy enforcement; Rust formatting; canonical CellScript example formatting; all workspace-package Rust checks (including the standalone artifact checker and `cellscript-tools`); checker mutation/Myelin handoff tests; simulator package scenarios; both Registry verifiers and their compiler-dependency boundaries; reproducible Registry Type Script build and CKB-VM tests; strict backend quick audit, syntax-combination quick audit, parity-gated skill-pack freshness, README-linked CellScript doc Status freshness, local markdown link check, whitespace diff check |
| `ci` | Pull requests, pushes, and routine merge readiness | Node 22 and native source-policy enforcement; all compiler/checker/adapter/tool tests and clippy; simulator plus CKB-VM package scenarios; standalone-checker dependency and mutation evidence; reproducible Registry Type Script identity plus CKB-VM tests and clippy; Registry API typecheck/tests with compiler-backed and least-privilege artifact workers, Node bundles, and dry-run Worker build; full website behavior/build regression suite; strict backend CI audit; package verification; parity-gated skill-pack/doc freshness; local-link and script syntax checks |
| `backend` | Changes touching IR, codegen, assembler, ABI, ELF, or RISC-V behavior | Compiler, artifact-checker, and Fiber checks/tests/clippy; checker dependency boundary; simulator plus CKB-VM package scenarios; native source-policy enforcement; and strict backend full audit, including stateful CKB scenarios |
| `release` | Nightly/stable release candidates and any production CKB claim | Clean tagged source plus `ci`, a fresh size-gated website WASM rebuild, tooling/docs and VS Code checks, pinned-CKB acceptance harnesses, public builder-contract generation, and mandatory stateful scenario/action coverage |
| `release-quick` | Wrapper compatibility and local compile-only preflight | `ci` plus compile-only production acceptance; not external live/devnet evidence |

`release-quick` is kept for `scripts/cellscript_ckb_release_gate.sh quick`.
Use `release` for any production or external live/devnet claim.

CI packages the independently publishable `cellscript-artifact-checker` first,
then verifies the `cellscript` package offline with an exact local crates.io
patch. A real crates.io release must preserve that dependency order: publish
and confirm the checker version before publishing the compiler version.

Package-manager changes must preserve the lock-authority regression matrix:
standard SemVer edge cases; missing/stale manifest digests; direct/transitive
source drift; alias and graph-edge identity; optional/default/all feature and
test-only roots; environment override plus CKB genesis binding; moving Git
branches remaining pinned until explicit update; exact offline/frozen cache
use; and bounded external resolvers normalizing to immutable sources without
running during locked builds. Registry API checks also validate the complete
`cellscript-registry-profile-catalog-v1` and prove that only CellScript source
profiles are dependency-resolving.

The same Registry matrix covers
`cellscript-registry-ls-idl-interface-v1`: raw ABI schema and size budgets,
SHA-256 binding, executable suffix placement, publish-time rejection cases,
SQL/in-memory Script lookup, byte-preserving canonical and compatibility
responses, ambiguous type-hash rejection, CLI validate/bind/fetch/bundle, and
both compiler-backed and least-privilege verifier outputs. Passing this matrix
does not assert that a Lock Script semantically implements its IDL.

`dev` and `ci` run `cellc fmt --check` against
`examples/language/core/canonical_style.cell`. The formatter's comma-terminated
field form is the canonical checked-in surface; the parser may continue to
accept comma-free fields as compatibility input. The same modes reject raw
`u64` maximum and `MAX - delta` magic literals in the checked NFT, timelock,
atomic-swap, and multi-phase-DAO example pairs; boundary arithmetic must use
their local `U64_MAX` constants.

The native source-policy check also rejects release or version markers in every
tracked or untracked `.cell` filename. Language examples are classified by
semantic purpose under `examples/language/{core,ckb,ownership,verification,collections,batches}`;
version history belongs in the changelog and release notes, not source paths.

Both release modes fail before doing expensive work unless the CellScript tree
is completely clean, including untracked files. GitHub release CI additionally
requires the exact `v<workspace-version>` tag at `HEAD`; a manual release dispatch must name
the same version as the root `[package].version`. The GitHub Release workflow
runs the full `release` gate first, and binary builds plus publication depend on
that job succeeding.

Production CKB acceptance rebuilds the pinned CKB `0.207.0` checkout in a
fresh dedicated Cargo target. That pin resolves `ckb-librocksdb-sys 8.5.4`,
whose `trace_record.h` uses fixed-width integer types without directly
including `<cstdint>`. The acceptance builder therefore sets the exact
`CXXFLAGS=-include cstdint` compatibility contract instead of patching the
clean CKB checkout. The production evidence validator requires both that flag
and `ckb-librocksdb-sys-8.5.4-explicit-cstdint-v1` in
`ckb_runtime_provenance`; changing either is a release-boundary change.

The 0.23 tooling migration is complete. `cellscript-tools` owns the backend,
syntax-combination, skill-pack, tooling-release, CKB production-evidence,
NovaSeal, and Evolving-DOB gate logic. Website data generation is implemented
by Node scripts in `website/scripts/`. Dev, CI, backend, and release gates have
no Python runtime dependency and reject tracked Python source files.
Node-backed CI uses Node 22. After one checked Registry-data generation pass,
the unified gate and manual website workflow both run
`npm --prefix website run build:ci`; that target owns the complete Registry,
playground, visual, homepage, preference, documentation, dist, deploy, Astro
check, and Astro build regression contract. It builds both production and
Pudge Testnet Registry outputs, checks the six shared routes in each, and
requires their generated CSS and JavaScript assets to be byte-identical while
allowing only explicit network authority and admitted-data differences.

The 0.23 line also has one edition contract: every package declares
`edition = "2026"`, and all emitted evidence binds the resolved compatibility
profile. The edition owns source semantics only; target, primitive assurance,
metadata schemas, and entry/witness ABIs remain independent profile axes.
Missing/non-2026 editions and superseded lock, deployment, receipt, builder, or
raw-witness placement identities are rejected rather than migrated. See
[`CELLSCRIPT_EDITION_POLICY.md`](CELLSCRIPT_EDITION_POLICY.md). Edition-owned
source changes require complete frontend closure. Independently versioned ABI
changes require the `backend` gate in addition to ordinary `dev` and `ci`
coverage.

The bounded persistent-Type-policy path uses explicit `[[artifacts]]`
declarations and `cellc build/check --artifact NAME`. Its outer witness ABI is
independent of the unchanged single-entry `CSARGv1` encoding. Changes to policy
selection, dispatch, placement, or record validation require the `backend`
gate; CLI and manifest integration also require the ordinary `dev`/`ci`
coverage. Focused codec and CLI tests do not replace those gates. See
[`CELLSCRIPT_POLICY_WITNESS_ABI.md`](CELLSCRIPT_POLICY_WITNESS_ABI.md) for bounds,
selection rules, and the remaining Lock-dispatch boundary.
`metadata --artifact` and `expand --artifact` use the metadata-only selected
policy path; their CLI regression checks pin the same contract and ensure no
machine artifact or sidecar is created during inspection.

The `ci` gate also typechecks/tests `services/registry-api`, builds both Node
entrypoints, performs its Wrangler dry-run build, and runs tests and clippy for
the independent real-compiler Registry verifier crate. `dev` at least checks
that verifier crate. This pins the single `/v1/artifacts` contract, orthogonal
verification/deployment/availability states, generic artifact bundles,
mainnet deployment evidence, additive migrations, worker boundary, and
database/static-object shape to the CLI-generated Registry entry. It is local
service coverage, not evidence
that Cloudflare, R2, Hyperdrive, Neon, DNS, or a production deployment works.
The CLI coverage includes both first-publish admission paths: the explicit
`cellc auth capability submit`, `cellc auth namespace claim`, then
`cellc publish` sequence, and the short-lived `cellc publish --authorise`
browser session in which the private publishing key remains in the local OS
keychain as pending while the CLI polls with a one-time secret, becomes active
only after the server returns the matching key ID, and is removed only after
the server confirms terminal cancellation or pending-session expiry. A local
polling deadline performs a final authoritative read and preserves the pending
key if the result is still pending or unreachable. Completed sessions remain
poll-readable for a bounded 24-hour recovery window. The browser token survives
a same-tab refresh but is cleared after completion or expiry; the website build
runs the fragment-store-refresh-clear lifecycle regression. Browser-session
completion is one atomic admission boundary across
nonce consumption, publishing-key registration, namespace claim/review,
session state, and audit events. API tests cover expiry, wrong browser/poll/
challenge tokens, challenge replay, concurrent completion, conflicting
namespace ownership, review-pending admission, post-expiry terminal reads, and
injected mid-transaction failure. Publisher maintenance additionally uses the capability-signed
`cellc artifact set-availability` path, and `cellc artifact cell-dep` performs a
fresh mainnet liveness check before producing a transaction-builder descriptor.
Independent reproducibility builders use `cellc auth reproducer create`; CLI
coverage verifies that its public enrollment contains an importable P-256 SPKI,
that private PKCS#8 material never appears in JSON output, and that explicit CI
secret files are mode 0600 on Unix and no-overwrite.
Capability registration does not silently claim a namespace;
the claim response must be `active` before the write API accepts a version.
Registry API tests pin both accepted publisher roots: JoyID signatures under
`principal_type = joyid_ckb` and recoverable CKB message signatures under
`principal_type = ckb_secp256k1`. CLI fixtures use the generic
`--wallet-signature` surface; the former `--joyid-signature` spelling remains a
visible compatibility alias and does not define a second request shape.
Explicit `--allow-unverified` and `--allow-quarantined` install choices are
persisted per dependency so the lock refresh and later builds exercise the
same auditable resolver policy.

Both `dev` and `ci` also build the independent
`contracts/registry-type-script` crate for
`riscv64imac-unknown-none-elf`, strip it with the pinned toolchain, verify the
tracked canonical ELF's SHA-256 and CKB data hash, and execute that ELF's
positive and negative lifecycle matrix in CKB-VM through `ckb-testtool`.
The reproducible builder accepts either GNU `sha256sum` or Perl `shasum` and
fails closed when neither SHA-256 implementation is available.
Linux x86_64 additionally requires the fresh build to match the tracked ELF
byte-for-byte. Other build hosts record their host artifact hash and make no
cross-host reproduction claim; the pinned container builder provides that
canonical check there.
Passing this local boundary proves the deployed bytes' behavior and identity;
it does not prove that the code Cell or custody Lock CellDep is live on
mainnet. Production readiness still performs live RPC and confirmation checks.

The full gate reads `scripts/ckb_acceptance_pin.json` and rejects a CKB checkout
whose revision or worktree differs from the pin. Its report binds the CKB
version string, executable SHA-256, source-template hashes, effective devnet
configuration hashes, and genesis hash. Production on-chain acceptance always
rebuilds CKB from that source in a fresh dedicated Cargo target directory and
archives the executable with the report; supplied or cached binaries cannot
satisfy the production gate. It then runs the exact stateful 43-action matrix
and validates every step's commit, spent-input liveness, live outputs, cycles,
serialized size, and occupied capacity. `--stateful-scenarios` remains only as
an explicit option for bounded runs.

The transaction matrix is produced by the native Rust acceptance harness and
is intentionally labelled as recipe-replayer evidence, not generated-builder
output. Separately, the gate runs the public `cellc action build` and
`cellc gen-builder` surfaces for every production action and hashes their
generated contracts. Resource Type Scripts in these local transactions remain
`always_success` fixtures; the report records that this proves verifier
behaviour and transaction shape, not a production passive-resource-identity
deployment.

### Fiber integration evidence

The no-profile Fiber path has a separate, non-gating acceptance entry point:

```bash
./scripts/cellscript_fiber_acceptance.sh --static
```

For live developer-node regression evidence,
`cellscript-tools fiber-node-experiments --cellscript-fungible-artifact <ELF>`
temporarily installs that exact ELF in Fiber's dev SimpleUDT contract slot and
restores the original fixture before returning. Its report binds the artifact
SHA-256, CKB data hash, byte length and Data2 selector together with clean
CellScript and Fiber revisions. Cached workflow results are reusable only when
all three identities remain exact. The runner defaults to Bruno CLI `1.20.0`
to match Fiber CI; a host-compatibility override must be an exact
`--bruno-cli @usebruno/cli@MAJOR.MINOR.PATCH` value. Bruno, Node, npm, CKB and
ckb-cli versions and the explicit `--bruno-sandbox safe|developer` selection
are report- and cache-bound. The installed ELF's CKB data hash is passed as
`UDT_CODE_HASH`. The router-pay compatibility workspace replaces its final
post-response JavaScript checks with equivalent Bruno declarative assertions;
the overspend rejection, final balances, request count, and synchronization
before requests remain unchanged, and every patched file is listed in the
report. Tracked Fiber state must return to its baseline; runtime-generated
untracked node backups are disclosed separately. If Bruno retains RPC handles
after printing its terminal summary, cleanup is accepted only after a
five-second grace and only when the non-empty suite has reported every request
as `200 OK` with no failed assertion marker. The report binds the expected and
observed request counts, terminal-summary status, timeout status, and exceptional
completion basis. This mode still produces bounded local devnet evidence rather
than a mainnet or operator-identity claim.

Static mode runs the dedicated CKB-VM transaction matrix, adapter tests, and
adapter clippy. It proves only compiler/artifact compatibility; it does not
prove that a Fiber node loaded configuration, advertised an asset, opened a
channel, routed a payment, or settled on chain.

Full mode consumes externally produced `compatibility.json` and
`acceptance.json` reports from a pinned Fiber checkout. It validates exact
revision/fingerprint bindings and requires every declared positive and negative
matrix row. Every completed row and certified topology report must cite a
non-empty regular file beneath an explicit evidence root together with its CKB
Blake2b-256 digest. Absolute paths, parent traversal, symlinks, missing files,
and digest mismatches fail closed. These bindings prove evidence-bundle
integrity, not who produced it. Fiber's native `node_info` exposes a seven-hex
build abbreviation, so full mode also checks the selected checkout's complete
40-hex HEAD. The script does not start, restart, configure, sign for, or stop
operator-owned CKB/Fiber nodes. Until the live matrix is stable and explicitly
promoted, neither `dev`, `ci`, `backend`, nor `release` runs this external
integration boundary.

The ordinary `dev`, `ci`, and `backend` gates do compile the adapter; `ci` and
`backend` also run its unit tests and clippy. This is workspace-code coverage,
not external Fiber lifecycle evidence.

On 2026-07-20, bounded non-gating local-devnet runs passed Fiber's official
`udt-router-pay` and
`watchtower/force-close-with-pending-tlcs-and-udt` collections with the exact
CellScript artifact and generated native configuration. Those observations are
recorded in the roadmap, but do not satisfy full mode because the CKB executable
and Fiber source/build were observed only in a bounded local fixture, no signed
announcement report was captured, and the complete declared matrix was not
produced.

### 0.24 verified-artifact and scenario evidence

The 0.24 development line advances compile metadata to schema 58 and makes a
CKB ELF build a four-file bundle: ELF, compile metadata, canonical verified
lowering record, and canonical source map. Every build validates the bundle,
and the gates separately build, test, lint, and dependency-audit
`cellscript-artifact-checker`. The checker does not depend on the parser,
resolver, IR, optimizer, assembler, or code generator. Its mutation and
malformed-input corpora pin bounded `V2400` through `V2418` rejection classes,
including reachability, stack, ELF, instruction, control-flow, syscall, digest,
and source-map failures.

`dev` runs executable package scenarios with the simulator. `ci` and `backend`
run both simulator and CKB-VM backends and require exact registered runtime
errors for negative fixtures. The v1 runner's multi-step Cell replacement is a
local bookkeeping contract; it does not inject scenario Cells into CKB
syscalls. The existing stateful CKB harness remains the transaction-shaped
oracle.

Registry API coverage keeps generic source/executable/ABI CKB bundles
`hash_bound`. Supplying any verified sidecar requires the complete
metadata/lowering-record/source-map set and dispatches to the least-privilege
artifact worker. A `structurally_verified` checker level records checker
version, policy, and report hash, but remains distinct from source equivalence,
CKB-VM execution, deployment, and chain evidence.

### 0.30 typed CKB runtime-view evidence

The `0.30` development branch advances compile metadata to schema 70 and binds
`runtime.ckb_runtime_view_contract = cellscript-ckb-runtime-view-v1` plus
`runtime.ckb_runtime_access_provenance_contract =
cellscript-ckb-runtime-access-provenance-v1`. The first
runtime-view tranche adds fixed-width Input, Output, CellDep, HeaderDep,
OutPoint, and Script field reads. The CKB-VM regression uses a nonzero header
epoch and block number, checks occupied/unoccupied capacity arithmetic and
CellDep data hashes, and requires stable fail-closed exits for substituted data
and a one-past-last HeaderDep index. This is executable evidence for the listed
closed fields only; it does not complete the wider 0.30 runtime-view, temporal,
authorization, or release portfolio. The authoritative field and exclusion
matrix is [the 0.30 CKB runtime-view matrix](CELLSCRIPT_0_30_CKB_RUNTIME_VIEW_MATRIX.md).

The additive issue #12 tranche keeps the old raw constructors and
`input_since_at` return type intact while adding distinct HeaderDep temporal
types, opaque and decoded typed-view `since`, all six absolute/relative
block/epoch/timestamp domains, checked raw decoding and narrowing, explicit raw
conversions, and canonical epoch-fraction comparison. Its CKB-VM regression
includes exact wire vectors for all six domains, a helper-call ABI round trip,
packed-order counterexamples, rationally equivalent fractions, reserved and
metric flag rejection, scalar/timestamp bounds, and malformed fraction
rejection. It also covers checked `EpochDuration` construction and EpochNumber
addition/subtraction, including 24-bit overflow and underflow rejection. The
same regression checks exact 208-byte full-header decoding of block number and
millisecond timestamp, including their typed-domain separation. See the
[typed CKB temporal-domain contract](CELLSCRIPT_0_30_TEMPORAL_DOMAINS.md) for
the implemented and deferred rows. `W3012` and its LSP workspace edit cover
raw-compatible source migration; canonical package-interface v3 binds the
temporal constructors, checked decoders, domains, fixed representation, and
migration identity, and the Registry API retains a v2 reader. This evidence
is mirrored by formatter, VS Code, generated-builder, locked package, WASM,
Playground, and six-family business-fixture checks. The canonical browser
summary build is 544,037 bytes gzip. Full candidate gates and independent
review are still required to close the temporal issue or the release gate.

### 0.26b semantic-foundation evidence

The `0.26b` experimental branch advances compile metadata to schema 67,
verified lowering records to v6, typed semantics to v8, and source maps to v2.
Typed semantics embeds `cellscript-semantic-foundation-v3`, whose canonical
records cover a bounded provenance DAG, entry selection, role binding, Cell
disposition, enforcement-classified claims, legacy migration nodes, and
layered semantic IDs. The standalone checker independently recomputes these
records and their metadata/bundle bindings without loading the frontend.
Fixed-Cell tables cross-check source, ordinal, local identity, schema and
Script-group membership against roles and provenance. Real VM regressions
exercise nonzero Type/Lock groups, extra group Cells, mixed CellDep forms and
the input-witness/output-only placement boundary. These records do not claim
complete syscall dataflow equivalence.
Typed semantics v8 also carries explicit `trusted-external` verifier records.
These are acceptable only when the same typed entry contains the ordered
CellDep-load, exact data-hash check, and EXEC or SPAWN/WAIT delegation sequence,
the manifest claim matches exactly, and
`compiler_proves_internal_semantics = false`. Raw or undeclared external calls
remain production blockers.
The target and constraints records additionally bind
`minimum_vm_version = 2`, `riscv_isa = "rv64imac_zbb"`, and
`deployment_hash_types = ["data2"]`. The independent checker rejects any
bundle that weakens this generated-artifact deployment contract. Constraints
metadata is schema 4.
Executable `require`/`enforce` claims additionally bind canonical condition
text to one condition-provenance node, the ordered typed success/failure
branch, and the exact fail-closed runtime error. Mutation tests reject broken
node, branch, and error links; differential tests require equivalent Edition
2026 and Edition 2027 conditions to retain the same semantic projection.

`cellc expand [INPUT]` renders this foundation for review; `--json` emits the
canonical foundation object. The human rendering is deterministic but is not
a hash boundary. Source paths and spans live only in source-map v2, while
source bytes have a separate `SourceDigest`.

The gate treats Edition 2027 as experimental, not a release claim. The current
`cellscript-source-semantics-2027-0.30-dev1` frontend inherits the `authoring1`
2026 value/declaration/statement kernel while retaining an independently
selected entry-body grammar. Ordinary modules retain legacy default provenance
and lifecycle meanings and may contain multiple actions/locks; those source
declarations do not create runtime dispatch.
Artifacts remain `SingleEntry` until a versioned dispatch ABI is implemented
and verified. The retained `preview4` native slice separately checks the
native `type_script` or `lock_script` container. It checks exact Type or Lock
group triggers, explicit provenance, exhaustive successor/pool/retirement/fresh
Type Script dispositions, metadata-only audit classification, and
authorization-only Lock scope as described in
[`CELLSCRIPT_2027_PREVIEW_GRAMMAR.md`](CELLSCRIPT_2027_PREVIEW_GRAMMAR.md).
Parser, formatter, LSP, checker mutation, cross-frontend identity, WASM-source,
and syntax-combination checks are part of ordinary `dev`/`ci` closure. These
checks do not freeze the proposed 1.0 grammar or satisfy the RFC's later
acceptance and release gates.

The bounded `cellc migrate --to 2027` path is also fail-closed. CLI tests require
it to preserve source outside the selected final entry, avoid implicit writes,
reject every unsupported or lossy form before creating an output, and prove
both `CoreSemanticId` equality and byte-identical RISC-V ELF lowering for each
emitted candidate. Ordinary Type Script candidates retain `action` authoring
and transaction-absolute locations; migration never silently substitutes native
group ports. This is local differential evidence, not graph-wide impact,
builder, CKB-VM, deployment, or chain evidence.

### 0.25/0.26 predecessor language and typed-semantics evidence

The 0.26 implementation advances compile metadata to schema 62 and constraints
metadata to schema 3. The compiler
gate now checks the generated executable-surface matrix, bounded generic value
instantiations, explicit visibility and canonical public interfaces, six-axis
interface compatibility, and Registry interface/hash admission. CKB ELF
lowering uses `cellscript-verified-lowering-record-v4`, embedding the canonical
`cellscript-typed-semantics-v3` record.

The standalone checker remains parser/resolver/codegen-independent. Its
mutation corpus extends the stable boundary with `V2419` for malformed or
inconsistent typed semantics and `V2420` for typed-record/hash/lowering/machine
binding failures. The compiler, syntax audit, editor extension, and Playground
must agree on generics, abilities, patterns, visibility, bitwise/shift syntax,
borrows, and labeled loop control before the branch can claim gate closure.

### Nightly 0.22 compiler evidence

The `nightly-0.22` line adds compile-time callable-effect contracts and
transaction-local terminal-flow evidence. These remain inside the existing gate
modes; they do not create a new gate command:

- `dev` and `ci` reject underdeclared `fn` effects, including transitive calls
  through source-authenticated package imports.
- invariant `reads` and aggregate operands share the closed `SourceView` /
  typed-target model; parser, type checking, IR, ProofPlan, formatter, and
  xUDT helper selection no longer reparse source-view strings independently;
- canonical 0.22 flows use an enum-backed state field, exactly one `initial`
  state, at least one `terminal` state, and no outgoing terminal edge;
- terminal discharge is currently only `terminal-by-output-state`, backed by
  generated state-transition checks and emitted as `checked-runtime` ProofPlan
  evidence;
- every ProofPlan record carries exactly one evidence tier:
  `checked-static`, `checked-runtime`, `runtime-helper-required`,
  `builder-evidence-required`, `metadata-only`, or
  `chain-evidence-required`;
- `--production` rejects `metadata-only` records whose invariant, terminal, or
  assert/check/enforce/require/validate/verify naming claims executable
  enforcement;
- legacy flows without initial/terminal declarations and numeric state fields
  remain accepted for migration, but metadata carries explicit audit warnings;
- none of this metadata proves that every live on-chain Cell eventually reaches
  a terminal state. `release` still requires exact-artifact and chain evidence
  before a production claim.

Metadata schema `54` carries declared/inferred/effective function effects, the
initial, terminal, discharge, state-model, and audit-warning fields for flows,
the canonical evidence tier on ProofPlan, flow, and function metadata, and
typed transaction-view handle records under
`runtime.transaction_view_handles`, `runtime.borrow_regions`,
`runtime.capability_proofs`, plus
`types[].validity_predicates`. Handle records must remain
`ownership = read-only-view`, carry `lifecycle_authority = false`, and report
checked-static typing plus checked-runtime read evidence.
Consumers must reject unsupported schema versions instead of silently dropping
these fields.

Schema 55 additionally carries
`runtime.fungible_type_group_entry`. That record is present only for the
dedicated, payload-free `fungible-type-group-v1` compilation path and binds the
selected type, 16-byte field, runtime helper, witness policy, the legacy
32-byte input-Lock authority and tagged 33-byte input-Type-Script authority,
and the unauthorised non-empty/conservation contract.
Ordinary action compilation must not emit it.

Concrete payload enum evidence is top-level under `enum_layouts`. Every record
pins the one-byte tag, packed variant field offsets, encoded width, storage
class, ownership, and ABI. Non-linear values use fixed bytes; pure-helper
returns up to 16 bytes use the `a0`/`a1` register-pair ABI. Enums containing a
Cell payload are local-only linear handles and cannot cross storage or entry
ABI boundaries. Dynamic, recursive, and generic payload ADTs fail before IR.
Quick syntax coverage pins exhaustive matching, dynamic rejection, and
arm-local linear discharge through the three `SCA-BUG-0.22-PAYLOAD-*` classes.

ProtocolGraph participant roles remain a derived audit view, never a verifier
or authorization condition. `actions[].protocol_role_candidates` preserves
the source of each candidate. A direct Address equality in a verification
predicate wins over witness/entry-witness or `lock_args` bindings, which win
over participant-like Address field names. Every candidate must carry
`evidence_tier = metadata-only` and `authorization_proven = false`; the
metadata validator rejects a `protocol-role` ProofPlan category. Graph edges
publish `role_source_used`, all candidates, and deterministic
`PG-ROLE-MISSING`, `PG-ROLE-WEAK-FIELD`, or `PG-ROLE-CONFLICT` lints. The quick
syntax gate pins the overclaim and conflict boundaries with the two
`SCA-BUG-0.22-PROTOCOLGRAPH-*` classes.

The top-level `capability_registry` is a closed, versioned audit contract.
Every `types[]` record carries the matching `capability_set_version`.
Composite operations emit `runtime.capability_proofs` with required, provided,
entailed, missing, identity-condition, capability-set-version, and
entailment-version fields. `destroy` is accepted by `consume + burn` (or a
labelled legacy compatibility alternative); `replace_unique` requires
`replace + identity-preservation`. Gates reject missing authority and any
attempt to borrow authority from another container/resource type. Quick syntax
coverage pins this with `SCA-BUG-0.22-CAPABILITY-OVERGRANT` and
`SCA-BUG-0.22-CAPABILITY-TRANSITIVE-GRANT`.

Bounded invariant quantifiers are finite-source declarations. Their ProofPlan
records use `bounded-source-quantifier`, identify the closed source view, and
record scan complexity, field reads, runtime cardinality, vacuous `forall`
status, and `u64` count overflow policy. Until a selected entry emits the named
bounded scan helper, their tier is `runtime-helper-required`, never
`checked-runtime` or `metadata-only`.

The explicit `ckb::require_bounded_cell_dep_data_hash` operation is a narrower
checked-runtime exception, not an automatic promotion of arbitrary
quantifiers. It has a compile-time `1..=64` bound, emits a real resolved
`Source::CellDep` `LOAD_CELL_BY_FIELD(DATA_HASH)` loop, and is covered by
positive/missing-dependency CKB-VM cases. Out point, dep type, and original
DepGroup identity remain manifest/builder evidence.

Bounded Cell collections use the same finite-evidence rule. In 0.26, the
ownership checker and backend promote only two fully specified shapes to
`checked-runtime`: fixed-width `input cells: BoundedCellSet<T, N>` discharged
once by `consume_each` over the exact current Type Script `GroupInput`, and a
fixed-width `witness plans: BoundedList<P, N>` whose one complete create
template per element is verified against the same relative `GroupOutput`.
Metadata records the versioned runtime contracts
`bounded-type-group-inputs-v1` and `bounded-output-plan-v1`, runtime-observed
cardinality, exact plan/output count, per-element predicate execution, output
data/lock checks, and the on-chain capacity floor.

The plan codec is `CSBPLv1\0 || u32_count_le || fixed_width_elements`; its
maximum encoded size is 4084 bytes so the surrounding `CSARGv1\0` entry payload
fits the 4096-byte wrapper buffer. Bounded bodies may update only mutable outer
numeric accumulators with `+=`, in addition to pure `require` predicates and
the single create template. The gate has production-policy and CKB-VM vectors
for zero/one/N/N+1 cardinality, malformed data and codecs, predicate failures,
output count/order/data/lock/capacity mismatches, and the four checked 0.26
business examples.

Every other bounded shape remains registered fail-closed. Dynamic or recursive
elements, non-input sources, custom output identities, incomplete templates,
missing explicit locks or capacity floors, and arbitrary body mutation return
runtime error 24 in permissive artifacts and are rejected before codegen with
E2105 under `--production` or `--deny-fail-closed`.

More generally, production treats every selected consensus-relevant ProofPlan
`gap:*` status as a hard blocker. This includes runtime-helper, builder-evidence,
and metadata-only gaps. Builder output/capacity evidence is construction data,
not a substitute for a verifier check.

Type validity uses one evidence contract across parser, type checking, IR,
metadata, ProofPlan, codegen, formatter, and LSP. A pure field predicate is
`checked-runtime` only when a concrete constructor/create instruction emits a
fail-closed guard before the output instruction on every selected create path.
`create_paths_selected` and `create_paths_checked` make partial coverage
auditable; partial, signature-only, or update paths without that lowering are
`runtime-helper-required`, and production gates must not promote them. Literal
`true` predicates may be `checked-static`.
`env::block_number()` is never treated as a compiler constant or an ambient
CKB-VM syscall: its record names both
`environment:env::block_number` and
`builder:header-dep-block-number-evidence`, with
`builder-evidence-required`. Every other `env::*` read fails closed. The quick
syntax audit requires positive evidence records and the unknown-environment
negative seed through `SCA-BUG-0.22-VALIDITY-EVIDENCE-MISSING` and
`SCA-BUG-0.22-VALIDITY-ENV-UNKNOWN`.

Explicit borrow blocks are a checked-static compiler contract. Each
`runtime.borrow_regions` record must use canonical `View<T>`, declare
`storage = none` and `abi = none`, and allow only `Pure` and `ReadOnly`
callees with a dedicated `&T` parameter. The matching `borrow-region`
ProofPlan entry records escape and root-lifecycle rejection. Quick syntax
coverage pins effect compatibility, escape rejection, and crossing
`consume`/`destroy` through the three `SCA-BUG-0.22-BORROW-*` classes.

## Command Cheatsheet

```bash
# Local fast path
./scripts/cellscript_gate.sh dev

# Default CI/PR gate
./scripts/cellscript_gate.sh ci

# Strict compiler-contract gate for backend work
./scripts/cellscript_gate.sh backend

# Release-facing CKB production gate
./scripts/cellscript_gate.sh release

# Compile-only release preflight; not external live/devnet evidence
./scripts/cellscript_gate.sh release-quick
```

For scripted gate wrappers, the global `--json` flag selects one command result
on stdout for either success or failure. Structured failures carry their
category and exit code in addition to source ranges and diagnostic codes.
`--message-format=json` remains a hidden deprecated alias for compatibility.

The old release wrapper remains supported:

```bash
./scripts/cellscript_ckb_release_gate.sh quick  # delegates to cellscript_gate.sh release-quick
./scripts/cellscript_ckb_release_gate.sh full   # delegates to cellscript_gate.sh release
```

## Lower-Level Components

Use these only when you need a focused failure:

```bash
./scripts/cellscript_syntax_combo_audit.sh quick
./scripts/cellscript_syntax_combo_audit.sh ci
./scripts/cellscript_strict_backend_audit.sh quick
./scripts/cellscript_strict_backend_audit.sh ci
./scripts/cellscript_strict_backend_audit.sh full
./scripts/ckb_cellscript_acceptance.sh --production --stateful-scenarios
```

`./scripts/cellscript_0_14_scope_audit.sh` is a historical standalone audit
from the 0.14 release line. It is not invoked by any current gate mode and is
retained for manual 0.14-compat debugging only; it is not part of the 0.21
release-evidence boundary.

The following ecosystem/bridge scripts are standalone manual tools that are
**not** wired into any gate mode and are **not** part of the release-evidence
boundary. They require sibling or explicitly selected external checkouts and
runtimes, and are documented in their respective guides for focused, opt-in
use:

- `./scripts/cellscript_ckb_ecosystem_reuse_gate.sh` — CKB-ecosystem reuse
  checks; see `docs/CELLSCRIPT_CKB_ADAPTER.md`.
- `./scripts/cellscript_ckb_adapter_acceptance.sh` — adapter acceptance against
  a sibling CKB checkout; see `docs/CELLSCRIPT_CKB_STD_COMPAT.md`.
- `./scripts/cellscript_ls_idl_upstream_acceptance.sh` — exact-pinned LS-IDL
  derive, client, and example-script compatibility, including the actual
  upstream Rust client calling the Registry compatibility handler, unmodified
  upstream RISC-V builds, LS-IDL-bound ELFs, and example CKB-VM execution; see
  `docs/CELLSCRIPT_LS_IDL_REGISTRY_PROFILE.md`.
- `./scripts/cellscript_cellfabric_bridge_smoke.sh` — CellFabric bridge smoke
  test; see `docs/CELLSCRIPT_CELLFABRIC_BRIDGE.md`.

These must not be described as gating evidence, and passing one does not imply
any release-gate mode passed.

Passing one component does not imply the corresponding higher-level gate passed.
For example, CKB acceptance proves selected transaction behavior, while the
syntax-combination and strict backend audits prove compiler-layer edge cases and
structural invariants.

## Artifact Reports

The gates write machine-readable reports under `target/`:

- `target/syntax-combo-audit/`
- `target/cellscript-strict-backend-audit/`
- `target/ckb-cellscript-acceptance/`
- `target/cellscript-backend-shape/`
- `target/cellscript-schema-manifest/`

These directories are local working storage, not the durable release archive.
Managed syntax, strict-backend, and CKB-acceptance streams retain the latest
three runs of each mode by default and publish a small `latest-<mode>.json`
index containing the full report path, SHA-256, size, and status. Set
`CELLSCRIPT_EVIDENCE_KEEP_RUNS=all` when an external archiver needs every local
run, or set it to an integer from 1 through 128 to choose another bound.

Successful syntax-combination runs retain `report.json` and `report.jsonl` but
remove deterministic case sources, formatter copies, assembly, metadata, and
their redundant incremental cache. Failed runs and explicit `repro` runs keep
those intermediates. `CELLSCRIPT_KEEP_GATE_WORKDIRS=1` preserves them during a
debugging session. CKB production acceptance keeps the full report, verified
artifacts, sidecars, generated builder contracts, archived pinned CKB binary,
configuration, and logs, but removes the fresh Cargo build target and the
stopped node database. Byte-identical acceptance files within and across
retained runs are hardlinked after their SHA-256 identities match; report paths
and bytes do not change.

For release evidence, archive the reported files outside `target/` and keep
their JSON paths in the release checklist rather than copying long logs into
review threads. The four-file verified-artifact bundle and evidence validation
semantics are unchanged by local retention.

## CellScript Build Report

`scripts/ckb_cellscript_acceptance.sh --production` emits
`cellscript_build_reports` inside `target/ckb-cellscript-acceptance/` reports.
This is the exact-artifact bridge between compiler output, ELF ABI evidence,
and live CKB code-cell evidence. It does not replace the acceptance report,
production gate, or ELF entry ABI gate; it binds their artifact identities
together.

The top-level index is:

```text
cellscript_build_reports {
  schema = "cellscript-ckb-build-report-index-v0.20"
  status = "passed"
  artifact_count
  target_profile = "ckb"
  vm_profile = "ckb-vm"
  artifact_format = "riscv64-elf"
  artifact_hash_algorithm = "ckb-blake2b256"
  requires_exact_artifact_hash = true
  requires_elf_entry_abi_gate = true
  requires_live_code_cell_data_hash_match = true
  reports = [CellScriptBuildReport]
}
```

Each `CellScriptBuildReport` row records:

```text
CellScriptBuildReport {
  schema = "cellscript-ckb-build-report-v0.20"
  name
  kind
  source
  original_source
  example
  entry_flag
  entry
  target_profile = "ckb"
  vm_profile = "ckb-vm"
  artifact_format = "riscv64-elf"
  artifact_path
  metadata_sidecar
  artifact_packaging
  artifact_size_bytes
  artifact_hash_algorithm = "ckb-blake2b256"
  deployable_elf_hash
  artifact_sha256
  deployment_hash_type_used_by_gate = "data2"
  verify_artifact_status = "passed"
  verify_target_profile = "ckb"
  elf_entry_abi_status = "passed"
  abi_trailer_stripped = true
  onchain_deployments
}
```

For full devnet acceptance, every row must have at least one
`onchain_deployments` entry whose `live_code_cell_data_hash` equals
`deployable_elf_hash`. Compile-only production evidence keeps
`onchain_deployments` empty and is therefore not external release evidence.

Package identity must carry the same codec boundary explicitly. `Cell.lock`
`[package.build]`, `Deployed.toml` `[build]`, deployment records, and generated
builder identity checks include `cell_data_codec_manifest_hash` alongside
`artifact_hash`, `metadata_hash`, `schema_hash`, `abi_hash`, and
`constraints_hash`. Registry and builder verification fail closed when this
hash is missing or disagrees, so raw cell-data layouts cannot be hidden behind a
Molecule-only schema identity.
