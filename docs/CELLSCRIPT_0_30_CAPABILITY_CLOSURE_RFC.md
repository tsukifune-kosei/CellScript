# CellScript 0.30 CKB Capability Closure RFC

## Status and release strategy

**Status: active 0.30 implementation and acceptance plan. It is not a release
announcement, a grammar freeze, or evidence that the listed capabilities are
already complete.**

The `0.30` implementation branch starts from `0.26b` commit `08c0ef38`. The
candidate release path is a direct stable-version jump from 0.25 to 0.30. The
experimental `0.26b` branch may be absorbed into 0.30 without publishing a 0.26
stable release. Until that decision is finalized, `0.26b` remains an
evidence-bearing development line rather than a release promise. No Cargo
version, source edition, metadata schema, witness ABI, deployment identity, or
published package changes merely because this branch and plan use the 0.30
name.

The first Stage 1 implementation slice is now present: authoring successor
relations accept `lock = exact_hash(script_hash)` only for the dedicated
`ScriptHash` source domain. Typed CKB transaction-view hash fields produce that
type, while `ckb::script_hash(Hash)` makes conversion from an already trusted
raw hash explicit. The conversion does not prove Script existence, deployment,
or authorization. Formatter/LSP support and real CKB-VM matching and
substitution-negative fixtures ship with the compiler path. This closes one
bounded part of #25; complete Script construction/hashing, authorization-domain
APIs, cryptographic capability contracts, and the rest of Stage 1 remain open.
The slice has the development source identity
`cellscript-source-semantics-2027-0.30-dev1`; it does not reuse or redefine the
recorded `authoring1` identity and is not the final 0.30 grammar identity.

The first #24 runtime-view tranche is specified by the
[0.30 CKB runtime-view matrix](CELLSCRIPT_0_30_CKB_RUNTIME_VIEW_MATRIX.md).
The additive typed HeaderDep and six-domain `Since` subset is specified in the
[0.30 temporal-domain contract](CELLSCRIPT_0_30_TEMPORAL_DOMAINS.md); it does
not by itself close issue #12.
Metadata schema 69 binds `cellscript-ckb-runtime-view-v1` together with the
structured `cellscript-ckb-runtime-access-provenance-v1` source/index/range
contract. Typed Cell views now expose occupied/unoccupied capacity, consensus
data hashes and input `since`;
typed HeaderDep views expose all three fields admitted by CKB's
`LOAD_HEADER_BY_FIELD`; and complete Script hashes are separated from code and
args hashes. CKB-VM tests cover a nonzero epoch, the derived epoch-start block,
one-past-last HeaderDep failure, and CellDep data-hash substitution. The matrix
also records exact CKB-VM `Since` vectors and checked decoder failures for all
mode/metric combinations. Checked `EpochDuration` construction and EpochNumber
add/sub now enforce the 24-bit domain with executable overflow and underflow
evidence. Exact 208-byte full-header decoding now supplies typed block number
and millisecond timestamp reads. Dynamic source indexes retain their parameter
binding and 32-bit runtime bound through metadata, generated TypeScript
builders, CKB-VM execution, and the standalone checker. Remaining work includes
bounded variable witness values, HeaderDep machine mutations, complete builder
parity, measurement, and release evidence.

The goal is business-scenario coverage comparable to hand-written Rust CKB
Scripts for a defined, bounded portfolio. It is not unrestricted Rust language
parity. CellScript should cover the common validation, state-transition,
authorization, composition, and transaction-inspection needs of that portfolio
without requiring a hand-written replacement for the primary verifier. Exact,
identity-pinned external cryptographic or protocol verifiers remain a supported
composition boundary when the compiler cannot and should not prove their
internals.

## What comparable capability means

CellScript reaches the 0.30 capability target only when every required portfolio
fixture can be:

1. expressed through the adopted authoring surface and versioned package
   contracts;
2. compiled to a production-admitted CKB-VM artifact with no hidden fail-closed
   placeholder on an accepting path;
3. constructed by generated builders using the same source, role, witness, and
   output correspondence contract enforced on chain;
4. checked by typed metadata and the standalone artifact checker at the exact
   boundary each checker claims;
5. executed through matched positive and adversarial CKB-VM fixtures, with a
   hand-written Rust reference where an equivalent implementation is practical;
6. measured for ELF size, cycles, stack, witness bytes, transaction size, and
   occupied capacity; and
7. reproduced through the applicable development, CI, backend, release, and
   deployment-evidence gates.

Passing one syntax example, emitting an ELF, or matching one Rust benchmark does
not satisfy this definition. Capability claims must name the admitted source,
runtime, builder, artifact-checker, product, and deployment universe.

## Current issue coverage

The existing GitHub issues cover much of the foundation, but they do not yet
form a complete 0.30 business-capability plan.

| Capability needed for the 0.30 target | Existing owner | Coverage assessment |
| --- | --- | --- |
| Bounded variable-cardinality Type-group inputs | [#7](https://github.com/CellScript-Labs/CellScript/issues/7) | Partial. It owns bounded selection, count, decode, predicate, and lifecycle discharge. Native authoring integration and the final cross-product of role shapes still need 0.30 acceptance. |
| Bounded output plans and one-to-one output correspondence | [#8](https://github.com/CellScript-Labs/CellScript/issues/8) | Partial. The runtime foundation exists on the 0.26 development line, while authoring, shared-witness composition, builders, and complete independent machine evidence remain release work. |
| Multi-Script transaction construction and conflict handling | [#9](https://github.com/CellScript-Labs/CellScript/issues/9) | Covered as the architecture owner. The ProtocolBundle must precede any `.celltx` convenience syntax. |
| Typed roles across Script boundaries | [#10](https://github.com/CellScript-Labs/CellScript/issues/10) | Covered as a design owner, dependent on the ProtocolBundle and exact Script/interface identity. |
| Runtime Script and verifier handles | [#11](https://github.com/CellScript-Labs/CellScript/issues/11) | Covered as the identity and ABI owner. Current exact-hash trusted delegation is a bounded precursor, not full closure. |
| Timelocks, epochs, timestamps, and `Since` | [#12](https://github.com/CellScript-Labs/CellScript/issues/12) | Covered for typed temporal domains. It does not own the rest of the transaction-view and syscall surface. |
| Digest-committed substate and authenticated openings | [#13](https://github.com/CellScript-Labs/CellScript/issues/13) | Covered for commitments and opening correspondence. It must share the entry witness envelope with output plans and verifier proofs. |
| Honest capability and product-completeness claims | [#14](https://github.com/CellScript-Labs/CellScript/issues/14) | Covered as a governance rule. It is not an implementation owner for the missing capabilities. |
| Reproducible workspace, resolver, compiler-requirement, build-plan, and upgrade behavior | [#15](https://github.com/CellScript-Labs/CellScript/issues/15), [#16](https://github.com/CellScript-Labs/CellScript/issues/16), [#17](https://github.com/CellScript-Labs/CellScript/issues/17), [#18](https://github.com/CellScript-Labs/CellScript/issues/18), [#19](https://github.com/CellScript-Labs/CellScript/issues/19), [#20](https://github.com/CellScript-Labs/CellScript/issues/20) | Covered by separate toolchain owners. #17 is a correctness prerequisite for chain-specific composition and deployment claims. |
| Typed zero-knowledge verifier contracts | [#22](https://github.com/CellScript-Labs/CellScript/issues/22) | Covered as research and typed external-verifier composition. A circuit DSL is outside the 0.30 core. |
| Stable public value-generics surface | [#23](https://github.com/CellScript-Labs/CellScript/issues/23) | Covered as a language-design owner. It must close before public 0.30 package APIs are frozen. |
| Typed CKB transaction views and runtime adapters | [#24](https://github.com/CellScript-Labs/CellScript/issues/24) | Newly owned for 0.30. It unifies admitted Cell/input/header/witness/Script/hash/source operations without a raw syscall escape hatch. |
| Cryptographic and authorization-domain contracts | [#25](https://github.com/CellScript-Labs/CellScript/issues/25) | Newly owned for 0.30. It separates native primitives, exact external verifiers, message domains, and Script/value identities. |
| Rust-comparable business acceptance corpus | [#26](https://github.com/CellScript-Labs/CellScript/issues/26) | Newly owned for 0.30. It freezes the cross-feature portfolio, matched Rust fixtures, adversarial cases, and evidence layers. |
| Product, publication, and deployment closure | [#27](https://github.com/CellScript-Labs/CellScript/issues/27) | Newly owned for 0.30. It prevents compiler-only evidence or stale generated products from being presented as a complete release. |

The four gaps found during the 0.30 review now have explicit issue owners:

- a typed, bounded CKB transaction-view and runtime-adapter closure covering the
  admitted Cell, input, header, witness, Script, hash, source, and syscall result
  families as one versioned contract;
- a cryptographic capability policy defining which primitives are compiler
  built-ins, which are exact external verifier contracts, and how message-domain
  and Script-identity types prevent confused-deputy use;
- a named business-equivalence corpus that turns Token, NFT, order, AMM,
  temporal, multisig, committed-state, and multi-Script scenarios into release
  acceptance rather than examples; and
- end-to-end 0.30 product and deployment closure across generated builders,
  language services, the browser product, package publication, node admission,
  deployment identity, and independent review.

Issues #24 through #27 record their dependencies, failure boundaries,
acceptance matrices, resource requirements, and stop conditions. This RFC owns
their release-level coordination; it does not use the existence of an issue to
silently admit a raw runtime feature.

## 0.30 workstreams

### A. Authoring and semantic closure

Complete the adopted `resource`, `action`, `lock`, and `require` authoring model
over the versioned semantic foundation. Successor relations must work in
ordinary branches and cover replacement, fixed and bounded split/merge,
creation, retirement, identity, Lock, Type, data, and capacity policy without
requiring authors to write preview4's verbose container form.

Required closure includes schema-change acknowledgements, exact Script identity
types, complete accepted-path role accounting, multiple actions under one
persistent deployed policy, complex action/helper ABIs, formatter and recovering
parser support, LSP and editor behavior, and direct AST/IR elaboration. The
retained preview4 grammar remains executable reference evidence and is not the
0.30 authoring target or an intermediate-language requirement.

### B. Bounded dynamic Cell sets and output plans

Complete #7 and #8 as one author-visible lifecycle system while preserving their
separate security contracts. The admitted surface must support transaction-chosen
cardinality from zero through a declared maximum, canonical group-relative
selection, exact schema and Script identity, deterministic decoding, per-element
checks, linear input discharge, and exact plan-to-output correspondence.

The implementation must cover bounded fungible splits and merges, batched state
updates, receipt settlement, and capped claims. Missing, extra, duplicated,
reordered, foreign, malformed, or over-bound elements must fail with stable
errors. Builders and verifiers must consume one versioned ordering and witness
specification.

### C. Typed CKB runtime-view closure

Define a new issue and a versioned support matrix for the CKB data a production
contract can inspect. The initial matrix must decide and test:

- current Script and Script hash;
- Cell data, capacity, occupied capacity, Lock and Type Scripts and hashes;
- input out points and `since`;
- headers, header dependencies, epochs, timestamps, and block numbers;
- raw witnesses and `WitnessArgs` fields with explicit ownership and bounds;
- transaction and script-group sources, indexes, lengths, and out-of-bound
  behavior;
- transaction preimages and the exact message domains used for authorization;
- CellDep lookup and exact-identity EXEC or SPAWN/WAIT adapters; and
- stable handling of syscall errors, partial reads, malformed Molecule values,
  and oversized byte ranges.

CellScript does not need a raw numeric-syscall escape hatch. Every admitted
operation must have a typed source contract, deterministic memory bound,
metadata record, codegen implementation, independent machine check where
claimed, and positive/adversarial VM evidence. Unsupported syscalls continue to
fail before production artifact emission.

### D. Multi-Script and external-verifier composition

Implement #9, #10, and #11 in dependency order. The first product boundary is
an artifact-only ProtocolBundle that admits exact checked artifacts, resolves
global and group-relative roles, reports witness/index/CellDep conflicts, builds
one transaction, and preserves per-Script evidence. Typed source syntax may be
added only after that contract is stable.

Extend trusted external verification through exact artifact, interface,
deployment, argument-adapter, and result contracts. General process or pipe
programming is not required for parity. A new bounded IPC adapter is admitted
only for a named business fixture and must define process, descriptor, cycle,
buffer, deadlock, and error behavior. The compiler must never claim to prove an
external verifier's internal parser, authorization, cryptography, or protocol
semantics.

### E. Cryptography, authorization, and committed state

Define the cryptographic capability issue before adding primitives. The 0.30
core should provide exact domain-separated hash and signature contracts required
by the acceptance corpus, while larger or protocol-specific verification uses
the typed, identity-pinned external-verifier path. Raw `Address`, complete
`Script`, Script hash, code/data hash, public key, signature, message digest,
commitment, proof, and witness bytes must remain distinct types or checked
conversions.

Complete #13 for authenticated openings. Keep #22 as an optional research
workstream unless a selected 0.30 fixture requires a ZK verifier contract; even
then, 0.30 standardizes provenance, identity, statement binding, witness
placement, and result enforcement rather than introducing a circuit DSL.

### F. Business-equivalence acceptance corpus

Create a dedicated issue and a canonical corpus containing at least:

| Family | Required scenario |
| --- | --- |
| Fungible asset | Authorized mint, transfer, bounded split, bounded merge, burn, replay rejection, and total-supply or conservation policy. |
| NFT or DOB | Mint with unique identity, metadata update, ownership transfer, capacity adjustment, burn, and duplicate-identity rejection. |
| Order and AMM | Partial fill or partial order, settlement across interacting asset groups, reserve/accounting checks, slippage or price bound, and adversarial output reordering. |
| Temporal | Absolute and relative timelock, vesting transition, typed epoch/timestamp/`Since` mismatch rejection, and required header-dependency behavior. |
| Authorization | Single-signature or standard Lock integration, multisig threshold change and spend, issuer authority, post-signing mutation rejection, and exact message-domain checks. |
| Committed state | Authenticated opening, successor commitment, stale or wrong opening rejection, and witness-envelope composition. |
| Multi-Script | One transaction involving at least three independently built artifacts with shared Cells or witnesses, ProtocolBundle conflict detection, per-group execution, and exact deployment identities. |
| External verifier | A real exact-hash verifier invoked through EXEC or SPAWN/WAIT, with wrong-dependency, wrong-adapter, nonzero-status, and post-build substitution failures. |

Each family needs positive and adversarial cases. Where a matched Rust reference
exists, both implementations must run against the same serialized transaction
fixtures and agree on accept/reject outcomes. Performance comparisons must name
the exact checked scope and build profile; they are evidence for the corpus, not
a universal claim that CellScript is smaller or faster than Rust.

### G. Toolchain, product, and release closure

Close #15 through #20 where they affect the selected corpus. Generated
TypeScript and Rust-facing builders must materialize typed parameters, merge
shared indexes and witnesses, preserve signing fields, and validate the same
roles and output plans enforced by the Script. Native CLI, package loading,
formatter, LSP, VS Code, metadata-only WASM, website Playground, Registry
interfaces, and artifact checker must all report the same admitted capability
boundary.

The browser bundle must pass its tracked size budget or the compiler surface
must be intentionally split behind a versioned product contract. A committed
bundle from an older capability set cannot serve as 0.30 evidence.

## Explicit non-goals

Comparable business coverage does not require:

- unrestricted recursion, unbounded loops, or allocator-backed unbounded Cell
  collections;
- arbitrary inline assembly, raw syscall numbers, CSRs, atomics, floating point,
  or the complete GNU assembler surface;
- automatic translation of arbitrary Rust crates into CellScript;
- compiler proof of the internals of an external cryptographic or protocol
  verifier;
- transaction-wide fuzzy Cell matching or authority inferred from names,
  schemas, builder choices, or Registry records;
- a circuit language or universal zero-knowledge system; or
- preserving experimental preview4 text as the final public grammar.

When a business fixture needs a capability outside this list, the requirement
must be stated as a typed, bounded contract. The project should not respond by
adding an untracked general-purpose escape hatch.

## Delivery sequence

### Stage 0: scope and issue closure

- File the four missing scoped issues identified above. Completed as #24 through
  #27 when the `0.30` implementation branch was opened.
- Freeze the required business corpus and matched Rust reference boundaries.
- Resolve shared witness ownership across #8, #13, and #22.
- Resolve the 0.30 Script identity, authorization, and source-value type
  contracts.
- Record whether 0.26 will be skipped; do not create a 0.26 stable tag merely
  to preserve numeric continuity.

### Stage 1: semantic and runtime foundations

- Complete authoring relations and schema acknowledgements.
- Complete #7, #8, #12, and #23 for the admitted corpus.
- Implement the typed CKB runtime-view issue and cryptographic capability issue.
- Extend typed semantics, ProofPlan, source maps, lowering records, runtime
  errors, and independent mutations together.

### Stage 2: composition and builders

- Complete #9, #10, and #11 in dependency order.
- Close the relevant #15-#20 package, environment, build, and upgrade
  prerequisites.
- Generate complete builders and execute multi-Script transaction fixtures.

### Stage 3: business parity and economics

- Execute every required corpus family under simulator and CKB-VM where each is
  authoritative.
- Run matched Rust differential cases and retain disagreements as release
  blockers until explained and resolved.
- Record worst-case resources and enforce budgets without deleting required
  checks or narrowing the promised corpus.
- Complete independent security reviews for dynamic selection/output
  correspondence, authorization, external delegation, and multi-Script
  composition.

### Stage 4: release candidate

- Pass `./scripts/cellscript_gate.sh dev`, `ci`, `backend`, and the applicable
  `release` gate on the exact candidate source.
- Rebuild and verify WASM, VS Code, generated builders, package contents,
  Registry-facing records, and all versioned sidecars.
- Reproduce clean-source CKB acceptance and stateful scenarios, then add node
  admission and deployment evidence for the selected network scope.
- Publish 0.30 only after the capability matrix identifies every row as
  implemented, deliberately excluded, or separately trusted with an exact
  boundary. A partial implementation retains a development identity.

## 0.26b disposition and compatibility

The preferred planning assumption is that 0.26b changes are selectively folded
into 0.30. The branch is valuable evidence for typed provenance, dispositions,
entry selection, authoring experiments, trusted delegation, policy dispatch,
CKB-VM lifecycle tests, independent checking, and backend economics. Absorbing
that work does not require publishing a 0.26 stable artifact.

The transition must preserve compatibility axes independently:

- Edition 2026 meaning remains stable unless an explicit migration contract
  says otherwise.
- Preview4 and `authoring1` source identities keep their recorded meaning;
  0.30 introduces a new source identity only after the grammar and semantics are
  accepted.
- Existing witness, output-plan, policy, metadata, checker, target-profile, and
  deployment formats are retained or versioned with explicit readers and
  migration tests.
- Existing Data1 deployments are not relabeled as VM2/Data2 artifacts.
- Package compiler requirements and chain identity are checked before source
  loading or dependency selection.
- No release document may describe 0.26b development evidence as a shipped 0.26
  contract or describe the 0.30 target as already implemented.

## Release acceptance decision

The 0.30 capability claim is accepted only when all required workstreams A-G
and their issue dependencies are complete for the frozen corpus. ZK research,
unbounded algorithms, raw syscall access, and general process/pipe programming
may remain outside the release. Their exclusion does not weaken the claim as
long as the published comparison states that CellScript matches the selected
bounded CKB business portfolio rather than arbitrary hand-written Rust.
