# Home

CellScript is a small language for writing Cell-based contracts on CKB. You
describe the Cells your protocol cares about, the actions that move those Cells,
and the locks that decide whether a Cell may be spent. The compiler then turns
that `.cell` source into ckb-vm compatible RISC-V assembly or ELF artifacts, and
writes metadata that explains what was built.

Last updated: 2026-09-08 (`0.30` capability-closure development branch).

This wiki is a guided path. It starts with one compiled example, then slowly
builds the mental model: source files, Cell effects, packages, the CKB profile,
metadata, tooling, and finally the bundled examples. You do not need to
understand every production gate on the first read. The important thing is to
learn what each layer proves, and what it does not prove yet.

## How to Read This Wiki

If CellScript is new to you, read the numbered tutorials in order. The sequence
starts with source shape, Cell movement, packages, CKB profiles, metadata, and
tooling, then continues into bundled examples and the deeper language chapters.
Those later chapters explain how the canonical action model expresses
input-to-output verification with `transition` and `verification`.
The v0.15 material then extends that model with identity policies, scoped
invariants, ProofPlan metadata, and primitive capability boundaries.

After that, the wiki continues outward:

- packages make builds repeatable;
- the CKB profile chooses the chain-facing runtime rules;
- metadata explains the artifact;
- v0.16 assurance commands explain ProofPlan soundness and builder assumptions;
- v0.21 receipts, TemplateLayout metadata, ProtocolGraph views, and nested CLI
  command groups make evidence easier to audit;
- v0.22 typed transaction views, finite invariant quantifiers, bounded
  collections, payload enums, validity predicates, borrow regions, stable
  `E2xxx` diagnostics, and bounded Fiber interoperability extend that evidence
  without hiding builder or chain obligations;
- v0.23 makes Edition 2026 the single source-semantics epoch, composes it with
  independently versioned target/assurance/ABI/schema axes, and places
  CellScript entry payloads only in canonical `WitnessArgs.input_type`;
- v0.23 also makes the browser playground recoverable: snapshots, last-valid
  results, worker restart, Cell Flow, and Inspector views keep metadata work
  auditable without claiming browser ELF generation;
- v0.24 emits a canonical lowering record and source-to-artifact map alongside
  each CKB ELF, then validates the four-file bundle with a bounded standalone
  checker that does not load the compiler front end or code generator;
- v0.24 makes `cellc test` run explicit simulator or CKB-VM scenarios with
  exact runtime errors, backend-labelled evidence, local multi-step Cell
  replacement, and conservative source-linked coverage;
- v0.24 publishes byte-exact LS-IDL for deployed Lock Scripts, binds the raw
  IDL SHA-256 to the executable suffix, and resolves it through the Registry
  without upgrading that identity check into an implementation or audit claim;
- v0.25 adds bounded value generics, explicit package interfaces, typed
  semantics bound to final machine records, complete patterns, bitwise and
  shift operations, and labelled loop control;
- v0.25 also closes a bounded-collection safety gap: `consume_each` and
  `create_each` remain visible to analysis, but production compilation rejects
  them until their consensus selection, codec, and output-correspondence rules
  are fully specified and executable;
- v0.26 implements that first narrow executable shape: exact fixed-width
  Type Script `GroupInput` scans and versioned fixed-width witness plans bound
  one-to-one to canonical `GroupOutput` data, locks, capacity, and count;
- v0.30 adds typed CKB runtime/time/signing domains and the ProtocolBundle v1
  path for composing independently checked artifacts through live resolution,
  external signing, tx-pool acceptance, and an uncommitted submission receipt;
- production evidence proves more than compiler success;
- editor tooling shortens the local loop;
- bundled examples show the style in real contracts.

If you already know what you need, jump directly:

- writing source: start with [Language Basics](Tutorial-02-Language-Basics.md);
- understanding Cell movement: read [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects.md);
- understanding actions: read [Action Model and Canonical Syntax](Tutorial-09-Action-Model-and-Canonical-Syntax.md);
- using stdlib patterns: read [Standard Library](Tutorial-10-Standard-Library.md);
- copying a known pattern: use [Cookbook Recipes](Cookbook-Recipes.md);
- checking CKB terms: keep [CKB Glossary](CKB-Glossary.md) nearby;
- building a package: use [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow.md);
- compiling for CKB: read [CKB Target Profiles](Tutorial-05-CKB-Target-Profiles.md);
- preparing evidence: use [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates.md);
- working in an editor: read [LSP and Tooling](Tutorial-07-LSP-and-Tooling.md);
- learning by example: finish with [Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts.md);
- driving `cellc` from an agent: read [Agentic Loops and cellscript-mcp](Tutorial-13-Agentic-Loops-and-cellscript-mcp.md).
- checking structural artifacts and executable scenarios: read
  [Verified Artifacts and Executable Tests](Tutorial-14-Verified-Artifacts-and-Executable-Tests.md).
- writing reusable generic values, publishing a stable interface, and checking
  typed artifacts: read
  [Generics, Public Interfaces, and Typed Artifacts](Tutorial-16-Generics-Interfaces-and-Typed-Artifacts.md).
- publishing or resolving an LS-IDL Lock Script interface: read
  [LS-IDL for CKB Lock Scripts](Tutorial-15-LS-IDL-for-CKB-Lock-Scripts.md).
- composing independently checked Scripts in one transaction: read
  [ProtocolBundle End to End](Tutorial-17-ProtocolBundle-End-to-End.md).
- using CellScript fungible assets with Fiber: read the
  [bounded Fiber interoperability guide](https://github.com/CellScript-Labs/CellScript/blob/nightly-0.24/examples/fiber/README.md).
- evaluating Spore or RGB++ integration: read
  [Spore and RGB++ Interoperability Boundaries](Spore-and-RGBPP-Interop-Boundaries.md).
- spawning a pinned BIP340 verifier: read the
  [verifier CellDep ABI](../CELLSCRIPT_SIGNATURE_VERIFIER_ABI.md).
- publishing or resolving a Lock Script interface: read the
  [LS-IDL Registry profile](../CELLSCRIPT_LS_IDL_REGISTRY_PROFILE.md).

## Tutorial Path

1. [Getting Started](Tutorial-01-Getting-Started.md): compile one example and
   verify its artifact.
2. [Language Basics](Tutorial-02-Language-Basics.md): learn the shape of a
   `.cell` file.
3. [Resources and Cell Effects](Tutorial-03-Resources-and-Cell-Effects.md):
   understand how values move through a Cell transaction.
4. [Packages and CLI Workflow](Tutorial-04-Packages-and-CLI-Workflow.md):
   create a package, build it, check it, and inspect reports.
5. [CKB Target Profiles](Tutorial-05-CKB-Target-Profiles.md): choose the CKB
   runtime assumptions before compiling.
6. [Metadata, Verification, and Production Gates](Tutorial-06-Metadata-Verification-and-Production-Gates.md):
   learn what artifact verification proves, and what still needs chain
   evidence.
7. [LSP and Tooling](Tutorial-07-LSP-and-Tooling.md): use editor feedback and
   command-backed reports.
8. [Bundled Example Contracts](Tutorial-08-Bundled-Example-Contracts.md): study
   the examples in a useful order.
9. [Action Model and Canonical Syntax](Tutorial-09-Action-Model-and-Canonical-Syntax.md):
   learn the signature-direction action model, `verification`, `transition`,
   named outputs, and source qualifiers.
10. [Standard Library](Tutorial-10-Standard-Library.md):
   use stdlib lifecycle, Cell metadata, accounting, runtime, and collection
   helpers without hiding verifier obligations.
11. [Scoped Invariants and ProofPlan](Tutorial-11-Scoped-Invariants-and-ProofPlan.md):
   inspect 0.15 invariant trigger/scope/read metadata and understand
   metadata-only ProofPlan gaps.
12. [Registry Artifacts: End-to-End](Tutorial-12-Phase1-Registry-End-to-End.md):
   publish and inspect CellScript and non-CellScript artifacts.
13. [Agentic Loops and cellscript-mcp](Tutorial-13-Agentic-Loops-and-cellscript-mcp.md):
   drive the read-oriented compiler surface from an automated writer in a
   write -> check -> explain -> fix loop.
14. [Verified Artifacts and Executable Tests](Tutorial-14-Verified-Artifacts-and-Executable-Tests.md):
   independently check a CKB ELF bundle, run simulator and CKB-VM package
   scenarios, and keep structural, runtime, and chain evidence separate.
15. [LS-IDL for CKB Lock Scripts](Tutorial-15-LS-IDL-for-CKB-Lock-Scripts.md):
   validate exact IDL bytes, bind them to a Lock Script executable, publish
   the Registry bundle, record deployment evidence, and resolve the interface
   with `cellc`.
16. [Generics, Public Interfaces, and Typed Artifacts](Tutorial-16-Generics-Interfaces-and-Typed-Artifacts.md):
   use bounded value generics, explicit visibility, deterministic interface
   compatibility, and the independently checked typed-semantics record.
17. [ProtocolBundle End to End](Tutorial-17-ProtocolBundle-End-to-End.md):
   compose independent CKB Script artifacts, preserve per-Script evidence,
   resume external signing, and keep submission separate from confirmation.

After the numbered path, use [Cookbook Recipes](Cookbook-Recipes.md) for small
patterns and keep [CKB Glossary](CKB-Glossary.md) nearby for terminology.

## The Core Idea

CellScript tries to keep the CKB model visible. A contract should not look like
an account database if it is really spending input Cells and creating output
Cells.

That is why the language has:

- `resource`, `shared`, and `receipt` for persistent Cell-backed values;
- explicit effects such as `consume`, `create`, action-boundary `read`
  parameters, expression-level `read_ref<T>()`, `destroy`, `claim`, and
  `settle`;
- compiler-recognized stdlib lifecycle patterns such as
  `std::lifecycle::transfer`, `std::receipt::claim`, and
  `std::lifecycle::settle`;
- identity-aware lifecycle forms such as `create_unique` and `replace_unique`;
- scoped `invariant` declarations with explicit trigger, scope, and reads;
- `action` entries for type-script style state transitions;
- `lock` entries for spend-boundary predicates;
- `protected`, `witness`, `lock_args`, and `require` so verifier-boundary source
  data and failure points are visible in source;
- metadata sidecars and ProofPlan records that describe schema, ABI,
  constraints, runtime requirements, and verifier obligations.
- builder assumption records and schema-bound transaction-shape validation for
  pre-signing review.
- compile receipts that authenticate metadata/artifact evidence without
  claiming transaction validity.

The wiki uses the same rule throughout: if something is only compiler evidence,
it is described as compiler evidence. If something needs a builder-backed CKB
transaction, the wiki says so.

## First Run

The fastest way to get oriented is to compile the token example:

```bash
git clone https://github.com/CellScript-Labs/CellScript.git
cd CellScript
git submodule update --init editors/vscode-cellscript # only needed for local extension work
./scripts/cellscript_gate.sh dev
cargo run --locked --bin cellc -- examples/token.cell --target riscv64-elf --target-profile ckb --primitive-strict 0.16 -o /tmp/token.elf
cargo run --locked --bin cellc -- verify-artifact /tmp/token.elf --expect-target-profile ckb
```

The compile step writes four files:

```text
/tmp/token.elf
/tmp/token.elf.meta.json
/tmp/token.elf.lowering.json
/tmp/token.elf.sourcemap.json
```

The ELF is the executable artifact. Metadata explains where the source came
from, which profile was used, what schema was produced, and which obligations
still need review. The lowering record exposes the bounded structural contract,
and the source map binds it to final instruction ranges.

## Before You Call It Production

`cellc verify-artifact` is an important first check, but it is not the whole
story. For an ELF it proves that the four-file bundle agrees and that the
standalone checker accepted the declared structural contract. It does not prove
complete source-to-machine semantic equivalence or that a concrete CKB
transaction can spend the right inputs, serialize the right witness, fit
capacity rules, pass dry-run, and commit.

Keep two levels separate:

- structural compiler evidence: source, artifact, metadata, lowering record,
  source map, and selected checker policy agree;
- runtime evidence: an explicitly named simulator or CKB-VM backend executed
  the scenario, with the evidence tier retained;
- CKB chain evidence: builder-generated transactions were checked on a local CKB
  chain with cycles, transaction size, capacity, and positive/negative behavior
  evidence.

Release-facing CKB evidence comes from the repository root:

```bash
./scripts/cellscript_gate.sh release
```

The bundled examples are covered by the current local production evidence suite.
The NovaSeal core, Agreement, six planned NovaSeal profiles, and Evolving DOB
profile now have current local devnet/source-package readiness evidence. Public
or mainnet deployment claims still need their own CellDep, verifier TCB, BTC
SPV, RWA/legal, or other external attestations where a profile depends on those
facts.
The 0.16.1 patch line also closes the token/AMM/launch and NFT first-cell
bootstrap examples used by external builders.
New external contracts still need their own metadata review, builder evidence,
security review, and chain acceptance evidence before they should be called
production-ready.

## Reference Examples

- [CKB hashing workflow](https://github.com/CellScript-Labs/CellScript/blob/main/docs/examples/ckb_hashing.md)
- [Collections matrix](https://github.com/CellScript-Labs/CellScript/blob/main/docs/examples/collections_matrix.md)
- [Deployment manifest](https://github.com/CellScript-Labs/CellScript/blob/main/docs/examples/deployment_manifest.md)
- [Output append](https://github.com/CellScript-Labs/CellScript/blob/main/docs/examples/output_append.md)
