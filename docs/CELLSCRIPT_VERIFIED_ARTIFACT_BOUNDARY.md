# CellScript Verified Artifact Boundary

**Status**: semantic-foundation and bounded machine contracts implemented on
the `0.30` development branch

**Schemas**: `cellscript-verified-lowering-record-v8`,
`cellscript-typed-semantics-v8`,
`cellscript-semantic-foundation-v3`,
`cellscript-value-provenance-dag-v1`,
`cellscript-source-artifact-map-v2`, and
`cellscript-verified-artifact-boundary-v2`, plus
`cellscript-artifact-checker-policy-v1`

**Metadata schema**: 71

## Purpose

Every CKB RISC-V ELF build now emits two canonical sidecars in addition to the
artifact and compile metadata:

```text
build/main.elf
build/main.elf.meta.json
build/main.elf.lowering.json
build/main.elf.sourcemap.json
```

The typed semantic record retains checked types, locals, calls, effects,
ownership, borrow regions, concrete generic instantiations, layouts, and CFG
operations in a parser-free schema. Typed semantics v8 also embeds the
frontend-independent semantic foundation: value provenance, artifact entry
selection, transaction roles, exhaustive Cell dispositions, enforcement
classes, legacy migration nodes, and layered semantic identities. Typed
semantics v8 additionally binds exact trusted-external verifier declarations
to ordered CellDep data-hash checks and delegation calls while retaining an
explicit no-proof-of-internals flag. Lowering
record v8 embeds that record and binds it to the final machine layout. Every
typed block is accounted for;
optimized/elided typed blocks have an explicit empty machine-block list, while
materialized blocks carry exact typed-block hashes. Source-map v2 binds source
spans both to lowering block IDs/final instruction ranges and to semantic node
IDs. `SourceDigest` identifies the source units separately. Paths and moving
spans never enter `CoreSemanticId`. Executable condition claims use their
originating condition or generated-sugar range when non-empty, with the
containing entry as a fail-safe diagnostic fallback. Other records may use the
containing entry range. All records are hash-bound into compile metadata and
validated immediately after compilation.

Typed semantics retains the mandatory fixed-Cell binding table introduced in v5:
physical source and ordinal, distinct input/output/read roles, local identity,
concrete schema, and current Type/Lock group membership or `unproven` identity.
Roles and provenance are projected from the resolved IR table rather than
reconstructed from signature indexes. The checker cross-checks those
projections and rejects missing, duplicate, or contradictory records after
outer hashes are rebound. Bounded collections retain their separate scan
contract. This does not prove arbitrary syscall dataflow equivalence.

Ordinary input/output bindings retain transaction-absolute locations. Native
group ports and documented `protected` Lock parameters use current-group
locations. Positional CellDep reads do not authenticate a deployed Type Script.
These corrections intentionally change affected semantic identities; v4
records are not silently reinterpreted as v5 records.

The policy contract introduced in typed semantics v6 and semantic foundation v2
retains the explicit
`policy-witness-v1` Type-group dispatch contract. Its resource layout, tagged
export set, ordered common checks, selector provenance, variant payload schemas,
fixed group counts, and outer witness ABI are canonical and hash-bound. The
checker cross-checks the policy metadata and builder parameter projection against
those typed records. The current lowering record's
nested typed and foundation versions must match exactly. Older records are not
accepted under the new versions by relabelling them.

### Fatal verifier failures

Typed semantics v8 declares `failure_semantics = current-vm-process-exit-v1`.
Explicit typed failure blocks end in `verifier-failure`, with a nonzero error
constant, rather than an ordinary value return. This operation must be the
final operation in a matching terminal block; it cannot appear as an ignored
value before a return or another failure. Semantic foundation v3 includes
this contract in the versioned core semantic identity. Scalar, predicate, wide
integer and tuple return values keep their established ABI; deliberately
exposed syscall statuses are not reclassified merely because they are nonzero.

Lowering records retain mandatory `verifier_failure_exits`, separately from the
existing diagnostic `runtime_error_exits`. The checker decodes each static
site's exact error constant and tail jump to a complete, memory-free EXIT sink.
It checks the syscall number and non-returning fallback, rejects entry into the
middle of a failure sequence, derives the static-site
inventory from incoming machine jumps, and requires every explicit typed
failure block to reach a recorded site. Only this verified sink is exempt from
joining incoming stack depths: it never reads a caller frame or returns.
An exact decoded EXIT sink also requires its declared contract; renaming the
entry and dropping its static-site list cannot hide it.

Lowering record v8 additionally specializes typed HeaderDep syscall sites.
For each epoch number, epoch start, epoch length, block number, or timestamp
helper, the checker binds the exact syscall number, field selector or RawHeader
offset, `HeaderDepView` source and 32-bit index domain, 8/208-byte buffer,
return-code branch, exact-length comparison, and terminal errors 44, 45, and 4
to decoded RISC-V instructions. The matching runtime-access record and typed
call must identify the same field and width. This is a bounded contract for
those five helpers, rather than a claim of general syscall dataflow recovery.

Version 8 also specializes canonical constructed-Script hashing. The checker
matches `script-hash-v1` runtime provenance with the typed helper call, then
decodes the 560-byte frame, 459-byte args guard, valid hash-type branches,
Molecule sizes and offsets, code/args byte loops, little-endian Bytes length,
bounded Blake2b target, and error 72 return. This proves the emitted helper has
the named fixed contract; it does not prove that the constructed Script is
deployed or authorized.

This bounded check does not establish completeness of every compiler-inserted
guard, arbitrary callee behavior, or the provenance of every dynamic verifier
status. Those require separate runtime and machine-dataflow evidence. EXIT
terminates the current VM process; it does not bypass a spawning parent's
explicit status-handling contract. No older ELF acquires this guarantee by
updating metadata.

Version 8 also specializes the bounded `policy-witness-v1` machine contract.
The checker decodes the wrapper's exact witness fallback syscalls, canonical
`CSPOLv1` envelope and one-to-eight-record DynVec scan, Molecule offsets,
strict key ordering, Type-role/current-Script-hash selector, single-match
guard, declared tag branches, ordered common calls with nonzero rejection,
unknown-tag failure, selected argument forwarding, private bounded adapter
copy, typed-parameter-derived outgoing stack reservation, exact action call,
frame restoration, and error-25 termination. This
binds the typed policy record to the emitted selector and adapters. It does
not prove the semantic meaning of an action predicate, arbitrary callee memory
effects, or deployment authentication; direct CKB-VM and deployment evidence
remain separate. See the
[policy witness ABI](CELLSCRIPT_POLICY_WITNESS_ABI.md) for the bounded entry
contract and the [implementation checklist](CELLSCRIPT_AUTHORING_IMPLEMENTATION.md)
for outstanding completion work.

The Edition 2027 `preview4` native Type Script surface may refine a legacy
`type-group` trigger to an exact non-empty `type-group<T>` value. Its native
Lock Script surface preserves the exact `lock-group` trigger while making role
provenance and authorization-only scope explicit. The independent checker
validates both spellings, their recomputed entry-node hashes, complete role
coverage, matched pooled input/output obligations, exact retirement/fresh
records, and the non-executable classification of external-policy audits. This is an
entry-contract distinction. An ordinary absolute input/output and a native
group-relative input/output are not equivalent bindings, even when a test
transaction happens to place both at index zero. Equivalent ordinary authoring
forms can share semantic identities across editions; differing physical
bindings must not.

The sidecars do not claim complete source-to-machine semantic equivalence.
Their explicit claims are typed-record validation, `binding-verified` for the
lowering record, and `structurally-verified` for machine code. The report keeps
`semantic_equivalence_claimed = false`.

## Independent Checker

`crates/cellscript-artifact-checker` has no production dependency on the
CellScript parser, resolver, type checker, IR, optimizer, assembler, or code
generator. It accepts artifact bytes, compile metadata, one canonical lowering
record, one canonical source map, and explicit policy budgets.

The checker is an independently publishable crate because the published
`cellscript` crate uses it as a production dependency. Release tooling must
publish the exact checker version before the matching compiler version; CI
verifies the same graph offline through an exact local crates.io patch.

The checker independently recomputes and validates:

- schema versions, unknown-field rejection, canonical JSON, counts, ordering,
  uniqueness, and domain-separated hashes;
- entry, block, CFG, reachability, call-depth, recursion, frame, stack-slot,
  typed ABI, capability, and ProofPlan relationships;
- typed semantic schemas, exact constants and operation detail, canonical type
  and local tables, call signatures and effects, definite-definition joins,
  ownership/borrow state transitions, enum/layout hashes, and owner-qualified
  concrete instantiations;
- canonical, bounded, acyclic provenance DAGs; explicit single-entry or
  versioned-dispatch contracts; role/schema/cardinality binding; exhaustive
  Cell envelopes and successor correspondence; claim enforcement classes;
  executable-claim links to condition provenance, ordered typed branches, and
  exact fail-closed runtime errors; and layered semantic identity projections;
- typed entry/block/operation identities against lowering blocks, final
  machine ABI, and the metadata `typed_semantics_hash`;
- ELF64 little-endian RISC-V identity, exact static sections, read/execute
  segment policy, entry and text/rodata bounds, and absence of dynamic or
  relocation state;
- the bounded RV64 instruction set emitted by CellScript, canonical direct
  calls, aligned branch/call targets, machine terminators, stack-pointer
  adjustments, return-path stack restoration, declared syscalls, and the
  specialized HeaderDep, constructed-Script-hash, and policy-dispatch machine
  contracts;
- every mapped block digest and every source-map range against final ELF bytes;
  and
- compiler, source, profile, deployable artifact, semantic layers,
  lowering-record, source-map, and verified-bundle identity agreement.

Declared unreachable machine blocks are not silently treated as reachable.
The record carries a `reachable` bit and the checker recomputes it from every
declared entry.

## Default Budgets

The default v1 policy caps each artifact, lowering record, and source map at
4 MiB; entries at 2,048; blocks and proof records at 65,536; edges at 262,144;
instructions at 1,048,576; call depth at 256; declared stack frames at 1 MiB;
source-map intervals at 65,536; and one diagnostic at 16 KiB. A consumer may
apply a stricter compatible policy.

Budget exhaustion is `V2400`. Input-derived counts are checked before graph
traversal, diagnostic text is bounded, and invalid input must return an error
instead of panicking.

## Stable Rejection Codes

| Code | Boundary |
| --- | --- |
| `V2400` | policy budget exceeded |
| `V2401` | malformed JSON |
| `V2402` | non-canonical JSON |
| `V2403` | unsupported schema or overclaimed verification state |
| `V2404` | non-canonical ordering or duplicate identity |
| `V2405` | referential-integrity failure |
| `V2406` | CFG, reachability, runtime-exit, or terminator failure |
| `V2407` | ABI, frame, stack-slot, or stack-pointer failure |
| `V2408` | ProofPlan coverage failure |
| `V2409` | artifact identity mismatch |
| `V2410` | compile-metadata or compatibility-profile mismatch |
| `V2411` | invalid ELF format |
| `V2412` | invalid or prohibited ELF section/link state |
| `V2413` | instruction outside the checker policy |
| `V2414` | decoded control-flow target or machine terminator mismatch |
| `V2415` | mapped block digest mismatch |
| `V2416` | source-map identity, range, path, or coverage failure |
| `V2417` | syscall declaration or bounded-call contract failure |
| `V2418` | recursion or call-depth policy failure |
| `V2419` | typed semantic schema, type/local/operation, ownership, borrow, layout, instantiation, or effect failure |
| `V2420` | typed semantic hash, lowering-block, entry ABI, call, or final machine binding failure |

The deterministic mutation corpus in `tests/artifact_checker.rs` exercises all
stable rejection codes. It is a regression corpus, not a proof of complete
semantic equivalence.

## CLI Verification

For an ELF build, `verify-artifact` loads the default sidecars automatically:

```bash
cellc verify-artifact build/main.elf --json
```

Use `--lowering-record` and `--source-map` only when the sidecars use custom
paths. The JSON report keeps these states separate:

- `binding_verification`;
- `structural_verification`;
- `lowering_record_verification`;
- `ckb_vm_evidence`;
- `chain_evidence`; and
- `semantic_equivalence_claimed`.

The checker does not execute CKB-VM and does not query a chain. A successful
structural report therefore leaves CKB-VM as `not-executed`, chain evidence as
`not-provided`, and semantic equivalence as `false`.

## Registry Boundary

The Registry preserves generic Rust/C/JavaScript CKB bundles as `hash_bound`
when they provide only `source`, `executable`, and `abi`. A bundle that opts
into CellScript structural verification by including any verified sidecar must
provide all of `metadata`, `lowering_record`, and `source_map`; partial sets
fail closed. Artifact-only admission runs
`cellscript-registry-artifact-verify`, whose normal dependency graph contains
the standalone checker but not the CellScript compiler. A
`structurally_verified` result records checker version, policy schema, and
checker-report hash.

Compiler-backed source-package verification remains a separate worker and a
separate trust state. Structural verification is not a security audit and is
not deployment or chain evidence.

## Compatibility Rules

- Unknown fields and future schema versions fail closed.
- Absolute and parent-traversing source paths are rejected.
- Raw `CSARGv1` witness compatibility is rejected; the compatibility profile
  must use canonical `WitnessArgs.input_type` placement.
- Assembly output has no verified-artifact sidecars and reports the boundary as
  not applicable.
- Consumers must bind all four files from the same build. Mixing a valid ELF,
  metadata file, lowering record, or source map from different builds fails.
- `DeployableArtifactId` identifies the ELF bytes. `VerifiedBundleId` binds the
  ELF, typed semantics, compatibility profile, lowering record, source map, and
  `SourceDigest`; it is not interchangeable with any semantic identity.
