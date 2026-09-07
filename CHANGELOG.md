# Changelog

## 0.30 - Capability closure development branch

- Introduce the first authoring-level CKB Script identity contract. Edition
  2027 successor relations now accept `lock = exact_hash(script_hash)` and
  require the expression to have the dedicated `ScriptHash` type. Typed CKB
  transaction views retain that type for complete Lock/Type Script hashes;
  `ckb::script_hash(hash)` is the explicit conversion from a trusted raw
  `Hash`. The conversion is a type-domain assertion and does not prove that a
  Script exists, is deployed, or authorizes the transaction. Parser, AST,
  typing, formatter, LSP completion, IR lowering, optimizer traversal, syntax
  audit, and real CKB-VM positive/substitution-negative tests share the same
  boundary. The existing `lock = exact(address)` form and preview4's legacy
  `Address`-typed `exact_hash` surface remain compatible. Advance the
  experimental Edition 2027 source identity to
  `cellscript-source-semantics-2027-0.30-dev1` and the artifact cache identity
  to `project-source-set-v31-0.30-dev1-script-hash`; the final 0.30 source
  identity remains gated on the complete adopted grammar.

- Establish `cellscript-ckb-runtime-view-v1` in compile metadata schema 68.
  Typed Cell views add occupied/unoccupied capacity, consensus data hash, and
  input `since`; typed HeaderDep views add the three CKB
  `LOAD_HEADER_BY_FIELD` epoch fields with exact 8-byte reads and stable errors;
  and `ScriptView` now keeps complete Script hash separate from raw code/args
  hashes. Real CKB-VM tests cover nonzero epoch values, derived epoch-start
  block number, one-past-last HeaderDep rejection, and CellDep data-hash
  substitution. Advance the artifact cache identity to
  `project-source-set-v32-0.30-dev1-runtime-view-v1`.

- Add the first typed CKB temporal domains without changing the Edition 2026
  raw API. `HeaderDepView` now distinguishes `EpochNumber`, `BlockNumber`, and
  `EpochLength`; `InputView.since` is `EncodedSince`; and the new
  `ckb::since_absolute_epoch` / `ckb::since_relative_epoch` constructors
  produce `AbsoluteEpochSince` / `RelativeEpochSince`. Same-domain epoch-Since
  comparisons use epoch-first rational-fraction ordering rather than packed
  integer ordering, explicit conversions recover raw wire bits, and temporal
  helper parameters use a fixed one-register ABI. Type tests reject mixed
  domains and real CKB-VM vectors cover absolute/relative encodings,
  equivalent fractions, helper calls, and malformed zero-length input. Keep
  the older constructors and `input_since_at` as `u64`, and advance the
  artifact cache identity to
  `project-source-set-v33-0.30-dev1-temporal-domains`.

- Complete the RFC0017 mode/metric product with distinct absolute and relative
  block-number, epoch-fraction, and timestamp `Since` types. Add checked
  block/timestamp constructors, `DecodedSince`, strict decoding from opaque
  input or explicit raw bits, six mode/metric narrowing operations, and typed
  flag/metric/value projections. Decoding rejects reserved bits, metric `11`,
  malformed epoch fractions, and timestamp values whose consensus
  seconds-to-milliseconds conversion overflows. CKB-VM tests bind exact vectors
  for all six domains and stable error 37 for bad flags, scalar bounds,
  timestamp overflow, and mismatched narrowing; checker mutations reject both
  changed mode and changed metric. Advance the artifact cache identity to
  `project-source-set-v34-0.30-dev1-since-domains` and bind target/deployment
  metadata to `since_abi = ckb-since-rfc0017-typed-v1`. Header
  timestamp/full-block readers, checked duration arithmetic, migration, and the
  complete business corpus remain open under issue #12.

- Add checked `EpochDuration` arithmetic to the typed temporal contract.
  `ckb::epoch_duration` validates the CKB 24-bit epoch-number domain;
  `ckb::epoch_add` rejects overflow and `ckb::epoch_sub` rejects underflow;
  `ckb::epoch_duration_to_u64` is the explicit representation escape hatch.
  The dedicated type cannot be mixed with `EpochNumber` or raw integers, and
  the three checked operations remain named in IR, typed semantics, runtime
  access metadata, and CKB-VM failure evidence. Invalid arithmetic uses stable
  error 20, `numeric-or-discriminant-invalid`. Advance the artifact cache
  identity to `project-source-set-v35-0.30-dev1-epoch-duration`.

- Complete the typed HeaderDep temporal readers that CKB does not expose via
  `LOAD_HEADER_BY_FIELD`. `HeaderDepView.block_number` returns `BlockNumber`
  and `HeaderDepView.timestamp` returns the distinct `TimestampMillis` domain.
  The runtime loads the fixed 208-byte Molecule `Header`, requires the exact
  size, and reads the official RawHeader offsets 16 and 8 respectively;
  missing headers retain error 45 and malformed lengths use error 4. Tests bind
  those constants to `ckb-types`, execute nonzero values in CKB-VM, and keep
  milliseconds distinct from timestamp-Since seconds. Advance the artifact
  cache identity to `project-source-set-v36-0.30-dev1-full-header-time`.

- Add targeted `W3012` warnings and a language-server workspace edit for every
  legacy raw temporal call with a total typed-domain replacement. The edit
  preserves comments and the surrounding `u64` result; the untyped GroupInput#0
  reader migrates to the explicitly named `ckb::input_since_raw()` alias. Move
  canonical package interfaces to `cellscript-package-interface-v3`, where the
  fixed representation, RFC0017 constructor/decoder set, domain inventory, and
  migration identity are hash-bound and runtime-ABI changes are classified as
  breaking. The Registry API continues to read v2 and validates the complete
  v3 temporal contract. Advance the artifact cache identity to
  `project-source-set-v37-0.30-dev1-temporal-migration-interface`.

- Complete the issue #12 implementation surface across formatter, VS Code,
  generated TypeScript builders, locked package fixtures, metadata-only WASM,
  and the website Playground. Migrate timelock, DAO, vesting, NFT-expiry,
  governance, and atomic-swap examples to typed HeaderDep, `Since`, and checked
  epoch-duration operations. Split browser metadata construction from the full
  native evidence path so the canonical Rust 1.97.1 / wasm-bindgen 0.2.121 /
  Binaryen 131 build retains its bounded summary at 543,507 bytes gzip. Advance
  the artifact cache identity to
  `project-source-set-v38-0.30-dev1-temporal-product`.

- Advance compile metadata to schema 69 and add
  `cellscript-ckb-runtime-access-provenance-v1`. Every CKB runtime access now
  records its resolved source, source origin, static/dynamic/bounded index,
  optional maximum, and fixed/whole/bounded byte range. The legacy numeric
  `index` remains a compatibility projection and is zero for dynamic accesses;
  the structured record is authoritative. Runtime source-view constructors
  accept dynamic `u64` parameters but terminate with stable error 44 when a
  value exceeds the packed 32-bit source-index domain. Generated TypeScript
  builders preserve the same records and reject out-of-domain parameters. The
  standalone artifact checker independently rejects source, index, range,
  contract, and module/entry projection mutations even after outer sidecar
  hashes are rebound. The canonical browser summary is 544,037 bytes gzip with
  SHA-256 `f0128b364ca624506ddf78639ff2be8850ec88424f19707f72fc009a3536407a`.
  Advance the artifact cache identity to
  `project-source-set-v39-0.30-dev1-runtime-provenance`.

- Add bounded, read-only variable-length witness views with explicit field
  ownership. `witness::bounded_raw`, `bounded_lock`, `bounded_entry`, and
  `bounded_output_type` produce `WitnessBytesView<owner,max>` values whose
  maximum is a compile-time literal in `0..=65536`. The views expose exact
  `.size`, byte/u32/u64 reads, and full-view streaming CKB Blake2b without a
  witness-sized allocation. `bounded_entry` names the one
  `WitnessArgs.input_type` field shared by the `CSARGv1` entry ABI and bounded
  plan/authorization consumers; it does not create a second payload. Missing
  fields and values above their declared bound use stable errors 67 and 68.
  Typed `WitnessArgsView.lock/input_type/output_type` now require and stream an
  exact 32-byte field regardless of total WitnessArgs or sibling-field size,
  while the legacy direct helpers retain their historical zero-pad/truncate
  behavior. CKB-VM tests cover all four owners, fields larger
  than the old 512-byte helper buffer, `Some(empty)` versus absent fields,
  malformed Molecule tables, range failures, GroupOutput provenance, and
  streaming hashes. Metadata schema 70 binds owner, maximum, source, and byte
  range; compiler metadata validation, including the metadata-only WASM path,
  and the standalone checker reject their mutation after outer hashes are
  rebound. The rebuilt browser bundle is 554,564 bytes gzip with SHA-256
  `e57adc617c36a7946c706d4b4e420d3463d4e97249f343ace84a56fe0df79a39`,
  within the 600 KiB budget. Advance the artifact cache identity to
  `project-source-set-v40-0.30-dev1-bounded-witness`.

- Add `ckb::transaction_hash() -> Hash` as the canonical fixed-width
  transaction identity primitive. The CKB backend calls `LOAD_TX_HASH`,
  requires success and an exact 32-byte result, and preserves the access as
  `transaction-hash` / `Transaction` provenance in metadata schema 70.
  Metadata validation and the standalone checker bind the operation, syscall,
  source, authoring name, implicit index, and exact range; rebound mutations
  cannot relabel it as a generic transaction read. Real CKB-VM evidence proves
  that a nonzero hash is available in an ordinary Type Script transaction, and
  the syntax audit, LSP, example, generated metadata path, and WASM tests share
  the same surface. This primitive is the raw transaction-hash prefix required
  by canonical signing domains; it does not by itself implement
  `env::sighash_all`, which remains fail-closed until group-witness ownership,
  first-witness lock replacement, extra-witness inclusion, and bounded message
  construction are explicit. The rebuilt browser bundle is 554,741 bytes gzip
  with SHA-256
  `7884304db93b50abadb8e7ca082d23afe60ee2d5d73886fd5f3572a4f525d179`,
  within the 600 KiB budget. Advance the artifact cache identity to
  `project-source-set-v41-0.30-dev1-transaction-hash`.

- Add the bounded `env::sighash_all_zero_lock(max_group_inputs, max_inputs,
  max_extra_witnesses, max_witness_bytes) -> SighashAllDigest` signing-message
  contract. The CKB backend hashes the exact transaction hash, the first
  current-group witness with its complete `WitnessArgs.lock` payload replaced
  by equal-length zero bytes, later present group witnesses, and witnesses after
  the transaction input count, with canonical little-endian `u64` length
  prefixes. All counts and each included witness are bounded; excess runtime
  shape uses stable error 69. A real CKB-VM differential matches the pinned
  `ckb-sdk-rust` generator across a non-contiguous Script group, an unrelated
  input witness, and a transaction-level extra witness. Metadata schema 71
  binds the exact domain, scope, transform, ordering, result type, and four
  literal limits. The generated TypeScript builder manifest and action plan
  preserve the domain and mark pre-signing witness placement as required; the
  browser summary exposes the same record. The standalone checker cross-checks
  those records against
  typed call operands and runtime access provenance after outer hashes are
  rebound. The generic `env::sighash_all(source)` path remains deferred, and
  this all-zero placeholder contract does not claim prefix-preserving multisig
  layouts. The rebuilt browser bundle is 560,647 bytes gzip with SHA-256
  `fb58a9463bbf83f056b496b505e44fb0072f8b0e6c8d392678c959771279ed15`,
  within the 600 KiB budget. Advance the artifact cache identity to
  `project-source-set-v42-0.30-dev1-sighash-zero-lock`.

- Make package environment propagation chain-identity-safe before the
  ProtocolBundle work begins. A dependency edge may name its dependency-local
  environment with `use_environment = "..."`, inherit the unique environment
  whose `chain_id` and normalized 32-byte genesis hash match the root, or
  declare `environment_independent = true`. Equal display names no longer
  select transitive overrides. Missing, mismatched, or ambiguous mappings fail
  with compile diagnostics, while update-time external resolvers receive the
  already validated chain identity without looking up an inherited name in the
  dependency manifest. Canonical dependency node IDs bind the root name,
  dependency-local name, selection policy, chain ID, and genesis hash, so
  frozen/offline materialization rejects stale mappings even when manifest and
  source hashes are rebound. Update-time resolver requests advance to
  `cellscript-dependency-resolver-request-v2`, carrying separate `root_name`
  and optional dependency `local_name` fields beside the validated identity.
  Also compare transitive path dependencies after
  resolving each path from its own manifest root. Unit coverage includes a
  three-package diamond with different local environment names, explicit
  independence, same-name/different-genesis rejection, ambiguous matches,
  rebound lock evidence, and the former external-resolver panic path.

- Add the Phase 0 and deterministic offline-composition core for issue #9.
  `cellc protocol bundle check` reads a bounded
  `cellscript-protocol-bundle-input-v1`, confines artifact paths, admits every
  referenced ELF/metadata/lowering/source-map set through the standalone
  checker, binds exact entry/package/lock/deployment/interface/typed-semantic
  identities, and emits a canonical `cellscript-protocol-bundle-v1` plus CKB
  bundle hash. The resolver sorts declarative inputs while retaining physical
  transaction array order and rejects all documented ownership, output,
  witness, dependency ordering, Script/resource identity, capacity,
  fee/change, network/profile, signing-domain, and missing-index conflicts with
  stable `PB200`-`PB211` codes. A real three-artifact order/token/authorization
  CLI fixture proves canonical order independence and fail-before-signing
  conflict output. The Phase 1 builder-contract slice additionally requires a
  generated builder manifest for action entries, checks its identities,
  runtime contract, structural manifests, and selected-action projection
  against admitted metadata, and validates the shared skeleton plus explicit
  builder-assumption evidence against every artifact. Missing or invalid
  builder evidence reports `PB212`; a tampered builder projection fails
  artifact admission. Runtime transaction serialization, per-Script-Group
  CKB-VM execution, RPC/signing/submission, and chain evidence remain
  explicitly unexecuted until the later #9 phases.

- Add the first #9 runtime-adapter materialization boundary. ProtocolBundle
  cell slots may now bind concrete input OutPoints, `since`, and exact cell
  data, while witness commitments may carry separately verified exact field
  bytes. `cellscript-ckb-adapter` independently rechecks the canonical bundle
  hash and complete per-artifact admission/metadata evidence, preserves the
  ordered transaction arrays in a packed CKB `TransactionView`, checks
  occupied output capacity, computes the fee remainder, and emits raw and
  full-serialization hashes and sizes. Each selected Lock or Type artifact is
  attributed to exact global and group-relative indexes and the same complete
  transaction byte hash. CKB-VM group execution, signing, RPC, and chain
  evidence remain explicitly unexecuted.

- Add a hash-checked ProtocolBundle node dry-run receipt. The CKB adapter sends
  the exact materialized transaction to `estimate_cycles`, rejects any
  transaction/materialization mismatch, retains aggregate cycles, and records
  every direct Lock/Type artifact as accepted under the same complete
  serialization hash. Per-group cycle fields remain null because this RPC
  exposes only the aggregate count; spawned verifiers remain independently
  unobserved. Tx-pool and committed-chain evidence are not inferred from the
  dry-run.

- Add fail-closed ProtocolBundle live-input resolution. The adapter verifies
  the connected chain ID and genesis hash, queries every input with full cell
  data, requires `live` status, and compares the ordered OutPoint, packed
  CellOutput hash, data hash, capacity, and resulting fee against the exact
  materialization. The new
  `cellscript-protocol-bundle-live-resolution-v1` record upgrades
  `capacity_source` from the bundle skeleton to `live-node` while remaining
  explicit that this is uncommitted state.

- Add live ProtocolBundle deployment-dependency resolution. Materialization
  now binds each admitted artifact hash and Script code identity to its exact
  transaction CellDep index. The adapter rechecks the connected chain, requires
  every code Cell to remain live, verifies the admitted ELF data hash for
  `data`/`data1`/`data2` and `type` deployments, and expands Molecule dep-group
  member OutPoints before accepting a match. The resulting dependency record
  is bound to the exact transaction and prior live-input evidence and remains
  explicitly uncommitted.

- Add the ProtocolBundle signing and submission state machine. Exact live-input
  and live-dependency receipts produce `ReadyToSignProtocolBundleTx`; the
  adapter runs caller-supplied CKB SDK unlockers, refuses remaining Lock Script
  Groups, preserves compiler-owned witness fields, and permits only witness
  lock changes over the same raw transaction. Signed node dry-run verifies
  signatures and every direct group, `test_tx_pool_accept` binds node cycles
  and fee, and submission is refused before RPC unless the exact signed bytes
  already carry tx-pool evidence. Submission receipts remain uncommitted.

- Extend generated TypeScript action builders with a typed ProtocolBundle v1
  client. Each package exports its metadata/artifact/interface identity, binds
  an exact deployment without accepting a mismatched ELF hash, and sequences
  offline check, materialization, live inputs, live dependencies, readiness,
  resumable external signing, signed dry-run, tx-pool acceptance, and
  submission. Signing requests contain an opaque transaction handle and
  explicitly contain no private keys. Generated packages compile with `tsc`
  and exercise both the positive state order and wrong-state rejection.

- Complete the first reorg-aware ProtocolBundle confirmation boundary. The CKB
  adapter polls the submitted transaction's canonical `get_transaction`
  location, derives depth from `get_tip_header`, restarts observation if an
  inclusion disappears or changes, and rechecks the location before emitting
  `cellscript-protocol-bundle-confirmation-v1`. The final
  `ConfirmedProtocolBundleTx` records inclusion block/index, observed tip,
  required and observed depth, network identity, and reorg count while
  explicitly refusing an absolute-finality claim. Generated TypeScript clients
  expose the same ninth state and validate bounded polling policy.

- Make ProtocolBundle eligibility discoverable through Registry verification
  evidence. Both independent Registry verifiers emit the exact bundle schema,
  artifact-binding schema, and runtime-adapter identity only for CKB ELF
  bundles that carry complete sidecars and pass the standalone checker. The
  Registry worker requires the versioned triple to appear together, refuses it
  outside structurally verified CKB ELF evidence, and preserves it in accepted
  build evidence. Generic CKB executables and source-only snapshots remain
  unmarked.

- Publish the numbered ProtocolBundle end-to-end wiki tutorial consumed by the
  website docs renderer. It connects standalone artifact admission, Registry
  discovery, offline conflict checks, Rust adapter states, generated TypeScript
  external-signing flow, and the bounded confirmation/finality boundary.

- Implement closed typed cross-Script roles for issue #10. The versioned
  `cellscript-protocol-closed-role-v1` record reuses ProtocolBundle Cell and
  witness claims, requires one exclusive provider plus shared-read consumers
  at the identical physical source, and checks an exact Molecule type/hash in
  every participant's independently admitted metadata. Resolved roles bind
  package, entry, interface, ELF, and deployment Script identities into the
  canonical bundle; `PB213` reports incompatible type, ownership,
  correspondence, or closed-foreign identity. Generated TypeScript packages
  export the same schema and a `bindClosedProtocolRole` constructor. Open or
  runtime-selected roles remain assigned to the separate Script-handle work.

## 0.26b - Experimental semantic-foundation branch

- Complete the 0.26 economic-backend tranche across layout, code generation,
  runtime access and cryptographic kernels. In addition to the compact ELF and
  small-`li` work below, the backend now shares byte primitives, removes
  dominated schema checks and immediate stack reloads, folds exact byte loops
  structurally in IR, uses source-bound four-way read windows with a
  profitability-gated register hot window, decodes `SourceView` with shifts
  instead of DIV/REM, keeps hash state in registers, and emits VM2 Zbb
  `rori`/`roriw` rotations. These transformations preserve bounds, source kind,
  exact length and fail-closed syscall handling; they do not delete semantic
  obligations or match business/action names.

  The matched three-scenario corpus is now smaller and faster than its
  size-tuned Rust references in every row: pool merge 2,512/2,816 bytes and
  6,000/9,232 cycles, schema roll 2,272/2,760 bytes and 8,661/10,350 cycles,
  ownership Lock 2,232/2,304 bytes and 5,583/6,333 cycles (CellScript/Rust).
  The real Spore+Agent closure runs the same 52,960-byte Agent ELF in 131 paired
  transactions; the current CellScript Spore ELF is 53,000 bytes versus 66,840
  for the matched Rust `z-fat` build, and every one of its 11 accepting paths
  is faster (2.8-11.7%, 5.9% aggregate). The Fiber commitment ELF is 63,336
  bytes versus 69,176 for Rust `z-thin`; all 256 accepted paths preserve
  behavior and the transaction-level aggregate remains lower, while individual
  rows include signature-dependent cycle variance and are not presented as
  isolated Script-group measurements. These are finite, reproducible corpus
  results, not a theorem that arbitrary CellScript beats arbitrary Rust.

  Because Zbb rotations require CKB-VM2, generated artifacts now declare
  `minimum_vm_version = 2`, `riscv_isa = rv64imac_zbb`, and the deployable
  `data2` hash type in both target and constraints metadata. `data2` is the new
  compiler default; a package that declares `deploy.ckb.hash_type = data` or
  `data1` fails closed. The independent checker rejects metadata that weakens
  the VM/ISA/hash-type binding. Advance compile metadata to schema 67,
  constraints metadata to schema 4, and the artifact cache identity to v30.
  Rebind the production CKB transaction recipe for all 60 scoped action/Lock
  artifacts, updating 417 exact code-hash references to the final VM2 output
  and upgrading all 253 generated-Script selectors from `data1` to `data2`.
  Rebind 143 embedded full-Script-hash payload occurrences across 30 generated
  identities as well: changing both code bytes and hash type changes the CKB
  Script identity carried inside witnesses and Cell data, not only the outer
  transaction selector.
  See [0.26 Economics and VM2](docs/releases/CELLSCRIPT_0_26_RELEASE_NOTES.md#economic-backend-closure-and-vm2-deployment-contract).

- Add bounded, explicit trusted-external verifier delegation. New
  `trusted_exec_cell_dep_u8_args`, `trusted_exec_cell_dep_hex4`, and
  `trusted_spawn_wait_cell_dep_hex4` source intrinsics require a compile-time
  32-byte CKB data hash plus an exact
  `cellscript-trusted-external-verifier-v1` declaration in `Cell.toml` for the
  semantic scope, operation, and exact argument adapter. Generated code
  resolves the selected CellDep,
  checks its complete `DATA_HASH`, and only then performs EXEC or SPAWN/WAIT;
  SPAWN also requires a zero child status. Raw delegation remains E2105 and an
  undeclared trusted call remains E2113 under `DenyFailClosed`;
  unused/duplicate/non-canonical declarations are rejected with E2113, and raw
  and trusted calls cannot mix within one scope. Advance compile metadata to
  schema 66 and typed semantics to v8 with a separate
  `trusted-external` evidence tier and an explicit
  `compiler_proves_internal_semantics = false` boundary. Compile metadata is
  now schema 67 after the later VM2 deployment-contract addition. The independent
  checker requires one ordered source/hash/delegate sequence over the same
  CellDep operand and cross-checks runtime, constraints, typed semantics,
  ProofPlan, and machine lowering. Real CKB-VM tests prove exact-hash EXEC and
  SPAWN positives plus CellDep-substitution rejection; checker mutations reject
  changed hashes, removed records, and evidence-tier inflation. See
  [Trusted External Verifiers](docs/CELLSCRIPT_TRUSTED_EXTERNAL_VERIFIERS.md).

- Bind live Fiber business experiments to the exact CellScript fungible ELF
  and both clean repository revisions. `fiber-node-experiments` can
  temporarily install `--cellscript-fungible-artifact` in Fiber's dev
  SimpleUDT slot, records its SHA-256, CKB data hash, byte length and Data2
  identity, restores the original fixture before reporting, and refuses to
  reuse prior execution when either repository or the artifact changes. Live
  runs default to Fiber CI's Bruno CLI `1.20.0`, accept only an explicitly
  pinned `--bruno-cli @usebruno/cli@MAJOR.MINOR.PATCH` override, and override
  `UDT_CODE_HASH` with the installed CellScript artifact's data hash. The exact
  Bruno, Node, npm, CKB and ckb-cli versions are part of the report and cache
  identity. Bruno's `safe`/`developer` sandbox selection is likewise explicit.
  The Fiber router-pay compatibility workspace expresses its final JavaScript
  checks as equivalent declarative assertions, avoiding a Bruno post-response
  hang without removing requests or weakening expected values. If Bruno retains
  RPC handles after its terminal summary, the runner requires a non-empty suite,
  every request at `200 OK`, no failed assertion marker, and a five-second exit
  grace before cleaning it up; the exceptional completion basis is recorded.
  Runtime-generated, untracked node backups are reported after restoration but
  do not masquerade as tracked source drift.

- Complete the final 0.26b business regression replay against clean, exact
  parent runtimes. CKB production acceptance at pinned CKB
  `f7fa4436737756f97a24e254f22c13a36316ecea` passes all 43 actions, 17 Locks,
  26 stateful scenarios / 46 committed steps, and 67 exact live artifact-hash
  bindings. The 218-case iCKB differential suite and full ecosystem-reuse gate
  also pass. Fiber at upstream
  `f9232d52254a5aa52195ecae296c896de7078887` runs the exact 2,032-byte Data2
  fungible ELF through direct UDT, routed payment, and UDT watchtower settlement
  workflows: 15/15, 16/16, and 28/28 requests pass with natural process exits.
  This is complete CKB production-inventory coverage and selected 3/16 Fiber
  workflow coverage, not a universal regression proof or mainnet certificate.
  See the [0.26b business end-to-end regression report](docs/releases/CELLSCRIPT_0_26_BUSINESS_E2E_REPORT.md).

- Add the bounded real-contract interoperability primitives exercised by the
  separate Spore and Fiber comparison work: exact witness/data/Lock/Type byte
  and size reads, exact Script/data-hash fields, Input `since`, transaction
  preimage reads, checked span and gathered BLAKE2b hashing, bounded byte-vector
  materialization, and the u8/hex EXEC plus hex SPAWN/WAIT adapters. These are
  typed, lowered through structured IR, emitted by the internal assembler,
  surfaced in LSP completion, and classified in the executable-surface matrix.
  The external verifier itself is not promoted by those raw adapters; production
  admission requires the trusted-external route above.

- Add a matched cost corpus (`tests/cost_corpus.rs` plus Rust references in
  `tests/fixtures/cost_corpus/`): three scenarios — a two-input pool merge
  with a checked sum and output lock binding, a two-field schema-roll
  successor with one updated field, and an ownership-claim Lock — each
  compiled on both sides with VM accept/reject parity, byte sizes, cycles
  and a growth budget. After the complete economic-backend tranche, CellScript
  is smaller on bytes (0.82-0.97x) and uses fewer cycles (12-35% less on the
  measured positives) in all three rows. Deployed sizes
  of the real DAO, secp256k1, secp-data and xUDT system scripts are printed
  as context with their different feature scopes called out; they are not
  matched comparisons.

- Compact the deployed ELF layout and use optimal small-immediate encoding.
  Move the `.text` payload from file offset 4,096 to 128; the LOAD segment
  still starts at file offset 0 and preserves virtual/file-offset congruence.
  Padding falls from 3,976 to eight bytes. A shared size/encoding classifier
  selects single ADDI or representable LUI forms for `li`; the 20-byte entry
  trampoline retains its fixed encoding. The audited relation ELF falls from
  7,824 to 3,392 bytes (-56.65%): 3,968 bytes saved in layout plus 464 in
  instructions, 41.92% below the matched 5,840-byte Rust sample. The measured
  relation and explicit expansion remain byte-identical at O0–O3. All 187
  committed iCKB differential matrix rows retain their acceptance outcomes;
  the separately reported suite has 218 tests. After the complete economic
  tranche and a fresh single-process replay, all 37 positive rows remain faster:
  805,060 CellScript cycles versus 1,952,526 original-contract cycles, a
  1,147,466-cycle transaction aggregate difference. These rows include shared
  auxiliary Scripts and are not isolated principal-Script measurements.
  Replace the size test's requirement that Rust remain smaller with an
  absolute CellScript byte budget. See the
  [0.26 release notes](docs/releases/CELLSCRIPT_0_26_RELEASE_NOTES.md#major-backend-optimization-compact-elf-and-immediate-encoding)
  for the mechanism, matched-comparison scope, multi-action measurements,
  and artifact-rebuild requirements.

- Make `lock = same` executable and unlock branch-local successors. Resource
  conservation now recognizes the updated-successor shape — verbatim field
  aliases plus verifier-checked u64 updates whose provenance roots in the
  consumed input (constant offsets keep field provenance, mirroring
  subtraction) — so a relation without an explicit lock target carries
  checked conservation evidence, executes in the real CKB-VM with positive
  and negative amount-update cases, and matches the spelled-out Edition 2026
  form. Separately, sibling branch arms no longer reuse a schema-field
  materialization defined only in the other arm: cached field reads now
  carry a branch depth and epoch, arms and loop bodies re-materialize when
  the defining context does not dominate, and a `replace` relation in each
  branch of an `if` compiles and validates. Existing generated code is
  unchanged (892 unit tests, the full regression batch and all 218 iCKB
  differential-suite tests pass without drift); only `exact_hash` stays reserved
  pending the Script-hash value contract.

- Add branch-local successor relations to the authoring route:
  `replace before -> after { data … lock = exact(address) capacity = same
  identity = same }` inside ordinary actions. `data { f = same, f = expr }`
  and `data = same except { f = expr }` expand against the resolved concrete
  schema with exhaustive-coverage, unknown-field and duplicate-field checks;
  the relation elaborates through the same consume/create, type-identity and
  capacity-preservation instructions as the spelled-out Edition 2026 forms,
  carries the identical obligation set, and executes in the real CKB-VM.
  Path-sensitive successor completeness is enforced at the source level: once
  a Cell role is disposed anywhere, every accepting path must dispose of it
  exactly once, loops reject disposal, and double disposal is rejected.
  `lock = same` and successors written in both branches of an `if` are now
  executable as described above. `exact_hash(...)` remains reserved with
  precise remediation because the Script-hash value contract is not frozen.
  The formatter prints the relation and its output recompiles identically.

- Record a WASM playground budget blocker: the canonical container rebuild
  after the 0.26b tranches produces a 643 KB gzip bundle, 44,650 bytes over
  the enforced 600 KB budget. The previously committed 576 KB bundle is kept;
  the policy/artifact/binding/authoring surface reachable from the
  metadata-only path must be trimmed or gated before the release gate's
  WASM bundle check can pass.

- Rebind the audited CKB acceptance recipes to the current artifact and CKB
  Script identities following the established refresh precedent. This closes
  all three identity layers together: sixty case artifacts and 417 exact
  code-hash references, 253 generated-Script selectors upgraded to `data2`,
  and 143 embedded full-Script-hash payload occurrences across 30 identities.
  External dependency selectors and identities remain unchanged. The clean
  production replay passes all 43 action cases, 17 Lock cases and 26 stateful
  scenarios / 46 committed steps, including all seven end-to-end lifecycles.

- Fail closed when a runtime `source::*` view index reaches the 32-bit index
  space. The generated SourceView helper previously added an unchecked index
  to the tagged view word, so an index at or above 2^32 carried into the view
  tag and silently re-routed an `Input` request to an `Output` view. The
  helper now rejects such indexes with `ckb-source-view-invalid` (44) through
  the existing fail-closed scalar status channel, and real-VM policy tests
  cover the forged issuer-authority transaction built from that carry.

- Add explicit bounded persistent Type policies through package artifact
  declarations and in-memory/virtual-source APIs. One ELF dispatches declared
  numeric tags from canonical, full Script-hash keyed policy witness records;
  common Unit checks precede the selected action. Fixed group roles and exact
  counts are checked at runtime. Add independent host/adapter codecs,
  pre-signing placement and typed policy/builder projection validation.
  Focused VM tests cover four action cardinalities and malformed requests.
  Chain/deployment closure for the authenticated lifecycle, independent
  machine dispatch proof, executable branch-alternative successors, remaining
  relation policies, schema acknowledgements and full product support remain
  implementation work.

- Correct the unsupported `env::sighash_all` boundary. Classify canonical
  digest construction as `ckb-sighash-all-deferred`, reject it under
  `DenyFailClosed`, and terminate audit execution with runtime error 66 rather
  than return a synthetic digest pointer. Preserve this effect through unused
  results and helper calls. Explicit BIP340 message verification and standard
  CKB Lock signing remain separate supported routes.

- Add the separately routed `cellscript-source-semantics-2027-authoring1`
  authoring policy over the complete shared Edition 2026 grammar. Ordinary
  action/lock bodies may omit `verification`, multiple entries may coexist in
  source, and existing default/read provenance and lifecycle meanings remain
  available. Keep the bounded native preview4 grammar as a reference surface
  and advance source/cache identities without changing the existing witness
  ABI. Full shared-policy product closure, executable branch alternatives,
  remaining successor-relation policies and schema acknowledgement remain
  tracked implementation work, not claims supplied by this authoring baseline.

- Resolve fixed Cell locations once in IR and emit them in typed semantics v5.
  Native Type ports now load the actual current Script group; `protected`
  parameters use the documented Lock group in both editions. Check membership
  and native fixed-group coverage, unify mixed CellDep read ordinals, and retain
  distinct anonymous output identities. Record ordinary absolute positions and
  unauthenticated positional dependencies truthfully. Group-role guards reject
  ambiguous same-hash Lock/Type use; this is an intentional tightening.
- Share exact artifact entry selection across codegen, metadata and CLI,
  including explicitly selected actions whose dependencies retain `main`.
  Permit witness fallback to outputs only when the input group is empty;
  a missing input witness must not authorize reading an unrelated output-side
  witness. Generated builders no longer require witness payloads for entries
  whose parameters consume no witness bytes.

- Add the parser-independent `cellscript-semantic-foundation-v3` record with a
  hash-consed value-provenance DAG, explicit artifact entry contract, typed
  transaction roles, exhaustive Cell dispositions, enforcement-classified
  claims, legacy migration nodes, and layered `CoreSemanticId`,
  `EntryContractId`, and `ArtifactContractId` identities. Keep source spans in
  source-map v2 and source bytes under a separate `SourceDigest`; neither is a
  core semantic hash input.
- Bind every executable source `require` or Edition 2027 `enforce` claim to its
  canonical condition, condition-provenance node, ordered typed
  success/failure branch, and exact fail-closed runtime error. Keep supporting
  ProofPlan claims distinct, make changed conditions change `CoreSemanticId`,
  and reject broken condition, branch, or error links in the independent
  checker. Map each executable claim node to its originating condition or
  generated-sugar range in source-map v2 without including that moving span in
  the semantic hash.
- Advance compile metadata to schema 65, typed semantics to v7, verified
  lowering records to v6, source maps to v2, and the verified-artifact metadata
  carrier to v2. Extend the independent
  artifact checker and mutation corpus across the new schemas and bind
  deployable-artifact and verified-bundle identities separately.
- Give generated fatal verification failures a separate current-VM-process
  EXIT contract while preserving normal callable return values and deliberate
  raw status APIs. Record explicit typed failures as terminal operations and
  bind static error constants to a checked non-returning machine exit. The
  shared exit does not require restoring caller frames or consuming a return
  register reserved for status. Full helper/optimizer regression closure remains
  part of the authoring production gate.
- Add `cellc expand`, an experimental Edition 2027 frontend selected through
  `Cell.toml`, formatter/LSP coverage, and cross-edition identity tests. The
  original native preview requires explicit transaction parameter sources and
  rejects ambiguous `consume`/`consume_each`; ordinary authoring retains these
  inherited forms. Ordinary artifact compilation retains `SingleEntry`; explicit
  policy compilation emits `PolicyWitnessV1`. The shared schema also represents
  `ExplicitVersionedDispatch`. This does not
  freeze the proposed 1.0 surface grammar or change the stable Edition 2026
  meaning.
- Add review-only `cellc migrate --to 2027` for the bounded legacy Type Script
  and Lock Script subset. Type Script candidates retain ordinary `action`
  authoring and transaction-absolute bindings; they are not silently converted
  into native group-relative ports. The tool preserves
  every source byte outside the final entry, writes nothing unless `--output`
  is explicit, and emits a candidate only after `CoreSemanticId` equality and
  byte-identical RISC-V ELF lowering succeed. Imports, multiple entries,
  custom require messages, ambiguous lifecycle operations, incomplete Cell
  envelopes, and every non-total mapping fail before output creation.
- Implement the bounded `cellscript-source-semantics-2027-preview4` native
  surface: one final native container; either one exact `type-group<T>` Type
  Script entry with exhaustive `replace`, fixed-role checked `pool`, exact
  `retire`, and explicit-identity `fresh` dispositions, or one exact
  `lock-group` Lock Script entry with explicit protected Cell, current Script
  arguments, witness provenance, and `AuthorizationOnly` scope. Add pure,
  type-checked `audit ... external_policy(...)` declarations that remain
  metadata-only and cannot authorize acceptance. Lower executable effects
  through the existing checked semantic paths, retain the source form for
  canonical formatting, retain exact disposition intent in shared IR and
  `CoreSemanticId`, validate it in the independent checker, and cover it through
  CLI, LSP, WASM-source API, editor, syntax-combination, differential-semantic,
  example-package, differential ELF, and negative tests. Keep the public
  website Playground on its coordinated stable Edition 2026 asset until a
  separate preview selector and bundle publication are approved.

## 0.26.0 - Unreleased

- Record the economic-backend optimization implemented on the `0.26b` branch:
  compact payload alignment, shorter constants, shared runtime operations,
  structured IR folds, cached exact reads, cheaper SourceView decoding and
  VM2 Zbb hash rotations make every matched three-scenario corpus row both
  smaller and faster than its size-tuned Rust reference, without changing its
  source or witness ABI. Generated artifacts now require `data2`/CKB-VM2.
  The [0.26 release notes](docs/releases/CELLSCRIPT_0_26_RELEASE_NOTES.md)
  explain the byte savings and evidence limits. This is branch implementation
  evidence, not a stable-release or `nightly-0.26` availability claim.

- Implement the first bounded consensus-runtime contracts. Fixed-width
  `BoundedCellSet<Resource, N>` now scans the exact current Type Script
  `GroupInput`, checks role, exact data size, runtime cardinality including an
  `N + 1` probe, and executes predicates once per element. Fixed-width
  `BoundedList<Plan, N>` now uses the versioned `CSBPLv1\0` Molecule FixVec
  witness plan and verifies one canonical `GroupOutput` per element, including
  complete data, exact lock, declared capacity floor, predicate execution, and
  final count. Bounded bodies admit only pure predicates, one create template,
  and numeric outer `+=` accumulators. Dynamic layouts, other sources, custom
  identities, incomplete templates, and implicit lock/capacity policy remain
  fail-closed.

- Add production-policy and real CKB-VM coverage for zero/one/N/N+1 inputs,
  malformed codecs and cell data, predicate failures, output
  count/order/data/lock/capacity mismatches, and typed/machine artifact
  mutations. Add checked `.cell` examples for variable-cardinality claims,
  1–16 order settlement, fragmented Cell merging, and bridge/rollup batches.
  Advance compile metadata to schema 62, constraints metadata to schema 3,
  verified lowering records to v4, and typed semantics to v3.

## 0.25.0 - Unreleased

- Rebase the 0.25 development line on the complete 0.24 trust boundary,
  including the lock-authoritative package graph, standalone artifact checker,
  sole internal assembler, modular code generator, executable scenarios,
  LS-IDL Registry path, and production/testnet website parity. Align the
  compiler, checker, adapters, verifiers, workspace lockfiles, and editor with
  the 0.25 development identity. Preserve the independently deployed Registry
  Type Script as the byte-identical 0.24.0 artifact whose package version and
  CKB data hash are already part of its published trust identity. Keep the
  website's public release badge on stable `v0.24.0` while giving the 0.25
  Playground compiler its own asset identity
  (`20260824-v0.25.0-32dc571c`, SHA-256
  `32dc571c2e8e32134460cb45e2329ddd29d754959d9cfe4478c638aa5fc4c7d7`).

- Harden bounded lifecycle collections at the production boundary. The typed
  IR now retains `consume_each` predicates and the `create_each` output
  template and lowers both constructs to an explicit registered fail-closed
  call instead of silently replacing the body with `Unit`. Non-production
  CKB artifacts reject the entry with stable runtime error 24
  (`collection-runtime-unsupported`); `--production` and
  `--deny-fail-closed` stop before ASM/ELF generation with E2105 and report the
  operation, source origin, missing ProofPlan enforcement, and remediation.
  Entry ABI metadata no longer presents either bounded collection as a
  supported schema pointer, and ProofPlan no longer fabricates a
  runtime-observed cardinality. Runtime Cell selection/decoding and witness
  plan/output correspondence remain deliberately unsupported until their
  consensus semantics are specified.

- Bound local compiler and gate storage without weakening the verified-artifact
  contract. Incremental build caches now retain at most 32 recent identities
  per cache root, syntax-combination success runs discard reproducible
  per-case intermediates, production CKB acceptance removes its multi-gigabyte
  transient Cargo target and stopped-node database, and managed gate streams
  retain the latest three runs by default. Duplicate acceptance files within
  and across retained runs are hardlinked when their SHA-256 identities match,
  while stable `latest-*.json`
  indexes point to the full reports. Failed syntax runs and explicit repro
  runs keep their diagnostic artifacts; release automation can request
  unlimited local retention explicitly. `cellc clean --cache` now removes
  nested workspace `.cell/build/cache` directories as well as the root cache.
  Cache payloads must be regular files, stores create a fresh entry instead of
  overwriting a pre-populated one, and recency updates use create-new plus
  rename so malicious cache symlinks cannot redirect compiler writes.

- Begin the 0.25 language-completeness implementation with a compiler-owned
  executable-surface registry, pre-codegen production rejection, full-range
  `u128` decimal literals, integer bitwise/shift lowering, and exact scalar and
  wide division-by-zero guards. Add the parameterized non-Cell value kernel:
  explicit struct/enum/function parameters, value abilities separate from Cell
  lifecycle capabilities, phantom identity rules, deterministic bounded
  monomorphization before IR, built-in `Option<T>`, generic fixed arrays,
  metadata and `cellc explain generics`, editor/Playground highlighting, and
  CKB-VM execution evidence. Ordinary generic layouts continue to reject
  Cell-backed values. Add recursive enum/tuple/struct patterns and binding-free
  or-patterns, and close the fixed tuple/array materialization and projection
  paths required for nested payload patterns to execute in CKB-VM. Extend
  explicit Cell borrows with field paths and canonical-root read-only
  reborrowing while preserving non-escape and lifecycle-crossing rejection.
  Add explicit public/package/private visibility, canonical package interfaces,
  six-dimensional interface compatibility with stable E2501 rejection,
  Registry interface/hash admission, metadata schema 61 typed-semantics-v2 records,
  lowering-record v3 and independent V2419/V2420 typed-to-machine checks. Generic
  templates now specialize across package boundaries in their owning module;
  implementation monomorphizations no longer pollute package interfaces. Add
  labeled break/continue CFG lowering and CKB-VM evidence. Upgrade the VS Code
  grammar and Playground highlighting. Keep the default Playground bundle
  under its 600 KB gzip budget with a bounded authoring summary; complete
  public-interface, typed-semantics, ProofPlan, verified-artifact, and semantic
  language-service output remains on native `cellc` and the VS Code extension.
  Route all wide u128 binary operands
  through shared stack-spilled loading so dynamic Molecule-table field
  validation can no longer clobber live limbs, keep constant folding from
  wrapping arithmetic the runtime would trap on, decide match exhaustiveness
  with a bounded constructor-matrix computation that merges nested and
  or-pattern payload coverage, derive Cell-backed value abilities structurally
  through struct and enum fields, and register E2501 with the shared error
  registry. Dynamic-schema u128 bitwise, addition, and shift paths now carry
  exact CKB-VM execution vectors.

## 0.24.0 - 2026-08-22

- Align the complete 0.24 release identity across every workspace and verifier
  crate, the independent checker dependency, lockfiles, Registry Type Script,
  Myelin handoff, VS Code extension, website WASM bundle, README, and release
  documentation. Restore the 0.23 release hardening that propagates one pinned
  CKB checkout through backend scenarios and transaction-measure tooling.

- Remove the unreachable external RISC-V toolchain fallback and make the
  audited internal assembler the sole ELF-emission path. Reassign `E2400` to
  the verified lowering/source-map boundary that already uses it, so the
  compiler error registry now matches live diagnostics.
- Split the code generator into its documented ABI, assembler, call,
  collection, expression, frame, runtime, schema, and Cell-operation modules;
  remove crate-wide Clippy exemptions; and replace long positional helper
  signatures with named context records.
- Harden the final wide-integer boundary: resolve dynamic Molecule-backed
  `u128` fields before loading limbs, preserve the left operand across a
  second dynamic load, and make `u128 +/- u64` overflow and underflow fail
  closed with runtime error 49. Add exact CKB-VM regression vectors, remove
  zero-divisor paths from the NFT and vesting examples, and reject
  non-canonical SemVer at Registry admission.
- Remove the CKB adapter's deprecated, permanently fail-closed automatic
  deployment methods. Callers must build a verified unsigned deployment
  transaction and hand signing to an external wallet.
- Replace the deprecated `serde_yaml` crate with the maintained
  `serde_yaml_ng` continuation in the Fiber configuration renderer.
- Remove tracked browser-session traces and unused design captures, ignore
  local Codex state, and make the native source-policy check reject future
  `.playwright-mcp` artifacts.
- Keep the production and Pudge Testnet Registry websites on one UI contract.
  The website gate now builds both environments from the same source, verifies
  six shared Registry routes, and requires every generated CSS/JavaScript asset
  to be byte-identical. Testnet now ships the LS-IDL route, defaults LS-IDL
  lookups and API examples to `testnet`, and no longer preloads production
  package records into Manage or artifact-detail fallbacks. Network-specific
  origins, chain selection, sandbox expiry, no-index policy, and storage remain
  isolated.
- Preserve the corrected website release lineage that removed stale 0.22
  metadata. Publish the homepage as `v0.24.0` while keeping the Playground on
  the matching 0.24 compiler identity. The canonical WASM bundle uses asset
  identity `20260819-v0.24.0-19ce8898` and SHA-256
  `19ce8898e8161f100edebf6f982d856f3e59bfac31572642b53f2e01c70a1a17`;
  distribution checks bind the current stable release URL and displayed tag
  separately from the compiler version, asset identity, and digest.
  Remove inherited 0.25-only package-interface, typed-semantics, and future-
  syntax presentation fields from the 0.24 website branch while retaining the
  0.24 LS-IDL surface. Publish the exact 0.24 and 0.25 website gitlinks on
  separate release branches so both parent lines clone without hidden commits.
- Add first-class LS-IDL publication and discovery for CKB Lock Scripts.
  `cellc artifact ls-idl` validates the bounded 0.1 schema, appends
  `SHA-256(raw idl.json)` to an executable, generates a publish-ready bundle,
  and fetches byte-exact IDL by deployed Script identity. Registry admission,
  both verifier boundaries, immutable object storage, Postgres lookup,
  canonical `/v1/ckb/scripts/:code_hash/interfaces/ls-idl` reads, and the
  compatibility `/idl/:code_hash` route all enforce the same schema and
  executable-suffix contract. Pin all 17 current upstream client vectors and
  seven derive/example IDLs, and add an opt-in test that runs the actual
  upstream Rust client against Registry's compatibility handler. Extend that
  opt-in acceptance through the fixes merged upstream in `ckb_sudt_script`
  PR #7, real RISC-V contract builds, LS-IDL-bound ELFs, and all 25 example
  CKB-VM tests without a local compatibility overlay. Add a
  runnable Rust example, website lookup/detail surfaces, and VS Code
  validate/bind/fetch commands. Name the website tab `LS-IDL` rather than the
  ambiguous `Interface`, give it the canonical `/registry/LS-IDL` route with a
  permanent redirect from `/registry/interface`, and align its lookup panel
  with the full-width Browse surface.
  Keep implementation correctness and security review outside this
  byte-identity claim.
- Ship the 0.24 package and Registry trust closure, informed by Sui Move's
  package-alt separation of resolution from compilation. Replace permissive
  custom version checks with standard SemVer; make `Cell.lock` v3 a
  manifest-digest-bound dependency graph with exact source/content identity,
  outgoing alias edges, runtime/test feature roots, and genesis-bound CKB
  environments. Add explicit `cellc lock`, lock-authoritative build/check/test,
  `--locked`/`--frozen`/`--offline`, package aliases, optional features,
  test-only dependencies, environment overrides, immutable Git-commit and
  Registry-snapshot caches, and bounded hash-pinned external resolvers that
  normalize to an ordinary source pin and never execute during locked builds.
  Keep build dependencies fail-closed until isolated execution exists. Replace
  scattered Registry artifact-profile conditionals with the versioned,
  fail-closed `cellscript-registry-profile-catalog-v1`; only CellScript source
  profiles are dependency-resolving, while executable, reproducible, and copy
  profiles remain explicit non-resolving artifacts. Add a portable
  `examples/package_graph` fixture that executes alias, SemVer, feature,
  test-only, environment, and override selection from the frozen graph.
- Implement the 0.24 trust-closure core. CKB ELF builds now emit canonical
  `cellscript-verified-lowering-record-v1` and
  `cellscript-source-artifact-map-v1` sidecars, bound by metadata schema 58 and
  checked by the compiler-independent, budgeted
  `cellscript-artifact-checker`. The checker independently parses static
  ELF64/RISC-V layout, decodes the emitted instruction/call/branch surface,
  checks CFG reachability, frames and stack restoration, ABI/ProofPlan/syscall
  contracts, block digests, source ranges, and cross-file identities with
  stable `V2400`-`V2418` rejection codes and deterministic mutations. Package
  the checker independently and require checker-first crates.io publication
  before the matching compiler crate. Extend
  `verify-artifact` with separate binding, structural, lowering-record,
  CKB-VM, chain, and semantic-equivalence states. Make `cellc test` require an
  explicit simulator/CKB-VM backend for execution and add versioned,
  fail-closed scenarios with exact runtime errors, local multi-step live-Cell
  replacement, source-linked coverage, cycle/size/capacity limits, and exact
  artifact/checker bindings. Add a least-privilege Registry artifact worker
  whose production graph excludes the compiler. Freeze the CellScript side of
  the Myelin handoff without a new profile or raw-witness alias; keep external
  Myelin adoption and the incomplete Fiber/RGB++ matrices explicitly pending.
  Add `examples/scenario_basics` as the runnable positive/exact-negative
  scenario and four-file verified-artifact walkthrough.
- Freeze the 0.23 implementation scope around Edition 2026 and its resolved
  profile/entry identities, the deployed Registry and publisher-session path,
  native gate tooling, the recoverable website workbench, and the bounded Fiber
  evidence actually obtained on this line. Keep mainnet Registry Script
  activation, publisher-owned wallet adoption, and incomplete Fiber/RGB++
  matrices as explicit external checkpoints. Retire the proposed CellScript
  Off-Chain Session Runtime target: current Myelin uses an attested external
  compiler process, production requests stay on `ckb`, and Myelin-owned
  extended semantics remain outside the compiler. Add the 0.24 trust-closure
  roadmap for an independent bounded artifact checker, executable package
  tests, source maps, the Myelin adapter handoff, and conditional ecosystem
  evidence promotion.

## 0.23.0 - 2026-08-11

- Make Registry chain confirmation compatible with the standard CKB v0.207.0
  RPC schema by resolving a live Cell's committed block through
  `get_transaction.tx_status` instead of depending on a proxy-specific
  `get_live_cell.block_hash` extension. Recorded evidence now names both RPC
  methods while historical evidence identifiers remain readable. Make the
  tooling-release gate parse website scripts structurally and enforce the
  stable build steps in order, so adding intermediate regression checks no
  longer breaks CI through an obsolete exact-string comparison. Let the full
  backend stateful audit use an explicit isolated pinned CKB checkout through
  `CELLSCRIPT_CKB_REPO`, avoiding any need to modify an unrelated sibling CKB
  worktree during release validation. Propagate the release gate's existing
  `--ckb-repo` selection to its independent `ckb-tx-measure` workspace as
  well, so every CKB-dependent release check resolves against the same pin.
- Turn the browser Playground into a recoverable Cell-oriented workbench.
  Browser-local workspace snapshots now retain source files, entry selection,
  active panels, and an honest saved/dirty state across refreshes. Failed
  compiles preserve the last valid output as explicitly stale evidence, and a
  failed compiler Worker can be restarted without reloading the page. Add a
  metadata-derived Cell Flow view, source-linked action/type selection, a
  contextual Inspector, and an optional three-step guide while keeping raw
  actions, types, metadata, diagnostics, and the existing no-ELF WASM boundary
  available. Unify the site's interactive controls around dense, standard, and
  workflow button sizes with distinct neutral, selected, and primary states.
  Registry and Playground actions now share the same contrast-safe treatment,
  compact copy controls, focus rings, press feedback, and Phosphor interaction
  icons. The Playground compile action keeps a stable label and exposes busy
  state without turning the action itself into a transient status display.
- Bound Registry discovery requests so the interface can no longer remain in
  an indefinite loading state. The browser now delays skeletons to avoid
  flashes on fast responses, reports slow and retrying requests, retries once
  with a strict deadline, preserves stale or mirrored results when available,
  and otherwise presents an explicit recovery action. Registry rows and empty
  states use compact artifact identity marks and low-motion transitions instead
  of generic placeholder panels. Redesign the global navigation around three
  primary destinations, quieter utility controls, Phosphor SVG icons, and a
  touch-safe mobile drawer with focus containment, Escape/backdrop dismissal,
  scroll locking, and persistent theme and language controls. Source discovery
  now has a quiet hover/focus label, while fixed full and compact language
  controls prevent locale changes from shifting the desktop navigation.
  The Playground now places its toolbar, compiler panels, and status bar in a
  centred wide-screen Studio frame instead of switching ambiguously between
  the site frame and an edge-to-edge editor. An explicit, persisted focus mode
  removes site chrome and expands the same workbench to the viewport without a
  first-paint flash; phones retain the existing panel switcher and site header.
  Registry discovery now translates verification, deployment, availability,
  and consumption mode into one consumer-facing use conclusion, supports
  URL-restored intent filters, and shows the latest release date without
  replacing the canonical status axes. Artifact details split the consumer
  action from the maintainer's current evidence or deployment task, explain
  each accepted evidence kind while keeping full hashes and raw JSON
  accessible, and avoid presenting build verification as a security audit.
  Maintenance keeps the selected task visible while progressively disclosing
  alternate and destructive operations.
- Close the first-publish browser/CLI loop with `cellc publish --authorise`.
  cellc now creates and stores the delegated P-256 publishing key locally,
  opens a 15-minute exact-coordinate wallet session, and resumes publishing
  automatically after Registry approval; `--no-open` supports remote and
  terminal-only environments. Session reads expose neither the polling secret
  nor the resulting key ID to the browser. The publishing key is written to
  the OS keychain as `pending` before the browser opens, promoted to `active`
  only when either successful status returns the matching key ID, and removed
  only after the Registry confirms cancellation or pending-session expiry. A
  local polling deadline performs one final authoritative read and otherwise
  preserves the pending key. Completed sessions remain poll-readable for 24
  hours after their 15-minute approval window, closing the boundary race in
  which wallet approval commits just before the CLI's next poll. This closes
  the process-exit window after wallet approval without treating local state
  as Registry authority. The browser
  token survives same-tab refresh in `sessionStorage` and is removed on
  completion or expiry, with an executable storage-lifecycle regression test.
  Session mode now
  lists only connectors that can actually complete the browser flow and folds
  challenge creation, wallet signing, and completion into one **Approve
  publishing access** action; the full external-wallet directory remains in
  the explicit manual CLI path. Session completion atomically consumes the
  nonce, records the publishing key, claims or reviews the namespace, updates
  the session, and writes its audit trail. Concurrent or replayed completion
  returns the committed result without duplicating authority. The Publish page
  is now session-first: a direct visit presents one `cellc publish --authorise`
  starting command, while a CLI session becomes a one-screen wallet approval
  surface with one current action and end-to-end release progress. Artifact
  identity is read-only in session mode because cellc and the manifest remain
  authoritative. External signing, manifest scaffolding, and existing-key
  checks remain available in a deliberately secondary advanced workspace.
  Technical scope and session identifiers stay collapsed by default, and
  loading, expiry, retry, review-pending, and terminal-continuation states keep
  the same stable layout. Safe publishing-access reads retry once with bounded
  deadlines, while signed writes are never retried automatically; an unchanged
  failed request keeps its signature, and any coordinate or payload change
  clears it with an explicit explanation.
- Add an isolated Pudge Testnet Registry Sandbox. Its API, Postgres database,
  object volume, signing origin, RPC identity, website build, wallet storage,
  and deployment evidence are separate from production. Sandbox releases are
  hidden 72 hours after admission; version JSON is deleted at expiry and source
  objects are deleted after a 24-hour grace period, while minimal audit
  tombstones remain. The API rejects a wrong-network RPC and cross-environment
  deployment payloads. `cellc artifact record-deployment --network testnet`
  defaults to the Pudge Registry API, and `cell-dep` revalidates liveness on the
  network recorded in accepted evidence. Pudge chain history remains immutable:
  expiry removes Registry indexing and off-chain objects, not on-chain Cells.
- Complete the Registry's generalized artifact and chain-evidence path. Rust,
  C, JavaScript, and other CKB artifacts now keep explicit source, build,
  deployment, TCB, and copy-only identities instead of being presented as
  CellScript dependencies. Reproducible profiles require P-256-signed reports
  from two to sixteen policy-approved builders spanning the configured minimum
  number of independent trust domains. Reports bind the signed environment,
  source, recipe, executable, build log, builder identity, and predecessor
  evidence before verification becomes `verified`; deployment is rejected
  until that evidence exists. Add `cellc artifact reproduction-report` and
  `cellc artifact reproduction-evidence`, wallet-ready mainnet commitment
  transaction intents, and `cellc auth reproducer create` for generating a
  builder-local P-256 key plus a public policy enrollment record without
  exposing PKCS#8 material. Explicit CI-key output is mode 0600 on Unix and
  no-overwrite. Add fixed Registry Type/commitment Lock configuration,
  Type-Script-indexed `CSREGv1` scans, and scheduled lifecycle reconciliation
  that demotes spent commitments or stale deployment Cells without deleting
  historical evidence. Both Script code CellDeps must be live and sufficiently
  confirmed before the chain path becomes ready. The chain path is implemented
  but remains operationally disabled until the canonical mainnet Registry Type
  Script, commitment custody Lock, and both CellDeps are deployed and configured.
- Harden the unified artifact Registry boundary: default discovery now hides
  pending/rejected releases and paginates by package coordinate; deployment
  records and admin recovery must match the immutable CKB `hash_type` and
  `dep_type`; generated CellDep descriptors re-query mainnet and reject spent
  code/DepGroup Cells; RPC calls are time- and size-bounded; and deployment
  capability use commits with the chain-verified state. Positive static-mirror
  publication now follows database admission, while suppressive states are
  mirrored first to fail closed; deferred sync is audited rather than
  advertising uncommitted positive state. Add the capability-signed
  `cellc artifact set-availability` publisher path used by Manage, defensive
  frontend page deduplication, and complete `Artifact.toml` plus bundle
  scaffolding for non-CellScript submissions.
- Split delegated Registry authority into independent `publish`, `deployment`,
  and `availability` scopes. Release admission no longer grants permission to
  attach CKB deployment evidence or change a release's public availability;
  exact-coordinate and namespace-wildcard grants remain supported. In a
  package directory the CLI infers only the exact `publish` scope; deployment
  and availability grants require explicit `--scope` flags. The API, Submit command builder,
  validation, tests, and operator documentation now share this contract.
- Redesign the Registry submission and package-maintenance surfaces around
  contextual, task-first workflows: remove the public `Manage` tab and
  redundant form controls, link maintenance from package details, guide first
  publication through explicit connect, sign, submit, and namespace-claim actions, show the publication
  orientation only once per browser, replace the CCC post-connect surface with
  a compact Registry-owned wallet chooser that has no unrelated `Manage`
  action, reveal yank fields only for the yank task, and close write commands
  over verify, dry-run, and publish. Registry route and workflow state changes
  now use reduced-motion-aware transitions instead of abrupt swaps. Browse and
  Submit share one DOM-persistent Registry header through navigation, avoiding
  replacement flicker while retaining the active locale; wallet connection no
  longer gates artifact definition or local preflight, and appears only after
  the developer has chosen an artifact coordinate and the new-capability path.
  Existing capability keys use a read-only server check for live status,
  expiry, exact publish scope, and active namespace ownership; entering a key
  ID never unlocks the UI locally. Final publish commands include the
  server-confirmed `--capability-key-id`. Primary authorisation controls use
  larger, shorter-reach interaction targets. Client-routed returns now
  reinitialize Submit and artifact-detail behavior instead of leaving stale
  event handlers behind. The advanced publisher keeps a per-environment,
  same-tab draft of non-secret artifact fields and UI state while explicitly
  excluding wallet signatures, challenge/browser tokens, capability payloads,
  and private keys. Registry, Publish, and API also share one route-transition,
  vertical-rhythm, active-tab, and localized-title contract; Browse reuses its
  latest in-memory result during background refresh rather than flashing a
  skeleton on every return.
  Browse uses a no-flash loading state, URL-backed server search, and API
  pagination; bundled data appears only as an explicitly labelled error
  fallback. Static and live package details share one responsive view with
  localized statuses and copyable audit values. Publisher authorisation now
  accepts both JoyID
  (`joyid_ckb`) and standard CKB secp256k1 (`ckb_secp256k1`) principals through
  the CCC CKB-signer boundary. Production exposes only mainnet; the separately
  built Pudge Sandbox constructs a testnet client without adding a network
  selector to either environment. The frontend never accepts
  mnemonic words; traditional recovery phrases remain inside the wallet. CLI
  auth commands use `--wallet-signature`, with `--joyid-signature` retained as
  a visible compatibility alias, and the API adds the corresponding typed
  principal migration and signature verification. The compact chooser now
  preserves the complete twelve-wallet CKB directory: compatible CCC CKB
  signers connect directly, while other entries are explicitly labelled as
  external links for importing a compatible `wallet-signature.json`; opening a
  link is never represented as a wallet connection. The browser checks the
  signature shape and principal binding before submission, while the API
  remains authoritative for cryptographic verification. Every entry
  now uses the corresponding official Nervos wallet-directory SVG rather than
  an autogenerated letter mark or a runtime favicon. The chooser header no
  longer reserves space for a hidden back control, so its title, explanatory
  text, and wallet list share one left alignment edge. Submit now asks for the
  artifact kind and source language independently, and Manage groups publish,
  inspection, reproduction, deployment, commitment, and availability as
  isolated task flows; hidden task fields can no longer leak into the selected
  workflow.
- Deploy the public Registry production slice at
  `api.registry.cellscript.dev` and `registry.cellscript.dev`: Postgres 17 is
  the authoritative write store, the Node 22 adapter persists source snapshots
  and version-addressed JSON to an isolated object volume, and a read-only
  nginx service exposes `/packages/*` independently of the API/database
  process. The production stack adds live dependency-aware readiness, bounded
  request bodies, structured logs, health checks, log rotation, generated
  secrets, HTTPS, and an 8 MiB proxy admission limit sized for the 5 MiB source
  snapshot contract. Public package search, package detail, and ordered
  evidence promotion APIs are live. A daily systemd job writes atomic,
  checksum-protected Postgres/object-store backups with bounded retention; its
  first backup passed database and archive restore inspection. Public version
  responses now expose immutable snapshot descriptors, the read-only service
  serves those content-addressed snapshots, and the CLI verifies object SHA-256,
  safe paths, per-file BLAKE2b, and the whole-tree source hash before atomically
  materialising a dependency. The CLI uses the public API's accepted status as
  the default resolution authority while retaining the explicit
  `CELLSCRIPT_REGISTRY_URL` Git/offline override, and the website renders the
  live Registry with a clearly labelled read-only bundled mirror only when the
  API is unavailable. The former Registry Coming Soon surface is removed.
  First-publish admission is now user-reachable end to end: `cellc auth
  namespace claim` and the submit page's **Claim namespace** action explicitly
  establish namespace ownership between capability registration and publish.
  Publish admission now commits package, snapshot, version, capability-use,
  acceptance-audit, and completed-idempotency state in one database transaction;
  pre-admission failures release the request-owned nonce and retry reservation,
  while production readiness verifies both managed object-store prefixes and
  volume initialization repairs their ownership and modes recursively.
  Explicit unverified/quarantined install acknowledgements are persisted in
  dependency tables, preventing lock refreshes and later builds from losing the
  caller's risk policy. Publish admission now transactionally creates a leased,
  bounded verification job. A separate least-privilege worker authenticates the
  immutable snapshot, compiles it with the current CellScript compiler, checks
  the signed manifest and compatibility-profile identities, atomically records
  `verified_build` evidence, and then converges the static version object.
  PostgreSQL `FOR UPDATE SKIP LOCKED` claims, expiring leases, three-attempt
  retry/dead-letter handling, operator queue metrics/requeue endpoints, bounded
  subprocess time/output/memory, and API readiness tied to the worker heartbeat
  make the formerly documented asynchronous queue real. Public search/list now
  excludes `source_published` and `indexed_pending` by default while preserving
  explicit status queries and direct audit URLs. Package-manifest identity uses
  canonical recursively sorted JSON, eliminating cross-process `HashMap` order
  drift between publisher and verifier. Deploy that worker to the live
  production topology and exercise external publish, queue claim, real
  compilation, evidence promotion, static convergence, default visibility, and
  a fresh consumer install/check/build without an unverified override. The
  one-time seeded smoke identity and live objects were removed afterward, queue
  counts returned to zero, and a checksum-verified backup captured the migrated
  clean state. Production Compose now accepts explicit prebuilt API/verifier
  image references so shared hosts can deploy with `--no-build`. Harden the API
  and static Registry response boundary with HSTS, anti-framing, no-sniff,
  permissions policy, cross-domain-policy denial, and a deny-all CSP for JSON
  surfaces. Add a reproducible website production Compose/nginx contract with
  a read-only root filesystem, bounded temporary filesystems, health checks,
  log rotation, `no-new-privileges`, and matching browser security headers. A
  production recovery drill restores the post-`0002` dump into an isolated
  Postgres 17 container, extracts the object archive into an isolated volume,
  verifies both migrations and all seven core Registry tables, and removes the
  temporary restore resources afterward.
- Close the 0.23 syntax-audit consistency gaps: canonical type declarations
  now use comma-terminated fields, syntax-combination gates cover canonical and
  comma-free compatibility input, checked example mirrors use named `U64_MAX`
  overflow expressions, and `dev` / `ci` reject regressions. Rebind the three
  affected timelock transaction recipes to the deterministic scoped ELF data
  hashes produced by those equivalent named expressions. CKB-VM crypto
  primitive fixtures now place `CSARGv1` through the current
  `WitnessArgs.input_type` adapter path instead of the retired raw-witness
  alias.
- Make `edition = "2026"` the single mandatory CellScript package contract.
  Edition is now explicitly a long-lived source-semantics epoch rather than an
  annual release or complete ABI bundle. The resolved compatibility profile
  independently composes source semantics, target, primitive assurance, entry
  payload and placement ABIs, and metadata schemas under
  `cellscript-resolved-compatibility-profile-v1`. Metadata schema 57 carries
  those axes, and their hash remains bound across cache keys, registry records,
  `Cell.lock` v2, `Deployed.toml` v2, compile receipts v2, generated builders,
  native APIs, WASM, LSP, and the playground. Missing or different editions
  and older persisted schemas are rejected; no migration or compatibility
  reader is provided. Generated CKB entries also remove the raw-`CSARGv1`
  witness fallback, so placement ABI v2 accepts the payload only inside
  canonical `WitnessArgs.input_type`. The deployed public registry uses one
  current contract: signed entries, the production database schema,
  version-addressed static JSON, and the website require both Edition 2026 and
  the separate compatibility-profile hash, with no fallback reader for
  incomplete entries. Generic admin status changes cannot manufacture
  `verified_build`, `deployed`, or `on_chain_committed` claims; those states
  require the ordered evidence-promotion path. See the
  [0.23 development release notes](docs/releases/CELLSCRIPT_0_23_RELEASE_NOTES.md).
- Complete the native-tooling cleanup: neutralize migration-era identifiers,
  remove tracked legacy traceback logs and cache exclusions, rename the native
  tooling integration suite, and add a repository-wide source-policy command
  to every gate. The policy traverses initialized submodules and rejects
  retired interpreter sources, generated bytecode/cache artifacts, capture
  logs, and active tooling references before they can re-enter the release
  contract. The canonical WASM container now explicitly selects its already
  installed pinned Rust toolchain, avoiding an unnecessary network sync during
  release builds.
- Restore the 0.23 release gate after the Python-to-Rust tooling migration by
  checking the semantic `requires_all_bundled_examples_strict_original_ckb`
  and emitted `source_provenance` CKB boundaries plus the Rust-backed NovaSeal
  acceptance summary instead of retired temporary-directory, helper, and shell
  field names, and refresh the NovaSeal external TCB review template to the
  current Rust-migrated verifier source-tree hash. Refresh the RWA legal-review
  template's profile source-tree hash after its manifest declares Edition
  2026. CKB transaction-recipe replay now tops up fresh devnet funding when a
  fixture has no disposable change output and its replacement input cannot
  fund every typed output.
  Rebuild the website WASM bundle with the witness-placement-v2 compiler so the
  playground and native release artifacts expose the same ABI.
- Add the explicit `cellscript-witnessargs-input-type-v2` placement ABI for
  parameterized CKB entries. Generated wrappers now resolve witnesses relative
  to the active script group, decode the `CSARGv1` payload from
  `WitnessArgs.input_type`, preserve wallet/multisig ownership of `lock`, reject
  malformed or wrongly placed payloads, and reject group-relative raw-v1
  placement. Builders place `input_type` before SDK signing because the
  complete `WitnessArgs` is signed. A canonical signed multisig-v2 CKB-VM
  regression covers a type group whose first input is not transaction input
  zero and rejects post-signing witness mutation. The Rust-native v0.23
  transaction recipes are rebound to the resulting audited ELF data hashes so
  the production stateful gate cannot silently replay stale code identities.

## 0.22.0 - 2026-07-19

- Make GitHub publication depend on the full release gate. Release evidence now
  requires a clean version/tag-matched CellScript tree, an exact clean CKB
  revision and version pin, hashed node/template/genesis provenance, mandatory
  43-action stateful coverage with per-step commit/liveness/measurement checks,
  a freshly built and archived CKB executable, complete 20-byte ELF trampoline verification,
  fresh WASM/VS Code packaging, and tests/clippy across every workspace crate.
  The WASM build now runs in a digest-pinned canonical Linux/amd64 container,
  remaps repository and Cargo source paths, uses SHA-256-pinned official
  wasm-pack 0.13.1, wasm-bindgen 0.2.121, and Binaryen 131 tools, and runs
  `wasm-opt -Oz` before enforcing the 600 KB gzip budget.
  Website provenance and assurance snapshots are regenerated from CellScript
  0.22.0 rather than displaying stale 0.17 compiler and metadata versions.
  Public `action build`/`gen-builder` contracts are verified separately from
  explicitly handwritten Python acceptance transactions; always-success
  resource Type Scripts remain a recorded fixture-only non-claim.
- Make the pinned NovaSeal RISC-V verifier artifact reproducible across the
  audited macOS arm64 and Linux amd64 builders by remapping source paths and
  stripping the release ELF with Rust's pinned `rust-objcopy`.
- Classify field-preserving N-input/N-output resource permutations as checked
  runtime conservation. This closes the strict CKB ProofPlan gap for NFT
  royalty/seller payment pairs without adding action-name-specific backend
  rules.
- Correct the misleading bundled `multisig.cell` surface: the example now
  models explicitly non-cryptographic `Approval` records, removes discarded
  64-byte signature payloads, labels witness time as reported rather than chain
  time, and keeps real signer authentication, sighash binding, witness layout,
  replay policy, and verification in an explicit Lock Script or pinned verifier
  package. The README no longer describes nonexistent CKB signature syscalls.
- Bind every `multi_phase_dao.cell` transition to the same
  `env::current_timepoint()` evidence path instead of mixing it with public
  witness time arguments.
- Harden the bundled contract examples around real Cell identities and asset
  settlement: AMM pools bind both token TypeHashes and geometric LP supply;
  NFT sales consume and relock typed Token payments; timelocks and swaps
  release actual Token outputs; DAO votes lock and redeem voting Tokens; and
  vesting separates repeatable partial claims from the terminal fully-vested
  transition, with an explicit runtime-checked `Active -> Active` self-loop for
  each partial claim. Package mirrors and acceptance action matrices track the
  same canonical sources.
- Document fail-closed Spore and RGB++ adapter boundaries, including maintained
  SDK selection, contract/deployment identity, Molecule and witness layouts,
  Bitcoin confirmation policy, and positive/negative fixture requirements.
- Add compile-checked Spore and RGB++ identity-adapter packages under
  `examples/ecosystem/`. They bind exact CKB Script identities and transaction
  positions while deliberately leaving Spore rules, RGB++ commitments,
  Bitcoin validation, witnesses, confirmations, and orchestration to pinned
  protocol packages and builders.
- Add executable exact and bounded resolved-CellDep data-hash checks. The
  bounded scan requires a literal `1..=64` maximum, uses the real
  `LOAD_CELL_BY_FIELD(DATA_HASH)` syscall path, stops on
  `INDEX_OUT_OF_BOUND`, and fails with stable runtime code `63` when absent.
  Original DepGroup identity remains manifest/builder evidence.
- Add fixed-width executable SHA-256 and SHA256d helpers for 32-byte values and
  64-byte pairs, plus a SHA256d Merkle verifier bounded to 16 siblings. Rust
  reference vectors and positive/negative CKB-VM tests cover the generated
  RISC-V; this is explicitly not a Bitcoin SPV implementation.
- Add `verifier::btc::bip340::require_signature_from_cell_dep` for an explicit
  literal verifier dependency index, retain the index-0 spelling for
  compatibility, and document the fixed 144-byte VM2 IPC envelope. The caller
  still owns message domain, ScriptGroup/WitnessArgs and sighash construction,
  authority binding, replay policy, deployment pinning, and external review.
- Migrate every in-tree Rust crate to Edition 2024 and Rust 1.97.1, adopt the
  Edition 2024 dependency resolver, pin the repository toolchain, and align CI,
  release builds, rustfmt, fixtures, and generated helper manifests.
- Harden diagnostic and CLI ergonomics: make global `--json` the canonical
  machine-output switch and emit exactly one success or failure document on
  stdout; retain hidden `--message-format=json` compatibility, classify exit
  codes, preserve error causes, assign stable `E2xxx` backend diagnostics with
  LSP `codeDescription` links, render Unicode source snippets by terminal
  width, unify VM/simulator run metrics, centralise core command rendering,
  and make MCP documentation reads UTF-8-safe.
- Add the bounded no-profile Fiber interoperability path. Metadata schema 55
  records the structurally derived `fungible-type-group-v1` entry; its ELF
  verifies exact 16-byte little-endian `u128` data, checked full-group
  conservation, legacy owner-lock or tagged policy-Type-authorised
  issuance/destruction, and unauthorised
  mint/burn rejection, while ignoring Fiber's xUDT-compatible witness prefix.
  The separate `cellscript-fiber-adapter` derives and materialises native Fiber
  configuration from compiler and live CKB evidence without a Fiber profile or
  a `fiber-lib` dependency. Bounded local-devnet runs passed Fiber's official
  multi-hop UDT payment and pending-TLC watchtower force-close collections.
  The clean, pinned full lifecycle/negative matrix remains pending, so this is
  not a production-readiness claim. Full external matrix validation requires
  content-addressed evidence files under an explicit confined root for every
  completed row and certified topology report; arbitrary non-empty evidence
  labels no longer qualify.
  Multi-asset packages may select one structurally eligible asset with
  `cellscript-fiber ... --asset <Type>`; omission remains valid only when the
  package contains exactly one candidate.
- Start the `nightly-0.22` language line with checked casts, canonical helper
  and capability registries, transitive callable effects, initial/terminal
  flow evidence, the six-tier ProofPlan taxonomy, and typed aggregate targets.
- Add typed read-only CKB transaction-view handles (`InputView<T>`,
  `OutputView<T>`, `CellDepView`, `HeaderDepView`, `WitnessArgsView`,
  `OutPoint`, and `ScriptView`). Their metadata records source, ownership,
  absence of lifecycle authority, checked-static typing evidence, and
  checked-runtime read evidence. Existing `source::*` functions remain the
  explicit low-level migration surface.
- Add finite invariant quantifiers: `forall <role> <binding> in
  <source_view<T>> { require ... }` and `count(<source_view<T>> where ...)`.
  They share the closed aggregate target model, reject unbounded and impure
  bodies, and emit ProofPlan scan complexity, field reads, cardinality/vacuous
  policy, `u64` count overflow policy, and runtime-helper-required evidence.
- Add source-aware bounded collection contracts: `input`-qualified
  `BoundedCellSet<CellType, N>` values are linearly discharged by
  `consume_each`, while `witness`-qualified fixed-width `BoundedList<Plan, N>`
  values may drive one `create` template per element through `create_each`.
  Metadata records source, ownership, maximum/runtime cardinality and vacuous
  status; ProofPlan keeps consume iteration at `runtime-helper-required` and
  output cardinality/capacity at `builder-evidence-required`. Generic
  `Vec<Resource>` remains rejected.
- Add the versioned capability algebra without inheritance syntax. The closed
  registry is shared by parsing, formatting, type checking, docgen, LSP, and
  metadata; `destroy` derives exactly `consume + burn`, while
  `replace_unique` requires `replace` plus the type's exact declared identity
  policy. Schema 51 records the registry, per-type capability-set version, and
  required/provided/entailed/missing proof fields, and rejects transitive
  authority from container-like resources.
- Add concrete fixed-width payload enums before generic ADTs. Payload variants
  now support constructor calls, exhaustive destructuring, packed one-byte-tag
  layouts, arm-local linear Cell ownership, RISC-V construction/projection, and
  an explicit pure-helper register-pair return ABI up to 16 bytes. Schema 52
  publishes canonical `enum_layouts`; dynamic, recursive, and generic payloads
  remain fail-closed/deferred.
- Add participant-role attribution to the derived ProtocolGraph without adding
  core session/channel syntax. Action metadata retains candidates from explicit
  Address equality predicates, witness or lock-args bindings, and weak
  participant-like Address field names in that precedence order. Graph edges
  publish the selected source, every candidate, deterministic conflict/missing
  lints, `metadata-only` evidence, and `authorization_proven = false`; roles are
  intentionally absent from ProofPlan. Schema 53 carries
  `actions[].protocol_role_candidates`.
- Add canonical type `validity` blocks. Pure field predicates lower to
  fail-closed checks before selected create/constructor instructions; paths
  without concrete lowering remain `runtime-helper-required`. The only
  approved environment read is `env::block_number()`, recorded as an explicit
  `builder-evidence-required` header-dep obligation because CKB-VM has no
  ambient tip-height syscall. Unknown `env::*`, transaction-view reads,
  lifecycle syntax, and non-Pure helper graphs are rejected. Type hover,
  metadata, ProofPlan, formatter, imported helper retention, and syntax-combo
  gates expose the same boundary.
- Add explicit `borrow root as view { ... }` regions for compile-time-only
  `View<T>` access to linear Cells. Views have no layout, storage,
  serialization, or ABI representation; escape, root lifecycle crossing, and
  calls outside `Pure`/`ReadOnly` helpers with dedicated `&T` parameters fail
  closed. Runtime metadata and ProofPlan expose the checked-static evidence.
- Advance compile metadata through schema version 55. The 0.22 schema sequence
  adds callable/flow/evidence fields, `runtime.transaction_view_handles`,
  bounded collection source/ownership/cardinality/vacuity/capacity evidence,
  type validity, borrow regions, capability proofs, enum layouts, protocol-role
  candidates, and the bounded Fiber compatibility contract.
- Publish the complete 0.22 release record, refresh the current wiki/roadmap and
  MCP documentation topics, document extension submodule initialization, and
  replace the unreachable VS Code gitlink with a validated 0.22 extension
  commit.

## 0.21.1 - 2026-07-11

- Close the 0.21 README documentation gap that the 0.21.0 changelog entry
  claimed but did not fully land:
  - Document the published-release install path
    (`scripts/install.sh` one-liner, including the `CELLSCRIPT_VERSION`
    pin) as the recommended way to install `cellc`; keep the source-tree
    `cargo install --path .` flow as the "tracks main" option.
  - Add `cellscript-mcp` to the README tooling-surface table so the 0.21
    agentic-loop surface is discoverable from the project front page.
  - Add `--message-format=json` and `--color=auto|always|never` to the
    README CLI options table, matching what `Tutorial-04` and the 0.21
    release notes already describe.
  - Add the 0.20 release notes, the 0.21 release notes, and the new
    `Tutorial-13: Agentic Loops and cellscript-mcp` link to the README
    docs list (the previous list stopped at 0.19).
  - Bump the wiki `Home.md` last-updated marker from `0.21.0-rc.1` to
    `0.21.0` so it matches the published tag.
- Bump the workspace crate versions (`cellscript`,
  `cellscript-ckb-adapter`, `cellscript-wasm`) from `0.21.0` to `0.21.1`
  so `cellc --version` reports the same value as the new release tag.
- No compiler, runtime, metadata, ABI, or CLI behaviour changes — the
  patch is documentation + version metadata only. The CKB target profile,
  the `--primitive-strict 0.16` / `0.17` gates, the xUDT aggregate
  invariant lowering, the flow edge validation, the CKB adapter
  resolution, the compile receipts, the `cellscript-mcp` server, and the
  CLI surface are byte-identical to 0.21.0.

## 0.21.0 - 2026-07-11

- Promote the common xUDT group amount aggregate invariant shape from
  metadata-only evidence into executable helper-backed lowering. Matching
  transfer-style actions now get an auto-lowered
  `__xudt_require_group_amount_conserved` prelude, ProofPlan records distinguish
  metadata-only, runtime-helper-required, and checked-runtime coverage, and
  strict `0.17` metadata validation rejects stale helper gaps that are not
  backed by generated runtime accesses.
- Add static flow edge membership validation. Actions that claim a state
  transition must use an edge declared by the corresponding `flow` block, while
  declared cyclic flows remain valid.
- Extend the CKB adapter with materialised action-plan resolution,
  action-aware scan selector evidence, variable-length `args_parts` script
  argument construction, manifest-backed CellDep completion, and fail-closed
  validation for missing or mismatched live-cell scan evidence.
- Bump compile metadata to schema version 44 and add type-level
  `template_layouts` plus action `state_transition_edges`. TemplateLayout
  records are metadata-only in this RC: they derive flat layouts, mark cyclic
  flows with `RootRequired`, and reject unsupported `consensus_checked = true`
  claims.
- Add compile receipts as authenticated metadata envelopes. `cellc receipt`,
  `cellc sign-receipt`, and `cellc verify-receipt` bind source, metadata,
  ProofPlan, ProtocolGraph, TemplateLayout, artifact hashes, and optional
  Ed25519 signatures; AST and IR normalised hashes remain explicitly deferred.
- Reorganise the CLI around canonical nested command groups for `explain`,
  `tx`, `deploy`, `registry`, `package`, and `auth capability` while keeping
  legacy flat aliases executable but hidden from public discovery.
- Add structured diagnostic transport through `--message-format=json`, explicit
  colour control through `--color=auto|always|never`, and `NO_COLOR` handling
  without changing successful `--json` payload semantics.
- Add the derived `ProtocolGraph` audit view and embed it in audit bundles. The
  graph remains a metadata-derived view, not a new IR or consensus source of
  truth.
- Add the in-repository read-only `cellscript-mcp` server and six CellScript
  programming skills. The dev and CI gates now run the skill-pack freshness
  check, and release modes inherit it through the embedded CI gate before
  release-only auxiliary checks.
- Reduce gate repetition: release auxiliary checks no longer repeat CI-level
  script, whitespace, and skill-pack checks; website builds avoid duplicate
  registry generation; the standalone website artifact workflow is manual-only.
- Document the 0.21 boundary across the roadmap, README, CKB adapter guide,
  metadata/gate tutorial, ProofPlan tutorial, and agentic tooling tutorial.
  P2 Template Merkleisation and new observation syntax remain deferred.
- Tighten the 0.21 RC validation boundary: add focused regression coverage for
  flow-edge membership, xUDT conserved lowering and ProofPlan coverage states,
  TemplateLayout cycle policy and `consensus_checked` rejection, CKB adapter
  `args_parts`/manifest CellDep/scan-selector evidence; add non-production
  `atomic_swap` and `multi_phase_dao` business-flow examples; extend the
  syntax-combo audit with flow, flow-create-state, and aggregate-invariant bug
  classes; add the 0.21 schema tokens to the acceptance-boundary audit; remove
  tautological registry tests and unreachable dead code in
  `scripts/cellscript_ckb_release_gate.sh`.

## 0.20.0 - 2026-06-28

- Bring `cellc` CLI discovery and direct-source diagnostics closer to Rust's
  developer experience: top-level help now shows package commands plus direct
  compile mode, `cellc --list` enumerates commands, unknown bare commands get
  nearest-command suggestions, and direct parse/lex/compile errors print
  `file:line:column` source snippets. The top-level `cellc --explain <CODE>`
  alias now mirrors the existing `cellc explain` command, and multi-diagnostic
  package checks render each frontend error with its own source context instead
  of collapsing them into one summary string.
- Fix numeric-width soundness by requiring exact non-literal numeric type
  equality while preserving declared integer literal widths through type
  checking and IR lowering.
- Reduce generated branch cost by skipping unconditional jumps to the physical
  fall-through block and by selecting `beqz`/`bnez` branch forms that keep the
  fall-through path implicit.
- Extend `cellc opt-report` and constraint artifact metadata with backend
  shape counters and estimated-cycle deltas across optimisation levels.
- Replace the incremental parallel compiler's identity ordering with a real
  dependency topological sort and cycle-safe fallback ordering.
- Close the registry source-package plan in docs and tooling: registry install,
  build, and update use the two-tier Git resolver with yanked-version skipping
  and `source_hash` verification, while `registry add` now prints next steps
  for the actual cloned discovery worktree.
- Harden the CKB/devnet acceptance path with an ELF entry ABI gate that checks
  RX-only executable segments, `filesz == memsz`, and entry trampoline
  stack-pointer preservation before local-node evidence is accepted.
- Require launch, token, and AMM bootstrap examples to carry passing ELF entry
  ABI evidence alongside existing builder-backed action, lock-spend, cycle,
  transaction-size, occupied-capacity, and stateful lifecycle checks.
- Add 0.20 release notes documenting the strengthened devnet acceptance
  boundary and the remaining difference between compile-only and live local
  devnet evidence.
- Promote multi-file package support into the 0.20 compiler/tooling boundary:
  exact-path imports, source-graph diagnostics, dependency-aware cache keys,
  package-aware LSP diagnostics, and an additive WASM multi-source metadata API.
- Mature cross-file helper reuse by inlining aliased imports, fully-qualified
  calls, same-basename dependency helpers, and transitive helper calls into the
  entry artifact with stable internal labels, while keeping ELF-linker and
  cross-script runtime-linking claims out of scope.
- Record the 0.20 evidence gate for protocol-source multi-file showcases:
  NovaSeal, iCKB, and DobEvo / DOB-EVO source refactors may demonstrate shared
  schema/type imports only when the matching devnet or CKB VM evidence is
  regenerated, and playground multi-file import/export remains browser-local.
- Add the first protocol-source multi-file candidate in NovaSeal
  fungible-xUDT by moving shared schema structs into
  `nova_fungible_xudt_schema.cell` and importing them from both profile and
  lifecycle entries. Metadata/artifact preparation records the shared schema
  source unit, and live local devnet stateful evidence passes issue, transfer,
  settle, and required negative cases for lifecycle data hash
  `0x394da78133cb2f5a5d6cd911feceeab9e97e6ad5d36c0e50f18be56653af85e5`.
- Add Tutorial 13 for agentic `cellc` loops, documenting the
  write-check-explain-fix workflow, `cellc-mcp` wrapper boundary, read-vs-write
  rule, and the distinction between compiler evidence and CKB chain evidence.

## 0.17.0 - 2026-05-04

- Add the research iCKB protocol-equivalence surface with partial CKB VM
  differential evidence, including 75 original-vs-CellScript executed rows,
  14 CellScript-only VM rows, 8 original-side VM rows, and an explicit
  `NOT_PROVEN` production-equivalence gate.
- Add 0.17 strict CKB protocol helpers for SourceView, DAO accumulated-rate
  and maturity checks, xUDT group amount helpers, script args/hash guards,
  MetaPoint/OutPoint relation scans, and C256 product requirements.
- Add executable iCKB benchmark specs and matrix evidence under
  `tests/benchmarks`, while keeping iCKB-specific receipt layout and fixture
  logic out of the generic compiler/runtime surface.
- Keep production equivalence deliberately unclaimed until owner-auth witness
  fixtures, byte-accurate receipt decoding, full DAO redeem accounting,
  generic aggregate lowering, and production manifest closure are complete.

## 0.16.1 - 2026-06-15

- Close the bundled token/AMM/launch bootstrap lifecycle gaps with explicit
  first-cell actions and strict original scoped CKB coverage.
- Rename the token authority mint action to `mint_with_authority` and the
  launch bootstrap action to `bootstrap_token` so builder-facing action names
  match the required input topology.
- Add `nft.cell::create_collection` and stateful coverage for the
  `create_collection -> mint -> create_listing -> buy_from_listing` path.
- Document and validate the CLI-first builder handoff through
  `--entry-action`, `cellc abi`, `cellc entry-witness`,
  `cellc explain-assumptions`, and `cellc validate-tx`.
- Re-run production local CKB acceptance with strict original scoped artifacts,
  complete bundled action coverage, and stateful lifecycle scenarios.

## 0.16.0 - 2026-06-14

- Add the scoped metadata-assurance release surface: operational semantics,
  ProofPlan soundness checks, builder-assumption metadata, transaction-shape
  validation, solver templates, deployment reports, proof diffs, profiling,
  transaction traces, and audit bundles.
- Ship NovaSeal as bundled proposal packages with local devnet/profile
  acceptance tooling, while keeping production claims blocked on external
  BIP340 TCB, public BTC SPV, public/shared CellDep, and profile-specific
  attestations.
- Tighten the NovaSeal public BTC SPV evidence contract so BTC-facing profile
  cases must bind current live CKB report hashes, service-builder hashes,
  CKB-side BTC commitment hashes, raw Bitcoin transaction material, block
  header and Merkle proof data, confirmation heights, and canonical SPV
  material hashes.
- Harden the 0.16 compiler-freeze gate with explicit IR poison rejection,
  instruction-level IR provenance, reserved-register contract checks, syscall
  ABI baseline coverage, and line-exact diagnostic regression directives.
- Align `cellc --help`, README command tables, and the VS Code active-file
  command surface with the 0.16 builder, transaction-template, deployment,
  profile, and audit-bundle tooling.
- Add `--primitive-strict=0.16`, which includes the 0.15 primitive vocabulary
  rules and rejects metadata-only/runtime-required ProofPlan gaps in strict
  assurance mode.
- Add descriptive standard CKB compatibility fixture manifests for sUDT, xUDT,
  ACP, Cheque, Omnilock, NervosDAO since/epoch behavior, Type ID,
  ScriptGroup, and `outputs_data` shapes.
- Add CKB stdlib protocol module schema stubs for sUDT, xUDT, TYPE_ID, HTLC,
  Cheque, ACP, and DAO-facing descriptors while keeping executable protocol
  lowering deferred.
- Carry the 0.15 proof/invariant scope forward without overstating it:
  aggregate invariant lowering, full ProofPlan soundness proofs, macro-only
  lowering, covenant stdlib helpers, strict address/script type separation,
  entry role syntax, versioned layout migration, and executable fixture
  matrices remain tracked for later releases.
- Merge the 0.15 strict syntax and example cleanup into the 0.16 assurance
  branch, including canonical `transition`/`where` action syntax, kernel-effect
  capabilities, stdlib lifecycle metadata, and VS Code packaging dry-runs.
- Keep the 0.16 documentation honest about scope: ProofPlan soundness and
  builder evidence are strict metadata-assurance gates, NovaSeal devnet
  certification is proposal-local evidence, and full production claims still
  require CKB dry-run/commit evidence plus required external attestations.

## 0.15.0 - 2026-05-26

- Add scoped invariant declarations with explicit trigger, scope, reads,
  coverage, and runtime-obligation metadata for CKB covenant auditing.
- Add Covenant ProofPlan records and `cellc explain-proof` so action, lock,
  invariant, aggregate, identity, and lifecycle obligations are inspectable in
  human-readable and JSON form.
- Add aggregate invariant primitives such as `assert_sum`,
  `assert_conserved`, `assert_delta`, `assert_distinct`, and
  `assert_singleton`; these currently emit metadata-only runtime obligations
  until executable aggregate verifier lowering is promoted.
- Promote cell identity policies and identity-aware lifecycle forms through
  `identity(...)`, `create_unique`, and `replace_unique`, including TYPE_ID,
  field, script-args, and singleton-type metadata.
- Add explicit destruction-policy forms and carry destruction policy through
  IR/codegen while keeping bare `destroy` available as the default policy.
- Reset resource capabilities from protocol verbs to 0.15 kernel effects such
  as `create`, `consume`, `replace`, `burn`, `relock`, `retarget_type`, and
  `read_ref`.
- Add `--primitive-compat 0.14` and `--primitive-strict 0.15` migration modes
  across direct `cellc` compilation and package commands, with CS0151-CS0160
  diagnostics for legacy `destroy` capability.
- Allow direct lifecycle operations to be authorized by kernel-effect
  equivalents: `destroy` accepts `consume + burn`.
- Convert canonical bundled examples, language examples, README examples, wiki
  tutorials, and release gates to strict 0.15 kernel-effect capabilities.
- Extend strict acceptance and syntax-combination gates so bundled examples
  compile directly under `--primitive-strict 0.15`, and update release
  documentation to keep 0.15 P0 scope separate from deferred 0.16 proof
  soundness and compatibility-suite work.

## 0.14.0 - 2026-05-09

- Add the CKB semantic-completeness surface for typed Source and WitnessArgs
  views, fixed-width `lock_args`, explicit `env::sighash_all(...)`, and
  profile-visible since, time, and epoch policy helpers.
- Add bounded Spawn/IPC verifier composition through `spawn`, `wait`, `pipe`,
  inherited file descriptors, and close/read/write helpers, with
  metadata-visible script references and type-checker rejection of static
  descriptor leaks, double closes, and use-after-close paths.
- Report a structured CKB target-profile ABI contract for witness data, lock
  args, Source encoding, Spawn/IPC, since/time, CellDep and script references,
  `outputs` / `outputs_data`, capacity floors, TYPE_ID, and CKB transaction
  version.
- Validate profile ABI metadata, runtime-access metadata, ScriptGroup evidence,
  TYPE_ID output plans, script references, and `outputs_data` bindings so
  release evidence fails closed when compiler policy and metadata drift apart.
- Expose declarative output capacity floors through
  `with_capacity_floor(...)` and `occupied_capacity(...)` while keeping builder
  funding, transaction-size, occupied-capacity, and acceptance evidence as
  explicit production responsibilities.
- Add executable fixed-Hash Blake2b support through CKB's
  `ckb-default-hash` personalization and metadata-visible `CKB_BLAKE2B`
  runtime access.
- Complete the state-edge spelling cleanup from legacy `move` to
  `transition`, and refresh examples, docs, formatter behavior, LSP
  completions, VS Code snippets, and syntax highlighting for the 0.14 surface.
- Add language examples for delegate verification, Spawn/IPC pipelines,
  witness/source views, TYPE_ID creation, capacity/time policy, and canonical
  style.
- Harden malformed input handling across metadata tampering, scheduler and CLI
  decoding, LSP incremental edits, static width calculations, entry-witness
  widths, and package-version parsing.
- Add the reusable 0.14 scope audit gate and document the release boundary:
  metadata/tamper validation and strict compilation now, with full
  accepted/rejected CKB transaction fixture matrices left to the later
  compatibility-suite track.

## 0.13.2 - 2026-05-03

- Complete syntax-governance layering for lifecycle semantics by keeping
  `claim`, `settle`, and `transfer` out of the executable core expression
  surface and implementing the corresponding stdlib patterns explicitly.
- Implement `std::cell::same_lock`, `std::cell::preserve_lock`, and
  `std::cell::preserve_capacity` through canonical cell metadata verifier
  checks.
- Make `std::lifecycle::transfer`, `std::receipt::claim`, and
  `std::lifecycle::settle` expand to consumed inputs, locked named outputs,
  and complete output field preservation.
- Harden preserve and require sugar so preserved fields are type-equivalent
  to their canonical require expansion and anonymous require blocks remain
  pure boolean verifier constraints.
- Remove the remaining compiler-level claim witness/signature special cases
  and reserve the old claim-signature runtime error code.
- Add example and editor-tooling coverage for the stdlib lifecycle and cell
  metadata helper surface.
- Add an executable syntax-combination audit runner for parser/formatter/type
  checking/lowering metadata/codegen oracles, wire the quick audit into local
  gates, and run the broader CI matrix in GitHub Actions and the full release
  gate.
- Make CI run on nightly branches and version tags, and add syntax-audit mode
  contracts so accidental coverage shrinkage fails closed.
- Sync the 0.13 roadmap/release scope with the 0.13.2 governance boundary and
  add a release-gate check that keeps those docs aligned.
- Pin VS Code extension packaging to `@vscode/vsce` and make local VSIX
  packaging dry-runs part of the release gate.
- Document the syntax-combination audit as a reusable release acceptance
  preflight that runs before builder-backed CKB acceptance.
- Finalize the 0.13.2 release notes under `docs/releases/`, add a docs map, and
  move historical 0.13 planning documents into `docs/archive/0.13/`.

## 0.13.0 - 2026-04-30

- Complete the internal RISC-V ELF assembler branch surface used by current
  codegen, including `beq`, `bne`, `blt`, `bge`, `bltu`, `bgeu`, `beqz`,
  `bnez`, and branch relaxation coverage.
- Harden the stack-backed `Vec<T>` helper boundary so unsupported receivers,
  invalid `extend_from_slice` element types, and unrefined `Vec::new()` slice
  extension cases fail at compile time instead of drifting into hidden runtime
  paths.
- Add `examples/language/collections/order_book.cell` as a non-production language example
  for local stack-backed order vectors.
- Add the CKB release-gate wrapper script and document the difference between
  quick compile-only evidence and full production acceptance.
- Add builder-backed local CKB valid-spend and invalid-spend acceptance coverage
  for all 16 bundled lock entries, in the same production gate as the 43 action
  flows.
- Fix lock predicate lowering so tail-expression lock results are preserved and
  `false` exits with a stable non-zero CKB script error.
- Complete the low-risk CellScript surface pass: canonicalize bundled example
  module names, capability declarations, field shorthand, typed `Vec<T>`
  literals, and the staged syntax RFC boundaries.
- Add create/struct field shorthand (`field` as `field: field`) and format
  redundant field initializers into shorthand form.
- Add contextual bounded `Vec<T>` literals for typed local bindings and
  create/struct field initializers, lowering to the existing stack collection
  constructor and push path without changing untyped array literal semantics.
- Add lock-boundary surface syntax for `protected` Cell parameters, `witness`
  data parameters, and `require` fail-closed predicates; reserve `lock_args`
  until explicit CKB script-args binding is implemented.
- Keep signer authority out of the 0.13 syntax surface: no implicit `Address`
  signer semantics, no hidden sighash defaults, and no first-class signer values
  before explicit CKB signature verification primitives.
- Split bundled examples into clean business examples and profiled acceptance
  examples, so scheduler/effect hints stay in release evidence without
  crowding the canonical teaching surface.
- Refresh LSP completions and the VS Code grammar/snippets for the new
  lock-boundary syntax.

## 0.12.0 - 2026-04-24

- Add a stable CellScript runtime error registry and expose code/name/hint
  entries through metadata and `cellc constraints`.
- Add CKB Blake2b builder/release helpers with pinned `ckb-default-hash`
  vectors through `cellc ckb-hash`.
- Add manifest-level CKB `hash_type` and `cell_deps`/DepGroup reporting, plus
  structured timelock and capacity evidence contracts.
- Add the standalone `tools/ckb-tx-measure` helper for CKB packed transaction
  size and occupied-capacity evidence, with CKB acceptance building the same
  source through a generated manifest for nested checkouts.
- Add `cellc abi`, `cellc scheduler-plan`, and `cellc opt-report` for entry
  witness inspection, scheduler-hint consumption, and optimization measurement.
- Use CKB Blake2b hashes for compiler metadata and release evidence.
- Expand entry witness tests to cover scalar, fixed-byte, `Vec<Address>`,
  `Vec<Hash>`, opaque nested `Vec<Vec<u8>>`, `Vec<u8>`, missing payload, and
  wrong-width payload cases.
- Add 0.12 production documentation for runtime errors, CKB authoring,
  deployment manifests, capacity, entry witnesses, collections, mutate,
  linear ownership, scheduler hints, migration, examples, and release evidence.
- Keep crates.io package contents narrow by excluding workflow, docs, editor,
  auxiliary tool directories, and unpublished helper binaries from the
  published crate.

## 0.11.0 - 2026-04-23

- Release CellScript 0.11.0 as the standalone CKB compiler package.
- Close the current CKB bundled-example production acceptance suite: all seven
  production examples strict-admit, all 43 actions and 16 locks strict-compile,
  and every bundled business action has an original-scoped on-chain production
  harness. Lock coverage is scoped compile coverage; `registry.cell` remains a
  compiler/tooling language example outside this production action matrix.
- Keep compatibility intact while documenting the remaining
  production hardening track around action builders, malformed matrices, and
  measured mass/cycle constraints.
- Preserve the production safety gates added in the 2026-04-23 development
  log: no CKB policy bypass, no unresolved-call ELF stubs, audit-only
  Wasm, tightened backend shape reporting, narrowed crates.io packaging, and
  explicit profile-aware constraints metadata.
- Promote the VS Code extension to production-grade local tooling with
  compiler-backed validation, formatting, scratch compilation, metadata and
  constraints reports, CKB target-profile arguments, status feedback, and stricter
  extension validation.

## 2026-04-23

- Marked Wasm output as audit-only instead of metadata-only production output.
- Removed the old ELF feature surface from runtime metadata.
- Reduced crates.io package contents by excluding GitHub workflow, wiki, and
  VS Code extension packaging files.
- Cleaned remaining clippy mechanical warnings and documented the intentional
  broad compiler-helper signature allowances so `cargo clippy --locked
  --all-targets -- -D warnings` is a release gate.
- Removed the remaining artifact-validation surface by returning a
  source-free `ValidatedArtifact` for metadata verification instead of building
  a synthetic AST.
- Kept scheduler witness metadata Molecule-only.
- Marked Wasm report output as audit-only and excluded standalone docs from the
  crates.io package contents.
- Stripped externally-linked RISC-V ELF artifacts when an external toolchain is
  available, matching the internal production artifact surface more closely.
- Made external RISC-V toolchains explicit opt-in via `CELLSCRIPT_RISCV_CC` or
  `CELLSCRIPT_RISCV_AS`/`CELLSCRIPT_RISCV_LD`, so production ELF output and
  backend shape budgets no longer depend on tools accidentally present in PATH.
- Hardened those external toolchain overrides to require absolute paths to
  existing executable files instead of accepting relative command names.
- Rebased the multisig bundled-example ELF budget on the deterministic internal
  ELF artifact size while keeping the assembly text/CFG budgets unchanged.
- Removed the executable Wasm pseudo-lowering path; the Wasm module now remains
  audit-only and rejects action/function modules instead of emitting approximate
  code.
- Removed empty module doc comments and simplified duplicated verifier branches
  reported by clippy.
- Kept lifecycle state storage explicit in cell data while allowing lifecycle
  state names in `create` initializers and qualified expressions such as
  `Ticket::Active`, avoiding hidden layout changes and numeric state
  boilerplate.
- Added LSP completions for qualified lifecycle states such as `Ticket::Active`.
- Clarified README CLI docs that `cellc test` is a compiler/policy harness, not
  trusted runtime execution.
- Removed the old CKB acceptance policy exception path so the CKB target
  profile now rejects unsupported CKB artifacts through the normal production policy
  gate.
- Removed unresolved-call ELF stub generation; production ELF emission now
  fails when a generated call target has not been lowered.
- Added executable cross-module callable linking for resolver-backed imports,
  so `launch.cell` links the real `seed_pool` callee and its transitive `isqrt`
  helper instead of relying on a synthetic fail-closed stub.
- Tightened launch example regression coverage to ensure imported callees are
  linked without pulling unrelated AMM actions into the artifact.
- Added `env::current_timepoint()` as a chain-neutral runtime time source:
  CKB lowers it to header epoch number.
- Switched bundled `vesting.cell` to the chain-neutral timepoint API, allowing
  original scoped `grant_vesting` artifacts under the CKB target profile.
- Added original scoped CKB on-chain acceptance for
  `vesting.cell::grant_vesting` with real Token/VestingConfig inputs,
  VestingGrant output verification, header dependency timepoint input, and
  malformed output rejection.
- Marked dynamic Molecule vector `len()` results as verifier-covered u64
  transition sources, so `collection.total_supply += recipients.len()` style
  CKB mutations are checked at runtime instead of reported as mutable-cell
  transition blockers.
- Fixed fixed-aggregate field byte-source lowering so original CKB verifier
  output lock checks can compare tuple-array address fields without fail-closed
  traps.
- Increased verifier expression temp slots and added regression coverage for
  the original launch bootstrap eight-recipient remaining-output sum.
- Switched CKB acceptance launch coverage from a standalone synthetic harness to
  the original scoped launch bootstrap artifact.
- Fixed dynamic Molecule table create-output checks for fixed/scalar fields so
  original `multisig.cell::create_wallet` verifies table fields through
  Molecule offsets instead of fixed-struct offsets.
- Switched the CKB multisig `create_wallet` acceptance harness to the original
  scoped artifact with dynamic `Vec<Address>` signer data.
- Preserved scalar verifier values across expected-expression evaluation and
  dynamic output decoding, fixing original `multisig.cell::propose_transfer`
  CKB checks for `Proposal.proposal_id` and `MultisigWallet.nonce`.
- Switched the CKB multisig `propose_transfer` acceptance harness to the
  original scoped artifact with dynamic `MultisigWallet` and `Proposal`
  Molecule table data.
- Switched CKB multisig `add_signature`, `propose_add_signer`,
  `propose_remove_signer`, and `propose_change_threshold` acceptance to
  original scoped artifacts with dynamic `Proposal` table/vector data.
- Switched CKB multisig `execute_proposal` and `cancel_proposal` acceptance to
  original scoped artifacts, removing the last standalone on-chain action
  harnesses from the bounded CKB matrix.
- Fixed destroy lowering to retain consumed input pointers for post-destroy
  output verification while relying on the checked Output absence scan for the
  actual destroy rule.
- Fixed scalar output verification to prefer schema/prelude expression sources
  but use runtime stack values for ordinary scalar variables, covering
  branch/match-derived bool outputs such as `ExecutionRecord.success`.
- Switched CKB token `mint`, `transfer_token`, `burn`, and `merge` acceptance
  from standalone harness sources to original scoped `token.cell` artifacts.
- Switched CKB NFT non-batch action acceptance from standalone harness sources
  to original scoped `nft.cell` artifacts, including dynamic `Collection`
  Molecule table data for `mint`.
- Switched CKB timelock `create_absolute_lock`, `create_relative_lock`,
  `lock_asset`, `request_release`, `request_emergency_release`, and
  `approve_emergency_release`, `execute_release`, `execute_emergency_release`,
  and `extend_lock` acceptance from standalone harness sources to original
  scoped `timelock.cell` artifacts.
- Fixed the CKB Molecule vector append verifier to compare fixvec payload
  bytes after the 4-byte count header, enabling original dynamic approval-list
  append checks.
- Switched CKB AMM pure-entry `isqrt` and `min` acceptance from standalone
  harness sources to original scoped `amm_pool.cell` artifacts.

## 2026-04-22

- Tightened backend CFG reachability analysis so unreachable-block metrics are rooted at the selected ELF entry label instead of treating every `.global` text symbol as reachable.
- Added a regression test proving unused global exports are still counted as unreachable from the entry root.
- Removed old `global_text_labels` parser storage after entry-root reachability replaced global-root reachability.
- Rebased bundled-example unreachable-block budgets on the stricter entry-root metric while keeping call-edge and CFG shape budgets enforced.
- Declared Rust 1.85.0 as the standalone crate MSRV so CI and users run with Cargo support for Edition 2024 dependencies.
- Updated standalone CI to archive backend-shape reports as release evidence.
- Added a committed standalone `Cargo.lock` and changed standalone CI to run with `--locked`.
