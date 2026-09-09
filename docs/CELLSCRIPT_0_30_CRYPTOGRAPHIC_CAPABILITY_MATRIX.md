# CellScript 0.30 Cryptographic and Authorization Capability Matrix

## Status and claim

**Status: candidate matrix for the frozen 0.30 business corpus.** The
machine-readable source is
[`tests/fixtures/cryptographic_capability_matrix.json`](../tests/fixtures/cryptographic_capability_matrix.json).
`check-business-corpus` validates its complete row and value-domain set, binds
all cited evidence into the corpus digest, and rejects release mode while its
release requirements or maximum-bound measurements remain incomplete.

The matrix covers the cryptographic and authorization operations actually used
by the eight-family corpus. It does not promise every algorithm available to a
Rust CKB Script. A capability is classified as either native executable
CellScript behavior, an exact checked identity, a standard Lock boundary, or a
typed trusted-external boundary. The last two classifications do not promote
the delegated implementation's internals into compiler proof.

## Value domains

| Domain | Source representation | Enforced distinction |
| --- | --- | --- |
| Address | `Address` | A fixed Lock-args payload. It is not a complete Script hash or signing digest. |
| Raw digest or identity | `Hash` | A 32-byte value with no implicit authority. |
| Complete Script | `Script` / `ScriptView` | Canonical code hash, hash type, and bounded args remain one value. |
| Complete Script hash | `ScriptHash` | Produced by a complete transaction Script view, `script::hash`, or explicit `ckb::script_hash` assertion. |
| Signing digest | `SighashAllDigest` | Produced only by the named bounded zero-Lock transform; conversion to `Hash` is explicit. |
| Bounded witness bytes | `WitnessBytesView<owner,max>` | Owner and literal maximum are retained in typing and runtime provenance. |
| Commitment root | `Hash` in a declared commitment position | Algorithm, preimage shape, opening, and equality site provide the checked domain. |
| Authenticated opening | Fixed leaf/siblings/index under the declared witness owner | Depth, index, root, and successor relation are checked together. |
| BIP340 key encoding | `[u8; 32]` in the exact adapter position | Width, argument position, verifier identity, and IPC encoding are fixed by the adapter. |
| BIP340 signature encoding | `[u8; 64]` in the exact adapter position | Width, argument position, verifier identity, and IPC encoding are fixed by the adapter. |
| Exact Script handle | `ExactScriptHandle` | Package, interface, artifact, deployment, network, role, selected Script, and verifier identity are bound. |
| Verification result | Terminal success or checked zero child status | No reusable authority-bearing byte value is returned. |

`Address`, `Hash`, `ScriptHash`, and `SighashAllDigest` cannot substitute for
one another through ordinary assignment or parameter passing. BIP340 public
keys and signatures remain fixed encodings at the exact external adapter
boundary; curve and signature validity belong to the pinned verifier rather
than to the CellScript type checker.

## Admitted portfolio capabilities

| Capability | Classification | Exact admitted shape | Primary evidence |
| --- | --- | --- | --- |
| CKB Blake2b-256 | Native | Fixed values, bounded Cell/witness spans, selected gathers, and bounded witness-owner streams | `tests/crypto_primitives.rs`, `tests/typed_runtime_views.rs`, checker mutations |
| SHA-256 and SHA256d | Native | One 32-byte value or one 64-byte pair | `tests/crypto_primitives.rs`, checker mutations |
| SHA256d Merkle opening | Native | Literal depth `0..=16`, `[Hash; 16]` siblings, checked index and expected root | CKB-VM root/mutation cases and schema-successor evidence |
| Canonical Script hashing | Native | Molecule Script with one of the four CKB hash types and fixed args up to 459 bytes | `tests/script_hash.rs`, authoring substitution cases, checker mutations |
| Raw transaction hash | Native | Exact 32-byte `LOAD_TX_HASH` result | typed runtime-view CKB-VM and checker mutations |
| Zero-Lock SighashAll | Native | Four literal bounds; complete first group Lock payload zeroed; later group and extra witnesses ordered canonically | differential CKB-VM comparison with pinned `ckb-sdk-rust` |
| Standard multisig Lock | Exact standard Lock | Standard Lock owns `WitnessArgs.lock`; CellScript owns `WitnessArgs.input_type` | signed multisig-v2 and persistent policy lifecycle tests |
| BIP340 verifier | Trusted external | Exact 32-byte message, 32-byte key, 64-byte signature, pinned adapter and verifier dependency | trusted-external and exact-handle tests plus the versioned ABI |
| Exact Script handle | Checked identity | Fixed receipt/value encoding checked against the selected Lock, Type, or verifier CellDep | CKB-VM substitution matrix and standalone checker mutations |
| General trusted delegation | Trusted external | Fixed `u8`/`hex4` EXEC or bounded SPAWN/WAIT adapters with exact data hash and zero-success contract | positive and wrong dependency/hash/adapter/status tests |

The complete API names, algorithms, bounds, stable failure codes, witness
owners, business-family mapping, evidence files, and proof boundaries live in
the JSON matrix. The gate requires every one of the ten rows and twelve value
domains exactly once; removing or renaming one fails before the corpus digest
is considered.

## Authorization boundaries

The native `env::sighash_all_zero_lock` operation covers Locks whose complete
placeholder is zeroed. Multisig layouts that preserve a configuration prefix
use the pinned standard Lock integration instead of silently reusing that
transform. The generic `env::sighash_all` spelling remains fail-closed.

`verifier::btc::bip340::*` and generic `trusted_*` calls bind the selected
CellDep, data hash, adapter, statement placement, argument encoding, and result
handling. Successful delegation does not establish that the compiler checked
the external parser or cryptographic implementation.

Commitment support proves the declared bounded opening and successor
correspondence. It does not attach protocol meaning to arbitrary committed
bytes. The shared entry-witness owner remains the same `WitnessArgs.input_type`
envelope used for action arguments and bounded output plans.

## Candidate and release boundary

Parser/type/IR, metadata, lowering, CKB-VM, generated-builder, standard Lock,
external-adapter, and standalone-checker evidence is present for the admitted
rows. The eight-family business corpus and its four-artifact composition anchor
exercise those operations through the product path.

The JSON matrix intentionally marks maximum-bound per-capability measurements
as `release-candidate-required`. Existing tests record representative cycles
and portfolio-level budgets, but issue #25 requires a final exact-candidate
resource record before these rows can be accepted for release. The matrix also
keeps the applicable release gate, selected-network deployment, and independent
review explicit and incomplete.

## Deferred surfaces

- generic signing-message construction without a named witness transform;
- an in-language multisig prefix-preserving signing transform;
- unbounded or allocator-backed hashing;
- arbitrary signature algorithms or dynamic cryptographic libraries;
- address-string decoding and network-prefix interpretation in CKB-VM; and
- compiler claims over any external verifier's internal implementation.

These exclusions preserve the target claim: broad application-level coverage
for the frozen bounded portfolio, without claiming unrestricted Rust-level
implementation freedom.
