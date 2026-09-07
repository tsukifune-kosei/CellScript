# RFC: CellScript Surface Elegance And Canonical Syntax Pass

## Status

Superseded for action syntax by
[`CELLSCRIPT_GRAMMAR_GOVERNANCE_RFC.md`](CELLSCRIPT_GRAMMAR_GOVERNANCE_RFC.md).
Keep this RFC as historical design context only. The active surface uses
signature-direction action outputs, braced action/lock bodies with
`verification`, repeated action-level `transition` declarations, and prefix
source qualifiers.

0.13 low-risk surface pass implemented. Authority-sensitive binding remains
deferred.

Updated: 2026-04-27.

This RFC is intentionally split into low-risk canonical style work, syntax sugar,
and security-boundary syntax. The goal is to make bundled examples read like a
canonical CellScript language surface without overstating CKB authorization
guarantees.

## Goal

CellScript's core CKB Cell movement model is already clear: persistent state is
created, consumed, destroyed, transferred, claimed, settled, or read by
transaction-shaped entries. The remaining issue is surface discipline. Bundled
examples should teach how to write Cell protocols, not merely prove compiler
coverage.

For lock syntax specifically, the goal is boundary explicitness, not
authorization convenience. The redesign should be framed as making CKB's real
spend boundaries visible in the language surface:

- which typed input Cell is guarded by the current lock invocation;
- which values are decoded from transaction witness data;
- which values are decoded from the executing lock script's args;
- which checks merely compare decoded data;
- which checks are backed by cryptographic signature verification;
- which assumptions still belong to builders, wallets, or protocol review.

CellScript should not make the underlying CKB model disappear. A good language
layer gives developers better tools to see where the model's real boundaries
are.

## Design Principles

- Keep Cell movement visible.
- Prefer CellScript-native syntax over compiler-looking metadata.
- Do not hide CKB security boundaries.
- Separate business readability from acceptance stress coverage.
- Treat examples as canonical language references, not informal demonstrations.
- Names do not grant authority. Only verified bindings do.
- Authorization syntax should be explicit before it is ergonomic.
- Hidden sighash defaults are rejected; signature scope must be visible.

Security-facing syntax should be literal before it is elegant. In particular,
CellScript should keep classification syntax separate from authority semantics:

| Layer | Examples | Meaning |
|---|---|---|
| Classification syntax | `protected`, `witness`, `require` | Names the CKB input Cell view, transaction witness data source, and script failure condition. |
| Authority semantics | `lock_args`, explicit sighash verification, verified signer values | Proves that data is bound to script args, transaction digest, script group semantics, or a cryptographic signature. |

The first layer can improve honesty without expanding the trust model. The
second layer must not be introduced until the CKB profile defines the exact
binding and replay assumptions.

The public framing for this work should stay narrow:

```text
The next lock syntax work is not intended to hide CKB authorization. It is
intended to make the source and scope of lock data explicit: typed input Cell
state guarded by the current lock invocation, transaction witness data, script
args, and eventually verified signature-derived identities. The early form
deliberately avoids treating Address as a signer.
```

## 0.13 Progress Snapshot

The 2026-04-26 pass completed the parts of this RFC that do not change CKB
authorization semantics:

- namespace-style module declarations and DSL-native capability declarations in
  bundled examples;
- create/struct field shorthand where `field` is equivalent to `field: field`;
- contextual `Vec<T>` literals for typed local bindings and struct/create field
  initializers, including empty `[]` as the existing `Vec::new()` path when the
  expected `Vec<T>` type is known;
- the `protected`, `witness`, and `require` lock-boundary classification syntax;
- single-source bundled examples at top-level `examples/*.cell`, with
  acceptance-only metadata kept in runner configuration or generated evidence;
- LSP and VS Code grammar/snippet updates for the new syntax.

The security-sensitive boundary remains deliberately narrow:

- `lock_args` binds fixed-width lock parameters to bytes decoded from the
  executing lock script's `Script.args`; explicit sighash verification remains
  separate.
- `source::group_input` and `witness::lock` are executable building blocks.
  `env::sighash_all` has source syntax but canonical digest construction is
  deferred: production policy rejects it and audit artifacts exit with error
  `66 sighash-all-unsupported`. The language examples retain it only as an
  inspectable deferred boundary. High-level `verify_sighash_all(sig, owner)`
  composition is also unavailable.
- `env::sighash_all_zero_lock(group, inputs, extra, bytes)` is the separate
  executable 0.30 domain for a complete zero-filled first lock placeholder. It
  exposes all bounds and returns `SighashAllDigest`; prefix-preserving multisig
  layouts are outside that contract.
- First-class verified signer values are deferred.
- `protects T { self ... }` sugar is deferred until protected-input selection
  and lock-group aggregation semantics are exact.
- An `Address` value, including `witness Address`, is not a signer proof.
- Hidden sighash defaults remain rejected.

## Phase 1: Canonical Style

Phase 1 should not change execution semantics.

### Module Names

Bundled examples should use namespace-style module paths:

```cell
module cellscript::token
module cellscript::amm_pool
module cellscript::vesting
module cellscript::nft
module cellscript::multisig
module cellscript::timelock
module cellscript::launch
module cellscript::registry
```

This makes the examples look like one language ecosystem instead of unrelated
example contracts.

### Capabilities

Prefer DSL-native capability declarations:

```cell
resource NFT has store, create, consume, replace, burn, relock {
    token_id: u64
    owner: Address
}

shared Pool has store {
    reserve_a: u64
    reserve_b: u64
}

receipt Listing has store, create, consume, burn {
    token_id: u64
    seller: Address
}
```

Attributes remain useful for profiled metadata, but capabilities
are business-facing Cell semantics and should read as first-class language
syntax.

### Comments

Comments should explain Cell movement and security boundaries, not ordinary
arithmetic. A good comment explains consume/create output binding, lock/witness
scope, or builder obligations.

## Phase 2: Syntax Sugar

Phase 2 adds readability features with no semantic expansion.

### Field Shorthand

Support shorthand create fields:

```cell
create proposal = Proposal {
    proposal_id
    proposer
    target
    amount
    required_approvals: wallet.threshold
}
```

This should lower exactly like `field: field` today.

Status: implemented for `create` expressions and ordinary struct literals. The
formatter now canonicalizes redundant `field: field` initializers to `field`.

### Bounded Collection Literals

Support collection literals only where boundedness and element width are known:

```cell
let owners: Vec<Address> = []
let owners: Vec<Address> = [owner, backup_owner]

create group = Group {
    members: [owner, backup_owner],
    labels: [],
}
```

This must not reopen generic cell-backed collection support. Unsupported or
unbounded collection shapes should continue to fail closed.

Status: implemented for contextual `Vec<T>` literals in typed local bindings
and `create`/struct field initializers.

The implemented rule is deliberately narrow:

```text
[] is syntax sugar for an empty local Vec<T> only when the expected type is Vec<T>.
[x, y] is syntax sugar for local Vec<T> construction plus push only when the expected type is Vec<T>.
Untyped [] is rejected.
Untyped [x, y] keeps its existing fixed-array meaning.
[] is not a generic collection literal.
[] does not infer Set, Map, custom collections, or cell-backed collection semantics.
All existing stack Vec capacity, boundedness, and CKB profile checks remain in force.
```

Explicit prefix forms such as `Vec<Address, 8>[owner, signer]` remain deferred
until the type grammar has a first-class bounded-vector form.

## Phase 3: Lock Boundary Syntax

Phase 3 is security-sensitive and must not be treated as pure surface sugar.
It is a boundary-explicitness pass, not an authorization-syntax beautification
pass.

The current boundary-aware syntax makes the protected input Cell and witness
source visible without claiming cryptographic signer authority:

```cell
lock nft_ownership(
    protected nft: NFT,
    witness claimed_owner: Address
) {
    require claimed_owner == nft.owner
}
```

This Stage 1 form is classification-only:

- `protected NFT` is a typed view of one input Cell whose spend is guarded by
  the current lock invocation.
- In CKB grouped execution, `protected NFT` is scoped to the current script group
  input selection; it is not every `NFT` Cell in the transaction.
- `protected NFT` is not an output Cell, a transaction-wide scan, or global
  state.
- `protected NFT` does not imply ownership of the protected Cell.
- `witness Address` is typed data decoded from the transaction witness surface.
- `witness Address` is not a cryptographic signer.
- `witness Address` is not an ownership proof.
- `Address` is an identity-like value, not an authorization proof.
- `require` means a false condition fails the current script validation.
- `require` does not create authorization by itself.

CKB vocabulary mapping:

| CellScript term | CKB-facing interpretation |
|---|---|
| `protected T` | Typed view of one selected input Cell in the current script group whose spend is guarded by this lock invocation. |
| `witness T` | Typed data decoded from the transaction witness surface for the entry. |
| `lock_args T` | Typed fixed-width decoding of the executing script args; this is data-source binding, not signer authority. |
| `require condition` | Fail the current script if `condition` is false. |

Until first-class signer or lock-args binding exists, examples must not imply
that an `Address` witness parameter proves signature authorization by itself.

### Rejected Early Forms

Implicit signer syntax is rejected:

```cell
lock nft_ownership(
    protected nft: NFT,
    signer: Signer
) {
    require signer.address == nft.owner
}
```

This hides the question that matters: what transaction digest did the signature
commit to?

Plain `Address` signer naming is also rejected:

```cell
lock nft_ownership(
    protected nft: NFT,
    signer: Address
) {
    require signer == nft.owner
}
```

Here `signer` is only a variable name. It would read like authorization without
providing authorization.

Hidden sighash defaults are rejected:

```cell
lock nft_ownership(
    protected nft: NFT,
    signer: verified Signer
) {
    require signer.address == nft.owner
}
```

The safe shape is explicit:

```cell
lock owner_signed_token(
    protected token: Token,
    lock_args owner: Address,
    witness sig: Signature
) {
    require verify_sighash_all(sig, owner)
    require owner == token.owner
}
```

The eventual ergonomic form must keep the digest mode visible:

```cell
lock owner_signed_token(
    protected token: Token,
    signer: verified Signer<sighash_all>
) {
    require signer.address == token.owner
}
```

### Authority Staging

Authority syntax should advance in explicit stages.

Stage 1 is honest classification only:

```cell
lock nft_ownership(
    protected nft: NFT,
    witness claimed_owner: Address
) {
    require claimed_owner == nft.owner
}
```

Documentation must state that this only proves equality with witness data. It
does not prove cryptographic ownership.

Stage 2 introduces explicit lock-args binding:

```cell
lock owner_bound_token(
    protected token: Token,
    lock_args owner: Address,
    witness claimed_owner: Address
) {
    require claimed_owner == owner
    require owner == token.owner
}
```

This identifies the data source, but still does not verify a signature.

Stage 3 introduces explicit signature verification primitives:

```cell
lock owner_signed_token(
    protected token: Token,
    lock_args owner: Address,
    witness sig: Signature
) {
    require verify_sighash_all(sig, owner)
    require owner == token.owner
}
```

This is intentionally more explicit than a first-class `signer` abstraction. It
must specify the transaction digest mode, script group scope, witness layout,
and replay assumptions.

Stage 4 may introduce first-class verified signer values:

```cell
lock owner_signed_token(
    protected token: Token,
    signer: verified Signer<sighash_all>
) {
    require signer.address == token.owner
}
```

This stage is only acceptable after Stage 3 is mature. A value named `signer`
must be produced by verified cryptographic binding, not passed as ordinary
action or witness data.

## Example Layout

The checked-in organization is intentionally single-source for bundled
business examples:

```text
examples/
  token.cell
  amm_pool.cell
  launch.cell
  vesting.cell
  nft.cell
  multisig.cell
  timelock.cell
  registry.cell

examples/language/
  registry.cell
  order_book.cell
  ...
```

The top-level `examples/*.cell` files are the canonical bundled source used by
the production acceptance runner. `examples/business` and `examples/acceptance`
are no longer checked in; any acceptance-only metadata belongs in runner
configuration or generated files under `target/`, not in mirrored source copies.
`examples/language/*.cell` remains for language and tooling coverage outside
the seven-example CKB production matrix.

## Canonical Style Example

`examples/language/core/canonical_style.cell` demonstrates:

- namespace module declaration;
- resource, shared, and receipt declarations;
- create/consume/destroy flows;
- named action outputs plus `transition`/`require` constraints for state
  continuation semantics;
- `protected`, `lock_args`, `witness`, and `require` lock-boundary syntax;
- field shorthand;
- bounded collection literals;
- minimal comments.

It should be the idiomatic reference for documentation, generated examples, and
future regression tests.

This is a syntax/formatting fixture, not an ownership-authorization reference.
Its `env::sighash_all` call is the explicitly deferred signing-message boundary:
production policy rejects it and audit execution exits with error 66. The
public-owner equality does not authenticate a spender. Use real signed Lock
fixtures for authorization evidence; comments inside this canonical fixture
are not retained by the current formatter.

## Acceptance Criteria

- Bundled examples use namespace-style module declarations.
- Capability declarations use DSL-native `has` syntax where supported.
- Business examples remain readable and do not hide security boundaries.
- Acceptance/profiled examples retain production evidence where needed.
- Existing action acceptance remains green.
- Existing CKB strict compile coverage remains green.
- Existing lock valid-spend and invalid-spend matrix remains green.

## Implementation List

This list is the living implementation tracker for the RFC.

| Item | Status | Notes |
|---|---|---|
| Canonical namespace module names for bundled examples | Done | Bundled examples use `module cellscript::...`. |
| DSL-native capability declarations in bundled examples | Done | Examples use `resource/shared/receipt X has ...` as the canonical capability surface. |
| Short Cell movement comments at security or Cell movement boundaries | In progress | Comments should explain consume/create output binding, lock/witness scope, or builder obligations only. |
| `create` field shorthand | Done | `field` lowers as `field: field`; formatter canonicalizes redundant initializers. |
| Ordinary struct literal field shorthand | Done | Same shorthand rule as `create`. |
| Contextual bounded collection literals | Done | `[]` and `[x, y]` lower to existing stack `Vec<T>` construction only when the expected type is `Vec<T>`. Untyped `[]` remains rejected. |
| Explicit `Vec<T, N>[...]` literals | Deferred | Wait for a first-class bounded-vector type grammar instead of encoding bounds in ad hoc type strings. |
| `protected` lock parameter classification | Done | Parses as a read-only typed input Cell view and records `source: "protected"` metadata for the current lock invocation's guarded input. |
| `witness` parameter classification | Done | Records `source: "witness"` metadata; this is still transaction witness data, never signer authority. |
| `require` lock assertion form | Done | Lowers false conditions to the same fail-closed script validation failure path while producing `true` on success for bool-returning locks. |
| `lock_args` data-source binding | Implemented for fixed-width lock parameters | Entry wrapper decodes the executing Script.args bytes and rejects trailing bytes after declared typed parameters. |
| Source and witness building blocks (`source::group_input`, `witness::lock`) | Done | Executable source view construction and witness lock field loading. |
| Canonical `env::sighash_all` digest construction | Deferred | Syntax remains inspectable; `ckb-sighash-all-deferred` rejects production compilation and audit execution exits with runtime error 66. No digest is produced. |
| Bounded `env::sighash_all_zero_lock` domain | Implemented for all-zero lock placeholders | Current input Script group, exact witness order, complete first-lock zero replacement, `SighashAllDigest`, and four literal bounds are explicit and checked. |
| High-level `verify_sighash_all` composition | Not started | Must compose building blocks into a single check and define digest mode, script group scope, witness layout, and replay assumptions. |
| First-class verified signer abstraction | Deferred | Only after explicit verification primitives are proven and documented. |
| Hidden sighash defaults | Rejected | Digest mode and signature scope must be visible. |
| Implicit `Address` as signer | Rejected | Address values do not become authorization proofs by name. |
| Single-source bundled examples | Done | Top-level `examples/*.cell` is the canonical checked-in bundled business source. `examples/business` and `examples/acceptance` are intentionally absent; acceptance metadata is runner/generated evidence. `examples/language/*.cell` remains for language/tooling coverage. |
| `examples/language/core/canonical_style.cell` | Done | Provides a compact idiomatic reference for module style, capabilities, field shorthand, `[]`, `&mut` replacement, and lock-boundary classification. |
| Action production acceptance | Done | Existing bundled action acceptance remains builder-backed. |
| Lock valid-spend and invalid-spend matrix | Done | Existing bundled locks are exercised through builder-backed local CKB transactions. |

## Non-Goals

- This RFC does not replace the existing production action acceptance.
- This RFC does not replace the existing lock spend matrix.
- This RFC does not introduce account-model abstractions.
- This RFC does not claim that witness `Address` values are signer proofs.
- This RFC does not make CellScript look like Solidity, Move, or Rust.

## Summary

This RFC shifts CellScript examples from compiler coverage artifacts toward a
canonical language surface for external developers. The easy style wins should
land first; lock authorization syntax should land only when the CKB security
binding is explicit enough to audit.
