# Tutorial 02: Language Basics

CellScript source reads best when you treat it as a small Cell story. First you
name the module. Then you describe the state that can exist on chain. Finally
you write the actions and locks that say how that state may change or be spent.

This chapter is a map. It does not cover every syntax detail, but it gives you
the vocabulary you need before reading the bundled examples.

## A Source File At A Glance

A typical `.cell` file contains:

- one `module` declaration;
- persistent declarations such as `resource`, `shared`, and `receipt`;
- optional ordinary `struct`, `enum`, and `const` declarations;
- optional top-level `invariant` declarations;
- executable `action` entries;
- executable `lock` entries.

The first split to learn is simple:

- ordinary data helps you calculate;
- persistent declarations describe Cell-backed state;
- actions change state;
- locks guard spending.

## Current Syntax Checklist

The current public surface keeps transaction shape visible. These are the
syntax forms you will see in the examples:

| Syntax | Use it for |
|---|---|
| `module cellscript::name` | Stable module identity. |
| `use cellscript::path::{A, B}` | Grouped imports from another module. |
| `resource T has store, create, consume, replace, burn, relock` | Linear Cell-backed assets with explicit kernel-effect capabilities. |
| `shared T has store` | Shared Cell-backed state such as pools or registries. |
| `receipt T` | Settlement-style proof Cells. |
| `receipt T -> Output` | Claimable receipt Cells with a declared claim output type. |
| `with_default_hash_type(Data1)` | Default CKB hash type metadata for a persistent declaration. |
| `flow Name for T.state { A -> B by action; }` | Named state graph for one explicit state field. |
| `flow T.state { A -> B; }` | Compact state graph when a separate flow name is unnecessary. |
| `action(old: T) -> new: T` | Core input-to-output verifier signature. |
| `-> (left: T, right: Receipt)` | Multiple named proposed output Cell bindings. |
| `input x: T` | Explicit consumed input Cell qualifier when the default action side is not enough. |
| `read cfg: T` | Read-only CellDep-backed action input. |
| `protected cell: T` | Lock-guarded input Cell view (lock parameters only). |
| `witness arg: T` | Decoded witness data. |
| `lock_args args: T` | Typed bytes from the executing lock script's `Script.args` (lock parameters only). |
| `transition old.state: A -> new.state: B` | Explicit field-to-field state edge. |
| `transition old -> new` | Same-type Cell continuation declaration. |
| `verification` | Action or lock proof section. |
| `create out = T { ... }` | Constraint on a named proposed output Cell. |
| `require condition, "message"` | Action or lock verifier guard with an optional message. |
| `let mut xs: Vec<Hash> = []` | Typed empty local `Vec<T>` literal. |
| `struct Pair<T: fixed + serializable + non_linear>` | Fixed-width non-Cell value template. |
| `fn identity<T: copy + drop>(value: T) -> T` | Value-generic helper with explicit constraints. |
| `Option::Some<u64>(value)` | Built-in generic optional value through the ordinary enum kernel. |

Names such as `old`, `new`, `input`, and `output` are ordinary bindings. The
semantics come from the action side, source qualifier, `transition`, `create`, and
`require` clauses. Do not use `&mut` on action-boundary Cell parameters; Cell
updates are expressed by naming the input and proposed output Cell.

## Module Declaration

Start with a stable module name:

```cellscript
module cellscript::demo
```

Bundled examples use the `cellscript::` namespace:

```cellscript
module cellscript::timelock
```

Module names are not decoration. They are part of source identity and appear in
metadata, so use names you are willing to keep stable.

CellScript does not have a Rust-style `mod` item. In packages, the module graph
is formed by discovering `.cell` files from `Cell.toml` `source_roots`, reading
each file's `module` declaration, and resolving explicit `use path::Symbol`
imports. A wrong import path is an error even if another loaded module happens
to define a symbol with the same basename.

The current production boundary supports cross-file type, schema, and helper
reuse end-to-end: resources, shared cells, receipts, structs, enums, constants,
and imported helper functions can be resolved from loaded modules for metadata
and artifact generation. Helper calls are compile-time reuse, not runtime
linkage: imported helper bodies are inlined into the single selected entry
artifact, including aliased imports, fully-qualified calls, same-basename
dependency helpers, and transitive helper calls.

There is still no ELF linker and no cross-script runtime linkage. Each CKB
script remains an independent artifact, so executable business logic must be
reachable from the selected entry.

## Scalar and Fixed Types

Common field and parameter types include:

```text
u8
u16
u32
i32
u64
u128
bool
Address
Hash
[u8; 8]
```

Use fixed-size byte arrays when a value must live in a predictable persistent
schema or CKB data layout.

### Expression-local Unsigned Widening

CellScript supports expression-local primitive unsigned integer widening for
arithmetic, bitwise operations, and numeric comparison:

```text
let total: u64 = amount_u64 + fee_u16
let under_limit: bool = fee_u16 < amount_u64
```

The chain is `u8 -> u16 -> u32 -> u64 -> u128`, but the widening is local to
the expression being evaluated. It does not cross assignment, return, ABI,
witness, `create` layout, struct field initialization, or serialization
boundaries.

Integer literals may be context-typed by an expected primitive integer type:

```text
let byte: u8 = 1
```

Decimal literals preserve every value through `u128::MAX`. A literal larger
than the target type is rejected at compile time instead of being truncated;
values above `u128::MAX` are rejected by the lexer.

Non-literal numeric values must keep their actual width at boundaries:

```text
let amount64: u64 = amount16        // rejected
let explicit: u64 = amount16 as u64 // accepted
```

Compound assignment is a write boundary. `target += rhs` is valid only when
`rhs` is the same width as, or narrower than, `target`. `u128` supports checked
add, subtract, multiply, divide, remainder, comparison, calls, parameters, and
returns.

### Bitwise and shift operators

The integer operators `&`, `|`, `^`, `<<`, and `>>` preserve the type and
width of the left value. Shift counts use `u8`, `u16`, `u32`, or `u64` (or
`usize`). A literal count must be smaller than the value width; a dynamic count
is checked in the generated Script and exits with stable runtime code 65
(`shift-amount-invalid`) when it is out of range.

```cellscript
let masked: u64 = flags & 255
let selected: u64 = (flags & mask) | fallback
let high: u128 = value << 64
let signed_quarter: i32 = signed_value >> 2
```

Right shift is logical for unsigned integers and arithmetic for `i32`.
Narrow-width left shifts truncate back to their declared width. Parenthesize a
bitwise expression before comparing it, for example
`(flags & required) == required`.

### Named Integer Boundaries

When an overflow guard needs the maximum `u64`, name it locally and keep the
relationship visible:

```cellscript
const U64_MAX: u64 = 18446744073709551615
const MAX_LOCK_PERIOD: u64 = 2628000

require current_height <= U64_MAX - MAX_LOCK_PERIOD,
    "lock range overflow"
```

Do not replace `U64_MAX - delta` with its precomputed decimal value. The named
expression documents the proof obligation and prevents top-level examples from
drifting away from their package `src/main.cell` mirrors. `u64::MAX` is not a
CellScript built-in in this release.

`Signature` is not a built-in scalar. If a contract needs to carry a signature,
model it explicitly:

```cellscript
struct Signature {
    signer: Address
    signature: [u8; 64]
}
```

That `signer` field is only data until a lock verifies it. Names do not create
authority.

For dynamic payloads that cross ABI or persistent schema boundaries, the
documented production surface includes targeted `Vec<u8>`, `Vec<Address>`,
`Vec<Hash>`, and concrete fixed-width struct-vector paths. Generic collection
ownership is intentionally narrower than "all collections are supported". Use
the collections support matrix before presenting a collection shape as
production-ready.

## Structs

Use `struct` for ordinary typed data that is not itself a persistent Cell:

```cellscript
struct Config {
    threshold: u64
}
```

A struct is a shape. It does not create on-chain storage by itself. A local
`Config` value is transaction-local unless you embed it in a `resource`,
`shared`, or `receipt`.

Struct literals and Cell `create` literals both support field shorthand when the
field name and local variable name match:

```text
let config = Config { threshold }

create token = Token {
    amount,
    symbol
}
```

The shorthand is exactly `field: field`; it does not infer or rename fields.

## Value Generics And Abilities

The 0.25 value kernel supports type parameters on ordinary structs, enums, and
pure functions. It specializes every used template before type checking and IR
lowering, so the backend sees only deterministic concrete types.

```cellscript
struct Pair<T: copy + drop + store + fixed + serializable + non_linear>
    has copy, drop, store, fixed, serializable, non_linear
{
    left: T
    right: T
}

fn first<T: copy + drop + fixed + serializable + non_linear>(pair: Pair<T>) -> T {
    return pair.left
}
```

Function type arguments may be explicit (`first<u64>(pair)`) or inferred from
typed arguments when there is one unambiguous substitution. Struct and enum
construction stays explicit so source review always shows the layout identity.

Value abilities are a separate vocabulary from Cell lifecycle capabilities:

- `copy` permits local duplication;
- `drop` permits a local value to be discarded;
- `store` permits inclusion in another ordinary value layout;
- `fixed` requires a deterministic fixed byte width;
- `serializable` requires a supported canonical encoding;
- `non_linear` states that the argument is not a Cell-backed linear value;
- `cell` is an explicit generic-function constraint for Cell-backed values; it
  does not grant `create`, `consume`, `replace`, or other lifecycle authority.

Ordinary generic structs and enums require non-phantom arguments to be fixed,
serializable, and non-linear. `Pair<Token>` is therefore rejected when `Token`
is a `resource`, `shared`, or `receipt`; use an explicit bounded Cell primitive
and its ownership rules instead.

A phantom parameter affects type identity without occupying serialized bytes:

```cellscript
struct Tagged<phantom Asset> has copy, drop, store, fixed, serializable, non_linear {
    value: u64
}
```

`Tagged<AssetA>` and `Tagged<AssetB>` are different monomorphizations with the
same one-field layout. A phantom parameter appearing in a field type is a
compile error. `cellc explain generics <INPUT>` lists canonical identities,
arguments, constraint status, and the separate bounded collection instances.

## Fixed-Width Payload Enums

Concrete, fixed-width payload variants were introduced on the 0.22 line and
remain supported by the current compiler:

```cellscript
enum Limit {
    None,
    Some(u64),
}

fn get_limit(enabled: bool) -> Limit {
    if enabled { Limit::Some(100) } else { Limit::None }
}
```

Destructure payloads with an exhaustive `match`:

```cellscript
match get_limit(enabled) {
    Limit::Some(value) => require amount <= value,
    Limit::None => require false, "missing limit",
}
```

The encoded form is a one-byte variant tag followed by the packed payload of
the selected variant, padded to the enum's maximum fixed width. Metadata under
`enum_layouts` records every tag, offset, width, ownership class, storage
boundary, and ABI. A pure helper may return an encoded enum of at most 16 bytes
through the `a0`/`a1` register pair.

Payloads using `Vec`, maps, another variable-width shape, or recursion are
rejected. Generic enum templates are supported when every materialized argument
uses the fixed-width non-Cell value kernel. `Option<T>` is built in through this
same enum path rather than a special runtime representation:

```cellscript
let optional: Option<u64> = Option::Some<u64>(42)
```

A concrete non-generic enum may still contain a Cell payload for tracked local
linear flows; bind it in the matching arm and explicitly consume, borrow,
preserve, or otherwise discharge it. Ordinary generic enum layouts never hide
Cell ownership, and `_` cannot discard a linear value.

### Complete fixed-value patterns

The 0.25 pattern kernel recursively checks and lowers tuple, struct, and enum
payload patterns. Binding-free or-patterns share one arm; exhaustiveness is
checked over the outer enum, and an irrefutable binding, struct/tuple pattern,
or `_` must be last:

```cellscript
match outer {
    Outer::Wrapped(Inner::Some((left, right))) => left + right,
    _ => 0,
}

match point {
    Point { x, y } => x + y,
}

match switch {
    Switch::On | Switch::Unknown => 1,
    Switch::Off => 0,
}
```

Struct patterns name every serialized field so that layout changes cannot be
silently ignored. Or-pattern alternatives are intentionally binding-free in
the 0.25 kernel; use separate arms when an alternative must expose payload
bindings. A wildcard at any level cannot discard a linear Cell-backed value.

## Typed Vec Literals

Use `[]` and `[x, y]` for local `Vec<T>` construction only where the expected
type is already known:

```text
let mut keys: Vec<Hash> = []
let mut owners: Vec<Address> = [primary_owner, backup_owner]

create proposal = Proposal {
    data: [],
    approvals: []
}
```

These literals lower to the same bounded, stack-backed `Vec<T>` helpers as
`Vec::new()` plus pushes. Untyped `[]` remains rejected, and cell-backed
collection ownership remains outside the supported production surface.

## Resources

Use `resource` for linear Cell-backed assets. If your protocol should not be
able to duplicate or silently drop a value, it probably belongs in a resource.

```cellscript
resource Token has store, create, consume, replace, burn, relock {
    amount: u64
    symbol: [u8; 8]
}
```

Resources are linear values. When an action receives one, the action must say
where it goes: consume it, validate a proposed output, return it, destroy it,
or use an explicit stdlib lifecycle pattern such as
`std::lifecycle::transfer`, `std::receipt::claim`, or
`std::lifecycle::settle`.

### Type Validity

Introduced on the 0.22 line and retained by the current compiler, a type can
state pure value predicates in a final
`validity` section:

```cellscript
resource TimeLock has store, create, consume {
    amount: u64
    locktime: u64
    owner: Address

    validity
        require amount > 0
        require owner != Address::zero()
        require locktime > env::block_number()
}
```

The fields are in scope, and a predicate may call only transitively Pure
helpers. Field-level `where` syntax, lifecycle operations, transaction-view
reads, and unknown `env::*` functions are rejected. Concrete create and local
constructor paths emit fail-closed field checks. A signature-only output or
update path records a `runtime-helper-required` gap instead of claiming that it
was checked.

`env::block_number()` is the one approved environment read. It is an explicit
`builder-evidence-required` header-dep contract, not a CKB-VM ambient-tip
syscall. Inspect `types[].validity_predicates` and the matching `type-validity`
ProofPlan entries before treating a path as enforced. LSP type hover displays
the same predicate, tier, and create/update status.

### Explicit Read-Only Borrow Regions

Use a lexical borrow block when several checks need to inspect one linear Cell
before its lifecycle operation:

```cellscript
#[effect(Pure)]
fn amount_is(token: &Token, expected: u64) -> bool {
    return token.amount == expected
}

action inspect(token: Token, expected: u64) -> u64 {
    verification
        borrow token as view {
            require amount_is(view, expected)
            require view.amount > 0
        }
        consume token
        return expected
}
```

`view` is a compiler-only `View<Token>` marker. It cannot be returned,
assigned, stored in an aggregate or collection, passed through an
untyped/generic slot, or used across `consume`, `destroy`, transfer, claim, or
settle of `token`. Calls that receive it must be `Pure` or `ReadOnly` functions
with an explicit `&Token` parameter. The block does not replace the
transaction's explicit consume/create lifecycle.

Borrow paths and read-only reborrows keep the same linear root:

```cellscript
borrow token.amount as amount_view {
    borrow amount_view as again {
        require *again > 0
    }
}
```

The metadata records the canonical root (`token`), the field path
(`amount`), and `View<u64>` for both regions. Dereferencing is allowed only
for non-Cell values; a Cell-backed value cannot be copied out through a view.
Destroying, consuming, or replacing `token` anywhere inside either region is
rejected. Generic Pure/ReadOnly helpers may receive a view only through an
explicit matching `&T` parameter and do not inherit Cell lifecycle authority.

Persistent declarations can also declare the default CKB script hash type used
for their type identity metadata:

```cellscript
#[type_id("cellscript::asset::Token:v1")]
resource Token has store
with_default_hash_type(Data1)
{
    amount: u64
    symbol: [u8; 8]
}
```

Supported spellings are `Data`, `Data1`, `Data2`, and `Type`. The lowercase CKB
forms are accepted too. Unknown hash types are compile errors, not deployment
warnings.

The current syntax inherits the 0.15 reset of `has ...` clauses from protocol
verbs to kernel effects.
New strict-mode declarations should use capabilities such as `create`,
`consume`, `replace`, `burn`, `relock`, `retarget_type`, and `read_ref`.
The older `transfer` and `destroy` capability words are accepted only through
the `--primitive-compat=0.14` migration path; `--primitive-strict=0.16`
includes the 0.15 kernel-effect checks and rejects them in type declarations.

The 0.22 capability algebra is deliberately closed and has no inheritance or
shortcut syntax. Composite lifecycle forms are checked against the exact
operand resource:

- `destroy token` requires `consume + burn`; the legacy `destroy` word is only
  a compatibility alternative and is exposed as such in metadata;
- `replace_unique<T>(...)` requires `replace` and an identity argument that
  exactly matches `T`'s declared non-`none` identity policy;
- a container's capability set never grants authority over a different inner
  or adjacent Cell resource.

Compiler errors report the required, provided, entailed, and missing authority
plus the capability-set and entailment versions. Successful composite checks
emit the same fields under `runtime.capability_proofs`.

## Identity Policies

A persistent declaration can name the identity policy that later lifecycle
forms must preserve:

```cellscript
resource NFT has store, create, replace
    identity(field(token_id))
{
    token_id: [u8; 32]
    owner: Address
}

resource ScriptBoundToken has store, create, replace
    identity(script_args)
{
    amount: u64
}

shared Config has store, replace
    identity(singleton_type)
{
    value: u64
}
```

Supported policies are `ckb_type_id`, `field(name)`, `script_args`, and
`singleton_type`. Omitting the declaration is the default `identity none`.
Fields used for `identity(field(...))` must be fixed-width schema fields.

## Shared State

Use `shared` for contention-sensitive state such as pools, launch state, or
registries:

```cellscript
shared Pool has store {
    token_reserve: u64
    ckb_reserve: u64
}
```

Shared state tells tools and schedulers that multiple transactions may care
about the same Cell-backed value. Reads and writes remain visible in metadata.

## Receipts

Use `receipt` for single-use proof Cells. A receipt is useful when one action
creates a right and another action later consumes that right.

```cellscript
receipt VestingGrant has store {
    beneficiary: Address
    amount: u64
    unlock_epoch: u64
}
```

`has store` is optional for receipts; ephemeral records such as execution logs
or settlement proofs may omit it. Use a claim output arrow when a receipt has a
direct claim output type:

```cellscript
receipt ClaimTicket -> Token {
    amount: u64
    beneficiary: Address
}
```

Receipts are a good fit for deposits, vesting grants, voting records,
settlement proofs, and claim flows.

## Actions

Use `action` for type-script style transition logic. The semantic core is a
verifier over proposed transaction Cells: Cell-backed parameters on the left are
input Cell evidence, named outputs on the right are proposed output Cell
evidence, and `require` states the guard conditions that must pass.

For flow transitions, prefer the input-to-output signature form. Given
an `Offer.state` graph such as `Live -> Filled`, the action names both Cell
views:

```cellscript
action fill_offer(input: Offer) -> output: Offer {
    transition input.state: Live -> output.state: Filled

    verification
        require input.price == output.price
        require input.seller == output.seller
}
```

The `transition` clause only proves the state edge. Authorization, preservation, and
conservation checks still belong in explicit `require` statements.

Consume/create-style actions remain valid as front-end sugar:

```cellscript
action transfer_token(token: Token, to: Address) -> next_token: Token {
    verification
        require token.amount > 0, "empty token"
        consume token

        create next_token = Token {
            amount: token.amount,
            symbol: token.symbol
        } with_lock(to)
}
```

Read this as a Cell transition: spend one token input, then validate a proposed
token output under a new lock. The verifier checks a proposed
transaction; it does not allocate Cells inside CKB-VM.

## Scoped Invariants

The current authoring surface includes top-level invariant declarations. They
are deliberately explicit about the verifier trigger, the protected scope, and
the CKB views they read:

```cellscript
invariant token_conservation {
    trigger: type_group
    scope: group
    reads: group_inputs<Token>.amount, group_outputs<Token>.amount

    assert_sum(group_outputs<Token>.amount) <= assert_sum(group_inputs<Token>.amount)
}
```

Supported triggers are `explicit_entry`, `lock_group`, and `type_group`.
Supported scopes are `selected_cells`, `group`, and `transaction`.
Aggregate primitives such as `assert_sum`, `assert_conserved`,
`assert_delta`, `assert_distinct`, and `assert_singleton` are recorded in
ProofPlan metadata; executable aggregate lowering is still a later milestone.

## Locks

Use `lock` for CKB spend-boundary predicates. A lock should make its data
sources obvious:

- `protected` marks the typed input Cell guarded by this lock invocation;
- `witness` marks decoded transaction witness data;
- `require` marks a verifier guard that fails the current script validation.

```cellscript
shared Wallet has store {
    owner: Address
    nonce: u64
}

lock owner_only(protected wallet: Wallet, witness claimed_owner: Address) -> bool {
    verification
        require wallet.owner == claimed_owner
}
```

Locks return `bool`. `protected Wallet` means a typed view of one selected input
Cell in the current script group whose spend is guarded by this lock
invocation. It is not an output Cell, not a transaction-wide scan, and not all
same-type Cells unless the language explicitly adds such multiplicity syntax.

`witness Address` means decoded transaction witness data only. Under Edition
2026 the entry wrapper obtains it from the `CSARGv1` payload inside
`WitnessArgs.input_type` on `GroupInput#0`, or `GroupOutput#0` for an
output-only script group. It does not mean an arbitrary raw witness, and it is
not a signer or ownership proof.

## Lock Boundary Primitives

The lock-boundary keywords are meant to expose CKB's transaction model instead
of hiding it behind account-style authorization language.

| Primitive | Meaning in CellScript | CKB-facing interpretation |
|---|---|---|
| `protected T` | Typed view of the Cell state guarded by this lock invocation. | One selected input Cell in the current script group, not an output Cell and not a transaction-wide scan. |
| `witness T` | Typed value decoded from transaction witness data. | A value decoded from the `CSARGv1` payload in canonical `WitnessArgs.input_type`. It is not a signer proof. |
| `require expr` / `require expr, "message"` | Action or lock verifier guard. | If `expr` is false, the current script validation fails. The optional string message is kept for source readability and tooling. |
| `lock_args T` | Typed fixed-width value decoded from the executing script args. | CKB `Script.args` data for this lock invocation. It is not a signer proof. |

Use `require` for verifier guards inside actions and locks. Public action and
lock code should not use `assert`; invariant assertions remain scoped to
top-level `invariant` declarations.

This lock checks equality between protected Cell state and witness data:

```cellscript
lock owner_only(protected wallet: Wallet, witness claimed_owner: Address) -> bool {
    verification
        require wallet.owner == claimed_owner
}
```

That comparison may be useful, but it does not prove that `claimed_owner` signed
the transaction. A misleading parameter name does not make it safer:

```cellscript
// Unsafe as an authorization claim: `signer` is only a witness value here.
lock misleading(protected wallet: Wallet, witness signer: Address) -> bool {
    verification
        require wallet.owner == signer
}
```

Real CKB authorization needs explicit binding to script args, transaction digest
scope, witness layout, and signature verification. Script args can now be named
explicitly, but signature verification is still deliberately not implicit:

```cellscript
lock owner_boundary(
    wallet: protected Wallet,
    owner: lock_args Address,
    claimed_owner: witness Address
) -> bool {
    verification
        let input = source::group_input(0)
        let witness_lock = witness::lock(input)
        let digest = env::sighash_all(input)
        require wallet.owner == owner
        require claimed_owner == owner
        require witness_lock == digest
}
```

`lock_args Address` tells the reader where the owner value comes from. It still
does not prove a signature. The example above is an inspectable deferred
boundary, not an executable ownership Lock: canonical `env::sighash_all`
construction is unimplemented. `DenyFailClosed` rejects it; audit artifacts
terminate with `66 sighash-all-unsupported` when it executes, even if its result
is discarded. `witness::lock(input)` is an executable witness-field read.
Treat `Address`,
`lock_args Address`, and `witness Address` as data unless an explicit verifier
result and key-to-authority binding prove otherwise.

For a custom verifier using a completely zero-filled first lock placeholder,
the separate bounded 0.30 API is
`env::sighash_all_zero_lock(max_group_inputs, max_inputs,
max_extra_witnesses, max_witness_bytes) -> SighashAllDigest`. It commits to the
exact transaction hash, later group witnesses, and witnesses after the input
count. It does not cover prefix-preserving multisig layouts. See the
[BIP340 verifier ABI](../CELLSCRIPT_SIGNATURE_VERIFIER_ABI.md) for the exact
order and limits.

These are two distinct witness uses. Entry parameters such as `claimed_owner`
come from `WitnessArgs.input_type`; `witness::lock(input)` explicitly reads the
`lock` field. Sharing one serialized `WitnessArgs` does not make the fields
interchangeable.

`lock_args Address` is already bound to the executing lock script's typed
`Script.args` bytes. That makes it a stable script-argument value, but it still
does not verify a transaction signature. CellScript 0.22 exposes the explicit
external-verifier boundary
`verifier::btc::bip340::require_signature_from_cell_dep(index, message_hash,
xonly_pubkey, signature)`. Its dependency index must be a literal in `0..=63`,
and new packages should first bind that resolved dependency with
`ckb::require_cell_data_hash`. The verifier checks the supplied prehash only;
the application still owns domain separation, ScriptGroup/WitnessArgs and
sighash construction, key binding, and replay policy. See the
[BIP340 verifier ABI](../CELLSCRIPT_SIGNATURE_VERIFIER_ABI.md).

CKB-facing finite helpers use compile-time bounds. For example,
`ckb::require_bounded_cell_dep_data_hash(max_deps, expected_hash)` requires a
literal `max_deps` in `1..=64`, while
`ckb::require_sha256d_merkle_root(leaf, siblings, depth, leaf_index, root)`
requires `[Hash; 16]` siblings and a literal depth in `0..=16`. These helpers
execute in CKB-VM; the latter is a Merkle primitive, not a complete Bitcoin SPV
implementation.

## Invariant Assertions

Use `assert_invariant(...)` only inside top-level `invariant` declarations.
Use `require` when the condition is a verifier guard on an action or lock
boundary.

## Comments

CellScript supports line comments and nested block comments:

```cellscript
// Explain Cell movement or security boundaries.

/*
   Block comments may contain nested /* inner */ comments.
*/
```

Use comments where they help the reader understand Cell movement, witness
scope, builder obligations, or a security boundary. Avoid comments that merely
repeat arithmetic.

The formatter is AST-based. It preserves action/function doc comments, but
ordinary line comments and block comments are not retained by `cellc fmt`.

## Next

With the source shape in mind, continue with
[Resources and Cell Effects](https://github.com/CellScript-Labs/CellScript/wiki/Tutorial-03-Resources-and-Cell-Effects). If a
CKB term is unclear, use the [CKB Glossary](https://github.com/CellScript-Labs/CellScript/wiki/CKB-Glossary).
