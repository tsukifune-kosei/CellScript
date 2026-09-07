# Trusted External Verifiers

**Status:** bounded experimental implementation on `0.26b`.

CellScript can delegate to an existing CKB verifier through `EXEC` or
`SPAWN`/`WAIT` without claiming that the compiler has proved the delegated
program. The supported boundary is deliberately narrower than a general
"trust this program" escape hatch:

1. the source uses a `trusted_*` intrinsic and pins a compile-time 32-byte
   Cell data hash;
2. `Cell.toml` contains one exact, versioned declaration for that source scope,
   operation, and hash;
3. generated code loads the selected CellDep's `DATA_HASH` and rejects a
   mismatch before delegation;
4. typed semantics and ProofPlan classify the result as `trusted-external`,
   not `checked-static` or `checked-runtime`; and
5. the independent artifact checker requires the source-load, hash-check, and
   delegation operations to be one ordered sequence bound to the same CellDep
   operand, then binds that sequence to the declaration and machine evidence.

Unlisted external calls remain fail-closed under `DenyFailClosed`. A declaration
cannot make a raw `exec_*` or `spawn_*` call trusted, and trusted and raw
delegation cannot be mixed in the same scope.

## Source surface

The bounded source intrinsics are:

```cellscript
ckb::trusted_exec_cell_dep_u8_args(
    dep,
    code_hash,
    argc,
    arg0,
    arg1,
    arg2,
    arg3
)

ckb::trusted_exec_cell_dep_hex4(
    dep,
    code_hash,
    bytes,
    len0,
    len1,
    len2,
    len3
)

ckb::trusted_spawn_wait_cell_dep_hex4(
    dep,
    code_hash,
    bytes,
    len0,
    len1,
    len2,
    len3
)
```

`code_hash` must be a compile-time `Hash` literal. `dep` selects a transaction
CellDep. The generated verifier resolves that exact CellDep, loads its complete
data hash, compares all 32 bytes with `code_hash`, and only then invokes the
bounded argument adapter. The four lengths partition the local byte vector into
at most four hexadecimal arguments. The non-hex form passes up to four bounded
single-byte arguments.

Successful `EXEC` replaces the current VM process and therefore does not return.
Statements written after a successful EXEC call are unreachable and must never
be cited as acceptance evidence; only the external verifier decides that success
path. They can still run after a failed syscall, where the generated adapter
fails closed before returning control to ordinary source code.
The `SPAWN` form waits for the child and accepts only a zero child exit status.
Argument construction, child memory, syscall errors, and non-zero child status
all fail closed through the ordinary runtime-error contract.

## Manifest declaration

Each trusted call needs one matching declaration:

```toml
[[deploy.ckb.trusted_external_verifiers]]
schema = "cellscript-trusted-external-verifier-v1"
name = "audited-agent-v1"
scope = "action:verify"
operation = "exec"
adapter = "hex4-v1"
code_hash = "cf79590446a6a526fe7ee2e64a0c5f216ae6755f79fb966fd03cd0e718157f69"
hash_type = "data"
source_identity = "upstream project, release/commit, and deployed identity"
applicability = "the exact message and argument contract used by action:verify"
trust_basis = "reproducible bytes plus an identified audit or deployment record"
guarantees = [
  "accepts exactly the delegated protocol message",
  "returns non-zero for malformed authorization",
]
```

Valid scopes are the emitted semantic entry identities: `action:<name>`,
`lock:<name>`, and `helper:<name>`. `operation` is `exec` or `spawn-wait`.
The adapter is also exact: EXEC accepts `u8-args-v1` or `hex4-v1`, while
SPAWN/WAIT accepts `hex4-v1`. This prevents a declaration reviewed for one
argument ABI from authorizing another.
Version 1 accepts only `hash_type = "data"`: the runtime contract is the exact
CKB `DATA_HASH` of the selected CellDep, not a Type ID, Script hash, source-file
hash, package name, or deployment label. Hash text is exactly 64 lowercase hex
digits without a `0x` prefix.

All descriptive fields and between one and 64 guarantees are mandatory; each
text field is bounded to 4,096 UTF-8 bytes. A package may declare at most 1,024
trusted verifier bindings and retain at most 1,024 matching call sites. They are
recorded audit claims. The compiler validates their presence and exact binding,
but it does not independently establish the truth of prose such as “audited” or
“deployed for N blocks.” Authors and reviewers remain responsible for that
evidence.

Declarations are exact and closed:

- a source call without a matching declaration is `E2113`;
- an unused declaration is `E2113`;
- duplicate `(scope, operation, adapter, code_hash)` bindings or duplicate names are
  `E2113`;
- unknown declaration fields, non-canonical hashes, unsupported operations,
  or empty evidence fields are rejected; and
- raw external delegation remains `E2105` under `DenyFailClosed`.

## Evidence and checker boundary

The trusted-external record was introduced in metadata schema 66 and remains
unchanged in current schema 70. `cellscript-typed-semantics-v8` carries the canonical
trusted-verifier record in runtime metadata, CKB constraints, typed semantics,
and the verified lowering bundle. The copies must agree exactly. Its fixed
fields include:

```text
identity_binding = runtime-load-cell-data-hash-before-delegation-v1
evidence_tier = trusted-external
compiler_proves_internal_semantics = false
```

The independent checker rejects an artifact if the record is removed, its hash
or evidence tier changes, the matching ProofPlan is absent, the target hash is
not a typed constant, or the load/hash/delegate sequence no longer uses the
same CellDep operand. Existing typed-to-machine checks then bind that typed
sequence to the ELF.

`trusted-external` means only:

- the selected external bytes have the declared CKB data hash;
- the supported EXEC or SPAWN/WAIT adapter is actually invoked; and
- for SPAWN/WAIT, the child must report success.

It does **not** mean that CellScript proved the external program's authorization
logic, parser, cryptography, state transition, audit history, deployment
longevity, or suitability for any use outside the declaration's applicability.

## Relationship to the adopted authoring target and issues

This is the bounded implementation of the direction reserved by authoring
contracts A2 and A4: an external mechanism may supply a guarantee only when its
exact identity, applicability, and required guarantee are explicit and actually
enforced. It also addresses the authenticated-external portion of the #10/#11
issue reconciliation without treating an ordinary source type, audit label, or
owner value as foreign authority.

The trusted-external implementation intentionally does not close the broader
Script identity API item. Version 1 binds CellDep `DATA_HASH`; it does not parse
an address, construct a Lock Script, validate a Type ID, or authenticate a
caller.

The 0.30 authoring work separately introduces a bounded `ScriptHash` source
domain for typed transaction-view fields and `lock = exact_hash(...)`, plus
`ckb::script_hash(Hash)` as an explicit conversion for already trusted complete
hashes. That conversion does not inherit the trusted-external declaration's
identity or guarantee claims and does not prove Script existence, deployment,
or authorization. Edition 2026 parsing and contextual identifier behavior are
unchanged.

## Deployment and review checklist

Before treating a trusted declaration as release evidence:

1. reproduce or independently obtain the exact delegated bytes;
2. compute their CKB data hash and compare it with both source and manifest;
3. identify the upstream version, deployment, audit, and argument ABI;
4. test positive and adversarial transactions against the actual bytes in
   CKB-VM;
5. retain a substitution negative proving that a different CellDep fails before
   delegation; and
6. run the independent artifact checker and the matching release gate.

This mechanism makes an external verifier dependency explicit and enforceable.
It does not convert third-party code into compiler-proved CellScript semantics.
