This page explains the CKB words that appear throughout the CellScript wiki.
Keep it nearby while reading the tutorials. The goal is not to replace the CKB
documentation; the goal is to make CellScript examples easier to read.

## Cell

A Cell is CKB's basic piece of state. A transaction consumes input Cells and
creates output Cells. CellScript tries to keep that movement visible with effects
such as `consume` and `create`.

In CellScript, a `resource`, `shared`, or `receipt` is a typed view over
Cell-backed state.

## Input Cell

An input Cell is a Cell being spent by the current transaction. When an action
consumes a resource, or when a lock protects a spend, you should think about the
input Cells involved.

In lock syntax, `protected T` means a typed view of one selected input Cell
guarded by the current lock invocation.

## Output Cell

An output Cell is a new Cell created by a transaction. In CellScript, `create`
materializes typed output data and attaches it to a lock:

```cellscript
create Token {
    amount,
    symbol
} with_lock(owner)
```

The output is not just a return value. It is new chain state.

## Lock Script

A lock script decides whether a Cell may be spent. CellScript `lock` entries
compile into spend-boundary predicates.

Use `require` inside locks for checks that should fail the current script
validation when false.

## Type Script

A type script checks state transition rules for Cells. CellScript `action`
entries are closer to type-script style transition logic: they describe the
inputs, invariants, and outputs of a state change.

Use `assert_invariant` inside actions for business-state transition checks.

## Witness

Witness data is user-supplied transaction data. It can carry signatures,
parameters, or other bytes, but the data itself is not automatically authority.

In CellScript, `witness T` means typed data decoded from the transaction witness
surface. A `witness Address` is still just data unless a lock verifies a real
signature binding.

## Script Args

Script args are bytes stored in the executing script. They are often used to
bind a script to a particular owner, policy, or configuration.

CellScript reserves the spelling `lock_args T` for typed script-args decoding.
That binding is intentionally fail-closed until the compiler and CKB profile
define it exactly.

## Lock Group

CKB groups script execution by matching script. A lock may run over a script
group rather than an isolated Cell.

When CellScript says `protected T`, read it narrowly: one selected input Cell in
the current script group, not every Cell of type `T` in the transaction.

## Capacity

Capacity is CKB's storage resource. Output Cells must have enough capacity for
their data and scripts. Compiler metadata can describe capacity requirements,
but release evidence still needs builder-backed occupied-capacity checks.

## CellDep

A CellDep is a referenced Cell dependency. It lets a transaction use code or
read-only data without consuming that Cell.

CellScript records read-only accesses and deployment metadata so builders and
reviewers can see which dependencies must be present.

## DepGroup

A DepGroup packages multiple CellDeps behind one dependency reference. Release
metadata reports DepGroup policy so deployment and builder workflows can audit
which dependencies are being used.

## Sighash

Sighash is the transaction digest scope used for signature verification. A
signature is only meaningful if you know what it signed.

CellScript does not hide sighash defaults. Future signature verification syntax
must expose digest mode, script group scope, witness layout, and replay
assumptions.
