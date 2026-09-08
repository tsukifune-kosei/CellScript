# CellScript Deployment-Line Handles

Status: off-chain receipt/fixed-value foundation and the distinct
`ckb-type-hash` generated-artifact profile are implemented on the `0.30`
development branch. Standard Type ID admission evidence, admission-state
transitions, ProtocolBundle binding, and CKB-adapter live dependency resolution
are also implemented. Source/runtime helpers, consensus execution cases, and
compatible open roles remain release blockers.

## Security boundary

A CKB Script whose `hash_type` is `type` can keep the same Script identity while
the referenced code Cell data changes. This supports upgrades, but the Type
Script hash proves only which code-cell line was selected. It does not prove
that new bytes passed CellScript's independent artifact checker, preserve an
interface, remain active, or were authorized by the expected upgrade policy.

The deployment-line contract therefore keeps four identities separate:

1. the stable Type-hash CKB Script;
2. the exact checked receipt and exact handle for the selected code version;
3. a six-dimensional interface compatibility report against both the baseline
   and immediate predecessor; and
4. a unique live admission Cell whose Type Script authorizes replacement and
   whose data commits the complete current line handle.

Data-hash deployments cannot be promoted into a deployment line. Their Script
identity changes with the code bytes and continues to use
`ExactScriptHandle`.

## Receipt chain

`cellscript-deployment-line-receipt-v1` records:

- a canonical package compatibility line (`name@major`, or `name@0.minor`);
- a stable line ID, role, selected entry, network, complete Script, baseline
  interface, policy, and admission Cell Type Script hash;
- a monotonic sequence and exact predecessor receipt hash;
- `active` or `yanked` availability;
- the current exact artifact receipt and full exact-handle hash; and
- derived `cellscript-interface-compatibility-v1` reports from the immediate
  predecessor and baseline to the current interface.

The fixed v1 policy requires all six current compatibility dimensions to be
non-breaking, preserves the complete Script, target profile, and runtime ABI,
and requires a separate unique admission-Cell replacement authority. An
upgrade must increase SemVer inside the same compatibility line. A yank is a
new hash-linked receipt that retains the same selected version and changes only
availability. A yanked receipt cannot authorize a later active version under
this policy version.

The constructors derive compatibility reports from the supplied canonical
`PackageInterface` values. They reject a copied or mismatched interface hash,
same-version replay, a broken predecessor link, a changed Script or role,
profile/ABI changes, and any breaking compatibility dimension.

## Fixed handle encoding

`cellscript-deployment-line-handle-value-v1` uses
`CSLINv1-fixed-386`:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | `CSLINv1\0` magic |
| 8 | 1 | Script/verifier class |
| 9 | 1 | Lock/Type/spawned-verifier role |
| 10 | 1 | active/yanked status |
| 11 | 5 | reserved zero bytes |
| 16 | 8 | little-endian sequence |
| 24 | 32 | line ID |
| 56 | 32 | compatibility/authorization policy hash |
| 88 | 32 | current line receipt hash |
| 120 | 32 | predecessor receipt hash, or zero for sequence 0 |
| 152 | 32 | unique admission Cell Type Script hash |
| 184 | 202 | complete current `CSHDLv1` exact handle |

`deployment_line_handle_value_hash` computes CKB Blake2b-256 over all 386
bytes. `deployment_line_commitment_data` produces the existing Registry
commitment shape, `CSREGv1 || handle_hash`, so an admission Cell can commit the
entire line value without treating the off-chain Registry as consensus.

## Implemented API

- `begin_deployment_line` creates sequence 0 from one checked Type-hash exact
  receipt and its canonical interface.
- `advance_deployment_line` derives both compatibility reports, checks the
  exact predecessor and stable line fields, and selects a new exact version.
- `yank_deployment_line` creates a terminal unavailable successor without
  changing the selected exact version.
- `validate_deployment_line_receipt`,
  `validate_deployment_line_successor`, and
  `validate_deployment_line_handle` independently recheck structural and hash
  bindings.
- `validate_deployment_line_admission_evidence` binds the active receipt to a
  distinct standard TYPE_ID admission Cell and TYPE_ID code Cell, verifies the
  exact admission data and checked ELF data hashes, and requires both direct
  CellDeps at their declared transaction positions.
- `validate_deployment_line_admission_transition` recomputes initial TYPE_ID
  args from the first serialized `CellInput` and output index. For upgrades and
  yanks it requires exactly one matching TYPE_ID input and output, exact
  predecessor data, and the checked receipt successor.

`ckb-type-hash` artifacts in `cellscript-protocol-bundle-input-v1` must carry
exactly one `cellscript-deployment-line-admission-evidence-v1` record. The
offline checker rejects missing, duplicate, predecessor/data-stale, yanked,
incompatible, wrong-code, wrong-Type-ID, and wrong-CellDep-position evidence.
The generated TypeScript builder contract exports both admission schemas and marks
`ckb-type-hash` packages as requiring this binding.

## Remaining runtime closure

The default `ckb` profile remains exact-data deployment and permits only
`data2`. The separate `ckb-type-hash` profile now emits the same CKB VM2/Zbb
artifact ABI while permitting only `type`, and the standalone checker binds
that choice to the artifact evidence. Admission and code state use separate
standard TYPE_ID lineages. Their input Locks authorize replacement; the
receipt's compatibility reports independently decide whether the next code
version may enter the line. The transition validator enforces the unique
one-input/one-output admission group shape without making Lock authorization a
compatibility claim.

The Rust validator checks the contents returned by a resolver. The CKB adapter
now obtains every admission/code out point with data from the selected node,
requires live status on the receipt's exact chain, and independently compares
the returned Lock, TYPE_ID Script, data hash, out point, and transaction
position. `ReadyToSignProtocolBundleTx` is unreachable unless all ordinary and
deployment-line dependencies pass together.

No source type or on-chain helper consumes `DeploymentLineHandle` yet. The
next phase must add those runtime checks, standalone-checker mutations, and
real CKB-VM stale/yank/substitution cases. Compatible open handles remain a
later phase and cannot infer behavioral equivalence from interface
compatibility.
