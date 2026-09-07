# CellScript 0.26b Business End-to-End Regression Report

Date: 2026-09-07

## Verdict

No regression was observed in the business and interoperability surfaces
executed by this campaign. The evidence covers every production CKB action and
Lock in the acceptance inventory, all committed iCKB differential rows, the
full CKB ecosystem-reuse gate, and three selected live Fiber workflows using an
exact CellScript fungible artifact.

This is strong finite evidence, not a universal proof. In particular, the
Fiber result is intentionally classified as `partial_execution_passed`: all 16
known workflow suites were discovered, but this campaign executed the three
that exercise the direct UDT, routed-payment, and UDT watchtower-settlement
boundaries. It does not claim mainnet readiness or complete Fiber coverage.

## Exact source and runtime binding

The live evidence was produced from a clean detached CellScript worktree at:

```text
babbe2d537493f42e6dcaa3c0ea1834a4496b5bf
```

The final documentation and audited-Fiber-pin commit is later than that
evidence commit and does not change the compiler, generated artifact, or live
runner implementation.

The CKB production replay used the clean parent CKB checkout already at the
repository's exact acceptance pin:

```text
CKB revision: f7fa4436737756f97a24e254f22c13a36316ecea
CKB version:  0.207.0
binary SHA-256: 84af0c041fe0877635555a9ba1f97e940938bac0f87f41259f568bb405121c19
```

The Fiber replay used a separate clean checkout of the exact upstream
revision now admitted by the adapter:

```text
Fiber revision: f9232d52254a5aa52195ecae296c896de7078887
```

The ordinary parent Fiber checkout was not rewritten. It already contains
that upstream runtime revision beneath its local documentation commit. The
parent CKB checkout was not advanced because it already exactly matched the
acceptance pin; moving it would have weakened reproducibility rather than
improved coverage.

## CKB production business replay

`scripts/cellscript_ckb_stateful_scenarios.sh` completed with exit status zero
from the clean CellScript worktree. Its production report has SHA-256
`dd8a95ba97bbd23cd81ab18e170ebf120bbeebb0f062eb61d4baf8c572df45a9`
and records:

| Evidence | Result |
| --- | ---: |
| Original scoped actions compiled and run on-chain | 43 / 43 |
| Original scoped Locks compiled | 17 / 17 |
| Valid Lock spends | 17 / 17 |
| Invalid Lock spends rejected | 17 / 17 |
| Stateful scenarios | 26 / 26 |
| Committed stateful steps | 46 / 46 |
| Stateful action coverage | 43 / 43 |
| Deployed artifacts with exact live data-hash match | 67 / 67 |
| Missing deployments or data-hash mismatches | 0 |
| Final production hardening gate | passed |

Every action and Lock row has measured cycles, consensus-serialized
transaction size, and occupied-capacity evidence. The seven complete business
lifecycles cover token, NFT, launch, multisig, AMM, timelock, and vesting;
action-branch scenarios close the remaining source actions.

The generated local report is:

```text
target/ckb-cellscript-acceptance/1788779467-production-1666333/
  ckb-cellscript-acceptance-report.json
```

The path is relative to the clean evidence worktree used for the run. Generated
acceptance reports are not release sources; the digest and reproduction command
are the durable binding.

## Differential and ecosystem regression coverage

Two independent CKB-facing suites passed before the production replay:

| Command | Result |
| --- | --- |
| `cargo test --locked -p cellscript --test ickb_diff -- --test-threads=1` | 218 / 218 passed |
| `./scripts/cellscript_ckb_ecosystem_reuse_gate.sh full` | passed |

The full ecosystem-reuse gate includes 13 `ckb-std` compatibility cases, 77
CKB-adapter tests, three deployment CLI tests, two SDK-builder tests, adapter
acceptance, CLI/action-boundary checks, and the corresponding strict clippy
checks.

The previously documented real Spore/Agent corpus is not counted as a fresh
standalone pass in this report. Its experimental source checkout contains
unrelated local work and the root repository does not retain that 131-case
suite as an independently runnable tracked test. The production acceptance
recipe still exercises the committed external-Agent fixture and exact trusted
dependency bindings, while the historical Spore/Agent result remains separate
release evidence.

## Fiber live business replay

The replay temporarily installed the exact CellScript `FiberToken` Type Script
in Fiber's development SimpleUDT slot, ran the selected upstream Bruno suites,
and restored the original fixture byte-for-byte afterward.

Artifact identity:

```text
ELF size:      2,032 bytes
SHA-256:       84116ae9226cf9c08c0b38bd84538228e06ecdb1cf556f0bef71d6f5126b0986
CKB data hash: 0xe0ccdfada7b4095158cd80d22977d46166372c5ecfaee3deb126869b33bfd06d
hash type:     data2
```

Exact live toolchain:

```text
CKB:       0.202.0 (d0a6c95 2025-06-11)
ckb-cli:   1.15.0 (8c892a5 2025-06-06)
Node:      v20.19.5
npm:       10.8.2
Bruno CLI: @usebruno/cli@4.1.0
sandbox:   developer
```

| Fiber workflow | Requests | Duration | Result |
| --- | ---: | ---: | --- |
| `udt` | 15 / 15 | 139.652 s | passed |
| `udt-router-pay` | 16 / 16 | 132.690 s | passed |
| `watchtower/force-close-with-pending-tlcs-and-udt` | 28 / 28 | 165.491 s | passed |

All three runs observed Bruno's terminal execution summary, returned zero,
did not time out, and exited naturally. No terminal-summary cleanup fallback
was needed. The router workflow covers two channels, invoice and keysend
payments, duplicate/overspend rejection, and final exact balances. The
watchtower workflow covers a pending TLC, force close, CKB block progression,
settlement, and final UDT and CKB balances.

The live JSON report has SHA-256
`138ddb892966152f082b3a1bc818ba2c8936b58cc84e9022a3a5e2677967f1c9`
and is stored locally at:

```text
target/business-e2e/fiber/final-business-e2e-babbe2d.json
```

As a diagnostic control, the same `udt-router-pay` suite also passed 16/16
against Fiber's native SimpleUDT artifact in 132.676 seconds. This supports the
conclusion that the compatibility workspace and Bruno runner do not manufacture
the CellScript result; it is supporting evidence rather than part of the clean
CellScript artifact binding.

## Runner integrity and compatibility boundary

The live runner binds its cache to both clean repository commits, the complete
CellScript artifact identity, and every external tool version. Reusing stale
Fiber execution after any of those values changes is therefore rejected.

Bruno 4.1 changed the behavior of several post-response JavaScript checks. For
the router and watchtower suites, the runner creates an isolated compatibility
copy and replaces those checks with equivalent declarative assertions. It does
not remove requests or weaken expected response values. The exact patched file
list is retained in the JSON report.

The runner also has a fail-closed fallback for a Bruno process that retains RPC
handles after printing its terminal result. That path requires a non-empty
suite, the expected request count, `200 OK` for every request, no failed
assertion marker, a terminal `Execution Summary`, and a five-second grace
period. Use of the fallback is explicit in the report. It was unit-tested but
was not exercised by the final three runs, which all exited normally.

## Remaining boundaries

- CKB production acceptance is a reproducible local-chain release gate, not a
  public-mainnet deployment or operator-identity attestation.
- Fiber coverage is three selected suites out of 16 discovered suites. LND/CCH
  cross-chain workflows, all remaining watchtower variants, and all channel
  lifecycle permutations were not executed in this campaign.
- Fiber compatibility is deliberately limited to an ordinary conserved `u128`
  fungible Type Script. NFTs, trailing state, rebasing assets, per-transfer
  callbacks, confidential amounts, and transaction shapes that Fiber's builder
  does not preserve remain out of scope.
- Passing finite tests cannot establish the absence of every defect. It does
  establish that no behavioral regression was observed across the exact,
  independently bound CKB and Fiber surfaces listed above.

## Reproduction gates

The tracked release contract remains:

```bash
./scripts/cellscript_gate.sh dev
./scripts/cellscript_gate.sh ci
./scripts/cellscript_gate.sh backend
./scripts/cellscript_ckb_ecosystem_reuse_gate.sh full
./scripts/cellscript_ckb_stateful_scenarios.sh
./scripts/cellscript_fiber_acceptance.sh --static
```

Live Fiber execution additionally requires the exact external toolchain and a
clean Fiber checkout. Its machine-readable report records the complete command,
artifact override, selected suites, compatibility-copy files, versions, and
completion basis.
