# AGENTS.md

Guidance for AI agents working in the CellScript compiler repository.

## What this repository is

CellScript is a domain-specific language that compiles `.cell` source files into
CKB ckb-vm RISC-V artifacts (assembly or ELF), together with typed metadata for
auditing, policy checks, schema binding, and scheduler-aware execution. The
crate at the repo root is `cellscript` (workspace member `.`); a sibling crate
`crates/cellscript-wasm` exposes the metadata-only compile path to browsers via
`wasm-bindgen`; `crates/cellscript-ckb-adapter` is a CKB-side adapter; and
`crates/cellscript-fiber-adapter` implements the bounded no-profile Fiber
interoperability path. `crates/cellscript-artifact-checker` independently
validates the versioned lowering/source-map/ELF boundary without loading the
compiler front end or code generator. The website submodule under `website/`
ships an Astro + WASM playground that loads the prebuilt bundle.

Version line: the workspace `Cargo.toml` pins `version = "0.25.0"`, Rust
Edition 2024, and `rust-version = "1.97.1"`. `rust-toolchain.toml` and CI pin
that exact toolchain; do not bump either version without coordinating with the
release gate.

## Required reading before any non-trivial change

1. `CODING_STYLE.md` — the tracked project standard for compiler, backend,
   docs, and release work. Treat it as a contract, not a suggestion.
2. `CHANGELOG.md` — current scope and what the latest release ships.
3. `BRANCHES.md` — which branch or release line (`main` /
   `nightly-0.21` vs `v0.20.0` vs `0.16` vs
   `research/protocol-equivalence`) represents which evidence level. Don't
   describe `research/protocol-equivalence` as production-equivalent; it keeps
   `equivalence_status = NOT_PROVEN` and
   `production_equivalence_claim = false` by design.
4. `docs/CELLSCRIPT_GATE_POLICY.md` and `docs/wiki/Tutorial-06-Metadata-Verification-and-Production-Gates.md`
   — what each gate mode (dev / ci / backend / release / release-quick) is
   meant to catch.

## Official CKB AI resources

For CKB-related work, prefer official CKB documentation over model memory. Start
with:

- `https://docs.nervos.org/llms.txt`
- `https://docs.nervos.org/llms-full.txt`
- `https://docs.nervos.org/docs/ai-agents/ai-resource`
- `https://ckb-ai.ckbdev.com/`

Treat the official docs and LLM files as the source of truth for Cell Model,
Script, transaction, SDK, testing, deployment, and version-sensitive behaviour.
CKB AI MCP and CKB Dev Skills are useful for discovery, workflow guidance, Cell
queries, RPC usage, debugging, examples, and prompts, but they are still under
active development. Verify important or version-sensitive answers against the
official docs, source repositories, RFCs, or release notes before coding or
making claims.

CKB uses the Cell Model, not an account model. Transactions consume live Cells
and create new Cells. State changes happen through Cell replacement. Lock
Scripts control spending; Type Scripts validate state rules; Scripts run in
CKB-VM.

Before coding CKB-facing changes, determine whether the task is dApp
integration, Script development, node/RPC work, or CellScript compiler/backend
work, then use the relevant official docs, maintained templates, and tooling.
Use these defaults unless the task explicitly requires a different path:

- For on-chain Scripts, prefer Rust with `ckb-std`; use C with `ckb-c-stdlib`
  only for low-level or legacy C workflows, and JS with `ckb-js-vm` only when
  the task explicitly targets the JS VM and the target network supports it.
- For dApps, prefer CCC, including `@ckb-ccc/shell` for TypeScript transaction
  work and `@ckb-ccc/connector-react` for React wallet connection flows.
- For project scaffolding, prefer maintained `ckb-script-templates`.
- For Script unit tests, prefer `ckb-testtool`; use `ckb-debugger` to reproduce
  VM execution, inspect failures, or debug exported transactions.
- For local development, prefer OffCKB unless the task depends on node, RPC,
  networking, or custom chain configuration behaviour.
- For Script deployment, prefer Type ID when upgradeability is required; use
  direct data deployment only for immutable Scripts, examples, or cases where
  upgradeability is intentionally not needed.
- For serialization, use Molecule.

Do not guess CKB node behaviour, VM behaviour, RPC schemas, SDK APIs, syscalls,
deployed Scripts, network behaviour, or OffCKB behaviour. Verify before coding.

## Build, test, lint — the only commands you should reach for

The unified entry point is `./scripts/cellscript_gate.sh <mode>`. CI runs it
with mode `ci`; the local analogue is `dev`. Other modes are heavier and
require extra tooling.

| Mode | What it does |
| --- | --- |
| `dev` | Explicit workspace-package formatting and checks for the compiler, standalone artifact checker, Fiber adapter, CKB adapter, WASM crate, CKB SDK builder example, `cellscript-tools`, and both independent Registry verifiers; checker mutation/Myelin handoff tests; simulator package scenarios; reproducible Registry Type Script build and CKB-VM tests; native source-policy enforcement; strict backend audit (quick); syntax combo audit (quick); parity-gated skill-pack freshness; `git diff --check`. Run before committing. |
| `ci` | `dev` coverage plus tests and clippy for every workspace package, `cellscript-tools`, both Registry verifiers, and the Registry Type Script; simulator and CKB-VM package scenarios; Registry API tests plus Node API/verifier bundles; full package contents check, website build check (requires `npm`), shell syntax and native source-policy checks, parity-gated skill-pack freshness, and trailing-whitespace check. Run before claiming merge-readiness. |
| `backend` | For IR / codegen / assembler / ABI / ELF / RISC-V changes: explicit workspace-package format checking, compiler/checker tests and clippy, both package-scenario backends, standalone-checker dependency enforcement, strict backend audit (full, which itself fires the CKB stateful-scenarios harness via `cellscript_ckb_stateful_scenarios.sh`), and `git diff --check`. |
| `release` / `release-quick` | Everything `ci` does plus release-auxiliary checks (CKB acceptance, NovaSeal pinning, NovaSeal Rust tooling for RISC-V, fresh WASM + VS Code packaging, CKB tx measure tool, etc.) and the CKB acceptance harness (`scripts/ckb_cellscript_acceptance.sh`). These modes need the pinned sibling CKB checkout from `scripts/ckb_acceptance_pin.json`, the NovaSeal submodule, a sibling `ckb-sdk-rust` checkout at tag `v5.1.0`, Docker for the canonical Linux/amd64 WASM build, and `riscv64imac-unknown-none-elf` for NovaSeal verifier builds. Do not run them casually. |

Focused commands are still useful while debugging — `cargo check --locked -p
cellscript --all-targets`, `cargo test --locked -p cellscript`, clippy with
`-D warnings`, and `git diff --check` — but passing one does not replace the
matching gate (`CODING_STYLE.md` is explicit about this).

Notes on Rust toolchain / target:

- `rust-version = "1.97.1"` in every in-tree Cargo manifest;
  `rust-toolchain.toml` and CI select that exact toolchain.
- Registry reproducibility accepts either GNU `sha256sum` or Perl `shasum` and
  fails closed if neither SHA-256 tool is available.
- The NovaSeal verifier (`proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_riscv`)
  builds with `--target riscv64imac-unknown-none-elf` in release mode.
  `scripts/cellscript_gate.sh` will not pass without it.
- `Cargo.toml` pins exact versions for several deps (`indexmap = "=2.2.6"`,
  `clap = "=4.5.49"`, `ckb-vm = "0.24"` with `asm` + `detect-asm`, etc.). Do
  not bump them without running the full gate.

## Cargo workspace layout

The root `Cargo.toml` declares a virtual workspace with these members:

- `.` (the `cellscript` library + `cellc` bin at `src/main.rs`)
- `crates/cellscript-ckb-adapter`
- `crates/cellscript-fiber-adapter`
- `crates/cellscript-artifact-checker`
- `crates/cellscript-tools`
- `crates/cellscript-wasm`
- `examples/ckb-sdk-builder`

Excluded from the workspace (still buildable through their own manifests):
`contracts/registry-type-script`, `services/registry-verifier`,
`services/registry-artifact-verifier`,
`proposals/novaseal/v0-mvp-skeleton/{harness,verifier}` and
`proposals/novaseal/agreement-profile-v0/harness/ckb_vm`. `tools/ckb-tx-measure`
defines its own `[workspace]` (no parent) because it pulls `ckb-jsonrpc-types`
and `ckb-types` from a sibling CKB checkout (`../ckb`).

The 0.23 tooling migration is complete. `cellscript-tools` is authoritative
for gate, evidence, fixture, and release validation; website data generation
uses the tracked Node modules under `website/scripts/`. Every gate runs the
native source-policy check, which rejects retired interpreter sources,
generated bytecode/cache artifacts, and interpreter references in active
tooling source across the repository and initialized submodules.

The 0.30 package closure is lock-authoritative. `Cell.lock` version 4 uses
`cellscript-lock-v0.30-compiler-requirement-v1` and binds the root manifest
digest, root/dependency compiler requirements and resolving compiler releases,
canonical dependency nodes/edges, dependency manifests and sources,
feature/test roots, and CKB environment chain identity. Use `cellc lock` or
`cellc update` for an intentional repin. Build/check/test must not perform
mutable version selection; `--frozen` also forbids network access and lockfile
writes. Bounded external resolvers run only during explicit repinning and
normalize to exact Registry or Git sources before the lock is written.

Features (root crate):

- `default = ["cli", "lsp", "vm-runner"]` — native `cellc test` can execute
  the authoritative CKB-VM scenario backend without an extra feature flag.
- `cli` — pulls `clap`, `colored`, `env_logger`, `keyring`, `reqwest` (rustls),
  `ring`, `base64`. Native I/O, gated out of the wasm build.
- `lsp` — pulls `tower-lsp` and `tokio` (full). Gated out of wasm.
- `wasm` — disables `cli` + `lsp` so `wasm32-unknown-unknown` can build.
- `vm-runner` — pulls `ckb-vm` for local VM execution.
- `ckb-acceptance` — test-only acceptance harness.

The release profile is `opt-level = "z"`, `lto = "thin"`,
`codegen-units = 16`. The wasm playground is size-sensitive; the native
release build is tuned to stay reasonably fast to compile.

## Source tree at a glance

`src/` is the compiler. Each subdirectory owns a phase:

- `lexer/`, `parser/`, `ast/` — front end.
- `resolve/`, `types/`, `flow/`, `proof_plan/`, `ir/` — semantic + lowering.
- `optimize/`, `codegen/` — backend (RISC-V ELF and ASM).
- `package/` — workspace + dependency manifest handling.
- `error/`, `runtime_errors.rs`, `assumptions.rs`, `simulate.rs` — diagnostics
  + simulation.
- `lsp/`, `wasm/`, `cli/` — consumers of the library.
- `repl.rs`, `main.rs` — interactive + CLI entry.
- `src/bin/ckb_tx_measure.rs` — `cellscript-ckb-tx-measure` binary; relies on a
  sibling CKB checkout (`../ckb`).

`src/codegen/mod.rs` is the orchestration layer of a multi-file backend; the
sub-module boundaries (`cell_ops.rs`, `schema.rs`, `frame.rs`, `calls.rs`,
`expr.rs`, `assembler.rs`, `runtime.rs`, `abi.rs`, `collections.rs`) are
documented in `CODING_STYLE.md` under "Backend And Codegen Rules" and "Module
Boundary: Schema vs Cell Operations vs Orchestration". New code must respect
those ownership layers — keep the implicit backend contracts explicit.

## Backend / codegen rules (non-obvious)

- The internal assembler (`src/codegen/assembler.rs`) must accept every
  mnemonic that codegen, generated stdlib, generated collection assembly, or
  internal lowering helpers emit. Adding a new mnemonic is a Tier-1 closure
  requirement: update `Instruction`, `parse_instruction`,
  `encode_instruction`, sizing, CFG/terminator handling, and add regression
  tests for the generated assembly.
- Tier 1 mnemonics (must be in the internal assembler): `add`, `addi`, `sub`,
  `and`, `andi`, `or`, `xor`, `mul`, `div`, `divu`, `rem`, `remu`, `slt`,
  `sltu`, `xori`, `ld`, `lbu`, `sb`, `sh`, `sw`, `sd`, `slli`, `srli`, `beq`,
  `bne`, `blt`, `bge`, `bltu`, `bgeu`, `ret`, `ecall`.
- Tier 2 candidates (add when needed by optimizer / typed emitter /
  constant materialiser): `nop`, `lui`, `auipc`, raw `jal`/`jalr`, `ori`,
  `sll`, `srl`, `sra`, `srai`, `addw`, `addiw`, `subw`.
- Tier 3 (demand-driven): signed byte/half/word loads, unsigned half/word
  loads, `slti`/`sltiu`, branch aliases (`ble`, `bleu`, `bgtu`, `bltz`,
  `bgtz`, `blez`), `not`, `jr`.
- Do not add CSRs, atomics, FP, compressed instructions, `fence`, `tail`, or
  the full GNU pseudo-instruction surface unless a concrete backend contract
  demands it.
- Stack access must go through `emit_stack_load`, `emit_stack_load_byte`,
  `emit_stack_store`, `emit_stack_store_byte`. Outgoing call-stack ABI args
  use dedicated outgoing helpers (so caller-local buffers like entry witness
  payloads aren't overwritten by `sp` adjustments).
- Large pointer arithmetic uses `emit_large_addi` or a helper that takes an
  explicit live-register avoid set. Helpers that need scratch registers must
  document the live registers via arguments or an avoid set; do not assume
  `t6` is free.
- Fixed-byte values wider than 8 bytes use fixed-byte storage + byte
  comparison/copy helpers — never pass them through the 64-bit scalar stack
  slot model.
- Unsupported runtime semantics must fail closed with a specific
  `CellScriptRuntimeError`; do not emit a clean success path for unsupported
  DSL.
- Do not encode domain-specific verifier rules by matching action/function
  names in codegen. Business rules must be explicit in DSL source,
  structured IR, or metadata before the backend lowers them.

## Refactor procedure for `src/codegen/mod.rs`

When extracting emitter methods from `codegen/mod.rs` into a sub-module:

1. Use `git show` or equivalent to extract the original code verbatim. Never
   reconstruct emitter logic from memory — a single wrong register, label, or
   branch will silently change generated assembly and break on-chain
   contracts.
2. Run the full test suite after each extraction. The codegen tests include
   end-to-end assembly assertions that catch transcription errors.
3. Cross-module `impl` blocks need method visibility to match call sites;
   use `pub(crate)` for methods called from other modules within the crate.
   Fields of types shared across module boundaries also need `pub(crate)`.
4. When removing code by line number with `sed`, delete later ranges first
   so earlier line numbers stay stable.
5. After every deletion, run formatting and a focused Rust check. The parser
   and compiler are authoritative for brace balance; do not rely on textual
   brace-count heuristics.

## CLI surface (where to add a new command)

The CLI is in `src/cli/commands.rs` and dispatched in `src/main.rs`. Adding a
command means: add an enum variant to `Command`, define the args struct, add
a `match` arm in the dispatcher, and update `docs/CELLSCRIPT_GATE_POLICY.md`
and any relevant `docs/wiki/` tutorial if it changes user-visible behaviour.
Existing command families to be aware of:

- `build`, `check`, `fmt`, `doc`, `test` — package-level lifecycle.
- `init`, `new`, `add`, `remove`, `clean` — workspace skeleton.
- `metadata`, `constraints`, `abi`, `scheduler-plan`, `explain*`, `opt-report`,
  `proof-diff`, `profile`, `trace-tx`, `audit-bundle`, `validate-tx`,
  `solve-tx`, `verify-ckb-fixtures`, `deploy-plan`, `verify-deploy`,
  `diff-deploy`, `lock-deps`, `action-build`, `gen-builder`, `entry-witness`,
  `verify-artifact`, `run` — build-product analysis and tooling.
- `publish`, `install`, `registry-verify`, `package-verify`, `registry-add`,
  `registry-edit`, `certify`, `update`, `info`, `login`, `auth-*` — registry
  and identity.

## Testing approach

- Package runtime fixtures use `cellscript-test-scenario-v1` JSON under
  `tests/scenarios/`. `cellc test` requires `--backend simulator|ckb-vm|all`
  unless `--no-run` is explicitly selected. Simulator evidence is
  non-consensus; CKB-VM evidence is runtime-only, and the v1 runner does not
  inject its local Cell bookkeeping into transaction syscalls.
- Integration tests live in `tests/*.rs`. Per-version suites exist
  (`tests/v0_14.rs`, `v0_16.rs`, `v0_17.rs`, `v0_18.rs`) — when adding a
  versioned boundary, add it to the latest suite and keep prior ones intact
  as historical evidence.
- `tests/cli.rs` (~267 KB) and `tests/ickb_diff.rs` (~934 KB) are the largest
  suites — they are run with `--test-threads=1` in CI to avoid filesystem
  races. Don't change that flag.
- `tests/syntax_combo/` holds the syntax-combination matrix
  (`matrix.toml` + `seeds/*.cell`) that `scripts/cellscript_syntax_combo_audit.sh`
  drives. New syntax should be reflected in the matrix and seeds.
- `tests/support/{ckb_script_runner.rs,ickb_model.rs}` and `tests/compat/ckb_standard/`
  support the CKB-compat and iCKB suites.
- `tests/benchmarks/` is a submodule (`cellscript-ickb-equivalence`) and is
  empty until initialized — run `git submodule update --init` if you need to
  inspect or run benchmark code. When a coordinated change needs to update iCKB
  benchmark specs or their docs (e.g. a new release line renames or consolidates
  test files the submodule cites), edit the submodule in place, commit inside
  it, and then bump the parent's submodule pointer in the same change. Do not
  push the submodule to its remote without explicit coordination; a local
  submodule commit + parent pointer bump is enough for review.
  The 0.21 RC citation-refresh submodule commit `82129ff1` was explicitly
  coordinated for remote publication on 2026-07-03; future submodule pushes
  still need their own coordination.

## CKB / NovaSeal gotchas

- The CKB acceptance harness is `scripts/ckb_cellscript_acceptance.sh`. It
  expects a sibling `../ckb-sdk-rust` checkout at tag `v5.1.0` and runs the
  `cellscript-tools validate-production-evidence` command against the build
  reports. Its build reports, source provenance hashes, and production
  hardening gate (`final_production_hardening_gate`) are referenced by
  string from the gate script; if you rename them, update
  `check_ckb_acceptance_boundaries` in `scripts/cellscript_gate.sh` too.
- The NovaSeal verifier pinning check (`check_novaseal_verifier_pinning` in
  the gate) reads the build ELF at
  `proposals/novaseal/v0-mvp-skeleton/verifier/novaseal_btc_verifier_riscv/target/riscv64imac-unknown-none-elf/release/novaseal_btc_verifier_riscv`,
  recomputes BLAKE2b + SHA-256 hashes, and compares them against
  `Cell.toml` manifests and `proofs/*.template.json` hashes. It rejects
  symlinks inside the verifier TCB source tree and inside NovaSeal profile
  source trees. The release ELF must be built with the verifier crate's
  `build_reproducible_release.sh`, which normalizes source paths and strips
  symbols with the pinned toolchain's `rust-objcopy`.
- `proposals/novaseal` is a submodule (`NovaSeal.git`, branch `main`). Same
  for `proposals/evolving-dob/evolving-dob-profile-v1`.
- `tools/ckb-tx-measure` depends on `../ckb/util/jsonrpc-types` and
  `../ckb/util/types`; the gate builds the helper with CellScript's pinned
  Rust 1.97.1 toolchain so its declared `rust-version` remains enforceable.
- `--primitive-strict 0.16` is the current production assurance gate; the
  README mentions it and the policy lives in `docs/`.

## Documentation conventions

- Do not describe a feature as implemented unless parser, type checking,
  lowering, metadata, LSP/editor behaviour, tests, examples, and docs all
  agree on the same boundary.
- Use "reserved", "deferred", or "fail-closed" when syntax exists but
  executable semantics are intentionally unavailable.
- Release notes separate highlights, scope boundaries, validation commands,
  and links to detailed docs.
- Release notes describe what shipped. Future work belongs in a concrete RFC
  or proposal with explicit ownership and acceptance criteria.

## Gotchas that are easy to miss

- Trailing whitespace is a tracked-file gate violation; many tracked files
  (including the gate script, all tracked `.rs`, and a curated set of docs
  and website files) are explicitly checked by `check_trailing_whitespace`.
  When you `sed -i` or paste snippets, expect to re-run `cargo fmt` and fix
  whitespace.
- `*.local.md` files are explicitly outside the project contract — they're
  not committed and the coding style doc calls this out. Don't add them to
  the gate.
- The website build (in `ci` / `release`) regenerates
  `website/src/data/registry-packages.json` via `npm run prepare:registry`,
  then fails if that file is dirty in the working tree. If your change
  regenerates registry data, commit the result.
- `src/cli/commands.rs` (~553 KB) and `src/codegen/mod.rs` (~940 KB) and
  `src/lib.rs` (~1 MB) are huge. Don't try to read them whole — scope your
  edits and use offset/limit.
- `cellscript-wasm` uses `default-features = false` and `--features wasm`,
  which is what gates out cli + lsp so the wasm32 target builds. Any
  addition to the cellscript library that pulls a native-IO dep must be
  gated behind `cli`/`lsp` (or moved behind the `wasm` exclusion) or the
  playground build breaks.
- The website playground's `compile_metadata_json` only exposes the
  metadata-only path — no ELF. The bundle size budget is 600 KB gzip;
  `website/scripts/build-wasm.sh` enforces it. Adding compiler surface area
  that wasm can't avoid will blow the budget; this is RFC path B / v2 per
  `crates/cellscript-wasm/src/lib.rs`.
- The playground serialises the entire `CompileMetadata` to JSON; anything
  you add to that struct will land in every user's browser. Heavy new
  fields should be `#[serde(skip)]` or gated behind a feature.

## Quick command cheat sheet

```bash
# Local development (fast feedback, what to run before commit)
./scripts/cellscript_gate.sh dev

# Merge-readiness (slow, ~CI parity; needs npm)
./scripts/cellscript_gate.sh ci

# Backend-only (IR / codegen / assembler / ABI / ELF / RISC-V)
./scripts/cellscript_gate.sh backend

# Rebuild the website WASM bundle (size budget enforced)
website/scripts/build-wasm.sh

# Build the native cellc binary
cargo build --locked -p cellscript --bin cellc
```

Do not invent commands. If something isn't listed above and isn't in
`Cargo.toml` / `package.json` / the gate script, it isn't part of the
project contract.
