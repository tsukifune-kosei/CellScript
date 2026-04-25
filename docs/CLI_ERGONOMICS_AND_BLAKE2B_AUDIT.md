# CellScript CLI Ergonomics and BLAKE2b Support Audit

**Date**: 2026-04-24  
**Audit Scope**: CLI UX + CKB BLAKE2b support  
**Status**: Issues found; BLAKE2b scope clarified  
**Verification**: Checked against this repository and the sibling `../ckb` checkout.

---

## Audit 1: CLI Ergonomics

### Current State

CellScript CLI currently has **24 subcommands** in the subcommand parser:

```text
build
test
doc
fmt
init
add
clean
remove
repl
check
metadata
constraints
abi
scheduler-plan
ckb-hash
opt-report
entry-witness
verify-artifact
run
publish
install
update
info
login
```

The public workflow is broadly Cargo-like:

```bash
# Build and check
cellc build              # Compile current package
cellc check              # Type-check/lower current package without writing artifacts
cellc build --release    # Optimized build

# Package management
cellc init               # Initialize a package
cellc add dep            # Add dependency
cellc remove dep         # Remove dependency

# Diagnostics and release evidence
cellc constraints        # Production constraints
cellc abi --action mint  # ABI details
cellc opt-report         # Optimization comparison
cellc ckb-hash --hex 00  # CKB default Blake2b hash utility
```

### CLI Strengths

1. **Cargo-style workflow**: `build`, `check`, `test`, `fmt`, `clean`, `add`, and `remove` are familiar.
2. **Rich diagnostics**: `constraints`, `abi`, `scheduler-plan`, `entry-witness`, `opt-report`, `metadata`, and `verify-artifact` provide a strong production-facing surface.
3. **Production gate integration**: `--production`, `--deny-fail-closed`, `--deny-symbolic-runtime`, `--deny-ckb-runtime`, and `--deny-runtime-obligations` are available on relevant commands.

### CLI Ergonomics Issues

#### Issue 1: Missing `cellc new` Command

**Current**: `cellc init` exists, but no `cellc new` subcommand is registered.

**Observed behavior**:

```bash
cellc init demo ./demo   # Creates package files in ./demo
```

`init` also creates package scaffolding rather than just initializing an already-created empty directory.

**Expected Cargo-compatible split**:

```bash
cellc new my_project      # Create new project directory, optionally with .git
cellc init                # Initialize the current existing directory
cellc init --name demo    # Optional explicit name, if supported
```

**Impact**: Rust developers will likely try `cellc new` first. The current `init NAME PATH` shape is functional but less predictable than Cargo's split.

**Effort**: 0.5-1 day

---

#### Issue 2: `build` Defaults to O0

**Current**:

```rust
fn build(args: BuildArgs) -> Result<()> {
    let opt_level = if args.release { 3 } else { 0 };
```

**Problem**:

- `cellc build` defaults to `opt_level=0`.
- `cellc build --release` uses `opt_level=3`.
- If dev builds are expected to produce reasonably representative verifier size/cycle output, O0 may be a poor default.

The previous claim that this causes a "30-40% slower development experience" was not backed by local benchmark evidence and should not be treated as established.

**Potential fix**:

```rust
let opt_level = if args.release { 3 } else { 1 };
```

This should be benchmarked against representative examples before changing the default, because O0 can also be useful for debugging generated assembly.

**Effort**: 0.5 day for the code change; more if benchmark evidence is required.

---

#### Issue 3: Error Presentation Is Not Rustc-style

**Current**:

The compiler has a stable runtime error registry, including:

```text
18 fixed-byte-comparison-unresolved
```

The registry includes names, descriptions, and hints, and the table is documented in `CELLSCRIPT_RUNTIME_ERROR_CODES.md`.

However, CLI error rendering is still mostly plain:

```bash
error: line 0: ...
```

or source snippets from the basic `ErrorReporter`, rather than a consistent rustc-style diagnostic.

**Expected**:

```bash
error[E0018]: fixed-byte comparison unresolved
   --> examples/token.cell:15:5
    |
15  |     assert_invariant(a.symbol == b.symbol, "symbol mismatch")
    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: use schema-backed parameters or fixed-byte values that the verifier can address
    = note: runtime error code 18, see docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md
```

**Correction from previous audit**:

- Do **not** say "add error codes" as if none exist.
- The missing work is to expose compiler/CLI diagnostic codes such as `E0018`, improve span/file reporting, and connect runtime error hints into CLI output.
- The previous reference to `docs/RUNTIME_ERRORS.md` was wrong; the existing file is `docs/CELLSCRIPT_RUNTIME_ERROR_CODES.md`.

**Effort**: 3-5 days

---

#### Issue 4: Missing `cellc explain`

**Current**: No `cellc explain` subcommand is registered.

**Expected**:

```bash
$ cellc explain E0018
Error E0018: fixed-byte-comparison-unresolved

A fixed-byte verifier comparison could not resolve its trusted source bytes.

Fix:
  Use schema-backed parameters or fixed-byte values that the verifier can address.

Runtime code:
  18
```

This can be backed by the existing runtime error registry and any future compiler diagnostic registry.

**Effort**: 1-2 days

---

#### Issue 5: `--verbose` Is Declared Internally But Not Wired

**Current**:

`BuildArgs` has a `verbose: bool` field, but the parser does not expose `-v` or `--verbose`, and the field is not used elsewhere.

**Expected**:

```bash
cellc build              # Concise output
cellc build -v           # Show compilation phases
cellc build -vv          # Show detailed logs
cellc build -vvv         # Dump selected IR/AST artifacts or paths to them
```

Use `ArgAction::Count` rather than a boolean if multi-level verbosity is desired.

**Effort**: 1-2 days

---

#### Issue 6: `run` Subcommand Is Feature-gated for VM Execution

**Current**:

`run` exists, but ckb-vm execution requires the `vm-runner` feature, which is not enabled by default:

```toml
[features]
default = []
vm-runner = ["dep:ckb-vm"]
```

Without that feature, `cellc run` degrades to an error suggesting `--simulate` or a build with `--features vm-runner`.

**Expected**:

Either:

1. Enable out-of-the-box local execution, or
2. Keep the current feature gate but make the help text and docs clearly state that `run` is experimental and VM execution is feature-gated.

**Effort**: 1-2 days, depending on binary size and dependency policy.

---

#### Issue 7: Missing `cellc tree` and `cellc why`

**Current**: No `tree` or `why` subcommands are registered.

**Expected**:

```bash
$ cellc tree
my_project
├── token_lib v0.1.0 (path: ../token_lib)
└── stdlib (builtin)

$ cellc why token_lib
my_project
└── token_lib v0.1.0
    └── used by: mint_action, transfer_action
```

**Effort**: 2-3 days

---

### CLI Ergonomics Score

| Dimension | Current | Target | Priority |
|-----------|---------|--------|----------|
| Subcommand coverage | 88/100 | 95/100 | P2 |
| Default behavior | 70/100 | 90/100 | P1 |
| Error presentation | 55/100 | 90/100 | P1 |
| Cargo compatibility | 82/100 | 95/100 | P2 |
| Diagnostics completeness | 90/100 | 95/100 | P2 |
| Overall | 77/100 | 93/100 | - |

---

## Audit 2: BLAKE2b Support

### Finding: Off-chain CKB Blake2b Is Implemented; Generic In-script Blake2b Is Not Claimed

BLAKE2b is not absent, but the supported surface is narrower than "full on-chain stdlib support".

The accurate statement is:

> CellScript 0.12 has a CKB default Blake2b helper for builder, deployment, and release tooling. It does not currently expose or claim a generic in-script dynamic `ckb::blake2b256(data)` function unless a final artifact links a real RISC-V Blake2b implementation and that path is covered by production gates.

### Verified Current State

#### Implemented: Rust/helper Blake2b

```rust
pub const CKB_DEFAULT_HASH_PERSONALIZATION: &[u8; 16] = b"ckb-default-hash";

pub fn ckb_blake2b256(data: &[u8]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(CKB_DEFAULT_HASH_PERSONALIZATION)
        .to_state();
    state.update(data);
    // ...
}
```

This matches the CKB default hash domain:

- digest length: 32 bytes
- personalization: `ckb-default-hash`
- empty input hash: `44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e`

The sibling `../ckb` checkout exposes the same default domain through `ckb_hash::new_blake2b()` / `ckb_hash::blake2b_256()`.

#### Implemented: `cellc ckb-hash`

```bash
$ cellc ckb-hash --json
{
  "algorithm": "blake2b-256",
  "hash": "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e",
  "input_bytes": 0,
  "personalization": "ckb-default-hash",
  "status": "ok"
}
```

Important correction: the empty input hash is `44f4...163e`. Hashing `"hello world"` is different:

```bash
$ cellc ckb-hash "hello world"
3376b3e62282513e03d78fc6c5bd555503d0c697bf394d55cd672cc96e6b0a2c
```

#### Implemented: CKB identity hash access through syscalls/fields

CellScript supports patterns such as:

```cellscript
let type_hash = cell.type_hash();
let lock_hash = cell.lock_hash();
```

On CKB, these correspond to script hashes exposed by transaction/cell syscalls. In the sibling `../ckb` checkout:

- `calc_script_hash()` hashes the packed `Script`.
- `calc_lock_hash()` delegates to lock script hash.
- `load_cell` `LockHash` and `TypeHash` fields return those script hashes.

This is valid and useful for cell identity verification.

### What Is Not Implemented or Claimed

#### Generic in-script Blake2b

There is no supported CellScript stdlib function equivalent to:

```cellscript
let digest = ckb::blake2b256(data);
```

The current authoring docs explicitly say not to document or depend on this unless the artifact links a real RISC-V Blake2b implementation and the path is covered by production gates.

#### Full "CKB contracts do not need on-chain Blake2b" claim

That claim is too broad and should not be made.

CKB itself supports Blake2b in on-chain scripts via the `ckb-hash` crate with the `ckb-contract` feature. Some specialized contracts may need to hash dynamic bytes on-chain. What is true is narrower:

- Current CellScript bundled examples do not require a generic in-script Blake2b helper.
- Current CellScript CKB authoring uses `type_hash()` / `lock_hash()` for many identity checks.
- Current CellScript 0.12 only supports CKB Blake2b as an off-chain/builder helper unless a real on-chain implementation is linked.

### Artifact and Type-id Hash Caveat

Do not describe `ckb_blake2b256()` as the general CellScript artifact hash or type-id hash mechanism.

Current metadata uses BLAKE3 fields such as:

- `artifact_hash_blake3`
- `source_hash_blake3`
- `source_content_hash_blake3`
- `type_id_hash_blake3`

The CKB Blake2b helper is for CKB deployment data, CKB-compatible data hashing, builder verification, and release evidence, not a replacement for all compiler metadata hashing.

---

## Impact on v0.13 Roadmap

### Not a P0 for Current Bundled Examples

Generic on-chain Blake2b is not required for the current bundled examples if those examples only rely on `type_hash()` / `lock_hash()` and builder-side CKB Blake2b evidence.

### Optional Future Work

If specialized contracts need dynamic on-chain hashing:

- Add a pure RISC-V Blake2b implementation with `ckb-default-hash` personalization.
- Expose a deliberate in-script API such as `ckb::blake2b256(data)`.
- Add production-gate checks proving the implementation is linked.
- Add CKB compatibility vectors against the sibling `../ckb` implementation.

**Effort**: 5-7 days  
**Priority**: P3 unless a concrete bundled example or production contract needs it.

---

## Recommendations

### Immediate Actions

1. Add `cellc new` or document why `init NAME PATH` intentionally differs from Cargo.
2. Decide whether `cellc build` should default to O1. If changing it, add benchmark/release evidence and keep an explicit O0 path for debugging.
3. Fix CLI diagnostic rendering: connect existing runtime error metadata to helpful CLI output and correct docs references.

### Short-term Actions

4. Add `cellc explain` backed by the existing runtime error registry and future compiler diagnostic registry.
5. Wire `-v` / `--verbose` with counted verbosity levels or remove the unused `BuildArgs.verbose` field.
6. Clarify `cellc run` feature-gating in help/docs or enable `vm-runner` by default after dependency/binary-size review.

### Medium-term Actions

7. Add `cellc tree` and `cellc why` for dependency visibility.
8. Keep generic in-script Blake2b as optional future work unless a real contract requires it.

---

## Summary

### CLI Ergonomics

| Issue | Priority | Effort | Status |
|-------|----------|--------|--------|
| `build` defaults to O0 | P1 | 0.5 day plus benchmarks | Verified |
| Missing `cellc new` | P2 | 0.5-1 day | Verified |
| Error presentation not rustc-style | P1 | 3-5 days | Verified |
| Missing `cellc explain` | P2 | 1-2 days | Verified |
| `--verbose` field not wired | P2 | 1-2 days | Verified |
| `run` VM execution feature-gated | P2 | 1-2 days | Verified |
| Missing `cellc tree` / `cellc why` | P3 | 2-3 days | Verified |

### BLAKE2b Support

| Layer | Status | Details |
|-------|--------|---------|
| Rust/tool helper | Implemented | `ckb_blake2b256()` uses CKB default personalization |
| CLI tool | Implemented | `cellc ckb-hash` supports text, hex, file, and JSON |
| Cell identity access | Implemented | `type_hash()` / `lock_hash()` support identity checks |
| Generic in-script Blake2b | Not claimed | Requires real RISC-V implementation and production-gate coverage |
| CKB compatibility | Partial but appropriate for current scope | Off-chain helper matches CKB default hash; full on-chain dynamic hashing is future work |

**Final assessment**: The previous audit was directionally useful for CLI ergonomics but overstated and contradicted itself on BLAKE2b. The corrected position is that CellScript has CKB-compatible off-chain Blake2b tooling, while generic on-chain Blake2b remains deliberately outside the current supported stdlib surface.
