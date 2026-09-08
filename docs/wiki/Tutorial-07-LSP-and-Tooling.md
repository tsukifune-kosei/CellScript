# Tutorial 07: LSP and Tooling

You can write CellScript with any text editor and the `cellc` CLI. The LSP and
VS Code extension make that loop shorter. Parse errors, type errors,
flow mistakes, symbols, hovers, formatting, and compiler-backed reports
can show up while you work instead of after a long command sequence.

The useful thing to remember is that editor feedback is not a separate language
implementation. It is tied to the same parser, type checker, state-transition checks,
and lowering metadata used by `cellc`.

Compiler diagnostics now carry typed severity. Current hard failures still
surface as `error`; future review notes can be reported as `warning` without
making `ErrorReporter::has_errors()` true. Release gates and production
commands remain error-gated, so a warning is a review signal rather than a
deployment certificate.

Backend diagnostics use stable `E2xxx` codes. LSP clients receive the code in
the standard diagnostic `code` field and a `codeDescription` link to the
compiler registry, so hover or diagnostic-detail UI can show the exact rule
instead of only the message. The same record is available through
`cellc explain E2202 --json`.

## What You Will Learn

- what the LSP server supports;
- how package-aware CLI, LSP, and WASM entry points select a source edition;
- how the VS Code extension starts the server;
- which settings matter for local development;
- where editor tooling helps;
- where release gates still need CLI and CKB evidence.

## LSP Capabilities

The LSP implementation supports the editor features you expect while writing a
contract:

- diagnostics for parse, type, flow, and lowering errors, with compiler-backed
  severity;
- hover information for actions, receipts, fields, local variables, flow
  states, and lowering metadata;
- keyword, type, symbol, field, local, enum variant, and qualified flow
  state completions such as `Ticket::Active`;
- go-to-definition;
- find-references;
- workspace rename with identifier-boundary checks;
- document symbols;
- document highlight;
- signature help;
- folding ranges;
- selection ranges;
- formatting;
- code actions for lowering diagnostics;
- incremental document sync using LSP UTF-16 positions.

Run the server over stdio:

```bash
cellc --lsp
```

In practice you usually let the editor start it for you.

## One Edition Across Tooling

The editor is not an edition compatibility layer. Package-backed LSP documents
take the explicit edition from `Cell.toml` and carry it into the same frontend
route as `cellc`. Edition 2026 remains stable. The `0.26b` branch additionally
accepts experimental Edition 2027, reports its explicit-source and disposition
diagnostics in the editor, and avoids offering ambiguous `consume` completions
for that edition. A missing or unknown value is a package error; the LSP does
not infer or migrate it. The native `type_script` and `lock_script`
completions and formatter follow the bounded contract in
[`CELLSCRIPT_2027_PREVIEW_GRAMMAR.md`](../CELLSCRIPT_2027_PREVIEW_GRAMMAR.md).

The browser boundary is equally explicit. The WASM metadata exports take an
edition argument:

```text
compile_metadata_json(source, edition, target?)
compile_metadata_json_diagnostics(source, edition, target?)
compile_metadata_json_sources(sources_json, entry_path, edition, target?)
```

The optional larger language-service build also exposes
`language_service_json_for_edition(source, edition, line, character)` for
virtual documents that have no `Cell.toml` path. The original
`language_service_json` remains Edition 2026 for compatibility. The checked-in
public Playground UI and generated bundle stay on their coordinated stable
Edition 2026 asset until a product-level preview selector is approved.

The native and WASM APIs on `0.26b` accept stable `"2026"` and experimental
`"2027"`. The public playground worker continues to pass `"2026"` explicitly
and records it in compiler-output provenance, so browser metadata cannot
silently opt into the preview contract.

Introduced on the 0.22 line and retained by the current compiler, qualified
enum completion includes concrete payload constructors: after `Limit::`,
`Some` advertises `Some(u64)` and inserts
`Some(value1)`, while `None` remains a bare variant. Enum hover reads the same
compiler metadata as `cellc metadata` and shows the tagged-union layout, ABI,
storage class, encoded width, and linear-payload flag. Generic or
variable-width payload ADTs are intentionally not advertised as supported.

## Recoverable Browser Workbench

The website playground is a metadata workbench over the WASM compiler path,
not a browser ELF builder. Its workspace snapshot preserves source files, the
selected entry, active panels, and saved/dirty state in browser-local storage.
Compile failure keeps the last valid output visible with an explicit stale
label; if the compiler Worker stops, restart it from the playground without
reloading the page.

Cell Flow derives an inputs → action → outputs view from compile metadata. The
Inspector connects a selected action or type back to its declaration and shows
effects, estimated cycles, capabilities, runtime features, and layout evidence.
Raw actions, types, diagnostics, and metadata remain available alongside those
views. None of these panels upgrades metadata into consensus proof, and the
browser path still emits no assembly or ELF.

## VS Code Extension

The extension lives in:

```text
editors/vscode-cellscript
```

It is a pinned Git submodule. Initialize it before local validation or
packaging:

```bash
git submodule update --init editors/vscode-cellscript
```

If that command cannot fetch the recorded commit, the parent repository points
at an unavailable extension revision and the release must update its gitlink;
do not silently substitute an arbitrary branch tip.

Validate and package it locally:

```bash
cd editors/vscode-cellscript
npm install
npm run validate
npm run package
```

Install the generated `.vsix` in VS Code. If `cellc` is not on `PATH`, set
`cellscript.compilerPath`.

Useful settings:

| Setting | Purpose |
|---|---|
| `cellscript.compilerPath` | Path to the `cellc` binary used for LSP and CLI-backed commands. |
| `cellscript.useCargoRunFallback` | Use `cargo run -q -p cellscript --` from a trusted workspace when `cellc` is unavailable. |
| `cellscript.target` | Compiler target for command-backed reports: `riscv64-asm` or `riscv64-elf`. |
| `cellscript.commandTimeoutMs` | Timeout for compiler-backed commands. |
| `cellscript.builderOutputDir` | Output directory for generated TypeScript action-builder packages. Relative paths resolve from the nearest package `Cell.toml`. |
| `cellscript.ckbRpcUrl` | Optional CKB RPC URL for live registry verification. |
| `cellscript.deploymentNetwork` | Optional network filter for live registry verification and generated builder deployment binding. |
| `cellscript.registryApiUrl` | Optional Registry API base URL for LS-IDL fetch. |
| `cellscript.registryRequirePublisherSignature` | Add `--require-publisher-signature` to registry verification commands. This is a metadata-presence gate, not cryptographic signature verification. |
| `cellscript.registryRequireAuditReport` | Add `--require-audit-report` to registry verification commands. |

The extension contributes commands for the local compiler and builder loop:

| Command | CLI boundary |
|---|---|
| `CellScript: Compile Current File` | `cellc <file>` |
| `CellScript: Show Metadata` | `cellc metadata` |
| `CellScript: Show Constraints` | `cellc constraints` |
| `CellScript: Show Entry Witness ABI` | selects an action/lock, then runs `cellc abi` |
| `CellScript: Show Action Build Plan` | selects an action, then runs `cellc action build --json` |
| `CellScript: Show Builder Assumptions` | `cellc explain assumptions --json` |
| `CellScript: Show Transaction Template` | `cellc tx solve --json` |
| `CellScript: Show Deploy Plan` | `cellc deploy plan --json` |
| `CellScript: Show Profile` | `cellc profile --json` |
| `CellScript: Generate Audit Bundle` | `cellc audit-bundle --output <scratch> --json` |
| `CellScript: Generate TypeScript Action Builder` | `cellc gen-builder --target typescript` |
| `CellScript: Verify Package` | `cellc package verify --json` |
| `CellScript: Verify Registry` | `cellc registry verify --json` |
| `CellScript: Verify Live Registry` | `cellc registry verify --live --json` |
| `CellScript: Show Production Report` | compiler version + metadata + constraints + release-audit boundary |
| `CellScript: Validate LS-IDL` | `cellc artifact ls-idl validate --idl <active-json>` |
| `CellScript: Bind LS-IDL to CKB Executable` | `cellc artifact ls-idl bind --idl <active-json> --executable <file>` |
| `CellScript: Fetch LS-IDL by CKB Script` | `cellc artifact ls-idl fetch --code-hash <hash> --output idl.json` |

The LS-IDL commands preserve the interface's exact byte identity. Validation
checks the supported schema, binding appends the raw IDL SHA-256 to a selected
executable, and fetch writes the Registry response without JSON
reserialisation. This proves schema and commitment identity, not that a Lock
Script implements the interface correctly.

Entry-witness commands report placement ABI
`cellscript-witnessargs-input-type-v2` within the resolved compatibility profile:
`CSARGv1` is stored in Molecule `WitnessArgs.input_type` on the selected
script-group witness. Tooling must preserve `lock` and `output_type`; it must
not emit the entry payload as raw witness bytes. Edition 2026 independently
identifies how the source was understood.

`CellScript: Show Production Report` is useful while editing because it displays
compiler version, metadata, constraints, and release-audit boundaries.

The 0.21 compiler also ships `cellscript-mcp`, compile receipts, ProtocolGraph,
TemplateLayout, and helper-backed aggregate evidence. Those remain compiler/MCP
surfaces in this extension release rather than command-palette entries.

On the 0.22 nightly line, `cellc explain graph --json` attributes participant
roles on each edge. Prefer `role_source = verification-predicate`; binding
sources are secondary and `field-name` is weak metadata. Always display
`role_warnings` and `authorization_proven` alongside the role. Mermaid output
includes the selected role and source in the edge label, while summary output
reports the deduplicated role-lint count. These labels explain the protocol;
they do not prove that an Address signed or that a lock authorized the action.

That report is a guide, not a deployment certificate. Chain acceptance still
requires CLI evidence and builder-backed CKB transactions.

Generated builder packages are local artifacts. After using
`CellScript: Generate TypeScript Action Builder`, run the generated package's
own checks before treating it as usable transaction-building evidence. This is
the generated package's `npm test` boundary:

```bash
npm --prefix target/cellscript-builder/typescript install --ignore-scripts
npm --prefix target/cellscript-builder/typescript test
```

The generated tests prove the TypeScript package compiles, plans actions,
delegates live-cell resolution/build/dry-run/submit to the runtime adapter, and
fails closed on mismatched lockfile or deployment identity. They do not prove
wallet signing, CKB node acceptance, or committed stateful flows.

## A Comfortable Local Loop

While editing, let the LSP catch small mistakes quickly. Before committing, run
the CLI checks explicitly:

```bash
cellc fmt --check
cellc check --all-targets --json
cellc metadata . --target riscv64-elf --target-profile ckb -o /tmp/metadata.json
cellc build --target riscv64-elf --target-profile ckb --json
cellc verify-artifact build/main.elf --verify-sources --expect-target-profile ckb
cellc test --backend all --json
cellc package verify --json
cellc registry verify --json
```

For trust metadata review, add the explicit presence gate:

```bash
cellc registry verify --require-publisher-signature --require-audit-report --json
```

Run these from a package directory that contains `Cell.toml`. The `.` argument
refers to the current package; for a single file, pass the file path instead.

For CKB admission, keep the profile visible:

```bash
cellc check --target-profile ckb --json
cellc build --target riscv64-elf --target-profile ckb --json
cellc verify-artifact build/main.elf --expect-target-profile ckb
cellc registry verify --live --rpc-url "$CELLSCRIPT_CKB_RPC_URL" --json
cellc action build . --action mint --target-profile ckb --fabric-intent --json
cellc gen-builder . --target typescript --output target/cellscript-builder/typescript --target-profile ckb --json
npm --prefix target/cellscript-builder/typescript install --ignore-scripts
npm --prefix target/cellscript-builder/typescript test
```

This loop gives fast feedback first, then more formal evidence as the contract
gets closer to review.

## Formatting

Apply formatting:

```bash
cellc fmt
```

Check formatting without changing files:

```bash
cellc fmt --check
```

The formatter is especially useful after applying field shorthand or cleaning up
example code. It keeps the source style consistent without turning style into a
manual review topic.

## Generated Documentation

Generate package docs:

```bash
cellc doc
```

With JSON summary:

```bash
cellc doc --json
```

Documentation output includes the public contract surface and metadata-derived
lowering information.

## Local Package Workflow

The package manager supports:

- `cellc init`
- `cellc build`
- `cellc check`
- `cellc fmt`
- `cellc doc`
- `cellc add --path`
- `cellc remove`
- `cellc lock`
- `cellc info`
- `cellc package verify`
- `cellc registry verify`
- manifest-bound `Cell.lock` v5 graph checks for local, Git, and Registry
  dependencies, feature/test modes, and named CKB environments

Use the top-level `cellc path/to/file.cell` form for one-off file compilation.
Use `cellc build` for package builds.

`cellc lock`, local `cellc install --path`, and registry source-package
`cellc install` are direct lockfile workflows for packages that can be resolved
and source-hash verified. `cellc update-plan` and the default `cellc update`
emit a read-only transactional receipt; `cellc update --apply-plan` is the
explicit reviewed mutation step. Normal build/check/test consume that graph;
`--frozen` adds offline, no-write behavior. For an
interactive first Registry write,
`cellc publish --authorise` obtains a wallet-rooted delegated capability and
resumes the publish; later `cellc publish` calls use the active scoped key.
`cellc registry add` remains the local/offline discovery metadata path.
Non-CellScript artifact profiles have explicit fetch, verify, pin, copy,
deployment, and commitment commands and never become source dependencies by
implicit resolver coercion.

## Next

With the tooling loop in place, continue with
[Bundled Example Contracts](https://github.com/CellScript-Labs/CellScript/wiki/Tutorial-08-Bundled-Example-Contracts).
For the 0.24 checker and scenario boundaries, also read
[Verified Artifacts and Executable Tests](Tutorial-14-Verified-Artifacts-and-Executable-Tests.md).
