# CellScript VS Code Extension

Production-grade local VS Code tooling for `.cell` contracts.

The extension is intentionally compiler-backed: it does not duplicate
CellScript semantics in JavaScript. It uses a local `cellc` binary, or a
workspace `cargo run -q -p cellscript --` fallback, for validation, formatting,
metadata, and constraints reports.

## Features

- `.cell` file association
- TextMate syntax highlighting
- comment, bracket, auto-close, and folding configuration
- snippets for resources, shared state, receipts, actions, locks, effects, and
  `create ... with_lock`
- edit/open/save diagnostics through `cellc --parse`
- optional wider compiler diagnostics through `cellc <file> --target riscv64-asm`
- document formatting through `cellc fmt`
- command palette entries for compile, metadata, constraints, validation, and
  target-profile selection
- production report output that combines `cellc --version`, `cellc metadata`,
  and `cellc constraints` for release review
- status bar state for compiler-backed editor commands
- hardened command execution with timeout and output-size limits

## Production Boundary

This extension is a mature local compiler-backed editor integration. It is not
an independent JSON-RPC language-server transport, and it does not start a
`cellc lsp --stdio` process. The compiler crate already exposes an in-process
LSP service, but VS Code currently uses direct `cellc` CLI calls for local
diagnostics, formatting, metadata, constraints, and production reports.

The next transport project, if needed, is a separate VS Code `LanguageClient`
integration backed by a standalone `cellc lsp --stdio` binary. That transport
would change process management and incremental document synchronization; it is
not required for the current local compiler-backed workflow.

## Requirements

Install `cellc` and make it available on `PATH`, or set
`cellscript.compilerPath` to the full compiler path.

When developing inside the CellScript or Spora Rust workspace, the extension can
fall back to:

```bash
cargo run -q -p cellscript --
```

Set `cellscript.useCargoRunFallback` to `false` to disable that fallback.

## Commands

| Command | Purpose |
|---|---|
| `CellScript: Validate Current File` | Run configured diagnostics for the active `.cell` file. |
| `CellScript: Compile Current File` | Compile the active file to a scratch RISC-V assembly artifact and print compiler output. |
| `CellScript: Show Metadata` | Run `cellc metadata` for the active file and show JSON in the CellScript output channel. |
| `CellScript: Show Constraints` | Run `cellc constraints` for the active file and show JSON in the CellScript output channel. |
| `CellScript: Show Production Report` | Show compiler version, artifact metadata, constraints, and release audit boundaries for the active file. |
| `CellScript: Format Current File` | Format the active file through `cellc fmt`. |
| `CellScript: Select Target Profile` | Store `spora`, `ckb`, or `portable-cell` in workspace settings. |

## Settings

| Setting | Default | Description |
|---|---:|---|
| `cellscript.compilerPath` | `cellc` | Compiler binary used by editor commands. |
| `cellscript.useCargoRunFallback` | `true` | Use workspace `cargo run -q -p cellscript --` if `cellc` is unavailable. |
| `cellscript.validationMode` | `parse` | `parse`, `compile-asm`, or `off`. |
| `cellscript.validateOnChange` | `true` | Run diagnostics after edits with a debounce. |
| `cellscript.validationDebounceMs` | `250` | Edit-time diagnostic debounce. |
| `cellscript.commandTimeoutMs` | `15000` | Compiler command timeout. |
| `cellscript.maxOutputBytes` | `4194304` | Captured stdout/stderr limit. |
| `cellscript.target` | `riscv64-asm` | Compiler target for compile/metadata/constraints commands. |
| `cellscript.targetProfile` | `spora` | Target profile for compile/metadata/constraints commands. |

## Local Validation

```bash
cd editors/vscode-cellscript
npm run validate
```

The validation script checks the extension manifest, grammar, snippets,
language configuration, commands, settings, and runtime wiring.

## Packaging

```bash
cd editors/vscode-cellscript
npm run package
```

Generated `.vsix` files are ignored by git and excluded from packaged source
archives.

## Release Review Checklist

For production release review, use `CellScript: Show Production Report` and
check the JSON/prose output for:

- compiler version pin;
- artifact metadata and artifact hash;
- schema hash and ABI/schema metadata;
- constraints hash or constraints JSON saved by the build;
- build provenance and source hash fields;
- target profile and entry-action/entry-lock scope;
- CKB capacity/cycle limits or Spora mass estimates;
- external audit signatures attached by the release process.

The extension displays compiler evidence. It does not create audit signatures,
publish packages, deploy code cells, or replace Spora/CKB acceptance gates.

## Scope

The extension is a stable local editor integration. It is not a debugger, and
it does not replace release gates such as `cargo test`, `cargo clippy`,
`cellc check --production`, or chain acceptance scripts.
